"""
app/scanner/gemini_selector.py
────────────────────────────────────────────────────────────────────────────
Privacy-safe Gemini 2.0 Flash integration for CVE → NSE script selection.

PRIVACY RULES (enforced by this module):
  ✅ Sends: CVE ID (public info), service name, product, version, script list
  ❌ Never sends: IP address, hostname, scan output, evidence, target details

WORKFLOW:
  1. ask_gemini() sends a MINIMAL prompt: CVE + service + product + version only
  2. Gemini names the right NSE script from training knowledge (~80 tokens vs ~2000)
  3. Answer validated against local filesystem — not a sent list
     Unknown / not-installed scripts fall through to the next layer cleanly
  4. Caller saves result to SQLite via cve_db.save_ai_result()
  5. Same CVE is never sent to Gemini again — DB cache prevents repeat calls

FALLBACK:
  If Gemini is unavailable (no key, network error, rate limit):
  → returns (None, reason_string) so caller can try version-range check
  → never raises an exception
  → on a quota/rate-limit (429) error, a cooldown circuit opens for
    GEMINI_COOLDOWN_SECS (default 300s): further calls return instantly
    with no network round-trip and no log spam until it elapses.
"""

from __future__ import annotations

import os
import re
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

# ── Circuit breaker for quota / rate-limit errors ───────────────────────────
# BUG (seen in production logs): when the Gemini free-tier quota is exhausted
# (HTTP 429, limit=0), every single candidate CVE in a scan was still being
# sent to Gemini, one by one, each failing with the *same* 429 — and since
# only successful lookups were cached to SQLite, the next scan/port-confirm
# call repeated the exact same doomed requests again. Result: dozens of
# guaranteed-to-fail API calls per scan and the full multi-line quota error
# (links, violations, quota_dimensions) logged at WARNING for every one.
#
# FIX: once a quota/rate-limit error is seen, "open" an in-memory circuit for
# GEMINI_COOLDOWN_SECS. While open, ask_gemini() short-circuits immediately
# (no network call, no log spam) for every subsequent CVE — within the same
# request loop *and* across future requests — until the cooldown elapses.
# This does NOT touch the permanent SQLite cache (reserved for genuine
# answers), so once the quota actually resets/billing is fixed, Gemini is
# automatically retried with no restart required.
GEMINI_COOLDOWN_SECS = int(os.environ.get("GEMINI_COOLDOWN_SECS", "300"))

_circuit_open_until: float = 0.0   # epoch seconds; 0 = closed


def _circuit_is_open() -> bool:
    return time.time() < _circuit_open_until


def _open_circuit(cooldown: float = GEMINI_COOLDOWN_SECS) -> None:
    global _circuit_open_until
    _circuit_open_until = time.time() + cooldown


def _is_quota_or_rate_limit_error(exc: Exception) -> bool:
    """Detect HTTP 429 / quota-exhaustion style failures (vs. e.g. a one-off
    network blip), so we only trip the breaker for errors that will keep
    failing identically on retry."""
    haystack = f"{type(exc).__name__} {exc}".lower()
    return any(tok in haystack for tok in (
        "429", "quota", "rate limit", "rate_limit", "resourceexhausted",
    ))


def _short_summary(exc: Exception) -> str:
    """One-line summary instead of the full Gemini error object, which can
    include a multi-KB dump of links/violations/quota_dimensions."""
    first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return first_line[:200]

# Scripts in these categories are safe to suggest for vulnerability confirmation
# (no brute force, no exploits, no DoS)
_SAFE_CATEGORIES = {
    "vuln", "cve", "backdoor", "heartbleed", "shellshock",
    "poodle", "drown", "logjam", "beast", "crime", "breach",
    "injection", "traversal", "disclosure", "enum", "info",
}

_BLOCKED_PATTERNS = re.compile(
    r'\b(brute|exploit|fuzzer|dos|flood|spray|crack|guess)\b',
    re.IGNORECASE
)


def is_gemini_available() -> bool:
    """Return True only if the SDK is installed and an API key is configured."""
    if not GEMINI_API_KEY or GEMINI_API_KEY in ("your_gemini_api_key_here", ""):
        return False
    try:
        import google.generativeai  # noqa: F401
        return True
    except ImportError:
        return False


def _filter_safe_scripts(available_scripts: list[str]) -> list[str]:
    """
    Return only scripts safe to run on live targets.
    Excludes brute-force, exploit, DoS, and fuzzer scripts.
    """
    safe = []
    for s in available_scripts:
        if _BLOCKED_PATTERNS.search(s):
            continue
        safe.append(s)
    return safe


NSE_SCRIPTS_DIR = os.environ.get("NSE_DIR", "/usr/share/nmap/scripts")


def _script_exists_locally(script_name: str) -> bool:
    """Check if an NSE script .nse file is present on this machine."""
    return os.path.isfile(os.path.join(NSE_SCRIPTS_DIR, script_name + ".nse"))


def _find_on_disk(candidate: str, available_scripts: list[str]) -> Optional[str]:
    """
    Validate a Gemini-suggested script name against the local filesystem.

    Priority order:
      1. Exact name exists on disk           → use it
      2. Exact name in available_scripts     → already verified on disk
      3. Candidate is substring of a script  → fuzzy match
      4. Script name ends with candidate     → trimmed-prefix match
    Returns the matched script name, or None if nothing found.
    """
    if _script_exists_locally(candidate):
        return candidate
    if candidate in available_scripts:
        return candidate
    for s in available_scripts:
        if candidate in s or s.endswith(candidate):
            return s
    return None


def ask_gemini(
    cve_id: str,
    service: str,
    product: str,
    version: str,
    available_scripts: list[str],
    timeout_seconds: int = 15,
) -> tuple[Optional[str], str]:
    """
    Ask Gemini 2.0 Flash which NSE script confirms a CVE.

    TOKEN-EFFICIENT DESIGN (v4.2)
    ──────────────────────────────
    Old design sent up to 200 script names in every prompt (~2 000 tokens).
    New design asks Gemini to NAME the script from its own training knowledge
    (~80 tokens), then validates the answer against the local filesystem.

    Gemini already knows every published Nmap NSE script from training data.
    We no longer need to list them.  If Gemini names a script that isn't
    installed on this machine, _find_on_disk() catches it and we fall through
    to the next selection layer cleanly.

    PRIVACY: Only CVE ID, service, product, version are sent to Gemini.
             IP addresses and scan output never leave this machine.
    """
    if not is_gemini_available():
        return None, "Gemini not configured (no GEMINI_API_KEY)"

    if _circuit_is_open():
        remaining = int(_circuit_open_until - time.time())
        logger.debug(
            "Gemini circuit open (%ss remaining) — skipping call for %s",
            remaining, cve_id,
        )
        return None, f"Gemini paused after rate-limit/quota error (retry in {remaining}s)"

    # Minimal prompt — no script list, just the vulnerability context.
    # Gemini names the script from training knowledge; we verify it on disk.
    prompt = f"""You are a Nmap NSE script expert for network security testing.

CVE:     {cve_id}
Service: {service}
Product: {product}
Version: {version}

What is the exact Nmap NSE script name that SPECIFICALLY confirms this vulnerability?

Rules:
1. Reply with ONLY the script filename WITHOUT the .nse extension, or the word "none"
2. The script must be a real, published Nmap NSE script — not invented
3. It must SPECIFICALLY test this CVE or its direct vulnerability class
4. For Exim-specific CVEs (e.g. smtp-vuln-cve2010-4344), do NOT suggest for Postfix/Sendmail
5. Prefer scripts whose name contains the CVE number (e.g. smb-vuln-ms17-010 for CVE-2017-0144)
6. If no dedicated NSE script exists for this CVE, reply: none

Reply — one word only:"""

    try:
        import google.generativeai as genai
        from google.generativeai.types import GenerationConfig

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(
            GEMINI_MODEL,
            generation_config=GenerationConfig(
                max_output_tokens=25,      # script name is short — cap tight
                temperature=0.0,           # deterministic answer
                candidate_count=1,
            )
        )

        response = model.generate_content(
            prompt,
            request_options={"timeout": timeout_seconds},
        )

        raw = response.text.strip().lower()

        # Normalise: strip .nse extension, quotes, "script:" / "answer:" prefixes
        raw = raw.replace(".nse", "").replace('"', "").replace("'", "").strip()
        if ":" in raw:
            raw = raw.split(":")[-1].strip()
        # Guard against multi-word replies — take first token only
        raw = raw.split()[0] if raw.split() else ""

        if raw in ("none", "n/a", "null", "") or not raw:
            logger.debug("Gemini: no NSE script for %s", cve_id)
            return None, f"Gemini: no dedicated NSE script for {cve_id}"

        # ── Validate against local filesystem ─────────────────────────────────
        # NEW: check disk directly instead of validating against the full list
        # that was previously sent inside the prompt.
        matched = _find_on_disk(raw, available_scripts)

        if matched:
            logger.info(
                "Gemini→disk: %r confirmed for %s (asked %r)",
                matched, cve_id, raw,
            )
            return matched, f"Gemini 2.0 Flash: {matched} for {cve_id}"

        # Gemini named a real script but it isn't installed here
        logger.warning(
            "Gemini suggested %r for %s — script not installed on this system. "
            "Tip: apt install nmap / nmap --script-updatedb",
            raw, cve_id,
        )
        return None, (
            f"Gemini suggested '{raw}' for {cve_id} "
            "but it is not installed on this system"
        )

    except Exception as exc:
        if _is_quota_or_rate_limit_error(exc):
            _open_circuit()
            logger.warning(
                "Gemini quota/rate-limit hit on %s — pausing Gemini for %ss "
                "(further CVEs in this batch will skip Gemini): %s",
                cve_id, GEMINI_COOLDOWN_SECS, _short_summary(exc),
            )
            return None, f"Gemini quota/rate-limit exceeded — pausing for {GEMINI_COOLDOWN_SECS}s"
        logger.warning("Gemini API call failed for %s: %s", cve_id, _short_summary(exc))
        return None, f"Gemini error: {_short_summary(exc)}"
