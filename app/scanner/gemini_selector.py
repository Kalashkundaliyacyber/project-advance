"""
app/scanner/gemini_selector.py
────────────────────────────────────────────────────────────────────────────
Privacy-safe Gemini 2.0 Flash integration for CVE → NSE script selection.

PRIVACY RULES (enforced by this module):
  ✅ Sends: CVE ID (public info), service name, product, version, script list
  ❌ Never sends: IP address, hostname, scan output, evidence, target details

WORKFLOW:
  1. ask_gemini() sends a short, grounded prompt to Gemini 2.0 Flash
  2. Gemini picks ONE script from the provided list (cannot hallucinate names)
  3. Result is validated against available_scripts before returning
  4. Caller saves result to SQLite via cve_db.save_ai_result()
  5. Same CVE is never sent to Gemini again — DB cache prevents repeat calls

FALLBACK:
  If Gemini is unavailable (no key, network error, rate limit):
  → returns (None, reason_string) so caller can try version-range check
  → never raises an exception
"""

from __future__ import annotations

import os
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

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

    Parameters
    ----------
    cve_id            : e.g. "CVE-2024-23897"
    service           : e.g. "http" (NEVER an IP)
    product           : e.g. "Jenkins"
    version           : e.g. "2.441"
    available_scripts : scripts actually on disk — grounds the response
    timeout_seconds   : API call timeout

    Returns
    -------
    (script_name, reasoning) if Gemini picks a valid script
    (None, reason_string)    if nothing matches or Gemini is unavailable

    PRIVACY: This function only sends the above parameters.
             IP addresses and scan output never leave this machine.
    """
    if not is_gemini_available():
        return None, "Gemini not configured (no GEMINI_API_KEY)"

    safe_scripts = _filter_safe_scripts(available_scripts)
    if not safe_scripts:
        return None, "No safe scripts available to suggest from"

    # Keep the list short to stay within Gemini's context window
    # and to force a specific, considered answer
    script_list = ", ".join(safe_scripts[:200])

    prompt = f"""You are a vulnerability scanner assistant helping select Nmap NSE scripts.

CVE ID:  {cve_id}
Service: {service}
Product: {product}
Version: {version}

Available NSE scripts installed on this Kali Linux system:
{script_list}

Task: Which ONE script from the list above best confirms vulnerability {cve_id}?

Rules:
1. Reply with ONLY the exact script name from the list, or the word "none"
2. Do NOT suggest any script not in the list above
3. Only suggest a script that specifically tests this CVE or its direct vulnerability class
4. If this is a Exim-specific CVE, do NOT suggest smtp scripts that test other MTA products
5. Prefer scripts with the CVE number in their name (e.g. http-vuln-cve2024-23897)
6. If no script in the list specifically addresses this CVE, reply: none

Reply format — one line, nothing else:
script_name_here"""

    try:
        import google.generativeai as genai
        from google.generativeai.types import GenerationConfig

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(
            GEMINI_MODEL,
            generation_config=GenerationConfig(
                max_output_tokens=40,      # script name only
                temperature=0.0,           # deterministic
                candidate_count=1,
            )
        )

        response = model.generate_content(
            prompt,
            request_options={"timeout": timeout_seconds},
        )

        raw = response.text.strip().lower().replace('"', '').replace("'", "").strip()

        # Strip any accidental prefix (model sometimes returns "script: xxx")
        if ":" in raw:
            raw = raw.split(":")[-1].strip()

        if raw == "none" or not raw:
            return None, f"Gemini found no matching script for {cve_id}"

        # Validate: must be in the available list
        if raw in available_scripts:
            logger.info("Gemini selected script %r for %s", raw, cve_id)
            return raw, f"Gemini 2.0 Flash: {raw} selected for {cve_id}"

        # Try partial match (model may have trimmed a prefix)
        for s in available_scripts:
            if raw in s or s.endswith(raw):
                logger.info("Gemini partial match %r → %r for %s", raw, s, cve_id)
                return s, f"Gemini 2.0 Flash (partial match): {s} for {cve_id}"

        logger.warning(
            "Gemini returned %r for %s — not in available scripts, discarding",
            raw, cve_id
        )
        return None, f"Gemini suggestion '{raw}' not found in available scripts"

    except Exception as exc:
        logger.warning("Gemini API call failed for %s: %s", cve_id, exc)
        return None, f"Gemini error: {exc}"
