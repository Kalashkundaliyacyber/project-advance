"""
ThreatWeave — Patch Generator v6.1 (Phase 5/23)
================================================
Intelligent local-first remediation workflow:
  1. Patch Knowledge Base (instant, 0 AI calls) — confidence 100/90/70
  2. CVE Cache Engine     (local DB lookup)
  3. DeepSeek R1          (deep security analysis)
  4. Qwen 2.5 7B          (general reasoning)
  5. Llama 3.1 8B         (general fallback)
  6. Rule Engine          (always works offline)

Target: 80%+ reduction in AI calls via KB + cache hits.

FIXED v6.1:
  - BUG-1: build_patch_prompt() was called with positional args in wrong order
    (cve_id was passed as service, service as port, etc.).
    Fixed by switching to explicit keyword arguments.
"""
import json
import logging
import time
from typing import Optional

from app.ai.providers.qwen_provider       import qwen_provider
from app.ai.providers.llama_provider      import llama_provider
from app.ai.providers.deepseek_provider   import deepseek_provider
from app.ai.remediation.remediation_templates import build_patch_response
from app.ai.remediation.prompt_builder        import build_patch_prompt, build_group_patch_prompt
from app.ai.remediation.remediation_cache     import get_cached, set_cached
from app.ai.remediation.patch_knowledge_base  import patch_kb, CONFIDENCE_VENDOR, CONFIDENCE_NVD, CONFIDENCE_AI
from app.ai.cache.ai_response_cache           import ai_response_cache
from app.ai.utils.json_sanitizer              import safe_parse_json
from app.ai.utils.logging_utils               import log_provider_call

logger = logging.getLogger("ThreatWeave.ai.patch_generator")

SYSTEM_PROMPT = (
    "You are a cybersecurity patch guidance specialist. "
    "Return ONLY valid JSON matching the requested schema. "
    "No markdown fences. No preamble. No explanation text."
)


def generate_patch(cve_id: str, service: str, version: str,
                   description: str = "", extra_context: dict = None) -> dict:
    """
    Generate patch guidance for a CVE.
    Returns dict with patch commands, confidence, source.
    """
    _port     = (extra_context or {}).get("port", 0)
    _severity = (extra_context or {}).get("severity", "medium")
    _os_hint  = (extra_context or {}).get("os_hint", "ubuntu")

    # ── Step 1: Patch Knowledge Base (zero AI calls) ──────────────────────────
    kb_entry = patch_kb.lookup_cve(cve_id)
    if kb_entry and kb_entry.get("confidence", 0) >= CONFIDENCE_NVD:
        logger.info("Patch KB hit for %s (confidence=%d, source=%s)",
                    cve_id, kb_entry["confidence"], kb_entry.get("source"))
        return {**kb_entry, "from_kb": True, "ai_called": False}

    # ── Step 2: Remediation cache ─────────────────────────────────────────────
    cached = get_cached(service, _port, version, cve_id, _severity)
    if cached:
        logger.info("Remediation cache hit for %s:%s:%s", cve_id, service, version)
        return {**cached, "from_cache": True, "ai_called": False}

    # ── Step 3: AI cache (response-level cache) ───────────────────────────────
    # BUG-1 FIX: use keyword arguments — previous code passed positional args
    # in wrong order: build_patch_prompt(cve_id, service, version, ...) but
    # signature is (service, port, version, cve_id, severity).
    prompt = build_patch_prompt(
        service=service,
        port=_port,
        version=version,
        cve_id=cve_id,
        severity=_severity,
    )
    ai_cached = ai_response_cache.get(prompt, model="patch")
    if ai_cached:
        parsed = safe_parse_json(ai_cached) or {}
        if parsed:
            parsed.update({"from_ai_cache": True, "ai_called": False, "confidence": CONFIDENCE_AI})
            return parsed

    # ── Step 4: AI generation chain ───────────────────────────────────────────
    result = None

    # DeepSeek R1 first for security analysis
    if deepseek_provider.is_available():
        result = _try_provider("deepseek", deepseek_provider, prompt)

    # Qwen fallback
    if not result and qwen_provider.is_available():
        result = _try_provider("qwen", qwen_provider, prompt)

    # Llama fallback
    if not result and llama_provider.is_available():
        result = _try_provider("llama", llama_provider, prompt)

    # Rule engine last resort
    if not result:
        logger.warning("All AI providers failed for %s — using rule engine", cve_id)
        result = build_patch_response(
            service=service,
            port=_port,
            version=version,
            cve_id=cve_id,
            severity=_severity,
            os_hint=_os_hint,
        )
        result["ai_called"]  = False
        result["confidence"] = 30
        result["source"]     = "rule_engine"
        result["engine"]     = "rule-engine-fallback"

    # ── Step 5: Cache every result ────────────────────────────────────────────
    try:
        ai_response_cache.set(prompt, json.dumps(result), model="patch")
    except Exception as _e:
        logger.debug("ai_response_cache.set failed: %s", _e)

    try:
        set_cached(service, _port, version, cve_id, _severity, result)
    except Exception as _e:
        logger.debug("set_cached failed: %s", _e)

    try:
        patch_kb.save_patch(
            cve_id,
            {**result, "service": service},
            source=result.get("source", "rule_engine"),
            confidence=result.get("confidence", 30),
        )
    except Exception as _e:
        logger.debug("patch_kb.save_patch failed: %s", _e)

    if result.get("ai_called") is not False:
        result["ai_called"] = True
    return result


def generate_group_patches(vulnerabilities: list) -> dict:
    """
    Generate patches for multiple CVEs efficiently.
    Groups by service to minimize AI calls.
    """
    results = {}
    kb_hits  = []
    ai_queue = []

    for vuln in vulnerabilities:
        cve_id = vuln.get("cve_id", "")
        if not cve_id:
            continue
        kb_entry = patch_kb.lookup_cve(cve_id)
        if kb_entry:
            results[cve_id] = kb_entry
            kb_hits.append(cve_id)
        else:
            ai_queue.append(vuln)

    logger.info("Group patch: %d KB hits, %d need AI", len(kb_hits), len(ai_queue))

    for vuln in ai_queue:
        cve_id  = vuln.get("cve_id", "")
        service = vuln.get("service", "")
        version = vuln.get("version", "")
        desc    = vuln.get("description", "")
        results[cve_id] = generate_patch(cve_id, service, version, desc)

    return results


# ── Internal helpers ───────────────────────────────────────────────────────────

def _try_provider(name: str, provider, prompt: str) -> Optional[dict]:
    t0 = time.time()
    try:
        raw    = provider.generate(prompt, system=SYSTEM_PROMPT,
                                   expect_json=True, max_tokens=1024)
        parsed = safe_parse_json(raw)
        if not parsed:
            return None
        latency = int((time.time() - t0) * 1000)
        log_provider_call(name, True, latency)
        parsed["provider"]   = name
        parsed["confidence"] = CONFIDENCE_AI
        parsed["ai_called"]  = True
        return parsed
    except Exception as e:
        latency = int((time.time() - t0) * 1000)
        log_provider_call(name, False, latency, reason=str(e)[:80])
        logger.warning("Patch provider %s failed: %s", name, e)
        return None


# ── Backward-compatibility aliases ────────────────────────────────────────────

def get_patch_guidance(service: str, port: int, version: str = "unknown",
                       cve_id: str = "unknown", severity: str = "medium",
                       session_id: str = "", os_hint: str = "ubuntu") -> dict:
    """Backward-compatible wrapper around generate_patch()."""
    description = f"{service} {version} on port {port} (severity: {severity})"
    result = generate_patch(cve_id, service, version, description,
                            extra_context={"port": port, "severity": severity, "os_hint": os_hint})
    return _normalize_compat(result, service, port, version, cve_id, severity)


def get_group_patch_guidance(service: str, group_summary: dict) -> dict:
    """Backward-compatible group patch wrapper."""
    vulns = group_summary.get("vulnerabilities", [])
    results = generate_group_patches(vulns)
    return {
        "service":   service,
        "patches":   results,
        "count":     len(results),
        "from_kb":   any(v.get("from_kb") for v in results.values()),
        "ai_called": any(v.get("ai_called") for v in results.values()),
    }


def _normalize_compat(result: dict, service: str, port: int,
                       version: str, cve_id: str, severity: str) -> dict:
    """Ensure result has all fields callers expect."""
    return {
        "service":          service,
        "port":             port,
        "version":          version,
        "cve_id":           cve_id,
        "severity":         severity,
        "patch_commands":   result.get("commands") or result.get("patch_commands") or {},
        "vendor_url":       result.get("vendor_url", ""),
        "mitigation":       result.get("mitigation", ""),
        "fix_version":      result.get("fix_version", "latest"),
        "title":            result.get("title", f"Patch {service} {version}"),
        "confidence":       result.get("confidence", 70),
        "source":           result.get("source", "ai"),
        "from_kb":          result.get("from_kb", False),
        "from_cache":       result.get("from_cache", False),
        "ai_called":        result.get("ai_called", False),
        "provider":         result.get("provider", ""),
    }
