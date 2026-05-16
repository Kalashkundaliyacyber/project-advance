"""
ScanWise AI — Patch Generator v3.0
Orchestrates AI fallback chain for patch guidance.

Architecture (Llama 3B removed):
  1. Qwen2.5-Coder 3B  (PRIMARY — all structured reasoning)
  2. Gemini             (CLOUD BACKUP)
  3. Rule engine        (FINAL FALLBACK — always works offline)

Features:
- Request deduplication
- Response caching
- Timeout + retry (via provider layer)
- JSON sanitization with bracket balancing
- OLLAMA_KEEP_ALIVE=0 hint passed in payloads to free VRAM after use
- Max concurrent = 1 for Patch All (configurable via AI_MAX_CONCURRENT)
"""
import logging
import time
from typing import Optional

from app.ai.providers.qwen_provider   import qwen_provider
from app.ai.providers.gemini_provider import gemini_provider, GeminiQuotaError, GeminiSafetyBlock
from app.ai.remediation.remediation_templates import build_patch_response
from app.ai.remediation.prompt_builder import build_patch_prompt, build_group_patch_prompt
from app.ai.remediation.remediation_cache import get_cached, set_cached
from app.ai.utils.json_sanitizer import safe_parse_json
from app.ai.utils.logging_utils import log_provider_call
from app.ai.remediation.knowledge_base import get_cve_remediation, get_cis_rules

logger = logging.getLogger("scanwise.ai.patch_generator")

QWEN_TIMEOUT   = 120   # seconds — generous for cold Ollama load
GEMINI_TIMEOUT = 30


def get_patch_guidance(
    service: str,
    port: int,
    version: str = "unknown",
    cve_id: str = "unknown",
    severity: str = "medium",
    os_hint: str = "ubuntu",
) -> dict:
    """
    Get AI patch guidance for a service/CVE.
    Tries Qwen → Gemini → Rule engine.
    Always returns a usable dict.
    """
    # Knowledge base lookup first (instant, no AI call needed for known CVEs)
    if cve_id and cve_id not in ("unknown", ""):
        kb_result = get_cve_remediation(cve_id)
        if kb_result:
            kb_result["service"] = service
            kb_result["port"] = port
            kb_result["cis_rules"] = get_cis_rules(service)
            kb_result["engine"] = "knowledge-base"
            log_provider_call("cache", True, 0, cache_hit=True)
            return kb_result

    # Cache check
    cached = get_cached(service, port, version, cve_id, severity)
    if cached is not None:
        log_provider_call("cache", True, 0, cache_hit=True)
        cached["from_cache"] = True
        return cached

    prompt = build_patch_prompt(service, port, version, cve_id, severity)
    system = (
        "You are a cybersecurity patch guidance specialist. "
        "Return ONLY valid JSON matching the requested schema. "
        "No markdown fences. No preamble. No explanation text. "
        "Respond with a single JSON object only."
    )

    result = None

    # ── Attempt 1: Qwen (PRIMARY) ──────────────────────────────────────────
    if qwen_provider.is_available():
        result = _try_provider(
            name="qwen",
            fn=lambda: qwen_provider.generate(
                prompt, system=system, expect_json=True, max_tokens=800
            ),
        )

    # ── Attempt 2: Gemini (CLOUD BACKUP) ──────────────────────────────────
    if result is None and gemini_provider.is_available():
        result = _try_gemini(prompt, system)

    # ── Attempt 3: Rule engine (ALWAYS WORKS) ─────────────────────────────
    if result is None:
        logger.warning(
            "All AI providers failed for %s:%d — using rule engine", service, port
        )
        result = build_patch_response(service, port, version, cve_id, severity, os_hint)
        result["engine"] = "rule-based-fallback"

    # Cache successful AI result (not rule-based)
    if not result.get("engine", "").startswith("rule"):
        set_cached(service, port, version, cve_id, severity, result)

    return result


def get_group_patch_guidance(service: str, group_summary: dict) -> dict:
    """
    Get consolidated patch guidance for a service group.
    Uses Qwen (best for structured reasoning).
    """
    top_cve  = (group_summary.get("cves") or [{}])[0]
    cve_id   = top_cve.get("cve_id", "unknown")
    version  = (group_summary.get("versions") or ["unknown"])[0]
    severity = group_summary.get("severity", "medium")
    port     = (group_summary.get("ports") or [0])[0]

    cached = get_cached(service, port, version, cve_id, severity)
    if cached is not None:
        cached["from_cache"] = True
        return cached

    prompt = build_group_patch_prompt(service, group_summary)
    system = (
        "You are a cybersecurity patch guidance specialist. "
        "Return ONLY valid JSON matching the requested schema. No markdown."
    )

    result = None

    if qwen_provider.is_available():
        result = _try_provider(
            name="qwen",
            fn=lambda: qwen_provider.generate(
                prompt, system=system, expect_json=True, max_tokens=1000
            ),
        )

    if result is None and gemini_provider.is_available():
        result = _try_gemini(prompt, system)

    if result is None:
        result = build_patch_response(service, port, version, cve_id, severity)
        result["engine"] = "rule-based-fallback"

    if not result.get("engine", "").startswith("rule"):
        set_cached(service, port, version, cve_id, severity, result)

    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

def _try_provider(name: str, fn) -> Optional[dict]:
    """Attempt a provider call. Returns parsed dict or None."""
    t0 = time.time()
    try:
        text    = fn()
        latency = int((time.time() - t0) * 1000)

        parsed = safe_parse_json(text)
        if isinstance(parsed, dict) and parsed:
            parsed["engine"] = name
            log_provider_call(name, True, latency)
            logger.info("Patch guidance via %s in %dms", name, latency)
            return parsed

        logger.warning("%s returned unparseable JSON: %s", name, (text or "")[:200])
        log_provider_call(name, False, latency, reason="invalid_json")
        return None

    except Exception as e:
        latency = int((time.time() - t0) * 1000)
        log_provider_call(name, False, latency, reason=str(e)[:80])
        logger.warning("%s provider failed: %s", name, e)
        return None


def _try_gemini(prompt: str, system: str) -> Optional[dict]:
    """Try Gemini as cloud backup."""
    t0 = time.time()
    try:
        text    = gemini_provider.generate(prompt, system=system,
                                           expect_json=True, max_tokens=800)
        latency = int((time.time() - t0) * 1000)
        parsed  = safe_parse_json(text)
        if isinstance(parsed, dict) and parsed:
            parsed["engine"] = "gemini"
            log_provider_call("gemini", True, latency)
            return parsed
        log_provider_call("gemini", False, latency, reason="invalid_json")
        return None
    except GeminiQuotaError as e:
        latency = int((time.time() - t0) * 1000)
        log_provider_call("gemini", False, latency, reason="quota_exceeded")
        logger.warning("Gemini quota exceeded: %s", e)
        return None
    except Exception as e:
        latency = int((time.time() - t0) * 1000)
        log_provider_call("gemini", False, latency, reason=str(e)[:80])
        logger.warning("Gemini backup failed: %s", e)
        return None
