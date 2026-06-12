"""
ThreatWeave AI — AI Patch Generator (Layer 4)
===========================================
Last resort in the 4-layer chain. Only called when:
  Layer 1 (Local Repository) → MISS
  Layer 2 (Vendor Advisory)  → MISS
  Layer 3 (NVD Cache)        → MISS

Uses provider chain: DeepSeek R1 → Qwen 2.5 → Llama 3.1 → Rule Engine

CHANGES v2:
  - Added os_hint param (default "ubuntu") — passed through to build_ai_prompt()
    so the AI generates OS-specific shell commands.
    All existing callers that omit os_hint get "ubuntu" commands unchanged.
  - _rule_engine_fallback() now also accepts os_hint to pick the right package
    manager command in the rule-based fallback.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from .ai_patch_cache     import ai_patch_cache
from .ai_patch_validator import validate_ai_patch, sanitize_ai_patch
from .ai_patch_formatter import format_ai_patch, build_ai_prompt

logger = logging.getLogger("threatweave.remediation.ai_generator")

_SYSTEM_PROMPT = (
    "You are a cybersecurity patch specialist. "
    "Return ONLY valid JSON matching the requested schema. "
    "No markdown fences. No preamble. No explanation text."
)

CONFIDENCE_AI   = 70
CONFIDENCE_RULE = 30

_REQUIRED_PATCH_FIELDS = {
    "patch_command", "upgrade_path",
    "verification_steps", "rollback_steps",
}

_PATCH_PROMPT_TEMPLATE = """{base_prompt}

Return ONLY this JSON schema (no markdown):
{{
  "patch_command": "<single shell command for {os_hint} to apply the patch>",
  "upgrade_path": "<version upgrade instructions, e.g. upgrade X to Y>",
  "verification_steps": ["<step 1>", "<step 2>"],
  "rollback_steps": ["<step 1>", "<step 2>"],
  "patch_type": "<upgrade|config|workaround|unknown>",
  "notes": "<any important warnings or prerequisites>",
  "confidence": <integer 0-100>,
  "source": "ai"
}}"""


def generate_ai_patch(
    cve_id:      str,
    service:     str,
    version:     str,
    description: str = "",
    os_hint:     str = "ubuntu",
) -> dict:
    """
    Generate patch guidance via AI (Layer 4 — last resort).
    Checks ai_patch_cache first. Tries providers in order.
    Stores result in cache + learning KB.

    Args:
        cve_id:      CVE identifier
        service:     Service/product name
        version:     Affected version
        description: CVE description for AI context
        os_hint:     Target OS — "ubuntu" | "rhel" | "arch" (default "ubuntu").
                     Existing callers that omit this get ubuntu commands unchanged.

    Returns:
        Structured patch dict with patch_command, upgrade_path,
        verification_steps, rollback_steps, patch_type, notes,
        confidence, source, layer, ai_called.
    """
    cve_id = cve_id.upper()

    # 1. AI cache check
    cached = ai_patch_cache.get(cve_id, service, version)
    if cached:
        logger.debug("[LAYER4] AI cache hit for %s", cve_id)
        cached.update({"ai_called": False, "from_ai_cache": True, "layer": "ai"})
        return cached

    # 2. Build enriched prompt with os_hint
    base_prompt = build_ai_prompt(cve_id, service, version, description, os_hint=os_hint)
    prompt = _PATCH_PROMPT_TEMPLATE.format(base_prompt=base_prompt, os_hint=os_hint)

    # 3. Try AI providers in priority order with confidence decay
    result = None
    current_confidence = CONFIDENCE_AI

    for name, provider in _get_providers():
        result = _try_provider(name, provider, prompt, cve_id, service)
        if result:
            result = _validate_and_fill(result, cve_id, service, version)
            result["confidence"] = current_confidence
            break
        current_confidence = max(CONFIDENCE_RULE, current_confidence - 5)

    # 4. Rule engine fallback
    if not result:
        logger.warning("[LAYER4] All AI providers failed for %s — using rule engine", cve_id)
        result = _rule_engine_fallback(cve_id, service, version, os_hint=os_hint)
        result["ai_called"]        = False
        result["validation_status"] = "rule_based"

    # 5. Cache and save to learning KB
    ai_patch_cache.set(cve_id, result, service, version)
    _save_to_learning_kb(cve_id, service, result)

    return result


# ── Field validation ───────────────────────────────────────────────────────────

def _validate_and_fill(result: dict, cve_id: str, service: str, version: str) -> dict:
    """
    Ensure all required fields are present.
    Fills missing fields with safe defaults rather than returning broken result.
    """
    if not result.get("patch_command"):
        result["patch_command"] = f"# Apply latest security update for {service}"

    if not result.get("upgrade_path"):
        result["upgrade_path"] = f"Upgrade {service} from {version} to latest stable release."

    if not result.get("verification_steps") or not isinstance(result["verification_steps"], list):
        result["verification_steps"] = [
            f"Verify {service} version: {service} --version",
            "Check vendor advisory for confirmation of patched version.",
        ]

    if not result.get("rollback_steps") or not isinstance(result["rollback_steps"], list):
        result["rollback_steps"] = [
            f"Reinstall previous version of {service} from package cache.",
            "Restore from backup if service is critical.",
        ]

    if not result.get("patch_type"):
        result["patch_type"] = "upgrade"

    result["layer"]            = "ai"
    result["ai_called"]        = True
    result["validation_status"] = "validated"
    return result


# ── Internal helpers ───────────────────────────────────────────────────────────

def _get_providers():
    """Yield (name, provider_object) in priority order."""
    try:
        from app.ai.providers.deepseek_provider import deepseek_provider
        yield "deepseek", deepseek_provider
    except ImportError:
        pass  # provider not installed — expected
    except Exception as exc:
        logger.warning("_get_providers: unexpected error loading deepseek_provider: %s", exc)
    try:
        from app.ai.providers.qwen_provider import qwen_provider
        yield "qwen", qwen_provider
    except ImportError:
        pass  # provider not installed — expected
    except Exception as exc:
        logger.warning("_get_providers: unexpected error loading qwen_provider: %s", exc)
    try:
        from app.ai.providers.llama_provider import llama_provider
        yield "llama", llama_provider
    except ImportError:
        pass  # provider not installed — expected
    except Exception as exc:
        logger.warning("_get_providers: unexpected error loading llama_provider: %s", exc)


def _try_provider(
    name:    str,
    provider,
    prompt:  str,
    cve_id:  str,
    service: str,
) -> Optional[dict]:
    if not provider.is_available():
        return None
    try:
        text = provider.generate(prompt, system=_SYSTEM_PROMPT, max_tokens=600)
        from app.ai.utils.json_sanitizer import safe_parse_json
        result = safe_parse_json(text)
        if not isinstance(result, dict) or not result.get("patch_command"):
            return None
        result["engine"] = name
        logger.info("[LAYER4] Patch generated for %s via %s", cve_id, name)
        return result
    except Exception as e:
        logger.debug("[LAYER4] Provider %s failed for %s: %s", name, cve_id, e)
        return None


def _save_to_learning_kb(cve_id: str, service: str, result: dict) -> None:
    try:
        from app.remediation.learning.knowledge_base import learning_kb
        learning_kb.store(cve_id, service, result)
    except Exception as e:
        logger.debug("Learning KB store failed: %s", e)


def _rule_engine_fallback(
    cve_id:  str,
    service: str,
    version: str,
    os_hint: str = "ubuntu",
) -> dict:
    """
    Rule engine fallback.
    Now OS-aware: selects the correct package manager command based on os_hint.
    Includes all required fields: verification_steps, rollback_steps, patch_type.
    """
    svc = service.lower()

    # OS-aware package manager command
    _os = os_hint.lower()
    if _os in ("rhel", "centos", "fedora"):
        pkg_cmd = f"sudo dnf upgrade {svc} -y"
        rollback_cmd = f"sudo dnf downgrade {svc} -y"
    elif _os == "arch":
        pkg_cmd = f"sudo pacman -Syu {svc} --noconfirm"
        rollback_cmd = f"sudo pacman -U /var/cache/pacman/pkg/{svc}-*.pkg.tar.zst"
    else:  # ubuntu / debian default
        pkg_cmd = f"sudo apt-get update && sudo apt-get install --only-upgrade {svc} -y"
        rollback_cmd = f"sudo apt-get install {svc}=<previous_version>"

    return {
        "patch_command":     pkg_cmd,
        "commands": {
            "ubuntu/debian": f"sudo apt-get update && sudo apt-get install --only-upgrade {svc} -y",
            "rhel/centos":   f"sudo dnf upgrade {svc} -y",
            "arch":          f"sudo pacman -Syu {svc} --noconfirm",
        },
        "upgrade_path":      f"Upgrade {service} from {version} to the latest patched version.",
        "verification_steps": [
            f"{service} --version  (confirm version is ≥ patched release)",
            "Restart service and verify functionality.",
            f"Check CVE {cve_id} at https://nvd.nist.gov/vuln/detail/{cve_id} for fix confirmation.",
        ],
        "rollback_steps": [
            rollback_cmd,
            "Restore configuration from backup if available.",
        ],
        "patch_type":        "upgrade",
        "notes":             f"Rule-based guidance for {cve_id}. Verify against vendor advisory.",
        "confidence":        CONFIDENCE_RULE,
        "source":            "rule_engine",
        "engine":            "rule_engine_fallback",
        "layer":             "ai",
        "ai_called":         False,
        "validation_status": "rule_based",
    }
