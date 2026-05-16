"""
ScanWise AI — Response Parser
Validates, normalises, and repairs AI provider JSON responses.
Ensures downstream consumers always get a conformant schema.
"""
import json
import re
import logging
from typing import Any, Optional

logger = logging.getLogger("scanwise.response_parser")

# Required top-level keys for a valid scan analysis response
REQUIRED_KEYS = {"summary", "risk_level", "cves", "recommendations", "ports"}

# Severity normalisation map
_SEV_NORM = {
    "crit":     "critical",
    "critical": "critical",
    "high":     "high",
    "med":      "medium",
    "medium":   "medium",
    "low":      "low",
    "info":     "low",
    "none":     "low",
}


def parse_and_validate(raw: str) -> dict:
    """
    Parse a raw AI response string into a validated dict.
    Steps:
      1. Strip markdown fences
      2. Parse JSON
      3. Validate required fields
      4. Normalise fields (severity, cvss, etc.)
      5. Fill defaults for missing optional fields
    Raises ValueError if the JSON cannot be recovered at all.
    """
    text = _strip_fences(raw)
    data = _parse_json(text)
    data = _normalise(data)
    data = _fill_defaults(data)
    return data


def validate_schema(data: dict) -> tuple[bool, list[str]]:
    """
    Return (is_valid, [list of issues]).
    Does not raise — safe to call for logging.
    """
    issues = []
    for k in REQUIRED_KEYS:
        if k not in data:
            issues.append(f"Missing required key: '{k}'")

    cves = data.get("cves", [])
    if not isinstance(cves, list):
        issues.append("'cves' must be a list")

    recs = data.get("recommendations", [])
    if not isinstance(recs, list):
        issues.append("'recommendations' must be a list")

    rl = data.get("risk_level", "")
    if rl and rl not in ("critical", "high", "medium", "low"):
        issues.append(f"'risk_level' has unexpected value: '{rl}'")

    return (len(issues) == 0), issues


def repair_partial(data: dict) -> dict:
    """
    Attempt to repair a partially-valid dict so it conforms to the
    expected schema.  Always returns a dict — never raises.
    """
    try:
        return _fill_defaults(_normalise(data))
    except Exception as e:
        logger.warning("repair_partial failed: %s — returning safe stub", e)
        return _safe_stub()


# ── Internal helpers ─────────────────────────────────────────────────────────

def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    return text.strip()


def _parse_json(text: str) -> Any:
    """Try multiple recovery strategies before giving up."""
    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: extract first { ... } block
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass

    # Strategy 3: remove trailing commas (common LLM mistake)
    cleaned = re.sub(r',\s*([}\]])', r'\1', text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    raise ValueError(
        f"Cannot parse response as JSON after 3 recovery attempts. "
        f"First 200 chars: {text[:200]}"
    )


def _normalise(data: dict) -> dict:
    """Normalise field values to expected formats."""
    if not isinstance(data, dict):
        return data

    # Normalise top-level risk_level
    rl = str(data.get("risk_level", "")).lower()
    data["risk_level"] = _SEV_NORM.get(rl, "low")

    # Normalise overall_risk alias
    if "overall_risk" in data:
        or_ = str(data["overall_risk"]).lower()
        data["overall_risk"] = _SEV_NORM.get(or_, "low")

    # Normalise CVE entries
    for cve in data.get("cves", []):
        if not isinstance(cve, dict):
            continue
        sev = str(cve.get("severity", "")).lower()
        cve["severity"] = _SEV_NORM.get(sev, "low")
        # Clamp CVSS
        score = cve.get("cvss_score", 0)
        try:
            cve["cvss_score"] = round(min(max(float(score), 0.0), 10.0), 1)
        except (TypeError, ValueError):
            cve["cvss_score"] = 0.0

    return data


def _fill_defaults(data: dict) -> dict:
    """Fill in missing required keys with safe defaults."""
    data.setdefault("summary", "Analysis complete.")
    data.setdefault("risk_level", "low")
    data.setdefault("cves", [])
    data.setdefault("recommendations", [])
    data.setdefault("ports", [])
    return data


def _safe_stub() -> dict:
    return {
        "summary":         "Analysis unavailable — AI provider error.",
        "risk_level":      "low",
        "cves":            [],
        "recommendations": [{"action": "Re-run scan to generate fresh analysis.", "priority": "low"}],
        "ports":           [],
    }

