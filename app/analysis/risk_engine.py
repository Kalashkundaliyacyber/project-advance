"""
Risk Prioritization Engine — v2.0
Weighted score → Low / Medium / High / Critical.

FIX6: Weights are now configurable via:
  1. config/settings.yaml  (risk_weights section)
  2. Environment variables  WEIGHT_CVSS, WEIGHT_CRIT, WEIGHT_VER, WEIGHT_EXP
  3. Live override via _set_weights() for experiment/research comparisons
Hardcoded 40/25/20/15 split replaced with dynamic loading at import time.
"""
import os
import logging

logger = logging.getLogger("scanwise.risk_engine")

CRITICALITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2}
VERSION_RISK_WEIGHT = {"high": 8, "medium": 5, "low": 1}
EXPOSURE_WEIGHT     = {"high": 8, "medium": 5, "low": 2, "none": 0}


def _load_weights() -> dict:
    """
    FIX6: Load risk weights from environment vars, then settings.yaml, then defaults.
    Priority: ENV > config file > hardcoded defaults.
    """
    defaults = {"cvss": 0.40, "criticality": 0.25, "version": 0.20, "exposure": 0.15}

    # 1. Try environment variables
    env_keys = {"WEIGHT_CVSS": "cvss", "WEIGHT_CRIT": "criticality",
                 "WEIGHT_VER": "version", "WEIGHT_EXP": "exposure"}
    loaded = dict(defaults)
    for env_k, weight_k in env_keys.items():
        val = os.environ.get(env_k)
        if val:
            try:
                loaded[weight_k] = float(val)
            except ValueError:
                logger.warning("Invalid %s=%s, using default", env_k, val)

    # 2. Try settings.yaml
    try:
        import yaml, os as _os
        cfg_path = _os.path.join(
            _os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))),
            "config", "settings.yaml"
        )
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        rw = cfg.get("risk_weights", {})
        for k in defaults:
            if k in rw:
                try:
                    loaded[k] = float(rw[k])
                except (ValueError, TypeError):
                    pass
    except Exception:
        pass  # yaml or file not available — use env/defaults

    # Normalise so weights sum to 1.0 (prevents misconfiguration breaking scores)
    total = sum(loaded.values())
    if total > 0 and abs(total - 1.0) > 0.01:
        loaded = {k: round(v / total, 4) for k, v in loaded.items()}
        logger.debug("FIX6: normalised risk weights to sum=1.0: %s", loaded)

    return loaded


# Module-level weights — loaded once at startup, overridable per-experiment
_WEIGHTS = _load_weights()


def _set_weights(cvss=None, criticality=None, version=None, exposure=None):
    """
    FIX6: Override weights at runtime for ablation / experiment comparisons.
    Call this before running a scan to use custom weights for that analysis.
    Example: risk_engine._set_weights(cvss=0.6, criticality=0.2, version=0.1, exposure=0.1)
    """
    global _WEIGHTS
    if cvss is not None:        _WEIGHTS["cvss"]        = float(cvss)
    if criticality is not None: _WEIGHTS["criticality"] = float(criticality)
    if version is not None:     _WEIGHTS["version"]     = float(version)
    if exposure is not None:    _WEIGHTS["exposure"]    = float(exposure)
    # Re-normalise
    total = sum(_WEIGHTS.values())
    if total > 0:
        _WEIGHTS = {k: round(v / total, 4) for k, v in _WEIGHTS.items()}
    logger.info("FIX6: risk weights updated to %s", _WEIGHTS)


def get_weights() -> dict:
    """Return current active weights (for UI display / export)."""
    return dict(_WEIGHTS)


def calculate_risk(context_data: dict) -> dict:
    result = dict(context_data)
    for host in result.get("hosts", []):
        host_exposure = host.get("context", {}).get("exposure", "medium")
        port_levels   = []
        for port in host.get("ports", []):
            port["risk"] = _calculate_port_risk(port, host_exposure)
            port_levels.append(port["risk"]["level"])
        host["risk_summary"] = _host_risk_summary(port_levels)
    return result


def _calculate_port_risk(port: dict, host_exposure: str) -> dict:
    cves       = port.get("cves", [])
    context    = port.get("context", {})
    va         = port.get("version_analysis", {})

    max_cvss   = max((c["cvss_score"] for c in cves), default=0.0)
    crit_score = CRITICALITY_WEIGHT.get(context.get("criticality", "low"), 2)
    ver_score  = VERSION_RISK_WEIGHT.get(context.get("version_risk", "medium"), 5)
    exp_score  = EXPOSURE_WEIGHT.get(host_exposure, 5)

    # FIX6: use configurable weights instead of hardcoded 0.40/0.25/0.20/0.15
    w = _WEIGHTS
    raw = (max_cvss   * w["cvss"]
           + crit_score * w["criticality"] * 10   # scale 0-10 like cvss
           + ver_score  * w["version"]     * 10
           + exp_score  * w["exposure"]    * 10) / 10

    # CVSS floor rules — high CVSS must never map to medium/low regardless of weights
    # This ensures real-world severity standards are upheld even with custom weight configs
    if max_cvss >= 10.0:
        raw = max(raw, 8.5)    # CVSS 10.0 → always critical
    elif max_cvss >= 9.0:
        raw = max(raw, 6.5)    # CVSS 9.x  → always at least high
    elif max_cvss >= 7.0:
        raw = max(raw, 4.0)    # CVSS 7–9  → always at least medium

    score = round(min(raw, 10.0), 1)
    level = _score_to_level(score)

    return {
        "score":    score,
        "level":    level,
        "max_cvss": max_cvss,
        "cve_count": len(cves),
        "reasons":  _build_reasons(max_cvss, context.get("criticality", "low"), va, host_exposure, len(cves)),
        "color":    _level_color(level),
        "weights_used": dict(w),   # FIX6: include weights in output for research traceability
    }


def _score_to_level(score: float) -> str:
    if score >= 8.5: return "critical"
    if score >= 6.5: return "high"
    if score >= 4.0: return "medium"
    return "low"


def _level_color(level: str) -> str:
    return {"critical": "#E24B4A", "high": "#EF9F27",
            "medium": "#378ADD", "low": "#1D9E75"}.get(level, "#888780")


def _build_reasons(cvss, criticality, va, exposure, cve_count) -> list:
    reasons = []
    if cvss >= 9.0:
        reasons.append(f"Critical CVSS score of {cvss} — severe vulnerability present")
    elif cvss >= 7.0:
        reasons.append(f"High CVSS score of {cvss}")
    elif cvss > 0:
        reasons.append(f"CVSS score of {cvss}")
    if criticality in ("critical", "high"):
        reasons.append(f"Service criticality is {criticality}")
    status = va.get("status", "unknown")
    if status == "unsupported":
        reasons.append("Running an end-of-life version with no security patches")
    elif status == "outdated":
        age = va.get("age_years")
        reasons.append(f"Version is outdated" + (f" ({age} years old)" if age else ""))
    if exposure in ("high", "medium"):
        reasons.append(f"Host has {exposure} overall exposure")
    if cve_count >= 3:
        reasons.append(f"{cve_count} known CVEs mapped to this service")
    elif cve_count > 0:
        reasons.append(f"{cve_count} known CVE(s) mapped")
    if not reasons:
        reasons.append("No significant risk factors identified")
    return reasons


def _host_risk_summary(port_levels: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for lvl in port_levels:
        if lvl in counts:
            counts[lvl] += 1
    if counts["critical"] > 0:   overall = "critical"
    elif counts["high"] > 0:     overall = "high"
    elif counts["medium"] > 0:   overall = "medium"
    else:                        overall = "low"
    return {
        "overall":     overall,
        "counts":      counts,
        "total_ports": len(port_levels),
        "color":       _level_color(overall),
    }
