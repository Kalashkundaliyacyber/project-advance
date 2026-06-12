"""
ThreatWeave — Explainable Risk Score Engine (Phase 8)
=====================================================
Every risk score comes with a plain-English breakdown showing
EXACTLY how the score was calculated. No black-box numbers.

Risk Score = (CVSS × 0.40) + (Criticality × 0.25) + (Version × 0.20) + (Exposure × 0.15)
"""
import logging
from typing import Optional

logger = logging.getLogger("ThreatWeave.explainable_risk")

WEIGHTS = {"cvss": 0.40, "criticality": 0.25, "version": 0.20, "exposure": 0.15}

CVSS_BUCKETS   = [(9.0, 100, "Critical CVSS"), (7.0, 75, "High CVSS"),
                  (4.0, 50, "Medium CVSS"),   (0.1, 25, "Low CVSS"), (0.0, 0, "No CVSS")]
CRIT_MAP       = {"critical": 100, "high": 75, "medium": 50, "low": 25}
VERSION_MAP    = {"high": 100, "medium": 60, "low": 20, "unknown": 40}
EXPOSURE_MAP   = {"high": 100, "medium": 60, "low": 20, "none": 0}

LEVEL_THRESHOLDS = [(80, "critical"), (60, "high"), (35, "medium"), (0, "low")]


def explain_risk_score(cvss: float = 0.0, criticality: str = "medium",
                        version_risk: str = "unknown", exposure: str = "medium",
                        service: str = "", port: int = 0) -> dict:
    """
    Calculate risk score with full explanation of each component.
    Returns score, level, and human-readable breakdown.
    """
    # CVSS component
    cvss_norm = 0
    cvss_label = "No CVSS data"
    for threshold, norm, label in CVSS_BUCKETS:
        if cvss >= threshold:
            cvss_norm = norm
            cvss_label = f"{label} ({cvss:.1f}/10)"
            break

    # Criticality component
    crit_norm  = CRIT_MAP.get(criticality.lower(), 50)
    crit_label = f"{criticality.title()} service criticality"

    # Version component
    ver_norm   = VERSION_MAP.get(version_risk.lower(), 40)
    ver_label  = f"{version_risk.title()} version risk"

    # Exposure component
    exp_norm   = EXPOSURE_MAP.get(exposure.lower(), 60)
    exp_label  = f"{exposure.title()} network exposure"

    # Weighted sum
    score = (
        cvss_norm  * WEIGHTS["cvss"]        +
        crit_norm  * WEIGHTS["criticality"] +
        ver_norm   * WEIGHTS["version"]     +
        exp_norm   * WEIGHTS["exposure"]
    )
    score = round(score, 1)

    level = next(lv for threshold, lv in LEVEL_THRESHOLDS if score >= threshold)

    # Build human-readable explanation
    breakdown = [
        {"component": "CVSS Score",       "weight": "40%", "raw": cvss_norm,  "contribution": round(cvss_norm  * 0.40, 1), "label": cvss_label},
        {"component": "Asset Criticality","weight": "25%", "raw": crit_norm,  "contribution": round(crit_norm  * 0.25, 1), "label": crit_label},
        {"component": "Version Risk",     "weight": "20%", "raw": ver_norm,   "contribution": round(ver_norm   * 0.20, 1), "label": ver_label},
        {"component": "Exposure",         "weight": "15%", "raw": exp_norm,   "contribution": round(exp_norm   * 0.15, 1), "label": exp_label},
    ]

    dominant = max(breakdown, key=lambda x: x["contribution"])
    narrative = _build_narrative(score, level, dominant["component"], service, port, cvss)

    return {
        "score":     score,
        "level":     level,
        "breakdown": breakdown,
        "dominant_factor": dominant["component"],
        "narrative": narrative,
        "formula":   "Score = (CVSS×0.40) + (Criticality×0.25) + (Version×0.20) + (Exposure×0.15)",
        "inputs": {
            "cvss": cvss, "criticality": criticality,
            "version_risk": version_risk, "exposure": exposure,
        },
    }


def _build_narrative(score: float, level: str, dominant: str,
                     service: str, port: int, cvss: float) -> str:
    svc_str  = f"{service} on port {port}" if service and port else (service or f"port {port}")
    intro    = f"Risk score {score}/100 ({level.upper()})"
    why      = f"primarily driven by {dominant}"
    if cvss >= 9.0:
        action = "Immediate patching required."
    elif cvss >= 7.0:
        action = "Patch within 72 hours."
    elif level == "high":
        action = "Schedule remediation this sprint."
    elif level == "medium":
        action = "Include in next maintenance window."
    else:
        action = "Monitor and patch on regular cycle."
    return f"{intro} for {svc_str}, {why}. {action}"
