"""
ThreatWeave — Confidence Scoring System (Phase 6)
===================================================
Assigns and stores confidence scores for every patch result.

Rules:
  Vendor Advisory  = 100  (official vendor security notice)
  NVD Reference    = 90   (NVD-sourced with vendor links)
  Community Ref    = 80   (third-party trusted source)
  AI Generated     = 70   (AI with valid output)
  Rule Engine      = 30   (pattern-based fallback)
"""
from __future__ import annotations

from typing import Optional

# Confidence constants — single source of truth
CONFIDENCE_VENDOR     = 100
CONFIDENCE_NVD        = 90
CONFIDENCE_COMMUNITY  = 80
CONFIDENCE_AI         = 70
CONFIDENCE_RULE       = 30

# Source → confidence mapping
_SOURCE_CONFIDENCE = {
    "vendor":       CONFIDENCE_VENDOR,
    "nvd":          CONFIDENCE_NVD,
    "community":    CONFIDENCE_COMMUNITY,
    "ai":           CONFIDENCE_AI,
    "ai_cache":     CONFIDENCE_AI,
    "rule_engine":  CONFIDENCE_RULE,
    "repository":   CONFIDENCE_AI,     # stored patches inherit original confidence
}

# Layer → confidence mapping
_LAYER_CONFIDENCE = {
    "repository": None,    # inherits stored confidence
    "vendor":     CONFIDENCE_VENDOR,
    "nvd_cache":  CONFIDENCE_NVD,
    "ai":         None,    # inherits from source
}


def score_patch(patch: dict) -> dict:
    """
    Assign or verify confidence score on a patch result.
    Returns the patch dict with `confidence` set correctly.
    """
    source = patch.get("source", "ai")
    layer  = patch.get("layer", "")

    # Layer-based override
    layer_conf = _LAYER_CONFIDENCE.get(layer)
    if layer_conf is not None:
        patch["confidence"] = layer_conf
    elif not patch.get("confidence"):
        patch["confidence"] = _SOURCE_CONFIDENCE.get(source, CONFIDENCE_AI)

    # Annotate confidence label
    patch["confidence_label"] = confidence_label(patch["confidence"])
    return patch


def confidence_label(score: int) -> str:
    """Return human-readable label for a confidence score."""
    if score >= CONFIDENCE_VENDOR:
        return "Vendor Advisory"
    if score >= CONFIDENCE_NVD:
        return "NVD Reference"
    if score >= CONFIDENCE_COMMUNITY:
        return "Community Reference"
    if score >= CONFIDENCE_AI:
        return "AI Generated"
    return "Rule Engine"


def get_source_confidence(source: str) -> int:
    """Return expected confidence for a given source string."""
    return _SOURCE_CONFIDENCE.get(source.lower(), CONFIDENCE_AI)
