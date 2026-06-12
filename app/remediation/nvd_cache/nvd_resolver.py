"""
ThreatWeave — NVD Resolver (Layer 3)
======================================
Converts NVD intelligence cache data into actionable patch guidance.
Confidence: 90 (NVD Reference).
"""
from __future__ import annotations

import logging
from typing import Optional

from .nvd_cache  import nvd_intelligence_cache
from .nvd_parser import extract_patch_guidance

logger = logging.getLogger("ThreatWeave.remediation.nvd_resolver")

CONFIDENCE_NVD = 90


def resolve_from_nvd(cve_id: str, service: str = "") -> Optional[dict]:
    """
    Layer 3 resolver: look up NVD intel and build patch guidance.

    Returns normalized patch dict (confidence=90) or None.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return None

    nvd_data = nvd_intelligence_cache.lookup(cve_id)
    if not nvd_data:
        return None

    guidance = extract_patch_guidance(nvd_data, service)

    return {
        "cve_id":       cve_id,
        "cvss":         nvd_data.get("cvss", 0),
        "severity":     nvd_data.get("severity", "unknown"),
        "description":  nvd_data.get("description", ""),
        "published":    nvd_data.get("published", ""),
        "modified":     nvd_data.get("modified", ""),
        "references":   nvd_data.get("references", []),
        "vendor_links": nvd_data.get("vendor_links", []),
        "commands":     guidance.get("commands", {}),
        "patch_command": guidance.get("patch_command", {}),
        "vendor_url":   guidance.get("vendor_url", ""),
        "official_url": guidance.get("vendor_url", ""),
        "mitigation":   guidance.get("mitigation", ""),
        "fix_version":  "latest",
        "confidence":   CONFIDENCE_NVD,
        "source":       "nvd",
        "layer":        "nvd_cache",
        "ai_called":    False,
        "patch_found":  True,
    }
