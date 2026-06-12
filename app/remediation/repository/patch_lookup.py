"""
ThreatWeave — Patch Lookup
===========================
Version-aware CVE patch lookup against the local SQLite repository.
Used as Layer 1 in the 4-layer resolution chain.
"""
from __future__ import annotations

import logging
from typing import Optional

from .patch_storage import patch_storage

logger = logging.getLogger("ThreatWeave.remediation.lookup")


def lookup_patch(cve_id: str, product: str = "", version: str = "") -> Optional[dict]:
    """
    Look up a patch in the local repository.

    Resolution order:
      1. Exact CVE-ID match (highest confidence wins)
      2. Product + version match (for product-keyed data)

    Returns a normalized patch dict or None if not found.
    """
    cve_id = cve_id.strip().upper()

    # 1. Direct CVE lookup
    if cve_id and cve_id != "UNKNOWN":
        entry = patch_storage.get_by_cve(cve_id)
        if entry:
            logger.debug("[LAYER1] CVE hit: %s (confidence=%d)", cve_id, entry.get("confidence", 0))
            return _normalize(entry)

    # 2. Product match
    if product:
        results = patch_storage.get_by_product(product, version)
        if results:
            best = results[0]  # already sorted by confidence DESC
            logger.debug("[LAYER1] Product hit: %s (confidence=%d)", product, best.get("confidence", 0))
            return _normalize(best)

    return None


def _normalize(entry: dict) -> dict:
    """Normalize storage row to standard patch response format."""
    cmds = entry.get("patch_command") or {}
    if isinstance(cmds, str):
        import json
        try:
            cmds = json.loads(cmds)
        except Exception:
            cmds = {}

    return {
        "cve_id":          entry.get("cve_id", ""),
        "vendor":          entry.get("vendor", ""),
        "product":         entry.get("product", ""),
        "affected_version": entry.get("affected_version", ""),
        "fixed_version":   entry.get("fixed_version", "") or entry.get("fix_version", ""),
        "patch_command":   cmds,
        "commands":        cmds,           # alias for compatibility
        "official_url":    entry.get("official_url", "") or entry.get("vendor_url", ""),
        "vendor_url":      entry.get("official_url", "") or entry.get("vendor_url", ""),
        "severity":        entry.get("severity", "unknown"),
        "confidence":      entry.get("confidence", 70),
        "source":          entry.get("source", "repository"),
        "last_verified":   entry.get("last_verified", 0),
        "layer":           "repository",
        "ai_called":       False,
        "patch_found":     True,
    }
