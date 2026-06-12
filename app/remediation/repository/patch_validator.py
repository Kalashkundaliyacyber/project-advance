"""
ThreatWeave — Patch Entry Validator
=====================================
Validates patch entries before storage.
"""
from __future__ import annotations
import re
from typing import Optional

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

REQUIRED_FIELDS = {"cve_id"}
VALID_SOURCES   = {"repository", "vendor", "nvd", "community", "ai", "rule_engine"}


def validate_patch_entry(entry: dict) -> tuple[bool, Optional[str]]:
    """
    Validate a patch entry dict.
    Returns (is_valid, error_message).
    """
    if not isinstance(entry, dict):
        return False, "Entry must be a dict"

    cve_id = entry.get("cve_id", "")
    if not cve_id:
        return False, "cve_id is required"
    # Allow standard CVE IDs, "UNKNOWN" placeholders, and test/internal IDs
    if cve_id.upper() not in ("UNKNOWN",) and not _CVE_RE.match(cve_id.upper()):
        # Accept CVE-TEST-* style IDs used in development/testing
        if not cve_id.upper().startswith("CVE-"):
            return False, f"Invalid CVE ID format: {cve_id}"

    confidence = entry.get("confidence", 70)
    if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
        return False, f"confidence must be 0-100, got {confidence}"

    source = entry.get("source", "repository")
    if source not in VALID_SOURCES:
        return False, f"source must be one of {VALID_SOURCES}"

    return True, None
