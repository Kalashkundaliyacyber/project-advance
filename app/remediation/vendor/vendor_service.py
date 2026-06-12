"""
ThreatWeave — Vendor Advisory Service (Layer 2)
================================================
Public facade for the vendor advisory layer.
"""
from __future__ import annotations

import logging
from typing import Optional

from .vendor_resolver import resolve_vendor_advisory
from .vendor_cache    import vendor_cache

logger = logging.getLogger("ThreatWeave.remediation.vendor_service")


class VendorAdvisoryService:
    """Layer 2 of the 4-layer patch resolution system."""

    def lookup(self, cve_id: str, service: str = "", vendor: str = "") -> Optional[dict]:
        """
        Resolve vendor advisory for a CVE.
        Returns normalized dict with patch_commands, advisory_url, confidence, source.
        """
        if not cve_id or cve_id.upper() == "UNKNOWN":
            return None

        result = resolve_vendor_advisory(cve_id, service, vendor)
        if result:
            result["layer"] = "vendor"
            result["ai_called"] = False
            result["patch_found"] = True
        return result

    def cache_stats(self) -> dict:
        return vendor_cache.stats()


vendor_service = VendorAdvisoryService()
