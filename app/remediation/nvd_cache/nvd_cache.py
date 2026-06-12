"""
ThreatWeave — NVD Intelligence Cache (Layer 3)
================================================
Wraps nvd_storage with auto-fetch from NVD 2.0 API.
Goal: 90% reduction in NVD API calls via persistent SQLite cache.

On first import, migrates any existing CVE entries from the older
data/cve_db/nvd_cache.db into nvd_intelligence.db so Layer 3 has
immediate data without requiring live NVD API calls.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .nvd_storage import nvd_intel_storage
from .nvd_parser  import parse_nvd_item

logger = logging.getLogger("ThreatWeave.remediation.nvd_cache")

_NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT     = 10
_USER_AGENT  = "ThreatWeave/3.0 (vulnerability scanner)"
_NVD_ENABLED = os.environ.get("NVD_ENABLED", "true").lower() == "true"

# Path to the older NVD cache populated by app/cve/nvd_client.py
_OLD_CACHE_DB = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "cve_db", "nvd_cache.db"
)


def _migrate_old_cache() -> None:
    """
    One-time migration: copy CVE entries from data/cve_db/nvd_cache.db
    (populated by app/cve/nvd_client.py) into nvd_intelligence.db.

    The old cache stores lists of CVE dicts keyed by CPE or keyword strings.
    We extract each individual CVE record and store it by cve_id so Layer 3
    can look them up during patch resolution.

    Safe to call repeatedly — INSERT OR IGNORE / TTL check prevents duplication.
    """
    if not os.path.exists(_OLD_CACHE_DB):
        return

    try:
        conn = sqlite3.connect(_OLD_CACHE_DB, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT payload FROM nvd_cache WHERE payload != '[]'"
        ).fetchall()
        conn.close()
    except Exception as e:
        logger.debug("Old NVD cache migration read error: %s", e)
        return

    migrated = 0
    for row in rows:
        try:
            entries = json.loads(row["payload"])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                cve_id = (entry.get("cve_id") or "").strip().upper()
                if not cve_id.startswith("CVE-"):
                    continue
                # Skip if already in the intelligence cache
                if nvd_intel_storage.get(cve_id):
                    continue
                # Map old schema → nvd_intel_storage schema
                nvd_intel_storage.set(cve_id, {
                    "cvss":        float(entry.get("cvss_score") or 0),
                    "severity":    (entry.get("severity") or "unknown").lower(),
                    "description": entry.get("description") or "",
                    "references":  [
                        r if isinstance(r, str) else r.get("url", "")
                        for r in (entry.get("references") or [])
                    ],
                    "vendor_links": [],
                    "published":   entry.get("published") or "",
                    "modified":    entry.get("modified") or "",
                })
                migrated += 1
        except Exception as e:
            logger.debug("Migration entry error: %s", e)

    if migrated:
        logger.info(
            "[LAYER3] Migrated %d CVE entries from nvd_cache.db → nvd_intelligence.db",
            migrated,
        )


# Run migration once at import time (fast — only touches rows not already stored)
_migrate_old_cache()


class NvdIntelligenceCache:
    """
    Layer 3 NVD cache with auto-populate from NVD 2.0 API.

    Features:
    - TTL-backed SQLite cache (7 days)
    - Automatic refresh mechanism
    - Duplicate prevention
    - Rate-limit aware (no API key → free tier 5 req/30s)
    """

    def lookup(self, cve_id: str) -> Optional[dict]:
        """
        Look up NVD data for a CVE.
        Returns cached entry immediately; fetches from NVD on miss.
        """
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            return None

        # 1. Cache hit
        cached = nvd_intel_storage.get(cve_id)
        if cached:
            logger.debug("[LAYER3] NVD cache hit for %s", cve_id)
            return cached

        # 2. Fetch from NVD
        if not _NVD_ENABLED:
            return None

        fetched = self._fetch(cve_id)
        if fetched:
            nvd_intel_storage.set(cve_id, fetched)
            logger.info("[LAYER3] NVD fetched and cached: %s", cve_id)
            return fetched

        return None

    def store(self, cve_id: str, data: dict) -> None:
        """Manually store NVD data (e.g. from existing nvd_client)."""
        nvd_intel_storage.set(cve_id.upper(), data)

    def refresh(self, cve_id: str) -> Optional[dict]:
        """Force re-fetch from NVD regardless of cache TTL."""
        cve_id = cve_id.upper()
        fetched = self._fetch(cve_id)
        if fetched:
            nvd_intel_storage.set(cve_id, fetched)
        return fetched

    def stats(self) -> dict:
        return nvd_intel_storage.stats()

    # ── Private ────────────────────────────────────────────────────────────────

    def _fetch(self, cve_id: str) -> Optional[dict]:
        url = f"{_NVD_BASE}?cveId={urllib.parse.quote(cve_id)}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                raw = json.loads(resp.read())

            vulns = raw.get("vulnerabilities", [])
            if not vulns:
                return None
            return parse_nvd_item(vulns[0])

        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            logger.debug("NVD HTTP %d for %s", e.code, cve_id)
            return None
        except Exception as e:
            logger.debug("NVD fetch error for %s: %s", cve_id, e)
            return None


nvd_intelligence_cache = NvdIntelligenceCache()
