"""
ThreatWeave — Local Patch Repository (Layer 1)
===============================================
High-level facade over patch_storage + patch_lookup.
Provides store/retrieve/update/version-match operations.

CHANGES:
  - Added _seed_vendor_data() — loads high-confidence vendor patches from
    seed_data.py on FIRST USE (lazy init), not at import time.
    Lazy init avoids circular import:
      app.remediation.__init__ → orchestrator → patch_repository → seed_data
      → app.remediation.confidence  ← still loading = crash
    By deferring seed until first lookup/store call, the package is fully
    loaded before seed_data is touched.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from .patch_storage   import patch_storage
from .patch_lookup    import lookup_patch
from .patch_validator import validate_patch_entry

logger = logging.getLogger("ThreatWeave.remediation.repository")

# Confidence constants (source of truth for the whole system)
CONFIDENCE_VENDOR     = 100
CONFIDENCE_NVD        = 90
CONFIDENCE_COMMUNITY  = 80
CONFIDENCE_AI         = 70
CONFIDENCE_RULE       = 30


class PatchRepository:
    """
    Layer 1 of the 4-layer patch resolution system.

    Responsibilities:
    - Store known patches (from vendor advisories, NVD, AI)
    - Retrieve patches by CVE ID or product/version
    - Version matching and confidence-based deduplication
    - JSON export for research/backup
    """

    def __init__(self):
        self._seeded = False   # lazy — seeded on first use, not at import

    def _ensure_seeded(self) -> None:
        """
        Seed vendor patches on first use.
        Lazy init prevents circular import during app.remediation package load:
          __init__.py → orchestrator → patch_repository (import) → seed_data
          → app.remediation.confidence  ← package not fully loaded yet → crash
        Deferring to first call lets the package finish loading first.
        """
        if self._seeded:
            return
        self._seeded = True
        try:
            from .seed_data import SEED_PATCHES
            count = 0
            for entry in SEED_PATCHES:
                cve_id = entry.get("cve_id", "")
                if not cve_id:
                    continue
                if not patch_storage.get_by_cve(cve_id.upper()):
                    stored = patch_storage.upsert({
                        **entry,
                        "cve_id":        cve_id.upper(),
                        "last_verified": time.time(),
                    })
                    if stored:
                        count += 1
            if count:
                logger.info("Patch repository seeded with %d vendor entries", count)
        except Exception as e:
            logger.warning("Patch repository seed failed: %s", e)

    # ── Public API ────────────────────────────────────────────────────────────

    def lookup(self, cve_id: str, product: str = "", version: str = "") -> Optional[dict]:
        """Look up a patch. Returns dict with confidence/source or None."""
        self._ensure_seeded()
        return lookup_patch(cve_id, product, version)

    def store(self, cve_id: str, patch_data: dict,
              source: str = "repository", confidence: int = CONFIDENCE_AI) -> bool:
        """
        Store a patch entry. Higher-confidence entries are never downgraded.
        Returns True if stored, False if a better entry already exists.
        """
        self._ensure_seeded()
        valid, err = validate_patch_entry({**patch_data, "cve_id": cve_id,
                                           "source": source, "confidence": confidence})
        if not valid:
            logger.warning("Invalid patch entry for %s: %s", cve_id, err)
            return False

        entry = {
            **patch_data,
            "cve_id":        cve_id.upper(),
            "source":        source,
            "confidence":    confidence,
            "last_verified": time.time(),
        }
        stored = patch_storage.upsert(entry)
        if stored:
            logger.debug("[REPO] Stored %s (source=%s conf=%d)", cve_id, source, confidence)
        return stored

    def update(self, cve_id: str, updates: dict) -> bool:
        """Merge updates into an existing entry (only if it raises confidence)."""
        self._ensure_seeded()
        existing = patch_storage.get_by_cve(cve_id.upper())
        if not existing:
            return self.store(cve_id, updates,
                              source=updates.get("source", "repository"),
                              confidence=updates.get("confidence", CONFIDENCE_AI))
        merged = {**existing, **updates, "cve_id": cve_id.upper()}
        return patch_storage.upsert(merged)

    def by_product(self, product: str, version: str = "") -> list[dict]:
        """Return all patches for a product, sorted by confidence."""
        self._ensure_seeded()
        return patch_storage.get_by_product(product, version)

    def export_json(self) -> str:
        """Export full repository to JSON. Returns file path."""
        return patch_storage.export_json()

    def stats(self) -> dict:
        return patch_storage.stats()


# Singleton — seed happens lazily on first call, not here
patch_repository = PatchRepository()
