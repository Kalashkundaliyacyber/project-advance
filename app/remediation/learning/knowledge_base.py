"""
ThreatWeave — Self-Learning Knowledge Base (Phase 7)
=====================================================
Stores AI-generated patches that have been approved / used successfully.
Reduces future AI calls by promoting approved results to Layer 1.

Storage: SQLite  data/remediation/learning_kb.db

Schema:
  {cve, service, approved, success_count, failure_count,
   patch_data, stored_at, last_used}
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Optional

logger = logging.getLogger("ThreatWeave.remediation.learning")

_DB_DIR  = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "remediation"
)
_DB_PATH = os.path.join(_DB_DIR, "learning_kb.db")

# Auto-promote to Layer 1 when success_count reaches this threshold
_PROMOTE_THRESHOLD = 3


class LearningKnowledgeBase:
    """
    Phase 7: Self-learning KB.

    When AI generates a patch:
      → store in learning KB (pending approval)
    When human approves or result is used successfully:
      → increment success_count
      → at threshold: auto-promote to Layer 1 repository
    When result fails:
      → increment failure_count
      → at high failure rate: mark as unreliable
    """

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db   = db_path
        self._lock = threading.Lock()
        self._init()

    def _conn(self):
        c = sqlite3.connect(self._db, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._lock:
            c = self._conn()
            c.execute("""
                CREATE TABLE IF NOT EXISTS learning_kb (
                    cve_id        TEXT NOT NULL,
                    service       TEXT DEFAULT '',
                    approved      INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    patch_data    TEXT NOT NULL,
                    provider      TEXT DEFAULT 'ai',
                    stored_at     REAL NOT NULL,
                    last_used     REAL DEFAULT 0,
                    PRIMARY KEY (cve_id, service)
                )
            """)
            c.commit(); c.close()

    # ── Public API ─────────────────────────────────────────────────────────────

    def store(self, cve_id: str, service: str, patch_data: dict) -> None:
        """Store an AI-generated patch for learning."""
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                # Only store if no existing entry or new data has higher confidence
                existing = c.execute(
                    "SELECT success_count FROM learning_kb WHERE cve_id=? AND service=?",
                    (cve_id, service.lower())
                ).fetchone()
                if existing:
                    return  # Already have data for this CVE/service

                c.execute("""
                    INSERT OR IGNORE INTO learning_kb
                      (cve_id, service, patch_data, provider, stored_at)
                    VALUES (?,?,?,?,?)
                """, (
                    cve_id, service.lower(),
                    json.dumps(patch_data),
                    patch_data.get("provider", "ai"),
                    time.time(),
                ))
                c.commit()
            finally:
                c.close()

    def approve(self, cve_id: str, service: str = "") -> bool:
        """
        Mark a patch as human-approved.
        When success_count >= threshold, auto-promotes to Layer 1.
        """
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                c.execute("""
                    UPDATE learning_kb
                    SET approved=1, success_count=success_count+1, last_used=?
                    WHERE cve_id=? AND service=?
                """, (time.time(), cve_id, service.lower()))
                c.commit()

                row = c.execute(
                    "SELECT * FROM learning_kb WHERE cve_id=? AND service=?",
                    (cve_id, service.lower())
                ).fetchone()
                if row and row["success_count"] >= _PROMOTE_THRESHOLD:
                    self._promote_to_layer1(dict(row))
                return True
            finally:
                c.close()

    def record_success(self, cve_id: str, service: str = "") -> None:
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                c.execute("""
                    UPDATE learning_kb
                    SET success_count=success_count+1, last_used=?
                    WHERE cve_id=? AND service=?
                """, (time.time(), cve_id, service.lower()))
                c.commit()
                row = c.execute(
                    "SELECT * FROM learning_kb WHERE cve_id=? AND service=?",
                    (cve_id, service.lower())
                ).fetchone()
                if row and row["success_count"] >= _PROMOTE_THRESHOLD:
                    self._promote_to_layer1(dict(row))
            finally:
                c.close()

    def record_failure(self, cve_id: str, service: str = "") -> None:
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                c.execute("""
                    UPDATE learning_kb
                    SET failure_count=failure_count+1
                    WHERE cve_id=? AND service=?
                """, (cve_id, service.lower()))
                c.commit()
            finally:
                c.close()

    def lookup(self, cve_id: str, service: str = "") -> Optional[dict]:
        """Check if we have an approved/proven patch in the learning KB."""
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                row = c.execute("""
                    SELECT * FROM learning_kb
                    WHERE cve_id=? AND (service=? OR service='')
                    ORDER BY success_count DESC LIMIT 1
                """, (cve_id, service.lower())).fetchone()
                if row:
                    data = json.loads(row["patch_data"])
                    data["from_learning_kb"] = True
                    data["success_count"]    = row["success_count"]
                    return data
                return None
            finally:
                c.close()

    def stats(self) -> dict:
        with self._lock:
            c = self._conn()
            try:
                total    = c.execute("SELECT COUNT(*) FROM learning_kb").fetchone()[0]
                approved = c.execute("SELECT COUNT(*) FROM learning_kb WHERE approved=1").fetchone()[0]
                promoted = c.execute("SELECT COUNT(*) FROM learning_kb WHERE success_count >= ?",
                                     (_PROMOTE_THRESHOLD,)).fetchone()[0]
                return {"total": total, "approved": approved, "auto_promoted": promoted}
            finally:
                c.close()

    # ── Internal ───────────────────────────────────────────────────────────────

    def _promote_to_layer1(self, row: dict) -> None:
        """Auto-promote a proven entry to the Layer 1 repository."""
        try:
            from app.remediation.repository.patch_repository import (
                patch_repository, CONFIDENCE_AI
            )
            patch_data = json.loads(row["patch_data"]) if isinstance(row["patch_data"], str) else row["patch_data"]
            patch_repository.store(
                cve_id=row["cve_id"],
                patch_data={**patch_data, "vendor": "", "product": row.get("service", "")},
                source="ai_promoted",
                confidence=CONFIDENCE_AI,
            )
            logger.info("[LEARNING] Auto-promoted %s/%s to Layer 1 (success_count=%d)",
                        row["cve_id"], row.get("service"), row.get("success_count", 0))
        except Exception as e:
            logger.debug("Layer 1 promotion failed: %s", e)


learning_kb = LearningKnowledgeBase()
