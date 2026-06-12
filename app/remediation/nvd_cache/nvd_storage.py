"""
ThreatWeave — NVD Intelligence Storage
========================================
Persistent SQLite storage for NVD CVE data.
Target: reduce NVD API calls by 90%.
TTL: 7 days (CVE data rarely changes after publication).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Optional

logger = logging.getLogger("ThreatWeave.remediation.nvd_storage")

_DB_DIR  = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "remediation"
)
_DB_PATH = os.path.join(_DB_DIR, "nvd_intelligence.db")
_TTL     = 604_800   # 7 days


class NvdIntelligenceStorage:
    """
    SQLite-backed storage for NVD CVE intelligence.

    Schema stores:
      cve, cvss, description, references, vendor_links, published, modified
    """

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db   = db_path
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._init()

    def _conn(self):
        c = sqlite3.connect(self._db, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._lock:
            c = self._conn()
            c.executescript("""
                CREATE TABLE IF NOT EXISTS nvd_intel (
                    cve_id       TEXT PRIMARY KEY,
                    cvss         REAL DEFAULT 0,
                    severity     TEXT DEFAULT 'unknown',
                    description  TEXT DEFAULT '',
                    ref_urls     TEXT DEFAULT '[]',
                    vendor_links TEXT DEFAULT '[]',
                    published    TEXT DEFAULT '',
                    modified     TEXT DEFAULT '',
                    cached_at    REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_severity ON nvd_intel(severity);
                CREATE INDEX IF NOT EXISTS idx_cvss     ON nvd_intel(cvss);
            """)
            # Clean expired entries
            c.execute("DELETE FROM nvd_intel WHERE cached_at + ? < ?", (_TTL, time.time()))
            c.commit(); c.close()

    def get(self, cve_id: str) -> Optional[dict]:
        """Return cached NVD entry or None on miss/expiry."""
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT * FROM nvd_intel WHERE cve_id=?", (cve_id,)
                ).fetchone()
                if not row:
                    self._misses += 1
                    return None
                if time.time() - row["cached_at"] > _TTL:
                    c.execute("DELETE FROM nvd_intel WHERE cve_id=?", (cve_id,))
                    c.commit()
                    self._misses += 1
                    return None
                self._hits += 1
                return self._row_to_dict(row)
            finally:
                c.close()

    def set(self, cve_id: str, data: dict) -> None:
        """Store NVD entry. Prevents duplicates via INSERT OR REPLACE."""
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                c.execute("""
                    INSERT OR REPLACE INTO nvd_intel
                      (cve_id, cvss, severity, description, ref_urls,
                       vendor_links, published, modified, cached_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    cve_id,
                    data.get("cvss", 0),
                    data.get("severity", "unknown"),
                    data.get("description", "")[:1000],
                    json.dumps(data.get("references", [])),
                    json.dumps(data.get("vendor_links", [])),
                    data.get("published", ""),
                    data.get("modified", ""),
                    time.time(),
                ))
                c.commit()
            except Exception as e:
                logger.warning("NVD storage set error: %s", e)
            finally:
                c.close()

    def refresh(self, cve_id: str) -> None:
        """Reset TTL on an existing entry (touch)."""
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                c.execute("UPDATE nvd_intel SET cached_at=? WHERE cve_id=?",
                          (time.time(), cve_id))
                c.commit()
            finally:
                c.close()

    def stats(self) -> dict:
        total = self._hits + self._misses
        with self._lock:
            c = self._conn()
            try:
                count = c.execute("SELECT COUNT(*) FROM nvd_intel").fetchone()[0]
            finally:
                c.close()
        return {
            "entries":  count,
            "hits":     self._hits,
            "misses":   self._misses,
            "hit_rate": f"{100*self._hits//total}%" if total else "—",
            "ttl_days": _TTL // 86400,
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        for col, key in (("ref_urls", "references"), ("vendor_links", "vendor_links")):
            try:
                d[key] = json.loads(d.pop(col, "[]"))
            except Exception:
                d[key] = []
        return d


nvd_intel_storage = NvdIntelligenceStorage()
