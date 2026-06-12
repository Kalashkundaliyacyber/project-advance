"""
ThreatWeave — AI Patch Cache (Layer 4)
========================================
Caches AI-generated patch guidance to prevent duplicate AI calls.
TTL: 72 hours. Backed by SQLite for cross-restart persistence.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Optional

logger = logging.getLogger("ThreatWeave.remediation.ai_cache")

_DB_DIR  = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "remediation"
)
_DB_PATH = os.path.join(_DB_DIR, "ai_patch_cache.db")
_TTL     = 259_200   # 72 hours


class AiPatchCache:
    """Persistent AI patch guidance cache with TTL."""

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
            c.execute("""
                CREATE TABLE IF NOT EXISTS ai_patches (
                    cache_key  TEXT PRIMARY KEY,
                    cve_id     TEXT DEFAULT '',
                    payload    TEXT NOT NULL,
                    provider   TEXT DEFAULT '',
                    cached_at  REAL NOT NULL
                )
            """)
            c.execute("DELETE FROM ai_patches WHERE cached_at + ? < ?", (_TTL, time.time()))
            c.commit(); c.close()

    def get(self, cve_id: str, service: str = "", version: str = "") -> Optional[dict]:
        key = self._key(cve_id, service, version)
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT payload, cached_at FROM ai_patches WHERE cache_key=?", (key,)
                ).fetchone()
                if row and time.time() - row["cached_at"] < _TTL:
                    self._hits += 1
                    return json.loads(row["payload"])
                self._misses += 1
                return None
            finally:
                c.close()

    def set(self, cve_id: str, data: dict,
            service: str = "", version: str = "") -> None:
        key = self._key(cve_id, service, version)
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT OR REPLACE INTO ai_patches VALUES (?,?,?,?,?)",
                    (key, cve_id.upper(), json.dumps(data),
                     data.get("provider", ""), time.time())
                )
                c.commit()
            finally:
                c.close()

    def stats(self) -> dict:
        total = self._hits + self._misses
        with self._lock:
            c = self._conn()
            try:
                count = c.execute("SELECT COUNT(*) FROM ai_patches").fetchone()[0]
            finally:
                c.close()
        return {
            "entries":  count,
            "hits":     self._hits,
            "misses":   self._misses,
            "hit_rate": f"{100*self._hits//total}%" if total else "—",
        }

    @staticmethod
    def _key(cve_id: str, service: str, version: str) -> str:
        raw = f"{cve_id.upper()}:{service.lower()}:{version.lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:20]


ai_patch_cache = AiPatchCache()
