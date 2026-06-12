"""
ThreatWeave — Vendor Advisory Cache
=====================================
In-memory + SQLite cache for vendor security advisories.
TTL: 24 hours (vendor advisories are stable but can be updated).
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

logger = logging.getLogger("ThreatWeave.remediation.vendor_cache")

_DB_DIR  = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "remediation"
)
_DB_PATH = os.path.join(_DB_DIR, "vendor_cache.db")
_TTL     = 86_400   # 24 hours


class VendorCache:
    """SQLite-backed vendor advisory cache."""

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db   = db_path
        self._lock = threading.Lock()
        self._mem: dict = {}          # in-memory L1 cache
        self._init()

    def _conn(self):
        c = sqlite3.connect(self._db, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._lock:
            c = self._conn()
            c.execute("""
                CREATE TABLE IF NOT EXISTS vendor_advisories (
                    cache_key   TEXT PRIMARY KEY,
                    payload     TEXT NOT NULL,
                    fetched_at  REAL NOT NULL,
                    vendor      TEXT DEFAULT '',
                    cve_id      TEXT DEFAULT ''
                )
            """)
            # Expire old entries
            c.execute("DELETE FROM vendor_advisories WHERE fetched_at + ? < ?",
                      (_TTL, time.time()))
            c.commit(); c.close()

    def get(self, cve_id: str, vendor: str = "") -> Optional[dict]:
        key = self._key(cve_id, vendor)
        # L1
        if key in self._mem:
            entry = self._mem[key]
            if time.time() - entry["ts"] < _TTL:
                return entry["data"]
            del self._mem[key]
        # L2
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT payload, fetched_at FROM vendor_advisories WHERE cache_key=?",
                    (key,)
                ).fetchone()
                if row and time.time() - row["fetched_at"] < _TTL:
                    data = json.loads(row["payload"])
                    self._mem[key] = {"ts": row["fetched_at"], "data": data}
                    return data
            finally:
                c.close()
        return None

    def set(self, cve_id: str, data: dict, vendor: str = "") -> None:
        key = self._key(cve_id, vendor)
        self._mem[key] = {"ts": time.time(), "data": data}
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT OR REPLACE INTO vendor_advisories VALUES (?,?,?,?,?)",
                    (key, json.dumps(data), time.time(), vendor, cve_id.upper())
                )
                c.commit()
            finally:
                c.close()

    def stats(self) -> dict:
        with self._lock:
            c = self._conn()
            try:
                total = c.execute("SELECT COUNT(*) FROM vendor_advisories").fetchone()[0]
                return {"entries": total, "mem_entries": len(self._mem), "ttl_hours": _TTL // 3600}
            finally:
                c.close()

    @staticmethod
    def _key(cve_id: str, vendor: str) -> str:
        return hashlib.sha256(f"{cve_id.upper()}:{vendor.lower()}".encode()).hexdigest()[:16]


vendor_cache = VendorCache()
