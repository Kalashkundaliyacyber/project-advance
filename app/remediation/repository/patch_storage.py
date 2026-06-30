"""
ThreatWeave — Patch Storage Backend
====================================
SQLite primary store with JSON export capability.
Supports Postgres via DATABASE_URL env variable.

Schema:
  patches(
    id           TEXT PRIMARY KEY,    -- sha256(cve_id+vendor+product)
    cve_id       TEXT NOT NULL,
    vendor       TEXT,
    product      TEXT,
    affected_version TEXT,
    fixed_version    TEXT,
    patch_command    TEXT,            -- JSON string of {os: command}
    official_url     TEXT,
    severity         TEXT,
    confidence       INTEGER DEFAULT 70,
    source           TEXT DEFAULT 'repository',
    last_verified    REAL,
    created_at       REAL
  )
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

logger = logging.getLogger("ThreatWeave.remediation.storage")

_DB_DIR  = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "remediation"
)
_DB_PATH = os.path.join(_DB_DIR, "patches.db")
_JSON_EXPORT = os.path.join(_DB_DIR, "patches_export.json")


def _make_id(cve_id: str, vendor: str = "", product: str = "") -> str:
    raw = f"{cve_id.upper()}:{vendor.lower()}:{product.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


class PatchStorage:
    """Thread-safe SQLite storage for the local patch repository."""

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db   = db_path
        self._lock = threading.Lock()
        self._init_schema()

    # ── Schema ─────────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init_schema(self):
        with self._lock:
            c = self._conn()
            c.executescript("""
                CREATE TABLE IF NOT EXISTS patches (
                    id               TEXT PRIMARY KEY,
                    cve_id           TEXT NOT NULL,
                    vendor           TEXT DEFAULT '',
                    product          TEXT DEFAULT '',
                    affected_version TEXT DEFAULT '',
                    fixed_version    TEXT DEFAULT '',
                    patch_command    TEXT DEFAULT '{}',
                    official_url     TEXT DEFAULT '',
                    severity         TEXT DEFAULT 'unknown',
                    confidence       INTEGER DEFAULT 70,
                    source           TEXT DEFAULT 'repository',
                    last_verified    REAL DEFAULT 0,
                    created_at       REAL DEFAULT 0,
                    title            TEXT DEFAULT '',
                    upgrade_path     TEXT DEFAULT '',
                    mitigation       TEXT DEFAULT '',
                    patch_type       TEXT DEFAULT 'upgrade',
                    notes            TEXT DEFAULT '',
                    verification_steps TEXT DEFAULT '[]',
                    rollback_steps      TEXT DEFAULT '[]',
                    "references"        TEXT DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_cve_id  ON patches(cve_id);
                CREATE INDEX IF NOT EXISTS idx_product ON patches(product, vendor);
            """)
            # Migration: the columns above were added after some databases
            # were already created with the original (smaller) schema.
            # CREATE TABLE IF NOT EXISTS does not retrofit existing tables,
            # so ALTER TABLE in any columns that are still missing.
            existing_cols = {row["name"] for row in c.execute("PRAGMA table_info(patches)")}
            migrations = {
                "title":              "TEXT DEFAULT ''",
                "upgrade_path":       "TEXT DEFAULT ''",
                "mitigation":         "TEXT DEFAULT ''",
                "patch_type":         "TEXT DEFAULT 'upgrade'",
                "notes":              "TEXT DEFAULT ''",
                "verification_steps": "TEXT DEFAULT '[]'",
                "rollback_steps":     "TEXT DEFAULT '[]'",
                '"references"':      "TEXT DEFAULT '[]'",
            }
            for col, decl in migrations.items():
                bare_name = col.strip('"')
                if bare_name not in existing_cols:
                    try:
                        c.execute(f"ALTER TABLE patches ADD COLUMN {col} {decl}")
                    except Exception as e:
                        logger.warning("PatchStorage migration: could not add column %s: %s", col, e)
            c.commit()
            c.close()

    # ── CRUD ───────────────────────────────────────────────────────────────────

    def upsert(self, entry: dict) -> bool:
        """Insert or update a patch entry. Returns True on success."""
        cve_id  = entry.get("cve_id", "").upper()
        vendor  = entry.get("vendor", "")
        product = entry.get("product", "")
        if not cve_id:
            return False

        row_id = _make_id(cve_id, vendor, product)
        with self._lock:
            c = self._conn()
            try:
                # Don't downgrade confidence
                existing = c.execute(
                    "SELECT confidence FROM patches WHERE id=?", (row_id,)
                ).fetchone()
                if existing and existing["confidence"] >= entry.get("confidence", 70):
                    return False  # existing entry is better or equal

                patch_cmd = entry.get("patch_command") or entry.get("commands") or {}
                if isinstance(patch_cmd, dict):
                    patch_cmd = json.dumps(patch_cmd)

                verification_steps = entry.get("verification_steps", [])
                rollback_steps     = entry.get("rollback_steps", [])
                references         = entry.get("references", [])

                c.execute("""
                    INSERT OR REPLACE INTO patches
                      (id, cve_id, vendor, product, affected_version, fixed_version,
                       patch_command, official_url, severity, confidence, source,
                       last_verified, created_at, title, upgrade_path, mitigation,
                       patch_type, notes, verification_steps, rollback_steps, "references")
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    row_id,
                    cve_id,
                    vendor,
                    product,
                    entry.get("affected_version", ""),
                    entry.get("fixed_version", "") or entry.get("fix_version", ""),
                    patch_cmd,
                    entry.get("official_url", "") or entry.get("vendor_url", ""),
                    entry.get("severity", "unknown"),
                    entry.get("confidence", 70),
                    entry.get("source", "repository"),
                    time.time(),
                    entry.get("created_at", time.time()),
                    entry.get("title", ""),
                    entry.get("upgrade_path", ""),
                    entry.get("mitigation", ""),
                    entry.get("patch_type", "upgrade"),
                    entry.get("notes", ""),
                    json.dumps(verification_steps) if isinstance(verification_steps, list) else (verification_steps or "[]"),
                    json.dumps(rollback_steps) if isinstance(rollback_steps, list) else (rollback_steps or "[]"),
                    json.dumps(references) if isinstance(references, list) else (references or "[]"),
                ))
                c.commit()
                return True
            except Exception as e:
                logger.warning("PatchStorage.upsert error: %s", e)
                return False
            finally:
                c.close()

    def get_by_cve(self, cve_id: str) -> Optional[dict]:
        """Return the highest-confidence patch entry for a CVE."""
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT * FROM patches WHERE cve_id=? ORDER BY confidence DESC LIMIT 1",
                    (cve_id,)
                ).fetchone()
                return self._row_to_dict(row) if row else None
            finally:
                c.close()

    def get_by_product(self, product: str, version: str = "") -> list[dict]:
        """Return all patches matching a product (optionally filtered by version)."""
        with self._lock:
            c = self._conn()
            try:
                rows = c.execute(
                    "SELECT * FROM patches WHERE LOWER(product) LIKE ? ORDER BY confidence DESC",
                    (f"%{product.lower()}%",)
                ).fetchall()
                results = [self._row_to_dict(r) for r in rows]
                if version:
                    results = [r for r in results
                               if not r.get("affected_version") or
                               version[:4] in r.get("affected_version", "")]
                return results
            finally:
                c.close()

    def delete(self, cve_id: str) -> bool:
        cve_id = cve_id.upper()
        with self._lock:
            c = self._conn()
            try:
                c.execute("DELETE FROM patches WHERE cve_id=?", (cve_id,))
                c.commit()
                return c.rowcount > 0
            finally:
                c.close()

    def stats(self) -> dict:
        with self._lock:
            c = self._conn()
            try:
                total = c.execute("SELECT COUNT(*) FROM patches").fetchone()[0]
                by_src = {}
                for row in c.execute(
                    "SELECT source, COUNT(*) as cnt FROM patches GROUP BY source"
                ).fetchall():
                    by_src[row["source"]] = row["cnt"]
                return {"total": total, "by_source": by_src, "db_path": self._db}
            finally:
                c.close()

    # ── JSON Export ────────────────────────────────────────────────────────────

    def export_json(self, path: str = _JSON_EXPORT) -> str:
        """Export all patches to a JSON file. Returns file path."""
        with self._lock:
            c = self._conn()
            try:
                rows = c.execute("SELECT * FROM patches ORDER BY confidence DESC").fetchall()
                data = [self._row_to_dict(r) for r in rows]
            finally:
                c.close()

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"exported_at": time.time(), "count": len(data), "patches": data},
                      f, indent=2)
        logger.info("Exported %d patches to %s", len(data), path)
        return path

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["patch_command"] = json.loads(d.get("patch_command") or "{}")
        except Exception:
            d["patch_command"] = {}
        for list_field in ("verification_steps", "rollback_steps", "references"):
            try:
                d[list_field] = json.loads(d.get(list_field) or "[]")
            except Exception:
                d[list_field] = []
        return d


# Singleton
patch_storage = PatchStorage()
