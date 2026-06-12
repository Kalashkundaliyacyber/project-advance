"""
ThreatWeave — Patch Knowledge Graph (Phase 8)
==============================================
Relationship model: Vendor → Product → Version → CVE → Patch → Verification

Backed by SQLite adjacency list.
Supports relationship traversal and fast lookup.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Optional

logger = logging.getLogger("ThreatWeave.remediation.graph")

_DB_DIR  = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "remediation"
)
_DB_PATH = os.path.join(_DB_DIR, "patch_graph.db")


class PatchKnowledgeGraph:
    """
    Adjacency-list knowledge graph for patch relationships.

    Nodes: vendor, product, version, cve, patch
    Edges: has_product, has_version, has_cve, has_patch, has_verification
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
            c.executescript("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id         TEXT PRIMARY KEY,
                    node_type  TEXT NOT NULL,   -- vendor|product|version|cve|patch
                    label      TEXT NOT NULL,
                    meta       TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS edges (
                    src        TEXT NOT NULL,
                    dst        TEXT NOT NULL,
                    rel        TEXT NOT NULL,   -- has_product|has_version|has_cve|has_patch|has_verification
                    weight     REAL DEFAULT 1.0,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (src, dst, rel)
                );
                CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
                CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
                CREATE INDEX IF NOT EXISTS idx_node_type ON nodes(node_type);
            """)
            c.commit(); c.close()

    # ── Node operations ────────────────────────────────────────────────────────

    def add_node(self, node_id: str, node_type: str, label: str,
                 meta: dict = None) -> None:
        with self._lock:
            c = self._conn()
            try:
                c.execute("""
                    INSERT OR IGNORE INTO nodes (id, node_type, label, meta)
                    VALUES (?,?,?,?)
                """, (node_id, node_type, label, json.dumps(meta or {})))
                c.commit()
            finally:
                c.close()

    def add_edge(self, src: str, dst: str, rel: str, weight: float = 1.0) -> None:
        with self._lock:
            c = self._conn()
            try:
                c.execute("""
                    INSERT OR IGNORE INTO edges (src, dst, rel, weight, created_at)
                    VALUES (?,?,?,?,?)
                """, (src, dst, rel, weight, time.time()))
                c.commit()
            finally:
                c.close()

    # ── High-level ingestion ───────────────────────────────────────────────────

    def ingest_patch(self, cve_id: str, vendor: str, product: str,
                     version: str, patch: dict) -> None:
        """
        Ingest a full patch record into the graph.
        Creates nodes and edges for: vendor→product→version→cve→patch
        """
        v_id  = f"vendor:{vendor.lower()}"
        p_id  = f"product:{vendor.lower()}:{product.lower()}"
        ver_id = f"version:{product.lower()}:{version}"
        c_id  = f"cve:{cve_id.upper()}"
        pat_id = f"patch:{cve_id.upper()}:{vendor.lower()}"

        self.add_node(v_id,   "vendor",   vendor)
        self.add_node(p_id,   "product",  product,  {"vendor": vendor})
        self.add_node(ver_id, "version",  version,  {"product": product})
        self.add_node(c_id,   "cve",      cve_id.upper(), {
            "severity": patch.get("severity", "unknown"),
            "cvss":     patch.get("cvss", 0),
        })
        self.add_node(pat_id, "patch", f"Patch for {cve_id}", {
            "confidence": patch.get("confidence", 70),
            "source":     patch.get("source", "unknown"),
            "fix_version": patch.get("fixed_version", "") or patch.get("fix_version", ""),
        })

        # Edges
        self.add_edge(v_id,   p_id,   "has_product")
        self.add_edge(p_id,   ver_id, "has_version")
        self.add_edge(ver_id, c_id,   "has_cve")
        self.add_edge(c_id,   pat_id, "has_patch")

        # Verification edge if present
        if patch.get("verification"):
            vfy_id = f"verify:{cve_id.upper()}"
            self.add_node(vfy_id, "verification", patch["verification"])
            self.add_edge(pat_id, vfy_id, "has_verification")

    # ── Traversal ──────────────────────────────────────────────────────────────

    def get_patches_for_cve(self, cve_id: str) -> list[dict]:
        """Return all patch nodes reachable from a CVE node."""
        c_id = f"cve:{cve_id.upper()}"
        with self._lock:
            c = self._conn()
            try:
                rows = c.execute("""
                    SELECT n.id, n.label, n.meta
                    FROM edges e JOIN nodes n ON e.dst = n.id
                    WHERE e.src=? AND e.rel='has_patch'
                """, (c_id,)).fetchall()
                return [{"id": r["id"], "label": r["label"],
                         "meta": json.loads(r["meta"])} for r in rows]
            finally:
                c.close()

    def get_cves_for_product(self, product: str) -> list[str]:
        """Return CVE IDs associated with a product (shallow traversal)."""
        product = product.lower()
        with self._lock:
            c = self._conn()
            try:
                # product → version → cve traversal
                versions = c.execute("""
                    SELECT e2.dst as ver_id
                    FROM edges e1 JOIN edges e2 ON e1.dst = e2.src
                    WHERE e1.src LIKE ? AND e1.rel='has_version' AND e2.rel='has_version'
                """, (f"%{product}%",)).fetchall()
                cves = []
                for v in versions:
                    rows = c.execute("""
                        SELECT dst FROM edges WHERE src=? AND rel='has_cve'
                    """, (v["ver_id"],)).fetchall()
                    cves.extend(r["dst"].replace("cve:", "") for r in rows)
                return list(set(cves))
            finally:
                c.close()

    def visualize_json(self, limit: int = 100) -> dict:
        """Export graph as node/edge JSON for visualization."""
        with self._lock:
            c = self._conn()
            try:
                nodes = [dict(r) for r in c.execute(
                    "SELECT id, node_type, label FROM nodes LIMIT ?", (limit,)
                ).fetchall()]
                edges = [dict(r) for r in c.execute(
                    "SELECT src, dst, rel FROM edges LIMIT ?", (limit * 3,)
                ).fetchall()]
                return {"nodes": nodes, "edges": edges,
                        "node_count": len(nodes), "edge_count": len(edges)}
            finally:
                c.close()

    def stats(self) -> dict:
        with self._lock:
            c = self._conn()
            try:
                nc = c.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
                ec = c.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
                by_type = {}
                for r in c.execute(
                    "SELECT node_type, COUNT(*) as cnt FROM nodes GROUP BY node_type"
                ).fetchall():
                    by_type[r["node_type"]] = r["cnt"]
                return {"nodes": nc, "edges": ec, "by_type": by_type}
            finally:
                c.close()


patch_graph = PatchKnowledgeGraph()
