"""
FIX12: False Positive / Accepted Risk Tracking
Allows users to mark CVE findings as false_positive or accepted_risk.
Status is stored in SQLite and automatically matched to recurring findings
by cve_id so future scans can restore the review status.
"""
import sqlite3
import time
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.files.session_manager import DB_PATH

logger = logging.getLogger("scanwise.findings")
router = APIRouter()

ALLOWED_STATUSES = {"false_positive", "accepted_risk", "open"}


def _init_findings_table():
    """Migration-safe — create review_status table if missing."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS review_status (
            cve_id       TEXT PRIMARY KEY,
            status       TEXT NOT NULL DEFAULT 'open',
            note         TEXT DEFAULT '',
            reviewed_by  TEXT DEFAULT '',
            reviewed_at  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


_init_findings_table()


class ReviewRequest(BaseModel):
    cve_id: str
    status: str          # "false_positive" | "accepted_risk" | "open"
    note: Optional[str] = ""
    reviewed_by: Optional[str] = ""


@router.post("/findings/review")
async def set_review_status(req: ReviewRequest):
    """FIX12: Set or update the review status of a CVE finding."""
    if req.status not in ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {list(ALLOWED_STATUSES)}")
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO review_status (cve_id,status,note,reviewed_by,reviewed_at) VALUES (?,?,?,?,?)",
        (req.cve_id.strip(), req.status, req.note or "", req.reviewed_by or "", now)
    )
    conn.commit()
    conn.close()
    logger.info("FIX12: %s marked as %s", req.cve_id, req.status)
    return {"cve_id": req.cve_id, "status": req.status}


@router.get("/findings/review")
async def list_reviews():
    """FIX12: Return all reviewed CVE findings."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM review_status ORDER BY reviewed_at DESC").fetchall()
    conn.close()
    return {"reviews": [dict(r) for r in rows]}


@router.get("/findings/review/{cve_id}")
async def get_review(cve_id: str):
    """FIX12: Get review status for a specific CVE."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM review_status WHERE cve_id=?", (cve_id,)).fetchone()
    conn.close()
    if not row:
        return {"cve_id": cve_id, "status": "open"}
    return dict(row)


def annotate_with_review_status(analysis: dict) -> dict:
    """
    FIX12: Walk every CVE in an analysis result and annotate it with stored review status.
    Called after loading a session so users see their previous reviews instantly.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT cve_id, status, note FROM review_status").fetchall()
        conn.close()
        status_map = {r["cve_id"]: {"status": r["status"], "note": r["note"]} for r in rows}
    except Exception:
        return analysis

    for host in analysis.get("risk", {}).get("hosts", []):
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                cid = cve.get("cve_id", "")
                if cid in status_map:
                    cve["review_status"] = status_map[cid]["status"]
                    cve["review_note"]   = status_map[cid]["note"]
                else:
                    cve.setdefault("review_status", "open")
    return analysis
