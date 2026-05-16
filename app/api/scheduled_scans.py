"""
FIX8: Scheduled / Recurring Scans
Stores scan schedules in SQLite (scheduled_scans table).
A background task checks and fires due scans on startup.
"""
import sqlite3
import time
import asyncio
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.files.session_manager import DB_PATH

logger = logging.getLogger("scanwise.scheduled")
router = APIRouter()

INTERVALS = {
    "24h":  86400,
    "7d":   604800,
    "30d":  2592000,
}


def _init_schedule_table():
    """Create scheduled_scans table if it does not exist (migration-safe)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target       TEXT NOT NULL,
            scan_type    TEXT NOT NULL,
            interval_key TEXT NOT NULL,
            project_name TEXT DEFAULT '',
            last_run     TEXT,
            next_run     TEXT,
            enabled      INTEGER DEFAULT 1,
            created_at   TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


_init_schedule_table()


class ScheduleRequest(BaseModel):
    target: str
    scan_type: str
    interval: str        # "24h" | "7d" | "30d"
    project_name: Optional[str] = ""


@router.post("/schedule")
async def create_schedule(req: ScheduleRequest):
    """FIX8: Create a new recurring scan schedule."""
    if req.interval not in INTERVALS:
        raise HTTPException(status_code=400, detail=f"interval must be one of {list(INTERVALS)}")
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    next_run = time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime(time.time() + INTERVALS[req.interval]))
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "INSERT INTO scheduled_scans (target,scan_type,interval_key,project_name,next_run,created_at) VALUES (?,?,?,?,?,?)",
        (req.target, req.scan_type, req.interval, req.project_name or "", next_run, now)
    )
    sched_id = cur.lastrowid
    conn.commit()
    conn.close()
    logger.info("FIX8: schedule #%s created — %s every %s", sched_id, req.target, req.interval)
    return {"id": sched_id, "target": req.target, "interval": req.interval, "next_run": next_run}


@router.get("/schedule")
async def list_schedules():
    """FIX8: List all scheduled scans."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scheduled_scans ORDER BY id DESC").fetchall()
    conn.close()
    return {"schedules": [dict(r) for r in rows]}


@router.delete("/schedule/{sched_id}")
async def delete_schedule(sched_id: int):
    """FIX8: Remove a scheduled scan."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scheduled_scans WHERE id=?", (sched_id,))
    conn.commit()
    conn.close()
    return {"ok": True, "id": sched_id}


async def run_due_schedules(pipeline_fn):
    """
    FIX8: Called from app startup — checks for any overdue schedules and fires them.
    pipeline_fn = _run_scan_pipeline from routes.py
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        now_ts = time.strftime("%Y-%m-%d %H:%M:%S")
        due = conn.execute(
            "SELECT * FROM scheduled_scans WHERE enabled=1 AND (next_run IS NULL OR next_run <= ?)",
            (now_ts,)
        ).fetchall()
        conn.close()

        for row in due:
            logger.info("FIX8: firing scheduled scan #%s → %s", row["id"], row["target"])
            try:
                await pipeline_fn(row["target"], row["scan_type"], project_name=row["project_name"] or "")
                interval_secs = INTERVALS.get(row["interval_key"], 86400)
                next_run = time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(time.time() + interval_secs))
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                c2 = sqlite3.connect(DB_PATH)
                c2.execute("UPDATE scheduled_scans SET last_run=?, next_run=? WHERE id=?",
                            (now_str, next_run, row["id"]))
                c2.commit()
                c2.close()
            except Exception as e:
                logger.warning("FIX8: scheduled scan #%s failed: %s", row["id"], e)
    except Exception as outer:
        logger.warning("FIX8: run_due_schedules error: %s", outer)
