"""
FIX10: Scan Profiles / Presets
Stores named scan presets (target + scan_type + project_name) in SQLite.
Users can save common configurations and rerun with one click.
"""
import sqlite3
import time
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.files.session_manager import DB_PATH

logger = logging.getLogger("scanwise.presets")
router = APIRouter()


def _init_presets_table():
    """Migration-safe table creation."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_presets (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            target       TEXT NOT NULL,
            scan_type    TEXT NOT NULL,
            project_name TEXT DEFAULT '',
            created_at   TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


_init_presets_table()


class PresetRequest(BaseModel):
    name: str
    target: str
    scan_type: str
    project_name: Optional[str] = ""


@router.post("/presets")
async def save_preset(req: PresetRequest):
    """FIX10: Save a named scan preset."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "INSERT INTO scan_presets (name,target,scan_type,project_name,created_at) VALUES (?,?,?,?,?)",
        (req.name.strip(), req.target.strip(), req.scan_type.strip(), req.project_name or "", now)
    )
    preset_id = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": preset_id, "name": req.name, "target": req.target, "scan_type": req.scan_type}


@router.get("/presets")
async def list_presets():
    """FIX10: Return all saved presets."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scan_presets ORDER BY id DESC").fetchall()
    conn.close()
    return {"presets": [dict(r) for r in rows]}


@router.delete("/presets/{preset_id}")
async def delete_preset(preset_id: int):
    """FIX10: Delete a preset."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scan_presets WHERE id=?", (preset_id,))
    conn.commit()
    conn.close()
    return {"ok": True, "id": preset_id}
