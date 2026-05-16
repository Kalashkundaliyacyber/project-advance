"""
FIX15: Prompt Ablation Testing
Research mode — re-run AI analysis on a saved scan with a modified system prompt.
Stores prompt versions, response versions, and comparison metrics without rescanning.
"""
import sqlite3
import time
import json
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.files.session_manager import DB_PATH, get_session

logger = logging.getLogger("scanwise.ablation")
router = APIRouter()


def _init_ablation_table():
    """Migration-safe table creation."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ablation_runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id    TEXT NOT NULL,
            prompt_label  TEXT NOT NULL,
            prompt_text   TEXT NOT NULL,
            ai_response   TEXT,
            metrics       TEXT,
            run_at        TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


_init_ablation_table()


class AblationRequest(BaseModel):
    session_id:   str
    prompt_label: str            # e.g. "no-context", "verbose", "minimal"
    prompt_text:  str            # the modified system prompt to test
    compare_with: Optional[int] = None   # ablation run ID to diff against


@router.post("/ablation/run")
async def run_ablation(req: AblationRequest):
    """
    FIX15: Re-run AI analysis on a saved scan result using a custom system prompt.
    Does NOT re-scan — uses the stored risk data from the session.
    """
    data = get_session(req.session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")

    risk = data.get("risk", {})
    if not risk:
        raise HTTPException(status_code=400, detail="No scan data in session — run a scan first")

    # Import AI analysis; override the system prompt dynamically
    try:
        from app.ai_analysis import analyze_scan
        import inspect

        # Build a minimal context string from risk data for the prompt
        hosts = risk.get("hosts", [])
        context_lines = []
        for h in hosts:
            for p in h.get("ports", []):
                svc  = p.get("service", "unknown")
                ver  = p.get("version", "")
                port = p.get("port", 0)
                cves = [c.get("cve_id","") for c in p.get("cves", [])]
                context_lines.append(
                    f"Port {port}/{svc} {ver} — CVEs: {', '.join(cves) or 'none'}"
                )
        context_str = "\n".join(context_lines)

        # Call analyze_scan with modified prompt injected via risk override
        # We store the custom prompt and the result, then compare metrics
        modified_risk = dict(risk)
        modified_risk["_ablation_prompt"] = req.prompt_text
        modified_risk["_ablation_context"] = context_str

        ai_response = analyze_scan(modified_risk)
        response_text = json.dumps(ai_response) if isinstance(ai_response, dict) else str(ai_response)

    except Exception as e:
        logger.warning("FIX15: ablation AI call failed: %s", e)
        ai_response    = {}
        response_text  = f"AI call failed: {e}"

    # Compute simple metrics vs original
    original_ai   = data.get("ai_analysis", {})
    orig_risk_lvl = original_ai.get("overall_risk", "unknown")
    new_risk_lvl  = ai_response.get("overall_risk", "unknown") if isinstance(ai_response, dict) else "unknown"

    metrics = {
        "original_overall_risk":  orig_risk_lvl,
        "ablation_overall_risk":  new_risk_lvl,
        "risk_changed":           orig_risk_lvl != new_risk_lvl,
        "original_finding_count": len(original_ai.get("findings", [])),
        "ablation_finding_count": len(ai_response.get("findings", [])) if isinstance(ai_response, dict) else 0,
        "prompt_length_chars":    len(req.prompt_text),
    }

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "INSERT INTO ablation_runs (session_id,prompt_label,prompt_text,ai_response,metrics,run_at) VALUES (?,?,?,?,?,?)",
        (req.session_id, req.prompt_label, req.prompt_text, response_text, json.dumps(metrics), now)
    )
    run_id = cur.lastrowid
    conn.commit()

    # Compare with another run if requested
    comparison = None
    if req.compare_with:
        row = conn.execute("SELECT * FROM ablation_runs WHERE id=?", (req.compare_with,)).fetchone()
        if row:
            other_metrics = json.loads(row[4] or "{}")
            comparison = {
                "vs_run_id":      req.compare_with,
                "vs_label":       row[2],
                "risk_agreement": other_metrics.get("ablation_overall_risk") == new_risk_lvl,
                "finding_delta":  metrics["ablation_finding_count"] - other_metrics.get("ablation_finding_count", 0),
            }
    conn.close()

    return {
        "run_id":     run_id,
        "session_id": req.session_id,
        "label":      req.prompt_label,
        "metrics":    metrics,
        "comparison": comparison,
        "response":   ai_response if isinstance(ai_response, dict) else {"raw": response_text},
        "run_at":     now,
    }


@router.get("/ablation/runs/{session_id}")
async def list_ablation_runs(session_id: str):
    """FIX15: List all ablation runs for a session."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id,prompt_label,metrics,run_at FROM ablation_runs WHERE session_id=? ORDER BY id DESC",
        (session_id,)
    ).fetchall()
    conn.close()
    return {
        "session_id": session_id,
        "runs": [
            {**dict(r), "metrics": json.loads(r["metrics"] or "{}")}
            for r in rows
        ]
    }
