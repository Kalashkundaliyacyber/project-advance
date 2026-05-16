"""
Session & File Management — v4.0
FIX SUMMARY:
  #1  Chat history saved to SQLite (chat_history table) — survives server restart
  #2  Per-session scan context stored in SQLite (scan_context table) — no global race
  #4  Session IDs now include UUID segment — not guessable by timestamp+target
  #8  Retention policy: auto-purge sessions older than 30 days, cap at 200 total
  #NEW frontend_chat table — full interactive chat widget state persisted to SQLite
       This is the core fix for "rich components lost on refresh":
       Every message (user text, AI text, scan cards, CVE tables, etc.) is stored
       server-side so it survives localStorage clear, browser restart, or run.sh.
"""
import os
import json
import time
import uuid
import sqlite3
import shutil
import logging

logger = logging.getLogger("scanwise.session_manager")

BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "sessions"
)
SESSIONS_DIR = BASE_DIR

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "scanwise.db"
)

# Fix #8: retention constants
MAX_SESSIONS     = 200
RETENTION_DAYS   = 30


def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(BASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            target       TEXT,
            scan_type    TEXT,
            timestamp    TEXT,
            overall_risk TEXT,
            open_ports   INTEGER,
            cve_count    INTEGER,
            project_name TEXT DEFAULT ''
        )
    """)

    # Fix #1: chat history table — keyed by frontend session_id
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            session_id TEXT PRIMARY KEY,
            history    TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL
        )
    """)

    # Fix #2: per-session scan context — no global variable
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_context (
            session_id  TEXT PRIMARY KEY,
            context     TEXT NOT NULL DEFAULT '{}',
            updated_at  TEXT NOT NULL
        )
    """)

    # NEW: Frontend full chat state — stores ALL message types including rich widgets
    # This is the critical table that enables full UI persistence across refresh/restart
    conn.execute("""
        CREATE TABLE IF NOT EXISTS frontend_chat (
            session_id   TEXT PRIMARY KEY,
            messages     TEXT NOT NULL DEFAULT '[]',
            project_name TEXT DEFAULT '',
            scan_data    TEXT DEFAULT NULL,
            updated_at   TEXT NOT NULL
        )
    """)

    conn.commit()

    # Live migrations for existing DBs
    cols = [row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()]
    if "project_name" not in cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN project_name TEXT DEFAULT ''")
        conn.commit()

    # Live migration: add scan_data column if missing
    fc_cols = [row[1] for row in conn.execute("PRAGMA table_info(frontend_chat)").fetchall()]
    if "scan_data" not in fc_cols:
        conn.execute("ALTER TABLE frontend_chat ADD COLUMN scan_data TEXT DEFAULT NULL")
        conn.commit()

    conn.close()


_init_db()

# FIX 5: Deferred startup cleanup — runs 2s after import so it never blocks startup.
# Removes any blank/unnamed frontend_chat rows left over from previous runs.
def _startup_cleanup():
    import time as _time
    _time.sleep(2)
    try:
        purge_blank_frontend_chats()
    except Exception:
        pass

try:
    from threading import Thread as _CleanupThread
    _CleanupThread(target=_startup_cleanup, daemon=True).start()
except Exception:
    pass


# ── Session CRUD ───────────────────────────────────────────────────────────────

def create_session(target: str, scan_type: str, project_name: str = "") -> str:
    # Fix #4: add UUID to make session IDs unguessable
    ts        = time.strftime("%Y%m%d_%H%M%S")
    uid       = uuid.uuid4().hex[:8]
    safe_tgt  = target.replace("/", "_").replace(".", "-")
    session_id = f"{ts}_{uid}_{safe_tgt}_{scan_type}"

    session_path = os.path.join(BASE_DIR, session_id)
    for sub in ("raw", "parsed", "analysis", "logs", "report", "patches"):
        os.makedirs(os.path.join(session_path, sub), exist_ok=True)
    log = os.path.join(session_path, "logs", "session.log")
    with open(log, "w") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Session created\n")
        f.write(f"Target: {target}\nScan: {scan_type}\nProject: {project_name}\nID: {session_id}\n")

    # Fix #8: enforce retention on every new session
    _enforce_retention()

    return session_id


def save_raw(session_id: str, raw_output: str, xml_output: str):
    base = os.path.join(BASE_DIR, session_id, "raw")
    with open(os.path.join(base, "output.txt"), "w") as f:
        f.write(raw_output)
    with open(os.path.join(base, "output.xml"), "w") as f:
        f.write(xml_output)


def save_parsed(session_id: str, parsed: dict):
    path = os.path.join(BASE_DIR, session_id, "parsed", "parsed.json")
    with open(path, "w") as f:
        json.dump(parsed, f, indent=2)


def save_analysis(session_id: str, analysis: dict):
    path = os.path.join(BASE_DIR, session_id, "analysis", "analysis.json")
    with open(path, "w") as f:
        json.dump(analysis, f, indent=2)

    hosts = analysis.get("risk", {}).get("hosts", [])
    overall_risk = "low"
    total_ports  = 0
    total_cves   = 0

    for host in hosts:
        rs    = host.get("risk_summary", {})
        level = rs.get("overall", "low")
        priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if priority.get(level, 0) > priority.get(overall_risk, 0):
            overall_risk = level
        total_ports += rs.get("total_ports", 0)
        for port in host.get("ports", []):
            total_cves += len(port.get("cves", []))

    project_name = analysis.get("project_name", "")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO sessions
        (session_id, target, scan_type, timestamp, overall_risk, open_ports, cve_count, project_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id,
        analysis.get("target", ""),
        analysis.get("scan_type", ""),
        analysis.get("timestamp", ""),
        overall_risk,
        total_ports,
        total_cves,
        project_name,
    ))
    conn.commit()
    conn.close()



def save_patches(session_id: str, patches: list) -> None:
    """
    Persist AI patch guidance for a session permanently.
    patches: list of patch result dicts from /api/patch/all or /api/patch/guidance.
    Stored at <session>/patches/patches.json.
    Timestamp and provider metadata are preserved.
    """
    import time as _time
    path = os.path.join(BASE_DIR, session_id, "patches", "patches.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "session_id":  session_id,
        "saved_at":    _time.strftime("%Y-%m-%d %H:%M:%S"),
        "patch_count": len(patches),
        "patches":     patches,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def load_patches(session_id: str) -> dict:
    """
    Load persisted patch guidance for a session.
    Returns dict with keys: patches, saved_at, patch_count.
    Returns empty dict if no patches saved yet.
    """
    path = os.path.join(BASE_DIR, session_id, "patches", "patches.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def list_sessions(target: str = None, severity: str = None) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM sessions"
    params = []
    conditions = []
    if target:
        conditions.append("(target LIKE ? OR project_name LIKE ?)")
        params.extend([f"%{target}%", f"%{target}%"])
    if severity:
        conditions.append("overall_risk = ?")
        params.append(severity)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT 100"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_session(session_id: str) -> dict:
    path = os.path.join(BASE_DIR, session_id, "analysis", "analysis.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def delete_session(session_id: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
    conn.execute("DELETE FROM chat_history WHERE session_id=?", (session_id,))
    conn.execute("DELETE FROM scan_context WHERE session_id=?", (session_id,))
    conn.execute("DELETE FROM frontend_chat WHERE session_id=?", (session_id,))
    conn.commit()
    conn.close()
    session_dir = os.path.join(SESSIONS_DIR, session_id)
    if os.path.isdir(session_dir):
        shutil.rmtree(session_dir)
    return True


def rename_session(session_id: str, new_name: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE sessions SET project_name=? WHERE session_id=?",
        (new_name, session_id)
    )
    conn.execute(
        "UPDATE frontend_chat SET project_name=? WHERE session_id=?",
        (new_name, session_id)
    )
    conn.commit()
    conn.close()

    analysis_path = os.path.join(SESSIONS_DIR, session_id, "analysis", "analysis.json")
    if os.path.exists(analysis_path):
        try:
            with open(analysis_path) as f:
                data = json.load(f)
            data["project_name"] = new_name
            data["label"] = new_name
            with open(analysis_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    return True


# ── Fix #8: Retention policy ──────────────────────────────────────────────────

def _enforce_retention():
    """Delete sessions older than RETENTION_DAYS or beyond MAX_SESSIONS cap."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        cutoff = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(time.time() - RETENTION_DAYS * 86400)
        )
        old_rows = conn.execute(
            "SELECT session_id FROM sessions WHERE timestamp < ? ORDER BY timestamp ASC",
            (cutoff,)
        ).fetchall()
        for row in old_rows:
            _delete_session_files(row["session_id"])
        if old_rows:
            conn.execute("DELETE FROM sessions WHERE timestamp < ?", (cutoff,))
            # FIX4: clean all child tables after purging old sessions
            conn.execute("DELETE FROM chat_history WHERE session_id NOT IN (SELECT session_id FROM sessions)")
            conn.execute("DELETE FROM scan_context WHERE session_id NOT IN (SELECT session_id FROM sessions)")
            # FIX4: frontend_chat orphaned rows were NOT cleaned before — now fixed
            conn.execute("""
                DELETE FROM frontend_chat
                WHERE session_id NOT IN (SELECT session_id FROM sessions)
            """)

        # Cap at MAX_SESSIONS — delete oldest beyond cap
        total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        if total > MAX_SESSIONS:
            overflow = conn.execute(
                "SELECT session_id FROM sessions ORDER BY timestamp ASC LIMIT ?",
                (total - MAX_SESSIONS,)
            ).fetchall()
            for row in overflow:
                _delete_session_files(row["session_id"])
            ids = tuple(r["session_id"] for r in overflow)
            placeholders = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM sessions WHERE session_id IN ({placeholders})", ids)

        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Retention enforcement failed: %s", e)


def _delete_session_files(session_id: str):
    d = os.path.join(SESSIONS_DIR, session_id)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)


# ── Fix #1: Chat history — SQLite-backed ─────────────────────────────────────

def save_chat_history(session_id: str, history: list):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO chat_history (session_id, history, updated_at)
        VALUES (?, ?, ?)
    """, (session_id, json.dumps(history), time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def load_chat_history(session_id: str) -> list:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT history FROM chat_history WHERE session_id=?", (session_id,)
    ).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return []
    return []


# ── Fix #2: Per-session scan context ─────────────────────────────────────────

def save_scan_context(session_id: str, context: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO scan_context (session_id, context, updated_at)
        VALUES (?, ?, ?)
    """, (session_id, json.dumps(context), time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def load_scan_context(session_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT context FROM scan_context WHERE session_id=?", (session_id,)
    ).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return {}
    return {}


# ── Frontend Chat State Persistence ──────────────────────────────────────────
# Stores the COMPLETE frontend chat state including rich widget tokens (scan cards,
# CVE tables, patch dashboards, etc.) so the entire interactive workspace can be
# restored after browser refresh, tab close, or server restart.

_INVALID_PROJECT_NAMES = {'unnamed session', 'unnamed', 'untitled', 'new session', 'new project', ''}


def _is_valid_project_name(name: str) -> bool:
    """FIX 4: Return True only if name is a non-empty, non-placeholder project name."""
    if not name or not isinstance(name, str):
        return False
    cleaned = name.strip().lower()
    return bool(cleaned) and cleaned not in _INVALID_PROJECT_NAMES


def save_frontend_chat(session_id: str, messages: list, project_name: str = "", scan_data: dict = None):
    """
    Persist full frontend chat messages (including rich widget tokens) to SQLite.
    FIX 1+4: Refuses to save sessions with no valid project name AND no messages.
    This is the core guard preventing blank "Unnamed Session" entries in the DB.

    Rich tokens look like:  __SCAN_COMPLETE__:{...json...}
    On restore, the frontend parses these and re-renders the full interactive widget.
    """
    try:
        trimmed_name = (project_name or '').strip()
        has_valid_name = _is_valid_project_name(trimmed_name)
        has_messages = bool(messages and len(messages) > 0)

        # FIX 1: Reject save if no valid project name AND no messages
        # This prevents the DB filling up with unnamed empty sessions
        if not has_valid_name and not has_messages:
            logger.debug(
                "save_frontend_chat blocked: session %s has no name and no messages", session_id
            )
            return

        # FIX 4: Reject explicitly invalid names (unless there is real content like messages/scan)
        if not has_valid_name and trimmed_name:
            logger.debug(
                "save_frontend_chat blocked: session %s has invalid project name '%s'", session_id, trimmed_name
            )
            return

        # Keep last 500 messages maximum to avoid DB bloat
        msgs = messages[-500:] if len(messages) > 500 else messages
        scan_json = json.dumps(scan_data, ensure_ascii=False) if scan_data else None
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT OR REPLACE INTO frontend_chat (session_id, messages, project_name, scan_data, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session_id,
            json.dumps(msgs, ensure_ascii=False),
            trimmed_name,
            scan_json,
            time.strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()
        logger.debug("Saved %d messages for session %s (project: %s)", len(msgs), session_id, trimmed_name)
    except Exception as e:
        logger.warning("save_frontend_chat failed for %s: %s", session_id, e)


def load_frontend_chat(session_id: str) -> dict:
    """
    Load persisted frontend chat state for a session.
    Returns dict with 'messages', 'project_name', and optionally 'scan_data'.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT messages, project_name, scan_data FROM frontend_chat WHERE session_id=?",
            (session_id,)
        ).fetchone()
        conn.close()
        if row:
            msgs = json.loads(row[0]) if row[0] else []
            scan_data = json.loads(row[2]) if row[2] else None
            return {
                "messages": msgs,
                "project_name": row[1] or "",
                "scan_data": scan_data,
            }
    except Exception as e:
        logger.warning("load_frontend_chat failed for %s: %s", session_id, e)
    return {"messages": [], "project_name": "", "scan_data": None}


def list_frontend_chats() -> list:
    """
    List all named frontend project sessions ordered by last update.
    FIX 5: Only returns sessions that have a non-empty project name.
    Sessions without a project name are never shown in History.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT session_id, project_name, updated_at,
                   json_array_length(messages) as msg_count
            FROM frontend_chat
            WHERE project_name IS NOT NULL
              AND TRIM(project_name) != ''
              AND LOWER(TRIM(project_name)) NOT IN ('unnamed session', 'unnamed', 'untitled', 'new session', 'new project')
            ORDER BY updated_at DESC
            LIMIT 100
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning("list_frontend_chats failed: %s", e)
        return []


def purge_blank_frontend_chats() -> int:
    """
    FIX 5: Remove all frontend_chat rows that:
      - have no project_name (null/empty/whitespace)
      - have no messages
      - have an 'Unnamed Session' or similar invalid project name
    Returns the number of rows deleted.
    Safe to call at startup — will not remove valid named sessions.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        result = conn.execute("""
            DELETE FROM frontend_chat
            WHERE (
                project_name IS NULL
                OR TRIM(project_name) = ''
                OR LOWER(TRIM(project_name)) IN ('unnamed session', 'unnamed', 'untitled', 'new session', 'new project')
            )
            AND (messages IS NULL OR messages = '[]' OR json_array_length(messages) = 0)
        """)
        deleted = result.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            logger.info("purge_blank_frontend_chats: removed %d blank session(s)", deleted)
        return deleted
    except Exception as e:
        logger.warning("purge_blank_frontend_chats failed: %s", e)
        return 0
