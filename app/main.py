"""ScanWise AI — FastAPI Application Entry Point

FIX v2.1:
  - /api/chat/save endpoint previously used multiple bare Body() parameters.
    When the frontend sends { session_id, messages } as a single JSON object,
    FastAPI requires either a Pydantic model or Body(embed=True) on each param.
    Fixed by introducing a ChatSaveRequest Pydantic model.
"""
import os
import socket
import time
import logging
import asyncio
from fastapi import FastAPI, Request

logger = logging.getLogger("scanwise.main")
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Any
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn

from app.api.routes import router, _run_scan_pipeline
from app.api.patch_api import router as patch_router
from app.api.scan_control import ctrl_router
from app.api.scheduled_scans import router as sched_router, run_due_schedules
from app.api.presets import router as presets_router
from app.api.findings import router as findings_router
from app.api.discovery import router as discovery_router
from app.api.ablation import router as ablation_router
from app.report.multi_format import report_router
from app.vuln.routes import nvd_router
from app.files.chat_manager import save_chat, list_chats
from app.files.session_manager import save_chat_history, load_chat_history

HOST      = os.environ.get("HOST", "0.0.0.0")
PORT      = int(os.environ.get("PORT", "3332"))
API_TOKEN = os.environ.get("API_TOKEN", "")
DEBUG     = os.environ.get("DEBUG", "false").lower() == "true"


def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LAN_IP = get_lan_ip()
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="ScanWise AI",
    description="Context-Aware Explainable Vulnerability Intelligence System",
    version="2.1.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

CORS_ORIGINS = [
    "http://localhost:3332",
    "http://127.0.0.1:3332",
    f"http://{LAN_IP}:3332",
    "http://localhost:8000",
    f"http://{LAN_IP}:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def no_cache_static_middleware(request: Request, call_next):
    """
    Disable browser caching for JS, CSS, and HTML files so that code changes
    are reflected immediately without requiring a hard refresh (Ctrl+Shift+R).
    This prevents the 304 Not Modified / stale cache problem during development.
    """
    response = await call_next(request)
    path = request.url.path
    if path.endswith(('.js', '.css', '.html')) or path == '/':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        # Remove ETag and Last-Modified so browser never sends conditional requests
        for h in ('etag', 'last-modified'):
            try:
                del response.headers[h]
            except KeyError:
                pass
    return response


@app.middleware("http")
async def token_middleware(request: Request, call_next):
    if API_TOKEN:
        protected = ["/api/scan", "/api/report", "/api/compare", "/api/chat"]
        if any(request.url.path.startswith(p) for p in protected):
            token = request.headers.get("X-API-Token", "")
            if token != API_TOKEN:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API token."}
                )
    return await call_next(request)


app.include_router(router,        prefix="/api")
app.include_router(patch_router,  prefix="/api/patch")  # v2: dedicated patch API
app.include_router(ctrl_router,   prefix="/api")
app.include_router(report_router, prefix="/api")
app.include_router(nvd_router)                    # prefix is /api/nvd (set in router)
app.include_router(sched_router, prefix="/api")   # FIX8: scheduled scans
app.include_router(presets_router, prefix="/api") # FIX10: scan presets
app.include_router(findings_router, prefix="/api")# FIX12: false positive tracking
app.include_router(discovery_router, prefix="/api")  # FIX9: network discovery
app.include_router(ablation_router, prefix="/api")   # FIX15: prompt ablation testing

# -- Telemetry and Circuit Breaker endpoints (Fix 9 and 7)
from fastapi import APIRouter as _APIRouter
_obs_router = _APIRouter()

@_obs_router.get("/telemetry")
async def telemetry_snapshot():
    from app.ai.utils.telemetry import telemetry
    return telemetry.snapshot()

@_obs_router.post("/ai/circuit-reset/{provider}")
async def reset_circuit_breaker(provider: str):
    from app.ai.routing.ai_router import ai_router as _ai
    _ai.reset_circuit_breaker(provider)
    return {"ok": True, "provider": provider, "state": "closed"}

@_obs_router.get("/ai/circuit-status")
async def circuit_status():
    from app.ai.routing.ai_router import ai_router as _ai
    st = _ai.status()
    return {"circuit_breakers": st.get("circuit_breakers", {})}

app.include_router(_obs_router, prefix="/api")


# ── Fix #5: Rate-limit /api/scan (20/minute per IP) ──────────────────────────
# Simple in-memory sliding-window counter — does NOT fire on /api/scan/stream
# or any other route, only on POST /api/scan exactly.

import collections, threading as _threading

_scan_counts: dict = collections.defaultdict(list)   # ip -> [timestamps]
_scan_lock = _threading.Lock()
_SCAN_RATE_LIMIT  = 20
_SCAN_RATE_WINDOW = 60   # seconds

@app.middleware("http")
async def _enforce_scan_rate_limit(request: Request, call_next):
    """Block more than 20 POST /api/scan requests per IP per minute."""
    if request.method == "POST" and request.url.path == "/api/scan":
        client_ip = (request.client.host if request.client else "unknown")
        now = __import__("time").time()
        with _scan_lock:
            timestamps = _scan_counts[client_ip]
            # Drop entries outside the window
            _scan_counts[client_ip] = [t for t in timestamps if now - t < _SCAN_RATE_WINDOW]
            if len(_scan_counts[client_ip]) >= _SCAN_RATE_LIMIT:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded: max {_SCAN_RATE_LIMIT} scans per minute. Try again shortly."}
                )
            _scan_counts[client_ip].append(now)
    return await call_next(request)


# ── Chat save endpoint (Pydantic model fix) ────────────────────────────────────

class ChatSaveRequest(BaseModel):
    session_id:   str      = ""
    messages:     List[Any] = []
    project_name: str      = ""


@app.post("/api/chat/save")
@limiter.limit("120/minute")
async def save_chat_endpoint(request: Request, body: ChatSaveRequest):
    # Persist chat messages to SQLite (keyed by frontend session_id)
    if body.session_id:
        try:
            save_chat_history(body.session_id, body.messages)
        except Exception as e:
            logger.warning("SQLite chat save failed for %s: %s", body.session_id, e)
        # Also register this as a named project session so it appears in history
        if body.project_name:
            try:
                _register_project_session(body.session_id, body.project_name, len(body.messages))
            except Exception as e:
                logger.warning("Project session register failed for %s: %s", body.session_id, e)
    return {"saved": True, "session_id": body.session_id}


def _register_project_session(session_id: str, project_name: str, msg_count: int):
    """Upsert a row in project_sessions so the History drawer can show named chats."""
    import sqlite3, time as _time
    from app.files.session_manager import DB_PATH, _init_db
    _init_db()   # ensure tables exist
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS project_sessions (
            session_id   TEXT PRIMARY KEY,
            project_name TEXT NOT NULL DEFAULT '',
            msg_count    INTEGER NOT NULL DEFAULT 0,
            updated_at   TEXT NOT NULL
        )
    """)
    conn.execute("""
        INSERT OR REPLACE INTO project_sessions (session_id, project_name, msg_count, updated_at)
        VALUES (?, ?, ?, ?)
    """, (session_id, project_name, msg_count, _time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


@app.get("/api/project-sessions")
@limiter.limit("60/minute")
async def list_project_sessions(request: Request):
    """Return all named project sessions (chat sessions, not scan sessions)."""
    import sqlite3
    from app.files.session_manager import DB_PATH, _init_db
    _init_db()
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE IF NOT EXISTS project_sessions (
                session_id   TEXT PRIMARY KEY,
                project_name TEXT NOT NULL DEFAULT '',
                msg_count    INTEGER NOT NULL DEFAULT 0,
                updated_at   TEXT NOT NULL
            )
        """)
        rows = conn.execute(
            "SELECT * FROM project_sessions ORDER BY updated_at DESC LIMIT 200"
        ).fetchall()
        conn.close()
        return {"sessions": [dict(r) for r in rows]}
    except Exception as e:
        logger.warning("list_project_sessions failed: %s", e)
        return {"sessions": []}


@app.get("/api/chat/load/{session_id}")
@limiter.limit("60/minute")
async def load_chat_endpoint(request: Request, session_id: str):
    """Return saved chat messages for a session so the frontend can restore them."""
    try:
        messages = load_chat_history(session_id)
        return {"session_id": session_id, "messages": messages}
    except Exception as e:
        logger.warning("Chat load failed for %s: %s", session_id, e)
        return {"session_id": session_id, "messages": []}


@app.get("/api/chat/history")
@limiter.limit("60/minute")
async def list_chat_history(request: Request):
    return {"files": list_chats()}


@app.get("/api/startup-token")
async def startup_token():
    """
    Returns the startup token written by run.sh on every fresh server start.
    The frontend compares this to its cached token in localStorage; if they
    differ, SessionManager creates a brand-new chat session instead of
    restoring the previous one — giving a clean chat on every run.sh execution.
    """
    token_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "startup_token.txt"
    )
    try:
        with open(token_path) as f:
            token = f.read().strip()
    except FileNotFoundError:
        # Server started without run.sh (e.g. direct uvicorn call) — generate one
        token = f"direct_{int(time.time())}"
    return {"token": token}


@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version":   "2.1.0",
    }

# /api/shutdown intentionally omitted for security — use Ctrl+C or kill


@app.get("/config")
async def config():
    return {
        "host":          LAN_IP,
        "port":          PORT,
        "local_url":     f"http://localhost:{PORT}",
        "lan_url":       f"http://{LAN_IP}:{PORT}",
        "token_enabled": bool(API_TOKEN),
        "debug":         DEBUG,
    }


static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "statics")


@app.get("/")
async def serve_ui():
    index = os.path.join(static_dir, "index.html")
    return FileResponse(index)


if os.path.isdir(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")


@app.on_event("startup")
async def startup_event():
    base = os.path.dirname(os.path.dirname(__file__))
    for d in ["data/sessions", "data/cve_db", "data/version_db",
              "data/logs", "data/history/chat", "reports", "exports"]:
        os.makedirs(os.path.join(base, d), exist_ok=True)

    print("\n" + "━" * 54)
    print("  🛡  ScanWise AI v2.1 — Security Intelligence Platform")
    print("━" * 54)
    print(f"  Local  →  http://localhost:{PORT}")
    print(f"  LAN    →  http://{LAN_IP}:{PORT}")
    print(f"  Docs   →  http://localhost:{PORT}/docs")
    if API_TOKEN:
        print(f"  Token  →  Required (X-API-Token header)")
    else:
        print(f"  Token  →  Not set (open access on LAN)")
    print("━" * 54 + "\n")

    # AI provider health check — logs which models are ready at startup
    try:
        from app.ai.routing.ai_router import ai_router
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, ai_router.run_startup_health_check)
    except Exception:
        pass  # non-fatal — providers checked lazily on first call

    # FIX8: fire any overdue scheduled scans on server startup
    try:
        asyncio.ensure_future(run_due_schedules(_run_scan_pipeline))
    except Exception as e:
        pass  # non-fatal


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
