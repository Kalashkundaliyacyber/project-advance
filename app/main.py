"""ThreatWeave AI — FastAPI Application Entry Point

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

logger = logging.getLogger("threatweave.main")
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn

from app.api.routes import router, _run_scan_pipeline
from app.api.analysis_routes import analysis_router
from app.api.patch_api import router as patch_router
from app.api.scan_control import ctrl_router
from app.api.scheduled_scans import router as sched_router, run_due_schedules
from app.api.presets import router as presets_router
from app.api.findings import router as findings_router
from app.api.discovery import router as discovery_router
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
    title="ThreatWeave AI",
    description="ThreatWeave AI — 4-Model Local Stack: Qwen 2.5 7B | Llama 3.2/3.1 | DeepSeek R1 8B",
    version="4.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Allow all private LAN subnets (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
# plus localhost. This prevents "NetworkError" when IP changes or you access
# from a different device on the same network.
import re as _re
def _is_private_origin(origin: str) -> bool:
    return bool(_re.match(
        r"http://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?$",
        origin or ""
    ))

_ALLOWED_ORIGINS_ENV = os.environ.get("ALLOWED_ORIGINS", "")
_CORS_ORIGINS = (
    [o.strip() for o in _ALLOWED_ORIGINS_ENV.split(",") if o.strip()]
    if _ALLOWED_ORIGINS_ENV
    else ["*"]  # default: open — LAN-only server; set ALLOWED_ORIGINS in .env to restrict
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
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
        protected = ["/api/scan", "/api/report", "/api/chat"]
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
app.include_router(analysis_router, prefix="/api") # Phase 8: analysis & intelligence routes
app.include_router(discovery_router, prefix="/api")  # FIX9: network discovery


# ── Fix #5: Rate-limit /api/scan (20/minute per IP) ──────────────────────────
# Simple in-memory sliding-window counter — does NOT fire on /api/scan/stream
# or any other route, only on POST /api/scan exactly.

import collections, asyncio as _asyncio

_scan_counts: dict = collections.defaultdict(list)   # ip -> [timestamps]
_scan_lock = _asyncio.Lock()                          # async-safe (no event-loop block)
_SCAN_RATE_LIMIT  = 20
_SCAN_RATE_WINDOW = 60   # seconds

@app.middleware("http")
async def _enforce_scan_rate_limit(request: Request, call_next):
    """Block more than 20 POST /api/scan requests per IP per minute."""
    if request.method == "POST" and request.url.path == "/api/scan":
        client_ip = (request.client.host if request.client else "unknown")
        now = __import__("time").time()
        async with _scan_lock:          # asyncio.Lock — never blocks event loop
            timestamps = _scan_counts[client_ip]
            _scan_counts[client_ip] = [t for t in timestamps if now - t < _SCAN_RATE_WINDOW]
            if len(_scan_counts[client_ip]) >= _SCAN_RATE_LIMIT:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded: max {_SCAN_RATE_LIMIT} scans per minute. Try again shortly."}
                )
            _scan_counts[client_ip].append(now)
    return await call_next(request)




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
        token = f"direct_{int(time.time())}"
    return {"token": token}


@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version":   "4.0.0",
    }


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
    print("  🛡  ThreatWeave AI v4.0 — Security Intelligence Platform")
    print("━" * 54)
    print(f"  Local  →  http://localhost:{PORT}")
    print(f"  LAN    →  http://{LAN_IP}:{PORT}")
    print(f"  Docs   →  http://localhost:{PORT}/docs")
    if API_TOKEN:
        print(f"  Token  →  Required (X-API-Token header)")
    else:
        print(f"  Token  →  Not set (open access on LAN)")
    print("━" * 54 + "\n")

    # FIX8: fire any overdue scheduled scans on server startup
    try:
        asyncio.create_task(run_due_schedules(_run_scan_pipeline))
    except Exception as e:
        logger.warning("startup: failed to schedule due scans: %s", e)


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
