"""
Scan Control Module v2.0
- /scan/stop    — kill running scan
- /scan/progress — polling fallback (kept for backward compat)
- /scan/stream  — NEW: Server-Sent Events endpoint (replaces polling)
"""
import os, signal, time, threading, asyncio, json
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

ctrl_router = APIRouter()

# ── Shared scan state ─────────────────────────────────────────────────────────
class ScanState:
    def __init__(self):
        self.pid        = None
        self.running    = False
        self.progress   = 0
        self.status     = "idle"
        self.start_time = None
        self.scan_type  = ""
        self.target     = ""
        self._lock      = threading.Lock()
        self._listeners: list = []   # SSE subscriber queues
        self._last_nmap_line: str = ""  # last nmap '% done' line from real stderr

    def start(self, pid, scan_type, target):
        with self._lock:
            self.pid        = pid
            self.running    = True
            self.progress   = 0
            self.status     = "running"
            self.start_time = time.time()
            self.scan_type  = scan_type
            self.target     = target
        self._broadcast()

    def update_progress(self, pct):
        with self._lock:
            self.progress = min(int(pct), 99)
        self._broadcast()

    def complete(self):
        with self._lock:
            self.running  = False
            self.progress = 100
            self.status   = "complete"
            self.pid      = None
        self._broadcast()

    def stop(self):
        with self._lock:
            self.running = False
            self.status  = "stopped"
            old_pid      = self.pid
            self.pid     = None
        self._broadcast()
        return old_pid

    def reset(self):
        with self._lock:
            self.pid = None; self.running = False
            self.progress = 0; self.status = "idle"
            self.start_time = None
        self._broadcast()

    def snapshot(self) -> dict:
        return {
            "progress":  self.progress,
            "status":    self.status,
            "target":    self.target,
            "scan_type": self.scan_type,
            "running":   self.running,
        }

    def add_listener(self, q):
        with self._lock:
            self._listeners.append(q)

    def remove_listener(self, q):
        with self._lock:
            try: self._listeners.remove(q)
            except ValueError: pass

    def _broadcast(self):
        data = self.snapshot()
        dead = []
        for q in list(self._listeners):
            try:
                q.put_nowait(data)
            except Exception:
                dead.append(q)
        for q in dead:
            self.remove_listener(q)


scan_state = ScanState()

# Fix #3: Per-session scan state registry — prevents concurrent scan race
_session_states: dict = {}
_session_states_lock = __import__("threading").Lock()

def get_scan_state(session_id: str = None) -> ScanState:
    """Return the ScanState for a specific session, or the global one."""
    if not session_id:
        return scan_state
    with _session_states_lock:
        if session_id not in _session_states:
            _session_states[session_id] = ScanState()
        return _session_states[session_id]

def clear_scan_state(session_id: str):
    """Remove a completed session's state to free memory."""
    with _session_states_lock:
        _session_states.pop(session_id, None)


# ── Progress estimator (background thread) ────────────────────────────────────
PHASE_WEIGHTS = {
    "tcp_basic":      [("host_discovery",10),("port_scan",85),("finalise",5)],
    "tcp_syn":        [("host_discovery",10),("port_scan",85),("finalise",5)],
    "udp_scan":       [("host_discovery",5), ("port_scan",90),("finalise",5)],
    "service_detect": [("host_discovery",10),("port_scan",40),("service",45),("finalise",5)],
    "version_deep":   [("host_discovery",10),("port_scan",30),("service",20),("version",35),("finalise",5)],
    "os_detect":      [("host_discovery",10),("port_scan",40),("os",45),("finalise",5)],
    "port_range":     [("host_discovery",10),("port_scan",85),("finalise",5)],
    "enum_scripts":   [("host_discovery",10),("port_scan",30),("service",20),("scripts",35),("finalise",5)],
}
SCAN_DURATIONS = {
    "tcp_basic":60, "tcp_syn":60, "udp_scan":3600, "service_detect":120,
    "version_deep":300, "os_detect":180, "port_range":180, "enum_scripts":600,
    "full_tcp":2700, "full_service_enum":900, "stealth_syn":300,
    "ping_sweep":30, "host_discovery":30, "arp_discovery":20,
    "banner_grab":120, "db_discovery":90,
    "vuln_scan":1800, "smb_audit":180, "ftp_audit":90, "ssh_audit":90, "web_pentest":300,
    "aggressive_pentest":2700, "firewall_evasion":300, "frag_scan":240,
    "decoy_scan":240, "timing_manipulation":900, "ultimate_recon":7200,
}

def _progress_worker():
    """
    Background thread that pushes progress to scan_state.
    Primary source: real nmap '% done' lines from stderr (set by executor).
    Fallback:       elapsed-time estimation (used when nmap hasn't emitted progress yet).
    """
    import re
    _nmap_pct_re = re.compile(r'(\d+(?:\.\d+)?)\s*%\s*done', re.IGNORECASE)

    while True:
        time.sleep(0.8)
        if not scan_state.running:
            continue

        # Check if the executor injected a real nmap progress line
        real_line = getattr(scan_state, '_last_nmap_line', '')
        if real_line:
            m = _nmap_pct_re.search(real_line)
            if m:
                pct = min(99, float(m.group(1)))
                scan_state.update_progress(pct)
                continue

        # Fallback: estimate from elapsed time vs expected duration
        elapsed  = time.time() - (scan_state.start_time or time.time())
        expected = SCAN_DURATIONS.get(scan_state.scan_type, 900)
        pct      = min(95, (elapsed / expected) * 100)
        scan_state.update_progress(pct)

_t = threading.Thread(target=_progress_worker, daemon=True)
_t.start()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@ctrl_router.get("/scan/progress")
async def get_progress():
    """Polling fallback — kept for backward compat."""
    return scan_state.snapshot()


@ctrl_router.get("/scan/stream")
async def stream_progress(request: Request):
    """
    Server-Sent Events endpoint — replaces the 1-second polling loop.
    The frontend connects once; the server pushes updates on every state change.
    """
    import asyncio

    queue: asyncio.Queue = asyncio.Queue(maxsize=32)
    scan_state.add_listener(queue)

    async def event_generator():
        try:
            # Send initial state immediately
            snap = scan_state.snapshot()
            yield f"data: {json.dumps(snap)}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(data)}\n\n"
                    # Stop streaming once scan is done
                    if data.get("status") in ("complete", "stopped", "idle"):
                        break
                except asyncio.TimeoutError:
                    # Keepalive comment so proxy doesn't close the connection
                    yield ": keepalive\n\n"
        finally:
            scan_state.remove_listener(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",    # disable nginx buffering
            "Connection": "keep-alive",
        }
    )


@ctrl_router.post("/scan/stop")
async def stop_scan():
    if not scan_state.running:
        return {"success": False, "message": "No scan running"}

    pid = scan_state.stop()

    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.8)
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        except ProcessLookupError:
            pass
        except PermissionError:
            pass

    return {"success": True, "message": "Scan stopped"}
