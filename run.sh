#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Run Script
#  Kali Linux | Python 3.13 | LAN accessible on port 3332
#
#  First time:  bash setup_env.sh
#  Every time:  bash run.sh
#  Options:     --test | --benchmark
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
PY="$VENV/bin/python3"
PORT="${PORT:-3332}"

# Load .env if it exists
if [ -f "$PROJECT_DIR/.env" ]; then
    export $(grep -v '^#' "$PROJECT_DIR/.env" | xargs)
    echo -e "${GREEN}  ✓ .env loaded${NC}"
fi

echo -e "${CYAN}"
echo "  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗    ██╗██╗███████╗███████╗"
echo "  ██╔════╝██╔════╝██╔══██╗████╗  ██║██║    ██║██║██╔════╝██╔════╝"
echo "  ███████╗██║     ███████║██╔██╗ ██║██║ █╗ ██║██║███████╗█████╗  "
echo "  ╚════██║██║     ██╔══██║██║╚██╗██║██║███╗██║██║╚════██║██╔══╝  "
echo "  ███████║╚██████╗██║  ██║██║ ╚████║╚███╔███╔╝██║███████║███████╗"
echo "  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝"
echo -e "${NC}               AI Security Intelligence Platform v2.0"
echo ""

# ── [1/3] Check venv ─────────────────────────────────────────────
echo -e "${YELLOW}[1/3] Checking environment...${NC}"
if [ ! -f "$PY" ]; then
    echo -e "${RED}  ✗ .venv not found. Run: bash setup_env.sh${NC}"; exit 1
fi

"$PY" -c "
import fastapi, uvicorn, pydantic, jinja2, slowapi
assert pydantic.VERSION.startswith('1.'), f'pydantic {pydantic.VERSION} is v2'
print(f'  fastapi {fastapi.__version__}  uvicorn {uvicorn.__version__}  pydantic {pydantic.VERSION}')
" 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import check failed. Run: bash setup_env.sh${NC}"; exit 1
fi

echo -e "${GREEN}  ✓ Environment OK${NC}"

# ── [2/3] Check nmap ─────────────────────────────────────────────
echo -e "${YELLOW}[2/3] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ $(nmap --version | head -1)${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not found — simulation mode active${NC}"
fi

mkdir -p data/sessions data/cve_db data/logs reports exports

# ── Optional modes ────────────────────────────────────────────────
if [ "$1" = "--test" ]; then
    echo -e "${YELLOW}\n[TESTS] Running unit tests...${NC}"
    "$PY" tests/run_tests.py; exit $?
fi
if [ "$1" = "--benchmark" ]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running CVE benchmark...${NC}"
    "$PY" tests/benchmark.py; exit $?
fi

# ── [3/3] Detect LAN IP and start server ─────────────────────────
echo -e "${YELLOW}[3/3] Starting ScanWise AI...${NC}"

LAN_IP=$("$PY" -c "
import socket
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',80))
    print(s.getsockname()[0]); s.close()
except: print('127.0.0.1')
")

# ── Check if ScanWise is already running on this port ────────────────────────
PID_FILE="$PROJECT_DIR/.scanwise.pid"

# ── Handle --restart: kill any running instance first ────────────────────────
if [ "$1" = "--restart" ]; then
    echo -e "${YELLOW}  → Stopping any running ScanWise instance...${NC}"
    # Kill by PID file
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            kill "$OLD_PID" 2>/dev/null
            sleep 2
            # Force kill if still alive
            kill -0 "$OLD_PID" 2>/dev/null && kill -9 "$OLD_PID" 2>/dev/null
            echo -e "${GREEN}  ✓ Previous instance stopped (PID $OLD_PID)${NC}"
        fi
        rm -f "$PID_FILE"
    fi
    # Also kill any uvicorn on our port (catches manual starts)
    STRAY=$(lsof -ti tcp:$PORT 2>/dev/null || ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP "pid=\K[0-9]+" | head -1)
    if [ -n "$STRAY" ]; then
        kill "$STRAY" 2>/dev/null
        sleep 1
        echo -e "${GREEN}  ✓ Freed port $PORT${NC}"
    fi
fi

# ── Kill any stray process occupying our port (non-restart path) ─────────────
STRAY_PID=$(lsof -ti tcp:$PORT 2>/dev/null | head -1)
if [ -n "$STRAY_PID" ]; then
    # Verify this is our own previous instance via PID file
    if [ -f "$PID_FILE" ]; then
        FILE_PID=$(cat "$PID_FILE" 2>/dev/null)
        if [ "$FILE_PID" = "$STRAY_PID" ]; then
            # Check if it actually responds — if yes, report and exit cleanly
            if curl -sf --max-time 2 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
                echo -e "${GREEN}  ✓ ScanWise is already running (PID $STRAY_PID)${NC}"
                echo ""
                echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
                echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
                echo -e "${CYAN}  Session state preserved — no data lost${NC}"
                echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                echo -e "${CYAN}  To force a restart, run: bash run.sh --restart${NC}"
                echo ""
                exit 0
            fi
        fi
    fi
    # Port occupied by dead/zombie process — kill it
    echo -e "${YELLOW}  ⚠  Port $PORT occupied by PID $STRAY_PID — killing stale process${NC}"
    kill "$STRAY_PID" 2>/dev/null
    sleep 2
    kill -9 "$STRAY_PID" 2>/dev/null
    echo -e "${GREEN}  ✓ Port $PORT freed${NC}"
fi

# Clean up any stale PID file
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
        rm -f "$PID_FILE"
        echo -e "${YELLOW}  ⚠  Stale PID file removed — starting fresh${NC}"
    fi
fi

# ── Write startup token so the frontend opens a FRESH chat ───────
# Every time run.sh executes a new server instance, we stamp a unique
# token into data/startup_token.txt.  The frontend reads this via
# GET /api/startup-token on page load.  If the token differs from
# what is stored in localStorage, SessionManager forces a new session
# instead of restoring the previous one — giving a clean chat every
# time run.sh is executed.
STARTUP_TOKEN="$(date +%s)_$$_$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n' 2>/dev/null || echo $RANDOM)"
echo "$STARTUP_TOKEN" > "$PROJECT_DIR/data/startup_token.txt"
echo -e "${GREEN}  ✓ Fresh chat token written (new session on connect)${NC}"

echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
echo -e "${CYAN}  Mobile →  Connect to same Wi-Fi, open LAN URL${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}  Press Ctrl+C or click the Stop button in the UI to stop${NC}"
echo ""

# Graceful shutdown handler
_graceful_shutdown() {
  # Kill uvicorn child if running
  if [ -n "$UVICORN_PID" ] && kill -0 "$UVICORN_PID" 2>/dev/null; then
    kill "$UVICORN_PID" 2>/dev/null
  fi
  rm -f "$PID_FILE"
  echo -e "${CYAN}\n  Thank you for using ScanWise AI! Goodbye.${NC}"
  echo -e "${YELLOW}  Session data has been preserved in data/ directory.${NC}\n"
}
trap '_graceful_shutdown' EXIT INT TERM

export PORT="$PORT"

# ── Start uvicorn in background, capture its PID ─────────────────
"$PY" -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" &
UVICORN_PID=$!

# Write the REAL uvicorn PID to the PID file
echo "$UVICORN_PID" > "$PID_FILE"

# Wait for server to actually come up (up to 15 seconds)
echo -e "${CYAN}  → Waiting for server to start...${NC}"
READY=0
for i in $(seq 1 15); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" = "1" ]; then
    echo -e "${GREEN}  ✓ Server is up and responding!${NC}"
    echo ""
    echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ ScanWise AI is running (PID $UVICORN_PID)${NC}"
    echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
    echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
    echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}  Press Ctrl+C to stop${NC}"
    echo ""
else
    echo -e "${RED}  ✗ Server did not respond in 15 seconds.${NC}"
    echo -e "${RED}    Check logs above for startup errors.${NC}"
    echo -e "${YELLOW}    Try: bash run.sh --restart${NC}"
    # Don't exit — uvicorn may still be starting (slow machine)
fi

# Keep the script alive — wait for uvicorn to finish
wait "$UVICORN_PID"
