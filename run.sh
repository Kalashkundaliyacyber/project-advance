#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  THREATWEAVE — Launch Script
#  AI Security Intelligence Platform v4.0
#
#  First time?  Run:  bash setup_env.sh
#  Every time:  Run:  bash run.sh
#
#  Options:
#    --restart    Force stop any running instance then start fresh
#    --test       Run unit test suite
#    --benchmark  Run CVE benchmark suite
# ═══════════════════════════════════════════════════════════════════

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ── Colours ────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
PY="$VENV/bin/python3"
PORT="${PORT:-3332}"
PID_FILE="$PROJECT_DIR/.threatweave.pid"

# ── Load .env ──────────────────────────────────────────────────────
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$PROJECT_DIR/.env"
    set +a
    echo -e "${GREEN}  ✓ .env loaded${NC}"
fi

# ── Banner ─────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗"
echo "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝"
echo "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  "
echo "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  "
echo "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗"
echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝"
echo -e "${NC}"
echo -e "               ${BOLD}AI Security Intelligence Platform v4.0${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════
# [1/3] Environment check
# ══════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[1/3] Checking environment...${NC}"

if [ ! -f "$PY" ]; then
    echo -e "${RED}  ✗ Virtual environment not found${NC}"
    echo -e "${YELLOW}    Run:  bash setup_env.sh${NC}"
    exit 1
fi

"$PY" -c "
import fastapi, uvicorn, pydantic, jinja2, slowapi
assert pydantic.VERSION.startswith('1.'), f'pydantic {pydantic.VERSION} requires v1'
print(f'  fastapi {fastapi.__version__}  uvicorn {uvicorn.__version__}  pydantic {pydantic.VERSION}')
" 2>&1 || {
    echo -e "${RED}  ✗ Dependency check failed — run: bash setup_env.sh${NC}"
    exit 1
}
echo -e "${GREEN}  ✓ Environment OK${NC}"

# ══════════════════════════════════════════════════════════════════
# [2/3] Nmap check
# ══════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[2/3] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ $(nmap --version | head -1)${NC}"
    NSE_COUNT=$(ls /usr/share/nmap/scripts/*.nse 2>/dev/null | wc -l)
    echo -e "${GREEN}  ✓ NSE scripts available: ${NSE_COUNT}${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not found — simulation mode active${NC}"
fi

mkdir -p data/sessions data/cve_db data/logs reports exports data

# ── CVE Intelligence Database status ───────────────────────────────────────
CVE_DB="data/cve_scripts.db"
if [ -f "$CVE_DB" ]; then
    CVE_TOTAL=$("$PY" -c "
import sqlite3
try:
    c = sqlite3.connect('$CVE_DB')
    total   = c.execute('SELECT COUNT(*) FROM cve_script_cache').fetchone()[0]
    gemini  = c.execute(\"SELECT COUNT(*) FROM cve_script_cache WHERE source='gemini'\").fetchone()[0]
    confirm = c.execute('SELECT COUNT(*) FROM cve_script_cache WHERE confirmed_count > 0').fetchone()[0]
    print(f'{total} entries ({gemini} Gemini-cached, {confirm} scan-confirmed)')
except Exception as e:
    print(f'error: {e}')
" 2>/dev/null || echo "unreadable")
    echo -e "${GREEN}  ✓ CVE database: ${CVE_TOTAL}${NC}"
else
    echo -e "${YELLOW}  ⚠  CVE database not found — will initialize on first scan${NC}"
    echo -e "${YELLOW}     Run: bash setup_env.sh  to pre-initialize${NC}"
fi

# ── Gemini API key status ───────────────────────────────────────────────────
GEMINI_KEY="${GEMINI_API_KEY:-}"
if [ -n "$GEMINI_KEY" ] && [ "$GEMINI_KEY" != "your_gemini_api_key_here" ]; then
    GEMINI_SDK=$("$PY" -c "import google.generativeai; print('ok')" 2>/dev/null || echo "missing")
    if [ "$GEMINI_SDK" = "ok" ]; then
        echo -e "${GREEN}  ✓ Gemini CVE selector: ENABLED (${GEMINI_MODEL:-gemini-2.0-flash})${NC}"
        echo -e "${CYAN}    New CVEs → Gemini → saved to local DB → never re-asked${NC}"
    else
        echo -e "${YELLOW}  ⚠  GEMINI_API_KEY set but SDK missing — run: bash setup_env.sh${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠  Gemini CVE selector: DISABLED${NC}"
    echo -e "${YELLOW}     Get a free key: https://aistudio.google.com/apikey${NC}"
    echo -e "${YELLOW}     Then add to .env: GEMINI_API_KEY=your_key_here${NC}"
fi

# ── Optional modes ─────────────────────────────────────────────────
case "${1:-}" in
    --test)
        echo -e "${YELLOW}\n[TESTS] Running unit tests...${NC}"
        "$PY" tests/run_tests.py
        exit $?
        ;;
    --benchmark)
        echo -e "${YELLOW}\n[BENCHMARK] Running CVE benchmark...${NC}"
        "$PY" tests/benchmark.py
        exit $?
        ;;
esac

# ══════════════════════════════════════════════════════════════════
# [3/3] Start server
# ══════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[3/3] Starting THREATWEAVE...${NC}"

# Detect LAN IP
LAN_IP=$("$PY" -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    print(s.getsockname()[0]); s.close()
except:
    print('127.0.0.1')
")

# ── Handle --restart ───────────────────────────────────────────────
if [ "${1:-}" = "--restart" ]; then
    echo -e "${YELLOW}  → Stopping any running instance...${NC}"
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            kill "$OLD_PID" 2>/dev/null
            sleep 2
            kill -0 "$OLD_PID" 2>/dev/null && kill -9 "$OLD_PID" 2>/dev/null
            echo -e "${GREEN}  ✓ Previous instance stopped (PID $OLD_PID)${NC}"
        fi
        rm -f "$PID_FILE"
    fi
    STRAY=$(lsof -ti tcp:"$PORT" 2>/dev/null | head -1)
    if [ -n "$STRAY" ]; then
        kill "$STRAY" 2>/dev/null; sleep 1
        echo -e "${GREEN}  ✓ Port $PORT freed${NC}"
    fi
fi

# ── Check if already running ───────────────────────────────────────
STRAY_PID=$(lsof -ti tcp:"$PORT" 2>/dev/null | head -1)
if [ -n "$STRAY_PID" ]; then
    if [ -f "$PID_FILE" ] && [ "$(cat "$PID_FILE" 2>/dev/null)" = "$STRAY_PID" ]; then
        if curl -sf --max-time 2 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
            echo ""
            echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${GREEN}  ✓ THREATWEAVE is already running (PID $STRAY_PID)${NC}"
            echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
            echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
            echo -e "${CYAN}  Session state preserved — no data lost${NC}"
            echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            echo -e "${CYAN}  To force a restart:  bash run.sh --restart${NC}"
            echo ""
            exit 0
        fi
    fi
    echo -e "${YELLOW}  ⚠  Port $PORT occupied (PID $STRAY_PID) — clearing...${NC}"
    kill "$STRAY_PID" 2>/dev/null; sleep 2
    kill -9 "$STRAY_PID" 2>/dev/null
    echo -e "${GREEN}  ✓ Port $PORT freed${NC}"
fi

# Remove stale PID file
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
        rm -f "$PID_FILE"
        echo -e "${YELLOW}  ⚠  Stale PID file removed — starting fresh${NC}"
    fi
fi

# Write startup token (triggers fresh chat session in the frontend)
STARTUP_TOKEN="$(date +%s)_$$_$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n' 2>/dev/null || echo $RANDOM)"
echo "$STARTUP_TOKEN" > "$PROJECT_DIR/data/startup_token.txt"
echo -e "${GREEN}  ✓ Fresh chat token written (new session on connect)${NC}"

echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
echo -e "${CYAN}  Docs   →  http://localhost:${PORT}/docs${NC}"
echo -e "${CYAN}  Mobile →  Connect to same Wi-Fi, open LAN URL${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}  Press Ctrl+C or use the Stop button in the UI to exit${NC}"
echo ""

# ── Graceful shutdown ──────────────────────────────────────────────
_graceful_shutdown() {
    if [ -n "${UVICORN_PID:-}" ] && kill -0 "$UVICORN_PID" 2>/dev/null; then
        kill "$UVICORN_PID" 2>/dev/null
    fi
    rm -f "$PID_FILE"
    echo -e "${CYAN}\n  THREATWEAVE stopped. Session data preserved in data/.${NC}"
    echo ""
}
trap '_graceful_shutdown' EXIT INT TERM

export PORT="$PORT"

# ── Launch uvicorn ─────────────────────────────────────────────────
"$PY" -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --timeout-keep-alive 600 \
    --timeout-graceful-shutdown 30 &
UVICORN_PID=$!
echo "$UVICORN_PID" > "$PID_FILE"

# Wait for server to become ready (up to 15 s)
echo -e "${CYAN}  → Waiting for server to start...${NC}"
READY=0
for i in $(seq 1 15); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        READY=1; break
    fi
    sleep 1
done

if [ "$READY" = "1" ]; then
    echo -e "${GREEN}  ✓ Server is up and responding!${NC}"
    echo ""
    echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ THREATWEAVE is running (PID $UVICORN_PID)${NC}"
    echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
    echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
    echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
else
    echo -e "${RED}  ✗ Server did not respond within 15 seconds${NC}"
    echo -e "${RED}    Check the logs above for startup errors${NC}"
    echo -e "${YELLOW}    Retry:  bash run.sh --restart${NC}"
fi

# Keep alive — wait for uvicorn to exit
wait "$UVICORN_PID"
