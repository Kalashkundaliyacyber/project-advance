#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  THREATWEAVE — Environment Setup
#  Run ONCE before first launch, or after a clean reinstall.
#
#  Usage:
#    bash setup_env.sh               # standard setup
#    PULL_LLAMA3B=true bash setup_env.sh   # also pull Llama 3.2 3B
#    PULL_GEMMA2=true  bash setup_env.sh   # also pull Gemma 2:2b
#
#  All pip packages and system dependencies are managed here.
#  To add a new package, add it to the "Install all packages" block.
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ── Colours ────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
VPIP="$VENV/bin/pip"
VPY="$VENV/bin/python3"

# ── Banner ─────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗"
echo "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝"
echo "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  "
echo "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  "
echo "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗"
echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}THREATWEAVE — Environment Setup${NC}"
echo -e "  AI Security Intelligence Platform v4.0"
echo ""

# ══════════════════════════════════════════════════════════════════
# SECTION 1 — System dependencies
# ══════════════════════════════════════════════════════════════════
echo -e "${CYAN}[1/6] System dependencies${NC}"

# nmap
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ nmap $(nmap --version | head -1 | awk '{print $3}') already installed${NC}"
else
    echo -e "${YELLOW}  → Installing nmap...${NC}"
    apt-get install -y nmap --quiet 2>/dev/null \
        || echo -e "${RED}  ✗ nmap install failed — run: sudo apt-get install -y nmap${NC}"
fi

# libxrender1 (required by reportlab for PDF font rendering)
if dpkg -l libxrender1 &>/dev/null 2>&1; then
    echo -e "${GREEN}  ✓ libxrender1 already installed${NC}"
else
    echo -e "${YELLOW}  → Installing libxrender1 (needed by reportlab)...${NC}"
    apt-get install -y libxrender1 --quiet 2>/dev/null \
        || echo -e "${YELLOW}  ⚠  libxrender1 install failed — PDF generation may be limited${NC}"
fi

# python3-venv
if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${YELLOW}  → Installing python3-venv...${NC}"
    apt-get install -y python3-venv
fi

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ python3 not found — run: apt install python3 python3-venv${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ $(python3 --version)${NC}"

# ══════════════════════════════════════════════════════════════════
# SECTION 2 — Ollama & local AI models
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}[2/6] Ollama & local AI models${NC}"
echo -e "${CYAN}  Architecture:${NC}"
echo -e "${CYAN}    PRIMARY    →  Qwen2.5-Coder 3B  (security analysis, remediation, JSON)${NC}"
echo -e "${CYAN}    CHATBOT    →  Llama 3.2 1B      (conversations, summaries)${NC}"
echo -e "${CYAN}    FALLBACK   →  Llama 3.2 3B      (optional — set PULL_LLAMA3B=true)${NC}"
echo -e "${CYAN}    CLOUD      →  Gemini            (emergency fallback — set GEMINI_API_KEY)${NC}"
echo -e "${CYAN}    OFFLINE    →  Rule engine       (always available, no model required)${NC}"

OLLAMA_MODEL_NAME="${OLLAMA_MODEL:-llama3.2:1b}"
QWEN_MODEL_NAME="${QWEN_MODEL:-qwen2.5-coder:3b}"

# Install Ollama if missing
if command -v ollama &>/dev/null; then
    echo -e "${GREEN}  ✓ Ollama $(ollama --version 2>/dev/null | head -1) already installed${NC}"
else
    echo -e "${YELLOW}  → Installing Ollama...${NC}"
    if curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null; then
        echo -e "${GREEN}  ✓ Ollama installed${NC}"
    else
        echo -e "${RED}  ✗ Ollama install failed — run: curl -fsSL https://ollama.com/install.sh | sh${NC}"
    fi
fi

# Ensure Ollama server is running
mkdir -p "$PROJECT_DIR/data/logs"
if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo -e "${YELLOW}  → Starting Ollama server in background...${NC}"
    nohup ollama serve > "$PROJECT_DIR/data/logs/ollama.log" 2>&1 &
    sleep 3
fi

# Pull Llama 3.2 1B (chatbot)
if ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL_NAME"; then
    echo -e "${GREEN}  ✓ $OLLAMA_MODEL_NAME already available${NC}"
else
    echo -e "${YELLOW}  → Pulling $OLLAMA_MODEL_NAME (~700MB, one-time)...${NC}"
    ollama pull "$OLLAMA_MODEL_NAME" \
        && echo -e "${GREEN}  ✓ $OLLAMA_MODEL_NAME ready${NC}" \
        || echo -e "${RED}  ✗ Pull failed — run manually: ollama pull $OLLAMA_MODEL_NAME${NC}"
fi

# Pull Qwen2.5-Coder 3B (primary AI engine)
if ollama list 2>/dev/null | grep -q "qwen2.5-coder"; then
    echo -e "${GREEN}  ✓ $QWEN_MODEL_NAME already available${NC}"
else
    echo -e "${YELLOW}  → Pulling $QWEN_MODEL_NAME (~1.9GB, one-time)...${NC}"
    ollama pull "$QWEN_MODEL_NAME" \
        && echo -e "${GREEN}  ✓ $QWEN_MODEL_NAME ready${NC}" \
        || echo -e "${RED}  ✗ Qwen pull failed — run manually: ollama pull $QWEN_MODEL_NAME${NC}"
fi

# Optional: Llama 3.2 3B
if [ "${PULL_LLAMA3B:-false}" = "true" ]; then
    if ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
        echo -e "${GREEN}  ✓ llama3.2:3b already available${NC}"
    else
        echo -e "${YELLOW}  → Pulling llama3.2:3b (~2GB, optional)...${NC}"
        ollama pull llama3.2:3b \
            || echo -e "${YELLOW}  ⚠  llama3.2:3b pull failed — continuing without it${NC}"
    fi
fi

# Optional: Gemma 2:2b
if [ "${PULL_GEMMA2:-false}" = "true" ]; then
    echo -e "${CYAN}  → Pulling gemma2:2b (optional)...${NC}"
    ollama pull gemma2:2b \
        || echo -e "${YELLOW}  ⚠  gemma2:2b pull failed — continuing${NC}"
fi

echo -e "${CYAN}  Installed models: $(ollama list 2>/dev/null | awk 'NR>1 {print $1}' | tr '\n' ' ' || echo 'none')${NC}"

# ══════════════════════════════════════════════════════════════════
# SECTION 3 — Gemini API check (optional cloud backup)
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}[3/6] Cloud AI configuration${NC}"
GEMINI_KEY="${GEMINI_API_KEY:-}"
if [ -n "$GEMINI_KEY" ] && [ "$GEMINI_KEY" != "your_gemini_api_key_here" ]; then
    echo -e "${GREEN}  ✓ GEMINI_API_KEY set — emergency cloud fallback active${NC}"
    echo -e "${CYAN}    Model: ${GEMINI_MODEL:-gemini-2.0-flash-lite}${NC}"
else
    echo -e "${YELLOW}  ⚠  GEMINI_API_KEY not set — local models only${NC}"
    echo -e "${YELLOW}     Optional: get a free key at https://aistudio.google.com/apikey${NC}"
fi

# ══════════════════════════════════════════════════════════════════
# SECTION 4 — Python virtual environment
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}[4/6] Python virtual environment${NC}"

# Remove stale venv if present
if [ -d "$VENV" ]; then
    echo -e "${YELLOW}  → Removing old .venv (clean slate)...${NC}"
    rm -rf "$VENV"
fi

python3 -m venv "$VENV"
echo -e "${GREEN}  ✓ .venv created${NC}"

"$VPIP" install --upgrade pip --quiet
echo -e "${GREEN}  ✓ pip upgraded${NC}"

# ══════════════════════════════════════════════════════════════════
# SECTION 5 — Python packages
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}[5/6] Installing Python packages${NC}"

# Hard-pin pydantic v1 — pydantic v2 requires Rust and fails on Python 3.13
cat > /tmp/tw_constraints.txt << 'CONSTRAINTS'
pydantic==1.10.21
pydantic-core==0.0.0
CONSTRAINTS

# Step A: Install pydantic v1 first, alone, before fastapi's resolver runs
echo -e "${CYAN}  → Pinning pydantic==1.10.21 (pre-install)...${NC}"
"$VPIP" install "pydantic==1.10.21" \
    --no-deps --no-cache-dir --quiet \
    || { echo -e "${RED}  ✗ pydantic install failed${NC}"; exit 1; }

# Step B: Install all project packages
# ╔══════════════════════════════════════════════════════════════════╗
# ║  ADD NEW PACKAGES HERE — single source of truth for all deps.  ║
# ╚══════════════════════════════════════════════════════════════════╝
echo -e "${CYAN}  → Installing all project packages...${NC}"
"$VPIP" install \
    \
    `# ── Web framework ────────────────────────────────────────────` \
    "fastapi==0.104.1" \
    "uvicorn==0.24.0" \
    "starlette==0.27.0" \
    \
    `# ── Rate limiting ─────────────────────────────────────────────` \
    "slowapi==0.1.9" \
    \
    `# ── Async / HTTP internals ────────────────────────────────────` \
    "anyio==3.7.1" \
    "sniffio==1.3.1" \
    "h11==0.14.0" \
    "idna==3.10" \
    \
    `# ── YAML config support (settings.yaml, risk weights) ─────────` \
    "pyyaml==6.0.2" \
    \
    `# ── Utilities ─────────────────────────────────────────────────` \
    "click==8.1.8" \
    "python-multipart==0.0.9" \
    "typing_extensions==4.12.2" \
    \
    `# ── Templating ────────────────────────────────────────────────` \
    "jinja2==3.1.6" \
    "MarkupSafe==3.0.2" \
    \
    `# ── Report generation ─────────────────────────────────────────` \
    "reportlab==4.2.5" \
    "python-docx==1.1.2" \
    "lxml==5.3.0" \
    \
    `# ── HTTP client / AI integrations ─────────────────────────────` \
    "httpx==0.27.0" \
    "python-dotenv==1.0.1" \
    \
    `# ── (Add new packages above this line) ────────────────────────` \
    \
    --constraint /tmp/tw_constraints.txt \
    --no-cache-dir \
    --quiet \
    || { echo -e "${RED}  ✗ Package install failed — check internet connection${NC}"; exit 1; }

# Step C: Force-reinstall pydantic v1 in case fastapi's resolver upgraded it
"$VPIP" install "pydantic==1.10.21" \
    --no-deps --force-reinstall --no-cache-dir --quiet
echo -e "${GREEN}  ✓ All packages installed${NC}"

# Verify pydantic is v1
PVER=$("$VPY" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
PMAJ=$(echo "$PVER" | cut -d. -f1)
[ "$PMAJ" = "1" ] \
    && echo -e "${GREEN}  ✓ pydantic $PVER confirmed (v1)${NC}" \
    || { echo -e "${RED}  ✗ pydantic $PVER — need v1.x${NC}"; exit 1; }

# Full import verification
echo -e "${CYAN}  → Verifying all imports...${NC}"
"$VPY" - << 'PYCHECK'
import sys
REQUIRED = {
    "fastapi":       "__version__",
    "uvicorn":       "__version__",
    "pydantic":      "VERSION",
    "starlette":     "__version__",
    "jinja2":        "__version__",
    "anyio":         "__version__",
    "slowapi":       "__version__",
    "multipart":     "__version__",
    "reportlab":     "Version",
    "docx":          "__version__",
    "lxml":          "__version__",
    "yaml":          "__version__",
    "httpx":         "__version__",
    "dotenv":        "__version__",
}
ok = True
for mod, attr in REQUIRED.items():
    try:
        m = __import__(mod)
        print(f"    ✓  {mod} {getattr(m, attr, '?')}")
    except ImportError as e:
        print(f"    ✗  {mod}: {e}")
        ok = False
import pydantic
if not pydantic.VERSION.startswith("1."):
    print(f"  ✗ pydantic {pydantic.VERSION} — need v1.x"); sys.exit(1)
if not ok:
    sys.exit(1)
print("  All imports OK")
PYCHECK

[ $? -eq 0 ] \
    && echo -e "${GREEN}  ✓ All imports verified${NC}" \
    || { echo -e "${RED}  ✗ Import check failed — see errors above${NC}"; exit 1; }

# ══════════════════════════════════════════════════════════════════
# SECTION 6 — Data directories
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}[6/6] Creating data directories${NC}"
mkdir -p \
    "$PROJECT_DIR/data/sessions" \
    "$PROJECT_DIR/data/cve_db" \
    "$PROJECT_DIR/data/version_db" \
    "$PROJECT_DIR/data/logs" \
    "$PROJECT_DIR/reports" \
    "$PROJECT_DIR/exports"
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ══════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✓ THREATWEAVE setup complete!${NC}"
GEMINI_KEY="${GEMINI_API_KEY:-}"
if [ -n "$GEMINI_KEY" ] && [ "$GEMINI_KEY" != "your_gemini_api_key_here" ]; then
    echo -e "${GREEN}  AI Primary  →  Qwen2.5-Coder 3B + Llama 3.2 1B${NC}"
    echo -e "${GREEN}  AI Backup   →  Gemini (emergency cloud fallback)${NC}"
else
    echo -e "${YELLOW}  AI Models   →  Qwen2.5-Coder 3B + Llama 3.2 1B (local only)${NC}"
    echo -e "${YELLOW}  Tip: Add GEMINI_API_KEY to .env for cloud fallback${NC}"
fi
echo ""
echo -e "${GREEN}  Start server  →  bash run.sh${NC}"
echo -e "${GREEN}  Run tests     →  bash run.sh --test${NC}"
echo -e "${GREEN}  Benchmark     →  bash run.sh --benchmark${NC}"
echo -e "${CYAN}  Custom model  →  OLLAMA_MODEL=mistral bash setup_env.sh${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
