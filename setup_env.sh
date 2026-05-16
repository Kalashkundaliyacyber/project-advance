#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Environment Setup Script
#  Run ONCE before starting the server:  bash setup_env.sh
#
#  ALL pip dependencies are installed here.
#  If you add a new package to the project, add it to the
#  "Install all packages" section below and nowhere else.
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
VPIP="$VENV/bin/pip"
VPY="$VENV/bin/python3"

echo -e "${CYAN}\n  ScanWise AI — Environment Setup${NC}\n"

# ── System dependencies ────────────────────────────────────────────
echo -e "${CYAN}  → Checking system dependencies...${NC}"

# nmap — required for all scan types
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ nmap $(nmap --version | head -1 | awk '{print $3}') already installed${NC}"
else
    echo -e "${YELLOW}  → Installing nmap (required for scanning)...${NC}"
    apt-get install -y nmap --quiet 2>/dev/null || \
        echo -e "${RED}  ✗ Could not install nmap. Run: sudo apt-get install -y nmap${NC}"
fi

# ── AI Architecture ───────────────────────────────────────────────
echo -e "${CYAN}  → ScanWise AI Hybrid Architecture:${NC}"
echo -e "${CYAN}    PRIMARY:       Qwen2.5-Coder 3B (remediation, analysis, JSON)${NC}"
echo -e "${CYAN}    CHATBOT:       Llama 3.2 1B     (conversations, summaries)${NC}"
echo -e "${CYAN}    FALLBACK:      Llama 3.2 3B     (optional, if VM allows)${NC}"
echo -e "${CYAN}    CLOUD BACKUP:  Gemini           (emergency fallback only)${NC}"
echo -e "${CYAN}    FINAL BACKUP:  Rule engine      (offline guarantee)${NC}"

# ── Gemini API — emergency cloud fallback only ─────────────────────
echo -e "${CYAN}  → Checking Gemini AI (emergency cloud fallback)...${NC}"
GEMINI_KEY="${GEMINI_API_KEY:-}"
if [ -n "$GEMINI_KEY" ] && [ "$GEMINI_KEY" != "your_gemini_api_key_here" ]; then
    echo -e "${GREEN}  ✓ GEMINI_API_KEY configured — emergency cloud fallback active${NC}"
    echo -e "${CYAN}    Model: ${GEMINI_MODEL:-gemini-2.0-flash-lite}${NC}"
    echo -e "${CYAN}    Note: Gemini is used ONLY if all local models fail${NC}"
else
    echo -e "${YELLOW}  ⚠ GEMINI_API_KEY not set — local Ollama models used exclusively${NC}"
    echo -e "${YELLOW}    Optional: get a free key at https://aistudio.google.com/apikey${NC}"
fi

# ── Ollama — local AI fallback (free, no API key) ────────────────────
echo -e "${CYAN}  → Checking Ollama (local AI fallback)...${NC}"

OLLAMA_MODEL_NAME="${OLLAMA_MODEL:-llama3.2:1b}"
QWEN_MODEL_NAME="${QWEN_MODEL:-qwen2.5-coder:3b}"

if command -v ollama &>/dev/null; then
    echo -e "${GREEN}  ✓ Ollama already installed ($(ollama --version 2>/dev/null | head -1))${NC}"
else
    echo -e "${YELLOW}  → Installing Ollama...${NC}"
    if curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null; then
        echo -e "${GREEN}  ✓ Ollama installed${NC}"
    else
        echo -e "${RED}  ✗ Ollama install failed. Install manually: curl -fsSL https://ollama.com/install.sh | sh${NC}"
    fi
fi

# Start ollama serve in background if not already running
if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo -e "${YELLOW}  → Starting Ollama server in background...${NC}"
    nohup ollama serve > "$PROJECT_DIR/data/logs/ollama.log" 2>&1 &
    sleep 3
fi

# Pull Llama 3.2 1B (chatbot / primary lightweight model)
if ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL_NAME"; then
    echo -e "${GREEN}  ✓ Model '$OLLAMA_MODEL_NAME' already pulled${NC}"
else
    echo -e "${YELLOW}  → Pulling '$OLLAMA_MODEL_NAME' (Llama 3.2 1B ~700MB, one-time only)...${NC}"
    if ollama pull "$OLLAMA_MODEL_NAME"; then
        echo -e "${GREEN}  ✓ Model '$OLLAMA_MODEL_NAME' ready${NC}"
    else
        echo -e "${RED}  ✗ Model pull failed. Run manually: ollama pull $OLLAMA_MODEL_NAME${NC}"
    fi
fi

# Pull Qwen2.5-Coder 3B (primary AI engine for remediation + analysis)
echo -e "${CYAN}  → Checking Qwen2.5-Coder 3B (primary remediation AI)...${NC}"
if ollama list 2>/dev/null | grep -q "qwen2.5-coder"; then
    echo -e "${GREEN}  ✓ Model '$QWEN_MODEL_NAME' already pulled${NC}"
else
    echo -e "${YELLOW}  → Pulling '$QWEN_MODEL_NAME' (~1.9GB, one-time only)...${NC}"
    echo -e "${YELLOW}    This is the primary AI engine — optimized for security analysis.${NC}"
    if ollama pull "$QWEN_MODEL_NAME"; then
        echo -e "${GREEN}  ✓ Model '$QWEN_MODEL_NAME' ready${NC}"
    else
        echo -e "${RED}  ✗ Qwen pull failed. Run manually: ollama pull $QWEN_MODEL_NAME${NC}"
        echo -e "${YELLOW}    System will fall back to Llama 3.2 for all AI tasks.${NC}"
    fi
fi


# Optionally pull Llama 3.2 3B (stronger fallback, only if VM can handle it)
echo -e "${CYAN}  → Optionally pulling llama3.2:3b (stronger fallback — skip if VM is tight)...${NC}"
if [ "${PULL_LLAMA3B:-false}" = "true" ]; then
    if ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
        echo -e "${GREEN}  ✓ llama3.2:3b already pulled${NC}"
    else
        echo -e "${YELLOW}  → Pulling llama3.2:3b (~2GB, optional)...${NC}"
        ollama pull llama3.2:3b || echo -e "${YELLOW}  ⚠ Optional llama3.2:3b pull failed — continuing without it${NC}"
    fi
else
    echo -e "${CYAN}    Skipped (set PULL_LLAMA3B=true to enable)${NC}"
fi

# Optionally pull gemma2:2b (tiny backup, optional)
if [ "${PULL_GEMMA2:-false}" = "true" ]; then
    echo -e "${CYAN}  → Pulling gemma2:2b (optional tiny backup)...${NC}"
    ollama pull gemma2:2b || echo -e "${YELLOW}  ⚠ Optional gemma2:2b pull failed — continuing${NC}"
fi

# Validate both models are available
echo -e "${CYAN}  → Validating model availability...${NC}"
AVAILABLE_MODELS=$(ollama list 2>/dev/null | awk 'NR>1 {print $1}' | tr '\n' ' ')
echo -e "${CYAN}    Installed models: ${AVAILABLE_MODELS:-none}${NC}"

# reportlab needs libxrender1 on headless Linux for font rendering
if dpkg -l libxrender1 &>/dev/null 2>&1; then
    echo -e "${GREEN}  ✓ libxrender1 already installed${NC}"
else
    echo -e "${YELLOW}  → Installing libxrender1 (needed by reportlab)...${NC}"
    apt-get install -y libxrender1 --quiet 2>/dev/null || \
        echo -e "${YELLOW}  ⚠ Could not install libxrender1 (may need sudo). PDF generation will still work.${NC}"
fi

# ── Python check ──────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ python3 not found. Run: apt install python3 python3-venv${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ $(python3 --version)${NC}"

# ── python3-venv check ────────────────────────────────────────────
if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${YELLOW}  → Installing python3-venv...${NC}"
    apt-get install -y python3-venv
fi

# ── Remove old venv (clean slate) ────────────────────────────────
if [ -d "$VENV" ]; then
    echo -e "${YELLOW}  → Removing old .venv ...${NC}"
    rm -rf "$VENV"
fi

# ── Create fresh venv ─────────────────────────────────────────────
echo -e "${CYAN}  → Creating fresh .venv ...${NC}"
python3 -m venv "$VENV"
echo -e "${GREEN}  ✓ venv created${NC}"

# ── Upgrade pip ───────────────────────────────────────────────────
"$VPIP" install --upgrade pip --quiet
echo -e "${GREEN}  ✓ pip upgraded${NC}"

# ── Constraint file: hard-block pydantic v2 ───────────────────────
# pydantic v2 requires Rust compilation and fails on Python 3.13.
# We pin v1 (pure Python) and block pydantic-core entirely.
cat > /tmp/sw_constraints.txt << 'CONSTRAINTS'
pydantic==1.10.21
pydantic-core==0.0.0
CONSTRAINTS

# ── Step 1: Install pydantic v1 FIRST, alone ─────────────────────
# Must be installed before fastapi, or fastapi's resolver pulls v2.
echo -e "${CYAN}  → Installing pydantic==1.10.21 (pure Python, no Rust)...${NC}"
"$VPIP" install "pydantic==1.10.21" \
    --no-deps \
    --no-cache-dir \
    --quiet
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ pydantic install failed. Check internet connection.${NC}"; exit 1
fi

# ── Step 2: Install ALL project packages ─────────────────────────
# ╔══════════════════════════════════════════════════════════════╗
# ║  ADD NEW PACKAGES HERE — this is the single source of truth ║
# ║  for all pip dependencies in ScanWise AI.                   ║
# ║  Format:  "package==version" \                              ║
# ╚══════════════════════════════════════════════════════════════╝
echo -e "${CYAN}  → Installing all project packages...${NC}"
"$VPIP" install \
    \
    `# ── Web framework ──────────────────────────────────────────` \
    "fastapi==0.104.1" \
    "uvicorn==0.24.0" \
    "starlette==0.27.0" \
    \
    `# ── Rate limiting ──────────────────────────────────────────` \
    "slowapi==0.1.9" \
    \
    `# ── Async / HTTP internals ─────────────────────────────────` \
    "anyio==3.7.1" \
    "sniffio==1.3.1" \
    "h11==0.14.0" \
    "idna==3.10" \
    \
    `# ── Utilities ──────────────────────────────────────────────` \
    "click==8.1.8" \
    "python-multipart==0.0.9" \
    "typing_extensions==4.12.2" \
    \
    `# ── Templating ─────────────────────────────────────────────` \
    "jinja2==3.1.6" \
    "MarkupSafe==3.0.2" \
    \
    `# ── Report generation ──────────────────────────────────────` \
    "reportlab==4.2.5" \
    "python-docx==1.1.2" \
    "lxml==5.3.0" \
    \
    `# ── OpenRouter / HTTP client ────────────────────────────────` \
    "httpx==0.27.0" \
    "python-dotenv==1.0.1" \
    \
    `# ── (Future packages go here) ───────────────────────────────` \
    \
    --constraint /tmp/sw_constraints.txt \
    --no-cache-dir \
    --quiet

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Package install failed. Check internet connection.${NC}"; exit 1
fi

# ── Step 3: Force reinstall pydantic v1 ──────────────────────────
# Ensures fastapi's dependency resolver did not silently upgrade to v2.
"$VPIP" install "pydantic==1.10.21" \
    --no-deps \
    --force-reinstall \
    --no-cache-dir \
    --quiet
echo -e "${GREEN}  ✓ All packages installed${NC}"

# ── Verify pydantic is v1 ─────────────────────────────────────────
PVER=$("$VPY" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
PMAJ=$(echo "$PVER" | cut -d. -f1)
if [ "$PMAJ" != "1" ]; then
    echo -e "${RED}  ✗ pydantic $PVER installed — need v1.x${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ pydantic $PVER confirmed${NC}"

# ── Verify all imports ────────────────────────────────────────────
echo -e "${CYAN}  → Verifying all imports...${NC}"
"$VPY" - << 'PYCHECK'
import sys
# All packages that must be importable at runtime
REQUIRED = {
    "fastapi":           "__version__",
    "uvicorn":           "__version__",
    "pydantic":          "VERSION",
    "starlette":         "__version__",
    "jinja2":            "__version__",
    "anyio":             "__version__",
    "slowapi":           "__version__",
    "multipart":         "__version__",
    "reportlab":         "Version",
    "docx":              "__version__",
    "lxml":              "__version__",
}
ok = True
for mod_name, ver_attr in REQUIRED.items():
    try:
        mod = __import__(mod_name)
        ver = getattr(mod, ver_attr, "?")
        print(f"    ✓  {mod_name} {ver}")
    except ImportError as e:
        print(f"    ✗  {mod_name}: {e}")
        ok = False

import pydantic
if not pydantic.VERSION.startswith("1."):
    print(f"  ✗ pydantic {pydantic.VERSION} — NEED v1.x")
    sys.exit(1)

if not ok:
    sys.exit(1)

print("    All imports OK")
PYCHECK

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import check failed. See errors above.${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ All imports verified${NC}"

# ── Create data directories ───────────────────────────────────────
echo -e "${CYAN}  → Creating data directories...${NC}"
mkdir -p \
    "$PROJECT_DIR/data/sessions" \
    "$PROJECT_DIR/data/cve_db" \
    "$PROJECT_DIR/data/version_db" \
    "$PROJECT_DIR/data/logs" \
    "$PROJECT_DIR/reports" \
    "$PROJECT_DIR/exports"
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ Setup complete!${NC}"
GEMINI_KEY="${GEMINI_API_KEY:-}"
if [ -n "$GEMINI_KEY" ] && [ "$GEMINI_KEY" != "your_gemini_api_key_here" ]; then
    echo -e "${GREEN}  → Primary AI:    Qwen2.5-Coder 3B (${QWEN_MODEL_NAME})${NC}"
    echo -e "${GREEN}  → Chat AI:       Llama 3.2 1B (${OLLAMA_MODEL_NAME})${NC}"
    echo -e "${GREEN}  → Cloud backup:  Gemini (emergency only, quota-safe)${NC}"
else
    echo -e "${YELLOW}  → Primary AI:    Qwen2.5-Coder 3B / Llama 3.2 1B (local)${NC}"
    echo -e "${YELLOW}  → Set GEMINI_API_KEY in .env for faster, smarter analysis${NC}"
fi
echo -e "${GREEN}  → Start server:  bash run.sh${NC}"
echo -e "${GREEN}  → Run tests:     bash run.sh --test${NC}"
echo -e "${GREEN}  → Benchmark:     bash run.sh --benchmark${NC}"
echo -e "${CYAN}  → Change model:  OLLAMA_MODEL=mistral bash setup_env.sh${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
