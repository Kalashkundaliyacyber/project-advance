# ScanWise AI — Kali Linux Setup Guide

## Two-step setup (copy-paste these commands)

### Step 1 — Setup environment (run ONCE)
```bash
cd /path/to/scanwise-ai
bash setup_env.sh
```

### Step 2 — Start the server (every time)
```bash
bash run.sh
```

Open browser → **http://localhost:8000**

---

## What went wrong before and what's fixed

| Problem | Cause | Fix |
|---------|-------|-----|
| `pydantic-core Rust build fails` | pip resolves pydantic v2 which needs Rust | `setup_env.sh` uses a constraints file to hard-block pydantic v2 |
| `pydantic got overwritten to v2` | fastapi dependency pulls v2 during install | pydantic v1 is installed first with `--no-deps`, then force-reinstalled after |
| `No module named uvicorn` | forgot to activate venv | `run.sh` uses full venv python path directly — no activation needed |
| `element truthiness in Python 3.13` | `if element:` is False for empty XML elements | All XML code uses `if element is not None:` |

---

## If setup_env.sh fails

Run these commands manually — one at a time:

```bash
# 1. Remove broken venv
rm -rf .venv

# 2. Create fresh one
python3 -m venv .venv

# 3. Upgrade pip
.venv/bin/pip install --upgrade pip

# 4. Create constraint file to BLOCK pydantic v2
echo "pydantic==1.10.21" > /tmp/constraint.txt
echo "pydantic-core==0.0.0" >> /tmp/constraint.txt

# 5. Install pydantic v1 alone, with no-deps
.venv/bin/pip install "pydantic==1.10.21" --no-deps --no-cache-dir --constraint /tmp/constraint.txt

# 6. Verify it's v1
.venv/bin/python3 -c "import pydantic; print(pydantic.VERSION)"
# Must print: 1.10.21

# 7. Install everything else with the constraint active
.venv/bin/pip install \
  "fastapi==0.104.1" "uvicorn==0.24.0" "starlette==0.27.0" \
  "anyio==3.7.1" "sniffio==1.3.1" "h11==0.14.0" "click==8.1.8" \
  "python-multipart==0.0.9" "jinja2==3.1.6" "MarkupSafe==3.0.2" \
  "typing_extensions==4.12.2" "idna==3.10" \
  --constraint /tmp/constraint.txt --no-cache-dir

# 8. Force reinstall pydantic v1 (in case step 7 overwrote it)
.venv/bin/pip install "pydantic==1.10.21" --no-deps --force-reinstall --no-cache-dir

# 9. Final verification
.venv/bin/python3 -c "import fastapi, uvicorn, pydantic; print('pydantic', pydantic.VERSION)"
# Must show: pydantic 1.10.21

# 10. Start server
.venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Quick test after setup

```bash
bash run.sh --test       # runs all 209 unit tests
bash run.sh --benchmark  # runs 5-fixture CVE benchmark
```

---

## Packages installed (all pure Python, no Rust)

```
pydantic==1.10.21    ← v1, pure Python, no Rust compilation
fastapi==0.104.1
uvicorn==0.24.0
starlette==0.27.0
anyio==3.7.1
sniffio==1.3.1
h11==0.14.0
click==8.1.8
python-multipart==0.0.9
jinja2==3.1.6
MarkupSafe==3.0.2
typing_extensions==4.12.2
idna==3.10
```
