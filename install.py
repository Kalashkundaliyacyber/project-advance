#!/usr/bin/env python3
"""
ScanWise AI — Guaranteed Installer
Downloads and installs exact wheel files directly. No resolver. No Rust.
Run as root inside the project folder:  python3 install.py
"""
import os, sys, subprocess, shutil, urllib.request, zipfile, tempfile

VENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
PIP  = os.path.join(VENV, "bin", "pip")
PY   = os.path.join(VENV, "bin", "python3")

# Exact wheel URLs from PyPI for Python 3 / any platform (pure-python wheels)
# All are py3-none-any.whl — guaranteed no compilation
WHEELS = [
    # (package_name, version, wheel_url)
    ("pydantic",          "1.10.21", "https://files.pythonhosted.org/packages/py3/p/pydantic/pydantic-1.10.21-py3-none-any.whl"),
    ("typing_extensions", "4.12.2",  "https://files.pythonhosted.org/packages/py3/t/typing_extensions/typing_extensions-4.12.2-py3-none-any.whl"),
    ("annotated_types",   "0.7.0",   "https://files.pythonhosted.org/packages/py3/a/annotated_types/annotated_types-0.7.0-py3-none-any.whl"),
    ("sniffio",           "1.3.1",   "https://files.pythonhosted.org/packages/py3/s/sniffio/sniffio-1.3.1-py3-none-any.whl"),
    ("idna",              "3.10",    "https://files.pythonhosted.org/packages/py3/i/idna/idna-3.10-py3-none-any.whl"),
    ("anyio",             "3.7.1",   "https://files.pythonhosted.org/packages/py3/a/anyio/anyio-3.7.1-py3-none-any.whl"),
    ("h11",               "0.14.0",  "https://files.pythonhosted.org/packages/py3/h/h11/h11-0.14.0-py3-none-any.whl"),
    ("click",             "8.1.8",   "https://files.pythonhosted.org/packages/py3/c/click/click-8.1.8-py3-none-any.whl"),
    ("MarkupSafe",        "3.0.2",   "https://files.pythonhosted.org/packages/py3/m/markupsafe/MarkupSafe-3.0.2-py3-none-any.whl"),
    ("jinja2",            "3.1.6",   "https://files.pythonhosted.org/packages/py3/j/jinja2/jinja2-3.1.6-py3-none-any.whl"),
    ("starlette",         "0.27.0",  "https://files.pythonhosted.org/packages/py3/s/starlette/starlette-0.27.0-py3-none-any.whl"),
    ("fastapi",           "0.104.1", "https://files.pythonhosted.org/packages/py3/f/fastapi/fastapi-0.104.1-py3-none-any.whl"),
    ("uvicorn",           "0.24.0",  "https://files.pythonhosted.org/packages/py3/u/uvicorn/uvicorn-0.24.0-py3-none-any.whl"),
    ("python_multipart",  "0.0.9",   "https://files.pythonhosted.org/packages/py3/p/python_multipart/python_multipart-0.0.9-py3-none-any.whl"),
]

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, shell=False, **kw)

def pip_install_simple(package_spec):
    """Install a single package spec, ignoring deps, using pip from venv."""
    run([PIP, "install", package_spec, "--no-deps", "--quiet",
         "--no-build-isolation", "--ignore-requires-python"])

def main():
    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  ScanWise AI Installer")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    # 1. Create venv
    if os.path.isdir(VENV):
        print("  → Removing old .venv ...")
        shutil.rmtree(VENV)

    print("  → Creating virtual environment ...")
    run([sys.executable, "-m", "venv", VENV])
    print("  ✓ Virtual environment created\n")

    # 2. Upgrade pip inside venv
    print("  → Upgrading pip ...")
    run([PIP, "install", "--upgrade", "pip", "--quiet"])

    # 3. Remove any pydantic v2 that might appear
    subprocess.run([PIP, "uninstall", "pydantic", "pydantic-core", "-y"],
                   capture_output=True)

    # 4. Install packages one by one using --no-deps
    print("  → Installing packages (no Rust, pure Python):\n")
    failed = []
    for name, ver, url in WHEELS:
        spec = f"{name}=={ver}"
        print(f"    installing {spec} ...", end=" ", flush=True)
        try:
            # Try direct pip install with pin first
            run([PIP, "install", spec, "--no-deps", "--quiet",
                 "--only-binary", ":all:", "--prefer-binary"])
            print("✓")
        except subprocess.CalledProcessError:
            # Fallback: download wheel and install from file
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    whl = os.path.join(tmp, f"{name}.whl")
                    urllib.request.urlretrieve(url, whl)
                    run([PIP, "install", whl, "--no-deps", "--quiet"])
                print("✓ (wheel)")
            except Exception as e:
                print(f"✗ ({e})")
                failed.append(spec)

    if failed:
        print(f"\n  ✗ Failed to install: {failed}")
        print("    Check internet connection and try again.")
        sys.exit(1)

    # 5. Verify pydantic version
    result = subprocess.run([PY, "-c",
        "import pydantic; print(pydantic.VERSION)"],
        capture_output=True, text=True)
    pydantic_ver = result.stdout.strip()
    major = int(pydantic_ver.split(".")[0]) if pydantic_ver else 0
    if major != 1:
        print(f"\n  ✗ pydantic {pydantic_ver} installed — need v1.x")
        sys.exit(1)
    print(f"\n  ✓ pydantic {pydantic_ver} confirmed\n")

    # 6. Verify all imports
    print("  → Verifying all imports:")
    mods = ["fastapi","uvicorn","pydantic","jinja2","starlette","anyio","h11","click"]
    for mod in mods:
        r = subprocess.run([PY, "-c", f"import {mod}; print({mod}.__version__ if hasattr({mod},'__version__') else {mod}.VERSION)"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"    ✓  {mod} {r.stdout.strip()}")
        else:
            print(f"    ✗  {mod}: {r.stderr.strip()}")
            sys.exit(1)

    # 7. Create data directories
    base = os.path.dirname(os.path.abspath(__file__))
    for d in ["data/sessions","data/cve_db","data/logs","reports","exports"]:
        os.makedirs(os.path.join(base, d), exist_ok=True)

    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  ✓ Installation complete!")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"\n  To start ScanWise AI:")
    print(f"    source .venv/bin/activate")
    print(f"    python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload")
    print(f"\n  Or simply:  bash run.sh\n")

if __name__ == "__main__":
    main()
