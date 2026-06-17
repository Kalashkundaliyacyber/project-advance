"""
app/scanner/script_selector.py
────────────────────────────────────────────────────────────────────────────
NSE script selector for ThreatWeave AI — CVE-first, evidence-only.

Public API
----------
  get_available_scripts()  — index /usr/share/nmap/scripts/
  find_scripts_for_port()  — return the best script for a port (CVE-first)
  run_confirmation_scan()  — run nmap and return stdout
  interpret_script_output()— classify raw NSE output
  confirm_unconfirmed_ports() — legacy orchestrator (kept for SSE live table)
"""

import os
import shutil
import subprocess
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

SCRIPTS_DIR = "/usr/share/nmap/scripts"

# ──────────────────────────────────────────────────────────────────────────
# Script index (built once, cached in memory)
# ──────────────────────────────────────────────────────────────────────────
_script_index: Optional[list] = None


def get_available_scripts() -> list:
    """Return cached list of all script names from /usr/share/nmap/scripts/."""
    global _script_index
    if _script_index is not None:
        return _script_index
    try:
        names = [f[:-4] for f in os.listdir(SCRIPTS_DIR) if f.endswith(".nse")]
        _script_index = sorted(names)
        logger.info("NSE script index: %d scripts found", len(_script_index))
        return _script_index
    except FileNotFoundError:
        logger.warning("Kali NSE scripts directory not found: %s", SCRIPTS_DIR)
        _script_index = []
        return []


# ──────────────────────────────────────────────────────────────────────────
# Core: CVE-first script selection
# ──────────────────────────────────────────────────────────────────────────

def find_scripts_for_port(service: str, product: str, version: str, cves: list) -> list:
    """
    Return the best NSE script(s) for this port, chosen by CVE mapping first.

    Flow:
      1. Normalise CVE list (accepts strings or dicts with cve_id key).
      2. Call cve_script_mapper.get_confirmation_plan() — CVE-first selection.
      3. If action == "NSE"  → return [script].
      4. If action == "VERSION" or "NONE" → return [] so caller can mark
         NOT_VALIDATABLE or POTENTIALLY_VULNERABLE instead of running a
         random script.

    This replaces the old tier-based keyword matching.
    """
    from app.scanner.cve_script_mapper import get_confirmation_plan

    # Normalise CVE entries: accept both "CVE-XXXX-YYYY" and {"cve_id": ...}
    cve_ids = []
    for c in cves:
        if isinstance(c, dict):
            cid = c.get("cve_id") or c.get("id") or ""
        else:
            cid = str(c) if c else ""
        if cid:
            cve_ids.append(cid)

    available = get_available_scripts()
    plan = get_confirmation_plan(cve_ids, service, product, version, available)

    if plan["action"] == "NSE" and plan["script"]:
        logger.info(
            "Script selected for %s %s (CVE %s): %s",
            service, version, plan["cve_id"], plan["script"]
        )
        return [plan["script"]]

    logger.debug(
        "No direct NSE script for %s %s (CVEs: %s) — action=%s",
        service, version, cve_ids, plan["action"]
    )
    return []


def find_scripts_for_port_with_plan(
    service: str, product: str, version: str, cves: list
) -> dict:
    """
    Extended version of find_scripts_for_port that returns the full plan dict
    including action, cve_id, confidence, and reason.
    Used by the /scan/confirm-port endpoint for richer responses.
    """
    from app.scanner.cve_script_mapper import get_confirmation_plan

    cve_ids = []
    for c in cves:
        if isinstance(c, dict):
            cid = c.get("cve_id") or c.get("id") or ""
        else:
            cid = str(c) if c else ""
        if cid:
            cve_ids.append(cid)

    available = get_available_scripts()
    return get_confirmation_plan(cve_ids, service, product, version, available)


# ──────────────────────────────────────────────────────────────────────────
# Confirmation scan runner
# ──────────────────────────────────────────────────────────────────────────

def run_confirmation_scan(
    target: str,
    port: int,
    protocol: str,
    scripts: list,
    timeout: int = 90,
) -> str:
    """
    Run nmap -p<port> --script <scripts> <target> and return raw stdout+stderr.
    Returns empty string if nmap is unavailable or scripts list is empty.
    Only uses safe/version/discovery/vuln category scripts — never brute force,
    exploits, or DoS checks.
    """
    if not scripts:
        return ""
    if not shutil.which("nmap"):
        return ""

    script_arg = ",".join(scripts)
    cmd = [
        "nmap",
        "-p", str(port),
        "-sV",                          # version detection (safe, improves NSE context)
        "--script", script_arg,
        "--script-timeout", "30s",      # per-script hard cap
        "--max-rtt-timeout", "300ms",
        "--min-rate", "300",
        "--open",
        target,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        logger.warning("Confirmation scan timed out for %s:%d (scripts: %s)", target, port, scripts)
        return ""
    except Exception as exc:
        logger.warning("Confirmation scan error for %s:%d: %s", target, port, exc)
        return ""


# ──────────────────────────────────────────────────────────────────────────
# Output analysis
# ──────────────────────────────────────────────────────────────────────────

def interpret_script_output(output: str) -> str:
    """
    Classify raw NSE output.
    Returns: "CONFIRMED" | "NOT_VULNERABLE" | "UNCONFIRMED"

    Delegates to cve_script_mapper.analyze_output() which enforces the
    safe-before-confirmed rule (NOT_VULNERABLE checked first) and
    restricts CONFIRMED to actual evidence lines, not just keyword presence.
    """
    from app.scanner.cve_script_mapper import analyze_output
    result = analyze_output(output)
    return result["status"]


# ──────────────────────────────────────────────────────────────────────────
# Legacy orchestrator — kept for the SSE live-table path
# (The sequential per-port confirmation table in the chatbot uses
# POST /api/scan/confirm-port instead, which calls find_scripts_for_port_with_plan
# directly for richer responses.)
# ──────────────────────────────────────────────────────────────────────────

def confirm_unconfirmed_ports(target: str, ports: list):
    """
    For each port that needs confirmation, run a targeted NSE scan and
    broadcast a port_update SSE event. One port at a time.
    Called from a background thread — do NOT await.
    """
    try:
        from app.scanner.executor import broadcast_port_update
    except ImportError:
        logger.error("Cannot import broadcast_port_update")
        return

    try:
        for port_data in ports:
            raw_vs = port_data.get("vuln_status", {})
            vuln_status = (
                raw_vs.get("status", "UNCONFIRMED")
                if isinstance(raw_vs, dict)
                else (str(raw_vs) if raw_vs else "UNCONFIRMED")
            )
            cves = port_data.get("cves", [])

            if vuln_status == "CONFIRMED":
                continue
            if vuln_status == "NOT_VULNERABLE" and not cves:
                continue

            service  = port_data.get("service", "")
            product  = port_data.get("product", service)
            version  = port_data.get("version", "")
            port_num = port_data.get("port", 0)
            protocol = port_data.get("protocol", "tcp")

            plan = find_scripts_for_port_with_plan(service, product, version, cves)

            if plan["action"] != "NSE":
                # No NSE available — emit appropriate status
                final_status = "POTENTIALLY_VULNERABLE" if plan["action"] == "VERSION" else "NOT_VALIDATABLE"
                broadcast_port_update({
                    **port_data,
                    "vuln_status": final_status,
                    "confirmation_note": plan["reason"],
                    "target": target,
                })
                continue

            script = plan["script"]
            logger.info("SSE confirm %s:%d — script: %s (CVE: %s)", target, port_num, script, plan["cve_id"])

            broadcast_port_update({**port_data, "vuln_status": "SCANNING", "target": target})

            output = run_confirmation_scan(target, port_num, protocol, [script])
            from app.scanner.cve_script_mapper import analyze_output
            result = analyze_output(output, script, plan["cve_id"] or "")

            broadcast_port_update({
                **port_data,
                "vuln_status":           result["status"],
                "confidence":            result["confidence"],
                "confirmation_scripts":  [script],
                "confirmation_cve":      plan["cve_id"],
                "evidence":              result["evidence"],
                "target":                target,
            })

            time.sleep(0.5)

    finally:
        try:
            from app.api.scan_control import scan_state
            scan_state.broadcast_stream_end()
        except Exception as se:
            logger.warning("Failed to broadcast stream_end: %s", se)
