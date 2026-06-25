"""
scanner_core.py
================
Phase 0 (Part A) + Phase 1 of the reconstruction.

THIS IS THE ONLY NMAP SCAN IN THE PRODUCT.

Before this phase, "what scan runs" was a choice the user made (25 named
templates in the old app/scanner/orchestrator.py — quick/deep/discovery/
stealth/etc). That file is gone. There is now exactly one scan, it always
runs the same command, and it runs automatically the moment a target is
known — no scan-type selection, no quick/deep choice, no slash command.

Everything downstream (CVE mapper, confirmation router, misconfig checks,
report builder) consumes the SAME unified dict this module returns, so none
of that code needed to change because of this refactor.
"""
import logging

from app.scanner.executor import execute_scan
from app.parser.nmap_parser import parse_nmap_output

logger = logging.getLogger("ThreatWeave.scanner_core")

# ── Phase 1: locked-in script category set ──────────────────────────────────
# This is the ONE place that controls which NSE script categories run.
# Change this constant — and only this constant — to adjust scope.
NMAP_SCRIPT_CATEGORIES = "vuln"

# Internal key passed to executor.py for timeout lookup (SCAN_TIMEOUTS) and
# simulated-output selection when nmap isn't installed. NOT a user-facing
# "scan type" — there is only one scan, this is just its internal label.
SCAN_KEY = "full_scan"


def build_full_scan_command(target: str) -> list:
    """
    The one and only nmap command this product ever runs.

        nmap -Pn -p- --script="vuln" -sV -sC -d -O \
             --min-rate 1000 --max-rtt-timeout 100ms --max-retries 5 \
             -oX - <target>

    -Pn is added defensively (treat host as up even if it doesn't respond to
    ping/ACK probes) — every other scan profile in the old orchestrator used
    -Pn too, it is not a new behavior, just preserved so firewalled hosts
    still get scanned instead of being skipped as "down".

    -oX - is required: it tells nmap to print machine-readable XML to
    stdout instead of its normal human-readable scan log. Without it,
    executor.py captures plain text as `xml_output`, parse_nmap_output()
    fails to parse it as XML, and every scan silently returns 0 hosts/
    0 ports — even when the underlying nmap run succeeded and found
    open ports (this was the root cause of "No live hosts found" /
    "0 ports" showing in the UI despite a long, successful scan).

    -O enables OS fingerprinting (populates host["os"] in nmap_parser.py).
    NOTE: -O needs raw-socket privileges — the process running this command
    must have root / CAP_NET_RAW, or nmap will skip OS detection and emit a
    warning on stderr (scan still completes, just without OS info).

    --min-rate 1000 / --max-rtt-timeout 100ms / --max-retries 5 tune nmap's
    timing for a full -p- sweep on a responsive LAN: send at least 1000
    packets/sec, give up waiting on a probe after 100ms, retransmit a probe
    at most 5 times before marking it filtered. This trades a little
    accuracy on lossy/high-latency links for a much faster full-port scan;
    drop --min-rate or raise --max-rtt-timeout if scanning over a WAN/VPN
    where this causes false negatives.
    """
    return [
        "nmap",
        "-Pn",
        "-p-",
        f"--script={NMAP_SCRIPT_CATEGORIES}",
        "-sV",
        "-sC",
        "-d",                   # FIX: debug output — logs every NSE script start/finish
        "-O",                   # and script output even when no vulnerability is found,
        "--min-rate", "1000",   # so the confirmation_router always has raw evidence to parse.
        "--max-rtt-timeout", "100ms",
        "--max-retries", "5",
        "-oX", "-",
        target,
    ]


def run_full_scan(ip: str) -> dict:
    """
    Phase 0 Part A: THE single scan entry point.

    Runs build_full_scan_command(ip) exactly once and returns a unified
    raw-output object. Every downstream module reads this same dict:

        {
          "target":      str,
          "command":     list[str],   # exact argv that ran
          "raw_output":  str,         # full stderr+stdout text from nmap
          "xml_output":  str,         # -oX style XML nmap printed to stdout
          "duration":    float,       # seconds
          "parsed":      dict,        # parse_nmap_output(xml, raw) — same
                                       # shape every downstream consumer
                                       # (CVE mapper / risk engine / report
                                       # builder) has always received.
        }

    Nothing downstream changes shape because of this function — it just
    replaces *how* the scan is triggered and run.
    """
    cmd = build_full_scan_command(ip)
    logger.info("run_full_scan(%s): %s", ip, " ".join(cmd))

    raw_output, xml_output, duration = execute_scan(cmd, ip, SCAN_KEY)
    parsed = parse_nmap_output(xml_output, raw_output)

    return {
        "target": ip,
        "command": cmd,
        "raw_output": raw_output,
        "xml_output": xml_output,
        "duration": duration,
        "parsed": parsed,
    }
