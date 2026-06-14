"""
app/scanner/script_selector.py
────────────────────────────────────────────────────────────────────────────
Intelligent NSE script selector for Kali Linux.

Workflow
--------
1. get_available_scripts()   — index /usr/share/nmap/scripts/ on first call
2. find_scripts_for_port()   — match service / version / CVE to script names
3. run_confirmation_scan()   — run nmap -p<port> --script <scripts> <target>
4. interpret_script_output() — return CONFIRMED / NOT_VULNERABLE / UNCONFIRMED
5. confirm_unconfirmed_ports() — orchestrate the whole flow for a full scan
   result; broadcasts port_update SSE events as each port is resolved.
"""

import os
import re
import shutil
import subprocess
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

SCRIPTS_DIR = "/usr/share/nmap/scripts"

# ──────────────────────────────────────────────────────────────────────────
# Script index (built once, cached)
# ──────────────────────────────────────────────────────────────────────────
_script_index: Optional[list] = None   # list of script names (no .nse)


def get_available_scripts() -> list:
    """Return cached list of all script names from /usr/share/nmap/scripts/."""
    global _script_index
    if _script_index is not None:
        return _script_index
    try:
        names = [
            f[:-4]                           # strip .nse
            for f in os.listdir(SCRIPTS_DIR)
            if f.endswith(".nse")
        ]
        _script_index = sorted(names)
        logger.info("NSE script index: %d scripts found", len(_script_index))
        return _script_index
    except FileNotFoundError:
        logger.warning("Kali NSE scripts directory not found: %s", SCRIPTS_DIR)
        _script_index = []
        return []


# ──────────────────────────────────────────────────────────────────────────
# Service → keyword mappings
# ──────────────────────────────────────────────────────────────────────────
# Each entry is (service_keyword, version_keyword_or_None, [script_keywords])
# Script keywords are matched against script names (case-insensitive substring).
_SERVICE_RULES = [
    # FTP
    ("ftp",   "vsftpd 2.3",  ["vsftpd-backdoor"]),
    ("ftp",   "proftpd 1.3", ["ftp-proftpd-backdoor"]),
    ("ftp",   None,           ["ftp-vuln", "ftp-anon", "ftp-bounce"]),
    # SSH
    ("ssh",   None,           ["ssh-vuln", "ssh-auth-methods", "sshv1"]),
    # HTTP / HTTPS
    ("http",  "apache 2.2",  ["http-vuln-cve2011-3192", "http-shellshock", "http-vuln"]),
    ("http",  "apache 2.4",  ["http-shellshock", "http-vuln", "http-slowloris"]),
    ("http",  "iis",          ["http-iis-webdav-vuln", "http-vuln"]),
    ("https", None,           ["ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
                                "ssl-ccs-injection", "http-vuln"]),
    ("http",  None,           ["http-vuln", "http-shellshock", "http-csrf",
                                "http-sql-injection", "http-stored-xss"]),
    # SMB
    ("smb",   None,           ["smb-vuln-ms17-010", "smb-vuln-ms08-067",
                                "smb-vuln-cve-2020-0796", "smb-security-mode",
                                "smb2-security-mode", "smb-vuln"]),
    ("microsoft-ds", None,    ["smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln"]),
    # RDP
    ("ms-wbt-server", None,   ["rdp-vuln-ms12-020", "rdp-enum-encryption"]),
    ("rdp",   None,           ["rdp-vuln-ms12-020", "rdp-enum-encryption"]),
    # MySQL
    ("mysql", None,           ["mysql-vuln-cve2012-2122", "mysql-empty-password",
                                "mysql-databases", "mysql-info"]),
    # MSSQL
    ("mssql", None,           ["ms-sql-info", "ms-sql-empty-password", "ms-sql-vuln"]),
    ("ms-sql",None,           ["ms-sql-info", "ms-sql-empty-password"]),
    # PostgreSQL
    ("postgresql", None,      ["pgsql-brute"]),
    # IRC / UnrealIRCd
    ("irc",   "unrealircd 3.2.8", ["irc-unrealircd-backdoor"]),
    ("irc",   None,           ["irc-unrealircd-backdoor", "irc-botnet-channels"]),
    # SMTP
    ("smtp",  None,           ["smtp-vuln-cve2010-4344", "smtp-open-relay",
                                "smtp-commands", "smtp-enum-users"]),
    # DNS
    ("dns",   None,           ["dns-zone-transfer", "dns-recursion", "dns-cache-snoop"]),
    # VNC
    ("vnc",   None,           ["vnc-vuln-cve2006-2369", "vnc-brute", "vnc-info"]),
    # Redis
    ("redis", None,           ["redis-info", "redis-brute"]),
    # MongoDB
    ("mongodb", None,         ["mongodb-info", "mongodb-databases"]),
    # Telnet
    ("telnet", None,          ["telnet-encryption", "telnet-ntlm-info"]),
    # SNMP
    ("snmp",  None,           ["snmp-info", "snmp-brute", "snmp-vuln-cve2012-6438"]),
    # NFS / RPC
    ("nfs",   None,           ["nfs-ls", "nfs-showmount", "nfs-statfs"]),
    ("rpcbind", None,         ["rpcinfo"]),
    # Java / AJP (Tomcat)
    ("ajp",   None,           ["ajp-headers", "ajp-request"]),
    ("http",  "tomcat",       ["http-vuln-cve2019-0232", "http-tomcat-manager"]),
    # Distcc
    ("distccd", None,         ["distcc-cve2004-2687"]),
    # X11
    ("x11",   None,           ["x11-access"]),
    # Generic fallback
    (None,    None,           ["vuln"]),
]


def find_scripts_for_port(service: str, product: str, version: str, cves: list) -> list:
    """
    Return a deduplicated list of NSE script names appropriate for this port.

    Parameters
    ----------
    service  : e.g. "ftp", "http", "ssh"
    product  : e.g. "vsftpd", "Apache httpd"
    version  : e.g. "2.3.4"
    cves     : list of CVE IDs like ["CVE-2011-3192"]

    Returns list of exact script names (no .nse extension) present on disk.
    """
    available = get_available_scripts()
    if not available:
        return []

    combined = f"{service} {product} {version}".lower()
    candidates: set = set()

    # 1. Match service rules
    for svc_kw, ver_kw, script_kws in _SERVICE_RULES:
        svc_match = (svc_kw is None) or (svc_kw.lower() in combined)
        ver_match = (ver_kw is None) or (ver_kw.lower() in combined)
        if svc_match and ver_match:
            for kw in script_kws:
                # Find all available scripts containing this keyword
                for s in available:
                    if kw.lower() in s.lower():
                        candidates.add(s)

    # 2. Match CVE IDs directly against script names
    # e.g. CVE-2017-0144 → smb-vuln-ms17-010 won't match by name,
    # but CVE-2011-3192 → http-vuln-cve2011-3192 will.
    #
    # `cves` entries may arrive as plain ID strings ("CVE-2011-2523") OR as
    # full CVE dicts ({"cve_id": "CVE-2011-2523", "cvss_score": ..., ...}) —
    # the latter is what nmap_parser/map_cves attach to each port. Accept
    # both so this function is safe regardless of caller.
    for cve in cves:
        if isinstance(cve, dict):
            cve_id = cve.get("cve_id") or cve.get("id") or ""
        else:
            cve_id = cve or ""
        if not cve_id:
            continue
        cve_clean = str(cve_id).lower().replace("cve-", "").replace("-", "")
        for s in available:
            s_clean = s.lower().replace("-", "")
            if cve_clean in s_clean:
                candidates.add(s)

    # Filter to only scripts actually on disk
    confirmed = [s for s in candidates if s in available]

    # Prefer targeted over generic; limit to 8 to keep scan fast
    generic = [s for s in confirmed if s == "vuln"]
    specific = [s for s in confirmed if s != "vuln"]
    result = specific[:7] + (generic if not specific else [])
    return result[:8]


# ──────────────────────────────────────────────────────────────────────────
# Confirmation scan runner
# ──────────────────────────────────────────────────────────────────────────

def run_confirmation_scan(target: str, port: int, protocol: str,
                          scripts: list, timeout: int = 120) -> str:
    """
    Run nmap -p<port> --script <scripts> <target> and return raw stdout.
    Returns empty string if nmap unavailable or scripts list is empty.
    """
    if not scripts:
        return ""
    if not shutil.which("nmap"):
        return ""
    script_arg = ",".join(scripts)
    cmd = [
        "nmap", "-p", str(port),
        f"-s{'U' if protocol == 'udp' else 'V'}",
        "--script", script_arg,
        "--script-timeout", "30s",
        "--max-rtt-timeout", "200ms",
        "--min-rate", "500",
        target,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        logger.warning("Confirmation scan timed out for %s:%d", target, port)
        return ""
    except Exception as exc:
        logger.warning("Confirmation scan error: %s", exc)
        return ""


def interpret_script_output(output: str) -> str:
    """
    Analyse nmap confirmation script output and return:
    - "CONFIRMED"       — vulnerability proven
    - "NOT_VULNERABLE"  — explicitly ruled out
    - "UNCONFIRMED"     — insufficient evidence
    """
    if not output:
        return "UNCONFIRMED"

    low = output.lower()

    # Strong positive signals
    confirmed_patterns = [
        r"\bstate:\s*vulnerable\b",
        r"\bvulnerable\b",
        r"\bexploit\b",
        r"\bbackdoor\b",
        r"\bcompromised\b",
        r"VULNERABLE",
        r"successfully exploited",
        r"CVE-\d{4}-\d+.*VULNERABLE",
    ]
    for pat in confirmed_patterns:
        if re.search(pat, output, re.IGNORECASE):
            return "CONFIRMED"

    # Strong negative signals
    safe_patterns = [
        r"\bstate:\s*not vulnerable\b",
        r"\bnot\s+vulnerable\b",
        r"patched",
        r"not affected",
    ]
    for pat in safe_patterns:
        if re.search(pat, output, re.IGNORECASE):
            return "NOT_VULNERABLE"

    return "UNCONFIRMED"


# ──────────────────────────────────────────────────────────────────────────
# Main orchestrator — call after a full scan completes
# ──────────────────────────────────────────────────────────────────────────

def confirm_unconfirmed_ports(target: str, ports: list):
    """
    For each port in `ports` that is UNCONFIRMED or has CVEs, run a targeted
    NSE confirmation scan and broadcast a port_update SSE event with the result.

    This runs in a background thread — do NOT await it.

    ALWAYS calls scan_state.broadcast_stream_end() in a finally block so the
    SSE connection closes cleanly after all confirmation events are sent, even
    if confirmation crashes mid-loop.
    """
    try:
        from app.scanner.executor import broadcast_port_update
    except ImportError:
        logger.error("Cannot import broadcast_port_update")
        return

    try:
        for port_data in ports:
            # FIX BUG 3: vuln_status from _parse_port() is a DICT
            # {"status": "CONFIRMED", "script_used": ..., "evidence": ...}
            # but was incorrectly compared to strings like "CONFIRMED".
            # Normalise to string here so all comparisons work correctly.
            raw_vs = port_data.get("vuln_status", {})
            if isinstance(raw_vs, dict):
                vuln_status = raw_vs.get("status", "UNCONFIRMED")
            else:
                vuln_status = str(raw_vs) if raw_vs else "UNCONFIRMED"

            cves = port_data.get("cves", [])

            # Only run confirmation on UNCONFIRMED ports or ports with known CVEs
            if vuln_status == "NOT_VULNERABLE" and not cves:
                continue
            if vuln_status == "CONFIRMED":
                continue

            service  = port_data.get("service", "")
            product  = port_data.get("product", port_data.get("service", ""))
            version  = port_data.get("version", "")
            port_num = port_data.get("port", 0)
            protocol = port_data.get("protocol", "tcp")

            scripts = find_scripts_for_port(service, product, version, cves)
            if not scripts:
                logger.debug("No scripts found for %s:%d (%s %s)", target, port_num, service, version)
                continue

            logger.info(
                "Confirmation scan %s:%d — scripts: %s",
                target, port_num, ", ".join(scripts)
            )

            # Broadcast SCANNING status so the chatbot row shows a progress indicator
            scanning_update = {**port_data, "vuln_status": "SCANNING", "target": target}
            broadcast_port_update(scanning_update)

            output = run_confirmation_scan(target, port_num, protocol, scripts)
            final_status = interpret_script_output(output)

            # Broadcast the confirmed result
            final_update = {
                **port_data,
                "vuln_status": final_status,
                "confirmation_scripts": scripts,
                "confirmation_output": output[:500] if output else "",
                "target": target,
            }
            broadcast_port_update(final_update)

            # Small pause between ports so we don't flood the target
            time.sleep(0.5)

    finally:
        # FIX BUG 1: Always signal stream_end after ALL confirmation work is done
        # (or if the loop never ran because all ports were already confirmed/filtered).
        # The SSE generator in scan_control.py now waits for this event instead of
        # closing on "status: complete", so no port_update events can be lost.
        try:
            from app.api.scan_control import scan_state
            scan_state.broadcast_stream_end()
            logger.info("NSE confirmation complete for %s — stream_end broadcast", target)
        except Exception as se:
            logger.warning("Failed to broadcast stream_end for %s: %s", target, se)
