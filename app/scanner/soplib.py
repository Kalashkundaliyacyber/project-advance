"""
soplib.py
=========
Phase 4 of the reconstruction — Script Output Pattern Library.

The problem this solves: app/scanner/cve_script_mapper.py::analyze_output()
only understands the standard NSE "State: VULNERABLE" / "VULNERABLE:"
format. Scripts like smb-security-mode, ssl-enum-ciphers, ftp-anon, and
nfs-showmount use their own output conventions and never say that — so they
all fell through to UNCONFIRMED even when they'd clearly found something.

SOPLIB is a dictionary keyed by NSE script name. soplib_check() is the
single function everything else calls.
"""
from __future__ import annotations

import re
import logging

logger = logging.getLogger("ThreatWeave.soplib")


SOPLIB: dict[str, dict] = {

    "smb-security-mode": {
        "confirmed_patterns": [
            r"message_signing:\s*disabled",
            r"message_signing:\s*not\s+required",
        ],
        "safe_patterns": [
            r"message_signing:\s*required",
        ],
        "finding_description": "SMB message signing is disabled or not required — allows man-in-the-middle relay attacks (e.g. NTLM relay).",
        "category": "MISCONFIGURATION",
        "severity": "HIGH",
    },

    "ssl-enum-ciphers": {
        "confirmed_patterns": [
            r"least\s+strength:\s*C\b",
            r"least\s+strength:\s*D\b",
            r"least\s+strength:\s*E\b",
            r"least\s+strength:\s*F\b",
            r"\bTLSv1\.0\b",
            r"\bSSLv3\b",
            r"\bRC4\b",
            r"\bNULL\b",
            r"\bEXPORT\b",
        ],
        "safe_patterns": [
            r"least\s+strength:\s*A\b",
        ],
        "finding_description": "Weak TLS configuration detected — outdated protocol version and/or weak cipher suite (RC4/NULL/EXPORT/grade C or below) in use.",
        "category": "MISCONFIGURATION",
        "severity": "MEDIUM",
    },

    "ftp-anon": {
        "confirmed_patterns": [
            r"Anonymous\s+FTP\s+login\s+allowed",
        ],
        "safe_patterns": [
            r"Anonymous\s+FTP\s+login\s+(?:not\s+allowed|disabled)",
        ],
        "finding_description": "Anonymous FTP login is allowed — unauthenticated users can access the FTP server.",
        "category": "MISCONFIGURATION",
        "severity": "MEDIUM",
    },

    "nfs-showmount": {
        # World-readable export, classically rendered as "/path *" or
        # "/path (everyone)". Nmap prefixes every script-output line with
        # "|" or "|_", so DON'T anchor on line-start whitespace — match the
        # export-path-then-wildcard shape anywhere in the line instead.
        "confirmed_patterns": [
            r"/\S*\s+\*\s*$",
            r"everyone",
        ],
        "safe_patterns": [],
        "finding_description": "An NFS export is world-readable (mountable by any host) — potential exposure of sensitive filesystem data.",
        "category": "MISCONFIGURATION",
        "severity": "HIGH",
    },

    "mysql-empty-password": {
        "confirmed_patterns": [
            r"account.*has\s+empty\s+password",
            r"\bempty\s+password\b",
        ],
        "safe_patterns": [
            r"No\s+accounts\s+found\s+with\s+empty\s+password",
        ],
        "finding_description": "One or more MySQL accounts have an empty password — trivial unauthenticated database access.",
        "category": "VULNERABILITY",
        "severity": "CRITICAL",
    },

    "http-methods": {
        "confirmed_patterns": [
            r"\bTRACE\b",
            r"\bDELETE\b",
            r"\bPUT\b",
        ],
        "safe_patterns": [
            r"Potentially\s+risky\s+methods:\s*$",   # header present but empty list
        ],
        "finding_description": "HTTP server allows risky methods (TRACE/DELETE/PUT) — TRACE enables cross-site tracing (XST); DELETE/PUT enable unauthorized content modification.",
        "category": "MISCONFIGURATION",
        "severity": "MEDIUM",
    },

    # FIX (missing misconfig): nmap's default/-sC script set runs http-trace
    # as its OWN script — a separate id from http-methods above — and reports
    # it as a one-line "TRACE is enabled" with no other distinguishing text.
    # Without this entry, soplib_check("http-trace", ...) always returned
    # None, so the finding never reached misconfig_findings even though the
    # raw nmap output clearly showed `_http-trace: TRACE is enabled`.
    "http-trace": {
        "confirmed_patterns": [
            r"TRACE\s+is\s+enabled",
        ],
        "safe_patterns": [
            r"TRACE\s+is\s+disabled",
        ],
        "finding_description": "HTTP TRACE method is enabled — allows cross-site tracing (XST), which can be used to steal cookies/headers via reflected JavaScript despite httpOnly protections.",
        "category": "MISCONFIGURATION",
        "severity": "MEDIUM",
    },

    "snmp-brute": {
        "confirmed_patterns": [
            r"Discovered\s+community\s+string",
            r"community\s+string:\s*\S+",
        ],
        "safe_patterns": [],
        "finding_description": "A guessable SNMP community string was found — grants read (or read-write) access to device configuration and traffic data.",
        "category": "VULNERABILITY",
        "severity": "HIGH",
    },

    "telnet-ntlm-info": {
        "confirmed_patterns": [
            r".+",   # any non-empty output = telnet is live and answering
        ],
        "safe_patterns": [],
        "finding_description": "Telnet service is running — all credentials and traffic are sent in cleartext.",
        "category": "MISCONFIGURATION",
        "severity": "HIGH",
    },

    # FIX FIX-S1: smb-vuln-cve-2017-7494 (SambaCry) ran on Samba but got
    # NT_STATUS_OBJECT_NAME_NOT_FOUND — the exploit path did not exist, so
    # the vulnerability was NOT confirmed.  Without safe_patterns here, the
    # verbose SMB debug output (containing words like "IPC$", "PIPE", "WARNING")
    # triggered Qwen's YES heuristic, producing a MISCONFIGURED false positive
    # on ports 139 and 445.  These safe patterns short-circuit Qwen by returning
    # NOT_VULNERABLE from soplib_check() before Qwen is ever called.
    "smb-vuln-cve-2017-7494": {
        "confirmed_patterns": [
            r"State:\s*VULNERABLE",
            r"VULNERABLE\s*\(Exploitable\)",
        ],
        "safe_patterns": [
            r"NT_STATUS_OBJECT_NAME_NOT_FOUND",   # exploit .so path not found
            r"NT_STATUS_LOGON_FAILURE",            # auth failed
            r"server\s+appears\s+to\s+be\s+Unix", # Unix-specific warning
        ],
        "finding_description": "SambaCry (CVE-2017-7494) — writable share + .so load path exploitation.",
        "category": "VULNERABILITY",
        "severity": "CRITICAL",
    },

    # FIX FIX-S2: mysql-vuln-cve2012-2122 timed out on MySQL 5.0.51a
    # (receiveGreeting(): failed. Reason: TIMEOUT). The script never established
    # a connection — nothing was confirmed.  Without safe_patterns here, the
    # partially logged output was passed to Qwen which returned YES, producing
    # a MISCONFIGURED false positive on port 3306.
    "mysql-vuln-cve2012-2122": {
        "confirmed_patterns": [
            r"State:\s*VULNERABLE",
            r"Authentication\s+bypass",
        ],
        "safe_patterns": [
            r"TIMEOUT",
            r"receiveGreeting\(\):\s*failed",
            r"connection\s+refused",
            r"failed\s+to\s+connect",
        ],
        "finding_description": "MySQL authentication bypass via timing attack (CVE-2012-2122).",
        "category": "VULNERABILITY",
        "severity": "HIGH",
    },
}


def soplib_check(script_name: str, raw_output: str) -> dict | None:
    """
    Phase 4 main entry point.

    Returns {status, evidence, description, severity} if `script_name` is in
    SOPLIB and a pattern matched, else None (meaning: SOPLib has no opinion,
    let the generic VULNERABLE-keyword fallback in analyze_output() decide).

    status is "CONFIRMED" or "NOT_VULNERABLE" — SOPLib only speaks for
    scripts it knows the format of, so there's no UNCONFIRMED case here;
    that's the caller's fallback to handle.
    """
    entry = SOPLIB.get(script_name)
    if not entry or not raw_output or not raw_output.strip():
        return None

    # Safe patterns checked first — same safe-before-confirmed ordering as
    # the existing analyze_output(), so a script that reports both a generic
    # "vulnerable" keyword and an explicit safe state never gets misread.
    for pat in entry["safe_patterns"]:
        m = re.search(pat, raw_output, re.IGNORECASE | re.MULTILINE)
        if m:
            return {
                "status": "NOT_VULNERABLE",
                "evidence": _trim(m.group(0)),
                "description": entry["finding_description"],
                "severity": entry["severity"],
            }

    for pat in entry["confirmed_patterns"]:
        m = re.search(pat, raw_output, re.IGNORECASE | re.MULTILINE)
        if m:
            return {
                "status": "CONFIRMED",
                "evidence": _trim(m.group(0) or raw_output),
                "description": entry["finding_description"],
                "severity": entry["severity"],
                "category": entry["category"],
            }

    return None


def _trim(s: str, n: int = 200) -> str:
    s = " ".join(s.split())
    return s[:n]


def scan_all_ports(parsed: dict) -> list[dict]:
    """
    Convenience for the pipeline: walk every port's port["scripts"] (already
    populated by the single scan in Phase 0/1 — these scripts already ran,
    SOPLib just needs to *read* the output, not re-run anything) and return
    every SOPLib finding, automatically, no slash command, right after the
    scan's output is available.
    """
    findings = []
    for host in parsed.get("hosts", []):
        ip = host.get("ip") or host.get("address", "")
        for port in host.get("ports", []):
            for script in port.get("scripts", []) or []:
                result = soplib_check(script.get("id", ""), script.get("output", ""))
                if result and result["status"] == "CONFIRMED":
                    findings.append({
                        **result,
                        "host": ip,
                        "port": port.get("port"),
                        "protocol": port.get("protocol", "tcp"),
                        "script": script.get("id", ""),
                    })
    logger.info("soplib: %d confirmed findings from non-standard script formats", len(findings))
    return findings
