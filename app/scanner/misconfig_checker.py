"""
misconfig_checker.py
=====================
Phase 5 of the reconstruction — misconfigurations as first-class findings.

Before this phase, only CVE-backed vulnerabilities were tracked — SMB
signing disabled, weak TLS, anonymous FTP, etc. have no CVE number, so they
were invisible to the rest of the pipeline even when SOPLib (Phase 4) had
already correctly identified them in script output.

MisconfigChecker wraps SOPLib's pattern matching (no duplicate regex logic)
for the script-output-based checks, and adds two purely port-presence checks
(telnet, SNMP) that don't need any script output at all.
"""
from __future__ import annotations

import logging
import re

from app.scanner.soplib import soplib_check

logger = logging.getLogger("ThreatWeave.misconfig_checker")

# Phase 5 requirement: a new status joining the existing string-based
# vocabulary (CONFIRMED / NOT_VULNERABLE / UNCONFIRMED / POTENTIALLY_VULNERABLE
# / NOT_VALIDATABLE / SCANNING — there's no central enum class for these in
# this codebase, they're plain strings checked at point of use).
STATUS_MISCONFIGURED = "MISCONFIGURED"

_REMEDIATION = {
    "smb-security-mode":    "Enable and require SMB message signing (Group Policy: 'Microsoft network server: Digitally sign communications (always)', or smb.conf: `server signing = mandatory`).",
    "ssl-enum-ciphers":     "Disable SSLv3/TLS 1.0/1.1, remove RC4/NULL/EXPORT ciphers from the server's cipher suite configuration; require TLS 1.2 or higher.",
    "ftp-anon":             "Disable anonymous FTP login (vsftpd: `anonymous_enable=NO`), or restrict it to a sandboxed, non-sensitive directory if required for business reasons.",
    "nfs-showmount":        "Restrict NFS exports to specific trusted hosts/networks in /etc/exports instead of `*` or `everyone`; run `exportfs -ra` after changing.",
    "http-methods":         "Disable TRACE (Apache: `TraceEnable Off`) and remove PUT/DELETE from allowed methods unless explicitly required (e.g. WebDAV with auth).",
    "http-trace":           "Disable the HTTP TRACE method (Apache: `TraceEnable Off`; IIS: remove TRACE via URLScan/Request Filtering) to prevent cross-site tracing (XST).",
    "http-csrf":            "Add a unique, per-session anti-CSRF token to every state-changing form and validate it server-side on submission; reject requests missing or mismatching the token.",
    "http-enum":            "Remove or restrict access to exposed admin panels, leftover CMS/test installs, and info-disclosure files (e.g. phpinfo.php); disable directory listing (Apache: `Options -Indexes`).",
    "telnet_open":          "Disable the Telnet service entirely and use SSH instead. If Telnet must remain for legacy reasons, restrict access to a management VLAN.",
    "snmp_default":         "Change the default SNMP community strings ('public'/'private') to strong, unique values, or migrate to SNMPv3 with authentication and encryption.",
    # FIX FIX-M1
    "bindshell_open":       "Immediately isolate this host from the network. Port is running an open root shell (bindshell), which is an unauthenticated backdoor. Rebuild the system from a clean image.",
    # FIX FIX-M2
    "rexec_open":           "Disable the rexec service (port 512): `systemctl disable rexec`, remove netkit-rsh/rsh-server packages. Replace with SSH for all remote command execution.",
    # FIX FIX-M3
    "rlogin_open":          "Disable the rlogin service (port 513): `systemctl disable rlogin`, remove netkit-rlogin packages. Replace with SSH for all remote access.",
    # FIX FIX-M4
    "http-cookie-flags":    "Set the HttpOnly flag on all session cookies to prevent JavaScript access. In Java/Tomcat: `context.setUseHttpOnly(true)` or add `httpOnly=true` to session-config in web.xml.",
}

# FIX (missing misconfig): both scripts can report MULTIPLE distinct items
# in one run (several CSRF-vulnerable forms, several enumerated paths).
# Routing them through the generic soplib_check()-based _script_check()
# below would only capture the FIRST regex match as evidence — for a script
# that found 7 paths, that silently drops 6 of them. These two patterns are
# only used to detect *whether* to build a custom, multi-item finding (see
# check_http_csrf / check_http_enum) — they are not registered in SOPLIB.
_HTTP_CSRF_FOUND_RE = re.compile(r"Found\s+the\s+following\s+possible\s+CSRF", re.IGNORECASE)
_HTTP_CSRF_PATH_RE  = re.compile(r"Path:\s*(\S+)")
_HTTP_ENUM_PATH_RE  = re.compile(r"^\s*(/\S+):\s+(.+)$", re.MULTILINE)


class MisconfigChecker:
    """
    Takes the unified scan output (parsed dict from Phase 0/1) plus the
    Phase 2 service-prober results, and produces MISCONFIGURATION findings
    independent of any CVE.
    """

    def __init__(self, scan_output: dict, probed_services: dict | None = None):
        self.scan_output = scan_output
        self.probed = probed_services or {}

    # ── per-script checks (delegate pattern matching to SOPLib) ────────────

    def _script_check(self, host_ip: str, port: dict, script_name: str) -> dict | None:
        for script in port.get("scripts", []) or []:
            if script.get("id") != script_name:
                continue
            result = soplib_check(script_name, script.get("output", ""))
            if result and result["status"] == "CONFIRMED":
                return {
                    "type":        "MISCONFIGURATION",
                    "name":        script_name,
                    "description": result["description"],
                    "severity":    result["severity"],
                    "evidence":    result["evidence"],
                    "remediation": _REMEDIATION.get(script_name, "Review and harden this service's configuration."),
                    "host":        host_ip,
                    "port":        port.get("port"),
                }
        return None

    def check_smb_signing(self, host_ip: str, port: dict) -> dict | None:
        return self._script_check(host_ip, port, "smb-security-mode")

    def check_ssl_ciphers(self, host_ip: str, port: dict) -> dict | None:
        return self._script_check(host_ip, port, "ssl-enum-ciphers")

    def check_ftp_anon(self, host_ip: str, port: dict) -> dict | None:
        return self._script_check(host_ip, port, "ftp-anon")

    def check_nfs_exports(self, host_ip: str, port: dict) -> dict | None:
        return self._script_check(host_ip, port, "nfs-showmount")

    def check_http_methods(self, host_ip: str, port: dict) -> dict | None:
        return self._script_check(host_ip, port, "http-methods")

    # FIX (missing misconfig): nmap's default/-sC script set runs http-trace
    # as a separate script from http-methods. Without this, a scan that only
    # picked up "_http-trace: TRACE is enabled" (and never ran http-methods)
    # produced zero MISCONFIGURATION findings for an open, exploitable TRACE
    # method — even though the raw NSE output already proved it.
    def check_http_trace(self, host_ip: str, port: dict) -> dict | None:
        return self._script_check(host_ip, port, "http-trace")

    # FIX (missing misconfig): http-csrf and http-enum both routinely report
    # MULTIPLE distinct items in one run on this scan (several forms with no
    # CSRF token; several enumerated admin/info-disclosure paths). These are
    # custom checks rather than _script_check()/soplib_check() calls because
    # that path only ever returns the FIRST regex match as evidence — fine
    # for a single yes/no script, but it would silently drop every item after
    # the first one here.
    def check_http_csrf(self, host_ip: str, port: dict) -> dict | None:
        for script in port.get("scripts", []) or []:
            if script.get("id") != "http-csrf":
                continue
            output = script.get("output", "") or ""
            if not _HTTP_CSRF_FOUND_RE.search(output):
                return None
            paths = _HTTP_CSRF_PATH_RE.findall(output)
            if not paths:
                return None
            shown = paths[:6]
            evidence = "Possible CSRF on: " + ", ".join(shown) + ("…" if len(paths) > 6 else "")
            return {
                "type":        "MISCONFIGURATION",
                "name":        "http-csrf",
                "description": (f"{len(paths)} form(s) without anti-CSRF tokens found during spidering — "
                                 "an attacker could trick an authenticated user into submitting unintended requests."),
                "severity":    "MEDIUM",
                "evidence":    evidence,
                "remediation": _REMEDIATION.get("http-csrf", "Review and harden this service's configuration."),
                "host":        host_ip,
                "port":        port.get("port"),
            }
        return None

    def check_http_enum(self, host_ip: str, port: dict) -> dict | None:
        for script in port.get("scripts", []) or []:
            if script.get("id") != "http-enum":
                continue
            output = script.get("output", "") or ""
            matches = _HTTP_ENUM_PATH_RE.findall(output)
            if not matches:
                return None
            items = [f"{path} ({desc.strip()})" for path, desc in matches]
            shown = items[:8]
            evidence = "; ".join(shown) + ("…" if len(items) > 8 else "")
            return {
                "type":        "MISCONFIGURATION",
                "name":        "http-enum",
                "description": f"Directory/file enumeration exposed {len(items)} potentially sensitive path(s): {evidence}",
                "severity":    "MEDIUM",
                "evidence":    evidence,
                "remediation": _REMEDIATION.get("http-enum", "Review and harden this service's configuration."),
                "host":        host_ip,
                "port":        port.get("port"),
            }
        return None

    # ── pure port-presence checks (no script output needed) ────────────────

    def check_telnet_open(self, host_ip: str, port: dict) -> dict | None:
        if port.get("port") == 23 and port.get("state") in ("open", "open|filtered"):
            return {
                "type":        "MISCONFIGURATION",
                "name":        "telnet_open",
                "description": "Telnet service is open — credentials and all traffic are sent in cleartext, trivially interceptable.",
                "severity":    "HIGH",
                "evidence":    f"Port 23/tcp open ({port.get('service', 'telnet')})",
                "remediation": _REMEDIATION["telnet_open"],
                "host":        host_ip,
                "port":        23,
            }
        return None

    def check_snmp_default(self, host_ip: str, port: dict) -> dict | None:
        if port.get("port") == 161 and port.get("state") in ("open", "open|filtered"):
            brute = self._script_check(host_ip, port, "snmp-brute")
            if brute:
                brute["name"] = "snmp_default"
                return brute
            return {
                "type":        "MISCONFIGURATION",
                "name":        "snmp_default",
                "description": "SNMP service is open — flagged for default/guessable community string follow-up.",
                "severity":    "MEDIUM",
                "evidence":    f"Port 161/udp open ({port.get('service', 'snmp')})",
                "remediation": _REMEDIATION["snmp_default"],
                "host":        host_ip,
                "port":        161,
            }
        return None

    # FIX FIX-M1: Open backdoor root shell — critical, missed entirely before.
    # Nmap identifies port 1524 service as "Metasploitable root shell" (bindshell).
    # Connecting to this port grants an unauthenticated interactive root shell.
    # No NSE script is needed — the service name alone is conclusive.
    def check_bindshell_open(self, host_ip: str, port: dict) -> dict | None:
        if port.get("state") not in ("open", "open|filtered"):
            return None
        service = (port.get("service") or "").lower()
        product = (port.get("product") or "").lower()
        version = (port.get("version") or "").lower()
        combined = f"{service} {product} {version}"
        _BINDSHELL_INDICATORS = [
            "bindshell", "root shell", "metasploitable root",
            "backdoor shell", "cmd shell",
        ]
        if any(ind in combined for ind in _BINDSHELL_INDICATORS):
            return {
                "type":        "MISCONFIGURATION",
                "name":        "bindshell_open",
                "description": (
                    f"Port {port.get('port')}/tcp is running an unauthenticated root-level "
                    "shell (bindshell). Any network connection to this port receives an "
                    "interactive root shell with no credentials required. Immediate isolation required."
                ),
                "severity":    "CRITICAL",
                "evidence":    f"Port {port.get('port')}/tcp open — service: {combined.strip()[:80]}",
                "remediation": _REMEDIATION["bindshell_open"],
                "host":        host_ip,
                "port":        port.get("port"),
            }
        return None

    # FIX FIX-M2: rexec service (port 512) — unauthenticated remote command execution.
    # rexec transmits credentials and all session data in cleartext. More dangerous
    # than Telnet: it is specifically designed for executing remote commands.
    def check_rexec_open(self, host_ip: str, port: dict) -> dict | None:
        if port.get("state") not in ("open", "open|filtered"):
            return None
        pnum    = port.get("port")
        service = (port.get("service") or "").lower()
        if pnum == 512 or "rexec" in service or "exec" in service:
            return {
                "type":        "MISCONFIGURATION",
                "name":        "rexec_open",
                "description": (
                    "rexec service is open (port 512) — allows remote command execution "
                    "with credentials transmitted in cleartext. More dangerous than Telnet: "
                    "disables host-based authentication by default."
                ),
                "severity":    "CRITICAL",
                "evidence":    f"Port {pnum}/tcp open ({port.get('service', 'exec')})",
                "remediation": _REMEDIATION["rexec_open"],
                "host":        host_ip,
                "port":        pnum,
            }
        return None

    # FIX FIX-M3: rlogin service (port 513) — cleartext remote login.
    # Equivalent security risk to Telnet: all session data including credentials
    # is transmitted in cleartext. The project flagged Telnet (port 23) but not rlogin.
    def check_rlogin_open(self, host_ip: str, port: dict) -> dict | None:
        if port.get("state") not in ("open", "open|filtered"):
            return None
        pnum    = port.get("port")
        service = (port.get("service") or "").lower()
        if pnum == 513 or "rlogin" in service or (pnum == 513 and "login" in service):
            return {
                "type":        "MISCONFIGURATION",
                "name":        "rlogin_open",
                "description": (
                    "rlogin service is open (port 513) — transmits all session data and "
                    "credentials in cleartext. Equivalent security risk to Telnet (port 23)."
                ),
                "severity":    "HIGH",
                "evidence":    f"Port {pnum}/tcp open ({port.get('service', 'login')})",
                "remediation": _REMEDIATION["rlogin_open"],
                "host":        host_ip,
                "port":        pnum,
            }
        return None

    # FIX FIX-M4: Session cookies missing HttpOnly flag.
    # nmap's http-cookie-flags script confirmed JSESSIONID and other session
    # cookies are served without HttpOnly on port 8180 (Apache Tomcat admin).
    # Without HttpOnly, XSS can steal session tokens via JavaScript.
    _COOKIE_HTTPONLY_RE = re.compile(
        r"(JSESSIONID|PHPSESSID|ASP\.NET_SessionId|session_id|auth_token)"
        r"[^\n]*httponly\s+flag\s+not\s+set",
        re.IGNORECASE,
    )

    def check_http_cookie_flags(self, host_ip: str, port: dict) -> dict | None:
        for script in port.get("scripts", []) or []:
            if script.get("id") != "http-cookie-flags":
                continue
            output = script.get("output", "") or ""
            matches = self._COOKIE_HTTPONLY_RE.findall(output)
            if not matches:
                # Fallback: any "httponly flag not set" mention is still a finding
                if not re.search(r"httponly\s+flag\s+not\s+set", output, re.IGNORECASE):
                    return None
                matches = ["session cookie"]
            unique = list(dict.fromkeys(matches))   # deduplicate, preserve order
            return {
                "type":        "MISCONFIGURATION",
                "name":        "http-cookie-flags",
                "description": (
                    f"Session cookie(s) missing HttpOnly flag: {', '.join(unique)}. "
                    "JavaScript can read these tokens — XSS exploits can lead to "
                    "session hijacking even when other XSS mitigations are in place."
                ),
                "severity":    "MEDIUM",
                "evidence":    output.strip()[:300],
                "remediation": _REMEDIATION["http-cookie-flags"],
                "host":        host_ip,
                "port":        port.get("port"),
            }
        return None

    # ── run everything ──────────────────────────────────────────────────────

    def run_all(self) -> list[dict]:
        """
        Phase 5 main entry point. Returns every MISCONFIGURATION finding
        across every host/port in the scan.
        """
        findings: list[dict] = []
        checks = [
            self.check_smb_signing,
            self.check_ssl_ciphers,
            self.check_ftp_anon,
            self.check_nfs_exports,
            self.check_http_methods,
            self.check_http_trace,
            self.check_http_csrf,
            self.check_http_enum,
            self.check_http_cookie_flags,   # FIX FIX-M4: session cookie HttpOnly check
            self.check_telnet_open,
            self.check_snmp_default,
            self.check_bindshell_open,      # FIX FIX-M1: open backdoor root shell
            self.check_rexec_open,          # FIX FIX-M2: rexec cleartext remote command
            self.check_rlogin_open,         # FIX FIX-M3: rlogin cleartext remote login
        ]
        for host in self.scan_output.get("hosts", []):
            host_ip = host.get("ip") or host.get("address", "")
            for port in host.get("ports", []):
                for check in checks:
                    try:
                        result = check(host_ip, port)
                    except Exception as e:
                        logger.warning("misconfig check %s failed for %s:%s — %s",
                                        check.__name__, host_ip, port.get("port"), e)
                        result = None
                    if result:
                        findings.append(result)
        logger.info("misconfig_checker: %d findings across %d host(s)",
                    len(findings), len(self.scan_output.get("hosts", [])))
        return findings


def run_all(scan_output: dict, probed_services: dict | None = None) -> list[dict]:
    """Module-level convenience wrapper, matches the phase spec's exact call shape."""
    return MisconfigChecker(scan_output, probed_services).run_all()
