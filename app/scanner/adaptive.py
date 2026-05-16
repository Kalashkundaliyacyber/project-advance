"""
ScanWise AI — Adaptive Scan Orchestrator
Service-aware scan depth selection and intelligent NSE script selection.

Why this matters:
  Static scanning wastes time, increases noise, and misses service-specific
  vulnerabilities. Adapting to detected services dramatically improves:
    - accuracy (service-specific checks)
    - speed (skip irrelevant probes)
    - stealth (smaller footprint)
    - usability (recommended next-step)

Architecture:
  Initial scan result → service detection → profile selector → recommended follow-up
"""
from __future__ import annotations
import logging
from typing import Optional

logger = logging.getLogger("scanwise.scanner.adaptive")

# ── Service → NSE script profiles ─────────────────────────────────────────────
# Maps detected service name → recommended NSE scripts and scan flags

_SERVICE_PROFILES: dict[str, dict] = {
    "http": {
        "label":    "Web service",
        "scripts":  ["http-headers", "http-methods", "http-title", "http-auth-finder",
                     "http-security-headers", "http-open-redirect", "http-csrf"],
        "flags":    ["-sV", "--script=http-headers,http-methods,http-title,http-security-headers"],
        "follow_up_scan": "service_detect",
        "rationale": "Apache/Nginx/IIS detected → run web-specific checks",
    },
    "https": {
        "label":    "HTTPS service",
        "scripts":  ["ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle",
                     "http-headers", "http-security-headers"],
        "flags":    ["-sV", "--script=ssl-cert,ssl-enum-ciphers,ssl-heartbleed"],
        "follow_up_scan": "service_detect",
        "rationale": "HTTPS detected → audit TLS ciphers, cert, and heartbleed",
    },
    "ssh": {
        "label":    "SSH service",
        "scripts":  ["ssh-auth-methods", "ssh-hostkey", "ssh2-enum-algos"],
        "flags":    ["-sV", "--script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos"],
        "follow_up_scan": "service_detect",
        "rationale": "SSH detected → check auth methods and host key algorithms",
    },
    "smb": {
        "label":    "SMB/Windows file sharing",
        "scripts":  ["smb-vuln-ms17-010", "smb-security-mode", "smb-enum-shares",
                     "smb-enum-users", "smb-os-discovery"],
        "flags":    ["-sV", "--script=smb-vuln-ms17-010,smb-security-mode,smb-enum-shares"],
        "follow_up_scan": "vuln_scan",
        "rationale": "SMB detected → check EternalBlue (MS17-010) and shares",
    },
    "ftp": {
        "label":    "FTP service",
        "scripts":  ["ftp-anon", "ftp-bounce", "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor"],
        "flags":    ["-sV", "--script=ftp-anon,ftp-vsftpd-backdoor"],
        "follow_up_scan": "service_detect",
        "rationale": "FTP detected → check anonymous login and known backdoors",
    },
    "mysql": {
        "label":    "MySQL database",
        "scripts":  ["mysql-empty-password", "mysql-info", "mysql-enum",
                     "mysql-databases", "mysql-audit"],
        "flags":    ["-sV", "--script=mysql-empty-password,mysql-info"],
        "follow_up_scan": "service_detect",
        "rationale": "MySQL detected → check empty password and info disclosure",
    },
    "postgresql": {
        "label":    "PostgreSQL database",
        "scripts":  ["pgsql-brute"],
        "flags":    ["-sV"],
        "follow_up_scan": "service_detect",
        "rationale": "PostgreSQL detected → verify authentication requirements",
    },
    "rdp": {
        "label":    "Remote Desktop",
        "scripts":  ["rdp-vuln-ms12-020", "rdp-enum-encryption"],
        "flags":    ["-sV", "--script=rdp-vuln-ms12-020"],
        "follow_up_scan": "vuln_scan",
        "rationale": "RDP detected → check BlueKeep-class vulnerabilities",
    },
    "telnet": {
        "label":    "Telnet (plaintext)",
        "scripts":  ["telnet-ntlm-info"],
        "flags":    ["-sV", "--script=telnet-ntlm-info"],
        "follow_up_scan": "service_detect",
        "rationale": "Telnet detected → plaintext protocol, confirm and document",
    },
    "snmp": {
        "label":    "SNMP",
        "scripts":  ["snmp-info", "snmp-sysdescr", "snmp-communities",
                     "snmp-interfaces", "snmp-processes"],
        "flags":    ["-sU", "-sV", "--script=snmp-info,snmp-communities"],
        "follow_up_scan": "service_detect",
        "rationale": "SNMP detected → enumerate community strings and system info",
    },
    "redis": {
        "label":    "Redis",
        "scripts":  ["redis-info"],
        "flags":    ["-sV", "--script=redis-info"],
        "follow_up_scan": "service_detect",
        "rationale": "Redis detected → check if authentication is required",
    },
    "mongodb": {
        "label":    "MongoDB",
        "scripts":  ["mongodb-info", "mongodb-databases"],
        "flags":    ["-sV", "--script=mongodb-info,mongodb-databases"],
        "follow_up_scan": "service_detect",
        "rationale": "MongoDB detected → check if authentication is enabled",
    },
    "ldap": {
        "label":    "LDAP",
        "scripts":  ["ldap-rootdse", "ldap-search"],
        "flags":    ["-sV", "--script=ldap-rootdse"],
        "follow_up_scan": "service_detect",
        "rationale": "LDAP detected → enumerate root DSE and directory info",
    },
    "smtp": {
        "label":    "SMTP",
        "scripts":  ["smtp-open-relay", "smtp-enum-users", "smtp-commands"],
        "flags":    ["-sV", "--script=smtp-open-relay,smtp-commands"],
        "follow_up_scan": "service_detect",
        "rationale": "SMTP detected → check open relay and user enumeration",
    },
    "domain": {
        "label":    "DNS",
        "scripts":  ["dns-recursion", "dns-zone-transfer"],
        "flags":    ["-sV", "--script=dns-recursion,dns-zone-transfer"],
        "follow_up_scan": "service_detect",
        "rationale": "DNS detected → check recursion and zone transfer",
    },
}

# Confidence scoring weights
_CONFIDENCE_WEIGHTS = {
    "service_version_known": 0.4,
    "cve_matched":           0.3,
    "nse_confirmed":         0.2,
    "port_standard":         0.1,
}


def recommend_followup(scan_result: dict) -> dict:
    """
    Given a scan result (parsed nmap output), recommend:
      - adaptive follow-up scan type
      - relevant NSE scripts per detected service
      - confidence scores per finding

    Returns an enriched dict with 'adaptive_recommendations' key.
    """
    services_found: list[str] = []
    for host in scan_result.get("hosts", []):
        for port in host.get("ports", []):
            svc = port.get("service", "").lower()
            if svc:
                services_found.append(svc)

    if not services_found:
        return dict(scan_result)

    recommendations: list[dict] = []
    follow_up_scans: set[str]   = set()

    for svc in set(services_found):
        profile = _SERVICE_PROFILES.get(svc)
        if not profile:
            continue
        recommendations.append({
            "service":       svc,
            "label":         profile["label"],
            "scripts":       profile["scripts"][:4],   # top 4 only
            "rationale":     profile["rationale"],
            "follow_up":     profile["follow_up_scan"],
            "priority":      "high" if svc in ("smb", "rdp", "telnet", "ftp") else "medium",
        })
        follow_up_scans.add(profile["follow_up_scan"])

    # Prioritize critical services first
    _priority_order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda r: _priority_order.get(r["priority"], 1))

    primary_follow_up = (
        "vuln_scan"     if "vuln_scan" in follow_up_scans else
        "service_detect" if "service_detect" in follow_up_scans else
        "tcp_basic"
    )

    enriched = dict(scan_result)
    enriched["adaptive_recommendations"] = {
        "follow_up_scan":      primary_follow_up,
        "service_profiles":    recommendations,
        "services_detected":   list(set(services_found)),
        "total_services":      len(set(services_found)),
    }

    logger.info(
        "Adaptive: %d service(s) detected, recommended follow-up: %s",
        len(set(services_found)), primary_follow_up,
    )
    return enriched


def score_confidence(port: dict) -> float:
    """
    Score finding confidence 0.0–1.0 based on available evidence.
    Higher confidence = more reliable finding = higher remediation priority.
    """
    score = 0.0

    # Service version known
    if port.get("version") and port["version"] not in ("unknown", ""):
        score += _CONFIDENCE_WEIGHTS["service_version_known"]

    # CVE matched
    if port.get("cves"):
        score += _CONFIDENCE_WEIGHTS["cve_matched"]

    # Port is a well-known standard port for the service
    svc  = port.get("service", "")
    pnum = port.get("port", 0)
    _STANDARD_PORTS = {22: "ssh", 80: "http", 443: "https", 21: "ftp",
                       23: "telnet", 25: "smtp", 3306: "mysql", 5432: "postgresql",
                       3389: "rdp", 445: "smb", 161: "snmp", 6379: "redis"}
    if _STANDARD_PORTS.get(pnum, "").lower() == svc.lower():
        score += _CONFIDENCE_WEIGHTS["port_standard"]

    return round(min(1.0, score), 2)
