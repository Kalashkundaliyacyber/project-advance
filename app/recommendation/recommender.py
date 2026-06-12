"""
Scan Recommendation Engine
Suggests the next safe scan based on current findings.
Only recommends from the approved whitelist.
"""

RECOMMENDATIONS = {
    "no_version_info": {
        "scan_type": "service_detect",
        "title":     "Service & Version Detection",
        "reason":    "Open ports found but no service versions detected. Run service detection to identify what is running on each port.",
        "priority":  1,
    },
    "critical_cve_found": {
        "scan_type": "enum_scripts",
        "title":     "Script Enumeration (Critical CVE Follow-up)",
        "reason":    "Critical CVEs detected. NSE scripts can confirm service details and gather additional intelligence for remediation planning.",
        "priority":  1,
    },
    "outdated_versions": {
        "scan_type": "version_deep",
        "title":     "Deep Version Detection",
        "reason":    "Outdated versions detected. A deep version scan will precisely fingerprint service versions for accurate CVE matching.",
        "priority":  2,
    },
    "udp_not_scanned": {
        "scan_type": "udp_scan",
        "title":     "UDP Top-100 Scan",
        "reason":    "UDP ports not yet scanned. Services like DNS (53), SNMP (161), and NTP (123) run over UDP and are commonly overlooked.",
        "priority":  3,
    },
    "scripts_not_run": {
        "scan_type": "enum_scripts",
        "title":     "Script Enumeration",
        "reason":    "Default NSE scripts can detect misconfigurations, additional banners, and service-specific vulnerabilities.",
        "priority":  4,
    },
    "os_not_detected": {
        "scan_type": "os_detect",
        "title":     "OS Detection",
        "reason":    "Operating system not identified yet. OS information helps assess patch level and overall attack surface.",
        "priority":  5,
    },
    "all_complete": {
        "scan_type": None,
        "title":     "Generate Report",
        "reason":    "Scanning appears comprehensive. Export a report summarising all findings, CVEs, risk scores, and patch recommendations.",
        "priority":  10,
    },
}


def get_recommendation(risk_data: dict, current_scan_type: str) -> dict:
    """Return the best next scan recommendation based on current findings."""
    hosts = risk_data.get("hosts", [])
    if not hosts:
        return _fmt(RECOMMENDATIONS["all_complete"])

    has_version_info   = False
    has_outdated       = False
    has_critical_cve   = False
    has_os             = False

    for host in hosts:
        if host.get("os"):
            has_os = True
        for port in host.get("ports", []):
            va = port.get("version_analysis", {})
            if va.get("status") not in (None, "unknown"):
                has_version_info = True
            if va.get("status") in ("outdated", "unsupported"):
                has_outdated = True
            for cve in port.get("cves", []):
                if cve.get("severity") in ("critical", "high"):
                    has_critical_cve = True

    checks = []

    if has_critical_cve and current_scan_type != "enum_scripts":
        checks.append("critical_cve_found")

    if not has_version_info:
        checks.append("no_version_info")
    elif has_outdated and current_scan_type != "version_deep":
        checks.append("outdated_versions")

    if current_scan_type != "udp_scan":
        checks.append("udp_not_scanned")

    if current_scan_type != "enum_scripts" and "critical_cve_found" not in checks:
        checks.append("scripts_not_run")

    if not has_os and current_scan_type != "os_detect":
        checks.append("os_not_detected")

    if not checks:
        return _fmt(RECOMMENDATIONS["all_complete"])

    # Pick highest priority (lowest number)
    best = min(checks, key=lambda k: RECOMMENDATIONS[k]["priority"])
    result = _fmt(RECOMMENDATIONS[best])
    result["alternatives"] = [
        _fmt(RECOMMENDATIONS[k]) for k in checks if k != best
    ][:2]
    return result


def _fmt(rec: dict) -> dict:
    from app.scanner.orchestrator import SCAN_TEMPLATES
    out = {
        "title":    rec["title"],
        "reason":   rec["reason"],
        "scan_type": rec["scan_type"],
        "priority": rec["priority"],
    }
    if rec["scan_type"] and rec["scan_type"] in SCAN_TEMPLATES:
        out["command_description"] = SCAN_TEMPLATES[rec["scan_type"]]["description"]
    return out
