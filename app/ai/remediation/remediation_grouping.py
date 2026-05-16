"""
ScanWise AI — Remediation Grouping
Groups vulnerabilities by service/software family to generate ONE
AI call per service group instead of one per CVE.
Dramatically reduces AI quota usage and prevents request storms.
"""
from typing import List, Dict


def group_by_service(ports: List[dict]) -> Dict[str, List[dict]]:
    """
    Group port entries by service family.
    Returns {service_key: [port_entries]} dict.

    Example groups: openssh, apache, smb, mysql, ...
    Multiple ports with the same service are merged into one group.
    """
    groups: Dict[str, List[dict]] = {}

    for port in ports:
        svc = _normalize_service(port.get("service", "unknown"))
        if svc not in groups:
            groups[svc] = []
        groups[svc].append(port)

    return groups


def build_group_summary(service: str, ports: List[dict]) -> dict:
    """
    Summarize a group of ports for a single AI call.
    Returns a compact dict with merged CVE list and worst-case severity.
    """
    all_cves = []
    seen_cves = set()
    worst_severity = "low"
    worst_cvss = 0.0
    versions = []

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for port in ports:
        v = port.get("version") or port.get("product") or "unknown"
        if v and v not in versions:
            versions.append(v)

        for cve in port.get("cves", []):
            cve_id = cve.get("cve_id", "")
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                all_cves.append(cve)

                sev = cve.get("severity", "low").lower()
                if severity_order.get(sev, 0) > severity_order.get(worst_severity, 0):
                    worst_severity = sev

                score = float(cve.get("cvss_score") or 0)
                if score > worst_cvss:
                    worst_cvss = score

    return {
        "service":   service,
        "ports":     [p.get("port") for p in ports],
        "versions":  versions[:3],  # top 3 detected versions
        "cves":      all_cves[:10],  # top 10 CVEs
        "severity":  worst_severity,
        "cvss":      worst_cvss,
        "port_count": len(ports),
    }


def prioritize_groups(groups: Dict[str, List[dict]]) -> List[tuple]:
    """
    Return groups sorted by worst severity (critical first).
    Returns list of (service, ports) tuples.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

    def _group_score(item):
        service, ports = item
        worst = "unknown"
        for port in ports:
            for cve in port.get("cves", []):
                sev = cve.get("severity", "low").lower()
                if severity_order.get(sev, 4) < severity_order.get(worst, 4):
                    worst = sev
        return severity_order.get(worst, 4)

    return sorted(groups.items(), key=_group_score)


# ── Internal ──────────────────────────────────────────────────────────────────

_SERVICE_ALIASES = {
    # SSH variants
    "openssh":   "ssh",
    "ssh2":      "ssh",
    # HTTP variants
    "apache":    "http",
    "nginx":     "http",
    "httpd":     "http",
    "iis":       "http",
    "apache2":   "http",
    # HTTPS
    "apache-ssl": "https",
    # FTP variants
    "vsftpd":    "ftp",
    "proftpd":   "ftp",
    "pureftpd":  "ftp",
    "sftp":      "ftp",
    # DB variants
    "mariadb":   "mysql",
    "mysqld":    "mysql",
    "postgres":  "postgresql",
    "pg":        "postgresql",
    # SMB
    "samba":     "smb",
    "microsoft-ds": "smb",
    "netbios":   "smb",
    # Telnet
    "telnetd":   "telnet",
    # SNMP
    "snmpd":     "snmp",
    # RDP
    "ms-wbt-server": "rdp",
    "terminal-services": "rdp",
}


def _normalize_service(service: str) -> str:
    """Normalize service name to a canonical group key."""
    s = service.lower().strip()
    return _SERVICE_ALIASES.get(s, s or "unknown")
