"""Context-Aware Analysis Engine — service criticality and exposure scoring."""

CRITICAL_SERVICES = {
    "ssh":        {"criticality": "high",     "reason": "Remote administration — high-value target"},
    "rdp":        {"criticality": "critical",  "reason": "Remote Desktop — full GUI access if compromised"},
    "ftp":        {"criticality": "high",      "reason": "File transfer — often transmits credentials in plaintext"},
    "telnet":     {"criticality": "critical",  "reason": "Plaintext remote access — must not be exposed"},
    "smb":        {"criticality": "critical",  "reason": "File sharing — primary ransomware attack vector"},
    "mysql":      {"criticality": "high",      "reason": "Database — may contain sensitive or personal data"},
    "postgresql": {"criticality": "high",      "reason": "Database — may contain sensitive or personal data"},
    "mssql":      {"criticality": "critical",  "reason": "MS SQL Server — frequent attack target"},
    "mongodb":    {"criticality": "high",      "reason": "NoSQL database — often misconfigured without auth"},
    "redis":      {"criticality": "high",      "reason": "In-memory store — commonly exposed without authentication"},
    "snmp":       {"criticality": "high",      "reason": "Network management — v1/v2c uses weak community strings"},
    "domain":     {"criticality": "high",      "reason": "DNS — can be abused for amplification or poisoning"},
    "http":       {"criticality": "medium",    "reason": "Web service — attack surface depends on the application"},
    "https":      {"criticality": "medium",    "reason": "Encrypted web service — verify TLS configuration"},
    "http-proxy": {"criticality": "high",      "reason": "Proxy — can be abused to relay traffic"},
    "vnc":        {"criticality": "critical",  "reason": "Remote desktop — often lacks strong authentication"},
    "smtp":       {"criticality": "medium",    "reason": "Mail relay — check for open relay misconfiguration"},
    "ldap":       {"criticality": "critical",  "reason": "Directory service — commonly stores credentials"},
}


def analyze_context(cve_data: dict) -> dict:
    result = dict(cve_data)
    for host in result.get("hosts", []):
        ports = host.get("ports", [])
        host["context"] = _host_context(len(ports))
        for port in ports:
            port["context"] = _port_context(port, len(ports))
    return result


def _host_context(port_count: int) -> dict:
    if port_count == 0:
        exposure, note = "none",   "No open ports found."
    elif port_count < 3:
        exposure, note = "low",    f"{port_count} open port(s). Minimal attack surface."
    elif port_count <= 8:
        exposure, note = "medium", f"{port_count} open ports. Moderate attack surface."
    else:
        exposure, note = "high",   f"{port_count} open ports. Large attack surface — review necessity of each service."
    return {"open_port_count": port_count, "exposure": exposure, "exposure_note": note}


def _port_context(port: dict, total_ports: int) -> dict:
    service    = port.get("service", "").lower()
    port_num   = port.get("port", 0)
    v_status   = port.get("version_analysis", {}).get("status", "unknown")

    svc_info = CRITICAL_SERVICES.get(service, {
        "criticality": "low",
        "reason":      "Non-standard service. Verify if this port should be open.",
    })

    if port_num in (21, 22, 23, 25, 80, 443, 3306, 5432, 3389, 445, 139, 161, 53):
        exposure_type = "commonly_exposed"
    elif port_num < 1024:
        exposure_type = "well_known_port"
    else:
        exposure_type = "high_port"

    version_risk = {"latest": "low", "outdated": "medium", "unsupported": "high"}.get(v_status, "medium")

    return {
        "criticality":        svc_info["criticality"],
        "criticality_reason": svc_info["reason"],
        "exposure_type":      exposure_type,
        "version_risk":       version_risk,
        "total_open_ports":   total_ports,
    }
