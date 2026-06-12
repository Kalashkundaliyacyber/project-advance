"""
ThreatWeave — Asset Criticality Engine (Phase 8)
=================================================
Assigns criticality scores to discovered assets based on:
  - Service type (database, auth, infrastructure)
  - Port exposure (internet-facing vs internal)
  - Known high-value ports
  - OS indicators
  - Service version age

Output: criticality_level (critical/high/medium/low) + score (0-100) + reasons
"""
import logging
from typing import Optional

logger = logging.getLogger("ThreatWeave.asset_criticality")

# Service criticality map
_SERVICE_CRITICALITY = {
    # Critical infrastructure
    "domain":     ("critical", 95, "DNS server — infrastructure backbone"),
    "kerberos":   ("critical", 95, "Kerberos auth — AD credential store"),
    "ldap":       ("critical", 90, "LDAP directory — identity store"),
    "ldaps":      ("critical", 90, "Secure LDAP — identity store"),
    "msrpc":      ("critical", 85, "MS-RPC — Windows core services"),
    "netbios-ssn":("critical", 85, "NetBIOS — Windows file sharing"),

    # Databases
    "mysql":      ("critical", 88, "MySQL database — potential data store"),
    "postgresql": ("critical", 88, "PostgreSQL — potential data store"),
    "mssql":      ("critical", 90, "MSSQL — enterprise database"),
    "oracle":     ("critical", 92, "Oracle DB — enterprise data"),
    "mongodb":    ("critical", 85, "MongoDB — NoSQL data store"),
    "redis":      ("high",     80, "Redis cache — may hold sensitive data"),
    "cassandra":  ("high",     78, "Cassandra — distributed database"),
    "elasticsearch": ("high",  80, "Elasticsearch — may index sensitive data"),

    # Remote access
    "ssh":        ("high",     75, "SSH — remote admin access"),
    "rdp":        ("critical", 90, "RDP — direct remote desktop, high-value target"),
    "vnc":        ("critical", 88, "VNC — unauthenticated remote desktop"),
    "telnet":     ("critical", 95, "Telnet — plaintext remote shell"),
    "rsh":        ("critical", 98, "RSH — legacy unauthenticated remote shell"),

    # Web
    "http":       ("medium",   55, "HTTP web service"),
    "https":      ("medium",   50, "HTTPS web service (encrypted)"),
    "http-alt":   ("medium",   55, "Alternate HTTP port"),

    # File transfer
    "ftp":        ("high",     78, "FTP — plaintext file transfer"),
    "ftps":       ("medium",   55, "FTPS — encrypted FTP"),
    "sftp":       ("medium",   50, "SFTP — secure file transfer"),
    "smb":        ("critical", 88, "SMB — Windows file sharing, WannaCry vector"),
    "nfs":        ("high",     80, "NFS — network file system, often over-exposed"),

    # Mail
    "smtp":       ("high",     70, "SMTP — mail relay, spam/phishing vector"),
    "pop3":       ("medium",   60, "POP3 — mail retrieval (plaintext)"),
    "imap":       ("medium",   60, "IMAP — mail access"),

    # Infrastructure
    "snmp":       ("high",     82, "SNMP — network device management, info leak"),
    "ntp":        ("medium",   45, "NTP — time sync"),
    "syslog":     ("high",     72, "Syslog — log aggregation"),

    # Default
    "unknown":    ("low",      30, "Unknown service"),
}

# High-value port → criticality override
_CRITICAL_PORTS = {
    22:    ("high",     75),
    23:    ("critical", 98),   # Telnet
    25:    ("high",     70),   # SMTP
    53:    ("critical", 90),   # DNS
    80:    ("medium",   50),
    88:    ("critical", 92),   # Kerberos
    135:   ("critical", 85),   # MSRPC
    139:   ("critical", 85),   # NetBIOS
    389:   ("critical", 88),   # LDAP
    443:   ("medium",   48),
    445:   ("critical", 90),   # SMB
    636:   ("critical", 88),   # LDAPS
    1433:  ("critical", 90),   # MSSQL
    1521:  ("critical", 92),   # Oracle
    2049:  ("high",     80),   # NFS
    3306:  ("critical", 88),   # MySQL
    3389:  ("critical", 92),   # RDP
    5432:  ("critical", 88),   # PostgreSQL
    5900:  ("critical", 90),   # VNC
    6379:  ("critical", 85),   # Redis
    8080:  ("medium",   52),
    27017: ("critical", 85),   # MongoDB
}


def score_asset(port: int, service: str, version: str = "",
                host_info: dict = None) -> dict:
    """
    Score a single service/port for asset criticality.
    Returns: {level, score, reasons, recommendations}
    """
    service_lower = service.lower() if service else "unknown"
    reasons = []

    # Start with service-based score
    svc_match = None
    for svc_key, (level, score, reason) in _SERVICE_CRITICALITY.items():
        if svc_key in service_lower:
            svc_match = (level, score, reason)
            break

    if not svc_match:
        svc_match = ("low", 30, "Unclassified service")

    level, score, reason = svc_match
    reasons.append(reason)

    # Port-based override if higher criticality
    if port in _CRITICAL_PORTS:
        port_level, port_score = _CRITICAL_PORTS[port]
        if port_score > score:
            score = port_score
            level = port_level
            reasons.append(f"Port {port} is a known high-value target")

    # Version risk bonus
    if version and _is_outdated_indicator(version):
        score = min(100, score + 10)
        reasons.append(f"Version {version} may be outdated")

    # Internet exposure penalty
    if host_info and _is_internet_exposed(host_info):
        score = min(100, score + 15)
        reasons.append("Service appears internet-exposed")

    # Normalize level based on final score
    if score >= 88:   level = "critical"
    elif score >= 70: level = "high"
    elif score >= 45: level = "medium"
    else:             level = "low"

    return {
        "level":           level,
        "score":           score,
        "service":         service,
        "port":            port,
        "reasons":         reasons,
        "recommendations": _get_recommendations(service_lower, level),
    }


def score_host(host: dict) -> dict:
    """
    Calculate overall asset criticality for a host (all ports combined).
    Returns: {overall_level, overall_score, port_scores, critical_services}
    """
    ports = host.get("ports", [])
    if not ports:
        return {"overall_level": "low", "overall_score": 0,
                "port_scores": [], "critical_services": []}

    port_scores = []
    for port_data in ports:
        port    = port_data.get("port", 0)
        service = port_data.get("service", {}).get("name", "unknown")
        version = port_data.get("service", {}).get("version", "")
        scored  = score_asset(port, service, version, host)
        port_scores.append(scored)

    # Overall = max score with weighted average bonus
    max_score  = max(p["score"] for p in port_scores)
    avg_score  = sum(p["score"] for p in port_scores) / len(port_scores)
    combined   = max_score * 0.7 + avg_score * 0.3

    if combined >= 85:   overall_level = "critical"
    elif combined >= 65: overall_level = "high"
    elif combined >= 40: overall_level = "medium"
    else:                overall_level = "low"

    critical_services = [p["service"] for p in port_scores if p["level"] in ("critical", "high")]

    return {
        "overall_level":    overall_level,
        "overall_score":    round(combined, 1),
        "port_count":       len(ports),
        "port_scores":      port_scores,
        "critical_services": list(set(critical_services)),
        "max_service_score": max_score,
    }


def _is_outdated_indicator(version: str) -> bool:
    """Simple heuristic: very old version numbers suggest outdated software."""
    old_patterns = ["1.", "2.0", "2.1", "2.2", "2.3", "2.4.0", "0.", "beta", "alpha"]
    v = version.lower()
    return any(p in v for p in old_patterns)


def _is_internet_exposed(host_info: dict) -> bool:
    """Check if host appears to be internet-facing."""
    ip = host_info.get("address", "") or host_info.get("ip", "")
    if not ip:
        return False
    # Private IP ranges are not internet-exposed
    private = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.2", "172.3", "127.", "::1", "fc", "fd")
    return not any(ip.startswith(p) for p in private)


def _get_recommendations(service: str, level: str) -> list:
    """Return quick-win recommendations for a service."""
    recs = {
        "rdp":    ["Place RDP behind VPN", "Enable NLA", "Use strong passwords"],
        "ssh":    ["Disable root login", "Use key auth", "Enable fail2ban"],
        "ftp":    ["Replace with SFTP", "Disable anonymous login"],
        "telnet": ["IMMEDIATELY disable Telnet — use SSH instead"],
        "smb":    ["Disable SMBv1", "Block port 445 externally", "Enable signing"],
        "redis":  ["Bind to localhost only", "Set requirepass", "Disable dangerous commands"],
        "mysql":  ["Bind to localhost", "Remove test database", "Audit user privileges"],
    }
    for key, r in recs.items():
        if key in service:
            return r
    if level == "critical":
        return ["Immediate review required", "Consider firewall restriction"]
    elif level == "high":
        return ["Review service exposure", "Apply latest patches"]
    return ["Keep up-to-date with patches"]
