"""
ThreatWeave — Security Score Engine (Phase 8)
=============================================
Produces an overall Security Posture Score (0-100) like a credit score.
A=90+, B=75-89, C=60-74, D=45-59, F=<45

Dimensions:
  1. Vulnerability Density   (25%) — CVEs per open port
  2. Critical Exposure       (30%) — critical/high severity services exposed
  3. Patch Currency          (20%) — how outdated are running versions
  4. Attack Surface          (15%) — number of open ports
  5. Configuration Quality   (10%) — telnet/FTP/plaintext protocols present
"""
import logging

logger = logging.getLogger("ThreatWeave.security_score")

GRADE_THRESHOLDS = [(90, "A", "Excellent"),  (75, "B", "Good"),
                    (60, "C", "Fair"),        (45, "D", "Poor"), (0, "F", "Critical")]


def calculate_security_score(analysis: dict, parsed: dict = None) -> dict:
    """
    Calculate overall security posture score.
    analysis: risk/CVE analysis dict from ai_analysis
    parsed:   nmap parsed output dict
    Returns: {score, grade, dimensions, recommendations, summary}
    """
    parsed = parsed or {}
    hosts  = parsed.get("hosts", [])
    if not hosts and isinstance(parsed, dict):
        hosts = parsed.get("results", {}).get("hosts", []) or []

    all_ports = []
    for host in hosts:
        all_ports.extend(host.get("ports", []))

    total_ports = len(all_ports)
    cves        = _extract_cves(analysis)
    risk_hosts  = analysis.get("risk", {}).get("hosts", []) or []

    # Dimension 1: Vulnerability Density
    vuln_density_score = _vuln_density_score(len(cves), total_ports)

    # Dimension 2: Critical Exposure
    critical_score = _critical_exposure_score(all_ports, risk_hosts)

    # Dimension 3: Patch Currency
    patch_score = _patch_currency_score(cves)

    # Dimension 4: Attack Surface
    surface_score = _attack_surface_score(total_ports)

    # Dimension 5: Configuration Quality
    config_score = _config_quality_score(all_ports)

    # Weighted final score
    final = (
        vuln_density_score * 0.25 +
        critical_score     * 0.30 +
        patch_score        * 0.20 +
        surface_score      * 0.15 +
        config_score       * 0.10
    )
    final = round(max(0, min(100, final)), 1)

    grade, label = next(
        (g, l) for threshold, g, l in GRADE_THRESHOLDS if final >= threshold
    )

    dimensions = [
        {"name": "Vulnerability Density",  "weight": "25%", "score": round(vuln_density_score, 1),
         "detail": f"{len(cves)} CVEs across {total_ports} open ports"},
        {"name": "Critical Exposure",      "weight": "30%", "score": round(critical_score, 1),
         "detail": "Based on severity of exposed services"},
        {"name": "Patch Currency",         "weight": "20%", "score": round(patch_score, 1),
         "detail": "Based on version age of detected services"},
        {"name": "Attack Surface",         "weight": "15%", "score": round(surface_score, 1),
         "detail": f"{total_ports} open ports detected"},
        {"name": "Configuration Quality",  "weight": "10%", "score": round(config_score, 1),
         "detail": "Presence of insecure protocols (telnet, FTP)"},
    ]

    recommendations = _get_score_recommendations(final, all_ports, cves)

    return {
        "score":           final,
        "grade":           grade,
        "label":           label,
        "dimensions":      dimensions,
        "recommendations": recommendations,
        "summary":         f"Security Grade {grade} ({final}/100) — {label}. {recommendations[0] if recommendations else ''}",
        "cve_count":       len(cves),
        "open_ports":      total_ports,
    }


# ── Dimension scorers ─────────────────────────────────────────────────────────

def _vuln_density_score(cve_count: int, port_count: int) -> float:
    """Fewer CVEs per port = higher score."""
    if port_count == 0:
        return 100 if cve_count == 0 else 30
    density = cve_count / max(port_count, 1)
    if density == 0:   return 100
    if density < 0.5:  return 85
    if density < 1.0:  return 65
    if density < 2.0:  return 45
    if density < 4.0:  return 25
    return 10


def _critical_exposure_score(ports: list, risk_hosts: list) -> float:
    """Fewer critical/high services = higher score."""
    critical_count = 0
    high_count = 0
    for host in risk_hosts:
        for port in host.get("ports", []):
            level = port.get("risk", {}).get("level", "low").lower()
            if level == "critical": critical_count += 1
            elif level == "high":   high_count += 1

    if critical_count == 0 and high_count == 0: return 95
    if critical_count == 0:                      return max(50, 90 - high_count * 10)
    return max(5, 60 - critical_count * 15 - high_count * 5)


def _patch_currency_score(cves: list) -> float:
    """Fewer old CVEs = higher score."""
    if not cves: return 95
    critical_cves = sum(1 for c in cves if c.get("severity", "").lower() == "critical")
    high_cves     = sum(1 for c in cves if c.get("severity", "").lower() == "high")
    if critical_cves > 0: return max(10, 70 - critical_cves * 15)
    if high_cves > 0:     return max(25, 85 - high_cves * 10)
    return max(50, 95 - len(cves) * 5)


def _attack_surface_score(port_count: int) -> float:
    """Fewer open ports = smaller attack surface = higher score."""
    if port_count == 0:   return 100
    if port_count <= 3:   return 90
    if port_count <= 8:   return 75
    if port_count <= 15:  return 60
    if port_count <= 30:  return 45
    if port_count <= 50:  return 30
    return 15


def _config_quality_score(ports: list) -> float:
    """No insecure protocols = good config = higher score."""
    insecure = {"telnet", "rsh", "rexec", "rlogin", "ftp", "tftp", "rpc"}
    warnings = {"http", "snmp", "smtp"}
    penalty  = 0
    for port in ports:
        raw_svc = port.get("service", "")
        # service is stored as a plain string by the nmap parser
        svc = (raw_svc if isinstance(raw_svc, str) else raw_svc.get("name", "")).lower()
        if any(bad in svc for bad in insecure): penalty += 20
        elif any(warn in svc for warn in warnings): penalty += 5
    return max(0, 100 - penalty)


def _extract_cves(analysis: dict) -> list:
    cves = []
    if isinstance(analysis, dict):
        cves.extend(analysis.get("cves", []))
        for host in analysis.get("risk", {}).get("hosts", []) or []:
            for port in host.get("ports", []):
                cves.extend(port.get("cves", []))
    return cves


def _get_score_recommendations(score: float, ports: list, cves: list) -> list:
    recs = []
    insecure_svcs = []
    for p in ports:
        raw_svc = p.get("service", "")
        svc_name = (raw_svc if isinstance(raw_svc, str) else raw_svc.get("name", ""))
        if any(bad in svc_name.lower() for bad in ("telnet", "rsh", "ftp")):
            insecure_svcs.append(svc_name)
    if insecure_svcs:
        recs.append(f"Disable insecure protocols: {', '.join(set(insecure_svcs))}")
    critical_cves = [c for c in cves if c.get("severity", "").lower() == "critical"]
    if critical_cves:
        recs.append(f"Patch {len(critical_cves)} critical CVE(s) immediately")
    if score < 60:
        recs.append("Conduct full security audit and penetration test")
    if score >= 75:
        recs.append("Maintain current security posture with regular scans")
    return recs or ["Continue regular scanning and patching"]
