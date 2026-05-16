"""
Explanation Layer
Generates plain-English, defensive-only explanations of scan findings.
No exploit instructions. Guidance is purely defensive.
"""

SERVICE_GUIDANCE = {
    "ssh": [
        "Disable root SSH login (set PermitRootLogin no in sshd_config).",
        "Use SSH key-based authentication instead of passwords.",
        "Restrict SSH access by IP using AllowUsers or firewall rules.",
    ],
    "ftp": [
        "Replace FTP with SFTP or SCP — FTP transmits credentials in plaintext.",
        "If FTP is required, restrict access to known IP ranges.",
        "Disable anonymous FTP login.",
    ],
    "http": [
        "Redirect all HTTP traffic to HTTPS.",
        "Review the web application for OWASP Top 10 vulnerabilities.",
        "Remove server version banners from HTTP response headers.",
    ],
    "https": [
        "Enforce TLS 1.2 or 1.3. Disable SSLv3, TLS 1.0, TLS 1.1.",
        "Check SSL certificate validity and renewal schedule.",
        "Enable HSTS (HTTP Strict Transport Security).",
    ],
    "mysql": [
        "Bind MySQL to localhost or internal IP only (not 0.0.0.0).",
        "Disable remote root login. Use application-specific DB accounts.",
        "Enable MySQL audit logging.",
    ],
    "smb": [
        "Disable SMBv1 immediately — it is exploited by ransomware like WannaCry.",
        "Block port 445 from external access at the firewall.",
        "Require SMB signing to prevent relay attacks.",
    ],
    "rdp": [
        "Place RDP behind a VPN — never expose directly to the internet.",
        "Enable Network Level Authentication (NLA).",
        "Use a non-standard port and restrict by IP at the firewall.",
    ],
    "snmp": [
        "Upgrade from SNMPv1/v2c (community strings) to SNMPv3 with authentication.",
        "Restrict SNMP access to monitoring systems only.",
        "Disable SNMP if not actively used.",
    ],
    "telnet": [
        "Disable Telnet immediately — it transmits all data including passwords in plaintext.",
        "Replace with SSH.",
    ],
    "domain": [
        "Restrict DNS zone transfers to authorised secondary servers only.",
        "Enable DNSSEC for DNS integrity.",
        "Rate-limit DNS queries to mitigate amplification attacks.",
    ],
    "ftp": [
        "Replace FTP with SFTP. FTP credentials are sent in plaintext.",
        "If FTP must run, restrict to a specific IP range.",
    ],
}

DB_PORTS = {3306, 5432, 27017, 6379, 1521, 1433}


def generate_explanation(risk_data: dict, recommendation: dict) -> dict:
    hosts = risk_data.get("hosts", [])
    if not hosts:
        return {
            "summary":            "No live hosts found in scan results.",
            "findings":           [],
            "defensive_guidance": ["Verify the target is reachable and online."],
            "next_step":          recommendation.get("reason", ""),
            "next_scan":          recommendation.get("title", ""),
        }

    all_findings   = []
    all_guidance   = []
    guidance_seen  = set()
    critical_count = 0
    high_count     = 0

    for host in hosts:
        for port in host.get("ports", []):
            finding = _explain_port(host.get("ip", "?"), port)
            all_findings.append(finding)
            for g in finding.get("guidance", []):
                if g not in guidance_seen:
                    guidance_seen.add(g)
                    all_guidance.append(g)
            level = port.get("risk", {}).get("level", "low")
            if level == "critical":
                critical_count += 1
            elif level == "high":
                high_count += 1

    return {
        "summary":            _build_summary(hosts, critical_count, high_count),
        "findings":           all_findings,
        "defensive_guidance": all_guidance,
        "next_step":          recommendation.get("reason", ""),
        "next_scan":          recommendation.get("title", ""),
    }


def _explain_port(ip: str, port: dict) -> dict:
    port_num  = port.get("port")
    protocol  = port.get("protocol", "tcp")
    service   = port.get("service", "unknown")
    product   = port.get("product", "")
    version   = port.get("version", "")
    cves      = port.get("cves", [])
    risk      = port.get("risk", {})
    va        = port.get("version_analysis", {})
    context   = port.get("context", {})

    full_ver   = f"{product} {version}".strip() or "unknown version"
    risk_level = risk.get("level", "low")
    v_status   = va.get("status", "unknown")

    # What was found
    what = f"Port {port_num}/{protocol} is open running {service.upper()}"
    if full_ver != "unknown version":
        what += f" ({full_ver})"

    # Why it matters
    why = context.get("criticality_reason", f"{service} service is accessible.")

    # Version narrative
    if v_status == "latest":
        version_note = f"{full_ver} is up to date."
    elif v_status == "outdated":
        age = va.get("age_years")
        version_note = (f"{full_ver} is outdated"
                        + (f" ({age} years old)" if age else "")
                        + ". Upgrade recommended.")
    elif v_status == "unsupported":
        version_note = (f"{full_ver} is end-of-life and no longer receives "
                        f"security patches. Replace immediately.")
    else:
        version_note = "Version not detected. Run a version detection scan for accurate CVE mapping."

    # CVE summary (top 3, description only — no exploit steps)
    top_cves = []
    for cve in cves[:3]:
        top_cves.append(
            f"{cve['cve_id']} (CVSS {cve['cvss_score']}, {cve['severity'].upper()}): "
            f"{cve['description']}"
        )

    # Risk explanation
    reasons = risk.get("reasons", ["No specific risk factors identified."])
    risk_explanation = (f"Risk classified as {risk_level.upper()} "
                        f"(score {risk.get('score', 0)}/10). "
                        + " ".join(reasons))

    # Defensive guidance
    guidance = _build_guidance(service, v_status, cves, port_num)

    return {
        "port":             port_num,
        "service":          service,
        "version":          full_ver,
        "risk_level":       risk_level,
        "what_was_found":   what,
        "why_it_matters":   why,
        "version_status":   version_note,
        "cve_count":        len(cves),
        "top_cves":         top_cves,
        "risk_explanation": risk_explanation,
        "guidance":         guidance,
    }


def _build_guidance(service: str, v_status: str, cves: list, port_num: int) -> list:
    guidance = []

    if v_status in ("outdated", "unsupported"):
        guidance.append(f"Upgrade {service.upper()} to the latest stable version immediately.")

    for tip in SERVICE_GUIDANCE.get(service, []):
        guidance.append(tip)

    for cve in cves[:2]:
        if cve.get("patch"):
            guidance.append(f"Patch: {cve['patch']}")

    if port_num in DB_PORTS:
        guidance.append(
            f"Port {port_num} should not be publicly accessible. "
            f"Restrict via firewall to authorised hosts only."
        )

    # Deduplicate preserving order
    seen = set()
    deduped = []
    for g in guidance:
        if g not in seen:
            seen.add(g)
            deduped.append(g)
    return deduped


def _build_summary(hosts: list, critical: int, high: int) -> str:
    host_count  = len(hosts)
    total_ports = sum(len(h.get("ports", [])) for h in hosts)
    parts = [f"Scan complete. Found {host_count} live host(s) with {total_ports} open port(s)."]
    if critical > 0:
        parts.append(f"{critical} CRITICAL finding(s) — immediate action required.")
    if high > 0:
        parts.append(f"{high} HIGH finding(s) — remediation strongly recommended.")
    if critical == 0 and high == 0:
        parts.append("No critical or high-severity findings in this scan.")
    return " ".join(parts)
