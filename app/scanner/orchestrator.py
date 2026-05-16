"""
Command Orchestrator
Maps scan_type string to a fixed, safe nmap argument list.
No shell injection possible. No arbitrary commands allowed.

Scan profiles follow professional pentesting standards.
Critical: Full scans (-p-) scan ALL 65535 ports.
"""

# ─────────────────────────────────────────────────────────────
#  SCAN PROFILE REGISTRY
# ─────────────────────────────────────────────────────────────

SCAN_TEMPLATES = {

    # ── DISCOVERY ────────────────────────────────────────────

    "ping_sweep": {
        "name":           "Ping Sweep",
        "description":    "Discovers live hosts on a network using ICMP echo requests.",
        "category":       "discovery",
        "args":           ["-sn", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "safe",
        "estimated_time": "~15s",
        "tags":           ["discovery", "hosts", "ping"],
        "recommended":    False,
        "advanced":       False,
    },

    "host_discovery": {
        "name":           "Host Discovery",
        "description":    "Multi-method host discovery without port scanning.",
        "category":       "discovery",
        "args":           ["-sn", "-PE", "-PS22,80,443", "-PA80", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "safe",
        "estimated_time": "~20s",
        "tags":           ["discovery", "hosts"],
        "recommended":    False,
        "advanced":       False,
    },

    "arp_discovery": {
        "name":           "ARP Discovery",
        "description":    "Local network ARP-based host discovery (LAN only).",
        "category":       "discovery",
        "args":           ["-sn", "-PR", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "safe",
        "estimated_time": "~10s",
        "tags":           ["discovery", "arp", "lan"],
        "recommended":    False,
        "advanced":       False,
    },

    # ── PORT SCANNING ─────────────────────────────────────────

    "tcp_basic": {
        "name":           "Quick TCP Scan",
        "description":    "Fast discovery of the top 1000 common TCP ports. Best for initial recon.",
        "category":       "port_scanning",
        "args":           ["-sS", "-T4", "--top-ports", "1000", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "moderate",
        "estimated_time": "~30s",
        "tags":           ["tcp", "quick", "recon"],
        "recommended":    True,
        "advanced":       False,
    },

    "full_tcp": {
        "name":           "Full TCP Scan",
        "description":    "Scans ALL 65535 TCP ports. Finds hidden services, admin panels, backdoors.",
        "category":       "port_scanning",
        "args":           ["-p-", "-sS", "-T4", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~5-15m",
        "tags":           ["tcp", "full", "all-ports", "p-"],
        "recommended":    True,
        "advanced":       False,
    },

    "udp_scan": {
        "name":           "Full UDP Scan",
        "description":    "Scans UDP ports. Detects DNS, SNMP, NTP, TFTP, VPN services. Slow but essential.",
        "category":       "port_scanning",
        "args":           ["-sU", "-p-", "--max-retries", "2", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~30-60m",
        "tags":           ["udp", "full", "dns", "snmp", "ntp"],
        "recommended":    True,
        "advanced":       False,
    },

    "stealth_syn": {
        "name":           "Stealth SYN Scan",
        "description":    "Low-speed stealthy SYN scan to evade basic IDS/firewall detection.",
        "category":       "port_scanning",
        "args":           ["-sS", "-Pn", "-T2", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "moderate",
        "estimated_time": "~3-5m",
        "tags":           ["stealth", "syn", "evasion"],
        "recommended":    True,
        "advanced":       False,
    },

    # ── ENUMERATION ───────────────────────────────────────────

    "service_detect": {
        "name":           "Service Detection",
        "description":    "Identifies services and versions on open TCP ports.",
        "category":       "enumeration",
        "args":           ["-sT", "-sV", "-T3", "--open", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~45s",
        "tags":           ["service", "version", "banner"],
        "recommended":    True,
        "advanced":       False,
    },

    "full_service_enum": {
        "name":           "Full Service Enumeration",
        "description":    "Scans ALL ports and detects service versions, banners, daemon info.",
        "category":       "enumeration",
        "args":           ["-p-", "-sV", "-sS", "-T4", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~15-30m",
        "tags":           ["service", "version", "full", "p-"],
        "recommended":    False,
        "advanced":       False,
    },

    "os_detect": {
        "name":           "OS Fingerprinting",
        "description":    "Identifies the target operating system via TCP/IP stack fingerprinting.",
        "category":       "enumeration",
        "args":           ["-O", "--osscan-guess", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "moderate",
        "estimated_time": "~60s",
        "tags":           ["os", "fingerprint"],
        "recommended":    False,
        "advanced":       False,
    },

    "banner_grab": {
        "name":           "Banner Grabbing",
        "description":    "Grabs service banners from open ports for technology identification.",
        "category":       "enumeration",
        "args":           ["-sT", "-sV", "--version-intensity", "5", "-T3", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~45s",
        "tags":           ["banner", "service", "version"],
        "recommended":    False,
        "advanced":       False,
    },

    "enum_scripts": {
        "name":           "Default Script Scan",
        "description":    "Runs safe NSE default scripts for service enumeration.",
        "category":       "enumeration",
        "args":           ["-sC", "-sV", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~90s",
        "tags":           ["scripts", "nse", "safe", "enum"],
        "recommended":    False,
        "advanced":       False,
    },

    # ── VULNERABILITY ASSESSMENT ──────────────────────────────

    "vuln_scan": {
        "name":           "Vulnerability Scan",
        "description":    "NSE vuln scripts across ALL ports. Detects known CVEs, weak services, misconfigs.",
        "category":       "vuln_assessment",
        "args":           ["--script", "vuln", "-sV", "-p-", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~20-40m",
        "tags":           ["vuln", "cve", "nse", "p-"],
        "recommended":    True,
        "advanced":       False,
    },

    "smb_audit": {
        "name":           "SMB Security Audit",
        "description":    "Enumerates SMB shares and users. Essential for Windows pentesting.",
        "category":       "vuln_assessment",
        "args":           ["--script", "smb-enum-shares,smb-enum-users", "-p", "445", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~30s",
        "tags":           ["smb", "windows", "enum", "shares"],
        "recommended":    False,
        "advanced":       False,
    },

    "ftp_audit": {
        "name":           "FTP Security Audit",
        "description":    "Checks for anonymous FTP login and vsftpd backdoor vulnerability.",
        "category":       "vuln_assessment",
        "args":           ["--script", "ftp-anon,ftp-vsftpd-backdoor", "-p", "21", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~20s",
        "tags":           ["ftp", "anonymous", "backdoor"],
        "recommended":    False,
        "advanced":       False,
    },

    "ssh_audit": {
        "name":           "SSH Security Audit",
        "description":    "Enumerates SSH auth methods and supported algorithms.",
        "category":       "vuln_assessment",
        "args":           ["--script", "ssh-auth-methods,ssh2-enum-algos", "-p", "22", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~20s",
        "tags":           ["ssh", "auth", "algorithms"],
        "recommended":    False,
        "advanced":       False,
    },

    "web_pentest": {
        "name":           "Web Pentest Scan",
        "description":    "Scans web ports and runs HTTP scripts to find admin panels, headers, directories.",
        "category":       "vuln_assessment",
        "args":           ["-p", "80,443,8080,8000,8443",
                           "--script", "http-enum,http-title,http-headers",
                           "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~60s",
        "tags":           ["web", "http", "https", "admin", "directories"],
        "recommended":    True,
        "advanced":       False,
    },

    # ── ADVANCED PENTESTING ───────────────────────────────────

    "aggressive_pentest": {
        "name":           "Aggressive Pentest",
        "description":    "Full OS+version detection, traceroute, NSE scripts across ALL ports.",
        "category":       "advanced",
        "args":           ["-A", "-p-", "-T4", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "very_noisy",
        "estimated_time": "~20-45m",
        "tags":           ["aggressive", "os", "version", "scripts", "traceroute", "p-"],
        "recommended":    False,
        "advanced":       True,
    },

    "firewall_evasion": {
        "name":           "Firewall Evasion Scan",
        "description":    "ACK scan to map firewall rules and detect filtered ports.",
        "category":       "advanced",
        "args":           ["-sA", "-T2", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~3-5m",
        "tags":           ["firewall", "evasion", "ack", "rules"],
        "recommended":    False,
        "advanced":       True,
    },

    "frag_scan": {
        "name":           "Fragmented Packets Scan",
        "description":    "Uses IP fragmentation to evade packet-filter firewalls and IDS.",
        "category":       "advanced",
        "args":           ["-sS", "-f", "-T3", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~2-5m",
        "tags":           ["fragmentation", "evasion", "firewall"],
        "recommended":    False,
        "advanced":       True,
    },

    "decoy_scan": {
        "name":           "Decoy Scan",
        "description":    "Masks the real source IP using random decoys. Advanced evasion.",
        "category":       "advanced",
        "args":           ["-sS", "-D", "RND:5", "-T3", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "aggressive",
        "estimated_time": "~2-4m",
        "tags":           ["decoy", "evasion", "stealth"],
        "recommended":    False,
        "advanced":       True,
    },

    "timing_manipulation": {
        "name":           "Timing Manipulation",
        "description":    "Paranoid-speed scan (T1) to evade time-based IDS detection.",
        "category":       "advanced",
        "args":           ["-sS", "-T1", "--top-ports", "100", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "moderate",
        "estimated_time": "~10-20m",
        "tags":           ["timing", "evasion", "paranoid"],
        "recommended":    False,
        "advanced":       True,
    },

    "ultimate_recon": {
        "name":           "Ultimate Recon",
        "description":    "Full professional recon: ALL ports, OS+version, scripts, vuln scan. Very slow and noisy.",
        "category":       "advanced",
        "args":           ["-p-", "-A", "-sV", "-O", "-sC", "--script", "vuln", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "very_noisy",
        "estimated_time": "~45-120m",
        "tags":           ["ultimate", "full", "os", "version", "vuln", "scripts", "p-"],
        "recommended":    True,
        "advanced":       True,
    },

    # ── LEGACY ALIASES (backward compatibility) ───────────────

    "tcp_syn": {
        "name":           "TCP SYN Scan",
        "description":    "Classic SYN scan of top 1000 ports.",
        "category":       "port_scanning",
        "args":           ["-sS", "-T3", "--open", "-oX", "-"],
        "requires_root":  True,
        "risk_level":     "moderate",
        "estimated_time": "~30s",
        "tags":           ["tcp", "syn"],
        "recommended":    False,
        "advanced":       False,
    },

    "version_deep": {
        "name":           "Deep Version Detection",
        "description":    "Aggressively fingerprints exact service versions at intensity 9.",
        "category":       "enumeration",
        "args":           ["-sT", "-sV", "--version-intensity", "9", "-T3", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "aggressive",
        "estimated_time": "~90s",
        "tags":           ["version", "deep", "fingerprint"],
        "recommended":    False,
        "advanced":       False,
    },

    "port_range": {
        "name":           "Port Range 1-1024",
        "description":    "Scans well-known ports 1 through 1024.",
        "category":       "port_scanning",
        "args":           ["-sT", "-p", "1-1024", "-T3", "--open", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~40s",
        "tags":           ["tcp", "well-known"],
        "recommended":    False,
        "advanced":       False,
    },

    "db_discovery": {
        "name":           "Database Discovery",
        "description":    "Scans common database ports: MSSQL, MySQL, PostgreSQL, MongoDB, Redis.",
        "category":       "enumeration",
        "args":           ["-p", "1433,3306,5432,27017,6379", "-sV", "-oX", "-"],
        "requires_root":  False,
        "risk_level":     "moderate",
        "estimated_time": "~30s",
        "tags":           ["database", "mysql", "postgres", "mssql", "redis", "mongo"],
        "recommended":    False,
        "advanced":       False,
    },
}


def get_scan_command(scan_type: str, target: str) -> list:
    """Return full nmap command as a safe list. Target is always last."""
    if scan_type not in SCAN_TEMPLATES:
        raise ValueError(
            f"Unknown scan type: '{scan_type}'. "
            f"Valid types: {', '.join(sorted(SCAN_TEMPLATES.keys()))}"
        )
    return ["nmap"] + SCAN_TEMPLATES[scan_type]["args"] + [target]


def get_scan_info(scan_type: str) -> dict:
    """Return the profile dict for a given scan type, or None."""
    return SCAN_TEMPLATES.get(scan_type)


def list_scan_types() -> list:
    """Return all available scan type keys."""
    return list(SCAN_TEMPLATES.keys())


def get_full_port_scan_types() -> list:
    """Return scan types that use -p- (all 65535 ports)."""
    return [k for k, v in SCAN_TEMPLATES.items() if "-p-" in v["args"]]
