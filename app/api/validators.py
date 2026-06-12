"""
Input validation — target and scan type sanitization.
Includes SSRF / private-range abuse protection.
"""
import re
import ipaddress

# All scan types available to users. Must stay in sync with orchestrator.SCAN_TEMPLATES.
ALLOWED_SCAN_TYPES = [
    # Discovery
    "ping_sweep", "host_discovery", "arp_discovery",
    # Port scanning
    "tcp_basic", "tcp_syn", "full_tcp", "udp_scan", "stealth_syn",
    # Enumeration
    "service_detect", "full_service_enum", "os_detect",
    "banner_grab", "version_deep", "port_range", "db_discovery",
    # Vulnerability assessment
    "vuln_scan", "smb_audit", "ftp_audit", "ssh_audit", "web_pentest",
    # Advanced pentesting
    "aggressive_pentest", "firewall_evasion", "frag_scan",
    "decoy_scan", "timing_manipulation", "ultimate_recon",
]

TARGET_PATTERN = re.compile(
    r'^((\d{1,3}\.){3}\d{1,3}'              # plain IPv4
    r'|localhost'                             # localhost
    r'|([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}'     # hostname
    r'|(\d{1,3}\.){3}\d{1,3}/\d{1,2})$'     # CIDR
)

# Matches "A.B.C,D" — common typo where last dot is typed as comma
_COMMA_FIX_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3}),(\d{1,3})$')

# Blocked SSRF ranges — loopback, link-local, metadata services, etc.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),         # "this" network
]

# Allowed scan CIDR ranges (configurable via settings.yaml or env).
# Empty list = allow any routable address.
# Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
_ALLOWED_SCAN_NETWORKS_RAW = []   # extend from settings if needed


def _is_blocked(ip_str: str) -> bool:
    """Return True if the IP is in a blocked (SSRF-risk) range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False  # hostname — can't do IP check; allowed by default

    # Block loopback etc.
    for net in _BLOCKED_NETWORKS:
        try:
            if addr in net:
                return True
        except TypeError:
            pass
    return False


def _extract_ip(target: str) -> str:
    """Extract the host part from a target (strips CIDR mask)."""
    return target.split("/")[0]


def validate_target(target: str) -> str:
    try:
        from fastapi import HTTPException
        Exc = HTTPException
    except ImportError:
        class Exc(Exception):
            def __init__(self, status_code=400, detail=""):
                super().__init__(detail)

    target = target.strip()
    if not target:
        raise Exc(status_code=400, detail="Target cannot be empty")
    if len(target) > 100:
        raise Exc(status_code=400, detail="Target too long")

    # ── Auto-correct comma-instead-of-dot typo ─────────────────
    # e.g. "10.83.113,112" → "10.83.113.112"
    m = _COMMA_FIX_PATTERN.match(target)
    if m:
        target = '.'.join(m.groups())

    if not TARGET_PATTERN.match(target):
        raise Exc(status_code=400,
                  detail="Invalid target. Use IP, hostname, or CIDR e.g. 192.168.1.0/24")

    # SSRF / localhost check
    host = _extract_ip(target)
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        raise Exc(status_code=400,
                  detail="Scanning localhost is not permitted.")
    if _is_blocked(host):
        raise Exc(status_code=400,
                  detail="Target is in a restricted address range (loopback/link-local). "
                         "Only routable LAN addresses are permitted.")

    return target


def validate_scan_type(scan_type: str) -> str:
    try:
        from fastapi import HTTPException
        Exc = HTTPException
    except ImportError:
        class Exc(Exception):
            def __init__(self, status_code=400, detail=""):
                super().__init__(detail)

    # Allow enum_scripts internally but not via public API
    all_types = ALLOWED_SCAN_TYPES + ["enum_scripts"]
    scan_type = scan_type.strip().lower()
    if scan_type not in all_types:
        raise Exc(status_code=400,
                  detail=f"Unknown scan type. Allowed: {', '.join(ALLOWED_SCAN_TYPES)}")
    return scan_type
