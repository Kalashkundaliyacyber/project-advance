"""
app/multi_scan/parser.py
Parse and validate a plain-text file of scan targets.
One target per line — IP address or hostname.
"""
import re
import ipaddress

# Max targets allowed per file
MAX_TARGETS = 100
MAX_FILE_BYTES = 50_000  # 50 KB

_HOSTNAME_RE = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

_COMMA_FIX = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3}),(\d{1,3})$')

# Ranges that are not routable / SSRF risks
_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_blocked_ip(s: str) -> bool:
    try:
        addr = ipaddress.ip_address(s)
        return any(addr in net for net in _BLOCKED_NETS)
    except ValueError:
        return False


def _fix_comma(s: str) -> str:
    """Auto-correct '10.0.0,1' → '10.0.0.1'."""
    m = _COMMA_FIX.match(s)
    return '.'.join(m.groups()) if m else s


def _is_valid_hostname(s: str) -> bool:
    if len(s) > 253:
        return False
    if s.lower() in ("localhost",):
        return False
    return bool(_HOSTNAME_RE.match(s))


def parse_targets_txt(content: str) -> dict:
    """
    Parse newline-separated targets from a .txt file body.

    Returns:
        {
          "valid":   ["192.168.1.1", "10.0.0.5", ...],
          "invalid": [{"line": 3, "raw": "abc", "reason": "..."}],
          "skipped": 0,   # blank lines
          "total":   N
        }
    """
    if len(content.encode()) > MAX_FILE_BYTES:
        raise ValueError(f"File too large (max {MAX_FILE_BYTES // 1024} KB).")

    valid:   list[str]  = []
    invalid: list[dict] = []
    skipped = 0

    for lineno, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()

        if not line or line.startswith('#'):
            skipped += 1
            continue

        line = _fix_comma(line)

        if _is_valid_ip(line):
            if _is_blocked_ip(line):
                invalid.append({"line": lineno, "raw": raw_line.strip(),
                                 "reason": "blocked address range"})
            elif line in valid:
                invalid.append({"line": lineno, "raw": raw_line.strip(),
                                 "reason": "duplicate"})
            else:
                valid.append(line)

        elif _is_valid_hostname(line):
            if line in valid:
                invalid.append({"line": lineno, "raw": raw_line.strip(),
                                 "reason": "duplicate"})
            else:
                valid.append(line)

        else:
            invalid.append({"line": lineno, "raw": raw_line.strip(),
                             "reason": "invalid IP or hostname format"})

        if len(valid) >= MAX_TARGETS:
            # Stop accepting more after limit
            remaining = len(content.splitlines()) - lineno
            if remaining > 0:
                invalid.append({
                    "line": lineno + 1,
                    "raw":  f"(+{remaining} more lines truncated)",
                    "reason": f"max {MAX_TARGETS} targets per scan",
                })
            break

    return {
        "valid":   valid,
        "invalid": invalid,
        "skipped": skipped,
        "total":   len(valid) + len(invalid),
    }
