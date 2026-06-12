"""
Version Detection Engine
Classifies detected service versions as latest / outdated / unsupported.
"""

VERSION_DB = {
    "ssh": [
        ("OpenSSH 9.8",        "latest",      2024, None),
        ("OpenSSH 9.7",        "latest",      2024, None),
        ("OpenSSH 9.6",        "outdated",    2023, None),
        ("OpenSSH 9.0",        "outdated",    2022, None),
        ("OpenSSH 8.9",        "outdated",    2022, None),
        ("OpenSSH 8.0",        "outdated",    2019, None),
        ("OpenSSH 7.9",        "outdated",    2018, None),
        ("OpenSSH 7.4",        "outdated",    2016, None),
        ("OpenSSH 7.2",        "outdated",    2016, None),
        ("OpenSSH 6",          "unsupported", 2013, 2015),
        ("OpenSSH 5",          "unsupported", 2008, 2012),
    ],
    "http": [
        ("Apache httpd 2.4.62","latest",      2024, None),
        ("Apache httpd 2.4.60","outdated",    2024, None),
        ("Apache httpd 2.4.58","outdated",    2023, None),
        ("Apache httpd 2.4.51","outdated",    2021, None),
        ("Apache httpd 2.4.49","outdated",    2021, None),
        ("Apache httpd 2.4.29","outdated",    2017, None),
        ("Apache httpd 2.2.34","unsupported", 2017, 2018),
        ("Apache httpd 2.2",   "unsupported", 2005, 2018),
        ("Apache httpd 2.0",   "unsupported", 2002, 2013),
        ("nginx 1.26",         "latest",      2024, None),
        ("nginx 1.24",         "outdated",    2023, None),
        ("nginx 1.18",         "outdated",    2020, None),
        ("nginx 1.14",         "unsupported", 2018, 2020),
    ],
    "https": [
        ("Apache httpd 2.4.62","latest",      2024, None),
        ("Apache httpd 2.2.34","unsupported", 2017, 2018),
        ("nginx 1.26",         "latest",      2024, None),
        ("nginx 1.18",         "outdated",    2020, None),
    ],
    "ftp": [
        ("vsftpd 3.0.5",       "latest",      2021, None),
        ("vsftpd 3.0.3",       "outdated",    2015, None),
        ("vsftpd 2.3.5",       "outdated",    2011, None),
        ("vsftpd 2.3.4",       "unsupported", 2011, 2011),
        ("ProFTPD 1.3.8",      "latest",      2023, None),
        ("ProFTPD 1.3.5",      "outdated",    2014, None),
    ],
    "mysql": [
        ("MySQL 8.4",          "latest",      2024, None),
        ("MySQL 8.0",          "outdated",    2018, None),
        ("MySQL 5.7",          "outdated",    2015, 2023),
        ("MySQL 5.6",          "unsupported", 2013, 2021),
        ("MySQL 5.5",          "unsupported", 2010, 2018),
    ],
    "domain": [
        ("ISC BIND 9.18",      "latest",      2022, None),
        ("ISC BIND 9.16",      "outdated",    2020, None),
        ("ISC BIND 9.11",      "unsupported", 2016, 2022),
        ("ISC BIND 9.9.5",     "unsupported", 2013, 2018),
    ],
    "snmp": [
        ("net-snmp 5.9",       "latest",      2020, None),
        ("net-snmp 5.7",       "outdated",    2013, None),
        ("net-snmp 5.6",       "outdated",    2011, None),
        ("net-snmp 5.4",       "unsupported", 2007, 2013),
    ],
}


def analyze_versions(parsed: dict) -> dict:
    result = dict(parsed)
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            port["version_analysis"] = _analyze_port_version(port)
    return result


def _analyze_port_version(port: dict) -> dict:
    service     = port.get("service", "").lower()
    product     = port.get("product", "")
    version     = port.get("version", "")
    full_ver    = f"{product} {version}".strip()

    if not full_ver:
        return {
            "status":         "unknown",
            "version_string": "Not detected",
            "confidence":     "low",
            "message":        "No version information available. Run a version detection scan.",
        }

    for db_ver, status, rel_year, eol_year in VERSION_DB.get(service, []):
        if _matches(full_ver, db_ver):
            age = 2025 - rel_year
            return {
                "status":         status,
                "version_string": full_ver,
                "db_entry":       db_ver,
                "release_year":   rel_year,
                "eol_year":       eol_year,
                "age_years":      age,
                "confidence":     "high",
                "message":        _status_msg(status, full_ver, age, eol_year),
            }

    if VERSION_DB.get(service):
        return {
            "status":         "outdated",
            "version_string": full_ver,
            "confidence":     "medium",
            "message":        f"{full_ver} is not in the version database. Treat as potentially outdated.",
            "age_years":      None,
        }

    return {
        "status":         "unknown",
        "version_string": full_ver,
        "confidence":     "low",
        "message":        f"Service '{service}' is not in the version knowledge base.",
        "age_years":      None,
    }


def _matches(detected: str, db_entry: str) -> bool:
    """
    FIX5: Use semantic version comparison instead of naive string prefix matching.
    Old logic: "OpenSSH 9.10".startswith("OpenSSH 9.1") → True (WRONG)
    New logic: extract version tokens, compare as Version objects so 9.10 != 9.1.
    Falls back to string containment only when no numeric version is found.
    """
    import re as _re
    d  = detected.lower().strip()
    db = db_entry.lower().strip()

    # Extract the name prefix (non-numeric leading part) and version number
    def _split(s):
        m = _re.match(r'([^0-9]+)([0-9][\d.]*)', s)
        if m:
            return m.group(1).strip(), m.group(2).strip()
        return s.strip(), None

    d_name,  d_ver  = _split(d)
    db_name, db_ver = _split(db)

    # Names must roughly match
    if d_name not in db_name and db_name not in d_name:
        return False

    # If neither has a version number, fall back to name equality
    if d_ver is None and db_ver is None:
        return d_name == db_name

    # If only one has a version, loose containment
    if d_ver is None or db_ver is None:
        return db in d or d in db

    # FIX5: semantic comparison via packaging.version (safe, handles partial versions)
    # Rules:
    #   1. EXACT match always works: "9.10" == "9.10" ✅
    #   2. MAJOR.MINOR prefix: "2.2.34" matches DB entry "2.2" (EOL entry covers all 2.2.x) ✅
    #   3. PREVENTS false prefix: "9.10" must NOT match "9.1" ✅
    try:
        from packaging.version import Version as _V
        def _strip_suffix(v):
            # Strip trailing non-numeric suffixes like 'p1', 'b2', 'rc1'
            import re as _r
            return _r.sub(r'[a-zA-Z].*$', '', v)

        def _safe_ver(v):
            # Pad partial versions: "9.1" -> "9.1.0" so comparison works correctly
            parts = _strip_suffix(v).split(".")
            while len(parts) < 3:
                parts.append("0")
            return _V(".".join(parts))

        dv  = _strip_suffix(d_ver)
        dbv = _strip_suffix(db_ver)

        # Case A: exact semantic version match (e.g. "9.10" == "9.10")
        if _safe_ver(dv) == _safe_ver(dbv):
            return True

        # Case B: DB entry is a major.minor prefix (e.g. "2.2") covering all 2.2.x releases
        # Only valid when db_ver has FEWER dot-segments than d_ver
        db_parts = dbv.split(".")
        d_parts  = dv.split(".")
        if len(db_parts) < len(d_parts):
            # Check detected version STARTS WITH the db prefix at each segment level
            # e.g. "2.2.34" starts with "2.2" → True
            # but "9.10" does NOT start with "9.1" because segment [1] is "10" != "1"
            if d_parts[:len(db_parts)] == db_parts:
                return True

        return False
    except Exception:
        # packaging not available — fall back to exact token match
        return d_ver == db_ver


def _status_msg(status: str, version: str, age: int, eol_year) -> str:
    if status == "latest":
        return f"{version} is up to date."
    if status == "outdated":
        return f"{version} is outdated ({age} years old). Upgrade recommended."
    if status == "unsupported":
        eol = f" (EOL: {eol_year})" if eol_year else ""
        return f"{version} is end-of-life{eol}. No longer receives security patches. Replace immediately."
    return f"{version}: status unknown."

# Expose for testing
_version_matches = _matches
_analyze_port_version = _analyze_port_version  # already public
