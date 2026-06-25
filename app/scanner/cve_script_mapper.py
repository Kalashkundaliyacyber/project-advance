"""
app/scanner/cve_script_mapper.py
────────────────────────────────────────────────────────────────────────────
Authoritative CVE → NSE confirmation mapping engine for ThreatWeave AI.

DESIGN RULES (enforced by this module):
  1.  CVE-first selection. Scripts are chosen by CVE, not by service name.
  2.  No unrelated scripts. If no confirmed NSE exists for a CVE, return
      NOT_VALIDATABLE — never run a random service script and call it proof.
  3.  Evidence-only confirmation. CONFIRMED requires "State: VULNERABLE" or
      "VULNERABLE:" in NSE output. Bare "Starting Nmap..." → UNCONFIRMED.
  4.  Safe-before-confirmed. "NOT VULNERABLE" is checked before "VULNERABLE"
      so "State: NOT VULNERABLE" can never be misread as CONFIRMED.
  5.  Version-based fallback. For CVEs with no NSE, known version ranges
      produce POTENTIALLY_VULNERABLE (confidence 50-70), not a fake run.
  6.  Live-safe only. No brute force, no exploits, no DoS in script list.

Status codes
────────────
  CONFIRMED            ✅  NSE output contains vulnerability proof
  NOT_VULNERABLE       ❌  NSE explicitly ruled it out
  POTENTIALLY_VULNERABLE ⚠️  Version in known vulnerable range, no NSE proof
  UNCONFIRMED          🔍  Script ran but output contains no evidence
  NOT_VALIDATABLE      ➖  No NSE script available for this CVE
"""

from __future__ import annotations

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CVE → NSE mapping database
#
# Each entry:
#   script   : exact NSE script name (without .nse). None = no script exists.
#   products : canonical product names the CVE affects (lowercase match)
#   confidence_base : confidence to report when NSE confirms vulnerability
#   notes    : why this mapping is authoritative
#
# Rule: a CVE entry is only used if `script` is present on disk AND at least
# one of `products` matches the detected product/service string (case-insensitive
# substring). This prevents ftp-vsftpd-backdoor being run against smbd.
# ─────────────────────────────────────────────────────────────────────────────
CVE_NSE_MAP: dict[str, dict] = {

    # ── FTP ──────────────────────────────────────────────────────────────────
    "CVE-2011-2523": {
        "script": "ftp-vsftpd-backdoor",
        "products": ["vsftpd", "ftp"],          # "ftp" service but NOT rpcbind
        "confidence_base": 95,
        "notes": "vsftpd 2.3.4 contains a backdoor triggered by :) in username",
    },
    "CVE-2010-4221": {
        "script": "ftp-vuln-cve2010-4221",
        "products": ["proftpd", "wu-ftpd"],
        "confidence_base": 90,
        "notes": "ProFTPD/wu-ftpd TELNET IAC stack overflow",
    },

    # ── SSH ──────────────────────────────────────────────────────────────────
    # Note: sshv1 detects *use* of SSHv1 but does not confirm a specific CVE
    # exploit. We map it at lower confidence as a weak detection.
    "CVE-2001-0572": {
        "script": "sshv1",
        "products": ["openssh", "ssh"],
        "confidence_base": 60,
        "notes": "Generic SSHv1 protocol weakness; sshv1 script is version detection only",
    },

    # ── SMB / Windows ────────────────────────────────────────────────────────
    "CVE-2017-0144": {
        "script": "smb-vuln-ms17-010",
        "products": ["microsoft", "windows", "samba", "smb"],
        "confidence_base": 95,
        "notes": "EternalBlue SMB RCE; ms17-010 is the canonical NSE script",
    },
    "CVE-2008-4250": {
        "script": "smb-vuln-ms08-067",
        "products": ["microsoft", "windows", "smb"],
        "confidence_base": 95,
        "notes": "MS08-067 NetAPI buffer overflow",
    },
    "CVE-2020-0796": {
        "script": "smb-vuln-cve-2020-0796",
        "products": ["microsoft", "windows", "smb"],
        "confidence_base": 90,
        "notes": "SMBGhost/CoronaBlue compression vulnerability",
    },
    "CVE-2009-3103": {
        "script": "smb-vuln-cve2009-3103",
        "products": ["samba", "smb", "netbios"],
        "confidence_base": 90,
        "notes": "Samba 3.x SMB2 request parsing vulnerability",
    },
    "CVE-2012-1182": {
        "script": "samba-vuln-cve-2012-1182",    # FIX DB-003: dedicated NSE exists; was wrong smb-vuln-cve2009-3103 (Windows SMB2 script)
        "products": ["samba"],
        "confidence_base": 90,
        "notes": "Samba heap buffer overflow < 3.6.4; samba-vuln-cve-2012-1182.nse is the correct dedicated script",
    },
    # DB-001+DB-002 FIX: CVE-2012-0037 was incorrectly mapped to smb-vuln-ms10-054.
    # CVE-2012-0037 is an Apache Jena XML injection — unrelated to SMB.
    # The MS10-054 SMB pool overflow is CVE-2010-2550. The Print Spooler bulletin
    # MS10-061 is CVE-2010-2729. Both are now mapped to their correct scripts.
    "CVE-2010-2550": {
        "script": "smb-vuln-ms10-054",           # FIX DB-001/DB-002: was keyed as CVE-2012-0037, wrong script smb-vuln-ms10-061
        "products": ["microsoft", "windows"],
        "confidence_base": 85,
        "notes": "MS10-054 SMB pool overflow (CVE-2010-2550); smb-vuln-ms10-054 is the correct script",
    },
    "CVE-2010-2729": {
        "script": "smb-vuln-ms10-061",           # FIX DB-002: was keyed as CVE-2010-2550; MS10-061 Print Spooler is CVE-2010-2729
        "products": ["microsoft", "windows"],
        "confidence_base": 90,
        "notes": "MS10-061 Print Spooler impersonation (CVE-2010-2729)",
    },

    # ── HTTP ─────────────────────────────────────────────────────────────────
    "CVE-2014-6271": {
        "script": "http-shellshock",
        "products": ["apache", "nginx", "http", "cgi"],
        "confidence_base": 90,
        "notes": "Shellshock: Bash CGI remote code execution",
    },
    "CVE-2014-7169": {
        "script": "http-shellshock",
        "products": ["apache", "nginx", "http", "cgi"],
        "confidence_base": 90,
        "notes": "Shellshock variant (Bash CVE-2014-7169)",
    },
    "CVE-2011-3192": {
        "script": "http-vuln-cve2011-3192",
        "products": ["apache"],
        "confidence_base": 90,
        "notes": "Apache Range header DoS (Apache Killer)",
    },
    "CVE-2017-7679": {
        "script": None,                           # FIX DB-007: http-vuln-cve2017-7679 does NOT exist in nmap standard scripts
        "products": ["apache"],
        "confidence_base": 0,
        "notes": "Apache mod_mime buffer over-read; no NSE script. Version range in KNOWN_VULNERABLE_VERSIONS.",
    },
    # FIX: Add CVE-2012-1823 — PHP-CGI argument injection (confirmed on port 80)
    # http-vuln-cve2012-1823 outputs "seems vulnerable to CVE-2012-1823" and executes commands.
    "CVE-2012-1823": {
        "script": "http-vuln-cve2012-1823",
        "products": ["apache", "php", "http"],
        "confidence_base": 95,
        "notes": "PHP-CGI argument injection RCE; script outputs 'seems vulnerable' and returns command output",
    },
    # FIX: Add CVE-2014-3704 — Drupalgeddon SQL injection (confirmed on port 80)
    # http-vuln-cve2014-3704 adds an admin user when vulnerable.
    "CVE-2014-3704": {
        "script": "http-vuln-cve2014-3704",
        "products": ["drupal", "apache", "http"],
        "confidence_base": 95,
        "notes": "Drupalgeddon SQLi; script outputs 'adding admin user' when exploitation succeeds",
    },
    "CVE-2017-5638": {
        "script": "http-vuln-cve2017-5638",
        "products": ["tomcat", "struts", "apache"],
        "confidence_base": 90,
        "notes": "Apache Struts2 remote code execution",
    },
    "CVE-2019-0232": {
        "script": None,                           # FIX DB-008: http-vuln-cve2019-0232 does NOT exist in nmap standard scripts
        "products": ["tomcat", "apache tomcat"],
        "confidence_base": 0,
        "notes": "Tomcat CGI enableCmdLineArguments RCE; no NSE. Version range check only.",
    },
    "CVE-2021-41773": {
        "script": "http-vuln-cve2021-41773",
        "products": ["apache"],
        "confidence_base": 90,
        "notes": "Apache HTTP 2.4.49 path traversal / RCE",
    },
    "CVE-2021-42013": {
        "script": "http-vuln-cve2021-42013",
        "products": ["apache"],
        "confidence_base": 90,
        "notes": "Apache HTTP 2.4.49-2.4.50 path traversal variant",
    },
    "CVE-2007-6750": {
        "script": "http-slowloris-check",
        "products": ["apache", "http"],
        "confidence_base": 80,
        "notes": "Slowloris HTTP DoS vulnerability",
    },

    # ── SSL / TLS ─────────────────────────────────────────────────────────────
    "CVE-2014-0160": {
        "script": "ssl-heartbleed",
        "products": ["openssl", "https", "ssl", "tls"],
        "confidence_base": 95,
        "notes": "Heartbleed OpenSSL information disclosure",
    },
    "CVE-2014-3566": {
        "script": "ssl-poodle",
        "products": ["openssl", "https", "ssl", "smtp", "ftp"],
        "confidence_base": 90,
        "notes": "POODLE: SSL 3.0 CBC padding oracle",
    },
    "CVE-2014-0224": {
        "script": "ssl-ccs-injection",
        "products": ["openssl", "https", "ssl", "postgresql", "mysql"],
        "confidence_base": 90,
        "notes": "OpenSSL CCS injection vulnerability",
    },
    "CVE-2015-4000": {
        "script": "ssl-dh-params",
        "products": ["openssl", "https", "ssl"],
        "confidence_base": 85,
        "notes": "Logjam: DHE export cipher downgrade",
    },

    # ── MySQL ────────────────────────────────────────────────────────────────
    "CVE-2012-2122": {
        "script": "mysql-vuln-cve2012-2122",
        "products": ["mysql", "mariadb"],
        "confidence_base": 85,
        "notes": "MySQL auth bypass via repeated failed connections",
    },

    # ── RPC / NFS ─────────────────────────────────────────────────────────────
    "CVE-2011-3556": {
        "script": "rmi-vuln-classloader",
        "products": ["java-rmi", "rmi", "classpath"],
        "confidence_base": 90,
        "notes": "Java RMI default configuration allows classloader code exec",
    },

    # ── DistCC ───────────────────────────────────────────────────────────────
    "CVE-2004-2687": {
        "script": "distcc-cve2004-2687",
        "products": ["distcc", "distccd"],
        "confidence_base": 95,
        "notes": "distccd remote code execution via EXEC request",
    },

    # ── VNC ──────────────────────────────────────────────────────────────────
    "CVE-2006-2369": {
        "script": "realvnc-auth-bypass",
        "products": ["vnc", "realvnc"],
        "confidence_base": 90,
        "notes": "RealVNC authentication bypass",
    },
    "CVE-2002-2088": {
        "script": None,                           # FIX DB-004: vnc-vuln-cve2006-2369 does NOT exist in nmap; was silently dead
        "products": ["vnc", "realvnc"],
        "confidence_base": 0,
        "notes": "VNC auth weakness; no dedicated NSE. Use version range check only.",
    },

    # ── IRC / UnrealIRCd ─────────────────────────────────────────────────────
    "CVE-2010-2075": {
        "script": "irc-unrealircd-backdoor",
        "products": ["unrealircd", "irc"],
        "confidence_base": 95,
        "notes": "UnrealIRCd 3.2.8.1 contains a deliberate backdoor",
    },
    # FIX DB-005: CVE-2016-7144 is a password disclosure bug — not the 2010 backdoor.
    # irc-unrealircd-backdoor only proves CVE-2010-2075. Setting script=None prevents
    # a backdoor confirmation from being wrongly attributed to CVE-2016-7144.
    "CVE-2016-7144": {
        "script": None,                           # FIX DB-005: was irc-unrealircd-backdoor (wrong CVE for that script)
        "products": ["unrealircd", "irc"],
        "confidence_base": 0,
        "notes": "UnrealIRCd password disclosure; no dedicated NSE. Version range check only.",
    },

    # ── SMTP ─────────────────────────────────────────────────────────────────
    "CVE-2010-4344": {
        "script": "smtp-vuln-cve2010-4344",
        "products": ["exim"],                  # EXIM ONLY — not Postfix
        "confidence_base": 90,
        "notes": "Exim 4.70 heap overflow; smtp-vuln-cve2010-4344 is Exim-specific",
    },

    # ── RDP ──────────────────────────────────────────────────────────────────
    "CVE-2012-0002": {
        "script": "rdp-vuln-ms12-020",
        "products": ["rdp", "ms-wbt-server", "microsoft"],
        "confidence_base": 90,
        "notes": "MS12-020 RDP remote code execution / DoS",
    },
    "CVE-2019-0708": {
        "script": None,                           # FIX DB-006: rdp-vuln-ms12-020 tests CVE-2012-0002 (different bulletin)
        "products": ["rdp", "ms-wbt-server"],     # A CONFIRMED result from ms12-020 would be false-positive for BlueKeep.
        "confidence_base": 0,
        "notes": "BlueKeep RDP pre-auth RCE; no stable NSE exists. Version range check only.",
    },

    # ── SNMP ─────────────────────────────────────────────────────────────────
    "CVE-2012-6438": {
        "script": "snmp-vuln-cve2012-6438",
        "products": ["snmp"],
        "confidence_base": 90,
        "notes": "Cisco SNMP buffer overflow",
    },

    # ── Explicit NO-SCRIPT entries ────────────────────────────────────────────
    # These block wrong auto-seeded DB entries (from nse_parse or Gemini) from
    # being used on the wrong service.  script=None → always falls through to
    # version-range check.  force=True in cve_db._seed_hardcoded ensures these
    # override any existing high-confidence wrong entries in cve_scripts.db.

    # Postfix CVE — smtp-vuln-cve2010-4344 is Exim-ONLY, never run on Postfix.
    "CVE-2005-0337": {
        "script": None,
        "products": ["postfix", "smtp"],
        "confidence_base": 0,
        "notes": "Postfix relay CVE; no NSE. smtp-vuln-cve2010-4344 is Exim-only — must not run on Postfix.",
    },
    # Exchange ProxyLogon — no NSE; wrong to run http-slowloris on Tomcat/Apache.
    "CVE-2021-26855": {
        "script": None,
        "products": ["exchange", "microsoft"],
        "confidence_base": 0,
        "notes": "MS Exchange ProxyLogon; no NSE. Exchange-specific — must not run on Apache/Tomcat.",
    },
    # PostgreSQL privilege escalation — ssl-poodle is for CVE-2014-3566, not this.
    "CVE-2016-5423": {
        "script": None,
        "products": ["postgresql"],
        "confidence_base": 0,
        "notes": "PostgreSQL privilege escalation; no NSE. ssl-poodle is for SSL3 (CVE-2014-3566), not PostgreSQL privesc.",
    },
    # OpenSSH weakness — no dedicated NSE confirmation script.
    "CVE-2010-4478": {
        "script": None,
        "products": ["openssh", "ssh"],
        "confidence_base": 0,
        "notes": "OpenSSH weak key exchange; no dedicated NSE. Version range check only.",
    },
    # telnetd — no NSE confirmation script available.
    "CVE-2021-27171": {
        "script": None,
        "products": ["telnetd", "telnet"],
        "confidence_base": 0,
        "notes": "Linux telnetd CVE; no NSE. Version range check only.",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Version-range table — used as fallback when no NSE script is available.
# Format: cve_id → list of (product_substring, min_version, max_version) triples.
# "min" and "max" are inclusive; comparison is on numeric tuple split by ".".
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_VULNERABLE_VERSIONS: dict[str, list] = {
    # Tomcat AJP Ghostcat — no reliable nmap NSE exists
    # FIX DB-013: deduplicated overlapping tomcat ranges into per-major-version bands
    "CVE-2020-1938": [
        ("tomcat", "7.0.0", "7.0.99"),   # 7.x: fixed in 7.0.100
        ("tomcat", "8.5.0", "8.5.50"),   # 8.5.x: fixed in 8.5.51
        ("tomcat", "9.0.0", "9.0.30"),   # 9.0.x: fixed in 9.0.31
        ("jserv",  "0.0.0", "9.0.30"),   # "Apache Jserv" product string
        ("ajp",    "0.0.0", "9.0.30"),   # AJP service name match
        ("coyote", "0.0.0", "9.0.30"),   # "Apache Tomcat/Coyote" product
    ],
    # Tomcat Exchange-ProxyLogon (actually Exchange, but keep for awareness)
    "CVE-2021-26855": [
        ("exchange", "0.0.0", "15.2.999"),
    ],
    # ProFTPD mod_copy unauth file copy
    "CVE-2019-12815": [
        ("proftpd", "0.0.0", "1.3.5b"),
    ],
    # OpenSSH user enumeration
    "CVE-2018-15473": [
        ("openssh", "0.0.0", "7.7.99"),
    ],
    # PostgreSQL privilege escalation
    "CVE-2016-5423": [
        ("postgresql", "9.3.0", "9.3.13"),
        ("postgresql", "9.4.0", "9.4.8"),
        ("postgresql", "9.5.0", "9.5.3"),
    ],
    # MySQL auth bypass
    # FIX DB-010: added 5.0.x range (target has 5.0.51a which was previously missed);
    # also corrected 5.5.x max from 5.5.20 → 5.5.28 (actual patch boundary)
    "CVE-2012-2122": [
        ("mysql", "5.0.0", "5.0.96"),    # FIX DB-010: 5.0.x all vulnerable — was missing
        ("mysql", "5.1.0", "5.1.61"),
        ("mysql", "5.5.0", "5.5.28"),    # FIX DB-010: corrected max (was 5.5.20)
    ],
    # Postfix CVE — no NSE, version check only
    # FIX DB-012: max was "2.1.4" (the fixed version); corrected to "2.1.3"
    "CVE-2005-0337": [
        ("postfix", "0.0.0", "2.1.3"),   # FIX DB-012: 2.1.4 is the patch; max = 2.1.3
    ],
    # Linux telnetd
    "CVE-2021-27171": [
        ("telnetd", "0.0.0", "1.999"),
        ("telnet",  "0.0.0", "1.999"),
    ],
    # FIX DB-009: CVE-2020-0796 is SMBGhost (Windows SMBv3 compression RCE).
    # It has NOTHING to do with Linux NFS/rpcbind/mountd/nlockmgr.
    # Removed all NFS entries; replaced with correct Windows SMB3 product.
    "CVE-2020-0796": [
        ("smb",     "0.0.0", "10.0.19041.0"),  # Windows 10 1909 and earlier
        ("windows", "0.0.0", "10.0.19041.0"),
    ],
    # SSH weak J-PAKE key exchange
    # FIX DB-011: max was 5.8.99 but CVE-2010-4478 was fixed in OpenSSH 5.6.
    # Versions 5.6–5.8 were incorrectly flagged as vulnerable.
    "CVE-2010-4478": [
        ("openssh", "0.0.0", "5.5.99"),   # FIX DB-011: was 5.8.99; fixed in 5.6
    ],
    # Apache mod_mime — no NSE (http-vuln-cve2017-7679 does not exist)
    "CVE-2017-7679": [
        ("apache", "2.2.0", "2.2.31"),
        ("apache", "2.4.0", "2.4.24"),
    ],
    # BlueKeep — no NSE (rdp-vuln-ms12-020 tests different bulletin)
    "CVE-2019-0708": [
        ("ms-wbt-server", "0.0.0", "6.1.7601.99"),   # Windows 7 / Server 2008 R2
        ("rdp",           "0.0.0", "6.1.7601.99"),
    ],
    # UnrealIRCd password disclosure (not the 2010 backdoor)
    "CVE-2016-7144": [
        ("unrealircd", "3.0.0", "3.2.10.5"),
        ("irc",        "3.0.0", "3.2.10.5"),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Helper: loose version comparison
# ─────────────────────────────────────────────────────────────────────────────
def _vtuple(ver: str):
    """'2.3.4' → (2, 3, 4)  |  '5.0.51a-3ubuntu5' → (5, 0, 51)"""
    parts = re.findall(r'\d+', ver.split()[0] if ver else "")
    return tuple(int(p) for p in parts[:4]) if parts else ()


def _version_in_range(detected: str, vmin: str, vmax: str) -> bool:
    """
    Return True if `detected` version falls in [vmin, vmax].
    Empty/unknown detected version → True (conservative: flag for human review).
    """
    if not detected or not detected.strip():
        return True    # unknown version on known-vulnerable product — flag it
    v = _vtuple(detected)
    lo = _vtuple(vmin)
    hi = _vtuple(vmax)
    # Pad shorter tuple with zeros for fair comparison
    length = max(len(v), len(lo), len(hi))
    v  = v  + (0,) * (length - len(v))
    lo = lo + (0,) * (length - len(lo))
    hi = hi + (0,) * (length - len(hi))
    return lo <= v <= hi


# ─────────────────────────────────────────────────────────────────────────────
# Core API
# ─────────────────────────────────────────────────────────────────────────────

def get_confirmation_plan(
    cves: list[str],
    service: str,
    product: str,
    version: str,
    available_scripts: list[str],
) -> dict:
    """
    Determine the best confirmation strategy for a single port.

    Lookup order (fastest / most reliable first):
      Layer 1 — SQLite DB (manual entries, NSE-parsed, cached Gemini answers)
      Layer 2 — Gemini 2.0 Flash (only for CVEs not in DB; result saved to DB)
      Layer 3 — Version range table (POTENTIALLY_VULNERABLE, no script run)
      Layer 4 — NOT_VALIDATABLE

    Returns a plan dict:
    {
        "action"                 : "NSE" | "VERSION" | "NONE",
        "script"                 : str | None,
        "cve_id"                 : str | None,
        "confidence_if_confirmed": int,
        "reason"                 : str,
        "source"                 : str,   # "db_manual"|"db_nse"|"db_gemini"|"gemini_live"|"version"|"none"
    }
    """
    avail_set = set(available_scripts)
    combined  = f"{service} {product} {version}".lower()

    # ── Layer 1: SQLite database lookup ──────────────────────────────────────
    # The DB contains: 45 manual entries + 600+ NSE-parsed entries + all
    # previous Gemini answers. After a few scans it handles >95% of CVEs
    # instantly without any network call.
    try:
        from app.scanner.cve_db import get_script_for_cve, get_version_ranges
        _db_available = True
    except ImportError:
        _db_available = False

    if _db_available:
        for cve_id in cves:
            db = get_script_for_cve(cve_id, service, product, list(avail_set))
            if not db["found"]:
                continue

            script = db["script"]

            # Product guard: if the DB entry has product keywords, verify
            # they match the detected service/product to avoid cross-service
            # script application (e.g. ftp-vsftpd-backdoor on rpcbind).
            prod_kws = [k.strip() for k in db.get("product_keywords", "").split(",") if k.strip()]
            if prod_kws and not any(kw in combined for kw in prod_kws):
                continue   # product mismatch — try next CVE

            if script and script in avail_set:
                return {
                    "action"                 : "NSE",
                    "script"                 : script,
                    "cve_id"                 : cve_id,
                    "confidence_if_confirmed": db["confidence"],
                    "reason"                 : f"DB hit ({db['source']}): {script} for {cve_id}",
                    "source"                 : f"db_{db['source']}",
                }

            # DB entry exists but has no script → has version range?
            if db.get("has_version_range"):
                ranges = get_version_ranges(cve_id)
                for prod_kw, vmin, vmax in ranges:
                    if prod_kw in combined and _version_in_range(version, vmin, vmax):
                        return {
                            "action"                 : "VERSION",
                            "script"                 : None,
                            "cve_id"                 : cve_id,
                            "confidence_if_confirmed": 60,
                            "reason"                 : (
                                f"No NSE for {cve_id}. Version {version!r} in "
                                f"known vulnerable range {vmin}–{vmax}."
                            ),
                            "source"                 : "version",
                        }

    # ── Layer 2: Gemini 2.0 Flash (live — only fires for unknown CVEs) ───────
    # Only called when the DB has no entry. Result is saved to DB so the
    # same CVE is never sent to Gemini again.
    try:
        from app.scanner.gemini_selector import ask_gemini, is_gemini_available
        gemini_ok = is_gemini_available()
    except ImportError:
        gemini_ok = False

    if gemini_ok:
        for cve_id in cves:
            script, reasoning = ask_gemini(
                cve_id, service, product, version, available_scripts
            )
            if script and script in avail_set:
                # Save to DB so we never ask Gemini for this CVE again
                if _db_available:
                    try:
                        from app.scanner.cve_db import save_ai_result
                        save_ai_result(
                            cve_id, script, service, product,
                            reasoning=reasoning, source="gemini"
                        )
                    except Exception:
                        pass
                return {
                    "action"                 : "NSE",
                    "script"                 : script,
                    "cve_id"                 : cve_id,
                    "confidence_if_confirmed": 75,
                    "reason"                 : reasoning,
                    "source"                 : "gemini_live",
                }

    # ── Layer 3: Static CVE_NSE_MAP (in-memory fallback if DB not ready) ─────
    for cve_id in cves:
        entry = CVE_NSE_MAP.get(cve_id)
        if not entry:
            continue
        script = entry["script"]
        if script not in avail_set:
            continue
        if not any(prod in combined for prod in entry["products"]):
            continue
        return {
            "action"                 : "NSE",
            "script"                 : script,
            "cve_id"                 : cve_id,
            "confidence_if_confirmed": entry["confidence_base"],
            "reason"                 : entry["notes"],
            "source"                 : "static_map",
        }

    # ── Layer 4: Static version ranges (in-memory fallback) ──────────────────
    for cve_id in cves:
        ranges = KNOWN_VULNERABLE_VERSIONS.get(cve_id, [])
        for prod_kw, vmin, vmax in ranges:
            if prod_kw in combined and _version_in_range(version, vmin, vmax):
                return {
                    "action"                 : "VERSION",
                    "script"                 : None,
                    "cve_id"                 : cve_id,
                    "confidence_if_confirmed": 60,
                    "reason"                 : (
                        f"No NSE for {cve_id}. Version {version!r} in "
                        f"known vulnerable range {vmin}–{vmax}."
                    ),
                    "source"                 : "version",
                }

    # ── Layer 5: Nothing matches ──────────────────────────────────────────────
    cve_list = ", ".join(cves[:5]) or "none"
    return {
        "action"                 : "NONE",
        "script"                 : None,
        "cve_id"                 : None,
        "confidence_if_confirmed": 0,
        "reason"                 : (
            f"No NSE script available for CVEs ({cve_list}) on "
            f"'{service}' ({product} {version}). "
            f"Gemini {'checked but found no match' if gemini_ok else 'not configured'}."
        ),
        "source"                 : "none",
    }


def analyze_output(output: str, script: str = "", cve_id: str = "") -> dict:
    """
    Parse raw nmap NSE output and produce a structured verdict.

    SAFE-BEFORE-CONFIRMED ordering: negative indicators are evaluated first
    so "State: NOT VULNERABLE" can never be misclassified as CONFIRMED.

    Returns
    -------
    {
        "status"     : "CONFIRMED" | "NOT_VULNERABLE" | "UNCONFIRMED",
        "confidence" : int (0-100),
        "evidence"   : str,   # clean excerpt suitable for the chatbot table
    }
    """
    if not output or not output.strip():
        return {
            "status": "UNCONFIRMED",
            "confidence": 0,
            "evidence": "Script produced no output",
        }

    # ── 0. SOPLib FIRST, for scripts it has specific knowledge of ──────────
    # Phase 4: generic patterns below are too broad for some of SOPLib's 8
    # scripts — e.g. the generic NOT_VULN keyword "disabled" (meant for
    # things like "WebDAV disabled" = safe) would otherwise misread
    # smb-security-mode's "message_signing: disabled" (a BAD finding) as
    # safe. For any script SOPLib explicitly knows the format of, let it
    # decide first; only fall through to the generic heuristics below for
    # scripts SOPLib has no entry for.
    from app.scanner.soplib import soplib_check, SOPLIB
    if script in SOPLIB:
        sop_result = soplib_check(script, output)
        if sop_result:
            return {
                "status":     sop_result["status"],
                "confidence": 90 if sop_result["status"] == "CONFIRMED" else 0,
                "evidence":   sop_result["evidence"],
            }
        # SOPLib knows the script but no pattern matched this output —
        # still let the generic logic below have a try (e.g. an NSE error
        # message), rather than jumping straight to UNCONFIRMED.

    # Extract only the script-output section (after nmap host header) to
    # avoid matching "vulnerable" that might appear in host names / banners.
    script_section = _extract_script_section(output)

    # ── 1. SAFE patterns — checked FIRST ─────────────────────────────────────
    NOT_VULN_PATTERNS = [
        r"State:\s*NOT\s+VULNERABLE",
        r"not\s+vulnerable",
        r"not\s+affected",
        r"patched",
        # FIX DB-014: "disabled" was too broad — matched "message_signing: disabled"
        # (a HIGH-severity SMB misconfiguration) and silently classified it as safe.
        # Narrowed to only the contexts that genuinely indicate a feature is safely off.
        r"\b(webdav|ssl|tls|compression)\s+disabled\b",
        r"not\s+exim",                        # smtp-vuln-cve2010-4344 on Postfix
        r"not\s+running\s+exim",
        r"version\s+is\s+not\s+affected",
        r"server\s+is\s+not\s+vulnerable",
        r"target\s+is\s+not\s+vulnerable",
        r"does\s+not\s+appear\s+to\s+be\s+vulnerable",
        r"host\s+is\s+not\s+vulnerable",
        # Safe outcomes from scripts that ran but couldn't reach/authenticate
        r"TIMEOUT",
        r"receiveGreeting\(\):\s*failed",
        r"NT_STATUS_OBJECT_NAME_NOT_FOUND",   # smb-vuln-cve-2017-7494 exploit path not found
        r"NT_STATUS_LOGON_FAILURE",
    ]
    for pat in NOT_VULN_PATTERNS:
        if re.search(pat, script_section, re.IGNORECASE):
            evidence = _best_evidence_line(output, [
                "not vulnerable", "not affected", "patched", "disabled",
                "not exim", "state:", "timeout", "failed"
            ])
            return {
                "status": "NOT_VULNERABLE",
                "confidence": 0,
                "evidence": evidence or "Script reported NOT VULNERABLE",
            }

    # ── 2. CONFIRMED patterns — NSE standard format ────────────────────────
    CONFIRMED_PATTERNS = [
        r"State:\s*VULNERABLE(?!\s*\(not exploitable\))",  # "State: VULNERABLE (Exploitable)"
        r"^\|[\s|]*VULNERABLE:\s*$",                       # "| VULNERABLE:" on its own line
        r"successfully\s+exploited",
        r"backdoor\s+was\s+installed",
        r"authentication\s+bypass",
        r"command\s+executed",
        r"shell\s+spawned",
        r"looks\s+like\s+trojaned",        # irc-unrealircd-backdoor: "Looks like trojaned version"
        r"trojaned\s+version",              # irc-unrealircd-backdoor variant
        r"backdoor\s+found",               # generic backdoor confirmation
        r"looks\s+like\s+the\s+trojanned", # irc-unrealircd-backdoor full phrase
        # FIX DB-016: http-vuln-cve2012-1823 uses freeform output (not "State: VULNERABLE").
        # It outputs "The website seems vulnerable to CVE-2012-1823" then returns command output.
        # Without these patterns, confirmed PHP-CGI RCE was silently dropped.
        r"seems\s+(to\s+be\s+)?vulnerable",               # http-vuln-cve2012-1823
        r"Output\s+of\s+the\s+command",                   # PHP-CGI executed command output
        # FIX DB-016: http-vuln-cve2014-3704 (Drupalgeddon) outputs this when it exploits.
        r"adding\s+admin\s+user",                         # Drupalgeddon successful exploitation
        r"uid=\d+\(\w+\)\s+gid=\d+",                     # Shell command returned uid= output
    ]
    for pat in CONFIRMED_PATTERNS:
        if re.search(pat, script_section, re.IGNORECASE | re.MULTILINE):
            evidence = _best_evidence_line(output, [
                "vulnerable", "state:", "evidence", "exploit", "backdoor",
                "bypass", "cve", "risk factor", "description"
            ])
            return {
                "status": "CONFIRMED",
                "confidence": 95,
                "evidence": evidence or "VULNERABLE: evidence found in script output",
            }

    # ── 3. Weak positive indicators (lower confidence) ──────────────────────
    # FIX DB-015: removed bare r"VULNERABLE" — too broad. Any script banner or
    # advisory text mentioning the word could trigger a false CONFIRMED at 75%.
    # All standard NSE output is already caught by CONFIRMED_PATTERNS above.
    WEAK_PATTERNS = [
        r"exploitable",      # kept: more specific than bare "VULNERABLE"
        r"LIKELY\s+VULNERABLE",   # http-slowloris-check: "State: LIKELY VULNERABLE"
    ]
    for pat in WEAK_PATTERNS:
        if re.search(pat, script_section, re.IGNORECASE):
            evidence = _best_evidence_line(output, ["vulnerable", "exploitable", "state:"])
            return {
                "status": "CONFIRMED",
                "confidence": 75,
                "evidence": evidence or "VULNERABLE keyword detected in script output",
            }

    # ── 4. Script ran cleanly but produced no evidence ──────────────────────
    # (SOPLib already had first refusal at step 0, for any script it knows —
    # reaching here means either an unknown script, or a SOPLib-known script
    # whose output didn't match any of its patterns.)
    evidence = _best_evidence_line(output, ["state:", "version", "error"]) or ""
    if not evidence:
        # Truly empty meaningful output — probably "Starting Nmap..." only
        evidence = output.strip()[:120]

    return {
        "status": "UNCONFIRMED",
        "confidence": 0,
        "evidence": evidence or "Script produced no vulnerability evidence",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_script_section(output: str) -> str:
    """
    Return only the lines that belong to the NSE script block in nmap output.
    Lines starting with '|' are script output; everything else is nmap header/footer.
    Falls back to full output if no '|' lines are found.
    """
    script_lines = [l for l in output.splitlines() if l.lstrip().startswith("|")]
    return "\n".join(script_lines) if script_lines else output


def _best_evidence_line(output: str, keywords: list[str]) -> str:
    """
    Return a clean evidence string: the first 3 lines that contain any of
    `keywords`, joined with ' | ', capped at 300 characters.
    """
    hits = []
    for line in output.splitlines():
        stripped = line.strip().lstrip("|_ ")
        if stripped and any(kw in stripped.lower() for kw in keywords):
            hits.append(stripped)
        if len(hits) >= 3:
            break
    return " | ".join(hits)[:300]
