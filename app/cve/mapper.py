"""
CVE Mapping Engine v2.0
- Local hardcoded DB (always available, instant)
- NVD 2.0 API live lookups (when NVD_API_KEY is set in .env)
- Simple file-based cache (data/cve_db/) to avoid hammering NVD

SAFETY: Returns descriptions and patch advice only. No exploit steps.
"""
import os
import json
import time
import logging

logger = logging.getLogger(__name__)

# ── Local fallback DB ─────────────────────────────────────────────────────────
LOCAL_CVE_DB = {
    "openssh": [
        {"cve_id": "CVE-2023-38408", "affected": ["7.", "8.", "9.0", "9.1", "9.2"],
         "cvss": 9.8, "severity": "critical",
         "description": "Remote code execution via ssh-agent forwarding. A malicious SSH server can execute arbitrary commands on a client running ssh-agent.",
         "patch": "Upgrade to OpenSSH 9.3p2 or later."},
        {"cve_id": "CVE-2023-28531", "affected": ["8.", "9.0", "9.1", "9.2"],
         "cvss": 9.8, "severity": "critical",
         "description": "Memory corruption in OpenSSH ssh-agent when a PKCS#11 provider is loaded. Allows remote code execution.",
         "patch": "Upgrade to OpenSSH 9.3 or later."},
        {"cve_id": "CVE-2018-15473", "affected": ["7.", "6.", "5."],
         "cvss": 5.3, "severity": "medium",
         "description": "Username enumeration in OpenSSH via crafted packet.",
         "patch": "Upgrade to OpenSSH 7.8 or later."},
        {"cve_id": "CVE-2016-6515", "affected": ["7.2", "7.1", "7.0", "6.", "5."],
         "cvss": 7.5, "severity": "high",
         "description": "DoS in OpenSSH — very long password string causes CPU exhaustion.",
         "patch": "Upgrade to OpenSSH 7.4 or later."},
        {"cve_id": "CVE-2016-0777", "affected": ["7.0", "6.", "5."],
         "cvss": 6.5, "severity": "medium",
         "description": "Information disclosure via OpenSSH client roaming. Private keys may be leaked.",
         "patch": "Upgrade to OpenSSH 7.1p2 or disable UseRoaming."},
    ],
    "apache httpd": [
        # ── Apache 2.2.x (EOL — all versions affected) ────────────────────
        {"cve_id": "CVE-2017-7679", "affected": ["2.2"],
         "cvss": 9.8, "severity": "critical",
         "description": "mod_mime buffer overread in Apache 2.2.x — allows remote code execution.",
         "patch": "Apache 2.2 is EOL. Upgrade to Apache 2.4.26 or later immediately.",
         "published": "2017-06-19T00:00:00"},
        {"cve_id": "CVE-2017-9798", "affected": ["2.2"],
         "cvss": 7.5, "severity": "high",
         "description": "Optionsbleed — Apache HTTP OPTIONS method leaks data from server memory.",
         "patch": "Upgrade to Apache 2.4.28 or later. Apache 2.2 is end-of-life.",
         "published": "2017-09-18T00:00:00"},
        {"cve_id": "CVE-2011-3192", "affected": ["2.2"],
         "cvss": 7.8, "severity": "high",
         "description": "Apache 2.2 Range header DoS (Apache Killer). Server exhausted with overlapping ranges.",
         "patch": "Upgrade to Apache 2.2.21+ or deploy mod_reqtimeout. Prefer 2.4.x.",
         "published": "2011-08-29T00:00:00"},
        # ── Apache 2.4.x CVEs ─────────────────────────────────────────────
        {"cve_id": "CVE-2021-41773", "affected": ["2.4.49"],
         "cvss": 9.8, "severity": "critical",
         "description": "Path traversal and RCE in Apache 2.4.49. Files readable outside docroot.",
         "patch": "Upgrade to Apache 2.4.51 or later immediately.",
         "published": "2021-10-05T00:00:00"},
        {"cve_id": "CVE-2021-42013", "affected": ["2.4.49", "2.4.50"],
         "cvss": 9.8, "severity": "critical",
         "description": "Incomplete fix for CVE-2021-41773 in Apache 2.4.50.",
         "patch": "Upgrade to Apache 2.4.51 or later.",
         "published": "2021-10-07T00:00:00"},
        {"cve_id": "CVE-2022-31813", "affected": ["2.4.53", "2.4.52", "2.4.51", "2.4.50", "2.4.49", "2.4.48"],
         "cvss": 9.8, "severity": "critical",
         "description": "HTTP Request Smuggling in Apache mod_proxy.",
         "patch": "Upgrade to Apache 2.4.54 or later.",
         "published": "2022-06-08T00:00:00"},
    ],
    "vsftpd": [
        {"cve_id": "CVE-2011-2523", "affected": ["2.3.4"],
         "cvss": 10.0, "severity": "critical",
         "description": "Backdoor in vsftpd 2.3.4 — supply-chain compromise.",
         "patch": "Remove vsftpd 2.3.4 immediately. Deploy vsftpd 3.0.5+."},
        {"cve_id": "CVE-2021-3618", "affected": ["3.0.3", "3.0.2", "3.0.1", "2.3."],
         "cvss": 7.4, "severity": "high",
         "description": "ALPACA cross-protocol attack affecting vsftpd.",
         "patch": "Enable strict TLS SNI. Upgrade to vsftpd 3.0.5."},
    ],
    "mysql": [
        {"cve_id": "CVE-2016-6662", "affected": ["5.5.", "5.6.", "5.7."],
         "cvss": 9.8, "severity": "critical",
         "description": "RCE in MySQL — any account can write config and escalate to root.",
         "patch": "Upgrade to MySQL 5.7.15 or 8.0+."},
        {"cve_id": "CVE-2012-2122", "affected": ["5.5.", "5.1.", "5.0."],
         "cvss": 7.5, "severity": "high",
         "description": "Authentication bypass in MySQL via timing attack.",
         "patch": "Upgrade to MySQL 5.5.24 or later."},
        {"cve_id": "CVE-2023-21980", "affected": ["8.0."],
         "cvss": 7.1, "severity": "high",
         "description": "MySQL optimizer DoS by low-privileged attacker.",
         "patch": "Upgrade to MySQL 8.0.33 or later."},
    ],
    "isc bind": [
        {"cve_id": "CVE-2021-25220", "affected": ["9.9.", "9.11.", "9.16.", "9.18."],
         "cvss": 6.8, "severity": "medium",
         "description": "DNS cache poisoning in BIND 9.",
         "patch": "Upgrade to BIND 9.18.3 or 9.16.27."},
    ],
    "net-snmp": [
        {"cve_id": "CVE-2022-44792", "affected": ["5.7.", "5.8.", "5.9."],
         "cvss": 6.5, "severity": "medium",
         "description": "NULL pointer dereference in net-snmp crashes snmpd.",
         "patch": "Upgrade to net-snmp 5.9.3."},
        {"cve_id": "CVE-2020-15861", "affected": ["5.7.", "5.6.", "5.4."],
         "cvss": 7.8, "severity": "high",
         "description": "Privilege escalation via EXTEND MIB in net-snmp.",
         "patch": "Disable EXTEND MIB or upgrade to net-snmp 5.7.3."},
    ],
    # ── Extended coverage ──────────────────────────────────────────────────
    "nginx": [
        {"cve_id": "CVE-2021-23017", "affected": ["1.20.", "1.19.", "1.18.", "1.17.", "1.16."],
         "cvss": 7.7, "severity": "high",
         "description": "Off-by-one in nginx DNS resolver allows heap write / RCE.",
         "patch": "Upgrade to nginx 1.21.0 or 1.20.1+."},
        {"cve_id": "CVE-2017-7529", "affected": ["1.13.", "1.12.", "1.11.", "1.10.", "1.9.", "1.8."],
         "cvss": 7.5, "severity": "high",
         "description": "Integer overflow in nginx range filter — information disclosure.",
         "patch": "Upgrade to nginx 1.13.3 or 1.12.1+."},
    ],
    "postfix": [
        {"cve_id": "CVE-2023-51764", "affected": ["3.8.", "3.7.", "3.6.", "3.5."],
         "cvss": 7.5, "severity": "high",
         "description": "SMTP smuggling allows forged e-mail to bypass SPF/DMARC checks.",
         "patch": "Apply Postfix patches released 2023-12-21 or set smtpd_data_restrictions."},
    ],
    "exim": [
        {"cve_id": "CVE-2019-10149", "affected": ["4.87", "4.88", "4.89", "4.90", "4.91"],
         "cvss": 9.8, "severity": "critical",
         "description": "Remote command execution in Exim — no authentication required.",
         "patch": "Upgrade to Exim 4.92 immediately."},
        {"cve_id": "CVE-2020-28017", "affected": ["4.94", "4.93", "4.92"],
         "cvss": 9.8, "severity": "critical",
         "description": "Heap overflow in Exim receive_add_recipient.",
         "patch": "Upgrade to Exim 4.94.2."},
    ],
    "microsoft-ds": [
        {"cve_id": "CVE-2017-0144", "affected": [""],   # EternalBlue — version-agnostic
         "cvss": 9.8, "severity": "critical",
         "description": "EternalBlue: SMBv1 remote code execution, exploited by WannaCry.",
         "patch": "Apply MS17-010. Disable SMBv1. Block port 445 at perimeter."},
        {"cve_id": "CVE-2020-0796", "affected": [""],
         "cvss": 10.0, "severity": "critical",
         "description": "SMBGhost: SMBv3 buffer overflow, unauthenticated RCE on Windows 10/Server 2019.",
         "patch": "Apply KB4551762. Disable SMBv3 compression as interim mitigation."},
    ],
    "ms-wbt-server": [  # RDP
        {"cve_id": "CVE-2019-0708", "affected": [""],
         "cvss": 9.8, "severity": "critical",
         "description": "BlueKeep: pre-auth RCE in Windows RDP — wormable.",
         "patch": "Apply Microsoft patch KB4499175. Disable RDP or put behind VPN."},
        {"cve_id": "CVE-2019-1182", "affected": [""],
         "cvss": 9.8, "severity": "critical",
         "description": "DejaBlue: second BlueKeep-class pre-auth RDP RCE.",
         "patch": "Apply August 2019 Microsoft patch Tuesday updates."},
    ],
    "telnet": [
        {"cve_id": "CVE-2011-4862", "affected": [""],
         "cvss": 10.0, "severity": "critical",
         "description": "Buffer overflow in BSD telnetd — pre-auth RCE.",
         "patch": "Disable telnet immediately. Replace with SSH."},
    ],
    "redis": [
        {"cve_id": "CVE-2022-0543", "affected": ["6.", "7."],
         "cvss": 10.0, "severity": "critical",
         "description": "Lua sandbox escape in Redis — allows RCE via crafted Lua scripts.",
         "patch": "Upgrade to Redis 6.2.7 or 7.0.0. Require authentication."},
        {"cve_id": "CVE-2015-8080", "affected": ["3.", "2."],
         "cvss": 7.5, "severity": "high",
         "description": "Integer overflow in Redis Lua scripting — DoS / RCE.",
         "patch": "Upgrade to Redis 3.0.6+."},
    ],
    "mongodb": [
        {"cve_id": "CVE-2019-2386", "affected": ["4.0.", "3.6.", "3.4."],
         "cvss": 7.1, "severity": "high",
         "description": "Auth bypass in MongoDB after user deletion — grants stale session access.",
         "patch": "Upgrade to MongoDB 4.0.9 / 3.6.13 / 3.4.21+."},
    ],
    "postgresql": [
        {"cve_id": "CVE-2019-10211", "affected": ["12.", "11.", "10.", "9."],
         "cvss": 9.8, "severity": "critical",
         "description": "Arbitrary code execution in PostgreSQL via host connection parameter injection.",
         "patch": "Upgrade to PostgreSQL 12.1, 11.6, 10.11, 9.6.16, or 9.4.21+."},
    ],
    "tomcat": [
        {"cve_id": "CVE-2020-1938", "affected": ["9.0.", "8.5.", "7."],
         "cvss": 9.8, "severity": "critical",
         "description": "Ghostcat: AJP connector file inclusion / RCE in Apache Tomcat.",
         "patch": "Upgrade to Tomcat 9.0.31, 8.5.51, or 7.0.100+. Disable AJP if unused."},
        {"cve_id": "CVE-2019-0232", "affected": ["9.0.", "8.5.", "7."],
         "cvss": 8.1, "severity": "high",
         "description": "CGI Servlet OS command injection on Windows in Apache Tomcat.",
         "patch": "Upgrade to Tomcat 9.0.19, 8.5.40, or 7.0.93+."},
    ],
    "samba": [
        {"cve_id": "CVE-2017-7494", "affected": ["4.6.", "4.5.", "4.4.", "4.3.", "4.2.", "4.1.", "3."],
         "cvss": 9.8, "severity": "critical",
         "description": "SambaCry: remote code execution via writable share in Samba.",
         "patch": "Upgrade to Samba 4.6.4, 4.5.10, 4.4.14+. Add 'nt pipe support = no' as workaround."},
    ],
    "wordpress": [
        {"cve_id": "CVE-2023-39999", "affected": ["6.3.", "6.2.", "6.1.", "6.0.", "5."],
         "cvss": 6.5, "severity": "medium",
         "description": "Authenticated blind SSRF in WordPress core.",
         "patch": "Upgrade to WordPress 6.3.2+."},
    ],
    "drupal": [
        {"cve_id": "CVE-2018-7600", "affected": ["8.5.", "8.4.", "7."],
         "cvss": 9.8, "severity": "critical",
         "description": "Drupalgeddon2: unauthenticated RCE in Drupal core.",
         "patch": "Upgrade to Drupal 8.5.1, 8.4.6, or 7.58+."},
    ],
    "elasticsearch": [
        {"cve_id": "CVE-2015-1427", "affected": ["1.4.", "1.3."],
         "cvss": 9.3, "severity": "critical",
         "description": "Groovy sandbox escape in Elasticsearch allows unauthenticated OS command execution.",
         "patch": "Upgrade to Elasticsearch 1.4.3+. Disable dynamic scripting."},
    ],
    "jenkins": [
        {"cve_id": "CVE-2018-1000861", "affected": ["2.153", "2.138"],
         "cvss": 9.8, "severity": "critical",
         "description": "Unauthenticated RCE in Jenkins via Stapler URL routing.",
         "patch": "Upgrade to Jenkins 2.154 / LTS 2.138.4."},
    ],
    "java-rmi": [
        {"cve_id": "CVE-2011-3556", "affected": [""],
         "cvss": 10.0, "severity": "critical",
         "description": "Java RMI server allows unauthenticated remote code execution.",
         "patch": "Disable RMI registry. Restrict port 1099. Upgrade to Java 7u2+."},
    ],
    "http-proxy": [
        {"cve_id": "CVE-2021-26855", "affected": [""],
         "cvss": 9.8, "severity": "critical",
         "description": "ProxyLogon: SSRF in Microsoft Exchange used for pre-auth RCE.",
         "patch": "Apply Microsoft Exchange cumulative update patches from March 2021."},
    ],
}

# ── NVD API config ────────────────────────────────────────────────────────────
_NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_DIR    = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "cve_db"
)
_CACHE_TTL_SEC = 86400  # 24 h


def _cache_path(key: str) -> str:
    safe = key.replace("/", "_").replace(" ", "_")
    return os.path.join(_CACHE_DIR, f"{safe}.json")


def _load_cache(key: str) -> list | None:
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        if time.time() - data.get("ts", 0) > _CACHE_TTL_SEC:
            return None
        return data.get("cves", [])
    except Exception:
        return None


def _save_cache(key: str, cves: list):
    os.makedirs(_CACHE_DIR, exist_ok=True)
    try:
        with open(_cache_path(key), "w") as f:
            json.dump({"ts": time.time(), "cves": cves}, f)
    except Exception:
        pass


def _nvd_lookup(product: str, version: str) -> list:
    """Query NVD 2.0 API for a product+version. Returns list of CVE dicts."""
    cache_key = f"{product}_{version}"
    cached = _load_cache(cache_key)
    if cached is not None:
        return cached

    try:
        import urllib.request, urllib.parse
        keyword = f"{product} {version}".strip()
        params  = {"keywordSearch": keyword, "resultsPerPage": "20"}
        url     = f"{_NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        req     = urllib.request.Request(url)
        if _NVD_API_KEY:
            req.add_header("apiKey", _NVD_API_KEY)
        req.add_header("User-Agent", "ScanWise-AI/2.0")

        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = json.loads(resp.read())

        results = []
        for item in raw.get("vulnerabilities", []):
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs if d["lang"] == "en"), "No description.")
            metrics = cve.get("metrics", {})
            cvss = 0.0
            sev  = "unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m    = metrics[key][0]
                    data = m.get("cvssData", {})
                    cvss = data.get("baseScore", 0.0)
                    sev  = data.get("baseSeverity", "unknown").lower()
                    break
            results.append({
                "cve_id":      cve_id,
                "cvss_score":  cvss,
                "severity":    sev,
                "description": desc[:300],
                "patch":       "Check vendor advisory at https://nvd.nist.gov/vuln/detail/" + cve_id,
            })

        results.sort(key=lambda x: x["cvss_score"], reverse=True)
        _save_cache(cache_key, results[:10])
        return results[:10]

    except Exception as e:
        logger.warning(f"[CVE] NVD lookup failed for '{product}': {e}")
        return []


# ── NSE Script CVE Extractor ─────────────────────────────────────────────────
# When nmap runs --script vuln (or any vuln script), confirmed CVEs are embedded
# in <script> elements in the XML.  This parser extracts them directly so we
# never miss a CVE that nmap already proved is present.

import re as _re

# Map NSE script id → (service_hint, default_cvss, default_severity)
_NSE_SCRIPT_META = {
    "ftp-vsftpd-backdoor":       ("vsftpd",        10.0, "critical"),
    "distcc-cve2004-2687":       ("distccd",        9.3, "critical"),
    "rmi-vuln-classloader":      ("java-rmi",       10.0, "critical"),
    "smb-vuln-ms17-010":         ("microsoft-ds",   9.8, "critical"),
    "smb-vuln-ms08-067":         ("microsoft-ds",   9.8, "critical"),
    "smb-vuln-ms10-054":         ("microsoft-ds",   9.3, "high"),
    "smb-vuln-ms10-061":         ("microsoft-ds",   9.3, "high"),
    "smb-vuln-ms07-029":         ("microsoft-ds",   9.3, "critical"),
    "smb-vuln-cve2009-3103":     ("microsoft-ds",   7.8, "high"),
    "smb-vuln-regsvc-dos":       ("microsoft-ds",   7.1, "high"),
    "ssl-poodle":                ("ssl",             3.4, "medium"),
    "ssl-ccs-injection":         ("ssl",             7.4, "high"),
    "ssl-dh-params":             ("ssl",             5.0, "medium"),
    "sslv2-drown":               ("ssl",             5.9, "medium"),
    "http-shellshock":           ("http",            9.8, "critical"),
    "http-slowloris-check":      ("http",            7.5, "high"),
    "http-vuln-cve2017-5638":    ("http",            10.0,"critical"),
    "http-vuln-cve2017-1001000": ("http",            9.8, "critical"),
    "irc-unrealircd-backdoor":   ("irc",             10.0,"critical"),
    "smtp-vuln-cve2010-4344":    ("smtp",            9.3, "critical"),
    "smtp-vuln-cve2011-1764":    ("smtp",            7.5, "high"),
    "mysql-vuln-cve2012-2122":   ("mysql",           7.5, "high"),
}

# Known CVE-ID → metadata for quick enrichment of NSE-confirmed findings
_KNOWN_CVES = {
    "CVE-2011-2523": {"cvss": 10.0, "severity": "critical",
        "description": "vsFTPd 2.3.4 backdoor — supply-chain compromise allows unauthenticated RCE via port 6200.",
        "patch": "Remove vsftpd 2.3.4 immediately. Deploy vsftpd 3.0.5+.",
        "source": "nse"},
    "CVE-2004-2687": {"cvss": 9.3, "severity": "critical",
        "description": "distcc daemon allows unauthenticated remote command execution. CVSSv2 9.3 HIGH.",
        "patch": "Upgrade distcc to version > 3.1. Restrict distccd access with --allow firewall rules.",
        "source": "nse"},
    "CVE-2011-3556": {"cvss": 10.0, "severity": "critical",
        "description": "Java RMI registry default configuration allows remote classloading → unauthenticated RCE.",
        "patch": "Disable RMI registry. Restrict port 1099 with firewall. Upgrade to Java 7u2+.",
        "source": "nse"},
    "CVE-2017-0144": {"cvss": 9.8, "severity": "critical",
        "description": "EternalBlue: SMBv1 remote code execution — exploited by WannaCry and NotPetya ransomware.",
        "patch": "Apply MS17-010. Disable SMBv1. Block port 445 at perimeter.",
        "source": "nse"},
    "CVE-2014-3566": {"cvss": 3.4, "severity": "medium",
        "description": "SSL POODLE: SSLv3 CBC padding oracle allows MITM plaintext recovery.",
        "patch": "Disable SSLv3. Enforce TLS 1.2+. Apply vendor patches.",
        "source": "nse"},
    "CVE-2014-0224": {"cvss": 7.4, "severity": "high",
        "description": "OpenSSL CCS Injection: MITM attackers can hijack sessions via crafted TLS handshake.",
        "patch": "Upgrade OpenSSL to 0.9.8za, 1.0.0m, or 1.0.1h+.",
        "source": "nse"},
    "CVE-2015-4000": {"cvss": 3.7, "severity": "medium",
        "description": "Logjam: TLS DHE_EXPORT downgrade allows MITM to break 512-bit export DH encryption.",
        "patch": "Disable DHE_EXPORT ciphers. Use 2048-bit+ DH groups. Upgrade TLS libraries.",
        "source": "nse"},
    "CVE-2007-6750": {"cvss": 7.5, "severity": "high",
        "description": "Slowloris DoS: partial HTTP requests keep connections open, exhausting server resources.",
        "patch": "Enable mod_reqtimeout / RequestReadTimeout. Use nginx or a reverse proxy with timeout controls.",
        "source": "nse"},
    "CVE-2016-6515": {"cvss": 7.5, "severity": "high",
        "description": "OpenSSH very long password DoS — CPU exhaustion via crafted authentication request.",
        "patch": "Upgrade to OpenSSH 7.4+.",
        "source": "nse"},
}

_SEVERITY_FROM_CVSS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]

def _cvss_to_severity(score: float) -> str:
    for threshold, label in _SEVERITY_FROM_CVSS:
        if score >= threshold:
            return label
    return "info"



# Scripts that confirm vulnerabilities but don't print the CVE ID in their output
_NSE_FORCED_CVE = {
    "rmi-vuln-classloader":  "CVE-2011-3556",
    "irc-unrealircd-backdoor": "CVE-2010-2075",
    "smb-vuln-ms17-010":     "CVE-2017-0144",
    "smb-vuln-ms08-067":     "CVE-2008-4250",
}

def _parse_nse_scripts(port: dict) -> list:
    """
    Extract confirmed CVE findings from NSE script output embedded in a port dict.

    nmap --script vuln embeds script results as:
      port["scripts"] = [{"id": "ftp-vsftpd-backdoor", "output": "...VULNERABLE...CVE:CVE-2011-2523..."}]

    This function:
      1. Skips scripts that report NOT VULNERABLE / ERROR / no VULNERABLE keyword
      2. Extracts any CVE-XXXX-XXXX IDs mentioned
      3. Extracts CVSS scores if present (CVSSv2: N.N)
      4. Enriches with _KNOWN_CVES metadata where available
      5. Falls back to _NSE_SCRIPT_META defaults
      6. Deduplicates by CVE ID
    """
    scripts = port.get("scripts", [])
    if not scripts:
        return []

    results = []
    seen_cve_ids: set = set()

    for script in scripts:
        sid    = script.get("id", "").lower()
        output = script.get("output", "")

        # Skip clearly not-vulnerable / error scripts
        output_lower = output.lower()
        if not output_lower:
            continue
        not_vuln = (
            "not vulnerable" in output_lower
            or "false" == output_lower.strip()
            or ("error" in output_lower and "vulnerable" not in output_lower)
        )
        if not_vuln:
            continue

        is_vulnerable = (
            "vulnerable" in output_lower
            or "exploitable" in output_lower
            or "state: vulnerable" in output_lower
            or "state: likely vulnerable" in output_lower
        )
        # Also treat backdoor / RCE confirmation scripts as vulnerable even without keyword
        confirmed_scripts = {
            "ftp-vsftpd-backdoor", "distcc-cve2004-2687", "rmi-vuln-classloader",
            "irc-unrealircd-backdoor",
        }
        if not is_vulnerable and sid not in confirmed_scripts:
            continue

        # --- Extract CVE IDs from script output ---
        cve_ids_in_output = _re.findall(r'CVE-\d{4}-\d{4,7}', output, _re.IGNORECASE)
        cve_ids_in_output = [c.upper() for c in cve_ids_in_output]

        # --- Extract CVSS score if present ---
        cvss_match = _re.search(r'CVSSv2[:\s]+([0-9.]+)', output, _re.IGNORECASE)
        parsed_cvss = float(cvss_match.group(1)) if cvss_match else None

        # --- Get defaults from script meta ---
        meta = _NSE_SCRIPT_META.get(sid, (None, 5.0, "medium"))
        default_cvss = parsed_cvss or meta[1]
        default_sev  = _cvss_to_severity(default_cvss)

        # --- Build description from output (first 3 non-empty lines) ---
        raw_lines  = [l.strip() for l in output.splitlines() if l.strip()]
        # Filter out pure reference lines
        desc_lines = [l for l in raw_lines if not l.startswith("http") and not l.startswith("https") and not l.startswith("|") and "References:" not in l][:3]
        auto_desc  = " | ".join(desc_lines) if desc_lines else output[:200]

        # Apply forced CVE IDs for scripts whose output doesn't print CVE numbers
        forced_cve = _NSE_FORCED_CVE.get(sid)
        if forced_cve and forced_cve not in cve_ids_in_output:
            cve_ids_in_output.insert(0, forced_cve)

        if cve_ids_in_output:
            for cve_id in cve_ids_in_output:
                if cve_id in seen_cve_ids:
                    continue
                seen_cve_ids.add(cve_id)
                known = _KNOWN_CVES.get(cve_id, {})
                results.append({
                    "cve_id":      cve_id,
                    "cvss_score":  known.get("cvss", default_cvss),
                    "severity":    known.get("severity", default_sev),
                    "description": known.get("description", auto_desc),
                    "patch":       known.get("patch", f"See https://nvd.nist.gov/vuln/detail/{cve_id}"),
                    "source":      "nse",
                    "nse_script":  sid,
                })
        else:
            # Vulnerable script but no CVE ID extracted — create a synthetic finding
            synthetic_id = f"NSE-{sid.upper().replace('-', '_')}"
            if synthetic_id in seen_cve_ids:
                continue
            seen_cve_ids.add(synthetic_id)
            results.append({
                "cve_id":      synthetic_id,
                "cvss_score":  default_cvss,
                "severity":    default_sev,
                "description": auto_desc or f"NSE script '{sid}' reported a vulnerability.",
                "patch":       "Investigate findings from nmap script output and apply vendor patches.",
                "source":      "nse",
                "nse_script":  sid,
            })

    return results


# ── Public API ────────────────────────────────────────────────────────────────

def map_cves(versioned: dict) -> dict:
    """
    Map CVEs to every port in the scan result.

    Priority order (highest confidence first):
      1. NSE script confirmed findings (nmap --script vuln already proved exploitation)
      2. Local DB product/version lookup (fast, offline, curated)
      3. NVD live lookup (if NVD_API_KEY is set)

    NSE results take precedence because they are *confirmed* by active testing,
    not just inferred from version strings.
    """
    result = dict(versioned)
    use_nvd = bool(_NVD_API_KEY)
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            port["cves"] = _find_cves(port, use_nvd=use_nvd)
    return result


def _find_cves(port: dict, use_nvd: bool = False) -> list:
    service = port.get("service", "").lower().strip()
    product = port.get("product", "").lower().strip()
    version = port.get("version", "").lower().strip()

    # ── STEP 0: NSE Script results (highest confidence — confirmed by nmap) ──
    # When running --script vuln, nmap actively tests and confirms vulnerabilities.
    # These are far more reliable than version-based inference, so collect them first.
    nse_results = _parse_nse_scripts(port)
    nse_cve_ids: set = {c["cve_id"] for c in nse_results}

    # If no product/version detected (common with vuln_scan which lacks -sV),
    # try to infer the product from NSE script metadata so local DB can also run.
    if not product and not service and nse_results:
        # Use the first NSE result's script meta to hint the service
        first_script = nse_results[0].get("nse_script", "")
        meta = _NSE_SCRIPT_META.get(first_script)
        if meta and meta[0]:
            service = meta[0]

    # Build a set of candidate lookup keys (order = most specific first)
    candidates: list[str] = []
    if product:
        candidates.append(product)
    # Normalise common product aliases so they hit LOCAL_CVE_DB keys
    _aliases = {
        "apache":         "apache httpd",
        "apache httpd":   "apache httpd",
        "httpd":          "apache httpd",
        "openssh":        "openssh",
        "ssh":            "openssh",
        "vsftpd":         "vsftpd",
        "mysql":          "mysql",
        "mariadb":        "mysql",
        "nginx":          "nginx",
        "nginx http":     "nginx",
        "postfix":        "postfix",
        "postfix smtpd":  "postfix",
        "exim":           "exim",
        "samba":          "samba",
        "smbd":           "samba",
        "redis":          "redis",
        "mongodb":        "mongodb",
        "postgresql":     "postgresql",
        "postgres":       "postgresql",
        "tomcat":         "tomcat",
        "apache tomcat":  "tomcat",
        "isc bind":       "isc bind",
        "bind":           "isc bind",
        "named":          "isc bind",
        "net-snmp":       "net-snmp",
        "snmpd":          "net-snmp",
        "wordpress":      "wordpress",
        "drupal":         "drupal",
        "elasticsearch":  "elasticsearch",
        "jenkins":        "jenkins",
        "redis server":   "redis",
        "microsoft-ds":   "microsoft-ds",
        "ms-wbt-server":  "ms-wbt-server",
        "rdp":            "ms-wbt-server",
        "telnet":         "telnet",
        "java-rmi":       "java-rmi",
        "java rmi":       "java-rmi",
        "http-proxy":     "http-proxy",
    }
    # Add alias-resolved product
    for raw_key in [product, service]:
        if raw_key in _aliases:
            candidates.append(_aliases[raw_key])
        # partial prefix match (e.g. "apache httpd 2.4" → "apache httpd")
        for alias_key in _aliases:
            if raw_key.startswith(alias_key) or alias_key.startswith(raw_key):
                candidates.append(_aliases[alias_key])

    # Deduplicate preserving order
    seen: set = set()
    unique_candidates: list = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    matches = []
    matched_cve_ids: set = set()

    # Local DB lookup across all candidate keys
    for candidate in unique_candidates:
        for db_key, cve_list in LOCAL_CVE_DB.items():
            if db_key in candidate or candidate in db_key:
                for cve in cve_list:
                    if cve["cve_id"] in matched_cve_ids:
                        continue
                    if _affected(version, cve["affected"]):
                        matches.append({
                            "cve_id":      cve["cve_id"],
                            "cvss_score":  cve["cvss"],
                            "severity":    cve["severity"],
                            "description": cve["description"],
                            "patch":       cve["patch"],
                        })
                        matched_cve_ids.add(cve["cve_id"])

    # Optionally augment with live NVD lookup
    if use_nvd and (product or service):
        nvd_product = product or service
        nvd_results = _nvd_lookup(nvd_product, version)
        for c in nvd_results:
            if c["cve_id"] not in matched_cve_ids:
                matches.append(c)
                matched_cve_ids.add(c["cve_id"])

    # ── Merge NSE + local DB + NVD results, deduplicated ──────────────────────
    # NSE results come first (confirmed), then local DB, then NVD.
    # Remove any local/NVD entries that duplicate an NSE-confirmed CVE.
    final_cve_ids: set = set(nse_cve_ids)
    local_filtered = []
    for m in matches:
        if m["cve_id"] not in final_cve_ids:
            local_filtered.append(m)
            final_cve_ids.add(m["cve_id"])

    all_matches = nse_results + local_filtered
    all_matches.sort(key=lambda x: x["cvss_score"], reverse=True)
    return all_matches


def _affected(detected: str, patterns: list) -> bool:
    """Return True if the detected version string matches any pattern.

    Rules:
      - Empty detected  → False (no version info, cannot confirm affected)
      - Empty pattern   → True  (version-agnostic CVE — always affected)
      - Otherwise check prefix match in both directions (e.g. "7.4" in "7.",
        or "7.4.1" detected against "7." pattern).
    """
    if not detected:
        return False
    for p in patterns:
        if p == "":          # version-agnostic CVE (e.g. EternalBlue)
            return True
        if detected.startswith(p) or p.startswith(detected[:len(p)]):
            return True
    return False


# Expose for testing
_version_affected = _affected
