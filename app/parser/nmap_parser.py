"""Nmap XML Output Parser — converts nmap -oX output to structured JSON."""
import xml.etree.ElementTree as ET
import re as _re
from typing import Optional


# ── Vuln Script Status Analysis ───────────────────────────────────────────────
# These are the three statuses a port can have after vuln script analysis:
#   CONFIRMED   — NSE script ran and found the service IS vulnerable
#   NOT_VULNERABLE — NSE script ran and confirmed the service is NOT vulnerable
#   UNCONFIRMED — CVE/version match found but no NSE script could confirm it
#
# SAFE-BEFORE-CONFIRMED rule (enforced throughout):
#   Negative indicators are always checked FIRST so "NOT VULNERABLE" can never
#   be misclassified as CONFIRMED.  The old regex used a lookahead that checked
#   what came AFTER "VULNERABLE" — but "NOT VULNERABLE" has NOT *before*
#   VULNERABLE, so the lookahead never fired and every "NOT VULNERABLE" string
#   was incorrectly treated as a positive match.
#
# FIX (v4.1): _VULN_POSITIVE_RE now uses explicit positive evidence patterns
#   (State: VULNERABLE, VULNERABLE: on its own, known backdoor outputs, etc.)
#   instead of a bare \bVULNERABLE\b keyword match.  The check order in
#   analyze_script_vuln_status() is also flipped: negative first, then positive.

# ── NEGATIVE patterns — checked FIRST ────────────────────────────────────────
_VULN_NEGATIVE_RE = _re.compile(
    r'NOT\s+VULNERABLE'
    r'|State:\s*NOT\s+VULNERABLE'
    r'|not\s+vulnerable'
    r'|not\s+exim'          # smtp-vuln-cve2010-4344 on Postfix
    r'|not\s+running\s+exim'
    r'|server\s+is\s+not\s+exim'
    r'|not\s+affected'
    r'|patched'
    # FIX: bare r'disabled' was too broad — it matched "message_signing: disabled"
    # (a HIGH-severity Samba misconfiguration) and silently killed that finding.
    # Narrowed to only contexts where "disabled" genuinely means "feature is off/safe".
    r'|\b(webdav|ssl|tls|compression)\s+disabled\b'
    r'|target\s+is\s+not\s+vulnerable'
    r'|server\s+is\s+not\s+vulnerable'
    r'|host\s+is\s+not\s+vulnerable'
    r'|does\s+not\s+appear\s+to\s+be\s+vulnerable',
    _re.IGNORECASE,
)

# ── POSITIVE patterns — checked SECOND (only if negative did NOT match) ───────
# These are explicit, unambiguous evidence strings that NSE scripts emit when
# they actually confirm a vulnerability.  Never use bare "VULNERABLE" — it
# always appears inside "NOT VULNERABLE" and causes false positives.
_VULN_POSITIVE_RE = _re.compile(
    r'State:\s*VULNERABLE(?!\s*\(not\s+exploitable\))'   # nmap standard format
    r'|^\|\s*VULNERABLE:\s*$'           # | VULNERABLE: on its own line
    r'|VULNERABLE:\s*\n'                # VULNERABLE: followed by newline
    r'|successfully\s+exploited'
    r'|backdoor\s+was\s+installed'
    r'|authentication\s+bypass'
    r'|command\s+executed'
    r'|shell\s+spawned'
    r'|looks\s+like\s+trojaned'         # irc-unrealircd-backdoor output
    r'|trojaned\s+version'              # irc-unrealircd-backdoor variant
    r'|looks\s+like\s+the\s+trojanned'  # irc-unrealircd-backdoor full phrase
    r'|backdoor\s+found'                # generic backdoor confirmation
    # FIX: http-vuln-cve2012-1823 (PHP-CGI) does NOT use vulns.lua "State:" format.
    # It outputs freeform text: "The website seems vulnerable to CVE-2012-1823"
    # followed by the result of the executed command (e.g. uname -a output).
    # Without these patterns this script's confirmed RCE was silently discarded.
    r'|seems\s+(to\s+be\s+)?vulnerable'             # http-vuln-cve2012-1823
    r'|Output\s+of\s+the\s+command'                 # PHP-CGI executed uname -a
    # FIX: http-vuln-cve2014-3704 (Drupalgeddon) outputs this line on successful
    # exploitation.  Without this pattern the created admin user was never surfaced.
    r'|adding\s+admin\s+user'                        # Drupalgeddon confirmed
    # FIX: uid= return from a shell command proves code execution.
    r'|uid=\d+\(\w+\)\s+gid=\d+',
    _re.IGNORECASE | _re.MULTILINE,
)

_SCRIPT_IDS_VULN = {
    # Known vuln-category NSE scripts that produce definitive output.
    # FIX: Added 'backdoor' so irc-unrealircd-backdoor and ftp-vsftpd-backdoor
    # are processed.  Added 'rmi-vuln' for Java RMI class-loader check.
    # Added 'distcc' and 'realvnc' explicitly for clarity.
    'http-vuln', 'smb-vuln', 'ftp-vuln', 'ssh-vuln', 'ssl-', 'smtp-vuln',
    'mysql-vuln', 'irc-', 'rmi-vuln', 'rdp-vuln', 'snmp-vuln',
    'ms17-010', 'ms08-067', 'ms12-020', 'cve-',
    'backdoor',                         # FIX: captures irc-unrealircd-backdoor
    'vsftpd-backdoor',
    'samba-vuln', 'realvnc-auth-bypass', 'distcc-cve2004',
}

# ── FIX (multi-vulnerability-per-port visibility) ──────────────────────────
# nmap's vulns.lua NSE library frequently reports SEVERAL distinct named
# vulnerabilities inside ONE script's output — e.g. ssl-dh-params on this
# very Metasploitable box reports three separate findings (anonymous DH,
# Logjam, insufficient DH group strength), each with its own
# "<Title>\n  State: ...\n  IDs: CVE:...\n    <description>" block, all
# concatenated into a single <script output="..."> string. The functions
# below split that back apart so every named vulnerability can be shown
# individually instead of being collapsed into one generic "VULNERABLE"
# line for the whole script.
_VULN_BLOCK_RE = _re.compile(
    r'^[ \t]*(?P<title>[^\n]+?)\r?\n'
    r'[ \t]*State:\s*(?P<state>VULNERABLE\s*\(Exploitable\)|VULNERABLE|LIKELY\s+VULNERABLE|NOT\s+VULNERABLE)',
    _re.MULTILINE,
)
_VULN_BLOCK_META_RE = _re.compile(
    r'^(IDs:|Risk\s+factor:|Disclosure\s+date:|Check\s+results:|Exploit\s+results:'
    r'|Extra\s+information:|References:|https?://)'
)
_CVE_RE = _re.compile(r'CVE-\d{4}-\d+')


def split_vuln_blocks(output: str) -> list:
    """
    Split a single NSE script's raw output into individual named-vulnerability
    findings, if it follows nmap's vulns.lua "Title / State: / IDs: /
    description" block format. Returns [] if the script doesn't use that
    format (e.g. one-liners like smtp-vuln-cve2010-4344, or the unrelated
    'vulners' CVE-correlation script, which has no "State:" lines at all).
    """
    if not output or "State:" not in output:
        return []
    matches = list(_VULN_BLOCK_RE.finditer(output))
    if not matches:
        return []

    blocks = []
    for i, m in enumerate(matches):
        title = m.group("title").strip().rstrip(":").strip()
        if not title or title.upper() == "VULNERABLE":
            continue
        state = _re.sub(r"\s+", " ", m.group("state").upper())
        start = m.end()
        end   = matches[i + 1].start() if i + 1 < len(matches) else len(output)
        block_text = output[start:end]

        cve_match = _CVE_RE.search(block_text)
        cve = cve_match.group(0) if cve_match else None

        evidence = ""
        for line in block_text.splitlines():
            stripped = line.strip()
            if not stripped or _VULN_BLOCK_META_RE.match(stripped):
                continue
            evidence = stripped
            break
        if not evidence:
            evidence = f"{title} — {state}"

        if "NOT" in state:
            status = "NOT_VULNERABLE"
        elif "LIKELY" in state:
            status = "POTENTIALLY_VULNERABLE"
        else:
            status = "CONFIRMED"

        blocks.append({"title": title, "status": status, "cve": cve, "evidence": evidence[:200]})
    return blocks


def extract_all_script_findings(scripts: list) -> list:
    """
    Return EVERY distinct finding on a port, across EVERY script — the
    complement to analyze_script_vuln_status() above, which deliberately
    collapses everything down to ONE summary verdict for badge/sorting
    purposes elsewhere in the app. This function keeps all of them, so a
    port like 25 (ssl-dh-params: 3 named vulnerabilities + ssl-poodle: 1)
    can show all 4 instead of just the one analyze_script_vuln_status()
    happened to pick as primary.

    Each finding: {title, status, script, cve, evidence}.
    """
    findings = []
    for sc in scripts:
        sid    = (sc.get("id") or "").lower()
        output = sc.get("output") or ""
        if not output:
            continue

        blocks = split_vuln_blocks(output)
        if blocks:
            for b in blocks:
                findings.append({
                    "title":    b["title"],
                    "status":   b["status"],
                    "script":   sid,
                    "cve":      b["cve"],
                    "evidence": b["evidence"],
                })
            continue

        # No vulns.lua-style block — only fall back to a single whole-script
        # verdict for scripts that actually look like vulnerability checks
        # (same scoping analyze_script_vuln_status() uses above), so this
        # doesn't manufacture findings out of unrelated scripts.
        is_vuln_script = any(kw in sid for kw in _SCRIPT_IDS_VULN) or "vuln" in sid
        if not is_vuln_script:
            continue

        if _VULN_NEGATIVE_RE.search(output):
            line = next((l.strip().lstrip("|_ ") for l in output.splitlines()
                         if l.strip() and _VULN_NEGATIVE_RE.search(l)), "")
            findings.append({
                "title": sid, "status": "NOT_VULNERABLE", "script": sid,
                "cve": None, "evidence": line or "Script confirmed: not vulnerable",
            })
        elif _VULN_POSITIVE_RE.search(output):
            line = next((l.strip().lstrip("|_ ") for l in output.splitlines()
                         if l.strip() and _VULN_POSITIVE_RE.search(l)), "")
            findings.append({
                "title": sid, "status": "CONFIRMED", "script": sid,
                "cve": None, "evidence": line or output.strip()[:120],
            })
    return findings


def analyze_script_vuln_status(scripts: list) -> dict:
    """
    Analyse the NSE script output for a port and return a verdict:
      {
        "status":      "CONFIRMED" | "NOT_VULNERABLE" | "UNCONFIRMED",
        "script_used": "script-id or None",
        "evidence":    "short excerpt from script output"
      }
    Called both during full-parse AND during the live streaming parse.

    SAFE-BEFORE-CONFIRMED: negative check always runs before positive so
    "NOT VULNERABLE" text can never be misclassified as CONFIRMED.
    """
    if not scripts:
        return {"status": "UNCONFIRMED", "script_used": None, "evidence": ""}

    confirmed_scripts = []
    not_vuln_scripts  = []

    for sc in scripts:
        sid    = (sc.get("id") or "").lower()
        output = sc.get("output") or ""

        # Only consider vuln-category scripts
        is_vuln_script = any(kw in sid for kw in _SCRIPT_IDS_VULN)
        if not is_vuln_script and "vuln" not in sid:
            continue

        # ── SAFE FIRST: negative check before positive ──
        # This is the critical ordering fix — the old code checked positive
        # first, causing "NOT VULNERABLE" to be misread as CONFIRMED.
        if _VULN_NEGATIVE_RE.search(output):
            not_vuln_scripts.append((sid, output))
        elif _VULN_POSITIVE_RE.search(output):
            confirmed_scripts.append((sid, output))

    if confirmed_scripts:
        sid, output = confirmed_scripts[0]
        # Extract a short evidence line (first line matching a positive pattern)
        evidence = ""
        for line in output.splitlines():
            stripped = line.strip()
            if stripped and _VULN_POSITIVE_RE.search(stripped):
                evidence = stripped[:120]
                break
        if not evidence:
            # Fallback: first non-empty script output line
            for line in output.splitlines():
                stripped = line.strip().lstrip("|_ ")
                if stripped:
                    evidence = stripped[:120]
                    break
        return {"status": "CONFIRMED", "script_used": sid, "evidence": evidence}

    if not_vuln_scripts:
        sid, output = not_vuln_scripts[0]
        # Include the actual "not vulnerable" line as evidence
        evidence = ""
        for line in output.splitlines():
            stripped = line.strip().lstrip("|_ ")
            if stripped and _VULN_NEGATIVE_RE.search(stripped):
                evidence = stripped[:120]
                break
        return {
            "status":     "NOT_VULNERABLE",
            "script_used": sid,
            "evidence":   evidence or "Script confirmed: not vulnerable",
        }

    # Scripts ran but produced no definitive output — treat as UNCONFIRMED
    if scripts:
        return {
            "status":     "UNCONFIRMED",
            "script_used": scripts[0].get("id"),
            "evidence":   "Script ran but no definitive result",
        }

    return {"status": "UNCONFIRMED", "script_used": None, "evidence": ""}


def parse_nmap_output(xml_output: str, raw_output: str = "") -> dict:
    result = {
        "hosts":        [],
        "scan_summary": {},
        "raw_length":   len(raw_output),
        "simulated":    "[SIMULATED" in raw_output,
    }
    try:
        root = ET.fromstring(xml_output.strip())
    except ET.ParseError as e:
        result["parse_error"] = str(e)
        return result

    run_stats = root.find("runstats")
    if run_stats is not None:
        fin        = run_stats.find("finished")
        hosts_elem = run_stats.find("hosts")
        # Use "is not None" — Python 3.13 deprecated truthiness test on XML elements
        if fin is not None:
            result["scan_summary"]["elapsed"] = fin.get("elapsed", "?")
            result["scan_summary"]["summary"] = fin.get("summary", "")
        if hosts_elem is not None:
            result["scan_summary"]["hosts_up"]    = hosts_elem.get("up", "0")
            result["scan_summary"]["hosts_total"] = hosts_elem.get("total", "0")

    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host is not None:
            result["hosts"].append(host)

    return result


def _parse_host(host_elem) -> Optional[dict]:
    status = host_elem.find("status")
    if status is None or status.get("state") != "up":
        return None

    host = {"ip": "", "hostnames": [], "os": None, "ports": []}

    for addr in host_elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            host["ip"] = addr.get("addr", "")
        elif addr.get("addrtype") == "mac":
            host["mac"]    = addr.get("addr", "")
            host["vendor"] = addr.get("vendor", "")

    hn_elem = host_elem.find("hostnames")
    if hn_elem is not None:
        for hn in hn_elem.findall("hostname"):
            host["hostnames"].append(hn.get("name", ""))

    os_elem = host_elem.find("os")
    if os_elem is not None:
        matches = os_elem.findall("osmatch")
        if matches:
            best = matches[0]
            host["os"] = {
                "name":     best.get("name", "Unknown"),
                "accuracy": best.get("accuracy", "0"),
            }

    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for pe in ports_elem.findall("port"):
            p = _parse_port(pe)
            if p is not None:
                host["ports"].append(p)

    return host


def _parse_port(port_elem) -> Optional[dict]:
    state_elem = port_elem.find("state")
    if state_elem is None:
        return None
    state = state_elem.get("state", "unknown")
    if state not in ("open", "open|filtered"):
        return None

    port = {
        "port":       int(port_elem.get("portid", 0)),
        "protocol":   port_elem.get("protocol", "tcp"),
        "state":      state,
        "service":    "",
        "product":    "",
        "version":    "",
        "extra_info": "",
        "confidence": 0,
        "method":     "",
    }

    svc = port_elem.find("service")
    if svc is not None:
        port["service"]    = svc.get("name", "")
        port["product"]    = svc.get("product", "")
        port["version"]    = svc.get("version", "")
        port["extra_info"] = svc.get("extrainfo", "")
        port["confidence"] = int(svc.get("conf", 0))
        port["method"]     = svc.get("method", "")

    scripts = []
    for sc in port_elem.findall("script"):
        scripts.append({"id": sc.get("id", ""), "output": sc.get("output", "")})
    if scripts:
        port["scripts"] = scripts

    # Determine vuln_status from NSE script output (single summary verdict —
    # used for badges/sorting/the live-confirmation decision elsewhere).
    port["vuln_status"] = analyze_script_vuln_status(scripts)

    # FIX (multi-vulnerability-per-port visibility): full breakdown of every
    # distinct finding on this port, not just the one picked above as
    # primary. See extract_all_script_findings() docstring.
    port["all_findings"] = extract_all_script_findings(scripts)

    return port
