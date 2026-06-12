"""Nmap XML Output Parser — converts nmap -oX output to structured JSON."""
import xml.etree.ElementTree as ET
import re as _re
from typing import Optional


# ── Vuln Script Status Analysis ───────────────────────────────────────────────
# These are the three statuses a port can have after vuln script analysis:
#   CONFIRMED   — NSE script ran and found the service IS vulnerable
#   NOT_VULNERABLE — NSE script ran and confirmed the service is NOT vulnerable
#   UNCONFIRMED — CVE/version match found but no NSE script could confirm it

_VULN_POSITIVE_RE = _re.compile(
    r'\bVULNERABLE\b(?!\s+TO\s+NOT|\s+NOT)',
    _re.IGNORECASE
)
_VULN_NEGATIVE_RE = _re.compile(
    r'NOT\s+VULNERABLE|State:\s*NOT\s+VULNERABLE|not\s+vulnerable|patched',
    _re.IGNORECASE
)
_SCRIPT_IDS_VULN = {
    # Known vuln-category NSE scripts that produce definitive output
    'http-vuln', 'smb-vuln', 'ftp-vuln', 'ssh-vuln', 'ssl-',
    'ms17-010', 'ms08-067', 'cve-', 'exploit', 'vsftpd-backdoor',
    'samba-vuln', 'realvnc-auth-bypass', 'distcc-cve2004',
}


def analyze_script_vuln_status(scripts: list) -> dict:
    """
    Analyse the NSE script output for a port and return a verdict:
      {
        "status":      "CONFIRMED" | "NOT_VULNERABLE" | "UNCONFIRMED",
        "script_used": "script-id or None",
        "evidence":    "short excerpt from script output"
      }
    Called both during full-parse AND during the live streaming parse.
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

        if _VULN_POSITIVE_RE.search(output):
            confirmed_scripts.append((sid, output))
        elif _VULN_NEGATIVE_RE.search(output):
            not_vuln_scripts.append((sid, output))

    if confirmed_scripts:
        sid, output = confirmed_scripts[0]
        # Extract a short evidence line (first line containing VULNERABLE)
        evidence = ""
        for line in output.splitlines():
            if _VULN_POSITIVE_RE.search(line):
                evidence = line.strip()[:120]
                break
        return {"status": "CONFIRMED", "script_used": sid, "evidence": evidence}

    if not_vuln_scripts:
        sid, output = not_vuln_scripts[0]
        return {"status": "NOT_VULNERABLE", "script_used": sid, "evidence": "Script confirmed: not vulnerable"}

    # Scripts ran but produced no definitive output — treat as UNCONFIRMED
    if scripts:
        return {"status": "UNCONFIRMED", "script_used": scripts[0].get("id"), "evidence": "Script ran but no definitive result"}

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

    # Determine vuln_status from NSE script output
    port["vuln_status"] = analyze_script_vuln_status(scripts)

    return port
