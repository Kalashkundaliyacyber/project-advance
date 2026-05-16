"""Nmap XML Output Parser — converts nmap -oX output to structured JSON."""
import xml.etree.ElementTree as ET
from typing import Optional


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

    return port
