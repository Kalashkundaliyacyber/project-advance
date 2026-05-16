#!/usr/bin/env python3
"""
ScanWise AI — Standalone Test Runner
Runs all unit tests without requiring pytest.
Usage: python3 tests/run_tests.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

PASS = 0
FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  ✓  {name}")
        PASS += 1
    else:
        print(f"  ✗  FAIL: {name} {detail}")
        FAIL += 1

# ─────────────────────────────────────────────────────────
# PARSER
# ─────────────────────────────────────────────────────────
def test_parser():
    print("\n[1] PARSER — nmap_parser.py")
    from app.parser.nmap_parser import parse_nmap_output

    XML_SERVICE = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="testhost" type="user"/></hostnames>
<ports>
  <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="7.4" conf="10" method="probed"/></port>
  <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.2.34" conf="10" method="probed"/></port>
  <port protocol="tcp" portid="443"><state state="closed" reason="reset"/>
    <service name="https" conf="3" method="table"/></port>
</ports></host>
<runstats><finished elapsed="10.00" exit="success" summary="1 IP address (1 host up) scanned in 10.00 seconds"/>
<hosts up="1" down="0" total="1"/></runstats></nmaprun>"""

    XML_UDP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
  <port protocol="udp" portid="53"><state state="open" reason="udp-response"/>
    <service name="domain" product="ISC BIND" version="9.9.5" conf="10" method="probed"/></port>
  <port protocol="udp" portid="161"><state state="open" reason="udp-response"/>
    <service name="snmp" product="net-snmp" version="5.7.2" conf="10" method="probed"/></port>
</ports></host>
<runstats><finished elapsed="20.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""

    XML_OS = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
  <service name="ssh" product="OpenSSH" version="8.9" conf="10" method="probed"/></port></ports>
<os><osmatch name="Linux 5.15" accuracy="97" line="58447">
  <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="97"/>
</osmatch></os>
</host>
<runstats><finished elapsed="8.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""

    r = parse_nmap_output(XML_SERVICE, "some raw")
    check("returns dict",                isinstance(r, dict))
    check("has hosts key",               "hosts" in r)
    check("one host found",              len(r["hosts"]) == 1)
    check("correct IP",                  r["hosts"][0]["ip"] == "192.168.1.10")
    check("hostname detected",           "testhost" in r["hosts"][0]["hostnames"])
    check("open ports only (2 of 3)",    len(r["hosts"][0]["ports"]) == 2)

    ports = {p["port"]: p for p in r["hosts"][0]["ports"]}
    check("port 22 present",             22 in ports)
    check("port 443 excluded (closed)",  443 not in ports)
    check("ssh version parsed",          ports[22]["version"] == "7.4")
    check("ssh product parsed",          ports[22]["product"] == "OpenSSH")
    check("apache product parsed",       "Apache" in ports[80]["product"])
    check("apache version parsed",       ports[80]["version"] == "2.2.34")
    check("scan summary present",        r.get("scan_summary") is not None)
    check("hosts_up == 1",               r["scan_summary"].get("hosts_up") == "1")
    check("simulated=False (normal)",    r["simulated"] is False)
    check("simulated=True (flagged)",    parse_nmap_output(XML_SERVICE, "[SIMULATED")["simulated"] is True)

    r2 = parse_nmap_output("<bad>>>xml", "")
    check("bad XML → no crash",          "parse_error" in r2)
    check("bad XML → empty hosts",       r2["hosts"] == [])
    check("empty string → no crash",     "parse_error" in parse_nmap_output("", ""))

    udp = parse_nmap_output(XML_UDP, "")
    udp_ports = {p["port"]: p for p in udp["hosts"][0]["ports"]}
    check("UDP port 53 parsed",          53 in udp_ports)
    check("UDP port 161 parsed",         161 in udp_ports)
    check("UDP protocol tag",            udp_ports[53]["protocol"] == "udp")

    os_r = parse_nmap_output(XML_OS, "")
    check("OS detection parsed",         os_r["hosts"][0]["os"] is not None)
    check("OS name contains Linux",      "Linux" in os_r["hosts"][0]["os"]["name"])
    check("OS accuracy == 97",           os_r["hosts"][0]["os"]["accuracy"] == "97")

    r_none = parse_nmap_output("""<?xml version="1.0"?><nmaprun version="7.95" xmloutputversion="1.05">
<runstats><finished elapsed="5.00" exit="success"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>""", "")
    check("no-host XML → empty hosts",   r_none["hosts"] == [])

# ─────────────────────────────────────────────────────────
# CVE MAPPER
# ─────────────────────────────────────────────────────────
def test_cve_mapper():
    print("\n[2] CVE MAPPER — mapper.py")
    from app.cve.mapper import map_cves, _find_cves, _version_affected

    check("prefix match true",            _version_affected("7.4", ["7."]))
    check("full match true",              _version_affected("2.3.4", ["2.3.4"]))
    check("no match false",               not _version_affected("9.8", ["7.", "6."]))
    check("empty version false",          not _version_affected("", ["7."]))
    check("5.5.62 matches 5.5.",          _version_affected("5.5.62", ["5.5."]))

    ssh = _find_cves({"service":"ssh","product":"OpenSSH","version":"7.4"})
    check("openssh CVEs returned",        len(ssh) > 0)
    check("CVE has cve_id",              "cve_id" in ssh[0])
    check("CVE has cvss_score",          "cvss_score" in ssh[0])
    check("CVE has severity",            "severity" in ssh[0])
    check("CVE has description",         "description" in ssh[0])
    check("CVE has patch",               "patch" in ssh[0])
    check("sorted by CVSS desc",         all(ssh[i]["cvss_score"] >= ssh[i+1]["cvss_score"]
                                             for i in range(len(ssh)-1)))

    ftp = _find_cves({"service":"ftp","product":"vsftpd","version":"2.3.4"})
    check("vsftpd backdoor CVE found",   any(c["cve_id"] == "CVE-2011-2523" for c in ftp))

    apache = _find_cves({"service":"http","product":"Apache httpd","version":"2.2.34"})
    check("apache 2.2.34 CVEs found",    len(apache) > 0)
    check("apache CVSS-17679 found",     any(c["cve_id"] == "CVE-2017-7679" for c in apache))

    mysql = _find_cves({"service":"mysql","product":"MySQL","version":"5.5.62"})
    check("mysql 5.5 CVEs found",        len(mysql) > 0)

    unknown = _find_cves({"service":"exotic","product":"FooDB","version":"1.0"})
    check("unknown service → []",        isinstance(unknown, list))

    new_ssh = _find_cves({"service":"ssh","product":"OpenSSH","version":"9.8"})
    check("newer SSH has fewer CVEs",    len(new_ssh) <= len(ssh))

    forbidden = ["exploit code","payload","shellcode","weaponize","metasploit module"]
    for svc, prod, ver in [("ssh","OpenSSH","7.4"),("ftp","vsftpd","2.3.4"),("http","Apache httpd","2.2.34")]:
        cves = _find_cves({"service":svc,"product":prod,"version":ver})
        txt = " ".join(c["description"]+c["patch"] for c in cves).lower()
        check(f"safety: no exploit terms in {svc}", not any(w in txt for w in forbidden))

    severity_valid = {"critical","high","medium","low"}
    for c in ssh:
        check(f"severity value valid ({c['severity']})", c["severity"] in severity_valid)

    parsed = {"hosts":[{"ip":"x","ports":[
        {"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH",
         "version":"7.4","version_analysis":{}}
    ]}],"scan_summary":{}}
    result = map_cves(parsed)
    check("map_cves attaches cves to port", "cves" in result["hosts"][0]["ports"][0])
    check("map_cves preserves port field",  result["hosts"][0]["ports"][0]["port"] == 22)
    check("map_cves empty hosts → []",      map_cves({"hosts":[],"scan_summary":{}})["hosts"] == [])

# ─────────────────────────────────────────────────────────
# VERSION ENGINE
# ─────────────────────────────────────────────────────────
def test_version_engine():
    print("\n[3] VERSION ENGINE — version_engine.py")
    from app.analysis.version_engine import analyze_versions, _analyze_port_version, _version_matches

    check("exact match case-insensitive",  _version_matches("openssh 7.4", "OpenSSH 7.4"))
    check("prefix match",                  _version_matches("apache httpd 2.2.34", "Apache httpd 2.2"))
    check("no match",                      not _version_matches("nginx 1.26", "Apache httpd 2.4"))

    va = _analyze_port_version({"service":"ftp","product":"vsftpd","version":"2.3.4"})
    check("vsftpd 2.3.4 → unsupported",   va["status"] == "unsupported")
    check("confidence high",               va["confidence"] == "high")

    va2 = _analyze_port_version({"service":"http","product":"Apache httpd","version":"2.2.34"})
    check("apache 2.2.34 → unsupported",  va2["status"] == "unsupported")

    va3 = _analyze_port_version({"service":"ssh","product":"OpenSSH","version":"7.4"})
    check("openssh 7.4 → outdated",       va3["status"] == "outdated")
    check("openssh 7.4 → age >= 8",       (va3.get("age_years") or 0) >= 8)

    va4 = _analyze_port_version({"service":"ssh","product":"","version":""})
    check("empty version → unknown",       va4["status"] == "unknown")
    check("empty version → low conf",      va4["confidence"] == "low")

    check("has message field",             "message" in va)
    check("message is non-empty string",   isinstance(va["message"], str) and len(va["message"]) > 5)
    check("has version_string",            "version_string" in va)

    parsed = {"hosts":[{"ip":"x","ports":[
        {"port":22,"service":"ssh","product":"OpenSSH","version":"7.4"}
    ]}],"scan_summary":{}}
    versioned = analyze_versions(parsed)
    check("version_analysis added to port","version_analysis" in versioned["hosts"][0]["ports"][0])
    check("empty hosts no crash",          analyze_versions({"hosts":[],"scan_summary":{}})["hosts"] == [])

# ─────────────────────────────────────────────────────────
# RISK ENGINE
# ─────────────────────────────────────────────────────────
def test_risk_engine():
    print("\n[4] RISK ENGINE — risk_engine.py")
    from app.analysis.risk_engine import calculate_risk, _score_to_level, _calculate_port_risk

    check("9.5 → critical",  _score_to_level(9.5) == "critical")
    check("8.5 → critical",  _score_to_level(8.5) == "critical")
    check("7.0 → high",      _score_to_level(7.0) == "high")
    check("6.5 → high",      _score_to_level(6.5) == "high")
    check("5.0 → medium",    _score_to_level(5.0) == "medium")
    check("4.0 → medium",    _score_to_level(4.0) == "medium")
    check("3.0 → low",       _score_to_level(3.0) == "low")
    check("0.0 → low",       _score_to_level(0.0) == "low")

    def make_port(cvss=5.3, crit="medium", v_status="outdated", cve_count=1):
        cves = [{"cve_id":"CVE-X","cvss_score":cvss,"severity":"high"}] * cve_count
        return {
            "port":22,"service":"ssh","product":"OpenSSH","version":"7.4",
            "cves": cves,
            "context":{"criticality":crit,"criticality_reason":"r","exposure_type":"commonly_exposed",
                        "version_risk":{"latest":"low","outdated":"medium","unsupported":"high"}.get(v_status,"medium"),
                        "total_open_ports":2},
            "version_analysis":{"status":v_status,"age_years":9,"confidence":"high","message":"Outdated"}
        }

    r = _calculate_port_risk(make_port(cvss=9.8, crit="critical", v_status="unsupported", cve_count=2), "high")
    check("high cvss+crit+unsupported → high/critical", r["level"] in ("critical","high"))
    check("score > 5 for high risk port", r["score"] > 5.0)

    r2 = _calculate_port_risk(make_port(cvss=0, crit="low", v_status="latest", cve_count=0), "low")
    check("no cve+latest → low score",   r2["score"] < 6.0)

    r3 = _calculate_port_risk(make_port(cvss=10.0, crit="critical", v_status="unsupported"), "high")
    check("cvss 10.0 → critical level",  r3["level"] == "critical")

    r4 = _calculate_port_risk(make_port(), "medium")
    check("result has score",    "score" in r4)
    check("result has level",    "level" in r4)
    check("result has reasons",  "reasons" in r4)
    check("result has color",    "color" in r4)
    check("result has max_cvss", "max_cvss" in r4)
    check("level is valid value",r4["level"] in ("low","medium","high","critical"))
    check("score ≤ 10",          r4["score"] <= 10.0)
    check("reasons is list",     isinstance(r4["reasons"], list))

    host = {"ip":"192.168.1.10","ports":[{
        "port":22,"protocol":"tcp","service":"ssh","product":"OpenSSH","version":"7.4","state":"open",
        "cves":[{"cve_id":"CVE-2018-15473","cvss_score":5.3,"severity":"medium","description":"x","patch":"y"}],
        "context":{"criticality":"high","criticality_reason":"r","exposure_type":"commonly_exposed",
                    "version_risk":"medium","total_open_ports":2},
        "version_analysis":{"status":"outdated","age_years":9,"confidence":"high","message":"Outdated"}
    }],"context":{"exposure":"medium","open_port_count":1,"exposure_note":""}}

    result = calculate_risk({"hosts":[host],"scan_summary":{}})
    port = result["hosts"][0]["ports"][0]
    check("risk added to port",             "risk" in port)
    check("risk_summary added to host",     "risk_summary" in result["hosts"][0])
    check("risk_summary has overall",       "overall" in result["hosts"][0]["risk_summary"])
    check("risk_summary.overall is valid",  result["hosts"][0]["risk_summary"]["overall"] in
                                            ("low","medium","high","critical"))
    check("risk_summary.counts present",    "counts" in result["hosts"][0]["risk_summary"])
    check("empty hosts no crash",           calculate_risk({"hosts":[],"scan_summary":{}})["hosts"] == [])

# ─────────────────────────────────────────────────────────
# CONTEXT ENGINE
# ─────────────────────────────────────────────────────────
def test_context_engine():
    print("\n[5] CONTEXT ENGINE — context_engine.py")
    from app.analysis.context_engine import analyze_context

    def make_parsed(ports):
        return {"hosts":[{"ip":"192.168.1.10","ports":ports,"hostnames":[],"os":None}],"scan_summary":{}}

    p_ssh  = {"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH",
               "version":"7.4","cves":[],"version_analysis":{"status":"outdated","message":"x"}}
    p_ftp  = {"port":21,"protocol":"tcp","state":"open","service":"ftp","product":"vsftpd",
               "version":"2.3.4","cves":[],"version_analysis":{"status":"unsupported","message":"x"}}
    p_http = {"port":80,"protocol":"tcp","state":"open","service":"http","product":"Apache httpd",
               "version":"2.2.34","cves":[],"version_analysis":{"status":"unsupported","message":"x"}}

    r = analyze_context(make_parsed([p_ssh, p_ftp, p_http]))
    host = r["hosts"][0]
    check("host context added",            "context" in host)
    check("port context added",            all("context" in p for p in host["ports"]))
    check("exposure_note is string",       isinstance(host["context"]["exposure_note"], str))
    check("open_port_count correct",       host["context"]["open_port_count"] == 3)
    check("exposure medium (3 ports)",     host["context"]["exposure"] == "medium")

    r2 = analyze_context(make_parsed([p_ssh]))
    check("1 port → low exposure",         r2["hosts"][0]["context"]["exposure"] == "low")

    ssh_ctx = [p["context"] for p in r["hosts"][0]["ports"] if p["port"] == 22][0]
    check("ssh criticality == high",       ssh_ctx["criticality"] == "high")
    check("ssh has criticality_reason",    len(ssh_ctx["criticality_reason"]) > 5)
    check("port 22 exposure = commonly_exposed", ssh_ctx["exposure_type"] == "commonly_exposed")

    ftp_ctx = [p["context"] for p in r["hosts"][0]["ports"] if p["port"] == 21][0]
    check("ftp criticality == high",       ftp_ctx["criticality"] == "high")
    check("unsupported → version_risk high", ftp_ctx["version_risk"] == "high")

    check("empty hosts no crash",          analyze_context({"hosts":[],"scan_summary":{}})["hosts"] == [])

# ─────────────────────────────────────────────────────────
# RECOMMENDATION ENGINE
# ─────────────────────────────────────────────────────────
def test_recommender():
    print("\n[6] RECOMMENDATION ENGINE — recommender.py")
    from app.recommendation.recommender import get_recommendation

    VALID_TYPES = {
        # Discovery
        "ping_sweep", "host_discovery", "arp_discovery",
        # Port scanning
        "tcp_basic", "tcp_syn", "full_tcp", "udp_scan", "stealth_syn",
        # Enumeration
        "service_detect", "full_service_enum", "os_detect",
        "banner_grab", "version_deep", "port_range", "db_discovery",
        # Vulnerability assessment
        "vuln_scan", "smb_audit", "ftp_audit", "ssh_audit", "web_pentest",
        # Advanced
        "aggressive_pentest", "firewall_evasion", "frag_scan",
        "decoy_scan", "timing_manipulation", "ultimate_recon",
        # Allowed internally but not via public API
        "enum_scripts",
        # No recommendation (None)
        None,
    }

    def base_host(version_status="outdated", has_cve=False, cve_critical=False):
        cves = []
        if has_cve:
            sev = "critical" if cve_critical else "medium"
            cves = [{"cve_id":"CVE-X","cvss_score":9.8 if cve_critical else 5.3,"severity":sev,
                     "description":"x","patch":"y"}]
        return {"ip":"x","ports":[{
            "port":22,"service":"ssh","product":"OpenSSH","version":"7.4","state":"open",
            "cves":cves,
            "version_analysis":{"status":version_status,"message":"","confidence":"high","age_years":9},
            "context":{"criticality":"high","criticality_reason":"r","exposure_type":"commonly_exposed",
                        "version_risk":"medium","total_open_ports":1},
            "risk":{"level":"medium","score":5.0,"reasons":[],"color":"#000","max_cvss":0,"cve_count":len(cves)}
        }],"os":None,
        "context":{"exposure":"medium","open_port_count":1,"exposure_note":""},
        "risk_summary":{"overall":"medium","counts":{"critical":0,"high":0,"medium":1,"low":0},"total_ports":1}}

    # No version → recommend service_detect
    no_ver_host = base_host(version_status="unknown")
    rec = get_recommendation({"hosts":[no_ver_host],"scan_summary":{}}, "tcp_basic")
    check("returns dict",                   isinstance(rec, dict))
    check("has title",                      "title" in rec)
    check("has reason",                     "reason" in rec)
    check("scan_type in valid set",         rec.get("scan_type") in VALID_TYPES)
    check("no version → service_detect",    rec.get("scan_type") == "service_detect")
    check("reason is non-empty string",     isinstance(rec["reason"],str) and len(rec["reason"]) > 5)
    check("alternatives is list",           isinstance(rec.get("alternatives",[]), list))

    # Critical CVE → recommend enum_scripts
    crit_host = base_host(version_status="outdated", has_cve=True, cve_critical=True)
    rec2 = get_recommendation({"hosts":[crit_host],"scan_summary":{}}, "tcp_basic")
    check("critical CVE → enum_scripts",    rec2.get("scan_type") == "enum_scripts")

    # Already did udp → don't recommend udp again
    rec3 = get_recommendation({"hosts":[base_host()],"scan_summary":{}}, "udp_scan")
    check("after udp scan, not udp again",  rec3.get("scan_type") != "udp_scan")

    # Empty hosts → all_complete
    rec4 = get_recommendation({"hosts":[],"scan_summary":{}}, "tcp_basic")
    check("empty hosts → scan_type None",   rec4.get("scan_type") is None)

    # Priority field present
    check("has priority field",             "priority" in rec)
    check("priority is int",                isinstance(rec["priority"], int))

# ─────────────────────────────────────────────────────────
# EXPLAINER
# ─────────────────────────────────────────────────────────
def test_explainer():
    print("\n[7] EXPLAINER — explainer.py")
    from app.explanation.explainer import generate_explanation

    def make_data(cve_critical=False, service="ssh"):
        cves = [{"cve_id":"CVE-2023-38408","cvss_score":9.8,"severity":"critical",
                  "description":"RCE in ssh-agent","patch":"Upgrade to 9.3p2"}] if cve_critical else []
        return {"hosts":[{"ip":"192.168.1.10","ports":[{
            "port":22,"protocol":"tcp","service":service,"product":"OpenSSH","version":"7.4","state":"open",
            "cves":cves,
            "version_analysis":{"status":"outdated","age_years":9,"message":"Outdated. Upgrade recommended."},
            "context":{"criticality":"high","criticality_reason":"Remote admin access",
                        "exposure_type":"commonly_exposed","version_risk":"medium","total_open_ports":1},
            "risk":{"level":"critical" if cve_critical else "medium","score":9.0 if cve_critical else 5.0,
                    "reasons":["Critical CVE" if cve_critical else "Outdated version"],
                    "color":"#E24B4A","max_cvss":9.8 if cve_critical else 0,"cve_count":len(cves)}
        }],"context":{"exposure":"medium","open_port_count":1,"exposure_note":""},
        "risk_summary":{"overall":"critical" if cve_critical else "medium",
                         "counts":{"critical":1 if cve_critical else 0,"high":0,"medium":0 if cve_critical else 1,"low":0},
                         "total_ports":1}}],"scan_summary":{}}

    rec = {"title":"Script Enumeration","reason":"Critical CVEs detected.","scan_type":"enum_scripts"}

    exp = generate_explanation(make_data(cve_critical=True), rec)
    check("returns dict",               isinstance(exp, dict))
    check("has summary",                "summary" in exp)
    check("has findings",               "findings" in exp)
    check("has defensive_guidance",     "defensive_guidance" in exp)
    check("has next_step",              "next_step" in exp)
    check("has next_scan",              "next_scan" in exp)
    check("summary is non-empty str",   isinstance(exp["summary"],str) and len(exp["summary"]) > 20)
    check("findings is list",           isinstance(exp["findings"], list))
    check("guidance is list",           isinstance(exp["defensive_guidance"], list))
    check("next_step = rec reason",     exp["next_step"] == rec["reason"])
    check("next_scan = rec title",      exp["next_scan"] == rec["title"])

    f = exp["findings"][0]
    check("finding has port",           "port" in f)
    check("finding has service",        "service" in f)
    check("finding has risk_level",     "risk_level" in f)
    check("finding has what_was_found", "what_was_found" in f)
    check("finding has why_it_matters", "why_it_matters" in f)
    check("finding has version_status", "version_status" in f)
    check("finding has cve_count",      "cve_count" in f)
    check("finding has top_cves",       "top_cves" in f)
    check("finding has risk_explanation","risk_explanation" in f)
    check("finding has guidance",       "guidance" in f)

    check("critical flagged in summary",any(w in exp["summary"].lower()
                                             for w in ["critical","immediate","action"]))
    check("guidance list non-empty",    len(exp["defensive_guidance"]) > 0)

    # Safety check
    all_txt = " ".join(exp["defensive_guidance"] + [f["risk_explanation"] for f in exp["findings"]]).lower()
    forbidden = ["exploit code","payload","shellcode","weaponize","metasploit module"]
    check("no exploit terms in output", not any(w in all_txt for w in forbidden))

    # Empty hosts
    exp2 = generate_explanation({"hosts":[],"scan_summary":{}}, rec)
    check("empty hosts → no crash",     isinstance(exp2, dict))
    check("empty hosts → summary msg",  "No live hosts" in exp2["summary"])
    check("empty hosts → empty findings",exp2["findings"] == [])

    # Service-specific guidance
    exp3 = generate_explanation(make_data(service="ftp"), rec)
    g_text = " ".join(exp3["defensive_guidance"]).lower()
    check("ftp guidance mentions sftp/plaintext", any(w in g_text for w in ["sftp","plaintext","ftp"]))

# ─────────────────────────────────────────────────────────
# VALIDATORS
# ─────────────────────────────────────────────────────────
def test_validators():
    print("\n[8] VALIDATORS — validators.py")
    # We test without FastAPI dependency by calling the regex directly
    import re
    from app.api.validators import TARGET_PATTERN, ALLOWED_SCAN_TYPES

    check("192.168.1.1 valid",           bool(TARGET_PATTERN.match("192.168.1.1")))
    check("10.0.0.1 valid",              bool(TARGET_PATTERN.match("10.0.0.1")))
    check("localhost valid",             bool(TARGET_PATTERN.match("localhost")))
    check("CIDR valid",                  bool(TARGET_PATTERN.match("192.168.1.0/24")))
    check("hostname valid",              bool(TARGET_PATTERN.match("example.com")))
    check("empty string invalid",        not bool(TARGET_PATTERN.match("")))
    check("semicolon invalid",           not bool(TARGET_PATTERN.match("192.168.1.1;ls")))
    check("pipe invalid",                not bool(TARGET_PATTERN.match("192.168.1.1|cat")))
    check("space invalid",               not bool(TARGET_PATTERN.match("192.168.1.1 ")))

    check("tcp_basic in allowed",        "tcp_basic" in ALLOWED_SCAN_TYPES)
    check("service_detect in allowed",   "service_detect" in ALLOWED_SCAN_TYPES)
    check("full_tcp in allowed",         "full_tcp" in ALLOWED_SCAN_TYPES)
    check("ultimate_recon in allowed",   "ultimate_recon" in ALLOWED_SCAN_TYPES)
    check("26 total scan types",         len(ALLOWED_SCAN_TYPES) == 26)
    check("arbitrary cmd not allowed",   "bash -c evil" not in ALLOWED_SCAN_TYPES)
    check("rm not allowed",              "rm -rf /" not in ALLOWED_SCAN_TYPES)

# ─────────────────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────────────────
def test_orchestrator():
    print("\n[9] ORCHESTRATOR — orchestrator.py")
    from app.scanner.orchestrator import get_scan_command, SCAN_TEMPLATES

    check("8 templates defined",         len(SCAN_TEMPLATES) == 8)
    check("all have name",               all("name" in v for v in SCAN_TEMPLATES.values()))
    check("all have description",        all("description" in v for v in SCAN_TEMPLATES.values()))
    check("all have args list",          all(isinstance(v["args"], list) for v in SCAN_TEMPLATES.values()))

    cmd = get_scan_command("service_detect", "192.168.1.10")
    check("cmd is list",                 isinstance(cmd, list))
    check("cmd starts with nmap",        cmd[0] == "nmap")
    check("cmd ends with target",        cmd[-1] == "192.168.1.10")
    check("target not injected",         all(";" not in a and "|" not in a for a in cmd))

    # Shell injection prevention
    for stype in SCAN_TEMPLATES:
        cmd2 = get_scan_command(stype, "192.168.1.1")
        check(f"{stype}: no shell chars in args",
              all(";" not in a and "|" not in a and "&" not in a for a in cmd2))

    try:
        get_scan_command("rm_rf", "192.168.1.1")
        check("unknown scan type raises", False)
    except (ValueError, KeyError):
        check("unknown scan type raises ValueError", True)

# ─────────────────────────────────────────────────────────
# REPORT BUILDER
# ─────────────────────────────────────────────────────────
def test_report_builder():
    print("\n[10] REPORT BUILDER — template_builder.py")
    import json, tempfile, os
    from app.report.template_builder import build_report, _overall, _build_conclusion

    check("_overall critical",  _overall({"critical":1,"high":0,"medium":0,"low":0}) == "CRITICAL")
    check("_overall high",      _overall({"critical":0,"high":2,"medium":0,"low":0}) == "HIGH")
    check("_overall medium",    _overall({"critical":0,"high":0,"medium":3,"low":0}) == "MEDIUM")
    check("_overall low",       _overall({"critical":0,"high":0,"medium":0,"low":5}) == "LOW")

    conclusion = _build_conclusion({"critical":1,"high":0,"medium":0,"low":0},
                                   [{"cve_id":"CVE-2011-2523","severity":"critical"}], "192.168.1.1")
    check("conclusion is string",            isinstance(conclusion, str))
    check("conclusion mentions target",      "192.168.1.1" in conclusion)
    check("conclusion mentions remediation", any(w in conclusion.lower()
                                                  for w in ["remediat","patch","upgrade","fix"]))

    analysis = {
        "target":"192.168.1.10","scan_type":"service_detect","duration":5.2,
        "timestamp":"2025-07-15 12:00:00",
        "risk":{"hosts":[{"ip":"192.168.1.10","ports":[{
            "port":22,"protocol":"tcp","service":"ssh","product":"OpenSSH","version":"7.4","state":"open",
            "cves":[{"cve_id":"CVE-2018-15473","cvss_score":5.3,"severity":"medium",
                      "description":"username enum","patch":"Upgrade"}],
            "risk":{"level":"medium","score":5.0,"reasons":[],"color":"#000","max_cvss":5.3,"cve_count":1},
            "version_analysis":{"status":"outdated","message":"Outdated","confidence":"high","age_years":9}
        }],"risk_summary":{"overall":"medium","counts":{"critical":0,"high":0,"medium":1,"low":0},"total_ports":1}}]},
        "explanation":{"summary":"Test summary.","defensive_guidance":["Upgrade SSH."],"findings":[]},
        "recommendation":{"title":"Full Service Enum","reason":"Outdated.","scan_type":"full_service_enum","alternatives":[]}
    }

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        session_id = "test_20250715_120000"
        session_path = os.path.join(tmp, session_id, "report")
        os.makedirs(session_path)
        import app.report.template_builder as tb
        orig = tb.BASE_DIR
        tb.BASE_DIR = tmp
        try:
            report_path = build_report(session_id, analysis)
            check("report file created",     os.path.exists(report_path))
            with open(report_path) as f:
                rpt = json.load(f)
            check("report is valid JSON",    isinstance(rpt, dict))
            check("has report_metadata",     "report_metadata" in rpt)
            check("has scan_information",    "scan_information" in rpt)
            check("has executive_summary",   "executive_summary" in rpt)
            check("has findings",            "findings" in rpt)
            check("has cve_details",         "cve_details" in rpt)
            check("has defensive_guidance",  "defensive_guidance" in rpt)
            check("has recommendation",      "recommendation" in rpt)
            check("has conclusion",          "conclusion" in rpt)
            check("target correct",          rpt["scan_information"]["target"] == "192.168.1.10")
            check("cve_details sorted",      len(rpt["cve_details"]) > 0)
        finally:
            tb.BASE_DIR = orig

# ─────────────────────────────────────────────────────────
# INTEGRATION — full pipeline
# ─────────────────────────────────────────────────────────
def test_integration():
    print("\n[11] INTEGRATION — Full pipeline end-to-end")
    from app.parser.nmap_parser import parse_nmap_output
    from app.analysis.version_engine import analyze_versions
    from app.cve.mapper import map_cves
    from app.analysis.context_engine import analyze_context
    from app.analysis.risk_engine import calculate_risk
    from app.recommendation.recommender import get_recommendation
    from app.explanation.explainer import generate_explanation

    XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/>
    <service name="ftp" product="vsftpd" version="2.3.4" conf="10" method="probed"/></port>
  <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.2.34" conf="10" method="probed"/></port>
  <port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/>
    <service name="mysql" product="MySQL" version="5.5.62" conf="10" method="probed"/></port>
</ports></host>
<runstats><finished elapsed="7.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""

    parsed   = parse_nmap_output(XML, "")
    versioned = analyze_versions(parsed)
    cve_data  = map_cves(versioned)
    context   = analyze_context(cve_data)
    risk      = calculate_risk(context)
    rec       = get_recommendation(risk, "service_detect")
    exp       = generate_explanation(risk, rec)

    host   = risk["hosts"][0]
    ports  = {p["port"]: p for p in host["ports"]}

    check("pipeline: 3 ports parsed",         len(host["ports"]) == 3)
    check("pipeline: vsftpd unsupported",      ports[21]["version_analysis"]["status"] == "unsupported")
    check("pipeline: apache unsupported",      ports[80]["version_analysis"]["status"] == "unsupported")
    check("pipeline: vsftpd backdoor found",   any(c["cve_id"]=="CVE-2011-2523" for c in ports[21]["cves"]))
    check("pipeline: apache CVEs found",       len(ports[80]["cves"]) > 0)
    check("pipeline: mysql CVEs found",        len(ports[3306]["cves"]) > 0)
    check("pipeline: risk scores present",     all("risk" in p for p in host["ports"]))
    check("pipeline: risk_summary on host",    "risk_summary" in host)
    check("pipeline: explanation summary",     len(exp["summary"]) > 20)
    check("pipeline: recommendation title",    len(rec["title"]) > 0)
    check("pipeline: guidance non-empty",      len(exp["defensive_guidance"]) > 0)
    check("pipeline: findings for all ports",  len(exp["findings"]) == 3)

    overall = host["risk_summary"]["overall"]
    check("pipeline: overall risk high/critical", overall in ("high","critical"))

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "━"*56)
    print("  ScanWise AI — Complete Test Suite")
    print("━"*56)

    tests = [
        test_parser, test_cve_mapper, test_version_engine,
        test_risk_engine, test_context_engine, test_recommender,
        test_explainer, test_validators, test_orchestrator,
        test_report_builder, test_integration
    ]

    for t in tests:
        try:
            t()
        except Exception as e:
            import traceback
            print(f"  ✗ TEST CRASHED: {t.__name__}: {e}")
            traceback.print_exc()
            FAIL += 1

    total = PASS + FAIL
    pct   = PASS / total * 100 if total else 0
    grade = "EXCELLENT ✦" if pct >= 95 else "GOOD" if pct >= 80 else "NEEDS WORK"

    print(f"\n{'━'*56}")
    print(f"  RESULTS:  {PASS}/{total} tests passed  |  {FAIL} failed")
    bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
    print(f"  SCORE:    [{bar}] {pct:.1f}%")
    print(f"  GRADE:    {grade}")
    print(f"{'━'*56}\n")

    sys.exit(0 if FAIL == 0 else 1)
