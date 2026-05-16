"""
ScanWise AI — Benchmark Evaluation Module
Measures correctness of CVE mapping, risk classification, and recommendation quality
against 5 known ground-truth fixtures.

Run with: python tests/benchmark.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.parser.nmap_parser import parse_nmap_output
from app.analysis.version_engine import analyze_versions
from app.cve.mapper import map_cves
from app.analysis.context_engine import analyze_context
from app.analysis.risk_engine import calculate_risk
from app.recommendation.recommender import get_recommendation
from app.explanation.explainer import generate_explanation

# ── Ground-truth fixtures ────────────────────────────────────────────────────

FIXTURES = [
    {
        "name": "Fixture 1: vsftpd backdoor (classic critical)",
        "xml": """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="21">
    <state state="open" reason="syn-ack"/>
    <service name="ftp" product="vsftpd" version="2.3.4" conf="10" method="probed"/>
  </port>
</ports></host>
<runstats><finished elapsed="3.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>""",
        "scan_type": "service_detect",
        "expected_cves": ["CVE-2011-2523"],
        "expected_risk": "critical",
        "expected_version_status": "unsupported",
        "expected_rec_contains": ["enum_scripts", "version_deep", "udp_scan"],
    },
    {
        "name": "Fixture 2: Outdated OpenSSH (medium risk)",
        "xml": """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="7.4" conf="10" method="probed"/>
  </port>
</ports></host>
<runstats><finished elapsed="2.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>""",
        "scan_type": "service_detect",
        "expected_cves": ["CVE-2018-15473"],
        "expected_risk": ["medium", "high", "critical"],
        "expected_version_status": "outdated",
        "expected_rec_contains": ["version_deep", "udp_scan", "enum_scripts"],
    },
    {
        "name": "Fixture 3: Apache 2.2 EOL + MySQL 5.5 (high exposure)",
        "xml": """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.0.10" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.2.34" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="3306">
    <state state="open" reason="syn-ack"/>
    <service name="mysql" product="MySQL" version="5.5.62" conf="10" method="probed"/>
  </port>
</ports></host>
<runstats><finished elapsed="5.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>""",
        "scan_type": "service_detect",
        "expected_cves": ["CVE-2017-7679", "CVE-2016-6662"],
        "expected_risk": ["high", "critical"],
        "expected_version_status": "unsupported",
        "expected_rec_contains": ["enum_scripts", "udp_scan"],
    },
    {
        "name": "Fixture 4: SNMP + BIND UDP (network services)",
        "xml": """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="10.10.0.1" addrtype="ipv4"/>
<ports>
  <port protocol="udp" portid="161">
    <state state="open" reason="udp-response"/>
    <service name="snmp" product="net-snmp" version="5.7.2" conf="10" method="probed"/>
  </port>
  <port protocol="udp" portid="53">
    <state state="open" reason="udp-response"/>
    <service name="domain" product="ISC BIND" version="9.9.5" conf="10" method="probed"/>
  </port>
</ports></host>
<runstats><finished elapsed="20.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>""",
        "scan_type": "udp_scan",
        "expected_cves": ["CVE-2022-44792", "CVE-2021-25220"],
        "expected_risk": ["medium", "high"],
        "expected_version_status": "unsupported",
        "expected_rec_contains": ["enum_scripts", "version_deep", "os_detect"],
    },
    {
        "name": "Fixture 5: No version info (needs service detect)",
        "xml": """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="172.16.0.50" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" conf="3" method="table"/>
  </port>
  <port protocol="tcp" portid="8080">
    <state state="open" reason="syn-ack"/>
    <service name="http-proxy" conf="3" method="table"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="open" reason="syn-ack"/>
    <service name="https" conf="3" method="table"/>
  </port>
</ports></host>
<runstats><finished elapsed="4.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>""",
        "scan_type": "tcp_basic",
        "expected_cves": [],
        "expected_risk": ["low", "medium"],
        "expected_version_status": "unknown",
        "expected_rec_contains": ["service_detect"],
    },
]


def run_pipeline(xml, scan_type):
    parsed = parse_nmap_output(xml, "")
    versioned = analyze_versions(parsed)
    cve_data = map_cves(versioned)
    context = analyze_context(cve_data)
    risk = calculate_risk(context)
    rec = get_recommendation(risk, scan_type)
    explanation = generate_explanation(risk, rec)
    return parsed, versioned, cve_data, risk, rec, explanation


def evaluate_fixture(fixture):
    print(f"\n{'─'*60}")
    print(f"  {fixture['name']}")
    print(f"{'─'*60}")

    parsed, versioned, cve_data, risk, rec, explanation = run_pipeline(
        fixture["xml"], fixture["scan_type"]
    )

    scores = []
    hosts = risk.get("hosts", [])

    # ── CVE recall ──────────────────────────────────────────────────────────
    found_cve_ids = []
    for host in hosts:
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                found_cve_ids.append(cve["cve_id"])

    expected_cves = fixture["expected_cves"]
    if expected_cves:
        recalled = [c for c in expected_cves if c in found_cve_ids]
        cve_recall = len(recalled) / len(expected_cves)
        print(f"  CVE Recall:      {len(recalled)}/{len(expected_cves)} ({cve_recall*100:.0f}%)")
        print(f"  Found CVEs:      {found_cve_ids}")
        scores.append(cve_recall)
    else:
        cve_recall = 1.0 if not found_cve_ids else 0.5
        print(f"  CVE Recall:      N/A (no CVEs expected, found {len(found_cve_ids)})")
        scores.append(cve_recall)

    # ── Risk classification ─────────────────────────────────────────────────
    actual_risk_levels = []
    for host in hosts:
        for port in host.get("ports", []):
            actual_risk_levels.append(port.get("risk", {}).get("level", "low"))

    expected_risk = fixture["expected_risk"]
    if isinstance(expected_risk, str):
        expected_risk = [expected_risk]

    risk_correct = any(lvl in expected_risk for lvl in actual_risk_levels)
    risk_score = 1.0 if risk_correct else 0.0
    print(f"  Risk Levels:     {actual_risk_levels}  (expected any of {expected_risk})")
    print(f"  Risk Correct:    {'✓ YES' if risk_correct else '✗ NO'}")
    scores.append(risk_score)

    # ── Version status ──────────────────────────────────────────────────────
    actual_statuses = []
    for host in hosts:
        for port in host.get("ports", []):
            s = port.get("version_analysis", {}).get("status", "unknown")
            actual_statuses.append(s)

    expected_vs = fixture["expected_version_status"]
    vs_correct = expected_vs in actual_statuses
    vs_score = 1.0 if vs_correct else 0.0
    print(f"  Version Status:  {actual_statuses}  (expected '{expected_vs}')")
    print(f"  Status Correct:  {'✓ YES' if vs_correct else '✗ NO'}")
    scores.append(vs_score)

    # ── Recommendation correctness ──────────────────────────────────────────
    rec_type = rec.get("scan_type")
    alt_types = [a.get("scan_type") for a in rec.get("alternatives", [])]
    all_rec_types = [rec_type] + alt_types
    expected_rec = fixture["expected_rec_contains"]
    rec_match = any(r in expected_rec for r in all_rec_types)
    rec_score = 1.0 if rec_match else 0.0
    print(f"  Recommendations: {all_rec_types}  (expected any of {expected_rec})")
    print(f"  Rec Correct:     {'✓ YES' if rec_match else '✗ NO'}")
    scores.append(rec_score)

    # ── Explanation quality ─────────────────────────────────────────────────
    exp_summary = explanation.get("summary", "")
    exp_guidance = explanation.get("defensive_guidance", [])
    exp_findings = explanation.get("findings", [])

    has_summary = len(exp_summary) > 30
    has_guidance = len(exp_guidance) > 0
    has_findings = len(exp_findings) > 0
    exp_score = (int(has_summary) + int(has_guidance) + int(has_findings)) / 3
    print(f"  Explanation:     summary={has_summary}, guidance={has_guidance}, findings={has_findings}")
    print(f"  Exp Quality:     {exp_score*100:.0f}%")
    scores.append(exp_score)

    overall = sum(scores) / len(scores)
    print(f"\n  ► Overall Score: {overall*100:.1f}%")
    return overall


def main():
    print("\n" + "="*60)
    print("  ScanWise AI — Benchmark Evaluation")
    print("="*60)

    total_scores = []
    for fixture in FIXTURES:
        score = evaluate_fixture(fixture)
        total_scores.append(score)

    avg = sum(total_scores) / len(total_scores)
    print(f"\n{'='*60}")
    print(f"  BENCHMARK RESULTS")
    print(f"{'='*60}")
    for i, (f, s) in enumerate(zip(FIXTURES, total_scores), 1):
        bar = "█" * int(s * 20) + "░" * (20 - int(s * 20))
        print(f"  F{i}: [{bar}] {s*100:.1f}%  {f['name'][:35]}")
    print(f"{'─'*60}")
    print(f"  Average Score:  {avg*100:.1f}%")
    grade = "Excellent" if avg >= 0.85 else "Good" if avg >= 0.70 else "Needs improvement"
    print(f"  Grade:          {grade}")
    print(f"{'='*60}\n")

    return avg


if __name__ == "__main__":
    score = main()
    sys.exit(0 if score >= 0.60 else 1)
