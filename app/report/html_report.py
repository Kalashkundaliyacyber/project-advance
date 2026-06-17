"""
HTML Report Generator — Formal Security Assessment Finding Report template
============================================================================
v6.0 — Replaces the dashboard-style report with a formal, paginated
"Security Assessment Finding Report" layout (cover / confidentiality /
disclaimer / contact / assessment overview / severity classification /
scope / executive summary / attack-chain summary / strengths & weaknesses /
vulnerabilities-by-impact chart / detailed findings / appendices /
client sign-off / closing page).

Every section is populated from real session analysis data — nothing about
a specific engagement is hard-coded. Fields that are inherently filled in
by a human after the fact (client contact name, signatures) are rendered
as clearly bracketed placeholders, exactly as a template should.

Notes on scope:
  - Per-finding "Remediation" text comes straight from the existing CVE
    `patch` field already produced by ThreatWeave's CVE/remediation
    pipeline. No exploitation/PoC section is generated — ThreatWeave's
    data model does not capture exploit mechanics, and this report stays
    purely defensive: description, impact, affected system, references,
    remediation.
  - Per multi_format.py's own v2.0 changelog, "Recommended Next Scan" /
    "Script Enumeration" upsell content is intentionally NOT included in
    exported reports.

Self-contained, no external services required at render time other than
a CDN-hosted icon-free CSS (none used). Printable to PDF via the browser
(Ctrl+P → Save as PDF) thanks to the @media print rules.
"""
import os
import time
import html as _html
from datetime import datetime

# ── Paths (unchanged contract) ───────────────────────────────────────────────
BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "sessions"
)
REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "reports"
)

COMPANY_NAME  = "ThreatWeave Security"
COMPANY_INIT  = "TWS"
COMPANY_EMAIL = "security@threatweave.local"

SEVERITY_ORDER  = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {
    "critical": "#a61c1c", "high": "#e67e22", "medium": "#f1c40f",
    "low": "#2ecc71", "informational": "#3498db", "unknown": "#8b949e",
}
SEVERITY_TEXT_ON = {  # text color that's readable on top of the badge color
    "critical": "#ffffff", "high": "#ffffff", "medium": "#1e2a3a",
    "low": "#ffffff", "informational": "#ffffff", "unknown": "#ffffff",
}

# Plain-language description of each scan type, used in §5 Assessment Components
SCAN_TYPE_INFO = {
    "tcp_basic":      ("TCP Basic Scan", "a lightweight TCP connect scan that enumerates open ports without active service fingerprinting"),
    "tcp_syn":        ("TCP SYN Scan", "a half-open TCP scan used to map the live attack surface of the in-scope target(s)"),
    "udp_scan":       ("UDP Scan", "a scan of common UDP services (e.g. DNS, SNMP, NTP) that are frequently overlooked in TCP-only assessments"),
    "service_detect": ("Service Detection Scan", "active probing used to identify the specific service and software running behind each open port"),
    "version_deep":   ("Deep Version Detection Scan", "aggressive version fingerprinting used to precisely identify software versions for accurate vulnerability correlation"),
    "os_detect":      ("OS Detection Scan", "TCP/IP stack fingerprinting used to identify the likely operating system of each host"),
    "port_range":     ("Port Range Scan", "a scan of a defined port range used to map the exposed attack surface"),
    "enum_scripts":   ("Script Enumeration Scan", "non-intrusive NSE scripts used to confirm service details and gather supporting evidence for remediation planning"),
    "vuln_scan":      ("Vulnerability Scan", "service version detection correlated against known CVE databases to identify exploitable software weaknesses without active exploitation"),
}

CLEARTEXT_SERVICES = {"ftp", "telnet", "rsh", "rlogin", "tftp", "rexec"}
_INVALID_PROJECT_NAMES = {"unnamed session", "unnamed", "untitled", "new session", "new project", ""}


def _e(v) -> str:
    """HTML-escape any value."""
    return _html.escape(str(v) if v is not None else "")


def build_html_report(session_id: str, analysis: dict) -> str:
    """Generate the formal security-assessment HTML report. Returns file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    ctx  = _build_context(session_id, analysis)
    html = _render(ctx)

    fname = f"report_{session_id}_{time.strftime('%Y%m%d_%H%M%S')}.html"
    fpath = os.path.join(REPORTS_DIR, fname)
    with open(fpath, "w") as f:
        f.write(html)

    # Also save to session folder (preserves existing contract used elsewhere)
    sess_report_dir = os.path.join(BASE_DIR, session_id, "report")
    os.makedirs(sess_report_dir, exist_ok=True)
    with open(os.path.join(sess_report_dir, "report.html"), "w") as f:
        f.write(html)

    return fpath


# ── Data aggregation ─────────────────────────────────────────────────────────

def _build_context(session_id: str, analysis: dict) -> dict:
    hosts       = analysis.get("risk", {}).get("hosts", []) or []
    explanation = analysis.get("explanation", {}) or {}
    ai          = analysis.get("ai_analysis", {}) or {}
    target      = analysis.get("target", "unknown")
    scan_type   = analysis.get("scan_type", "unknown")
    timestamp   = analysis.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    duration    = analysis.get("duration")
    project     = (analysis.get("project_name") or "").strip()

    all_findings    = []
    all_cves        = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for host in hosts:
        host_ip = host.get("ip", target)
        for port in host.get("ports", []):
            risk  = port.get("risk", {}) or {}
            level = risk.get("level", "low")
            severity_counts[level] = severity_counts.get(level, 0) + 1
            finding = {
                "host":     host_ip,
                "port":     port.get("port"),
                "proto":    port.get("protocol", "tcp"),
                "service":  port.get("service") or "unknown",
                "product":  port.get("product", ""),
                "version":  port.get("version", ""),
                "version_str": f"{port.get('product','')} {port.get('version','')}".strip(),
                "state":    port.get("state"),
                "risk":     level,
                "score":    risk.get("score", 0),
                "v_status": (port.get("version_analysis", {}) or {}).get("status", "unknown"),
                "cve_count": len(port.get("cves", []) or []),
            }
            all_findings.append(finding)
            for cve in port.get("cves", []) or []:
                all_cves.append({
                    "cve_id":   cve.get("cve_id", "—"),
                    "host":     host_ip,
                    "service":  port.get("service") or "unknown",
                    "product":  port.get("product", ""),
                    "version":  port.get("version", ""),
                    "port":     port.get("port"),
                    "proto":    port.get("protocol", "tcp"),
                    "cvss":     cve.get("cvss_score", 0) or 0,
                    "severity": (cve.get("severity") or "unknown").lower(),
                    "desc":     cve.get("description", ""),
                    "patch":    cve.get("patch", ""),
                    "nvd_url":  cve.get("nvd_url", f"https://nvd.nist.gov/vuln/detail/{cve.get('cve_id','')}"),
                })

    all_cves.sort(key=lambda x: (x["cvss"] or 0), reverse=True)

    total_hosts = len(hosts)
    total_ports = len(all_findings)
    total_cves  = len(all_cves)
    overall     = _overall(severity_counts)

    client_label = project if (project and project.strip().lower() not in _INVALID_PROJECT_NAMES) else "[Client Organization Name]"
    scan_label, scan_desc = SCAN_TYPE_INFO.get(scan_type, (scan_type.replace("_", " ").title() or "Security Scan",
                                                            "an automated security scan of the in-scope target(s)"))

    return {
        "session_id":      session_id,
        "target":          target,
        "scan_type":       scan_type,
        "scan_label":      scan_label,
        "scan_desc":        scan_desc,
        "timestamp":       timestamp,
        "date_long":       _fmt_date_long(timestamp),
        "date_short":      _fmt_date_short(timestamp),
        "duration_str":    _fmt_duration(duration),
        "client_label":    client_label,
        "project":         project,
        "hosts":           hosts,
        "all_findings":    all_findings,
        "all_cves":        all_cves,
        "severity_counts": severity_counts,
        "overall":         overall,
        "total_hosts":     total_hosts,
        "total_ports":     total_ports,
        "total_cves":      total_cves,
        "explanation":     explanation,
        "ai":              ai,
        "guidance":        explanation.get("defensive_guidance", []) or [],
        "summary_text":    explanation.get("summary", "") or
                            f"Assessment of {target} completed. {total_ports} open service(s) and {total_cves} known CVE(s) were identified.",
    }


def _overall(counts: dict) -> str:
    if counts.get("critical", 0) > 0: return "critical"
    if counts.get("high", 0) > 0:     return "high"
    if counts.get("medium", 0) > 0:   return "medium"
    return "low"


def _fmt_date_long(ts: str) -> str:
    try:
        dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%B %-d, %Y")
    except Exception:
        try:
            return ts.split(" ")[0]
        except Exception:
            return ts or "—"


def _fmt_date_short(ts: str) -> str:
    try:
        dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts or "—"


def _fmt_duration(seconds) -> str:
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "—"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    m, s = divmod(int(round(seconds)), 60)
    return f"{m} min {s} sec" if s else f"{m} min"


# ── Narrative builders (derived purely from analysis data) ──────────────────

def _ver_str(product: str, version: str) -> str:
    """Join product+version cleanly, stripping the inner join (not just the ends)
    so an empty product never leaves a stray leading space, e.g. '' + '2-4' -> '2-4'."""
    return f"{(product or '').strip()} {(version or '').strip()}".strip()


def _build_attack_summary(all_cves: list, max_steps: int = 8) -> list:
    """Step-by-step table of how the highest-severity findings chain together.
    Intentionally limited to: what was found -> CVE -> defensive remediation.
    No exploitation mechanics are included."""
    steps = []
    seen_ports = set()
    for cve in all_cves:
        key = (cve["host"], cve["port"])
        if key in seen_ports and len(steps) >= 3:
            # allow a couple of repeats for context, then prefer new ports
            if len(steps) >= max_steps:
                break
        if len(steps) >= max_steps:
            break
        seen_ports.add(key)
        ver_str = _ver_str(cve["product"], cve["version"])
        svc_desc = f"{_e(cve['service'])} ({_e(ver_str)})" if ver_str else _e(cve["service"])
        action = f"Service enumeration identified {svc_desc} open on port {cve['port']}/{cve['proto']} of {_e(cve['host'])}."
        patch = cve["patch"] or "Apply vendor patches or upgrade the affected service, then re-scan to confirm remediation."
        finding = f"{cve['cve_id']} — CVSS {cve['cvss']:.1f} ({cve['severity'].title()}). {patch}"
        steps.append({"action": action, "finding": finding})
    return steps


def _build_strengths(all_findings: list, severity_counts: dict) -> list:
    bullets = []
    if severity_counts.get("critical", 0) == 0:
        bullets.append("No critical-severity vulnerabilities were identified during this assessment.")
    if severity_counts.get("high", 0) == 0:
        bullets.append("No high-severity vulnerabilities were identified during this assessment.")
    cleartext_found = any(f["service"] in CLEARTEXT_SERVICES for f in all_findings)
    if not cleartext_found:
        bullets.append("No clear-text, credential-exposing protocols (e.g. Telnet, FTP) were observed in active use.")
    if 0 < len(all_findings) <= 5:
        bullets.append(f"The observed attack surface is relatively small, with only {len(all_findings)} open service(s) detected.")
    if not bullets:
        bullets.append("No significant strengths were identified given the number and severity of issues discovered "
                        "during this assessment. Logging and alerting posture could not be evaluated as part of this engagement.")
    return bullets


def _build_weaknesses(all_findings: list, all_cves: list) -> list:
    bullets = []

    outdated = sorted({f["version_str"] or f["service"] for f in all_findings
                        if f["v_status"] in ("outdated", "unsupported") and (f["version_str"] or f["service"])})
    if outdated:
        shown = ", ".join(outdated[:6]) + (f", and {len(outdated) - 6} more" if len(outdated) > 6 else "")
        bullets.append(f"<strong>Outdated or Unsupported Software</strong> — the following service version(s) are "
                        f"outdated or no longer supported by their vendor: {_e(shown)}.")

    cleartext = sorted({f["service"] for f in all_findings if f["service"] in CLEARTEXT_SERVICES})
    if cleartext:
        bullets.append(f"<strong>Clear-text Protocols</strong> — {_e(', '.join(cleartext))} "
                        f"transmit credentials and/or data without encryption.")

    no_auth_kw = ("without authentication", "unauthenticated", "no authentication", "missing authentication")
    no_auth_services = sorted({c["service"] for c in all_cves if any(k in (c["desc"] or "").lower() for k in no_auth_kw)})
    if no_auth_services:
        bullets.append(f"<strong>Authentication Weaknesses</strong> — one or more findings on "
                        f"{_e(', '.join(no_auth_services))} indicate missing or bypassable authentication.")

    if len(all_findings) > 15:
        bullets.append(f"<strong>Large Attack Surface</strong> — {len(all_findings)} open services were detected, "
                        f"which increases the overall attack surface and should be reviewed for necessity.")

    if not bullets:
        bullets.append("No systemic weaknesses beyond the individual findings listed in Section 10 were identified.")
    return bullets


# ── Page renderers ────────────────────────────────────────────────────────────

def _render(ctx: dict) -> str:
    pages = [
        _page_cover(ctx),
        _page_confidentiality_contact(ctx),
        _page_overview_components_severity(ctx),
        _page_scope_executive_summary(ctx),
        _page_impact_chart(ctx),
        *_pages_detailed_findings(ctx),
        _page_appendix_inventory(ctx),
        _page_appendix_cve_table(ctx),
        _page_signoff(ctx),
        _page_thankyou(ctx),
    ]
    body = "\n".join(pages)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{COMPANY_NAME} — Security Assessment Finding Report — {_e(ctx['target'])}</title>
{_STYLE}
</head>
<body>
{body}
</body>
</html>"""


_STYLE = """<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', sans-serif;
    background: #e6e9ef; padding: 30px 20px; color: #1e2a3a;
    font-size: 14px; line-height: 1.55;
}
.report-page {
    max-width: 1100px; margin: 0 auto 30px auto; background: white;
    box-shadow: 0 8px 20px rgba(0,0,0,0.1); padding: 50px 45px;
    page-break-after: always; border-radius: 4px;
}
.report-page:last-child { page-break-after: auto; }
h1 { font-size: 28px; font-weight: 700; margin-bottom: 10px; color: #0b2b3b; }
h2 { font-size: 20px; margin: 28px 0 12px 0; padding-bottom: 6px; border-bottom: 2px solid #ccd7e4; color: #1c4e6e; }
h3 { font-size: 17px; margin: 20px 0 10px; color: #2c5a7a; }
h4 { font-size: 14px; margin: 14px 0 6px; color: #2c5a7a; }
p { margin-bottom: 8px; }
ul { margin-left: 22px; margin-top: 6px; margin-bottom: 8px; }
li { margin-bottom: 6px; }
table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }
th { background: #f0f4f8; padding: 10px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #bdc4cf; }
td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
.severity-badge {
    display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold;
    font-size: 12px; text-align: center; min-width: 80px;
}
.critical { background: #a61c1c; color: white; }
.high { background: #e67e22; color: white; }
.medium { background: #f1c40f; color: #1e2a3a; }
.low { background: #2ecc71; color: white; }
.info { background: #3498db; color: white; }
.unknown { background: #8b949e; color: white; }
.muted { color: #4a627a; font-size: 12px; }
.vuln-card {
    background: #fafcfd; border-left: 4px solid; margin: 22px 0; padding: 12px 20px;
    border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.vuln-meta { font-size: 12.5px; color: #4a627a; margin: 4px 0; }
.chart-bar-container { width: 100%; background: #edf2f7; border-radius: 8px; margin: 15px 0; padding: 4px; }
.chart-bar { padding: 8px 12px; border-radius: 6px; color: white; font-weight: bold; margin: 5px 0; font-size: 13px; }
.signature-line { margin: 30px 0 20px; border-top: 1px solid #aaa; width: 300px; padding-top: 8px; font-size: 12px; color: #555; }
.footer-note { margin-top: 35px; font-size: 11px; text-align: center; color: #6c86a3; border-top: 1px solid #ddd; padding-top: 18px; }
.thankyou { text-align: center; margin-top: 160px; font-size: 18px; color: #2c5a7a; }
.code-inline { background: #f4f4f4; border: 1px solid #ddd; border-radius: 4px; padding: 1px 6px; font-family: 'Courier New', monospace; font-size: 12.5px; }
.placeholder { color: #9aa7b5; font-style: italic; }
@media print {
    body { background: white; padding: 0; margin: 0; }
    .report-page { box-shadow: none; padding: 0.75in; margin: 0; page-break-after: always; }
    .severity-badge { border: 1px solid #ccc; }
}
</style>"""


def _badge(level: str) -> str:
    level = (level or "unknown").lower()
    css = level if level in ("critical", "high", "medium", "low") else ("info" if level == "informational" else "unknown")
    label = "Informational" if level == "informational" else level.title()
    return f'<span class="severity-badge {css}">{_e(label)}</span>'


# PAGE 1 — Cover ---------------------------------------------------------------

def _page_cover(ctx: dict) -> str:
    subtitle = f"Engagement: {_e(ctx['project'])}" if ctx["project"] and ctx["client_label"] != "[Client Organization Name]" else ""
    return f"""<div class="report-page">
  <div style="text-align: center; margin-top: 110px;">
    <h1 style="font-size: 36px;">{_e(ctx['client_label'])}</h1>
    <p style="font-size: 24px; margin: 20px 0;">Security Assessment Finding Report</p>
    {f'<p class="muted" style="font-size:14px;margin-bottom:10px;">{_e(subtitle)}</p>' if subtitle else ''}
    <p style="margin-top: 50px;">{_e(ctx['date_long'])}</p>
    <p class="muted" style="margin-top:6px;">Target Scope: {_e(ctx['target'])} &nbsp;|&nbsp; Assessment Type: {_e(ctx['scan_label'])}</p>
    <p style="margin-top: 90px; font-size: 12px; color: #4a627a;">Confidential – Proprietary Information</p>
    <p style="margin-top: 6px; font-size: 12px; color: #4a627a;">Prepared by {COMPANY_NAME}</p>
  </div>
</div>"""


# PAGE 2 — Confidentiality + Disclaimer + Contact -------------------------------

def _page_confidentiality_contact(ctx: dict) -> str:
    client = ctx["client_label"]
    placeholder_row = (
        '<tr><td><span class="placeholder">[Client Contact Name]</span></td>'
        '<td><span class="placeholder">[Title]</span></td>'
        '<td><span class="placeholder">[Phone] / [Email]</span></td></tr>'
    )
    return f"""<div class="report-page">
  <h2>1. Confidentiality Statement</h2>
  <p>This document is the exclusive property of {_e(client)} and {COMPANY_NAME} ({COMPANY_INIT}). This document
  contains proprietary and confidential information. Duplication, redistribution, or use, in whole or in part,
  in any form, requires consent of both {_e(client)} and {COMPANY_INIT}. {COMPANY_INIT} may share this document
  with auditors under non-disclosure agreements to demonstrate security assessment compliance.</p>

  <h2>2. Disclaimer</h2>
  <p>A security assessment is considered a snapshot in time. The findings and recommendations in this report
  reflect the information gathered during the assessment window ({_e(ctx['date_long'])}) and do not account for
  any changes or modifications made outside of that period. Time-limited engagements do not allow for a full
  evaluation of all security controls. {COMPANY_INIT} prioritized this assessment to identify the weakest security
  controls an attacker would be likely to exploit. {COMPANY_INIT} recommends conducting similar assessments on a
  recurring (e.g. quarterly or annual) basis using internal or third-party assessors.</p>

  <h2>3. Contact Information</h2>
  <table>
    <tr><th>Name</th><th>Title</th><th>Contact Information</th></tr>
    {placeholder_row}
    <tr><td>{COMPANY_NAME} Team</td><td>Security Analyst</td><td>Email: {COMPANY_EMAIL}</td></tr>
  </table>
  <p class="muted">The client contact row above is intentionally left blank for the engagement owner to complete.</p>
</div>"""


# PAGE 3 — Assessment Overview + Components + Severity Classification ----------

def _page_overview_components_severity(ctx: dict) -> str:
    return f"""<div class="report-page">
  <h2>4. Assessment Overview</h2>
  <p>On {_e(ctx['date_long'])}, {COMPANY_INIT} used the {COMPANY_NAME} platform to evaluate the security posture
  of {_e(ctx['client_label'])}'s infrastructure against current industry best practices, including a
  {_e(ctx['scan_label'])} of the in-scope target(s). Methodology is based on the NIST SP 800-115 Technical Guide
  to Information Security Testing and Assessment, the OWASP Testing Guide, and {COMPANY_NAME}'s own automated
  testing framework. Phases of the assessment include the following:</p>
  <ul>
    <li><strong>Planning</strong> – Assessment goals, scope, and rules of engagement are established.</li>
    <li><strong>Discovery</strong> – Scanning and enumeration are performed to identify potential vulnerabilities and weak areas.</li>
    <li><strong>Correlation</strong> – Discovered service versions are matched against known CVE databases and scored for risk.</li>
    <li><strong>Reporting</strong> – All findings, version intelligence, and remediation guidance are documented in this report.</li>
  </ul>

  <h2>5. Assessment Components</h2>
  <p><strong>{_e(ctx['scan_label'])}</strong> – this assessment used {_e(ctx['scan_desc'])}. The assessment lasted
  approximately {_e(ctx['duration_str'])} and covered {ctx['total_hosts']} live host(s).</p>

  <h2>6. Findings Severity Classification</h2>
  <table>
    <tr><th>Severity</th><th>CVSS v3 Score Range</th><th>Definition</th></tr>
    <tr><td>{_badge('critical')}</td><td>9.0 – 10.0</td><td>Exploitation is straightforward and usually results in system-level compromise. Immediate action required.</td></tr>
    <tr><td>{_badge('high')}</td><td>7.0 – 8.9</td><td>Exploitation is more difficult but could cause elevated privileges and potential loss of data or downtime.</td></tr>
    <tr><td>{_badge('medium')}</td><td>4.0 – 6.9</td><td>Vulnerabilities exist but are not easily exploitable or require extra steps. Patch after high-priority issues.</td></tr>
    <tr><td>{_badge('low')}</td><td>0.1 – 3.9</td><td>Non-exploitable but would reduce attack surface. Patch during the next maintenance window.</td></tr>
    <tr><td>{_badge('informational')}</td><td>N/A</td><td>No vulnerability exists. Additional information about strong controls or documentation.</td></tr>
  </table>
  <p class="muted">Note: the per-finding risk level shown elsewhere in this report (Sections 9–10) is
  {COMPANY_NAME}'s composite risk score — CVSS (40%), service criticality (25%), version currency (20%), and
  exposure (15%) — rather than raw CVSS alone, and may therefore differ slightly from the CVE's own CVSS-based
  severity shown on each finding card.</p>
</div>"""


# PAGE 4 — Scope + Executive Summary --------------------------------------------

def _page_scope_executive_summary(ctx: dict) -> str:
    attack_steps = _build_attack_summary(ctx["all_cves"])
    steps_html = "".join(
        f"<tr><td>{i+1}</td><td>{s['action']}</td><td>{_e(s['finding'])}</td></tr>"
        for i, s in enumerate(attack_steps)
    ) or '<tr><td colspan="3" class="muted">No CVE-backed findings were available to summarize an attack chain.</td></tr>'

    strengths = "".join(f"<li>{_e(b)}</li>" for b in _build_strengths(ctx["all_findings"], ctx["severity_counts"]))
    weaknesses = "".join(f"<li>{b}</li>" for b in _build_weaknesses(ctx["all_findings"], ctx["all_cves"]))

    ai_note = ""
    engine = ctx["ai"].get("engine")
    if engine:
        label = "Claude AI" if engine == "claude-ai" else engine.replace("-", " ").title()
        ai_note = f'<p class="muted">Narrative summary generated using {_e(label)} analysis.</p>'

    return f"""<div class="report-page">
  <h2>7. Scope</h2>
  <table>
    <tr><th>Assessment</th><th>Scope Details</th></tr>
    <tr><td>{_e(ctx['scan_label'])}</td><td>{_e(ctx['target'])}</td></tr>
  </table>
  <h3>7.1 Scope Exclusion</h3>
  <p>Per {COMPANY_NAME}'s standard safety policy, denial-of-service style attacks and live exploitation were not
  performed; this assessment is limited to non-intrusive discovery, version detection, and vulnerability
  correlation.</p>
  <h3>7.2 Client Allowances</h3>
  <p>No special allowances (e.g. credentials, IP whitelisting) were provided for this assessment.</p>

  <h2>8. Executive Summary</h2>
  <p>{_e(ctx['summary_text'])}</p>
  <p>Overall risk for this assessment is rated <strong>{_e(ctx['overall'].upper())}</strong>, based on
  {ctx['total_ports']} open service(s) across {ctx['total_hosts']} host(s) and {ctx['total_cves']} matched CVE(s).</p>
  {ai_note}

  <h3>8.1 Attack Summary</h3>
  <p>The following table illustrates how the highest-severity findings could be chained together by an attacker,
  step by step, based on the discovered weaknesses.</p>
  <table>
    <tr><th>Step</th><th>Action</th><th>Finding / Recommendation</th></tr>
    {steps_html}
  </table>

  <h3>8.2 Security Strengths</h3>
  <ul>{strengths}</ul>

  <h3>8.3 Security Weaknesses</h3>
  <ul>{weaknesses}</ul>
</div>"""


# PAGE 5 — Vulnerabilities by Impact (chart) ------------------------------------

def _page_impact_chart(ctx: dict) -> str:
    counts = ctx["severity_counts"]
    total  = max(sum(counts.values()), 1)
    bars = ""
    for level in SEVERITY_ORDER:
        n = counts.get(level, 0)
        pct = round(100 * n / total)
        color = SEVERITY_COLORS[level]
        text_color = SEVERITY_TEXT_ON[level]
        width = max(pct, 3) if n else 0
        if n == 0:
            continue
        bars += (f'<div class="chart-bar" style="background:{color};color:{text_color};width:{width}%;">'
                  f'{level.title()} ({n} finding{"s" if n != 1 else ""}) – {pct}%</div>')
    if not bars:
        bars = '<p class="muted">No open services were found to chart.</p>'

    dominant = max(counts, key=lambda k: counts[k]) if any(counts.values()) else None
    dom_text = (f"{dominant.title()}-severity findings dominate the risk landscape, representing "
                f"{counts[dominant]} of {total} total finding(s)." if dominant and counts[dominant] else
                "No open services with an assigned risk level were found during this assessment.")

    return f"""<div class="report-page">
  <h2>9. Vulnerabilities by Impact</h2>
  <p>Figure 1 illustrates the open services found by impact, based on {COMPANY_NAME}'s composite risk score
  (CVSS, service criticality, version currency, and exposure).</p>
  <div style="margin: 30px 0;">
    <div class="chart-bar-container">{bars}</div>
    <p class="muted"><em>Figure 1: Distribution of findings by severity level ({total} total)</em></p>
  </div>
  <p>{_e(dom_text)}</p>
</div>"""


# PAGE 6+ — Detailed Findings (vuln cards) --------------------------------------

def _pages_detailed_findings(ctx: dict, max_cards: int = 25, per_page: int = 4) -> list:
    cves = ctx["all_cves"]
    shown = cves[:max_cards]
    if not shown:
        return [f"""<div class="report-page">
  <h2>10. {_e(ctx['scan_label'])} Findings</h2>
  <p>No CVE-backed findings were identified for the in-scope target(s). See Appendix A for the full inventory of
  open services observed during this assessment.</p>
</div>"""]

    cards = [_render_vuln_card(i + 1, c) for i, c in enumerate(shown)]
    pages = []
    for i in range(0, len(cards), per_page):
        chunk = cards[i:i + per_page]
        header = f"<h2>10. {_e(ctx['scan_label'])} Findings</h2>" if i == 0 else f"<h3>10. {_e(ctx['scan_label'])} Findings (continued)</h3>"
        note = ""
        if i == 0 and len(cves) > max_cards:
            note = (f'<p class="muted">Showing the top {max_cards} of {len(cves)} total matched CVEs, ordered by '
                     f'CVSS score. The complete list is provided in Appendix B.</p>')
        pages.append(f'<div class="report-page">{header}{note}{"".join(chunk)}</div>')
    return pages


def _render_vuln_card(idx: int, c: dict) -> str:
    sev = c["severity"] if c["severity"] in SEVERITY_COLORS else "unknown"
    color = SEVERITY_COLORS[sev]
    remediation = c["patch"] or "Apply the latest vendor patch for this service and re-scan to confirm remediation."
    ver_str = _ver_str(c["product"], c["version"])
    title_suffix = f" ({_e(ver_str)})" if ver_str else ""
    return f"""<div class="vuln-card" style="border-left-color: {color};">
  <h4>10.{idx} {_e(c['cve_id'])} — {_e(c['service'])}{title_suffix}</h4>
  <p>{_badge(sev)} <span class="vuln-meta">CVSS {c['cvss']:.1f}/10</span></p>
  <p><strong>Description:</strong> {_e(c['desc']) or 'No description available.'}</p>
  <p><strong>Affected System:</strong> {_e(c['host'])}:{_e(c['port'])}/{_e(c['proto'])}</p>
  <p><strong>References:</strong> {_e(c['cve_id'])} — <a href="{_e(c['nvd_url'])}">{_e(c['nvd_url'])}</a></p>
  <p><strong>Remediation:</strong> {_e(remediation)}</p>
</div>"""


# Appendix A — Full port/service inventory --------------------------------------

def _page_appendix_inventory(ctx: dict) -> str:
    rows = ""
    for f in ctx["all_findings"]:
        clr = SEVERITY_COLORS.get(f["risk"], "#8b949e")
        rows += (f"<tr><td>{_e(f['host'])}</td><td>{_e(f['port'])}/{_e(f['proto'])}</td>"
                 f"<td>{_e(f['service'])}</td><td>{_e(f['version_str']) or '—'}</td>"
                 f"<td>{_e(f['v_status'])}</td><td>{_e(f['state'])}</td>"
                 f"<td>{_badge(f['risk'])}</td><td style='font-weight:700;color:{clr}'>{_e(f['score'])}</td>"
                 f"<td>{f['cve_count']}</td></tr>")
    if not rows:
        rows = '<tr><td colspan="9" class="muted">No open ports were found.</td></tr>'
    return f"""<div class="report-page">
  <h2>Appendix A — Full Port &amp; Service Inventory</h2>
  <p>The following table lists every open service observed during this assessment, including those without a
  matched CVE, for completeness.</p>
  <table>
    <tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Version Status</th>
        <th>State</th><th>Risk</th><th>Score</th><th>CVEs</th></tr>
    {rows}
  </table>
</div>"""


# Appendix B — Full CVE table -----------------------------------------------------

def _page_appendix_cve_table(ctx: dict, max_rows: int = 60) -> str:
    cves = ctx["all_cves"]
    shown = cves[:max_rows]
    rows = ""
    for c in shown:
        rows += (f"<tr><td>{_e(c['cve_id'])}</td><td>{_e(c['host'])}:{_e(c['port'])}</td>"
                 f"<td>{_e(c['service'])}</td><td>{c['cvss']:.1f}</td>"
                 f"<td>{_badge(c['severity'])}</td><td>{_e(c['desc'])[:160]}</td></tr>")
    if not rows:
        rows = '<tr><td colspan="6" class="muted">No CVEs were matched during this assessment.</td></tr>'
    note = ""
    if len(cves) > max_rows:
        note = (f'<p class="muted">Showing the top {max_rows} of {len(cves)} matched CVEs, ordered by CVSS score, '
                 f'to keep this report to a manageable length. The complete machine-readable list is retained '
                 f'with the scan session and can be exported on request.</p>')
    return f"""<div class="report-page">
  <h2>Appendix B — CVE Listing ({len(cves)} total matched)</h2>
  {note}
  <table>
    <tr><th>CVE ID</th><th>Host:Port</th><th>Service</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>
    {rows}
  </table>
</div>"""


# Sign-off page -----------------------------------------------------------------

def _page_signoff(ctx: dict) -> str:
    return f"""<div class="report-page">
  <h2>11. Client Acknowledgment &amp; Sign-off</h2>
  <p>By signing below, the client acknowledges receipt of this Security Assessment Finding Report and agrees to
  review the findings, assess associated risks, and implement remediation actions as appropriate.</p>

  <table style="margin-top: 40px;">
    <tr><td style="border: none; width: 50%;"><strong>Client Representative Name:</strong><br><br>
        <div style="border-bottom: 1px solid #000; width: 90%; margin-top: 10px;">&nbsp;</div></td>
        <td style="border: none;"><strong>Title:</strong><br><br>
        <div style="border-bottom: 1px solid #000; width: 90%; margin-top: 10px;">&nbsp;</div></td>
    </tr>
    <tr><td style="border: none;"><strong>Signature:</strong><br><br>
        <div style="border-bottom: 1px solid #000; width: 90%; margin-top: 10px;">&nbsp;</div></td>
        <td style="border: none;"><strong>Date:</strong><br><br>
        <div style="border-bottom: 1px solid #000; width: 90%; margin-top: 10px;">&nbsp;</div></td>
    </tr>
    <tr><td colspan="2" style="border: none;"><strong>Comments / Observations:</strong><br><br>
        <div style="border-bottom: 1px solid #000; width: 100%; margin-top: 10px; height: 60px;">&nbsp;</div></td>
    </tr>
  </table>

  <div style="margin-top: 40px;">
    <p><strong>For {COMPANY_NAME}:</strong></p>
    <div style="margin-top: 20px;">
      <div style="border-bottom: 1px solid #000; width: 250px;">&nbsp;</div>
      <p style="margin-top: 5px;">Lead Security Analyst</p>
      <p>{_e(ctx['date_long'])}</p>
    </div>
  </div>

  <div class="footer-note">This sign-off confirms that the report has been delivered and accepted for review.</div>
</div>"""


# Closing page --------------------------------------------------------------------

def _page_thankyou(ctx: dict) -> str:
    return f"""<div class="report-page">
  <div class="thankyou">
    <h1 style="font-size: 32px; margin-bottom: 30px;">Thank You</h1>
    <p style="font-size: 16px; margin-bottom: 20px;">We appreciate the opportunity to assess your security posture.</p>
    <p style="font-size: 14px; color: #4a627a;">{COMPANY_NAME} remains committed to helping you build a resilient and secure environment.</p>
    <p style="margin-top: 50px; font-size: 12px;">For any questions or follow-up, please contact us at {COMPANY_EMAIL}</p>
    <p style="margin-top: 90px; font-style: italic; font-size: 12px;">— This report concludes the Security Assessment Finding Report —</p>
  </div>
  <div class="footer-note">Generated by {COMPANY_NAME} – Professional Security Assessment Platform &nbsp;|&nbsp; {_e(ctx['date_short'])}</div>
</div>"""
