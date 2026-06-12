"""
HTML Report Generator
Produces a self-contained HTML report from session analysis data.
Can be printed to PDF via browser (Ctrl+P → Save as PDF).
No external dependencies required.
"""
import os
import json
import time
import html as _html


def _e(v) -> str:
    """HTML-escape any value. Fix #9 — prevents XSS in exported reports."""
    return _html.escape(str(v) if v is not None else "")

BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "sessions"
)

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "reports"
)


def build_html_report(session_id: str, analysis: dict) -> str:
    """Generate a self-contained HTML report. Returns file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    hosts       = analysis.get("risk", {}).get("hosts", [])
    explanation = analysis.get("explanation", {})
    rec         = analysis.get("recommendation", {})
    ai          = analysis.get("ai_analysis", {})
    target      = analysis.get("target", "unknown")
    scan_type   = analysis.get("scan_type", "unknown")
    timestamp   = analysis.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))

    # Aggregate data
    all_findings   = []
    all_cves       = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for host in hosts:
        for port in host.get("ports", []):
            risk  = port.get("risk", {})
            level = risk.get("level", "low")
            severity_counts[level] = severity_counts.get(level, 0) + 1
            all_findings.append({
                "host":    host.get("ip"),
                "port":    port.get("port"),
                "proto":   port.get("protocol", "tcp"),
                "service": port.get("service"),
                "version": f"{port.get('product','')} {port.get('version','')}".strip(),
                "state":   port.get("state"),
                "risk":    level,
                "score":   risk.get("score", 0),
                "v_status": port.get("version_analysis", {}).get("status", "unknown"),
            })
            for cve in port.get("cves", []):
                all_cves.append({
                    "cve_id":  cve["cve_id"],
                    "service": port.get("service"),
                    "port":    port.get("port"),
                    "cvss":    cve["cvss_score"],
                    "severity": cve["severity"],
                    "desc":    cve["description"],
                    "patch":   cve.get("patch", ""),
                })

    all_cves.sort(key=lambda x: x["cvss"], reverse=True)
    overall = _overall(severity_counts)

    color_map = {"critical": "#E24B4A", "high": "#EF9F27",
                 "medium": "#378ADD", "low": "#1D9E75", "unknown": "#8b949e"}

    # Build HTML sections
    findings_html  = _findings_table(all_findings, color_map)
    cve_html       = _cve_table(all_cves, color_map)
    guidance_html  = _guidance_list(explanation.get("defensive_guidance", []))
    ai_html        = _ai_section(ai)
    summary_html   = _summary_cards(severity_counts, len(all_cves), len(hosts))
    chart_data_json = json.dumps({
        "risk":     [severity_counts["critical"], severity_counts["high"],
                     severity_counts["medium"],   severity_counts["low"]],
        "cve_svcs": _cve_by_service(all_cves),
    })

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ThreatWeave — Security Report — {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#f6f8fa;color:#24292f;font-size:14px;line-height:1.6}}
  .page{{max-width:1100px;margin:0 auto;padding:32px 24px}}
  h1{{font-size:24px;font-weight:700;color:#0d1117}}
  h2{{font-size:16px;font-weight:600;color:#0d1117;margin:28px 0 12px;
      border-bottom:2px solid #e1e4e8;padding-bottom:6px}}
  h3{{font-size:14px;font-weight:600;color:#0d1117;margin:0 0 8px}}
  .header{{background:#0d1117;color:#e6edf3;padding:28px 32px;border-radius:12px;
           margin-bottom:28px;display:flex;justify-content:space-between;align-items:center}}
  .header-left h1{{color:#e6edf3;font-size:22px}}
  .header-left p{{color:#8b949e;margin-top:4px;font-size:13px}}
  .badge{{padding:4px 12px;border-radius:20px;font-weight:700;font-size:12px;
          text-transform:uppercase}}
  .badge-critical{{background:#3d1f1f;color:#E24B4A}}
  .badge-high{{background:#3d2a0f;color:#EF9F27}}
  .badge-medium{{background:#1a2d3d;color:#378ADD}}
  .badge-low{{background:#1a2d25;color:#1D9E75}}
  .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}
  .card{{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:16px;text-align:center}}
  .card-num{{font-size:32px;font-weight:700}}
  .card-label{{font-size:12px;color:#57606a;margin-top:4px}}
  .card-critical .card-num{{color:#E24B4A}}
  .card-high .card-num{{color:#EF9F27}}
  .card-medium .card-num{{color:#378ADD}}
  .card-low .card-num{{color:#1D9E75}}
  table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d0d7de;
         border-radius:8px;overflow:hidden;font-size:13px}}
  th{{background:#f6f8fa;padding:10px 14px;text-align:left;font-weight:600;
      border-bottom:1px solid #d0d7de;color:#57606a;font-size:12px;text-transform:uppercase}}
  td{{padding:10px 14px;border-bottom:1px solid #f0f0f0}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#f6f8fa}}
  .risk-pill{{display:inline-block;padding:2px 8px;border-radius:10px;
              font-size:11px;font-weight:700;text-transform:uppercase}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}}
  .chart-box{{background:#fff;border:1px solid #d0d7de;border-radius:8px;
              padding:20px;height:280px;position:relative}}
  .chart-box h3{{margin-bottom:12px;font-size:13px;color:#57606a}}
  .guidance-list{{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:16px}}
  .guidance-item{{padding:8px 0;border-bottom:1px solid #f0f0f0;
                  display:flex;gap:10px;font-size:13px}}
  .guidance-item:last-child{{border-bottom:none}}
  .guidance-arrow{{color:#1D9E75;font-weight:700;flex-shrink:0}}
  .rec-box{{background:#1c2d40;border:1px solid #2a5a7e;border-radius:8px;
            padding:16px;color:#e6edf3}}
  .rec-box h3{{color:#388bfd;margin-bottom:6px}}
  .rec-box p{{font-size:13px;color:#8b949e}}
  .ai-box{{background:#1a1f2e;border:1px solid #7f77dd44;border-radius:8px;
           padding:16px;color:#e6edf3}}
  .ai-box h3{{color:#7f77dd;margin-bottom:8px}}
  .ai-summary{{font-size:13px;color:#c9d1d9;line-height:1.7}}
  .ai-engine{{font-size:11px;color:#8b949e;margin-top:8px}}
  .footer{{text-align:center;color:#8b949e;font-size:12px;margin-top:32px;
           padding-top:16px;border-top:1px solid #e1e4e8}}
  .section{{background:#fff;border:1px solid #d0d7de;border-radius:8px;
            padding:20px;margin-bottom:20px}}
  @media print{{
    body{{background:#fff}}
    .page{{padding:16px}}
    .charts{{grid-template-columns:1fr 1fr}}
    canvas{{max-height:200px}}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>🛡 ThreatWeave — Security Assessment Report</h1>
      <p>Target: <strong>{target}</strong> &nbsp;|&nbsp;
         Scan: <strong>{scan_type}</strong> &nbsp;|&nbsp;
         Date: <strong>{timestamp}</strong></p>
    </div>
    <div>
      <span class="badge badge-{overall}">{overall.upper()} RISK</span>
    </div>
  </div>

  <!-- Summary cards -->
  <h2>Executive Summary</h2>
  {summary_html}

  <!-- Charts -->
  <h2>Visual Analysis</h2>
  <div class="charts">
    <div class="chart-box">
      <h3>Risk Distribution</h3>
      <canvas id="riskChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>CVEs per Service</h3>
      <canvas id="cveChart"></canvas>
    </div>
  </div>

  <!-- AI Analysis -->
  {ai_html}

  <!-- Findings table -->
  <h2>Findings ({len(all_findings)} open ports)</h2>
  {findings_html}

  <!-- CVE table -->
  <h2>CVE Details ({len(all_cves)} matched)</h2>
  {cve_html}

  <!-- Defensive guidance -->
  <h2>Defensive Guidance</h2>
  <div class="guidance-list">{guidance_html}</div>

  <div class="footer">
    Generated by ThreatWeave v1.0 &nbsp;|&nbsp;
    For defensive security assessment only &nbsp;|&nbsp;
    {time.strftime("%Y-%m-%d %H:%M:%S")}
  </div>
</div>

<script>
const D = {chart_data_json};

// Risk distribution doughnut
new Chart(document.getElementById('riskChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical','High','Medium','Low'],
    datasets: [{{
      data: D.risk,
      backgroundColor: ['#E24B4A','#EF9F27','#378ADD','#1D9E75'],
      borderWidth: 0
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'right', labels: {{ font: {{ size: 11 }} }} }} }}
  }}
}});

// CVE per service bar
const svcs = D.cve_svcs;
new Chart(document.getElementById('cveChart'), {{
  type: 'bar',
  data: {{
    labels: Object.keys(svcs).map(s=>s.toUpperCase()),
    datasets: [{{
      data: Object.values(svcs),
      backgroundColor: '#E24B4A88',
      borderColor: '#E24B4A',
      borderWidth: 1
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }}
  }}
}});
</script>
</body>
</html>"""

    fname = f"report_{session_id}_{time.strftime('%Y%m%d_%H%M%S')}.html"
    fpath = os.path.join(REPORTS_DIR, fname)
    with open(fpath, "w") as f:
        f.write(html)

    # Also save to session folder
    sess_report_dir = os.path.join(BASE_DIR, session_id, "report")
    os.makedirs(sess_report_dir, exist_ok=True)
    with open(os.path.join(sess_report_dir, "report.html"), "w") as f:
        f.write(html)

    return fpath


# ── HTML helpers ───────────────────────────────────────────────────────────────

def _overall(counts):
    if counts.get("critical", 0) > 0: return "critical"
    if counts.get("high", 0) > 0:     return "high"
    if counts.get("medium", 0) > 0:   return "medium"
    return "low"

def _cve_by_service(cves):
    result = {}
    for c in cves:
        svc = c.get("service", "unknown")
        result[svc] = result.get(svc, 0) + 1
    return result

def _summary_cards(counts, total_cves, total_hosts):
    return f"""<div class="cards">
  <div class="card card-critical">
    <div class="card-num">{counts['critical']}</div>
    <div class="card-label">Critical</div>
  </div>
  <div class="card card-high">
    <div class="card-num">{counts['high']}</div>
    <div class="card-label">High</div>
  </div>
  <div class="card card-medium">
    <div class="card-num">{counts['medium']}</div>
    <div class="card-label">Medium</div>
  </div>
  <div class="card card-low">
    <div class="card-num">{counts['low']}</div>
    <div class="card-label">Low</div>
  </div>
</div>
<div class="cards" style="grid-template-columns:repeat(2,1fr)">
  <div class="card">
    <div class="card-num" style="color:#7f77dd">{total_cves}</div>
    <div class="card-label">Total CVEs Matched</div>
  </div>
  <div class="card">
    <div class="card-num" style="color:#388bfd">{total_hosts}</div>
    <div class="card-label">Live Hosts</div>
  </div>
</div>"""

def _findings_table(findings, color_map):
    if not findings:
        return "<p style='color:#8b949e;padding:16px'>No open ports found.</p>"
    rows = ""
    for f in findings:
        clr  = color_map.get(f["risk"], "#888")
        rows += f"""<tr>
  <td>{_e(f['host'])}</td>
  <td><strong>{_e(f['port'])}/{_e(f['proto'])}</strong></td>
  <td>{_e(f['service'])}</td>
  <td style="font-family:monospace;font-size:12px">{_e(f['version']) or '—'}</td>
  <td>{_e(f['v_status'])}</td>
  <td>{_e(f['state'])}</td>
  <td><span class="risk-pill" style="background:{clr}22;color:{clr}">{_e(f['risk']).upper()}</span></td>
  <td style="font-weight:700;color:{clr}">{_e(str(f['score']))}</td>
</tr>"""
    return f"""<table>
<thead><tr>
  <th>Host</th><th>Port</th><th>Service</th><th>Version</th>
  <th>V.Status</th><th>State</th><th>Risk</th><th>Score</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""

def _cve_table(cves, color_map):
    if not cves:
        return "<p style='color:#8b949e;padding:16px'>No CVEs matched in this scan.</p>"
    rows = ""
    for c in cves:
        clr  = color_map.get(c["severity"], "#888")
        rows += f"""<tr>
  <td style="font-family:monospace;font-weight:700;color:#388bfd">{_e(c['cve_id'])}</td>
  <td>{_e(c['service'])}</td>
  <td><strong>{_e(str(c['cvss']))}</strong></td>
  <td><span class="risk-pill" style="background:{clr}22;color:{clr}">{_e(c['severity']).upper()}</span></td>
  <td style="color:#57606a">{_e(c['desc'])}</td>
  <td style="color:#1D9E75;font-size:12px">{_e(c['patch'])}</td>
</tr>"""
    return f"""<table>
<thead><tr>
  <th>CVE ID</th><th>Service</th><th>CVSS</th><th>Severity</th>
  <th>Description</th><th>Patch</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""

def _guidance_list(items):
    if not items:
        return "<p style='color:#8b949e'>No guidance generated.</p>"
    return "".join(
        f'<div class="guidance-item"><span class="guidance-arrow">→</span><span>{_e(g)}</span></div>'
        for g in items
    )

def _recommendation_box(rec):
    if not rec:
        return "<p style='color:#8b949e'>No recommendation available.</p>"
    return f"""<div class="rec-box">
  <h3>💡 {rec.get('title','Next Scan')}</h3>
  <p>{rec.get('reason','')}</p>
  {"<p style='margin-top:8px;color:#c9d1d9'>Scan type: <strong>" + rec.get('scan_type','') + "</strong></p>" if rec.get('scan_type') else ''}
</div>"""

def _ai_section(ai):
    if not ai:
        return ""
    engine  = ai.get("engine", "unknown")
    summary = ai.get("summary", "")
    overall = ai.get("overall_risk", "")
    icon    = "🤖" if engine == "claude-ai" else "⚙️"
    label   = "Claude AI Analysis" if engine == "claude-ai" else "Rule-Based Analysis"
    return f"""<h2>AI Analysis</h2>
<div class="ai-box">
  <h3>{icon} {label}</h3>
  <div class="ai-summary">{_e(summary)}</div>
  {"<p style='margin-top:8px;color:#7f77dd'>AI Overall Risk: <strong>" + overall.upper() + "</strong></p>" if overall else ""}
  <div class="ai-engine">Engine: {engine}</div>
</div>"""
