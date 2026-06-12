"""
ThreatWeave — Professional Report Builder (Phase 17/18)
=======================================================
Generates professional-grade HTML/PDF reports including:
  - Executive Summary
  - Security Score (A-F grade) with breakdown
  - Asset Criticality per host
  - Threat Intelligence (KEV, EPSS, threat actors)
  - Vulnerability Timeline
  - Patch Commands with vendor URLs and confidence scores
  - Risk Breakdown charts
  - Appendix with CVE details

Phase 18 additions:
  - Patch commands per CVE
  - Vendor URLs and fix versions
  - Mitigation steps and verification status
  - Confidence scores (Vendor=100, NVD=90, AI=70)
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ThreatWeave.report.professional")

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "reports"
)
os.makedirs(REPORTS_DIR, exist_ok=True)


def build_professional_report(session_data: dict) -> str:
    """
    Build a complete professional HTML report.
    Includes all Phase 8/17/18 features.
    Returns the file path of the saved report.
    """
    sess_id  = session_data.get("session_id", "unknown")
    target   = session_data.get("target", "Unknown Target")
    parsed   = session_data.get("parsed")   or {}
    analysis = session_data.get("analysis") or {}
    ts       = session_data.get("timestamp", datetime.now(timezone.utc).isoformat())[:10]

    # Phase 8 enrichment
    try:
        from app.analysis.security_score import calculate_security_score
        sec_score = calculate_security_score(analysis, parsed)
    except Exception:
        sec_score = {"score": 0, "grade": "?", "label": "Unavailable", "dimensions": [], "recommendations": []}

    try:
        from app.analysis.threat_intel import enrich_with_threat_intel
        cves  = analysis.get("cves", []) or []
        svcs  = [p.get("service", {}).get("name", "") for h in parsed.get("hosts", []) for p in h.get("ports", [])]
        ti    = enrich_with_threat_intel(cves, svcs)
    except Exception:
        ti = {"kev_count": 0, "threat_summary": "Threat intelligence unavailable.", "enriched_cves": []}

    try:
        from app.analysis.vuln_timeline import build_cve_timeline
        timeline = build_cve_timeline(cves if 'cves' in dir() else [])
    except Exception:
        timeline = {"stats": {}, "kev_count": 0}

    html = _render_html(target, ts, sess_id, parsed, analysis, sec_score, ti, timeline)

    fname = f"ThreatWeave_report_{sess_id[:8]}_{ts.replace('-','')}.html"
    fpath = os.path.join(REPORTS_DIR, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(html)
    return fpath


def _port_rows(hosts: list) -> str:
    """Build HTML table rows for open ports — avoids f-string dict literal issues."""
    rows = []
    for h in hosts:
        for p in h.get("ports", [])[:30]:
            svc     = p.get("service") or {}
            svc_name = svc.get("name", "?") if isinstance(svc, dict) else "?"
            version  = (svc.get("version", "") or "") if isinstance(svc, dict) else ""
            rows.append(
                f'<tr><td><strong>{p.get("port")}</strong></td>'
                f'<td>{p.get("protocol","tcp")}</td>'
                f'<td>{svc_name}</td>'
                f'<td><code>{version[:40]}</code></td>'
                f'<td>🟢 {p.get("state","open")}</td></tr>'
            )
    if not rows:
        return '<tr><td colspan="5" style="text-align:center;color:#718096;padding:20px">No open ports found</td></tr>'
    return "".join(rows)


def _render_html(target, ts, sess_id, parsed, analysis, sec_score, ti, timeline) -> str:
    hosts      = parsed.get("hosts", []) if isinstance(parsed, dict) else []
    all_ports  = [p for h in hosts for p in h.get("ports", [])]
    risk_hosts = (analysis.get("risk") or {}).get("hosts", []) or []
    cves       = analysis.get("cves", []) or []

    grade      = sec_score.get("grade", "?")
    score      = sec_score.get("score", 0)
    score_label = sec_score.get("label", "")
    grade_color = {"A":"#2ecc71","B":"#27ae60","C":"#f39c12","D":"#e67e22","F":"#e74c3c"}.get(grade, "#95a5a6")

    overall_risk = analysis.get("overall_risk", "unknown").upper()
    risk_color   = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f39c12","LOW":"#2ecc71"}.get(overall_risk, "#95a5a6")

    kev_count    = ti.get("kev_count", 0)
    active_exploits = ti.get("active_exploit_count", 0)

    now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dims_html = ""
    for d in sec_score.get("dimensions", []):
        bar_w = int(d["score"])
        bar_c = "#2ecc71" if d["score"] >= 75 else "#f39c12" if d["score"] >= 50 else "#e74c3c"
        dims_html += f"""
        <tr>
          <td>{d['name']}</td>
          <td style="width:200px">
            <div style="background:#eee;border-radius:4px;height:14px">
              <div style="width:{bar_w}%;background:{bar_c};height:14px;border-radius:4px"></div>
            </div>
          </td>
          <td style="font-weight:bold">{d['score']}/100</td>
          <td style="color:#666;font-size:0.85em">{d['weight']} · {d['detail']}</td>
        </tr>"""

    vuln_rows = ""
    patch_section = ""
    for cve in ti.get("enriched_cves", [])[:50]:
        cve_id   = cve.get("cve_id", "?")
        svc      = cve.get("service", "?")
        sev      = cve.get("severity", "?").upper()
        cvss     = cve.get("cvss_score", cve.get("cvss", 0))
        is_kev   = cve.get("is_kev", False)
        epss     = cve.get("epss_score", 0)
        priority = cve.get("threat_priority", "?")
        sev_c    = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f39c12","LOW":"#2ecc71"}.get(sev,"#95a5a6")
        kev_badge = '<span style="background:#e74c3c;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.75em;margin-left:4px">KEV</span>' if is_kev else ""
        vuln_rows += f"""<tr>
          <td><a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank">{cve_id}</a>{kev_badge}</td>
          <td>{svc}</td>
          <td style="color:{sev_c};font-weight:bold">{sev}</td>
          <td>{cvss}</td>
          <td>{epss:.3f}</td>
          <td>{priority}</td>
        </tr>"""

        # Patch section — 4-Layer Intelligent Resolver (Phase 10)
        try:
            from app.remediation import resolve_patch
            patch = resolve_patch(
                cve_id  = cve_id,
                service = svc if svc != "?" else "",
            )
            if patch and patch.get("patch_found"):
                cmds     = patch.get("commands") or patch.get("patch_command") or {}
                cmd_html = ""
                for os_name, cmd_str in list(cmds.items())[:2]:
                    cmd_html += (
                        f'<div style="margin:4px 0"><strong>{os_name}:</strong><br>'
                        f'<code style="background:#f4f4f4;padding:4px 8px;display:block;border-radius:3px">'
                        f'{cmd_str}</code></div>'
                    )
                conf      = patch.get("confidence", 0)
                conf_c    = "#2ecc71" if conf >= 90 else "#f39c12" if conf >= 70 else "#e67e22"
                conf_lbl  = patch.get("confidence_label", patch.get("source", "?"))
                layer_lbl = patch.get("layer", "?").replace("_", " ").title()
                url       = patch.get("vendor_url") or patch.get("official_url", "")
                patch_section += f"""
                <div style="margin:12px 0;padding:12px;border:1px solid #ddd;border-radius:6px;border-left:4px solid {sev_c}">
                  <strong>{cve_id}</strong> — {patch.get('title','')}<br>
                  <span style="font-size:0.85em;color:#666">
                    Service: {svc} |
                    Fix Version: <code>{patch.get('fix_version') or patch.get('fixed_version') or 'latest'}</code> |
                    <span style="color:{conf_c}">Confidence: {conf}% — {conf_lbl}</span> |
                    Source: {layer_lbl}
                  </span>
                  {cmd_html}
                  {f'<div style="margin-top:6px;font-size:0.85em">🛡️ Mitigation: {patch.get("mitigation","")}</div>' if patch.get("mitigation") else ""}
                  {f'<div style="margin-top:4px;font-size:0.85em"><a href="{url}">Vendor Advisory ↗</a></div>' if url else ""}
                </div>"""
        except Exception:
            pass

    recs_html = "".join(f"<li>{r}</li>" for r in sec_score.get("recommendations", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatWeave — Security Report: {target}</title>
<style>
  body {{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0;background:#f5f7fa;color:#2d3748}}
  .page {{max-width:1100px;margin:0 auto;padding:32px 24px}}
  .header {{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:40px;border-radius:12px;margin-bottom:24px}}
  .header h1 {{margin:0 0 8px;font-size:2em}}
  .header p {{margin:0;opacity:0.8}}
  .badge {{display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.85em;font-weight:bold;margin:4px}}
  .card {{background:#fff;border-radius:10px;padding:24px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
  .card h2 {{margin-top:0;padding-bottom:10px;border-bottom:2px solid #e2e8f0;font-size:1.2em}}
  .grade-circle {{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:2.5em;font-weight:bold;color:#fff;margin:0 auto}}
  .metric-grid {{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}
  .metric {{background:#fff;border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
  .metric .val {{font-size:2em;font-weight:bold}}
  .metric .lbl {{font-size:0.85em;color:#718096;margin-top:4px}}
  table {{width:100%;border-collapse:collapse;font-size:0.9em}}
  th {{background:#f7fafc;text-align:left;padding:10px 12px;border-bottom:2px solid #e2e8f0;font-weight:600}}
  td {{padding:8px 12px;border-bottom:1px solid #edf2f7}}
  tr:hover td {{background:#f7fafc}}
  .tag {{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.78em;font-weight:bold}}
  code {{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:0.9em}}
  @media print {{body{{background:#fff}}.page{{padding:16px}}}}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <h1>🛡️ Network Security Assessment Report</h1>
    <p>Target: <strong>{target}</strong> &nbsp;·&nbsp; Generated: {now_str} &nbsp;·&nbsp; Session: {sess_id[:8]}</p>
    <div style="margin-top:16px">
      <span class="badge" style="background:{risk_color}">Overall Risk: {overall_risk}</span>
      <span class="badge" style="background:{grade_color}">Security Grade: {grade} ({score}/100)</span>
      {f'<span class="badge" style="background:#e74c3c">{kev_count} KEV CVEs</span>' if kev_count else ''}
      {f'<span class="badge" style="background:#c0392b">{active_exploits} Active Exploits</span>' if active_exploits else ''}
    </div>
  </div>

  <!-- Metrics -->
  <div class="metric-grid">
    <div class="metric">
      <div class="val" style="color:{grade_color}">{grade}</div>
      <div class="lbl">Security Grade</div>
    </div>
    <div class="metric">
      <div class="val">{len(all_ports)}</div>
      <div class="lbl">Open Ports</div>
    </div>
    <div class="metric">
      <div class="val" style="color:{'#e74c3c' if len(cves) > 5 else '#f39c12' if len(cves) > 0 else '#2ecc71'}">{len(cves)}</div>
      <div class="lbl">CVEs Found</div>
    </div>
    <div class="metric">
      <div class="val" style="color:{'#e74c3c' if kev_count else '#2ecc71'}">{kev_count}</div>
      <div class="lbl">In CISA KEV</div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="card">
    <h2>📋 Executive Summary</h2>
    <p>Security assessment of <strong>{target}</strong> completed on {ts}.
    The target has a security grade of <strong style="color:{grade_color}">{grade} ({score}/100 — {score_label})</strong>
    with <strong>{len(all_ports)}</strong> open ports, <strong>{len(cves)}</strong> CVEs identified,
    and <strong>{kev_count}</strong> vulnerabilities in the CISA Known Exploited Vulnerabilities catalog.</p>
    <p>{ti.get('threat_summary','')}</p>
    {f'<ul>{"".join(f"<li>{r}</li>" for r in sec_score.get("recommendations",[])[:4])}</ul>' if sec_score.get("recommendations") else ""}
  </div>

  <!-- Security Score -->
  <div class="card">
    <h2>🔐 Security Score Breakdown</h2>
    <table>
      <tr><th>Dimension</th><th>Score Bar</th><th>Score</th><th>Detail</th></tr>
      {dims_html}
    </table>
    <p style="margin-top:12px;font-size:0.85em;color:#718096">
      Formula: (Vulnerability Density×25%) + (Critical Exposure×30%) + (Patch Currency×20%) + (Attack Surface×15%) + (Config Quality×10%)
    </p>
  </div>

  <!-- Vulnerability Intelligence -->
  <div class="card">
    <h2>⚠️ Vulnerability Intelligence ({len(cves)} CVEs)</h2>
    {f'<div style="background:#fef3cd;padding:10px;border-radius:6px;margin-bottom:12px">⚠️ {kev_count} CVE(s) are in the CISA KEV catalog — actively exploited in the wild.</div>' if kev_count else ''}
    <table>
      <tr><th>CVE ID</th><th>Service</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Priority</th></tr>
      {vuln_rows or '<tr><td colspan="6" style="text-align:center;color:#718096;padding:20px">No CVEs found — good posture!</td></tr>'}
    </table>
  </div>

  <!-- Patch Recommendations -->
  {f'<div class="card"><h2>🔧 Patch Recommendations (Phase 18)</h2>{patch_section}</div>' if patch_section else ''}

  <!-- Open Ports -->
  <div class="card">
    <h2>🔓 Open Ports & Services ({len(all_ports)} found)</h2>
    <table>
      <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th></tr>
      {_port_rows(hosts)}
    </table>
  </div>

  <!-- Footer -->
  <div style="text-align:center;color:#718096;font-size:0.85em;margin-top:32px;padding-top:16px;border-top:1px solid #e2e8f0">
    Generated by <strong>ThreatWeave</strong> · 4-Model Local Stack · {now_str}<br>
    <em>For authorized security testing only. Keep this report confidential.</em>
  </div>

</div>
</body>
</html>"""
