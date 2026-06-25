"""
Multi-Format Report Generator v3.0
- PDF now mirrors the formal "Security Assessment Finding Report" template
  used by the HTML report (cover / confidentiality / disclaimer / scope /
  executive summary / attack-chain summary / severity-classified findings /
  appendices / client sign-off / closing page), built natively with
  reportlab so it does not depend on a browser print engine.
- Reuses app.report.html_report._build_context() so the PDF and HTML
  exports always show identical figures and narrative text.
- DOCX format has been removed; only 'pdf' and 'html' are supported
- Removes "Recommended Next Scan" / "Script Enumeration" from all exports
- Download endpoints with correct MIME types
"""
import os
import json
import time
import logging

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Literal

logger       = logging.getLogger(__name__)
report_router = APIRouter()

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "reports"
)
BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "sessions"
)


class ReportGenRequest(BaseModel):
    session_id: str
    format: Literal["pdf", "html"] = "html"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@report_router.post("/report/generate")
async def generate_report_multi(req: ReportGenRequest):
    """Generate a report in the requested format."""
    from app.files.session_manager import get_session
    from app.report.html_report import build_html_report

    data = get_session(req.session_id)
    if not data:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")

    os.makedirs(REPORTS_DIR, exist_ok=True)

    if req.format == "html":
        path  = build_html_report(req.session_id, data)
        fname = os.path.basename(path)
        return {
            "format":   "html",
            "filename": fname,
            "download": f"/api/report/download/html/{req.session_id}",
            "message":  "HTML report ready"
        }

    elif req.format == "pdf":
        path  = _build_pdf(req.session_id, data)
        fname = os.path.basename(path)
        return {
            "format":   "pdf",
            "filename": fname,
            "download": f"/api/report/download/file/{req.session_id}/pdf",
            "message":  "PDF report ready"
        }

    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'pdf' or 'html'.")


@report_router.get("/report/download/html/{session_id}")
async def download_html_report(session_id: str):
    """Serve the generated HTML report as a downloadable file.
    FIX: This endpoint was referenced in generate_report_multi() but never existed,
    causing HTML reports to 404 when clicked.
    """
    import glob
    from fastapi.responses import FileResponse
    from fastapi import HTTPException

    # Find any HTML file matching this session_id
    matches = glob.glob(os.path.join(REPORTS_DIR, f"report_{session_id}*.html"))
    if not matches:
        # Regenerate on-the-fly if not cached
        from app.files.session_manager import get_session
        from app.report.html_report import build_html_report
        data = get_session(session_id)
        if not data:
            raise HTTPException(status_code=404, detail="Session not found — run the scan again.")
        path = build_html_report(session_id, data)
    else:
        # Use the most recently modified match
        matches.sort(key=os.path.getmtime, reverse=True)
        path = matches[0]

    return FileResponse(
        path,
        media_type="text/html",
        filename=f"ThreatWeave_report_{session_id}.html",
        headers={"Content-Disposition": f'attachment; filename="ThreatWeave_report_{session_id}.html"'}
    )


@report_router.get("/report/download/file/{session_id}/{fmt}")
async def download_report_file(session_id: str, fmt: str):
    from fastapi.responses import FileResponse
    from fastapi import HTTPException

    ext_map  = {"pdf": ".pdf"}
    ext      = ext_map.get(fmt, ".html")
    path     = os.path.join(REPORTS_DIR, f"report_{session_id}{ext}")

    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=f"{fmt.upper()} report not found. Generate it first via /api/report/generate."
        )

    MIME = {
        "pdf":  "application/pdf",
    }
    return FileResponse(
        path,
        media_type=MIME.get(fmt, "application/octet-stream"),
        filename=f"ThreatWeave_report_{session_id}{ext}",
        headers={"Content-Disposition": f'attachment; filename="ThreatWeave_report_{session_id}{ext}"'}
    )


# ── PDF builder ───────────────────────────────────────────────────────────────
#
# Mirrors app.report.html_report's page layout 1:1 in reportlab so the PDF
# export is a faithful, browser-independent rendition of the same formal
# "Security Assessment Finding Report" template. All figures and narrative
# text are pulled from the shared `_build_context()` helper so the PDF and
# HTML exports can never drift apart.

def _build_pdf(session_id: str, analysis: dict) -> str:
    out_path = os.path.join(REPORTS_DIR, f"report_{session_id}.pdf")
    os.makedirs(REPORTS_DIR, exist_ok=True)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                         TableStyle, HRFlowable, PageBreak, KeepTogether)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm

        from app.report.html_report import (
            _build_context, _build_attack_summary, _build_strengths, _build_weaknesses,
            _ver_str, SEVERITY_COLORS, SEVERITY_ORDER, COMPANY_NAME, COMPANY_INIT, COMPANY_EMAIL,
        )

        ctx = _build_context(session_id, analysis)

        PAGE_W, _ = A4
        CONTENT_W = PAGE_W - 40 * mm  # 20mm margins each side -> 170mm usable

        def _c(level: str):
            return colors.HexColor(SEVERITY_COLORS.get((level or "unknown").lower(), "#8b949e"))

        def _text_on(level: str):
            return colors.HexColor("#1e2a3a") if (level or "").lower() == "medium" else colors.white

        styles = getSampleStyleSheet()
        muted_clr = colors.HexColor("#4a627a")
        body      = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13)
        body_sm   = ParagraphStyle("BodySm", parent=styles["Normal"], fontSize=8.5, leading=11.5)
        body_sm_c = ParagraphStyle("BodySmCenter", parent=body_sm, alignment=TA_CENTER)
        muted     = ParagraphStyle("Muted", parent=body, fontSize=8.5, textColor=muted_clr)
        center    = ParagraphStyle("Center", parent=body, alignment=TA_CENTER)
        muted_c   = ParagraphStyle("MutedCenter", parent=muted, alignment=TA_CENTER)
        h1        = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16, textColor=colors.HexColor("#0b2b3b"), spaceAfter=6)
        h2        = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1c4e6e"), spaceBefore=10, spaceAfter=6)
        h3        = ParagraphStyle("H3", parent=styles["Heading3"], fontSize=11, textColor=colors.HexColor("#2c5a7a"), spaceBefore=8, spaceAfter=4)
        h4        = ParagraphStyle("H4", parent=styles["Heading4"], fontSize=9.5, textColor=colors.HexColor("#2c5a7a"), spaceAfter=2)
        cover_t   = ParagraphStyle("CoverTitle", parent=h1, fontSize=26, alignment=TA_CENTER, spaceAfter=10)
        cover_s   = ParagraphStyle("CoverSub", parent=body, fontSize=15, alignment=TA_CENTER)

        def _tbl(data, **kw):
            tb = Table(data, **kw)
            tb.hAlign = "LEFT"
            return tb

        TABLE_HDR = ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f4f8"))
        TABLE_GRID = ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bdc4cf"))
        TABLE_BASE = [TABLE_HDR, TABLE_GRID,
                      ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                      ("VALIGN", (0, 0), (-1, -1), "TOP"),
                      ("LEFTPADDING", (0, 0), (-1, -1), 5),
                      ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                      ("TOPPADDING", (0, 0), (-1, -1), 4),
                      ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]

        def _badge_para(level: str) -> Paragraph:
            level = (level or "unknown").lower()
            label = "Informational" if level == "informational" else level.title()
            st = ParagraphStyle(f"Badge{level}", parent=body_sm, textColor=_text_on(level),
                                 backColor=_c(level), alignment=TA_CENTER, borderPadding=3)
            return Paragraph(f"<b>{label}</b>", st)

        story = []

        # ── Footer drawn on every page ──────────────────────────────────────
        def _footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#ddd"))
            canvas.line(20 * mm, 16 * mm, PAGE_W - 20 * mm, 16 * mm)
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(muted_clr)
            canvas.drawString(20 * mm, 11 * mm, f"{COMPANY_NAME} — CONFIDENTIAL — {ctx['target']}")
            canvas.drawRightString(PAGE_W - 20 * mm, 11 * mm, f"Page {doc.page}")
            canvas.restoreState()

        # ── PAGE 1 — Cover ───────────────────────────────────────────────────
        story.append(Spacer(1, 55 * mm))
        story.append(Paragraph(ctx["client_label"], cover_t))
        story.append(Paragraph("Security Assessment Finding Report", cover_s))
        if ctx["project"] and ctx["client_label"] != "[Client Organization Name]":
            story.append(Spacer(1, 4 * mm))
            story.append(Paragraph(f"Engagement: {ctx['project']}", muted_c))
        story.append(Spacer(1, 16 * mm))
        story.append(Paragraph(ctx["date_long"], center))
        story.append(Paragraph(f"Target Scope: {ctx['target']} &nbsp;|&nbsp; Assessment Type: {ctx['scan_label']}", muted_c))
        story.append(Spacer(1, 34 * mm))
        story.append(Paragraph("Confidential – Proprietary Information", muted_c))
        story.append(Paragraph(f"Prepared by {COMPANY_NAME}", muted_c))
        story.append(PageBreak())

        # ── PAGE 2 — Confidentiality + Disclaimer + Contact ────────────────
        client = ctx["client_label"]
        story.append(Paragraph("1. Confidentiality Statement", h2))
        story.append(Paragraph(
            f"This document is the exclusive property of {client} and {COMPANY_NAME} ({COMPANY_INIT}). "
            f"This document contains proprietary and confidential information. Duplication, redistribution, "
            f"or use, in whole or in part, in any form, requires consent of both {client} and {COMPANY_INIT}. "
            f"{COMPANY_INIT} may share this document with auditors under non-disclosure agreements to "
            f"demonstrate security assessment compliance.", body))

        story.append(Paragraph("2. Disclaimer", h2))
        story.append(Paragraph(
            f"A security assessment is considered a snapshot in time. The findings and recommendations in "
            f"this report reflect the information gathered during the assessment window ({ctx['date_long']}) "
            f"and do not account for any changes made outside of that period. Time-limited engagements do not "
            f"allow for a full evaluation of all security controls. {COMPANY_INIT} prioritized this assessment "
            f"to identify the weakest security controls an attacker would be likely to exploit. {COMPANY_INIT} "
            f"recommends conducting similar assessments on a recurring basis using internal or third-party "
            f"assessors.", body))

        story.append(Paragraph("3. Contact Information", h2))
        contact_rows = [
            ["Name", "Title", "Contact Information"],
            [Paragraph("<i>[Client Contact Name]</i>", body_sm), Paragraph("<i>[Title]</i>", body_sm),
             Paragraph("<i>[Phone] / [Email]</i>", body_sm)],
            [f"{COMPANY_NAME} Team", "Security Analyst", f"Email: {COMPANY_EMAIL}"],
        ]
        t = _tbl(contact_rows, colWidths=[45 * mm, 45 * mm, 80 * mm])
        t.setStyle(TableStyle(TABLE_BASE))
        story.append(t)
        story.append(Paragraph("The client contact row above is intentionally left blank for the engagement owner to complete.", muted))
        story.append(PageBreak())

        # ── PAGE 3 — Overview + Components + Severity classification ──────
        story.append(Paragraph("4. Assessment Overview", h2))
        story.append(Paragraph(
            f"On {ctx['date_long']}, {COMPANY_INIT} used the {COMPANY_NAME} platform to evaluate the security "
            f"posture of {client}'s infrastructure against current industry best practices, including a "
            f"{ctx['scan_label']} of the in-scope target(s). Methodology is based on the NIST SP 800-115 "
            f"Technical Guide to Information Security Testing and Assessment, the OWASP Testing Guide, and "
            f"{COMPANY_NAME}'s own automated testing framework.", body))
        for label, desc in [
            ("Planning", "Assessment goals, scope, and rules of engagement are established."),
            ("Discovery", "Scanning and enumeration are performed to identify potential vulnerabilities and weak areas."),
            ("Correlation", "Discovered service versions are matched against known CVE databases and scored for risk."),
            ("Reporting", "All findings, version intelligence, and remediation guidance are documented in this report."),
        ]:
            story.append(Paragraph(f"&bull; <b>{label}</b> – {desc}", body))

        story.append(Paragraph("5. Assessment Components", h2))
        story.append(Paragraph(
            f"<b>{ctx['scan_label']}</b> – this assessment used {ctx['scan_desc']}. The assessment lasted "
            f"approximately {ctx['duration_str']} and covered {ctx['total_hosts']} live host(s).", body))

        story.append(Paragraph("6. Findings Severity Classification", h2))
        sev_rows = [["Severity", "CVSS v3 Score Range", "Definition"]]
        sev_defs = [
            ("critical", "9.0 – 10.0", "Exploitation is straightforward and usually results in system-level compromise. Immediate action required."),
            ("high", "7.0 – 8.9", "Exploitation is more difficult but could cause elevated privileges and potential loss of data or downtime."),
            ("medium", "4.0 – 6.9", "Vulnerabilities exist but are not easily exploitable or require extra steps. Patch after high-priority issues."),
            ("low", "0.1 – 3.9", "Non-exploitable but would reduce attack surface. Patch during the next maintenance window."),
            ("informational", "N/A", "No vulnerability exists. Additional information about strong controls or documentation."),
        ]
        for lvl, rng, definition in sev_defs:
            sev_rows.append([_badge_para(lvl), rng, Paragraph(definition, body_sm)])
        t = _tbl(sev_rows, colWidths=[28 * mm, 32 * mm, 110 * mm])
        t.setStyle(TableStyle(TABLE_BASE + [("ALIGN", (0, 1), (0, -1), "CENTER")]))
        story.append(t)
        story.append(Paragraph(
            f"Note: the per-finding risk level shown in Sections 9–10 is {COMPANY_NAME}'s composite risk score "
            f"(CVSS 40%, service criticality 25%, version currency 20%, exposure 15%) rather than raw CVSS "
            f"alone, and may differ slightly from each CVE's own CVSS-based severity.", muted))
        story.append(PageBreak())

        # ── PAGE 4 — Scope + Executive Summary + Attack Summary + S/W ──────
        story.append(Paragraph("7. Scope", h2))
        t = _tbl([["Assessment", "Scope Details"], [ctx["scan_label"], ctx["target"]]], colWidths=[60 * mm, 110 * mm])
        t.setStyle(TableStyle(TABLE_BASE))
        story.append(t)
        story.append(Paragraph("7.1 Scope Exclusion", h3))
        story.append(Paragraph(
            f"Per {COMPANY_NAME}'s standard safety policy, denial-of-service style attacks and live exploitation "
            f"were not performed; this assessment is limited to non-intrusive discovery, version detection, and "
            f"vulnerability correlation.", body))
        story.append(Paragraph("7.2 Client Allowances", h3))
        story.append(Paragraph("No special allowances (e.g. credentials, IP whitelisting) were provided for this assessment.", body))

        story.append(Paragraph("8. Executive Summary", h2))
        story.append(Paragraph(ctx["summary_text"], body))
        story.append(Paragraph(
            f"Overall risk for this assessment is rated <b>{ctx['overall'].upper()}</b>, based on "
            f"{ctx['total_ports']} open service(s) across {ctx['total_hosts']} host(s) and "
            f"{ctx['total_cves']} matched CVE(s).", body))
        engine = ctx["ai"].get("engine")
        if engine:
            label = "Claude AI" if engine == "claude-ai" else engine.replace("-", " ").title()
            story.append(Paragraph(f"Narrative summary generated using {label} analysis.", muted))

        story.append(Paragraph("8.1 Attack Summary", h3))
        story.append(Paragraph(
            "The following table illustrates how the highest-severity findings could be chained together by an "
            "attacker, step by step, based on the discovered weaknesses.", body))
        attack_steps = _build_attack_summary(ctx["all_cves"])
        atk_rows = [["Step", "Action", "Finding / Recommendation"]]
        if attack_steps:
            for i, s in enumerate(attack_steps, 1):
                atk_rows.append([str(i), Paragraph(s["action"], body_sm), Paragraph(s["finding"], body_sm)])
        else:
            atk_rows.append(["—", Paragraph("No CVE-backed findings were available to summarize an attack chain.", body_sm), ""])
        t = _tbl(atk_rows, colWidths=[12 * mm, 70 * mm, 88 * mm])
        t.setStyle(TableStyle(TABLE_BASE))
        story.append(t)

        story.append(Paragraph("8.2 Security Strengths", h3))
        for b in _build_strengths(ctx["all_findings"], ctx["severity_counts"]):
            story.append(Paragraph(f"&bull; {b}", body))

        story.append(Paragraph("8.3 Security Weaknesses", h3))
        for b in _build_weaknesses(ctx["all_findings"], ctx["all_cves"]):
            story.append(Paragraph(f"&bull; {b}", body))

        # ── Vulnerabilities by Impact ────────────────────────────────────
        story.append(Paragraph("9. Vulnerabilities by Impact", h2))
        story.append(Paragraph(
            f"Figure 1 illustrates the open services found by impact, based on {COMPANY_NAME}'s composite risk "
            f"score (CVSS, service criticality, version currency, and exposure).", body))
        story.append(Spacer(1, 4 * mm))
        counts = ctx["severity_counts"]
        total = max(sum(counts.values()), 1)
        bar_total_w = 150 * mm
        track_color = colors.HexColor("#edf2f7")
        any_bar = False
        for level in SEVERITY_ORDER:
            n = counts.get(level, 0)
            if n == 0:
                continue
            any_bar = True
            pct = round(100 * n / total)
            bar_w = max(bar_total_w * pct / 100, 6 * mm)
            label_style = ParagraphStyle(f"BarLabel{level}", parent=body_sm, fontName="Helvetica-Bold",
                                          textColor=_c(level))
            story.append(Paragraph(f"{level.title()} ({n} finding{'s' if n != 1 else ''}) – {pct}%", label_style))
            track = _tbl([["", ""]], colWidths=[bar_w, bar_total_w - bar_w], rowHeights=[5 * mm])
            track.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), _c(level)),
                ("BACKGROUND", (1, 0), (1, 0), track_color),
                ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))
            story.append(track)
            story.append(Spacer(1, 3 * mm))
        if not any_bar:
            story.append(Paragraph("No open services were found to chart.", muted))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(f"<i>Figure 1: Distribution of findings by severity level ({total} total)</i>", muted))
        dominant = max(counts, key=lambda k: counts[k]) if any(counts.values()) else None
        dom_text = (f"{dominant.title()}-severity findings dominate the risk landscape, representing "
                    f"{counts[dominant]} of {total} total finding(s)." if dominant and counts[dominant] else
                    "No open services with an assigned risk level were found during this assessment.")
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(dom_text, body))

        # ── PAGE 6+ — Detailed Findings (vuln cards) ───────────────────────
        MAX_CARDS = 25
        shown_cves = ctx["all_cves"][:MAX_CARDS]
        story.append(Paragraph(f"10. {ctx['scan_label']} Findings", h2))
        if not shown_cves:
            story.append(Paragraph(
                "No CVE-backed findings were identified for the in-scope target(s). See Appendix A for the "
                "full inventory of open services observed during this assessment.", body))
        else:
            if len(ctx["all_cves"]) > MAX_CARDS:
                story.append(Paragraph(
                    f"Showing the top {MAX_CARDS} of {len(ctx['all_cves'])} total matched CVEs, ordered by CVSS "
                    f"score. The complete list is provided in Appendix B.", muted))
            for idx, c in enumerate(shown_cves, 1):
                sev = c["severity"] if c["severity"] in SEVERITY_COLORS else "unknown"
                ver_str = _ver_str(c["product"], c["version"])
                title = f"10.{idx} {c['cve_id']} — {c['service']}" + (f" ({ver_str})" if ver_str else "")
                remediation = c["patch"] or "Apply the latest vendor patch for this service and re-scan to confirm remediation."
                cell = [
                    Paragraph(title, h4),
                    Paragraph(f"{('Informational' if sev=='informational' else sev.title())} &nbsp; "
                              f"<font color='#4a627a'>CVSS {c['cvss']:.1f}/10</font>", body_sm),
                    Paragraph(f"<b>Description:</b> {c['desc'] or 'No description available.'}", body_sm),
                    Paragraph(f"<b>Affected System:</b> {c['host']}:{c['port']}/{c['proto']}", body_sm),
                    Paragraph(f"<b>References:</b> {c['cve_id']} — "
                              f"<link href='{c['nvd_url']}' color='blue'>{c['nvd_url']}</link>", body_sm),
                    Paragraph(f"<b>Remediation:</b> {remediation}", body_sm),
                ]
                card = _tbl([["", cell]], colWidths=[3 * mm, CONTENT_W - 3 * mm])
                card.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, 0), _c(sev)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (1, 0), (1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ]))
                story.append(KeepTogether([card, Spacer(1, 3 * mm)]))
        story.append(PageBreak())

        # ── Appendix A — Full port/service inventory ───────────────────────
        story.append(Paragraph("Appendix A — Full Port &amp; Service Inventory", h2))
        story.append(Paragraph(
            "The following table lists every open service observed during this assessment, including those "
            "without a matched CVE, for completeness.", body))
        inv_rows = [["Host", "Port", "Service", "Version", "Status", "Risk", "Score", "CVEs"]]
        for f in ctx["all_findings"]:
            inv_rows.append([
                Paragraph(f["host"], body_sm), Paragraph(f"{f['port']}/{f['proto']}", body_sm),
                Paragraph(f["service"], body_sm), Paragraph(f["version_str"] or "—", body_sm),
                Paragraph(f["v_status"], body_sm),
                _badge_para(f["risk"]), str(f["score"]), str(f["cve_count"]),
            ])
        if len(inv_rows) == 1:
            inv_rows.append(["—", "—", "No open ports were found.", "", "", "", "", ""])
        t = _tbl(inv_rows, colWidths=[27 * mm, 18 * mm, 20 * mm, 34 * mm, 21 * mm, 22 * mm, 14 * mm, 14 * mm], repeatRows=1)
        t.setStyle(TableStyle(TABLE_BASE + [("ALIGN", (5, 1), (5, -1), "CENTER")]))
        story.append(t)
        story.append(Spacer(1, 6 * mm))

        # ── Appendix B — Full CVE table (capped for a sane page count; the
        # complete list always remains in the session's analysis.json) ──────
        MAX_CVE_ROWS = 60
        cve_list = ctx["all_cves"]
        shown_cve_rows = cve_list[:MAX_CVE_ROWS]
        story.append(Paragraph(f"Appendix B — CVE Listing ({len(cve_list)} total matched)", h2))
        if len(cve_list) > MAX_CVE_ROWS:
            story.append(Paragraph(
                f"Showing the top {MAX_CVE_ROWS} of {len(cve_list)} matched CVEs, ordered by CVSS score, to keep "
                f"this report to a manageable length. The complete machine-readable list is retained with the "
                f"scan session and can be exported on request.", muted))
        cve_rows = [["CVE ID", "Host:Port", "Service", "CVSS", "Severity", "Description"]]
        for c in shown_cve_rows:
            cve_rows.append([
                Paragraph(c["cve_id"], body_sm), Paragraph(f"{c['host']}:{c['port']}", body_sm),
                Paragraph(c["service"], body_sm), Paragraph(f"{c['cvss']:.1f}", body_sm_c),
                _badge_para(c["severity"]), Paragraph((c["desc"] or "")[:160], body_sm),
            ])
        if len(cve_rows) == 1:
            cve_rows.append(["—", "—", "No CVEs were matched during this assessment.", "", "", ""])
        t = _tbl(cve_rows, colWidths=[27 * mm, 34 * mm, 19 * mm, 11 * mm, 23 * mm, 56 * mm], repeatRows=1)
        t.setStyle(TableStyle(TABLE_BASE + [("ALIGN", (3, 1), (3, -1), "CENTER")]))
        story.append(t)
        story.append(Spacer(1, 6 * mm))

        # ── Sign-off page ─────────────────────────────────────────────────
        sign_off = []
        sign_off.append(Paragraph("11. Client Acknowledgment &amp; Sign-off", h2))
        sign_off.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#ccd7e4"),
                                     spaceBefore=0, spaceAfter=10))
        sign_off.append(Paragraph(
            "By signing below, the client acknowledges receipt of this Security Assessment Finding Report and "
            "agrees to review the findings, assess associated risks, and implement remediation actions as "
            "appropriate.", body))
        sign_off.append(Spacer(1, 10 * mm))

        def _sig_cell(label):
            return [Paragraph(f"<b>{label}</b>", body_sm), Spacer(1, 9 * mm)]

        sig_rows = [
            [_sig_cell("Client Representative Name:"), _sig_cell("Title:")],
            [_sig_cell("Signature:"), _sig_cell("Date:")],
        ]
        t = _tbl(sig_rows, colWidths=[85 * mm, 85 * mm])
        t.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (0, 0), 0.7, colors.black),
            ("LINEBELOW", (1, 0), (1, 0), 0.7, colors.black),
            ("LINEBELOW", (0, 1), (0, 1), 0.7, colors.black),
            ("LINEBELOW", (1, 1), (1, 1), 0.7, colors.black),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        sign_off.append(t)
        sign_off.append(Spacer(1, 4 * mm))
        sign_off.append(Paragraph("<b>Comments / Observations:</b>", body_sm))
        sign_off.append(Spacer(1, 16 * mm))
        sign_off.append(HRFlowable(width="100%", thickness=0.7, color=colors.black, spaceAfter=0))

        sign_off.append(Spacer(1, 10 * mm))
        sign_off.append(Paragraph(f"<b>For {COMPANY_NAME}:</b>", body_sm))
        sign_off.append(Spacer(1, 8 * mm))
        line = _tbl([[""]], colWidths=[60 * mm])
        line.setStyle(TableStyle([("LINEBELOW", (0, 0), (0, 0), 0.7, colors.black)]))
        sign_off.append(line)
        sign_off.append(Paragraph("Lead Security Analyst", body_sm))
        sign_off.append(Paragraph(ctx["date_long"], body_sm))
        sign_off.append(Spacer(1, 8 * mm))
        sign_off.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#dddddd"), spaceAfter=6))
        sign_off.append(Paragraph(
            "This sign-off confirms that the report has been delivered and accepted for review.", muted_c))
        story.append(KeepTogether(sign_off))
        story.append(PageBreak())

        # ── Closing page ──────────────────────────────────────────────────
        story.append(Spacer(1, 60 * mm))
        story.append(Paragraph("Thank You", ParagraphStyle("ThankYou", parent=cover_t, fontSize=22)))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("We appreciate the opportunity to assess your security posture.", center))
        story.append(Paragraph(f"{COMPANY_NAME} remains committed to helping you build a resilient and secure environment.", muted_c))
        story.append(Spacer(1, 12 * mm))
        story.append(Paragraph(f"For any questions or follow-up, please contact us at {COMPANY_EMAIL}", muted_c))
        story.append(Spacer(1, 20 * mm))
        story.append(Paragraph("— This report concludes the Security Assessment Finding Report —", muted_c))

        doc = SimpleDocTemplate(out_path, pagesize=A4,
                                 leftMargin=20 * mm, rightMargin=20 * mm,
                                 topMargin=20 * mm, bottomMargin=20 * mm,
                                 title=f"{COMPANY_NAME} Security Assessment Finding Report")
        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        logger.info(f"[Report] PDF generated: {out_path}")

    except ImportError as e:
        logger.error(f"[Report] reportlab missing — {e}. Run: pip install reportlab")
        _build_pdf_fallback(out_path, analysis)
    except Exception as e:
        logger.error(f"[Report] PDF generation failed: {e}", exc_info=True)
        _build_pdf_fallback(out_path, analysis)

    return out_path


def _build_pdf_fallback(out_path: str, analysis: dict):
    """Minimal valid PDF stub when reportlab fails or an unexpected data shape is hit."""
    target = analysis.get("target", "unknown")
    ts     = time.strftime("%Y-%m-%d %H:%M:%S")
    text   = f"ThreatWeave Report | Target: {target} | {ts} | Install reportlab for full PDF"
    # Minimal valid single-page PDF
    body   = f"BT /F1 10 Tf 40 750 Td ({text}) Tj ET"
    body_b = body.encode()
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 595 842]/Parent 2 0 R"
        b"/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n"
        b"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
        b"5 0 obj<</Length " + str(len(body_b)).encode() + b">>\n"
        b"stream\n" + body_b + b"\nendstream\nendobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"trailer<</Size 6/Root 1 0 R>>\nstartxref\n0\n%%EOF"
    )
    with open(out_path, "wb") as f:
        f.write(content)
