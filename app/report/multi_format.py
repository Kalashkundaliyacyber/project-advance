"""
Multi-Format Report Generator v2.0
- Fixes PDF generation (correct data path for risk/overall)
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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _overall_risk(analysis: dict) -> tuple[str, float]:
    """Derive overall risk level and max score from per-port risks."""
    hosts = analysis.get("risk", {}).get("hosts", [])
    best_level = "low"
    best_score = 0.0
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for host in hosts:
        for port in host.get("ports", []):
            r     = port.get("risk", {})
            lvl   = r.get("level", "low").lower()
            score = float(r.get("score", 0))
            if order.get(lvl, 0) > order.get(best_level, 0):
                best_level = lvl
                best_score = score
            elif score > best_score:
                best_score = score
    return best_level, best_score


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
        filename=f"scanwise_report_{session_id}.html",
        headers={"Content-Disposition": f'attachment; filename="scanwise_report_{session_id}.html"'}
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
        filename=f"scanwise_report_{session_id}{ext}",
        headers={"Content-Disposition": f'attachment; filename="scanwise_report_{session_id}{ext}"'}
    )


# ── PDF builder ───────────────────────────────────────────────────────────────

def _build_pdf(session_id: str, analysis: dict) -> str:
    out_path = os.path.join(REPORTS_DIR, f"report_{session_id}.pdf")
    os.makedirs(REPORTS_DIR, exist_ok=True)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm

        doc    = SimpleDocTemplate(out_path, pagesize=A4,
                                   leftMargin=20*mm, rightMargin=20*mm,
                                   topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story  = []

        RISK_COLORS = {
            "critical": "#E24B4A", "high": "#EF9F27",
            "medium":   "#378ADD", "low":  "#1D9E75"
        }

        def _color(lvl): return colors.HexColor(RISK_COLORS.get(lvl.lower(), "#8b949e"))

        # ── Title
        story.append(Paragraph(
            "ScanWise AI — Security Assessment Report",
            ParagraphStyle("T", parent=styles["Title"], fontSize=18,
                           textColor=colors.HexColor("#1f6feb"))
        ))
        story.append(Spacer(1, 6*mm))

        # ── Meta table
        overall_lvl, overall_score = _overall_risk(analysis)
        meta = [
            ["Target",        analysis.get("target", "—")],
            ["Scan Type",     analysis.get("scan_type", "—")],
            ["Date",          analysis.get("timestamp", "—")],
            ["Duration",      f"{analysis.get('duration', '—')} s"],
            ["Overall Risk",  f"{overall_lvl.upper()}  (score {overall_score:.1f})"],
        ]
        mt = Table(meta, colWidths=[45*mm, 120*mm])
        mt.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#161b22")),
            ("TEXTCOLOR",     (0, 0), (0, -1),  colors.HexColor("#8b949e")),
            ("TEXTCOLOR",     (1, 0), (1, -1),  colors.HexColor("#e6edf3")),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1),
             [colors.HexColor("#161b22"), colors.HexColor("#21262d")]),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#30363d")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            # Color overall risk cell
            ("TEXTCOLOR",     (1, 4), (1, 4),   _color(overall_lvl)),
            ("FONTNAME",      (1, 4), (1, 4),   "Helvetica-Bold"),
        ]))
        story.append(mt)
        story.append(Spacer(1, 6*mm))

        # ── Executive summary
        exp     = analysis.get("explanation", {})
        summary = exp.get("summary", "")
        if summary:
            story.append(Paragraph("Executive Summary", styles["Heading2"]))
            story.append(Paragraph(summary, styles["Normal"]))
            story.append(Spacer(1, 4*mm))

        # ── Findings
        hosts = analysis.get("risk", {}).get("hosts", [])
        all_ports = [(h, p) for h in hosts for p in h.get("ports", [])]
        if all_ports:
            story.append(Paragraph("Port & Service Findings", styles["Heading2"]))
            rows = [["Port", "Service", "Product / Version", "Risk", "Score"]]
            for _, port in all_ports:
                r   = port.get("risk", {})
                lvl = r.get("level", "low")
                rows.append([
                    f"{port.get('port')}/{port.get('protocol', 'tcp')}",
                    port.get("service", "—"),
                    f"{port.get('product', '')} {port.get('version', '')}".strip() or "—",
                    lvl.upper(),
                    str(r.get("score", 0)),
                ])
            ft = Table(rows, colWidths=[28*mm, 28*mm, 55*mm, 26*mm, 18*mm])
            ts = [
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#30363d")),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1),
                 [colors.HexColor("#161b22"), colors.HexColor("#21262d")]),
                ("TEXTCOLOR",     (0, 1), (-1, -1), colors.HexColor("#e6edf3")),
            ]
            for i, row in enumerate(rows[1:], 1):
                lvl = row[3].lower()
                ts.append(("TEXTCOLOR", (3, i), (3, i), _color(lvl)))
                ts.append(("FONTNAME",  (3, i), (3, i), "Helvetica-Bold"))
            ft.setStyle(TableStyle(ts))
            story.append(ft)
            story.append(Spacer(1, 4*mm))

        # ── CVE table
        all_cves = []
        for _, port in all_ports:
            for cve in port.get("cves", []):
                all_cves.append(cve)
        all_cves.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

        if all_cves:
            story.append(Paragraph("CVE Details", styles["Heading2"]))
            # White-text paragraph style for description cells on dark bg rows
            desc_style = ParagraphStyle(
                "CveDesc", parent=styles["Normal"],
                fontSize=8, textColor=colors.HexColor("#e6edf3")
            )
            crows = [["CVE ID", "Severity", "CVSS", "Description"]]
            for cve in all_cves[:20]:
                crows.append([
                    cve.get("cve_id", "—"),
                    cve.get("severity", "—").upper(),
                    str(cve.get("cvss_score", "—")),
                    Paragraph(cve.get("description", "")[:120], desc_style),
                ])
            ct = Table(crows, colWidths=[35*mm, 22*mm, 15*mm, 93*mm])
            cts = [
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#E24B4A")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#30363d")),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1),
                 [colors.HexColor("#161b22"), colors.HexColor("#21262d")]),
                ("TEXTCOLOR",     (0, 1), (2, -1),  colors.HexColor("#e6edf3")),
                # FIX: description column (col 3) text also needs to be white on dark bg
                ("TEXTCOLOR",     (3, 1), (3, -1),  colors.HexColor("#e6edf3")),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]
            SEV_COLORS = {
                "CRITICAL": "#E24B4A", "HIGH": "#EF9F27",
                "MEDIUM":   "#378ADD", "LOW":  "#1D9E75"
            }
            for i, row in enumerate(crows[1:], 1):
                sev = row[1]
                clr = SEV_COLORS.get(sev, "#8b949e")
                cts.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(clr)))
                cts.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))
            ct.setStyle(TableStyle(cts))
            story.append(ct)
            story.append(Spacer(1, 4*mm))

        # ── Defensive guidance
        guidance = exp.get("defensive_guidance", [])
        if guidance:
            story.append(Paragraph("Defensive Guidance", styles["Heading2"]))
            for g in guidance[:15]:
                story.append(Paragraph(f"→ {g}", styles["Normal"]))
            story.append(Spacer(1, 4*mm))

        # ── Footer
        story.append(HRFlowable(width="100%", thickness=0.5,
                                 color=colors.HexColor("#30363d")))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            f"Generated by ScanWise AI v2.0  ·  "
            f"{time.strftime('%Y-%m-%d %H:%M:%S')}  ·  Defensive use only",
            ParagraphStyle("Footer", parent=styles["Normal"],
                           fontSize=8, textColor=colors.HexColor("#8b949e"))
        ))

        doc.build(story)
        logger.info(f"[Report] PDF generated: {out_path}")

    except ImportError as e:
        logger.error(f"[Report] reportlab missing — {e}. Run: pip install reportlab")
        _build_pdf_fallback(out_path, analysis)
    except Exception as e:
        logger.error(f"[Report] PDF generation failed: {e}", exc_info=True)
        _build_pdf_fallback(out_path, analysis)

    return out_path


def _build_pdf_fallback(out_path: str, analysis: dict):
    """Minimal valid PDF stub when reportlab fails."""
    target = analysis.get("target", "unknown")
    ts     = time.strftime("%Y-%m-%d %H:%M:%S")
    text   = f"ScanWise AI Report | Target: {target} | {ts} | Install reportlab for full PDF"
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
