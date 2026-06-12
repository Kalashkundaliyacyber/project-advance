"""
ThreatWeave — Analysis & Intelligence Routes (Phase 6/8/11)
============================================================
Extracted from routes.py to keep files under 500 lines.
Covers: asset criticality, explainable risk, security score,
        threat intel, vuln timeline, patch KB, AI cache.
"""
import logging
from fastapi import APIRouter, HTTPException, Request

from app.files.session_manager import get_session, load_scan_context, list_sessions

logger = logging.getLogger("ThreatWeave.routes.analysis")
analysis_router = APIRouter()


# ── Asset Criticality ─────────────────────────────────────────────────────────

@analysis_router.get("/asset-criticality/{session_id}")
async def get_asset_criticality(session_id: str, request: Request):
    """Phase 8: Asset Criticality Engine — per-host/port criticality scores."""
    try:
        from app.analysis.asset_criticality import score_host
        sess = get_session(session_id)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        parsed = sess.get("parsed") or {}
        hosts  = parsed.get("hosts", []) if isinstance(parsed, dict) else []
        result = [{"host": h.get("address", h.get("ip", "?")), **score_host(h)} for h in hosts]
        return {"ok": True, "session_id": session_id, "assets": result, "count": len(result)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Asset criticality: %s", e)
        return {"ok": False, "error": str(e)}


# ── Explainable Risk ─────────────────────────────────────────────────────────

@analysis_router.post("/risk/explain")
async def explain_risk(body: dict, request: Request):
    """Phase 8: Explainable Risk Score with per-component breakdown."""
    try:
        from app.analysis.explainable_risk import explain_risk_score
        return {"ok": True, **explain_risk_score(
            cvss=float(body.get("cvss", 0)),
            criticality=body.get("criticality", "medium"),
            version_risk=body.get("version_risk", "unknown"),
            exposure=body.get("exposure", "medium"),
            service=body.get("service", ""),
            port=int(body.get("port", 0)),
        )}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Vulnerability Timeline ────────────────────────────────────────────────────

@analysis_router.get("/vuln/timeline/{session_id}")
async def get_vuln_timeline(session_id: str, request: Request):
    """Phase 8: CVE timeline with KEV status and exposure windows."""
    try:
        from app.analysis.vuln_timeline import build_cve_timeline
        ctx  = load_scan_context(session_id) or {}
        cves = ctx.get("cves", []) or []
        if not cves:
            sess = get_session(session_id)
            if sess:
                cves = sess.get("analysis", {}).get("cves", []) or []
        return {"ok": True, "session_id": session_id, **build_cve_timeline(cves)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Security Score ────────────────────────────────────────────────────────────

@analysis_router.get("/security-score/{session_id}")
async def get_security_score(session_id: str, request: Request):
    """Phase 8: Security grade (A-F) with dimension breakdown."""
    try:
        from app.analysis.security_score import calculate_security_score
        sess = get_session(session_id)
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        return {"ok": True, "session_id": session_id,
                **calculate_security_score(sess.get("analysis") or {}, sess.get("parsed") or {})}
    except HTTPException:
        raise
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Threat Intelligence ───────────────────────────────────────────────────────

@analysis_router.get("/threat-intel/{session_id}")
async def get_threat_intel(session_id: str, request: Request):
    """Phase 8: Threat Intelligence — KEV, EPSS, threat actors."""
    try:
        from app.analysis.threat_intel import enrich_with_threat_intel
        ctx  = load_scan_context(session_id) or {}
        cves = ctx.get("cves", []) or []
        svcs = ctx.get("services", []) or []
        if not cves:
            sess = get_session(session_id)
            if sess:
                cves = sess.get("analysis", {}).get("cves", []) or []
        return {"ok": True, "session_id": session_id,
                **enrich_with_threat_intel(cves, svcs)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@analysis_router.get("/threat-intel/kev/{cve_id}")
async def kev_lookup(cve_id: str, request: Request):
    """Check if a CVE is in the CISA KEV catalog."""
    try:
        from app.analysis.threat_intel import lookup_kev
        entry = lookup_kev(cve_id.strip().upper())
        if entry:
            return {"ok": True, "cve_id": cve_id, "in_kev": True, **entry}
        return {"ok": True, "cve_id": cve_id, "in_kev": False}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Patch Knowledge Base ──────────────────────────────────────────────────────

@analysis_router.get("/patch-kb/stats")
async def patch_kb_stats(request: Request):
    """Phase 5: Patch Knowledge Base statistics."""
    try:
        from app.ai.remediation.patch_knowledge_base import patch_kb
        return {"ok": True, **patch_kb.stats()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@analysis_router.get("/patch-kb/lookup/{cve_id}")
async def patch_kb_lookup(cve_id: str, request: Request):
    """Phase 5: Look up a CVE in the local Patch KB."""
    try:
        from app.ai.remediation.patch_knowledge_base import patch_kb
        entry = patch_kb.lookup_cve(cve_id.strip().upper())
        if entry:
            return {"ok": True, "cve_id": cve_id, "found": True, **entry}
        return {"ok": True, "cve_id": cve_id, "found": False}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── AI Cache ──────────────────────────────────────────────────────────────────

@analysis_router.get("/ai/cache/stats")
async def ai_cache_stats(request: Request):
    """Phase 5/22: AI response cache statistics."""
    try:
        from app.ai.cache.ai_response_cache import ai_response_cache
        return {"ok": True, **ai_response_cache.stats()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@analysis_router.delete("/ai/cache/clear")
async def ai_cache_clear(request: Request):
    """Phase 22: Clear AI response cache."""
    try:
        from app.ai.cache.ai_response_cache import ai_response_cache
        n = ai_response_cache.clear()
        return {"ok": True, "cleared_entries": n}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Intelligent Remediation ───────────────────────────────────────────────────

@analysis_router.post("/remediation/cve")
async def remediate_cve_endpoint(body: dict, request: Request):
    """Phase 23: Intelligent remediation for a single CVE."""
    try:
        from app.ai.remediation.intelligent_remediation import remediate_cve
        cve_id = body.get("cve_id", "")
        if not cve_id:
            return {"ok": False, "error": "cve_id required"}
        result = remediate_cve(
            cve_id=cve_id,
            service=body.get("service", ""),
            version=body.get("version", ""),
            description=body.get("description", ""),
            host=body.get("host", ""),
        )
        return {"ok": True, **result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@analysis_router.post("/remediation/batch")
async def batch_remediate_endpoint(body: dict, request: Request):
    """Phase 23: Batch remediation for multiple CVEs."""
    try:
        from app.ai.remediation.intelligent_remediation import batch_remediate
        vulns = body.get("vulnerabilities", [])
        if not vulns:
            return {"ok": False, "error": "vulnerabilities list required"}
        result = batch_remediate(vulns)
        return {"ok": True, **result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Phase 13: Project Workspace ───────────────────────────────────────────────

@analysis_router.get("/workspace/{project_name}")
async def get_project_workspace(project_name: str, request: Request):
    """
    Phase 13: Project Workspace — all sessions, scans, reports for a project.
    Returns unified view: sessions, history, linked reports, cumulative stats.
    """
    try:
        from app.files.session_manager import list_sessions
        all_sessions = list_sessions()
        proj_sessions = [
            s for s in all_sessions
            if (s.get("project_name") or "").lower() == project_name.lower()
            or (s.get("target") or "").lower() == project_name.lower()
        ]
        if not proj_sessions:
            return {"ok": True, "project_name": project_name, "sessions": [],
                    "summary": "No sessions found for this project."}

        # Aggregate stats
        total_cves  = sum(s.get("cve_count", 0) for s in proj_sessions)
        total_ports = sum(s.get("open_ports", 0) for s in proj_sessions)
        risk_levels = [s.get("overall_risk", "low") for s in proj_sessions]
        worst_risk  = max(risk_levels, key=lambda r: {"critical":4,"high":3,"medium":2,"low":1}.get(r,0))

        return {
            "ok":           True,
            "project_name": project_name,
            "sessions":     proj_sessions,
            "session_count": len(proj_sessions),
            "aggregate": {
                "total_scans":  len(proj_sessions),
                "total_cves":   total_cves,
                "total_ports":  total_ports,
                "worst_risk":   worst_risk,
                "first_scan":   min((s.get("timestamp","") for s in proj_sessions), default=""),
                "last_scan":    max((s.get("timestamp","") for s in proj_sessions), default=""),
            },
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@analysis_router.get("/workspace")
async def list_workspaces(request: Request):
    """
    Phase 13: List all project workspaces with aggregated stats.
    """
    try:
        from app.files.session_manager import list_sessions
        all_sessions = list_sessions()
        workspaces: dict = {}
        for s in all_sessions:
            name = s.get("project_name") or s.get("target", "default")
            if not name:
                name = "default"
            if name not in workspaces:
                workspaces[name] = {"sessions": 0, "cves": 0, "ports": 0, "risks": []}
            workspaces[name]["sessions"] += 1
            workspaces[name]["cves"]     += s.get("cve_count", 0)
            workspaces[name]["ports"]    += s.get("open_ports", 0)
            workspaces[name]["risks"].append(s.get("overall_risk", "low"))

        result = []
        for name, data in workspaces.items():
            worst = max(data["risks"], key=lambda r: {"critical":4,"high":3,"medium":2,"low":1}.get(r,0))
            result.append({
                "project_name": name,
                "session_count": data["sessions"],
                "total_cves":    data["cves"],
                "total_ports":   data["ports"],
                "worst_risk":    worst,
            })
        result.sort(key=lambda x: x["session_count"], reverse=True)
        return {"ok": True, "workspaces": result, "total": len(result)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
