"""
ScanWise AI — Patch Guidance API Routes v2.0
Redesigned /api/patch/guidance endpoint with:
  - Request deduplication (no duplicate in-flight calls)
  - Response caching (avoids repeat AI calls for same CVE)
  - Grouped remediation (one AI call per service group)
  - asyncio queue integration (prevents VRAM spikes)
  - Structured JSON output
  - Full fallback chain: Qwen → Llama → Gemini → Rule engine
"""
import asyncio
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.ai.remediation.patch_generator   import get_patch_guidance, get_group_patch_guidance
from app.ai.remediation.remediation_cache import deduplicated_fetch
from app.ai.remediation.remediation_grouping import group_by_service, build_group_summary, prioritize_groups
from app.ai.queue.ai_queue import run_with_queue, get_queue_depth, get_queue_stats, get_job_status, cancel_job
from app.files.session_manager import load_scan_context, get_session, save_patches, load_patches

logger = logging.getLogger("scanwise.api.patch")
router = APIRouter()


# ── Request models ────────────────────────────────────────────────────────────

class PatchGuidanceRequest(BaseModel):
    service:    str
    port:       int
    version:    str       = "unknown"
    cve_id:     str       = "unknown"
    severity:   str       = "medium"
    session_id: str       = ""
    os_hint:    str       = "ubuntu"


class PatchAllRequest(BaseModel):
    session_id: str
    os_hint:    str = "ubuntu"
    group_by_service: bool = True   # if True: one AI call per service group


# ── /api/patch/guidance — single service ─────────────────────────────────────

@router.post("/guidance")
async def patch_guidance_endpoint(req: PatchGuidanceRequest):
    """
    Return AI patch guidance for a single service/port.
    Features:
    - Cache check first (no AI call if already computed)
    - In-flight deduplication (concurrent same-key requests share one AI call)
    - Queue throttling (prevents VRAM spikes)
    - Full fallback chain
    """
    svc_name = req.service.strip()
    version  = req.version
    cve_id   = req.cve_id
    severity = req.severity

    # Enrich from session if values are unknown
    if req.session_id and (version == "unknown" or cve_id == "unknown"):
        version, cve_id, severity = _enrich_from_session(
            req.session_id, req.port, version, cve_id, severity
        )

    logger.info(
        "patch/guidance: service=%s port=%d cve=%s severity=%s queue=%d",
        svc_name, req.port, cve_id, severity, get_queue_depth()
    )

    # Deduplicated async fetch through queue
    async def _fetch():
        return await run_with_queue(
            get_patch_guidance,
            svc_name, req.port, version, cve_id, severity, req.os_hint,
            timeout=120.0,
        )

    try:
        result = await deduplicated_fetch(
            svc_name, req.port, version, cve_id, severity, _fetch
        )
    except asyncio.TimeoutError:
        logger.warning("patch/guidance timed out for %s port=%d", svc_name, req.port)
        from app.ai.remediation.remediation_templates import build_patch_response
        result = build_patch_response(svc_name, req.port, version, cve_id, severity, req.os_hint)
        result["timeout"] = True

    # Persist single-port result to session patches file (appends/merges)
    if req.session_id and result and not result.get("error"):
        try:
            existing = load_patches(req.session_id)
            current  = existing.get("patches", [])
            # Deduplicate by service+port key
            key = f"{result.get('service','')}:{result.get('port','')}"
            current = [p for p in current if f"{p.get('service','')}:{p.get('port','')}" != key]
            current.append(result)
            save_patches(req.session_id, current)
        except Exception as _e2:
            logger.warning("save_patches (guidance) failed for %s: %s", req.session_id, _e2)

    return result


# ── /api/patch/all — full session remediation dashboard ──────────────────────

@router.post("/all")
async def patch_all_endpoint(req: PatchAllRequest):
    """
    Generate patch guidance for ALL vulnerable ports in a session.
    Groups by service family → one AI call per group (dramatically reduces quota usage).
    Returns sorted results (critical first).
    """
    # Load session data
    ctx = {}
    try:
        ctx = load_scan_context(req.session_id) or get_session(req.session_id) or {}
    except Exception as e:
        logger.warning("patch/all: session load failed for %s: %s", req.session_id, e)

    # Extract all ports
    all_ports = []
    for h in (ctx.get("risk") or {}).get("hosts", []):
        for p in h.get("ports", []):
            all_ports.append({
                "ip":         h.get("ip", ""),
                "port":       p.get("port"),
                "service":    p.get("service", ""),
                "version":    p.get("version", "") or p.get("product", ""),
                "protocol":   p.get("protocol", "tcp"),
                "risk_level": (p.get("risk") or {}).get("level", "low"),
                "risk_score": (p.get("risk") or {}).get("score", 0),
                "cves":       p.get("cves", []),
            })

    if not all_ports:
        return {"ok": False, "error": "No scan data found for this session", "results": []}

    if req.group_by_service:
        results = await _patch_grouped(all_ports, req.os_hint)
    else:
        results = await _patch_individual(all_ports, req.os_hint)

    # Sort critical first
    _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: _risk_order.get(x.get("severity") or x.get("risk_level", "low"), 3))

    # Persist patch results to session storage (Fix 6)
    try:
        save_patches(req.session_id, results)
    except Exception as _e:
        logger.warning("save_patches failed for %s: %s", req.session_id, _e)

    return {
        "ok":           True,
        "session_id":   req.session_id,
        "total_ports":  len(all_ports),
        "results":      results,
        "grouped":      req.group_by_service,
    }


# ── Queue status ──────────────────────────────────────────────────────────────


@router.get("/history/{session_id}")
async def patch_history(session_id: str):
    """
    Return previously saved patch guidance for a session.
    Used to reload patch results after page refresh or session restore.
    Returns {ok, patches, saved_at, patch_count} or {ok: False} if none saved.
    """
    data = load_patches(session_id)
    if not data:
        return {"ok": False, "session_id": session_id, "patches": [], "patch_count": 0}
    return {"ok": True, "session_id": session_id, **data}


@router.get("/status")
async def patch_status():
    """Return current AI queue depth, cache stats, circuit breaker state, telemetry."""
    from app.ai.remediation.remediation_cache import get_stats as _cache_stats
    from app.ai.utils.logging_utils import get_stats as _ai_stats
    from app.ai.queue.ai_queue import get_queue_stats
    from app.ai.routing.ai_router import ai_router as _ai
    from app.ai.utils.telemetry import telemetry as _tel

    ai_status = _ai.status()
    return {
        "queue_depth":      get_queue_depth(),
        "queue_stats":      get_queue_stats(),
        "cache":            _cache_stats(),
        "ai_stats":         _ai_stats(),
        "circuit_breakers": ai_status.get("circuit_breakers", {}),
        "active_provider":  ai_status.get("active_provider", "unknown"),
        "telemetry":        _tel.snapshot(),
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _patch_grouped(ports: list, os_hint: str) -> list:
    """Generate one patch guidance per service group."""
    groups = group_by_service(ports)
    sorted_groups = prioritize_groups(groups)
    results = []

    for service, group_ports in sorted_groups:
        summary = build_group_summary(service, group_ports)
        try:
            guidance = await run_with_queue(
                get_group_patch_guidance,
                service, summary,
                timeout=120.0,
            )
        except Exception as e:
            logger.warning("Group patch failed for %s: %s", service, e)
            from app.ai.remediation.remediation_templates import build_patch_response
            top_cve = (summary.get("cves") or [{}])[0]
            guidance = build_patch_response(
                service,
                (summary.get("ports") or [0])[0],
                (summary.get("versions") or ["unknown"])[0],
                top_cve.get("cve_id", "unknown"),
                summary.get("severity", "medium"),
                os_hint,
            )

        # Add metadata from original ports
        guidance["ports"]      = summary["ports"]
        guidance["service"]    = service
        guidance["cves"]       = summary["cves"][:5]
        guidance["risk_level"] = summary["severity"]
        guidance["port_count"] = summary["port_count"]
        results.append(guidance)

    return results


async def _patch_individual(ports: list, os_hint: str) -> list:
    """Generate one patch guidance per port (original behaviour, higher quota cost)."""
    results = []
    for entry in ports:
        cves    = entry.get("cves", [])
        top_cve = cves[0] if cves else {}
        svc     = entry.get("service") or f"port {entry.get('port', 0)}"

        async def _fetch(e=entry, tc=top_cve):
            return await run_with_queue(
                get_patch_guidance,
                e["service"] or f"port {e['port']}",
                int(e.get("port") or 0),
                e.get("version") or "unknown",
                tc.get("cve_id", "unknown"),
                tc.get("severity", "medium"),
                os_hint,
                timeout=120.0,
            )

        try:
            guidance = await deduplicated_fetch(
                svc, int(entry.get("port") or 0),
                entry.get("version") or "unknown",
                top_cve.get("cve_id", "unknown"),
                top_cve.get("severity", "medium"),
                _fetch,
            )
        except Exception as e:
            logger.warning("Individual patch failed for %s: %s", svc, e)
            from app.ai.remediation.remediation_templates import build_patch_response
            guidance = build_patch_response(
                svc, int(entry.get("port") or 0),
                entry.get("version") or "unknown",
                top_cve.get("cve_id", "unknown"),
                top_cve.get("severity", "medium"),
                os_hint,
            )

        guidance["ip"]         = entry.get("ip", "")
        guidance["port"]       = entry.get("port")
        guidance["risk_level"] = entry.get("risk_level", "low")
        guidance["risk_score"] = entry.get("risk_score", 0)
        guidance["all_cves"]   = cves
        results.append(guidance)

    return results


def _enrich_from_session(session_id: str, port: int,
                          version: str, cve_id: str, severity: str) -> tuple:
    """Enrich version/cve from session data."""
    try:
        ctx = load_scan_context(session_id) or get_session(session_id) or {}
        for h in (ctx.get("risk") or {}).get("hosts", []):
            for p in h.get("ports", []):
                if str(p.get("port")) == str(port):
                    if version == "unknown":
                        version = p.get("version", "") or p.get("product", "") or "unknown"
                    if cve_id == "unknown":
                        cves = p.get("cves", [])
                        if cves:
                            cve_id   = cves[0].get("cve_id", "unknown")
                            severity = cves[0].get("severity", severity)
                    break
    except Exception as e:
        logger.debug("Session enrich failed: %s", e)
    return version, cve_id, severity
