"""
ThreatWeave AI — Patch Guidance API Routes v3.1
Unified entry point: routes all patch requests through the 4-layer orchestrator.

CHANGES v3.1 (this file):
  - Added POST /api/patch/add endpoint.
    Allows the UI (slash command /patch add) to store a custom patch directly
    into the local patch repository (Layer 1 / patches.db) without going
    through the AI pipeline.  Useful for importing vendor advisories manually
    or adding multi-OS commands for CVEs that rule_engine stored without them.

CHANGES v3.0:
  - Single patch guidance now calls resolve_patch() (4-layer orchestrator)
    instead of get_patch_guidance() (Gen1 only).
  - Group patching calls resolve_patch() per CVE (orchestrator is already fast
    due to LRU cache; group KB pre-check retained).
  - All existing features preserved: deduplication, async queue, os_hint,
    session enrichment, timeout fallback, /all endpoint, /status endpoint.
  - Output schema is unchanged from the caller's perspective: commands,
    patch_command, fix_version, vendor_url, confidence, from_kb, from_cache,
    ai_called are all present (normalized by orchestrator._normalize_output).
"""
import asyncio
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict

# Unified 4-layer pipeline (replaces Gen1 get_patch_guidance)
from app.remediation import resolve_patch, resolve_patches_batch
from app.remediation.confidence import confidence_label

# Gen1 helpers that are still used for grouping, dedup, queue, fallback
from app.ai.remediation.remediation_cache    import deduplicated_fetch
from app.ai.remediation.remediation_grouping import group_by_service, build_group_summary, prioritize_groups
from app.ai.queue.ai_queue                   import run_with_queue, get_queue_depth
from app.ai.remediation.remediation_templates import build_patch_response
from app.files.session_manager               import load_scan_context, get_session

logger = logging.getLogger("ThreatWeave.api.patch")
router = APIRouter()


# ── Request models ────────────────────────────────────────────────────────────

class PatchGuidanceRequest(BaseModel):
    service:    str
    port:       int
    version:    str  = "unknown"
    cve_id:     str  = "unknown"
    severity:   str  = "medium"
    session_id: str  = ""
    os_hint:    str  = "ubuntu"


class PatchAllRequest(BaseModel):
    session_id:       str
    os_hint:          str  = "ubuntu"
    group_by_service: bool = True


class PatchAddRequest(BaseModel):
    """
    Request model for POST /api/patch/add.
    Stores a custom patch record directly into patches.db (Layer 1).

    Fields:
        cve_id:        CVE identifier, e.g. "CVE-2024-6387"
        vendor:        Vendor / product family, e.g. "openssh"
        product:       Product name (same as vendor if unknown)
        fixed_version: Patched version string, e.g. "9.8p1"
        commands:      Dict of OS-family → shell command.
                       Keys should be "ubuntu/debian", "rhel/centos", "arch", "windows", etc.
                       Example: {"ubuntu/debian": "apt-get install openssh-server",
                                 "rhel/centos":   "dnf update openssh"}
        official_url:  Optional vendor advisory URL
        severity:      "critical" | "high" | "medium" | "low"  (default "unknown")
        confidence:    Integer 0-100 (default 90 for manually added patches)
    """
    cve_id:        str
    vendor:        str
    product:       str              = ""
    fixed_version: str              = ""
    commands:      Dict[str, str]   = {}
    official_url:  str              = ""
    severity:      str              = "unknown"
    confidence:    int              = 90


# ── /api/patch/guidance — single service ─────────────────────────────────────

@router.post("/guidance")
async def patch_guidance_endpoint(req: PatchGuidanceRequest):
    """
    Return patch guidance for a single service/port.
    Routes through the unified 4-layer orchestrator.
    Features: cache check, in-flight dedup, queue throttle, full fallback chain.
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
        "patch/guidance: service=%s port=%d cve=%s severity=%s os=%s queue=%d",
        svc_name, req.port, cve_id, severity, req.os_hint, get_queue_depth()
    )

    # Deduplicated async fetch — resolve_patch is sync, queue wraps it
    async def _fetch():
        return await run_with_queue(
            resolve_patch,
            cve_id=cve_id,
            service=svc_name,
            version=version,
            os_hint=req.os_hint,
            timeout=25.0,
        )

    try:
        result = await deduplicated_fetch(
            svc_name, req.port, version, cve_id, severity, _fetch
        )
    except asyncio.TimeoutError:
        logger.warning("patch/guidance timed out for %s port=%d", svc_name, req.port)
        result = build_patch_response(svc_name, req.port, version, cve_id, severity, req.os_hint)
        result["timeout"] = True

    # Enrich with request context not carried by orchestrator result
    result.setdefault("port",     req.port)
    result.setdefault("severity", severity)
    result.setdefault("service",  svc_name)
    return result


# ── /api/patch/all — full session remediation dashboard ──────────────────────

@router.post("/all")
async def patch_all_endpoint(req: PatchAllRequest):
    """
    Generate patch guidance for ALL vulnerable ports in a session.
    Groups by service family → one orchestrator call per group.
    Returns sorted results (critical first).
    """
    ctx = {}
    try:
        ctx = load_scan_context(req.session_id) or get_session(req.session_id) or {}
    except Exception as e:
        logger.warning("patch/all: session load failed for %s: %s", req.session_id, e)

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

    _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: _risk_order.get(x.get("severity") or x.get("risk_level", "low"), 3))

    return {
        "ok":          True,
        "session_id":  req.session_id,
        "total_ports": len(all_ports),
        "results":     results,
        "grouped":     req.group_by_service,
        "os_hint":     req.os_hint,  # echo back so UI can confirm which OS was used
    }


# ── /api/patch/add — store a custom patch ────────────────────────────────────

@router.post("/add")
async def patch_add_endpoint(req: PatchAddRequest):
    """
    Store a custom / manually-supplied patch into the local patch repository
    (Layer 1 — patches.db).

    This endpoint is called by the /patch add slash command in the chatbot UI.
    It accepts a CVE, the fixed version, OS-keyed shell commands, and an
    optional advisory URL.  The patch is stored with source='manual' and
    the supplied confidence (default 90).

    Once stored, subsequent /patch guidance calls for the same CVE will hit
    Layer 1 (repository) before reaching the AI engine — making the manually
    supplied commands the authoritative answer.

    Returns the stored patch record on success.
    """
    import json, time
    from app.remediation.repository.patch_repository import patch_repository, CONFIDENCE_VENDOR

    cve_id = req.cve_id.strip().upper()
    if not cve_id:
        raise HTTPException(status_code=422, detail="cve_id is required")
    if not req.commands and not req.fixed_version:
        raise HTTPException(status_code=422, detail="At least one of 'commands' or 'fixed_version' must be provided")

    patch_data = {
        "cve_id":        cve_id,
        "vendor":        req.vendor.strip(),
        "product":       req.product.strip() or req.vendor.strip(),
        "fixed_version": req.fixed_version.strip(),
        "patch_command": req.commands,   # dict of os → cmd
        "commands":      req.commands,
        "official_url":  req.official_url.strip(),
        "severity":      req.severity.strip(),
        "confidence":    req.confidence,
        "source":        "manual",
        "created_at":    time.time(),
    }

    try:
        stored = patch_repository.store(
            cve_id=cve_id,
            patch_data=patch_data,
            source="manual",
            confidence=req.confidence,
        )
        logger.info(
            "patch/add: manually stored patch for %s vendor=%s os_keys=%s",
            cve_id, req.vendor, list(req.commands.keys())
        )
        return {
            "ok":      True,
            "cve_id":  cve_id,
            "stored":  patch_data,
            "message": f"Patch for {cve_id} stored successfully. It will now be used as the primary (Layer 1) resolution.",
        }
    except Exception as e:
        logger.error("patch/add: store failed for %s: %s", cve_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to store patch: {str(e)}")


# ── /api/patch/status ────────────────────────────────────────────────────────

@router.get("/status")
async def patch_status():
    """Return current AI queue depth and cache stats."""
    from app.ai.remediation.remediation_cache import get_stats as _lru_stats
    from app.ai.utils.logging_utils import get_stats as _ai_stats
    cve_cache_stats = {}
    try:
        from app.cve.cve_cache_engine import cve_cache
        cve_cache_stats = cve_cache.get_stats()
    except Exception:
        pass
    return {
        "queue_depth": get_queue_depth(),
        "cache":       _lru_stats(),
        "ai_stats":    _ai_stats(),
        "cve_cache":   cve_cache_stats,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _patch_grouped(ports: list, os_hint: str) -> list:
    """Generate one patch guidance per service group via orchestrator."""
    groups        = group_by_service(ports)
    sorted_groups = prioritize_groups(groups)
    results       = []

    for service, group_ports in sorted_groups:
        summary = build_group_summary(service, group_ports)
        cves    = summary.get("cves") or [{}]
        version = (summary.get("versions") or ["unknown"])[0]
        top_cve_id = cves[0].get("cve_id", "unknown")

        try:
            # Run top CVE through orchestrator — LRU cache makes repeats instant
            guidance = await run_with_queue(
                resolve_patch,
                cve_id=top_cve_id,
                service=service,
                version=version,
                os_hint=os_hint,
                timeout=25.0,
            )
        except Exception as e:
            logger.warning("Group patch failed for %s: %s", service, e)
            guidance = build_patch_response(
                service,
                (summary.get("ports") or [0])[0],
                version,
                top_cve_id,
                summary.get("severity", "medium"),
                os_hint,
            )

        guidance["ports"]      = summary["ports"]
        guidance["service"]    = service
        guidance["cves"]       = cves[:5]
        guidance["risk_level"] = summary["severity"]
        guidance["port_count"] = summary["port_count"]
        results.append(guidance)

    return results


async def _patch_individual(ports: list, os_hint: str) -> list:
    """Generate one patch guidance per port."""
    results = []
    for entry in ports:
        cves    = entry.get("cves", [])
        top_cve = cves[0] if cves else {}
        svc     = entry.get("service") or f"port {entry.get('port', 0)}"
        port    = int(entry.get("port") or 0)
        version = entry.get("version") or "unknown"
        cve_id  = top_cve.get("cve_id", "unknown")
        sev     = top_cve.get("severity", "medium")

        async def _fetch(s=svc, v=version, c=cve_id, sv=sev, p=port):
            return await run_with_queue(
                resolve_patch,
                cve_id=c,
                service=s,
                version=v,
                os_hint=os_hint,
                timeout=25.0,
            )

        try:
            guidance = await deduplicated_fetch(svc, port, version, cve_id, sev, _fetch)
        except Exception as e:
            logger.warning("Individual patch failed for %s: %s", svc, e)
            guidance = build_patch_response(svc, port, version, cve_id, sev, os_hint)

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
                        cve_list = p.get("cves", [])
                        if cve_list:
                            cve_id   = cve_list[0].get("cve_id", "unknown")
                            severity = cve_list[0].get("severity", severity)
                    break
    except Exception as e:
        logger.debug("Session enrich failed: %s", e)
    return version, cve_id, severity
