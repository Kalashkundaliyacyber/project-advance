"""
ThreatWeave — 4-Layer Patch Resolution Orchestrator
=====================================================
Implements the Intelligent Patch Resolution Framework.

Resolution chain (cheap → expensive):
  Layer -1 → In-memory LRU cache    (sub-millisecond, process-scoped, 1h TTL)
  Layer  0 → Learning KB            (approved AI results, SQLite)
  Layer  1 → Local Patch Repository (SQLite, confidence=stored, vendor-seeded)
  Layer  2 → Vendor Advisory Repo   (Ubuntu USN / Red Hat / Known advisories)
  Layer  3 → NVD Intelligence Cache (NVD 2.0 API, cached 7 days, 3s timeout guard)
  Layer  4 → AI Remediation Engine  (DeepSeek R1 → Qwen → Llama → Rule Engine)

CHANGES v2:
  - Added Layer -1: in-memory LRU cache (from Gen1 remediation_cache.py).
    Same CVE repeat within 1h is a sub-ms hit with zero I/O.
  - Added os_hint param (default "ubuntu") — passed to Layer 4 AI generator
    for OS-aware patch commands. All existing callers unchanged.
  - Added _normalize_output() — unified schema emitting both "commands" and
    "patch_command" keys so all callers (routes.py, patch_api.py) work without
    any change to their key-lookup logic.
  - layer_timings now includes "layer_lru_cache" when LRU hits.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger("ThreatWeave.remediation.orchestrator")

# ── Layer imports ──────────────────────────────────────────────────────────────

from app.remediation.repository.patch_repository import (
    patch_repository, CONFIDENCE_VENDOR, CONFIDENCE_NVD, CONFIDENCE_AI,
)
from app.remediation.vendor.vendor_service    import vendor_service
from app.remediation.nvd_cache.nvd_resolver   import resolve_from_nvd
from app.remediation.ai.ai_patch_generator    import generate_ai_patch
from app.remediation.confidence               import score_patch, confidence_label
from app.remediation.learning.knowledge_base  import learning_kb
from app.remediation.graph.patch_graph        import patch_graph

# Layer -1: in-memory LRU (Gen1 remediation_cache — reused, not replaced)
from app.ai.remediation.remediation_cache import get_cached as _lru_get, set_cached as _lru_set

_NVD_TIMEOUT_SECS = 3.0


def resolve_patch(
    cve_id:      str,
    service:     str = "",
    version:     str = "",
    vendor:      str = "",
    description: str = "",
    os_hint:     str = "ubuntu",
) -> dict:
    """
    Main entry point for the unified patch resolution system.

    Args:
        cve_id:      CVE identifier (e.g. "CVE-2024-6387")
        service:     Service/product name (e.g. "openssh", "nginx")
        version:     Affected version string
        vendor:      Optional vendor hint (e.g. "ubuntu", "redhat")
        description: CVE description for AI context (optional)
        os_hint:     Target OS for AI-generated commands (default "ubuntu").
                     Accepted values: "ubuntu", "rhel", "arch".
                     All existing callers that omit this param get "ubuntu".

    Returns:
        Normalized patch dict with all fields required by routes.py, patch_api.py,
        and the frontend.  See _normalize_output() for the full field list.
    """
    cve_id  = (cve_id or "").strip().upper()
    service = (service or "").strip()
    t0      = time.time()
    layer_timings   = {}
    resolution_path = []

    def _ts(label: str, t_start: float) -> None:
        layer_timings[label] = round((time.time() - t_start) * 1000, 1)

    # ── Layer -1: In-memory LRU (fastest, no I/O) ─────────────────────────────
    t   = time.time()
    lru = _lru_get(service, 0, version, cve_id, "medium")
    _ts("layer_lru_cache", t)
    if lru:
        resolution_path.append("layer_lru_cache")
        lru["from_lru_cache"] = True
        return _finalise(
            _normalize_output(lru, cve_id, service, 0, version),
            resolution_path, layer_timings, t0,
        )

    # ── Layer 0: Learning KB ──────────────────────────────────────────────────
    t = time.time()
    kb_result = learning_kb.lookup(cve_id, service)
    _ts("layer0_learning_kb", t)
    if kb_result:
        kb_result = score_patch(kb_result)
        resolution_path.append("layer0_learning_kb")
        result = _normalize_output(kb_result, cve_id, service, 0, version)
        _lru_set(service, 0, version, cve_id, "medium", result)
        return _finalise(result, resolution_path, layer_timings, t0)

    # ── Layer 1: Local Patch Repository ──────────────────────────────────────
    t  = time.time()
    l1 = patch_repository.lookup(cve_id, service, version)
    _ts("layer1_repository", t)
    if l1:
        l1 = score_patch(l1)
        resolution_path.append("layer1_repository")
        _ingest_graph(cve_id, vendor or service, service, version, l1)
        result = _normalize_output(l1, cve_id, service, 0, version)
        _lru_set(service, 0, version, cve_id, "medium", result)
        return _finalise(result, resolution_path, layer_timings, t0)

    # ── Layer 2: Vendor Advisory Repository ──────────────────────────────────
    t  = time.time()
    l2 = vendor_service.lookup(cve_id, service, vendor)
    _ts("layer2_vendor", t)
    if l2:
        l2 = score_patch(l2)
        resolution_path.append("layer2_vendor")
        patch_repository.store(cve_id, l2, source=l2.get("source", "vendor"),
                               confidence=l2.get("confidence", CONFIDENCE_VENDOR))
        _ingest_graph(cve_id, vendor or service, service, version, l2)
        result = _normalize_output(l2, cve_id, service, 0, version)
        _lru_set(service, 0, version, cve_id, "medium", result)
        return _finalise(result, resolution_path, layer_timings, t0)

    # ── Layer 3: NVD Intelligence Cache ──────────────────────────────────────
    t  = time.time()
    l3 = _resolve_nvd_with_timeout(cve_id, service, version)
    _ts("layer3_nvd", t)
    if l3:
        l3 = score_patch(l3)
        resolution_path.append("layer3_nvd")
        patch_repository.store(cve_id, l3, source=l3.get("source", "nvd"),
                               confidence=l3.get("confidence", CONFIDENCE_NVD))
        _ingest_graph(cve_id, vendor or service, service, version, l3)
        result = _normalize_output(l3, cve_id, service, 0, version)
        _lru_set(service, 0, version, cve_id, "medium", result)
        return _finalise(result, resolution_path, layer_timings, t0)

    # ── Layer 4: AI Remediation Engine ───────────────────────────────────────
    t  = time.time()
    l4 = generate_ai_patch(cve_id, service, version, description, os_hint=os_hint)
    _ts("layer4_ai", t)
    resolution_path.append("layer4_ai")
    l4 = score_patch(l4)
    patch_repository.store(cve_id, l4, source=l4.get("source", "ai"),
                           confidence=l4.get("confidence", CONFIDENCE_AI))
    _ingest_graph(cve_id, vendor or service, service, version, l4)
    result = _normalize_output(l4, cve_id, service, 0, version)
    _lru_set(service, 0, version, cve_id, "medium", result)
    return _finalise(result, resolution_path, layer_timings, t0)


def resolve_patch_batch(vulnerabilities: list) -> list:
    """
    Bulk patch resolution for scan reports.
    Processes each CVE independently; errors are caught per-CVE.

    Args:
        vulnerabilities: list of dicts with keys: cve_id, service, version,
                         vendor (optional), description (optional), os_hint (optional)

    Returns:
        list of normalized patch result dicts in same order as input
    """
    results = []
    for vuln in vulnerabilities:
        try:
            result = resolve_patch(
                cve_id      = vuln.get("cve_id") or vuln.get("id", ""),
                service     = vuln.get("service", ""),
                version     = vuln.get("version", ""),
                vendor      = vuln.get("vendor", ""),
                description = vuln.get("description", ""),
                os_hint     = vuln.get("os_hint", "ubuntu"),
            )
        except Exception as e:
            logger.warning("resolve_patch_batch failed for %s: %s",
                           vuln.get("cve_id", "?"), e)
            result = {
                "cve_id":        vuln.get("cve_id", "unknown"),
                "error":         str(e),
                "patch_command": "# Error — see logs",
                "commands":      {},
                "confidence":    0,
                "source":        "error",
                "layer":         "error",
                "patch_found":   False,
            }
        results.append(result)

    ai_calls   = sum(1 for r in results if r.get("layer") == "layer4_ai" and r.get("ai_called"))
    cache_hits = sum(1 for r in results
                     if r.get("layer") in ("layer_lru_cache", "layer0_learning_kb", "layer1_repository"))
    logger.info(
        "Batch resolution: %d CVEs, %d AI calls, %d cache/KB hits",
        len(results), ai_calls, cache_hits,
    )
    return results


# ── Public alias (routes.py imports this spelling) ────────────────────────────
resolve_patches_batch = resolve_patch_batch


def get_resolution_stats() -> dict:
    """
    Returns per-layer statistics for the resolution framework.
    Used by /api/remediation/stats endpoint.
    """
    stats: dict = {}

    try:
        kb_stats = learning_kb.stats() if hasattr(learning_kb, "stats") else {}
        stats["learning_kb"] = kb_stats
    except Exception as e:
        logger.debug("get_resolution_stats learning_kb error: %s", e)
        stats["learning_kb"] = {}

    try:
        repo_stats = patch_repository.stats() if hasattr(patch_repository, "stats") else {}
        stats["layer1_repository"] = repo_stats
    except Exception as e:
        logger.debug("get_resolution_stats repo error: %s", e)
        stats["layer1_repository"] = {}

    stats["layer3_nvd"] = {}
    stats["layer4_ai"]  = {}

    try:
        graph_stats = patch_graph.stats() if hasattr(patch_graph, "stats") else {}
        stats["knowledge_graph"] = graph_stats
    except Exception as e:
        logger.debug("get_resolution_stats graph error: %s", e)
        stats["knowledge_graph"] = {}

    # LRU cache stats
    try:
        from app.ai.remediation.remediation_cache import get_stats as _lru_stats
        stats["lru_cache"] = _lru_stats()
    except Exception as e:
        logger.debug("get_resolution_stats lru error: %s", e)
        stats["lru_cache"] = {}

    return stats


# ── Internal helpers ───────────────────────────────────────────────────────────

def _normalize_output(
    result:   dict,
    cve_id:   str,
    service:  str  = "",
    port:     int  = 0,
    version:  str  = "",
    severity: str  = "medium",
) -> dict:
    """
    Unified output schema.

    Emits BOTH "commands" and "patch_command" so that:
      - routes.py:  entry.get("commands") or entry.get("patch_command")  → works
      - patch_api.py: same dual-key pattern                               → works
      - Gen2 orchestrator consumers that expect "patch_command"           → works
      - Gen1 _normalize_compat consumers that expect "patch_commands"     → works
    """
    cmds = (
        result.get("commands")
        or result.get("patch_command")
        or result.get("patch_commands")
        or {}
    )
    return {
        # ── Identity ──────────────────────────────────────────────────────────
        "cve_id":              (cve_id or result.get("cve_id", "")).upper(),
        "service":             service or result.get("service", ""),
        "port":                port or result.get("port", 0),
        "version":             version or result.get("version", ""),
        "severity":            severity or result.get("severity", "medium"),
        # ── Patch details ─────────────────────────────────────────────────────
        "title":               result.get("title", f"Patch {service} for {cve_id}"),
        "fix_version":         result.get("fix_version") or result.get("fixed_version", "latest"),
        "commands":            cmds,          # routes.py / Gen1 key
        "patch_command":       cmds,          # Gen2 / orchestrator key
        "patch_commands":      cmds,          # compat for older callers
        "upgrade_path":        result.get("upgrade_path", ""),
        "verification_steps":  result.get("verification_steps", []),
        "rollback_steps":      result.get("rollback_steps", []),
        "patch_type":          result.get("patch_type", "upgrade"),
        "mitigation":          result.get("mitigation", ""),
        "vendor_url":          result.get("vendor_url") or result.get("official_url", ""),
        "official_url":        result.get("vendor_url") or result.get("official_url", ""),
        "references":          result.get("references", []),
        "notes":               result.get("notes", ""),
        # ── Provenance / audit ────────────────────────────────────────────────
        "confidence":          result.get("confidence", 70),
        "confidence_label":    confidence_label(result.get("confidence", 70)),
        "source":              result.get("source", "ai"),
        "provider":            result.get("provider") or result.get("engine", ""),
        "layer":               result.get("layer", ""),
        "patch_found":         result.get("patch_found", True),
        "from_kb":             result.get("from_kb") or result.get("from_learning_kb", False),
        "from_cache":          (
            result.get("from_cache")
            or result.get("from_ai_cache")
            or result.get("from_lru_cache", False)
        ),
        "from_lru_cache":      result.get("from_lru_cache", False),
        "ai_called":           result.get("ai_called", False),
        "validation_status":   result.get("validation_status", ""),
        # ── Timing (audit trail) ──────────────────────────────────────────────
        "resolution_path":     result.get("resolution_path", []),
        "layer_timings_ms":    result.get("layer_timings_ms", {}),
        "total_latency_ms":    result.get("total_latency_ms", 0),
    }


def _resolve_nvd_with_timeout(cve_id: str, service: str, version: str) -> Optional[dict]:
    """Wraps NVD resolver with a timeout guard."""
    import concurrent.futures
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(resolve_from_nvd, cve_id, service, version)
            return future.result(timeout=_NVD_TIMEOUT_SECS)
    except concurrent.futures.TimeoutError:
        logger.warning("[LAYER3] NVD timeout for %s (>%.1fs) — falling to Layer 4",
                       cve_id, _NVD_TIMEOUT_SECS)
        return None
    except Exception as e:
        logger.debug("[LAYER3] NVD resolver error for %s: %s", cve_id, e)
        return None


def _ingest_graph(cve_id, vendor, service, version, result):
    """Ingest patch result into knowledge graph."""
    try:
        patch_graph.ingest_patch(
            cve_id=cve_id, vendor=vendor, product=service,
            version=version, patch=result,
        )
    except Exception as e:
        logger.debug("Patch graph ingest failed: %s", e)


def _finalise(result: dict, resolution_path: list,
              layer_timings: dict, t0: float) -> dict:
    """Attach audit metadata to resolved patch result."""
    result["resolution_path"]  = resolution_path
    result["layer_timings_ms"] = layer_timings
    result["total_latency_ms"] = round((time.time() - t0) * 1000, 1)
    logger.info(
        "[%s] Patch resolved for %s | confidence=%s | latency=%.1fms",
        (resolution_path[-1] if resolution_path else "unknown").upper(),
        result.get("cve_id", "?"),
        result.get("confidence_label", result.get("confidence", "?")),
        result["total_latency_ms"],
    )
    return result
