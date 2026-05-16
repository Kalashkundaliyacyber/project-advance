"""
NVD API Routes  —  app/vuln/routes.py
======================================
FastAPI router exposing NVD integration endpoints.

Endpoints
---------
GET  /api/nvd/status          — Integration health, key status, cache stats
GET  /api/nvd/cve/{cve_id}    — Fetch single CVE by ID
POST /api/nvd/lookup          — Keyword/CPE search
POST /api/nvd/enrich          — Enrich a scan result blob with NVD data
POST /api/nvd/cache/clear     — Clear expired cache entries
"""

from __future__ import annotations

import asyncio
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

from app.vuln.nvd_client import nvd_client, build_cpe
from app.vuln.enrichment import nvd_status, enrich_with_nvd

logger = logging.getLogger("scanwise.nvd.routes")

nvd_router = APIRouter(prefix="/api/nvd", tags=["nvd"])


# ── Request / Response models ─────────────────────────────────────────────────

class NvdLookupRequest(BaseModel):
    product: str
    version: Optional[str] = ""
    service: Optional[str] = ""
    cpe:     Optional[str] = None     # explicit CPE overrides product lookup


class NvdEnrichRequest(BaseModel):
    scan_data: dict                    # versioned scan result from pipeline


# ── Endpoints ─────────────────────────────────────────────────────────────────

@nvd_router.get("/status")
async def get_nvd_status():
    """
    Return NVD integration health.

    Fields:
    - enabled: whether NVD enrichment is active
    - api_key_set: whether NVD_API_KEY is configured
    - rate_limit: current request rate limit
    - cache_db: path to the SQLite cache
    - cache_stats: entry counts
    """
    return nvd_status()


@nvd_router.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    """
    Fetch a single CVE record from NVD by ID.

    Example: GET /api/nvd/cve/CVE-2021-41773
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Must start with CVE-")

    cve = await nvd_client.fetch_cve(cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in NVD")
    return {"cve": cve}


@nvd_router.post("/lookup")
async def lookup_cves(req: NvdLookupRequest):
    """
    Search NVD for CVEs by product name, version, and optional service.

    Tries CPE-based lookup first (more precise), then falls back to keyword search.
    Results are cached — repeated calls for the same product/version are instant.

    Request body:
        { "product": "Apache httpd", "version": "2.4.49", "service": "http" }
    """
    product = req.product.strip()
    version = (req.version or "").strip()
    service = (req.service or "").strip()

    if not product:
        raise HTTPException(status_code=400, detail="product is required")

    # Try explicit CPE first if provided
    cpe = req.cpe
    if not cpe and product:
        cpe = build_cpe(service, product, version)

    results = []
    if cpe:
        results = await nvd_client.search_by_cpe(cpe)

    # Fall back to keyword if CPE gave no results
    if not results:
        results = await nvd_client.search_by_keyword(product, version)

    return {
        "product":  product,
        "version":  version,
        "cpe_used": cpe,
        "count":    len(results),
        "cves":     results,
    }


@nvd_router.post("/enrich")
async def enrich_scan(req: NvdEnrichRequest):
    """
    Enrich an existing scan result with NVD CVE data.

    Accepts the versioned scan result dict (as stored in session data)
    and returns it with all ports enriched with live NVD intelligence.

    Used by the frontend when a session is loaded from history and NVD
    enrichment was not yet run (e.g. pre-NVD sessions).
    """
    try:
        enriched = await enrich_with_nvd(req.scan_data)
        return {"enriched": enriched}
    except Exception as e:
        logger.error("Enrich endpoint error: %s", e)
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {e}")


@nvd_router.post("/cache/clear")
async def clear_nvd_cache():
    """Clear expired NVD cache entries to free disk space."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, nvd_client.clear_expired_cache)
    stats = nvd_client.cache_stats()
    return {"message": "Expired cache entries cleared.", "stats": stats}


@nvd_router.get("/cpe/build")
async def build_cpe_string(
    service: str = "",
    product: str = "",
    version: str = "",
):
    """
    Utility: generate a CPE 2.3 string from nmap service/product/version.

    Example: GET /api/nvd/cpe/build?service=http&product=Apache+httpd&version=2.4.49
    → cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    cpe = build_cpe(service, product, version)
    return {
        "service": service,
        "product": product,
        "version": version,
        "cpe":     cpe,
    }
