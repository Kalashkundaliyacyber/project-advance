"""
Vulnerability Enrichment Pipeline  —  app/vuln/enrichment.py
=============================================================
Bridges the NVD API client into the scan pipeline.

The enrichment step runs AFTER:
  parse_nmap_output → analyze_versions → map_cves (local DB)

And BEFORE:
  analyze_context → calculate_risk → AI analysis

It augments each port's "cves" list with live NVD data, adding:
  • CVSS v2/v3/v4 scores and vectors
  • CWE weakness IDs
  • CPE match strings
  • Reference URLs with patch advisories
  • Published / modified dates
  • Severity colour codes for the UI

Architecture notes
------------------
* Runs async via asyncio.gather so all ports are queried concurrently
* Rate-limiter in nvd_client prevents API overload
* Falls back to local-DB-only data if NVD is unavailable or key not set
* Normalises local-DB CVEs to match the full NVD schema so consumers
  (chatbot, report, AI analysis) see a single unified format
* Safe: never crashes the scan pipeline — wraps everything in try/except
"""

from __future__ import annotations

import asyncio
import logging
import os

from app.vuln.nvd_client import nvd_client, severity_color, enrich_scan_sync

logger = logging.getLogger("scanwise.enrichment")

# Controls whether NVD enrichment runs (env override for testing)
_NVD_ENABLED = os.environ.get("NVD_ENABLED", "true").lower() != "false"


# ── Schema normalisation ───────────────────────────────────────────────────────
import time as _time_mod

def _days_since(pub_date: str) -> int | None:
    """FIX11: Return days since published date string (ISO-8601 or YYYY-MM-DD)."""
    if not pub_date:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            import datetime
            pub = datetime.datetime.strptime(pub_date[:19], fmt[:len(fmt)])
            delta = datetime.datetime.utcnow() - pub
            return max(0, delta.days)
        except Exception:
            continue
    return None

def _age_severity(days: int | None) -> str:
    """FIX11: Convert age in days to a severity label for old unpatched CVEs."""
    if days is None: return "unknown"
    if days > 1095: return "critical"   # >3 years — very serious if unpatched
    if days > 365:  return "high"
    if days > 90:   return "medium"
    return "low"



def normalise_local_cve(cve: dict) -> dict:
    """
    Upgrade a local-DB CVE record to the full NVD canonical schema.
    Local records use "cvss" instead of "cvss_score" and lack some fields —
    this ensures all downstream code sees a uniform structure.
    """
    score   = float(cve.get("cvss_score") or cve.get("cvss") or 0.0)
    sev     = str(cve.get("severity", "unknown")).lower()
    cve_id  = cve.get("cve_id", "")

    return {
        "cve_id":       cve_id,
        "description":  cve.get("description", ""),
        "cvss_score":   score,
        "cvss_version": "local",
        "vector":       "",
        "severity":     sev,
        "color":        severity_color(sev),
        "cwes":         cve.get("cwes", []),
        "cpes":         cve.get("cpes", []),
        "references":   cve.get("references", []),
        "published":    cve.get("published", ""),
        "modified":     cve.get("modified", ""),
        "nvd_url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        "patch":        cve.get("patch", ""),
        "source":       cve.get("source", "local"),
        # FIX11: compute days since publication for age-severity tracking
        "days_since_published": _days_since(cve.get("published", "")),
        "age_severity":         _age_severity(_days_since(cve.get("published", ""))),
    }


def normalise_all_cves(versioned: dict) -> dict:
    """
    Walk every port in the result and normalise its CVE list so that
    local-DB records match the same schema as live NVD records.
    """
    for host in versioned.get("hosts", []):
        for port in host.get("ports", []):
            port["cves"] = [
                normalise_local_cve(c) for c in port.get("cves", [])
            ]
    return versioned


# ── Main enrichment entry point ────────────────────────────────────────────────

async def enrich_with_nvd(cve_data: dict) -> dict:
    """
    Async enrichment step.  Normalises local CVEs then augments with NVD.

    Workflow:
      1. Normalise local-DB CVE schema on all ports.
      2. If NVD is enabled and an API key is set (or unauthenticated is ok),
         call nvd_client.enrich_scan() which queries NVD concurrently for
         each port with a detected product.
      3. Return the enriched result.

    Always returns a valid dict — never raises.
    """
    try:
        # Step 1: normalise local CVEs
        normalised = normalise_all_cves(dict(cve_data))

        # Step 2: NVD enrichment
        if not _NVD_ENABLED:
            logger.debug("NVD enrichment disabled via NVD_ENABLED=false")
            return normalised

        enriched = await nvd_client.enrich_scan(normalised)
        _log_enrichment_summary(enriched)
        return enriched

    except Exception as e:
        logger.warning("NVD enrichment failed gracefully: %s", e)
        # Return at minimum the normalised local data
        try:
            return normalise_all_cves(dict(cve_data))
        except Exception:
            return cve_data


def enrich_with_nvd_sync(cve_data: dict) -> dict:
    """
    Synchronous wrapper — used when called from run_in_executor.
    Spawns its own event loop to run the async enrichment.
    """
    try:
        # Normalise first (always safe)
        normalised = normalise_all_cves(dict(cve_data))
        if not _NVD_ENABLED:
            return normalised
        return enrich_scan_sync(normalised)
    except Exception as e:
        logger.warning("enrich_with_nvd_sync error: %s", e)
        try:
            return normalise_all_cves(dict(cve_data))
        except Exception:
            return cve_data


# ── Logging helpers ────────────────────────────────────────────────────────────

def _log_enrichment_summary(enriched: dict):
    total_ports = 0
    total_cves  = 0
    nvd_cves    = 0
    for host in enriched.get("hosts", []):
        for port in host.get("ports", []):
            total_ports += 1
            cves = port.get("cves", [])
            total_cves += len(cves)
            nvd_cves   += sum(1 for c in cves if c.get("source") == "nvd")

    logger.info(
        "NVD enrichment complete: %d ports, %d total CVEs (%d from NVD)",
        total_ports, total_cves, nvd_cves,
    )


# ── Status endpoint helper ─────────────────────────────────────────────────────

def nvd_status() -> dict:
    """Return NVD integration status for the /api/nvd/status endpoint."""
    return {
        "enabled":       _NVD_ENABLED,
        "api_key_set":   bool(os.environ.get("NVD_API_KEY", "").strip()),
        **nvd_client.status(),
    }
