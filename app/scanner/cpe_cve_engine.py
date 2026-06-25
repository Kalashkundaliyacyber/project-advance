"""
cpe_cve_engine.py
==================
Phase 3 of the reconstruction — local CPE + CVE matching, so the system
isn't dependent on Gemini for every finding.

IMPORTANT — this does NOT duplicate the CVE database. Two real engines
already exist in this codebase and are already wired into the automatic
pipeline (_run_scan_pipeline → map_cves → enrich_with_nvd_sync):

  - app/cve/mapper.py        — local hardcoded product/version-range DB,
                                instant, fully offline (LOCAL_CVE_DB, _affected)
  - app/vuln/nvd_client.py   — live NVD REST API (services.nvd.nist.gov),
                                with build_cpe(), a SQLite cache (7 days for
                                exact CVE-ID lookups, 24h for keyword/CPE
                                searches — already tighter than the "once a
                                week" ceiling this phase asked for), and
                                rate limiting

What was actually missing, and what this file adds:
  1. ONE place to call that runs both engines and returns results in the
     exact shape this phase specified — cve_id / severity / description /
     cvss_score / confidence
  2. The "confidence: exact | range" field neither engine set before —
     exact = the live NVD CPE match against the precise detected version;
     range = a prefix/version-range match (local DB, or NVD keyword search
     with no exact CPE hit)

This still doesn't touch Gemini — Gemini's job in this codebase is choosing
*which NSE script* confirms a CVE (app/scanner/gemini_selector.py), not
finding which CVEs apply to a version. That's Phase 6 territory. This phase
only changes how CVEs get found in the first place.
"""
from __future__ import annotations

import asyncio
import logging

from app.cve.mapper import LOCAL_CVE_DB, _affected
from app.vuln.nvd_client import build_cpe, nvd_client, NVD_BASE_URL  # noqa: F401 (URL re-exported for visibility)

logger = logging.getLogger("ThreatWeave.cpe_cve_engine")

# Re-exported so callers/docs have one obvious name for "the feed URL".
NVD_FEED_URL = NVD_BASE_URL


def build_cpe_string(service: str, product: str, version: str) -> str | None:
    """
    e.g. build_cpe_string("ssh", "OpenSSH", "4.7")
         -> "cpe:2.3:a:openbsd:openssh:4.7:*:*:*:*:*:*:*"
    Thin pass-through to the existing, already-tested builder.
    """
    return build_cpe(service, product, version)


def _local_matches(service: str, product: str, version: str) -> list[dict]:
    """Local hardcoded DB — version-range matching, confidence='range'."""
    combined = f"{product} {service}".lower().strip()
    version = (version or "").lower().strip()
    out = []
    for db_key, cve_list in LOCAL_CVE_DB.items():
        if db_key not in combined and combined not in db_key:
            continue
        for cve in cve_list:
            if not _affected(version, cve["affected"]):
                continue
            # A pattern of "" (version-agnostic) or a short prefix is a range
            # match by construction — local DB never claims an exact version.
            out.append({
                "cve_id":      cve["cve_id"],
                "severity":    cve["severity"],
                "description": cve["description"],
                "cvss_score":  cve["cvss"],
                "confidence":  "range",
            })
    return out


async def _nvd_matches(service: str, product: str, version: str) -> list[dict]:
    """
    Live NVD lookup (cached locally — see nvd_client._NvdCache, 24h-7day TTL).
    CPE match (version baked into the CPE string) -> confidence='exact'.
    Keyword fallback (no version in the query) -> confidence='range'.
    """
    out = []
    cpe = build_cpe(service, product, version)
    if cpe:
        try:
            cves = await nvd_client.search_by_cpe(cpe)
        except Exception as e:
            logger.warning("cpe_cve_engine: NVD CPE lookup failed: %s", e)
            cves = []
        for c in cves:
            out.append({
                "cve_id":      c.get("cve_id"),
                "severity":    c.get("severity", "unknown"),
                "description": c.get("description", ""),
                "cvss_score":  c.get("cvss_score", 0),
                "confidence":  "exact",
            })
    if not out and product:
        try:
            cves = await nvd_client.search_by_keyword(product, version)
        except Exception as e:
            logger.warning("cpe_cve_engine: NVD keyword lookup failed: %s", e)
            cves = []
        for c in cves:
            out.append({
                "cve_id":      c.get("cve_id"),
                "severity":    c.get("severity", "unknown"),
                "description": c.get("description", ""),
                "cvss_score":  c.get("cvss_score", 0),
                "confidence":  "range",
            })
    return out


def lookup_cves(service: str, product: str, version: str, use_nvd: bool = True) -> list[dict]:
    """
    Phase 3 main entry point (sync — safe to call from a thread executor,
    same pattern as every other pipeline stage in _run_scan_pipeline).

    Returns a deduplicated list of:
        {cve_id, severity, description, cvss_score, confidence: "exact"|"range"}
    sorted by cvss_score descending. Local DB results always included
    (instant, free); NVD results merged in when use_nvd=True and don't
    duplicate a CVE ID the local DB already found.
    """
    local = _local_matches(service, product, version)
    seen = {c["cve_id"] for c in local}

    nvd_results: list[dict] = []
    if use_nvd:
        try:
            loop = asyncio.new_event_loop()
            try:
                nvd_results = loop.run_until_complete(_nvd_matches(service, product, version))
            finally:
                loop.close()
        except Exception as e:
            logger.warning("cpe_cve_engine: NVD stage failed, local-only: %s", e)
            nvd_results = []

    merged = list(local)
    for c in nvd_results:
        if c["cve_id"] and c["cve_id"] not in seen:
            merged.append(c)
            seen.add(c["cve_id"])

    merged.sort(key=lambda c: c.get("cvss_score", 0) or 0, reverse=True)
    return merged


def tag_confidence_on_parsed(parsed: dict) -> dict:
    """
    Pipeline integration helper: walks every port's existing port["cves"]
    list (already populated by map_cves() + enrich_with_nvd_sync() earlier
    in _run_scan_pipeline) and adds the missing "confidence" field in place,
    using the same local-DB-vs-NVD-CPE distinction as lookup_cves() — without
    re-running either lookup or duplicating storage.

    NSE-confirmed entries (already actively proven by --script vuln, the
    highest-trust source — see app/cve/mapper.py::_find_cves Step 0) get
    confidence="exact" since nmap *tested* them, not inferred them.
    """
    local_ids = {c["cve_id"] for entries in LOCAL_CVE_DB.values() for c in entries}
    for host in parsed.get("hosts", []):
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                if "confidence" in cve:
                    continue
                if cve.get("cve_id") in local_ids:
                    cve["confidence"] = "range"
                elif "nse_script" in cve:
                    cve["confidence"] = "exact"   # actively confirmed by NSE
                else:
                    cve["confidence"] = "exact"   # came from NVD CPE match
    return parsed
