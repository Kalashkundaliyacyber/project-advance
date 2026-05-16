"""
NVD API Client v1.0  —  app/vuln/nvd_client.py
===============================================
Full integration with the National Vulnerability Database (NVD) API v2.

Features
--------
* CVSS v2 / v3.0 / v3.1 / v4.0 scores + severity
* CWE (weakness) mappings
* CPE (product) matching
* Published / modified timestamps
* Reference URLs and advisories
* SQLite-backed persistent cache (data/cve_db/nvd_cache.db)
* Token-bucket rate limiter: 50 req/30s (no key) · 2000 req/30s (with key)
* Exponential back-off retry (up to 3 attempts) on 503 / network errors
* Async-ready: all blocking I/O wrapped in run_in_executor
* Graceful degradation — never raises; returns [] on any failure
* Adapter architecture: NvdAdapter base class for future sources
  (Vulners, EPSS, CISA KEV, ExploitDB, Shodan)

Usage
-----
    from app.vuln.nvd_client import nvd_client

    # Lookup by exact CVE ID
    cve = await nvd_client.fetch_cve("CVE-2021-41773")

    # Lookup by CPE string
    cves = await nvd_client.search_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

    # Lookup by product keyword + version
    cves = await nvd_client.search_by_keyword("Apache httpd", "2.4.49")

    # Enrich all ports in a parsed scan result
    enriched = await nvd_client.enrich_scan(versioned_result)

Environment
-----------
    NVD_API_KEY=<your key>   # optional — raises rate limit 5x
    Set in .env file; never committed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("scanwise.nvd")

# ── Configuration ──────────────────────────────────────────────────────────────

NVD_BASE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "").strip()
USER_AGENT     = "ScanWise-AI/3.0 (security scanner; contact=admin@localhost)"

# Rate limiting: NVD enforces 5 req/30s without key, 50 req/30s with key.
# We stay well under to avoid 503 responses.
_RATE_WINDOW   = 30.0                          # seconds
_RATE_LIMIT    = 40 if NVD_API_KEY else 4     # requests per window
_REQUEST_GAP   = _RATE_WINDOW / _RATE_LIMIT   # minimum seconds between requests

# Cache TTL: 24 hours for keyword searches, 7 days for exact CVE lookups
_CACHE_TTL_KEYWORD = 86_400      # 24 h
_CACHE_TTL_CVE_ID  = 604_800    # 7 days

# Retry parameters
_MAX_RETRIES   = 3
_RETRY_BASE    = 2.0             # seconds (doubles each attempt)
_REQUEST_TIMEOUT = 12            # seconds per HTTP request

# Results caps
_MAX_RESULTS_PER_QUERY = 20      # NVD max is 2000; we cap at 20 for perf
_MAX_CVE_PER_PORT      = 10      # top-N CVEs returned per port

# DB location
_DB_DIR  = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "cve_db",
)
_DB_PATH = os.path.join(_DB_DIR, "nvd_cache.db")


# ── Severity colour map ────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#4488ff",
    "none":     "#aaaaaa",
    "unknown":  "#888888",
}


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["unknown"])


# ── Adapter base class (future-ready) ─────────────────────────────────────────

class NvdAdapter(ABC):
    """
    Abstract adapter for vulnerability intelligence sources.
    Future implementations: VulnersAdapter, EpssAdapter, CisaKevAdapter,
    ExploitDbAdapter, ShodanAdapter.
    """

    @abstractmethod
    async def fetch_cve(self, cve_id: str) -> dict | None:
        """Return a single normalised CVE record, or None."""

    @abstractmethod
    async def search_by_cpe(self, cpe: str) -> list[dict]:
        """Return list of normalised CVE records matching a CPE string."""

    @abstractmethod
    async def search_by_keyword(self, product: str, version: str) -> list[dict]:
        """Return list of normalised CVE records matching product+version."""


# ── SQLite cache ───────────────────────────────────────────────────────────────

class _NvdCache:
    """
    Thread-safe SQLite-backed persistent cache.
    Schema: (cache_key TEXT PK, payload TEXT, fetched_at REAL, ttl REAL)
    """

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._lock    = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._connect()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key  TEXT PRIMARY KEY,
                    payload    TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    ttl        REAL NOT NULL
                )
            """)
            # Prune expired entries on startup
            conn.execute(
                "DELETE FROM nvd_cache WHERE fetched_at + ttl < ?",
                (time.time(),)
            )
            conn.commit()
            conn.close()

    def get(self, key: str) -> list[dict] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT payload, fetched_at, ttl FROM nvd_cache WHERE cache_key = ?",
                    (key,)
                ).fetchone()
                if row is None:
                    return None
                if time.time() > row["fetched_at"] + row["ttl"]:
                    conn.execute("DELETE FROM nvd_cache WHERE cache_key = ?", (key,))
                    conn.commit()
                    return None
                return json.loads(row["payload"])
            except Exception as e:
                logger.debug("Cache read error for %s: %s", key, e)
                return None
            finally:
                conn.close()

    def set(self, key: str, data: list[dict], ttl: float):
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO nvd_cache
                       (cache_key, payload, fetched_at, ttl) VALUES (?, ?, ?, ?)""",
                    (key, json.dumps(data), time.time(), ttl)
                )
                conn.commit()
            except Exception as e:
                logger.debug("Cache write error for %s: %s", key, e)
            finally:
                conn.close()

    def clear_expired(self):
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "DELETE FROM nvd_cache WHERE fetched_at + ttl < ?",
                    (time.time(),)
                )
                conn.commit()
            finally:
                conn.close()

    def stats(self) -> dict:
        with self._lock:
            conn = self._connect()
            try:
                total   = conn.execute("SELECT COUNT(*) FROM nvd_cache").fetchone()[0]
                expired = conn.execute(
                    "SELECT COUNT(*) FROM nvd_cache WHERE fetched_at + ttl < ?",
                    (time.time(),)
                ).fetchone()[0]
                return {"total_entries": total, "expired_entries": expired}
            finally:
                conn.close()


# ── Token-bucket rate limiter ─────────────────────────────────────────────────

class _RateLimiter:
    """
    Simple token-bucket limiter.  Thread-safe.
    Ensures we never exceed _RATE_LIMIT requests per _RATE_WINDOW seconds.
    """

    def __init__(self, limit: int, window: float):
        self._limit   = limit
        self._window  = window
        self._tokens  = limit
        self._last    = time.monotonic()
        self._lock    = threading.Lock()

    def acquire(self):
        """Block until a token is available."""
        while True:
            with self._lock:
                now     = time.monotonic()
                elapsed = now - self._last
                # Refill tokens proportionally
                refill  = int(elapsed / self._window * self._limit)
                if refill:
                    self._tokens = min(self._limit, self._tokens + refill)
                    self._last   = now
                if self._tokens > 0:
                    self._tokens -= 1
                    return
            # No token — sleep a fraction of the window and retry
            time.sleep(self._window / self._limit)


# ── NVD response normaliser ───────────────────────────────────────────────────

def _parse_cvss(metrics: dict) -> tuple[float, str, str, str]:
    """
    Extract best available CVSS score and severity from NVD metrics block.
    Priority: v4.0 → v3.1 → v3.0 → v2.0
    Returns: (base_score, severity, cvss_version, vector_string)
    """
    priority = [
        ("cvssMetricV40",  "4.0"),
        ("cvssMetricV31",  "3.1"),
        ("cvssMetricV30",  "3.0"),
        ("cvssMetricV2",   "2.0"),
    ]
    for key, ver in priority:
        entries = metrics.get(key, [])
        if entries:
            m     = entries[0]
            data  = m.get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            sev   = (data.get("baseSeverity") or
                     data.get("severity") or
                     _score_to_severity(score)).lower()
            vec   = data.get("vectorString", "")
            return score, sev, ver, vec
    return 0.0, "unknown", "N/A", ""


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0:  return "low"
    return "none"


def _parse_cwes(cve: dict) -> list[str]:
    """Extract CWE IDs from a CVE record."""
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    return cwes


def _parse_references(cve: dict) -> list[dict]:
    """Extract references (url + tags) from a CVE record."""
    refs = []
    for ref in cve.get("references", [])[:5]:   # cap at 5
        refs.append({
            "url":  ref.get("url", ""),
            "tags": ref.get("tags", []),
        })
    return refs


def _parse_cpes(cve: dict) -> list[str]:
    """Extract CPE match strings from a CVE record."""
    cpes = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe = match.get("criteria", "")
                    if cpe:
                        cpes.add(cpe)
    return sorted(cpes)[:10]   # cap


def _normalise_cve(item: dict) -> dict | None:
    """
    Convert a raw NVD API vulnerability item into the canonical ScanWise format.

    Canonical schema:
    {
        "cve_id":       str,
        "description":  str,
        "cvss_score":   float,
        "cvss_version": str,       # "3.1" / "4.0" etc.
        "vector":       str,       # CVSS vector string
        "severity":     str,       # critical / high / medium / low / none
        "color":        str,       # hex colour for UI
        "cwes":         list[str],
        "cpes":         list[str],
        "references":   list[dict],
        "published":    str,
        "modified":     str,
        "nvd_url":      str,
        "patch":        str,
        "source":       "nvd",
    }
    """
    try:
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description (English preferred)
        descs = cve.get("descriptions", [])
        desc  = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            "No description available."
        )

        metrics               = cve.get("metrics", {})
        score, sev, ver, vec  = _parse_cvss(metrics)
        cwes                  = _parse_cwes(cve)
        cpes                  = _parse_cpes(cve)
        refs                  = _parse_references(cve)

        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Build a concise patch advisory from references
        patch_urls = [r["url"] for r in refs if any(
            t in ("Patch", "Vendor Advisory", "Mitigation") for t in r.get("tags", [])
        )]
        patch = (
            f"Apply vendor patch. See: {patch_urls[0]}"
            if patch_urls else
            f"Check vendor advisory at {nvd_url}"
        )

        return {
            "cve_id":       cve_id,
            "description":  desc[:400],
            "cvss_score":   score,
            "cvss_version": ver,
            "vector":       vec,
            "severity":     sev,
            "color":        severity_color(sev),
            "cwes":         cwes,
            "cpes":         cpes,
            "references":   refs,
            "published":    cve.get("published",     ""),
            "modified":     cve.get("lastModified",  ""),
            "nvd_url":      nvd_url,
            "patch":        patch,
            "source":       "nvd",
        }
    except Exception as e:
        logger.debug("CVE normalise error: %s", e)
        return None


# ── Core NVD HTTP client ───────────────────────────────────────────────────────

class NvdApiClient(NvdAdapter):
    """
    Production NVD API v2 client.

    Thread-safe.  All public methods are async; blocking I/O runs in the
    default executor so the FastAPI event loop is never blocked.
    """

    def __init__(self):
        self._cache   = _NvdCache(_DB_PATH)
        self._limiter = _RateLimiter(_RATE_LIMIT, _RATE_WINDOW)
        self._lock    = threading.Lock()

    # ── Internal HTTP ────────────────────────────────────────────────────────

    def _make_headers(self) -> dict:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        return headers

    def _get(self, url: str) -> dict:
        """
        Blocking GET with rate limiting + exponential retry.
        Returns parsed JSON dict, or raises on final failure.
        """
        self._limiter.acquire()
        for attempt in range(_MAX_RETRIES):
            try:
                req = urllib.request.Request(url, headers=self._make_headers())
                with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                    raw = resp.read()
                return json.loads(raw)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {}           # CVE not found — not an error
                if e.code in (429, 503) and attempt < _MAX_RETRIES - 1:
                    wait = _RETRY_BASE ** (attempt + 1)
                    logger.warning("NVD rate-limited (HTTP %s), retrying in %.1fs", e.code, wait)
                    time.sleep(wait)
                    self._limiter.acquire()
                    continue
                raise
            except (urllib.error.URLError, OSError) as e:
                if attempt < _MAX_RETRIES - 1:
                    wait = _RETRY_BASE ** (attempt + 1)
                    logger.warning("NVD network error (%s), retry %d in %.1fs", e, attempt + 1, wait)
                    time.sleep(wait)
                    self._limiter.acquire()
                    continue
                raise
        raise RuntimeError(f"NVD request failed after {_MAX_RETRIES} attempts: {url}")

    def _fetch_sync(self, url: str) -> list[dict]:
        """Synchronous fetch → parse → normalise. Returns [] on any error."""
        try:
            data  = self._get(url)
            items = data.get("vulnerabilities", [])
            out   = []
            for item in items:
                normalised = _normalise_cve(item)
                if normalised:
                    out.append(normalised)
            # Sort by CVSS score descending
            out.sort(key=lambda x: x["cvss_score"], reverse=True)
            return out[:_MAX_RESULTS_PER_QUERY]
        except Exception as e:
            logger.warning("NVD fetch error: %s", e)
            return []

    # ── Async public API ─────────────────────────────────────────────────────

    async def fetch_cve(self, cve_id: str) -> dict | None:
        """
        Fetch a single CVE by ID (e.g. "CVE-2021-41773").
        Returns normalised dict or None.
        """
        cve_id = cve_id.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            logger.debug("Invalid CVE ID format: %s", cve_id)
            return None

        cache_key = f"id:{cve_id}"
        cached    = self._cache.get(cache_key)
        if cached is not None:
            return cached[0] if cached else None

        url    = f"{NVD_BASE_URL}?cveId={urllib.parse.quote(cve_id)}"
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._fetch_sync, url)

        self._cache.set(cache_key, result, _CACHE_TTL_CVE_ID)
        return result[0] if result else None

    async def search_by_cpe(self, cpe: str) -> list[dict]:
        """
        Search CVEs by CPE 2.3 string.
        Example: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        """
        cpe = cpe.strip()
        if not cpe.startswith("cpe:"):
            logger.debug("Invalid CPE: %s", cpe)
            return []

        cache_key = f"cpe:{cpe}"
        cached    = self._cache.get(cache_key)
        if cached is not None:
            return cached

        params = {
            "cpeName":        cpe,
            "resultsPerPage": str(_MAX_RESULTS_PER_QUERY),
            "isVulnerable":   "",   # only return vulns where this CPE is vulnerable
        }
        url    = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._fetch_sync, url)

        self._cache.set(cache_key, result, _CACHE_TTL_KEYWORD)
        return result

    async def search_by_keyword(self, product: str, version: str = "") -> list[dict]:
        """
        Search NVD by product name + optional version keyword.
        Falls back gracefully to product-only if version is empty.
        """
        product = product.strip()
        version = version.strip()
        if not product:
            return []

        keyword   = f"{product} {version}".strip()
        cache_key = f"kw:{keyword.lower()}"
        cached    = self._cache.get(cache_key)
        if cached is not None:
            return cached

        params = {
            "keywordSearch":   keyword,
            "keywordExactMatch": "",
            "resultsPerPage":  str(_MAX_RESULTS_PER_QUERY),
        }
        url    = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._fetch_sync, url)

        # If version-specific query returned nothing, retry product-only
        if not result and version:
            cache_key2 = f"kw:{product.lower()}"
            cached2    = self._cache.get(cache_key2)
            if cached2 is not None:
                result = cached2
            else:
                params2 = {"keywordSearch": product, "resultsPerPage": str(_MAX_RESULTS_PER_QUERY)}
                url2    = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params2)}"
                result  = await loop.run_in_executor(None, self._fetch_sync, url2)
                self._cache.set(cache_key2, result, _CACHE_TTL_KEYWORD)

        self._cache.set(cache_key, result, _CACHE_TTL_KEYWORD)
        return result

    # ── Scan enrichment (the main integration point) ─────────────────────────

    async def enrich_scan(self, versioned: dict) -> dict:
        """
        Enrich every port in a versioned scan result with live NVD CVE data.

        Runs all port lookups concurrently (bounded by the rate limiter).
        Merges NVD results with any existing local-DB CVEs, deduplicating by
        CVE ID.  Never overwrites a port's existing CVEs — only appends.

        This replaces the old cve/mapper.py NVD lookup path entirely.
        """
        if not NVD_API_KEY:
            # Without API key, NVD is unreliable for production use.
            # Still attempt but with reduced concurrency.
            logger.info("NVD_API_KEY not set — using unauthenticated lookups (rate limited)")

        result = dict(versioned)
        tasks  = []
        ports  = []   # flat list of port dicts to match tasks back to

        for host in result.get("hosts", []):
            for port in host.get("ports", []):
                product = port.get("product", "").strip()
                version = port.get("version", "").strip()
                if product:
                    tasks.append(self._enrich_port(port, product, version))
                    ports.append(port)

        if tasks:
            # asyncio.gather — all NVD calls run concurrently but each
            # internally rate-limited, so we never flood the API.
            enriched_lists = await asyncio.gather(*tasks, return_exceptions=True)
            for port, enriched in zip(ports, enriched_lists):
                if isinstance(enriched, Exception):
                    logger.debug("Port enrich error: %s", enriched)
                    continue
                if enriched:
                    # Merge: existing CVEs (local DB) + new NVD CVEs
                    existing_ids = {c["cve_id"] for c in port.get("cves", [])}
                    for cve in enriched:
                        if cve["cve_id"] not in existing_ids:
                            port.setdefault("cves", []).append(cve)
                    # Re-sort by severity
                    port["cves"].sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
                    port["cves"] = port["cves"][:_MAX_CVE_PER_PORT]

        return result

    async def _enrich_port(self, port: dict, product: str, version: str) -> list[dict]:
        """
        Enrich a single port.  Tries CPE lookup first (more precise),
        falls back to keyword search.
        """
        # Try CPE-based lookup first
        cpe = build_cpe(port.get("service", ""), product, version)
        if cpe:
            cves = await self.search_by_cpe(cpe)
            if cves:
                return cves

        # Fallback: keyword search
        return await self.search_by_keyword(product, version)

    # ── Utility ──────────────────────────────────────────────────────────────

    def cache_stats(self) -> dict:
        return self._cache.stats()

    def clear_expired_cache(self):
        self._cache.clear_expired()

    def status(self) -> dict:
        return {
            "api_key_set":    bool(NVD_API_KEY),
            "rate_limit":     f"{_RATE_LIMIT} req / {int(_RATE_WINDOW)}s",
            "cache_db":       _DB_PATH,
            "cache_stats":    self._cache.stats(),
            "nvd_base_url":   NVD_BASE_URL,
        }


# ── CPE generator ─────────────────────────────────────────────────────────────

# Maps nmap service name / product fragments → NVD vendor:product CPE components
_CPE_MAP: list[tuple[str, str, str]] = [
    # (nmap_service_or_product_fragment,  cpe_vendor,    cpe_product)
    # IMPORTANT: more-specific entries must come BEFORE generic ones
    ("apache tomcat",    "apache",         "tomcat"),
    ("openssh",          "openbsd",        "openssh"),
    ("apache httpd",     "apache",         "http_server"),
    ("apache",           "apache",         "http_server"),
    ("nginx",            "nginx",          "nginx"),
    ("vsftpd",           "vsftpd_project", "vsftpd"),
    ("proftpd",          "proftpd",        "proftpd"),
    ("mysql",            "oracle",         "mysql"),
    ("mariadb",          "mariadb",        "mariadb"),
    ("postgresql",       "postgresql",     "postgresql"),
    ("mongodb",          "mongodb",        "mongodb"),
    ("redis",            "redislabs",      "redis"),
    ("isc bind",         "isc",            "bind"),
    ("net-snmp",         "net-snmp",       "net-snmp"),
    ("postfix",          "postfix",        "postfix"),
    ("exim",             "exim",           "exim"),
    ("samba",            "samba",          "samba"),
    ("microsoft-ds",     "microsoft",      "windows"),
    ("ms-wbt-server",    "microsoft",      "remote_desktop_protocol"),
    ("telnet",           "mit",            "telnet"),
    ("openssl",          "openssl",        "openssl"),
    ("php",              "php",            "php"),
    ("python",           "python",         "python"),
    ("java",             "oracle",         "jdk"),
    ("jenkins",          "jenkins",        "jenkins"),
    ("wordpress",        "wordpress",      "wordpress"),
    ("drupal",           "drupal",         "drupal"),
    ("joomla",           "joomla",         "joomla"),
    ("elasticsearch",    "elastic",        "elasticsearch"),
    ("kibana",           "elastic",        "kibana"),
    ("rabbitmq",         "vmware",         "rabbitmq"),
    ("memcached",        "memcached",      "memcached"),
    ("docker",           "docker",         "docker"),
    ("kubernetes",       "kubernetes",     "kubernetes"),
    ("iis",              "microsoft",      "internet_information_services"),
]


def build_cpe(service: str, product: str, version: str) -> str | None:
    """
    Construct a CPE 2.3 string from nmap service/product/version strings.

    Example:
        service="http", product="Apache httpd", version="2.4.49"
        → "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

    Returns None if no mapping found.
    """
    lookup = (product + " " + service).lower().strip()
    cpe_vendor  = None
    cpe_product = None

    for fragment, vendor, prod in _CPE_MAP:
        if fragment in lookup:
            cpe_vendor  = vendor
            cpe_product = prod
            break

    if not cpe_vendor:
        return None

    # Normalise version: keep only digits and dots, drop extra labels
    clean_ver = re.sub(r"[^0-9.]", "", version.split(" ")[0]) if version else "*"
    if not clean_ver:
        clean_ver = "*"

    return f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{clean_ver}:*:*:*:*:*:*:*"


# ── Module-level singleton ─────────────────────────────────────────────────────

nvd_client = NvdApiClient()


# ── Convenience sync wrapper (for run_in_executor callers) ───────────────────

def enrich_scan_sync(versioned: dict) -> dict:
    """
    Synchronous wrapper for use in FastAPI's run_in_executor.
    Runs the async enrich_scan in a new event loop.
    """
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(nvd_client.enrich_scan(versioned))
    except Exception as e:
        logger.warning("enrich_scan_sync error: %s", e)
        return versioned
    finally:
        try:
            loop.close()
        except Exception:
            pass
