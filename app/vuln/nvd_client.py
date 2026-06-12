"""
NVD API Client v2.0  —  app/vuln/nvd_client.py
===============================================
Uses the correct NVD API v2 endpoint:
  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-4577

No API key required — unauthenticated free tier (5 req/30s).
Set NVD_ENABLED=false in .env to disable entirely (no timeout spam).
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
from typing import Any

logger = logging.getLogger("threatweave.nvd")

# ── Configuration ─────────────────────────────────────────────────────────────
NVD_BASE_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_ENABLED      = os.environ.get("NVD_ENABLED", "true").lower() == "true"
USER_AGENT       = "ThreatWeave-AI/3.0 (security scanner)"

# No API key — free unauthenticated tier: 5 req / 30s
_RATE_LIMIT      = 4       # stay safely under 5/30s
_RATE_WINDOW     = 30.0
_REQUEST_TIMEOUT = 10      # seconds — fail fast
_MAX_RETRIES     = 1       # only 1 retry — don't spam on timeout
_RETRY_DELAY     = 2.0

_CACHE_TTL_CVE_ID  = 604_800   # 7 days
_CACHE_TTL_KEYWORD = 86_400    # 24 h
_MAX_RESULTS       = 20
_MAX_CVE_PER_PORT  = 10

_DB_DIR  = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "cve_db",
)
_DB_PATH = os.path.join(_DB_DIR, "nvd_cache.db")

SEVERITY_COLORS = {
    "critical": "#ff4444", "high": "#ff8800",
    "medium":   "#ffcc00", "low":  "#4488ff",
    "none":     "#aaaaaa", "unknown": "#888888",
}

def severity_color(s: str) -> str:
    return SEVERITY_COLORS.get(s.lower(), SEVERITY_COLORS["unknown"])


# ── SQLite cache ───────────────────────────────────────────────────────────────
class _NvdCache:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db   = db_path
        self._lock = threading.Lock()
        self._init()

    def _conn(self):
        c = sqlite3.connect(self._db, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._lock:
            c = self._conn()
            c.execute("""CREATE TABLE IF NOT EXISTS nvd_cache (
                cache_key TEXT PRIMARY KEY,
                payload   TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                ttl        REAL NOT NULL
            )""")
            c.execute("DELETE FROM nvd_cache WHERE fetched_at + ttl < ?", (time.time(),))
            c.commit(); c.close()

    def get(self, key: str):
        with self._lock:
            c = self._conn()
            try:
                row = c.execute(
                    "SELECT payload,fetched_at,ttl FROM nvd_cache WHERE cache_key=?", (key,)
                ).fetchone()
                if not row: return None
                if time.time() > row["fetched_at"] + row["ttl"]:
                    c.execute("DELETE FROM nvd_cache WHERE cache_key=?", (key,))
                    c.commit(); return None
                return json.loads(row["payload"])
            except Exception: return None
            finally: c.close()

    def set(self, key: str, data, ttl: float):
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT OR REPLACE INTO nvd_cache VALUES (?,?,?,?)",
                    (key, json.dumps(data), time.time(), ttl)
                )
                c.commit()
            except Exception as exc:
                logger.warning("NVD cache write failed for key=%r: %s", key, exc)
            finally: c.close()

    def stats(self):
        with self._lock:
            c = self._conn()
            try:
                total = c.execute("SELECT COUNT(*) FROM nvd_cache").fetchone()[0]
                return {"total_entries": total}
            finally: c.close()


# ── Rate limiter ───────────────────────────────────────────────────────────────
class _RateLimiter:
    def __init__(self, limit: int, window: float):
        self._limit  = limit
        self._window = window
        self._tokens = limit
        self._last   = time.monotonic()
        self._lock   = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now    = time.monotonic()
                refill = int((now - self._last) / self._window * self._limit)
                if refill:
                    self._tokens = min(self._limit, self._tokens + refill)
                    self._last   = now
                if self._tokens > 0:
                    self._tokens -= 1
                    return
            time.sleep(self._window / self._limit)


# ── Parsers ────────────────────────────────────────────────────────────────────
def _parse_cvss(metrics: dict):
    for key, ver in [("cvssMetricV40","4.0"),("cvssMetricV31","3.1"),
                     ("cvssMetricV30","3.0"),("cvssMetricV2","2.0")]:
        entries = metrics.get(key, [])
        if entries:
            data  = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            sev   = (data.get("baseSeverity") or data.get("severity") or
                     _score_to_sev(score)).lower()
            return score, sev, ver, data.get("vectorString", "")
    return 0.0, "unknown", "N/A", ""

def _score_to_sev(s):
    if s >= 9: return "critical"
    if s >= 7: return "high"
    if s >= 4: return "medium"
    if s > 0:  return "low"
    return "none"

def _normalise(item: dict):
    try:
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id: return None
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"),
                    "No description available.")
        score, sev, ver, vec = _parse_cvss(cve.get("metrics", {}))
        cwes = [d["value"] for w in cve.get("weaknesses",[])
                for d in w.get("description",[]) if d.get("value","").startswith("CWE-")]
        refs = [{"url":r.get("url",""),"tags":r.get("tags",[])}
                for r in cve.get("references",[])[:5]]
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        patch_urls = [r["url"] for r in refs
                      if any(t in ("Patch","Vendor Advisory","Mitigation") for t in r.get("tags",[]))]
        return {
            "cve_id": cve_id, "description": desc[:400],
            "cvss_score": score, "cvss_version": ver,
            "vector": vec, "severity": sev, "color": severity_color(sev),
            "cwes": cwes[:5], "references": refs,
            "published": cve.get("published",""), "modified": cve.get("lastModified",""),
            "nvd_url": nvd_url,
            "patch": f"Apply vendor patch. See: {patch_urls[0]}" if patch_urls
                     else f"Check vendor advisory at {nvd_url}",
            "source": "nvd",
        }
    except Exception: return None


# ── HTTP client ────────────────────────────────────────────────────────────────
class NvdApiClient:
    def __init__(self):
        self._cache   = _NvdCache(_DB_PATH)
        self._limiter = _RateLimiter(_RATE_LIMIT, _RATE_WINDOW)

    def _get(self, url: str) -> dict:
        """Blocking GET with rate limit + single retry."""
        self._limiter.acquire()
        for attempt in range(_MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 404: return {}
                if e.code in (429, 503) and attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY); self._limiter.acquire(); continue
                logger.warning("NVD HTTP %s for %s", e.code, url)
                return {}
            except Exception as e:
                if attempt < _MAX_RETRIES:
                    logger.warning("NVD network error (%s), retry %d", e, attempt + 1)
                    time.sleep(_RETRY_DELAY); self._limiter.acquire(); continue
                logger.warning("NVD fetch error: %s", e)
                return {}
        return {}

    def _fetch_sync(self, url: str) -> list[dict]:
        data  = self._get(url)
        items = data.get("vulnerabilities", [])
        out   = [n for n in (_normalise(i) for i in items) if n]
        out.sort(key=lambda x: x["cvss_score"], reverse=True)
        return out[:_MAX_RESULTS]

    # ── Public async API ──────────────────────────────────────────────────────

    async def fetch_cve(self, cve_id: str):
        if not NVD_ENABLED: return None
        cve_id = cve_id.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id): return None

        key    = f"id:{cve_id}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached[0] if cached else None

        # Use the exact URL format from the docs
        url    = f"{NVD_BASE_URL}?cveId={urllib.parse.quote(cve_id)}"
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._fetch_sync, url)
        self._cache.set(key, result, _CACHE_TTL_CVE_ID)
        return result[0] if result else None

    async def search_by_keyword(self, product: str, version: str = "") -> list[dict]:
        if not NVD_ENABLED: return []
        product = product.strip()
        if not product: return []

        keyword = f"{product} {version}".strip()
        key     = f"kw:{keyword.lower()}"
        cached  = self._cache.get(key)
        if cached is not None: return cached

        params = {
            "keywordSearch":    keyword,
            "resultsPerPage":   str(_MAX_RESULTS),
        }
        url    = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._fetch_sync, url)

        # Retry with product-only if no results
        if not result and version:
            key2   = f"kw:{product.lower()}"
            cached2 = self._cache.get(key2)
            if cached2 is not None:
                result = cached2
            else:
                url2   = f"{NVD_BASE_URL}?keywordSearch={urllib.parse.quote(product)}&resultsPerPage={_MAX_RESULTS}"
                result = await loop.run_in_executor(None, self._fetch_sync, url2)
                self._cache.set(key2, result, _CACHE_TTL_KEYWORD)

        self._cache.set(key, result, _CACHE_TTL_KEYWORD)
        return result

    async def search_by_cpe(self, cpe: str) -> list[dict]:
        if not NVD_ENABLED: return []
        cpe = cpe.strip()
        if not cpe.startswith("cpe:"): return []

        key    = f"cpe:{cpe}"
        cached = self._cache.get(key)
        if cached is not None: return cached

        url    = f"{NVD_BASE_URL}?cpeName={urllib.parse.quote(cpe)}&resultsPerPage={_MAX_RESULTS}"
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._fetch_sync, url)
        self._cache.set(key, result, _CACHE_TTL_KEYWORD)
        return result

    async def enrich_scan(self, versioned: dict) -> dict:
        if not NVD_ENABLED:
            logger.info("NVD disabled — skipping enrichment")
            return versioned

        result = dict(versioned)
        tasks, ports = [], []
        for host in result.get("hosts", []):
            for port in host.get("ports", []):
                product = port.get("product", "").strip()
                version = port.get("version", "").strip()
                if product:
                    tasks.append(self._enrich_port(port, product, version))
                    ports.append(port)

        if tasks:
            enriched_lists = await asyncio.gather(*tasks, return_exceptions=True)
            for port, enriched in zip(ports, enriched_lists):
                if isinstance(enriched, Exception): continue
                if enriched:
                    existing = {c["cve_id"] for c in port.get("cves", [])}
                    for cve in enriched:
                        if cve["cve_id"] not in existing:
                            port.setdefault("cves", []).append(cve)
                    port["cves"].sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
                    port["cves"] = port["cves"][:_MAX_CVE_PER_PORT]

        return result

    async def _enrich_port(self, port: dict, product: str, version: str) -> list[dict]:
        cpe = build_cpe(port.get("service", ""), product, version)
        if cpe:
            cves = await self.search_by_cpe(cpe)
            if cves: return cves
        return await self.search_by_keyword(product, version)

    def status(self) -> dict:
        return {
            "enabled":      NVD_ENABLED,
            "base_url":     NVD_BASE_URL,
            "rate_limit":   f"{_RATE_LIMIT} req / {int(_RATE_WINDOW)}s",
            "cache_stats":  self._cache.stats(),
        }


# ── CPE builder ────────────────────────────────────────────────────────────────
_CPE_MAP = [
    ("apache tomcat","apache","tomcat"), ("openssh","openbsd","openssh"),
    ("apache httpd","apache","http_server"), ("apache","apache","http_server"),
    ("nginx","nginx","nginx"), ("vsftpd","vsftpd_project","vsftpd"),
    ("proftpd","proftpd","proftpd"), ("mysql","oracle","mysql"),
    ("mariadb","mariadb","mariadb"), ("postgresql","postgresql","postgresql"),
    ("mongodb","mongodb","mongodb"), ("redis","redislabs","redis"),
    ("isc bind","isc","bind"), ("net-snmp","net-snmp","net-snmp"),
    ("postfix","postfix","postfix"), ("exim","exim","exim"),
    ("samba","samba","samba"), ("php","php","php"),
    ("jenkins","jenkins","jenkins"), ("wordpress","wordpress","wordpress"),
    ("elasticsearch","elastic","elasticsearch"), ("kibana","elastic","kibana"),
    ("openssl","openssl","openssl"), ("iis","microsoft","internet_information_services"),
]

def build_cpe(service: str, product: str, version: str):
    lookup = (product + " " + service).lower()
    for frag, vendor, prod in _CPE_MAP:
        if frag in lookup:
            ver = re.sub(r"[^0-9.]", "", version.split(" ")[0]) if version else "*"
            return f"cpe:2.3:a:{vendor}:{prod}:{ver or '*'}:*:*:*:*:*:*:*"
    return None


# ── Singletons ─────────────────────────────────────────────────────────────────
nvd_client = NvdApiClient()

def enrich_scan_sync(versioned: dict) -> dict:
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(nvd_client.enrich_scan(versioned))
    except Exception as e:
        logger.warning("enrich_scan_sync error: %s", e)
        return versioned
    finally:
        try: loop.close()
        except Exception as exc:
            logger.debug("enrich_scan_sync: loop.close() failed: %s", exc)
