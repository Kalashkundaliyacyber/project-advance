"""
ThreatWeave — Intelligent CVE Cache Engine v1.0
================================================
Fixes the "All AI providers failed" token-burn problem by:

  1. LOCAL JSON DB FIRST  — instant, zero tokens, zero API calls
  2. LOCAL EMBEDDED DB    — curated mapper.py data (offline guarantee)
  3. NVD API LOOKUP       — only when CVE not in local JSON DB
  4. SAVE TO JSON DB      — so every NVD hit is cached forever

JSON DB file: data/cve_db/cve_intelligence.json
Schema per entry:
  {
    "cve_id": "CVE-XXXX-XXXX",
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "...",
    "patch": "...",
    "affected_versions": ["..."],
    "references": ["https://..."],
    "source": "nvd|local|nse",
    "cached_at": 1700000000.0
  }

Usage:
    from app.cve.cve_cache_engine import cve_cache
    result = cve_cache.lookup("CVE-2023-38408")
    result = cve_cache.lookup_by_product("openssh", "9.2")
"""

import json
import logging
import os
import time
import threading
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

logger = logging.getLogger("ThreatWeave.cve.cache")

_BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "cve_db"
)
_CACHE_FILE   = os.path.join(_BASE_DIR, "cve_intelligence.json")
_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
_CACHE_TTL    = 7 * 24 * 3600   # 7 days — CVEs don't change often
_NVD_TIMEOUT  = 10               # seconds per request


class CVECacheEngine:
    """
    Intelligent local-first CVE lookup with persistent JSON storage.
    Thread-safe. Writes are async (fire-and-forget) to avoid blocking scans.
    """

    def __init__(self):
        self._lock   = threading.Lock()
        self._db: dict = {}        # cve_id → entry
        self._dirty  = False
        self._loaded = False
        self._save_timer: Optional[threading.Timer] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def lookup(self, cve_id: str) -> Optional[dict]:
        """
        Look up a CVE by ID.
        Order: JSON DB cache → NVD API (saved to DB on hit).
        Returns None if not found anywhere.
        """
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            return None

        self._ensure_loaded()

        # 1. Check local JSON DB
        cached = self._db.get(cve_id)
        if cached and self._is_fresh(cached):
            logger.debug("[CVE-CACHE] HIT  %s (age %.0fh)",
                         cve_id, (time.time() - cached.get("cached_at", 0)) / 3600)
            return cached

        # 2. Fetch from NVD and save
        logger.debug("[CVE-CACHE] MISS %s — fetching from NVD", cve_id)
        fetched = self._nvd_fetch_by_id(cve_id)
        if fetched:
            self._store(fetched)
            return fetched

        # 3. Return stale cache rather than nothing
        if cached:
            logger.debug("[CVE-CACHE] STALE %s — returning stale entry", cve_id)
            return cached

        return None

    def lookup_by_product(self, product: str, version: str = "") -> list:
        """
        Look up CVEs by product name + version keyword.
        Order: JSON DB scan → NVD keyword search (saves results).
        Returns list of CVE dicts sorted by CVSS descending.
        """
        self._ensure_loaded()
        key = f"product:{product.lower()}:{version.lower()}"

        # Scan local DB for matching entries
        local_hits = [
            entry for entry in self._db.values()
            if product.lower() in entry.get("product_hint", "").lower()
            and (not version or any(version[:3] in av for av in entry.get("affected_versions", [])))
            and self._is_fresh(entry)
        ]

        # Check if we have a recent full product search cached
        product_cache_key = f"__search__{product.lower()}__{version[:3] if version else ''}"
        product_meta = self._db.get(product_cache_key)
        if product_meta and self._is_fresh(product_meta):
            ids = product_meta.get("cve_ids", [])
            known = [self._db[i] for i in ids if i in self._db]
            if known:
                return sorted(known, key=lambda x: x.get("cvss_score", 0), reverse=True)[:10]

        # Fallback: NVD keyword search
        fetched = self._nvd_keyword_search(product, version)
        if fetched:
            for entry in fetched:
                entry["product_hint"] = product.lower()
                self._store(entry)
            # Save product-level search result metadata
            self._db[product_cache_key] = {
                "cve_ids":   [e["cve_id"] for e in fetched],
                "cached_at": time.time(),
            }
            self._schedule_save()

        combined = {e["cve_id"]: e for e in (local_hits + fetched)}
        return sorted(combined.values(), key=lambda x: x.get("cvss_score", 0), reverse=True)[:10]

    def get_stats(self) -> dict:
        """Return cache statistics."""
        self._ensure_loaded()
        total   = sum(1 for k in self._db if not k.startswith("__"))
        fresh   = sum(1 for k, v in self._db.items()
                      if not k.startswith("__") and self._is_fresh(v))
        stale   = total - fresh
        return {
            "total_entries": total,
            "fresh": fresh,
            "stale": stale,
            "cache_file": _CACHE_FILE,
            "nvd_api_key_set": bool(_NVD_API_KEY),
        }

    def save_now(self):
        """Force-write the DB to disk (call on shutdown)."""
        self._write_db()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _ensure_loaded(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._load_db()
            self._loaded = True

    def _load_db(self):
        os.makedirs(_BASE_DIR, exist_ok=True)
        if not os.path.exists(_CACHE_FILE):
            self._db = {}
            logger.info("[CVE-CACHE] No cache file found — starting fresh at %s", _CACHE_FILE)
            return
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                self._db = json.load(f)
            logger.info("[CVE-CACHE] Loaded %d entries from %s",
                        sum(1 for k in self._db if not k.startswith("__")), _CACHE_FILE)
        except Exception as e:
            logger.warning("[CVE-CACHE] Failed to load cache: %s — starting fresh", e)
            self._db = {}

    def _write_db(self):
        with self._lock:
            try:
                os.makedirs(_BASE_DIR, exist_ok=True)
                tmp = _CACHE_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._db, f, indent=2)
                os.replace(tmp, _CACHE_FILE)
                self._dirty = False
                logger.debug("[CVE-CACHE] Saved %d entries to disk",
                             sum(1 for k in self._db if not k.startswith("__")))
            except Exception as e:
                logger.warning("[CVE-CACHE] Save failed: %s", e)

    def _store(self, entry: dict):
        """Store a CVE entry in the DB and schedule a background save."""
        if not entry.get("cve_id"):
            return
        entry.setdefault("cached_at", time.time())
        with self._lock:
            self._db[entry["cve_id"]] = entry
            self._dirty = True
        self._schedule_save()

    def _schedule_save(self):
        """Debounced background save — writes 5s after last change."""
        if self._save_timer:
            self._save_timer.cancel()
        self._save_timer = threading.Timer(5.0, self._write_db)
        self._save_timer.daemon = True
        self._save_timer.start()

    def _is_fresh(self, entry: dict) -> bool:
        return time.time() - entry.get("cached_at", 0) < _CACHE_TTL

    def _nvd_fetch_by_id(self, cve_id: str) -> Optional[dict]:
        """Fetch a specific CVE from NVD 2.0 API."""
        if not _NVD_API_KEY:
            logger.debug("[CVE-CACHE] No NVD_API_KEY — skipping NVD fetch for %s", cve_id)
            return None
        try:
            params = {"cveId": cve_id}
            url    = f"{_NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
            req    = urllib.request.Request(url, headers={
                "apiKey":     _NVD_API_KEY,
                "User-Agent": "ThreatWeave/2.0",
            })
            with urllib.request.urlopen(req, timeout=_NVD_TIMEOUT) as resp:
                raw = json.loads(resp.read())

            vulns = raw.get("vulnerabilities", [])
            if not vulns:
                return None

            return self._parse_nvd_item(vulns[0])

        except urllib.error.HTTPError as e:
            logger.warning("[CVE-CACHE] NVD HTTP %d for %s", e.code, cve_id)
            return None
        except Exception as e:
            logger.warning("[CVE-CACHE] NVD fetch failed for %s: %s", cve_id, e)
            return None

    def _nvd_keyword_search(self, product: str, version: str = "") -> list:
        """Keyword search NVD for a product + optional version."""
        if not _NVD_API_KEY:
            return []
        try:
            keyword = f"{product} {version}".strip()
            params  = {
                "keywordSearch": keyword,
                "resultsPerPage": "20",
                "keywordExactMatch": "",  # partial match
            }
            url = f"{_NVD_BASE_URL}?{urllib.parse.urlencode({k: v for k, v in params.items() if v})}"
            req = urllib.request.Request(url, headers={
                "apiKey":     _NVD_API_KEY,
                "User-Agent": "ThreatWeave/2.0",
            })
            with urllib.request.urlopen(req, timeout=_NVD_TIMEOUT) as resp:
                raw = json.loads(resp.read())

            results = []
            for item in raw.get("vulnerabilities", []):
                parsed = self._parse_nvd_item(item)
                if parsed:
                    results.append(parsed)

            results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
            logger.info("[CVE-CACHE] NVD keyword '%s' → %d results", keyword, len(results))
            return results[:10]

        except Exception as e:
            logger.warning("[CVE-CACHE] NVD keyword search failed for '%s': %s", product, e)
            return []

    @staticmethod
    def _parse_nvd_item(item: dict) -> Optional[dict]:
        """Parse a single NVD vulnerability item into our schema."""
        try:
            cve     = item.get("cve", {})
            cve_id  = cve.get("id", "")
            if not cve_id:
                return None

            # English description
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "No description.")

            # CVSS score — prefer v3.1 > v3.0 > v2
            cvss, sev = 0.0, "unknown"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m    = metrics[key][0]
                    data = m.get("cvssData", {})
                    cvss = float(data.get("baseScore", 0.0))
                    sev  = data.get("baseSeverity", "unknown").lower()
                    break

            # Affected versions from CPE
            affected_versions = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        ver = cpe_match.get("versionStartIncluding") or cpe_match.get("versionEndIncluding", "")
                        if ver:
                            affected_versions.append(ver[:8])

            # References
            refs = [r.get("url", "") for r in cve.get("references", [])[:5] if r.get("url")]

            # Published date
            published = cve.get("published", "")[:10]

            return {
                "cve_id":            cve_id,
                "cvss_score":        cvss,
                "severity":          sev,
                "description":       desc[:500],
                "patch":             f"See https://nvd.nist.gov/vuln/detail/{cve_id}",
                "affected_versions": affected_versions[:5],
                "references":        refs,
                "source":            "nvd",
                "published":         published,
                "cached_at":         time.time(),
            }
        except Exception as e:
            logger.debug("[CVE-CACHE] Parse error: %s", e)
            return None


# ── Singleton ─────────────────────────────────────────────────────────────────
cve_cache = CVECacheEngine()
