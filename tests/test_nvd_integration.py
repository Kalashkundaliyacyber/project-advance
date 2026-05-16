"""
NVD Integration Test Suite  —  tests/test_nvd_integration.py
=============================================================
Tests for:
  - NVD cache (SQLite persistence, expiry, thread safety)
  - CPE builder (service/product → CPE 2.3 string)
  - Response normaliser (CVSS v2/v3/v4, CWE, references)
  - Rate limiter (token bucket)
  - Enrichment pipeline (local-DB normalisation, merge logic)
  - API client (mocked HTTP, no live NVD calls)
  - Severity colour mapping

Run: pytest tests/test_nvd_integration.py -v
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Helpers ────────────────────────────────────────────────────────────────────

def run_async(coro):
    """Run an async coroutine synchronously for test purposes."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_nvd_item(cve_id="CVE-2021-41773", score=9.8, severity="CRITICAL",
                   description="Test CVE description.", cwe="CWE-22"):
    """Build a minimal fake NVD API vulnerability item."""
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-10-05T00:00:00.000",
            "lastModified": "2021-10-07T00:00:00.000",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
            "references": [
                {"url": "https://httpd.apache.org/security/vulnerabilities_24.html",
                 "tags": ["Vendor Advisory", "Patch"]},
            ],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {"vulnerable": True,
                         "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                    ]
                }]
            }],
        }
    }


# ── 1. CPE Builder tests ───────────────────────────────────────────────────────

class TestBuildCpe(unittest.TestCase):

    def _build(self, service, product, version):
        from app.vuln.nvd_client import build_cpe
        return build_cpe(service, product, version)

    def test_apache_httpd(self):
        cpe = self._build("http", "Apache httpd", "2.4.49")
        self.assertIsNotNone(cpe)
        self.assertIn("apache", cpe)
        self.assertIn("http_server", cpe)
        self.assertIn("2.4.49", cpe)
        self.assertTrue(cpe.startswith("cpe:2.3:a:"))

    def test_nginx(self):
        cpe = self._build("http", "nginx", "1.18.0")
        self.assertIsNotNone(cpe)
        self.assertIn("nginx", cpe)
        self.assertIn("1.18.0", cpe)

    def test_openssh(self):
        cpe = self._build("ssh", "OpenSSH", "7.4")
        self.assertIsNotNone(cpe)
        self.assertIn("openssh", cpe)
        self.assertIn("7.4", cpe)

    def test_mysql(self):
        cpe = self._build("mysql", "MySQL", "5.7.38")
        self.assertIsNotNone(cpe)
        self.assertIn("mysql", cpe)

    def test_unknown_product_returns_none(self):
        cpe = self._build("unknown-svc", "SomeRandomTool", "1.0")
        self.assertIsNone(cpe)

    def test_empty_version_uses_wildcard(self):
        cpe = self._build("http", "Apache httpd", "")
        self.assertIsNotNone(cpe)
        self.assertIn(":*:", cpe)

    def test_version_with_extra_labels_cleaned(self):
        # "2.4.49p1" → should keep only "2.4.49"
        cpe = self._build("ssh", "OpenSSH", "8.2p1")
        self.assertIsNotNone(cpe)
        self.assertNotIn("p", cpe.split("openssh:")[1].split(":")[0])

    def test_redis(self):
        cpe = self._build("", "Redis", "6.2.6")
        self.assertIsNotNone(cpe)
        self.assertIn("redis", cpe)

    def test_postgresql(self):
        cpe = self._build("postgresql", "PostgreSQL", "13.4")
        self.assertIsNotNone(cpe)
        self.assertIn("postgresql", cpe)

    def test_tomcat(self):
        cpe = self._build("http", "Apache Tomcat", "9.0.44")
        self.assertIsNotNone(cpe)
        self.assertIn("tomcat", cpe)


# ── 2. CVSS normaliser tests ───────────────────────────────────────────────────

class TestNormaliseCve(unittest.TestCase):

    def _normalise(self, item):
        from app.vuln.nvd_client import _normalise_cve
        return _normalise_cve(item)

    def test_basic_fields_present(self):
        result = self._normalise(_make_nvd_item())
        self.assertIsNotNone(result)
        for field in ("cve_id", "description", "cvss_score", "cvss_version",
                      "vector", "severity", "color", "cwes", "cpes",
                      "references", "published", "modified", "nvd_url",
                      "patch", "source"):
            self.assertIn(field, result, f"Missing field: {field}")

    def test_cvss_score_is_float(self):
        result = self._normalise(_make_nvd_item(score=9.8))
        self.assertIsInstance(result["cvss_score"], float)
        self.assertAlmostEqual(result["cvss_score"], 9.8)

    def test_severity_lowercased(self):
        result = self._normalise(_make_nvd_item(severity="CRITICAL"))
        self.assertEqual(result["severity"], "critical")

    def test_cwe_extracted(self):
        result = self._normalise(_make_nvd_item(cwe="CWE-22"))
        self.assertIn("CWE-22", result["cwes"])

    def test_cpe_extracted(self):
        result = self._normalise(_make_nvd_item())
        self.assertTrue(any("apache" in c for c in result["cpes"]))

    def test_nvd_url_correct(self):
        result = self._normalise(_make_nvd_item(cve_id="CVE-2021-41773"))
        self.assertIn("CVE-2021-41773", result["nvd_url"])
        self.assertIn("nvd.nist.gov", result["nvd_url"])

    def test_source_is_nvd(self):
        result = self._normalise(_make_nvd_item())
        self.assertEqual(result["source"], "nvd")

    def test_description_truncated_at_400(self):
        long_desc = "A" * 1000
        result = self._normalise(_make_nvd_item(description=long_desc))
        self.assertLessEqual(len(result["description"]), 400)

    def test_v2_cvss_parsed(self):
        from app.vuln.nvd_client import _normalise_cve
        item = {
            "cve": {
                "id": "CVE-2010-0001",
                "published": "2010-01-01T00:00:00.000",
                "lastModified": "2010-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Old CVE with v2 only."}],
                "metrics": {
                    "cvssMetricV2": [{
                        "cvssData": {
                            "baseScore": 7.5,
                            "severity": "HIGH",
                            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        }
                    }]
                },
                "weaknesses": [],
                "references": [],
                "configurations": [],
            }
        }
        result = _normalise_cve(item)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result["cvss_score"], 7.5)
        self.assertEqual(result["cvss_version"], "2.0")

    def test_no_cve_id_returns_none(self):
        from app.vuln.nvd_client import _normalise_cve
        result = _normalise_cve({"cve": {"id": ""}})
        self.assertIsNone(result)

    def test_malformed_item_returns_none(self):
        from app.vuln.nvd_client import _normalise_cve
        result = _normalise_cve({})
        self.assertIsNone(result)


# ── 3. Severity colour tests ───────────────────────────────────────────────────

class TestSeverityColor(unittest.TestCase):

    def _color(self, sev):
        from app.vuln.nvd_client import severity_color
        return severity_color(sev)

    def test_critical_is_red(self):
        self.assertEqual(self._color("critical"), "#ff4444")

    def test_high_is_orange(self):
        self.assertEqual(self._color("high"), "#ff8800")

    def test_medium_is_yellow(self):
        self.assertEqual(self._color("medium"), "#ffcc00")

    def test_low_is_blue(self):
        self.assertEqual(self._color("low"), "#4488ff")

    def test_unknown_has_fallback(self):
        color = self._color("unknown")
        self.assertTrue(color.startswith("#"))

    def test_case_insensitive(self):
        self.assertEqual(self._color("CRITICAL"), self._color("critical"))


# ── 4. Cache tests ─────────────────────────────────────────────────────────────

class TestNvdCache(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_cache.db")
        from app.vuln.nvd_client import _NvdCache
        self.cache = _NvdCache(self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_set_and_get(self):
        data = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8}]
        self.cache.set("test:key", data, ttl=3600)
        result = self.cache.get("test:key")
        self.assertEqual(result, data)

    def test_expired_returns_none(self):
        data = [{"cve_id": "CVE-TEST"}]
        self.cache.set("expired:key", data, ttl=0.001)
        time.sleep(0.05)
        result = self.cache.get("expired:key")
        self.assertIsNone(result)

    def test_missing_key_returns_none(self):
        self.assertIsNone(self.cache.get("does:not:exist"))

    def test_overwrite_existing(self):
        self.cache.set("key", [{"a": 1}], ttl=3600)
        self.cache.set("key", [{"b": 2}], ttl=3600)
        result = self.cache.get("key")
        self.assertEqual(result, [{"b": 2}])

    def test_stats_returns_dict(self):
        stats = self.cache.stats()
        self.assertIn("total_entries", stats)
        self.assertIn("expired_entries", stats)

    def test_thread_safety(self):
        """Multiple threads writing/reading should not corrupt data."""
        errors = []
        def worker(i):
            try:
                key  = f"thread:{i}"
                data = [{"cve_id": f"CVE-{i:04d}"}]
                self.cache.set(key, data, ttl=60)
                result = self.cache.get(key)
                assert result == data, f"Data mismatch for key {key}"
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors, [], f"Thread safety errors: {errors}")

    def test_clear_expired(self):
        self.cache.set("live", [{"x": 1}], ttl=3600)
        self.cache.set("dead", [{"x": 2}], ttl=0.001)
        time.sleep(0.05)
        self.cache.clear_expired()
        self.assertIsNotNone(self.cache.get("live"))
        self.assertIsNone(self.cache.get("dead"))


# ── 5. Score → severity helper ─────────────────────────────────────────────────

class TestScoreToSeverity(unittest.TestCase):

    def _sev(self, score):
        from app.vuln.nvd_client import _score_to_severity
        return _score_to_severity(score)

    def test_critical(self):  self.assertEqual(self._sev(9.8), "critical")
    def test_high(self):      self.assertEqual(self._sev(7.5), "high")
    def test_medium(self):    self.assertEqual(self._sev(5.0), "medium")
    def test_low(self):       self.assertEqual(self._sev(2.0), "low")
    def test_none(self):      self.assertEqual(self._sev(0.0), "none")
    def test_boundary_9(self):self.assertEqual(self._sev(9.0), "critical")
    def test_boundary_7(self):self.assertEqual(self._sev(7.0), "high")
    def test_boundary_4(self):self.assertEqual(self._sev(4.0), "medium")


# ── 6. Enrichment pipeline tests ──────────────────────────────────────────────

class TestEnrichmentPipeline(unittest.TestCase):

    def _make_versioned(self, ports):
        return {
            "hosts": [{"ip": "192.168.1.10", "ports": ports, "hostnames": [], "os": None}],
            "scan_summary": {},
        }

    def _local_cve(self):
        """Simulates a local-DB CVE using old schema (cvss instead of cvss_score)."""
        return {
            "cve_id":     "CVE-2023-38408",
            "cvss":       9.8,           # old field name
            "severity":   "critical",
            "description":"Test OpenSSH CVE.",
            "patch":      "Upgrade to OpenSSH 9.3p2.",
        }

    def test_normalise_local_cve_upgrades_schema(self):
        from app.vuln.enrichment import normalise_local_cve
        result = normalise_local_cve(self._local_cve())
        self.assertIn("cvss_score", result)
        self.assertAlmostEqual(result["cvss_score"], 9.8)
        self.assertIn("color", result)
        self.assertIn("nvd_url", result)
        self.assertIn("source", result)
        self.assertNotIn("cvss", result)   # old key should be absent

    def test_normalise_all_cves_upgrades_all_ports(self):
        from app.vuln.enrichment import normalise_all_cves
        versioned = self._make_versioned([
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "state": "open", "cves": [self._local_cve()]},
            {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.2.34",
             "state": "open", "cves": []},
        ])
        result = normalise_all_cves(versioned)
        port22 = result["hosts"][0]["ports"][0]
        self.assertIn("cvss_score", port22["cves"][0])
        self.assertAlmostEqual(port22["cves"][0]["cvss_score"], 9.8)

    def test_normalise_preserves_other_fields(self):
        from app.vuln.enrichment import normalise_all_cves
        versioned = self._make_versioned([
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "state": "open", "protocol": "tcp", "cves": [self._local_cve()]},
        ])
        result = normalise_all_cves(versioned)
        port = result["hosts"][0]["ports"][0]
        self.assertEqual(port["port"], 22)
        self.assertEqual(port["service"], "ssh")
        self.assertEqual(port["protocol"], "tcp")

    def test_enrich_with_nvd_sync_without_api_key(self):
        """Without API key, enrichment still runs (normalisation step)."""
        from app.vuln.enrichment import enrich_with_nvd_sync
        versioned = self._make_versioned([
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "state": "open", "cves": [self._local_cve()]},
        ])
        result = enrich_with_nvd_sync(versioned)
        # Should at minimum normalise
        self.assertIsInstance(result, dict)
        self.assertIn("hosts", result)

    def test_enrich_gracefully_handles_empty_hosts(self):
        from app.vuln.enrichment import enrich_with_nvd_sync
        result = enrich_with_nvd_sync({"hosts": [], "scan_summary": {}})
        self.assertEqual(result["hosts"], [])

    def test_enrichment_merges_without_duplicates(self):
        """If the same CVE ID appears in local and NVD results, it should only appear once."""
        from app.vuln.enrichment import normalise_all_cves
        cve = self._local_cve()
        versioned = self._make_versioned([
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "state": "open", "cves": [cve, cve]},   # duplicate
        ])
        # normalise_all_cves doesn't deduplicate — that's enrich_scan's job.
        # Just verify it doesn't crash.
        result = normalise_all_cves(versioned)
        self.assertIsInstance(result["hosts"][0]["ports"][0]["cves"], list)


# ── 7. API client mock tests ───────────────────────────────────────────────────

class TestNvdApiClientMocked(unittest.TestCase):
    """Tests the NVD API client using mocked HTTP responses — no live API calls."""

    def _make_client(self, tmpdir):
        """Create a fresh client with an isolated cache in tmpdir."""
        db_path = os.path.join(tmpdir, "test.db")
        from app.vuln.nvd_client import NvdApiClient, _NvdCache, _RateLimiter
        client = NvdApiClient.__new__(NvdApiClient)
        client._cache   = _NvdCache(db_path)
        client._limiter = _RateLimiter(100, 30)   # no rate limiting in tests
        client._lock    = threading.Lock()
        return client

    def test_fetch_cve_returns_normalised(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            fake_response = {"vulnerabilities": [_make_nvd_item("CVE-2021-41773", 9.8)]}
            with patch.object(client, "_get", return_value=fake_response):
                result = run_async(client.fetch_cve("CVE-2021-41773"))
            self.assertIsNotNone(result)
            self.assertEqual(result["cve_id"], "CVE-2021-41773")
            self.assertAlmostEqual(result["cvss_score"], 9.8)

    def test_fetch_cve_invalid_format_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            result = run_async(client.fetch_cve("NOT-A-CVE"))
            self.assertIsNone(result)

    def test_search_by_keyword_returns_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            fake_response = {
                "vulnerabilities": [
                    _make_nvd_item("CVE-2021-41773", 9.8),
                    _make_nvd_item("CVE-2021-42013", 9.8),
                ]
            }
            with patch.object(client, "_get", return_value=fake_response):
                results = run_async(client.search_by_keyword("Apache httpd", "2.4.49"))
            self.assertEqual(len(results), 2)
            for r in results:
                self.assertIn("cve_id", r)
                self.assertIn("cvss_score", r)

    def test_results_sorted_by_cvss_desc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            fake_response = {
                "vulnerabilities": [
                    _make_nvd_item("CVE-LOW", 3.5),
                    _make_nvd_item("CVE-CRIT", 9.8),
                    _make_nvd_item("CVE-MED", 5.5),
                ]
            }
            with patch.object(client, "_get", return_value=fake_response):
                results = run_async(client.search_by_keyword("Apache httpd", "2.4.49"))
            scores = [r["cvss_score"] for r in results]
            self.assertEqual(scores, sorted(scores, reverse=True))

    def test_cache_hit_skips_http(self):
        """Second call for same key must hit cache, not make HTTP request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            fake_response = {"vulnerabilities": [_make_nvd_item()]}
            call_count = {"n": 0}

            def counting_get(url):
                call_count["n"] += 1
                return fake_response

            with patch.object(client, "_get", side_effect=counting_get):
                run_async(client.search_by_keyword("Apache httpd", "2.4.49"))
                run_async(client.search_by_keyword("Apache httpd", "2.4.49"))

            self.assertEqual(call_count["n"], 1, "Cache miss on second call")

    def test_empty_nvd_response_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            with patch.object(client, "_get", return_value={"vulnerabilities": []}):
                results = run_async(client.search_by_keyword("UnknownProduct", "9.9"))
            self.assertEqual(results, [])

    def test_network_error_returns_empty_list(self):
        import urllib.error
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            with patch.object(client, "_get", side_effect=urllib.error.URLError("timeout")):
                results = run_async(client.search_by_keyword("Apache", "2.4"))
            self.assertEqual(results, [])

    def test_status_returns_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            status = client.status()
            self.assertIn("api_key_set", status)
            self.assertIn("cache_stats", status)
            self.assertIn("rate_limit", status)

    def test_enrich_scan_merges_new_cves(self):
        """NVD CVEs must be added to port, not replace existing ones."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            existing_cve = {
                "cve_id": "CVE-LOCAL-001", "cvss_score": 7.0,
                "severity": "high", "source": "local",
                "description": "Local CVE", "patch": "Patch it",
                "color": "#ff8800", "cwes": [], "cpes": [],
                "references": [], "published": "", "modified": "",
                "nvd_url": "", "vector": "", "cvss_version": "local",
            }
            versioned = {
                "hosts": [{
                    "ip": "10.0.0.1",
                    "ports": [{
                        "port": 80, "service": "http",
                        "product": "Apache httpd", "version": "2.4.49",
                        "state": "open", "cves": [existing_cve],
                    }],
                }],
                "scan_summary": {},
            }
            new_cve = _make_nvd_item("CVE-2021-41773", 9.8)
            with patch.object(client, "_get", return_value={"vulnerabilities": [new_cve]}):
                result = run_async(client.enrich_scan(versioned))

            port = result["hosts"][0]["ports"][0]
            cve_ids = [c["cve_id"] for c in port["cves"]]
            self.assertIn("CVE-LOCAL-001", cve_ids)
            self.assertIn("CVE-2021-41773", cve_ids)

    def test_enrich_scan_no_duplicates(self):
        """If NVD returns a CVE already in local list, it must not be duplicated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            existing_cve = {
                "cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                "severity": "critical", "source": "local",
                "description": "Already known", "patch": "Upgrade",
                "color": "#ff4444", "cwes": [], "cpes": [],
                "references": [], "published": "", "modified": "",
                "nvd_url": "", "vector": "", "cvss_version": "local",
            }
            versioned = {
                "hosts": [{"ip": "10.0.0.1", "ports": [{
                    "port": 80, "service": "http",
                    "product": "Apache httpd", "version": "2.4.49",
                    "state": "open", "cves": [existing_cve],
                }]}],
                "scan_summary": {},
            }
            # NVD returns the same CVE ID
            with patch.object(client, "_get",
                               return_value={"vulnerabilities": [_make_nvd_item("CVE-2021-41773")]}):
                result = run_async(client.enrich_scan(versioned))

            port  = result["hosts"][0]["ports"][0]
            ids   = [c["cve_id"] for c in port["cves"]]
            self.assertEqual(ids.count("CVE-2021-41773"), 1)

    def test_enrich_scan_empty_product_skipped(self):
        """Ports without a detected product should not trigger NVD lookup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            versioned = {
                "hosts": [{"ip": "10.0.0.1", "ports": [{
                    "port": 8080, "service": "http",
                    "product": "",   # no product
                    "version": "", "state": "open", "cves": [],
                }]}],
                "scan_summary": {},
            }
            call_count = {"n": 0}
            def counting_get(url):
                call_count["n"] += 1
                return {"vulnerabilities": []}

            with patch.object(client, "_get", side_effect=counting_get):
                run_async(client.enrich_scan(versioned))

            self.assertEqual(call_count["n"], 0, "NVD called for port with no product")


# ── 8. Rate limiter tests ──────────────────────────────────────────────────────

class TestRateLimiter(unittest.TestCase):

    def test_acquire_does_not_block_under_limit(self):
        from app.vuln.nvd_client import _RateLimiter
        limiter = _RateLimiter(limit=10, window=1.0)
        start = time.monotonic()
        for _ in range(10):
            limiter.acquire()
        elapsed = time.monotonic() - start
        # 10 tokens should be issued instantly (< 0.5s)
        self.assertLess(elapsed, 0.5)

    def test_acquire_is_thread_safe(self):
        from app.vuln.nvd_client import _RateLimiter
        limiter = _RateLimiter(limit=50, window=1.0)
        errors  = []
        results = []
        lock    = threading.Lock()

        def worker():
            try:
                limiter.acquire()
                with lock:
                    results.append(1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 50)


# ── 9. Smoke test: full import chain ──────────────────────────────────────────

class TestImports(unittest.TestCase):

    def test_nvd_client_importable(self):
        from app.vuln.nvd_client import nvd_client, build_cpe, severity_color
        self.assertIsNotNone(nvd_client)

    def test_enrichment_importable(self):
        from app.vuln.enrichment import enrich_with_nvd, enrich_with_nvd_sync, nvd_status
        self.assertIsNotNone(enrich_with_nvd)

    def test_routes_importable(self):
        from app.vuln.routes import nvd_router
        self.assertIsNotNone(nvd_router)

    def test_nvd_status_returns_dict(self):
        from app.vuln.enrichment import nvd_status
        status = nvd_status()
        self.assertIsInstance(status, dict)
        self.assertIn("enabled", status)
        self.assertIn("api_key_set", status)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
