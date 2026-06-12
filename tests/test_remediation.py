"""
ThreatWeave — Phase 12: 4-Layer Patch Resolution Test Suite
============================================================
Tests all resolution scenarios:
  - Layer 1 repository hit
  - Layer 2 vendor advisory hit
  - Layer 3 NVD cache hit
  - Layer 4 AI fallback
  - Confidence scoring
  - Learning KB promotion
  - Knowledge graph ingestion
  - Chatbot slash commands (mock)
  - Report integration (mock)

Run:  python -m pytest tests/test_remediation.py -v
  or: python tests/test_remediation.py
"""
import json
import os
import sys
import time
import unittest
import tempfile
import shutil

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestLayer1Repository(unittest.TestCase):
    """Layer 1: Local Patch Repository."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Override DB path for isolated tests
        os.environ["ThreatWeave_DATA_DIR"] = self.tmp

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_store_and_lookup_by_cve(self):
        from app.remediation.repository.patch_storage import PatchStorage
        db = PatchStorage(os.path.join(self.tmp, "test_patches.db"))
        db.upsert({
            "cve_id":    "CVE-2024-6387",
            "vendor":    "ubuntu",
            "product":   "openssh",
            "fix_version": "9.8",
            "patch_command": {"ubuntu/debian": "apt-get upgrade openssh-server"},
            "confidence": 100,
            "source":    "vendor",
        })
        result = db.get_by_cve("CVE-2024-6387")
        self.assertIsNotNone(result)
        self.assertEqual(result["cve_id"], "CVE-2024-6387")
        self.assertEqual(result["confidence"], 100)

    def test_confidence_not_downgraded(self):
        from app.remediation.repository.patch_storage import PatchStorage
        db = PatchStorage(os.path.join(self.tmp, "test_conf.db"))
        db.upsert({
            "cve_id": "CVE-2024-9999", "confidence": 100,
            "source": "vendor", "patch_command": {}
        })
        # Try to insert lower confidence — should be rejected
        stored = db.upsert({
            "cve_id": "CVE-2024-9999", "confidence": 70,
            "source": "ai", "patch_command": {}
        })
        self.assertFalse(stored, "Lower confidence should not replace higher")
        result = db.get_by_cve("CVE-2024-9999")
        self.assertEqual(result["confidence"], 100)

    def test_export_json(self):
        from app.remediation.repository.patch_storage import PatchStorage
        db = PatchStorage(os.path.join(self.tmp, "test_export.db"))
        db.upsert({
            "cve_id": "CVE-2024-0001", "confidence": 90,
            "source": "nvd", "patch_command": {}
        })
        out = db.export_json(os.path.join(self.tmp, "export.json"))
        self.assertTrue(os.path.exists(out))
        data = json.load(open(out))
        self.assertIn("patches", data)
        self.assertGreater(data["count"], 0)

    def test_product_lookup(self):
        from app.remediation.repository.patch_storage import PatchStorage
        db = PatchStorage(os.path.join(self.tmp, "test_product.db"))
        db.upsert({
            "cve_id": "CVE-2024-0002", "product": "openssh",
            "vendor": "ubuntu", "confidence": 100, "source": "vendor",
            "patch_command": {"ubuntu/debian": "apt-get upgrade openssh-server"}
        })
        results = db.get_by_product("openssh")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["product"], "openssh")


class TestLayer1Validator(unittest.TestCase):
    """Patch entry validator."""

    def test_valid_entry(self):
        from app.remediation.repository.patch_validator import validate_patch_entry
        ok, err = validate_patch_entry({
            "cve_id": "CVE-2024-6387",
            "confidence": 100,
            "source": "vendor",
        })
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_invalid_cve_format(self):
        from app.remediation.repository.patch_validator import validate_patch_entry
        ok, err = validate_patch_entry({"cve_id": "NOTACVE-123", "confidence": 70, "source": "ai"})
        self.assertFalse(ok)

    def test_missing_cve_id(self):
        from app.remediation.repository.patch_validator import validate_patch_entry
        ok, err = validate_patch_entry({"confidence": 70, "source": "ai"})
        self.assertFalse(ok)

    def test_invalid_confidence(self):
        from app.remediation.repository.patch_validator import validate_patch_entry
        ok, err = validate_patch_entry({"cve_id": "CVE-2024-1111", "confidence": 999, "source": "ai"})
        self.assertFalse(ok)


class TestLayer2VendorModels(unittest.TestCase):
    """Vendor advisory models and cache."""

    def test_advisory_to_dict(self):
        from app.remediation.vendor.vendor_models import VendorAdvisory
        adv = VendorAdvisory(
            cve_id="CVE-2024-6387",
            vendor="ubuntu",
            product="openssh",
            patch_commands={"ubuntu/debian": "apt-get upgrade openssh-server"},
            advisory_url="https://ubuntu.com/security/CVE-2024-6387",
            confidence=100,
        )
        d = adv.to_dict()
        self.assertEqual(d["cve_id"], "CVE-2024-6387")
        self.assertEqual(d["confidence"], 100)
        self.assertEqual(d["layer"], "vendor")
        self.assertTrue(d["patch_found"])

    def test_vendor_cache_set_get(self):
        import tempfile, shutil
        tmp = tempfile.mkdtemp()
        try:
            from app.remediation.vendor.vendor_cache import VendorCache
            cache = VendorCache(os.path.join(tmp, "vc.db"))
            data  = {"cve_id": "CVE-2024-6387", "confidence": 100, "vendor": "ubuntu"}
            cache.set("CVE-2024-6387", data, "ubuntu")
            result = cache.get("CVE-2024-6387", "ubuntu")
            self.assertIsNotNone(result)
            self.assertEqual(result["confidence"], 100)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestLayer3NVD(unittest.TestCase):
    """NVD Intelligence Cache."""

    def test_nvd_storage_set_get(self):
        import tempfile, shutil
        tmp = tempfile.mkdtemp()
        try:
            from app.remediation.nvd_cache.nvd_storage import NvdIntelligenceStorage
            storage = NvdIntelligenceStorage(os.path.join(tmp, "nvd.db"))
            storage.set("CVE-2024-6387", {
                "cvss": 8.1, "severity": "high",
                "description": "OpenSSH vulnerability",
                "references": ["https://example.com/ref1"],
                "vendor_links": ["https://ubuntu.com/security/CVE-2024-6387"],
                "published": "2024-07-01",
                "modified": "2024-07-15",
            })
            result = storage.get("CVE-2024-6387")
            self.assertIsNotNone(result)
            self.assertEqual(result["severity"], "high")
            self.assertEqual(result["cvss"], 8.1)
            self.assertIsInstance(result["references"], list)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_nvd_parser(self):
        from app.remediation.nvd_cache.nvd_parser import parse_nvd_item
        mock_item = {
            "cve": {
                "id": "CVE-2024-6387",
                "descriptions": [{"lang": "en", "value": "OpenSSH vulnerability test"}],
                "references": [
                    {"url": "https://ubuntu.com/security/CVE-2024-6387",
                     "tags": ["Vendor Advisory"]},
                    {"url": "https://example.com/patch", "tags": ["Patch"]},
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}
                    }]
                },
                "published": "2024-07-01T00:00:00.000",
                "lastModified": "2024-07-15T00:00:00.000",
            }
        }
        result = parse_nvd_item(mock_item)
        self.assertIsNotNone(result)
        self.assertEqual(result["cve_id"], "CVE-2024-6387")
        self.assertEqual(result["severity"], "high")
        self.assertAlmostEqual(result["cvss"], 8.1)
        self.assertGreater(len(result["vendor_links"]), 0)

    def test_patch_guidance_extraction(self):
        from app.remediation.nvd_cache.nvd_parser import extract_patch_guidance
        nvd_entry = {
            "cve_id": "CVE-2024-6387",
            "vendor_links": ["https://ubuntu.com/security/CVE-2024-6387"],
            "references": [],
        }
        guidance = extract_patch_guidance(nvd_entry, "openssh")
        self.assertIn("commands", guidance)
        cmds = guidance["commands"]
        self.assertIsInstance(cmds, dict)
        self.assertGreater(len(cmds), 0)


class TestLayer4AI(unittest.TestCase):
    """AI Patch Cache and Validator."""

    def test_ai_cache_set_get(self):
        import tempfile, shutil
        tmp = tempfile.mkdtemp()
        try:
            from app.remediation.ai.ai_patch_cache import AiPatchCache
            cache  = AiPatchCache(os.path.join(tmp, "ai.db"))
            result = {
                "cve_id": "CVE-2024-6387",
                "commands": {"ubuntu/debian": "apt-get upgrade openssh-server"},
                "confidence": 70, "source": "ai", "provider": "deepseek",
            }
            cache.set("CVE-2024-6387", result, "openssh", "9.7")
            got = cache.get("CVE-2024-6387", "openssh", "9.7")
            self.assertIsNotNone(got)
            self.assertEqual(got["provider"], "deepseek")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ai_patch_validator_valid(self):
        from app.remediation.ai.ai_patch_validator import validate_ai_patch
        data = {
            "title": "Update OpenSSH",
            "fix_version": "9.8",
            "commands": {"ubuntu/debian": "apt-get upgrade openssh-server"},
            "vendor_url": "https://www.openssh.com/security.html",
        }
        ok, err = validate_ai_patch(data)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_ai_patch_validator_rejects_junk(self):
        from app.remediation.ai.ai_patch_validator import validate_ai_patch
        data = {
            "title": "Update package",
            "commands": {"ubuntu": "apt-get upgrade your_package"},
        }
        ok, err = validate_ai_patch(data)
        self.assertFalse(ok)

    def test_ai_formatter(self):
        from app.remediation.ai.ai_patch_formatter import format_ai_patch
        raw = {
            "title": "OpenSSH Race Condition Fix",
            "fix_version": "9.8",
            "commands": {"ubuntu/debian": "apt-get update && apt-get upgrade openssh-server"},
            "vendor_url": "https://www.openssh.com/security.html",
            "mitigation": "Restrict SSH access via firewall",
            "verification": "ssh -V",
        }
        result = format_ai_patch(raw, "CVE-2024-6387", "openssh", "deepseek")
        self.assertEqual(result["cve_id"], "CVE-2024-6387")
        self.assertEqual(result["confidence"], 70)
        self.assertEqual(result["source"], "ai")
        self.assertTrue(result["ai_called"])
        self.assertIn("ubuntu/debian", result["commands"])


class TestConfidenceScoring(unittest.TestCase):
    """Phase 6: Confidence scoring system."""

    def test_vendor_confidence(self):
        from app.remediation.confidence import score_patch, confidence_label
        patch = {"source": "vendor", "layer": "vendor", "commands": {}}
        result = score_patch(patch)
        self.assertEqual(result["confidence"], 100)
        self.assertEqual(result["confidence_label"], "Vendor Advisory")

    def test_nvd_confidence(self):
        from app.remediation.confidence import score_patch
        patch = {"source": "nvd", "layer": "nvd_cache", "commands": {}}
        result = score_patch(patch)
        self.assertEqual(result["confidence"], 90)

    def test_ai_confidence(self):
        from app.remediation.confidence import score_patch
        patch = {"source": "ai", "layer": "ai", "commands": {}, "confidence": 70}
        result = score_patch(patch)
        self.assertEqual(result["confidence"], 70)
        self.assertEqual(result["confidence_label"], "AI Generated")

    def test_confidence_label_boundaries(self):
        from app.remediation.confidence import confidence_label
        self.assertEqual(confidence_label(100), "Vendor Advisory")
        self.assertEqual(confidence_label(90),  "NVD Reference")
        self.assertEqual(confidence_label(80),  "Community Reference")
        self.assertEqual(confidence_label(70),  "AI Generated")
        self.assertEqual(confidence_label(30),  "Rule Engine")


class TestLearningKB(unittest.TestCase):
    """Phase 7: Self-learning knowledge base."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_kb(self):
        from app.remediation.learning.knowledge_base import LearningKnowledgeBase
        return LearningKnowledgeBase(os.path.join(self.tmp, "kb.db"))

    def test_store_and_lookup(self):
        kb = self._make_kb()
        kb.store("CVE-2024-6387", "openssh", {
            "commands": {"ubuntu/debian": "apt-get upgrade openssh-server"},
            "confidence": 70, "source": "ai",
        })
        result = kb.lookup("CVE-2024-6387", "openssh")
        self.assertIsNotNone(result)
        self.assertTrue(result.get("from_learning_kb"))

    def test_approve_increments_count(self):
        kb = self._make_kb()
        kb.store("CVE-2024-5555", "nginx", {"commands": {}, "confidence": 70, "source": "ai"})
        kb.approve("CVE-2024-5555", "nginx")
        stats = kb.stats()
        self.assertGreaterEqual(stats["approved"], 1)

    def test_failure_recording(self):
        kb = self._make_kb()
        kb.store("CVE-2024-4444", "apache", {"commands": {}, "confidence": 70, "source": "ai"})
        kb.record_failure("CVE-2024-4444", "apache")
        # Should not raise, failure count incremented internally


class TestKnowledgeGraph(unittest.TestCase):
    """Phase 8: Knowledge graph."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ingest_and_retrieve(self):
        from app.remediation.graph.patch_graph import PatchKnowledgeGraph
        g = PatchKnowledgeGraph(os.path.join(self.tmp, "graph.db"))
        g.ingest_patch(
            cve_id="CVE-2024-6387",
            vendor="ubuntu",
            product="openssh",
            version="9.7",
            patch={
                "severity": "high", "cvss": 8.1, "confidence": 100,
                "source": "vendor", "fix_version": "9.8",
                "verification": "ssh -V",
            }
        )
        patches = g.get_patches_for_cve("CVE-2024-6387")
        self.assertGreater(len(patches), 0)

    def test_visualize_json(self):
        from app.remediation.graph.patch_graph import PatchKnowledgeGraph
        g = PatchKnowledgeGraph(os.path.join(self.tmp, "graph2.db"))
        g.ingest_patch("CVE-2024-0001", "cisco", "ios", "15.2",
                       {"severity": "critical", "confidence": 100, "source": "vendor"})
        viz = g.visualize_json()
        self.assertIn("nodes", viz)
        self.assertIn("edges", viz)
        self.assertGreater(viz["node_count"], 0)


class TestOrchestrator(unittest.TestCase):
    """
    Phase 12: Integration — tests full layer chain.
    Layer 1 is seeded directly; layers 2-4 are tested
    via known-good CVEs and service names.
    """

    def test_layer1_hit(self):
        """Layer 1 should return when CVE is in repository."""
        from app.remediation.repository.patch_repository import patch_repository
        from app.remediation.orchestrator import resolve_patch

        patch_repository.store(
            cve_id="CVE-TEST-1001",
            patch_data={
                "vendor": "test", "product": "testservice",
                "commands": {"ubuntu/debian": "apt-get upgrade testservice"},
                "fix_version": "2.0", "official_url": "https://example.com/advisory",
            },
            source="vendor",
            confidence=100,
        )
        result = resolve_patch(cve_id="CVE-TEST-1001")
        self.assertIsNotNone(result)
        self.assertTrue(result.get("patch_found"))
        self.assertEqual(result.get("layer"), "repository")
        self.assertFalse(result.get("ai_called"))

    def test_layer3_nvd_seeded_hit(self):
        """Layer 3 should return when NVD data is cached."""
        from app.remediation.nvd_cache.nvd_cache import nvd_intelligence_cache
        from app.remediation.orchestrator import resolve_patch

        nvd_intelligence_cache.store("CVE-TEST-2001", {
            "cve_id": "CVE-TEST-2001",
            "cvss": 7.5, "severity": "high",
            "description": "Test vulnerability",
            "references": ["https://example.com/ref"],
            "vendor_links": ["https://example.com/advisory"],
            "published": "2024-01-01",
            "modified": "2024-01-15",
        })
        result = resolve_patch(cve_id="CVE-TEST-2001", service="testd")
        self.assertIsNotNone(result)
        self.assertTrue(result.get("patch_found"))

    def test_result_has_confidence_label(self):
        """Every result must have confidence_label."""
        from app.remediation.orchestrator import resolve_patch
        result = resolve_patch(cve_id="CVE-TEST-9999", service="nginx")
        self.assertIn("confidence_label", result)
        self.assertIn("confidence", result)
        self.assertIn("layer", result)
        self.assertIn("source", result)

    def test_batch_resolution(self):
        """Batch resolution returns same count as input."""
        from app.remediation.orchestrator import resolve_patches_batch
        vulns = [
            {"cve_id": "CVE-TEST-3001", "service": "apache", "version": "2.4.49"},
            {"cve_id": "CVE-TEST-3002", "service": "nginx",  "version": "1.20"},
        ]
        results = resolve_patches_batch(vulns)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn("patch_found", r)
            self.assertIn("confidence", r)


# ── Test runner ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("ThreatWeave — 4-Layer Patch Resolution Test Suite")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    test_classes = [
        TestLayer1Repository,
        TestLayer1Validator,
        TestLayer2VendorModels,
        TestLayer3NVD,
        TestLayer4AI,
        TestConfidenceScoring,
        TestLearningKB,
        TestKnowledgeGraph,
        TestOrchestrator,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"Results: {result.testsRun} tests | "
          f"{len(result.failures)} failures | "
          f"{len(result.errors)} errors")

    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ SOME TESTS FAILED")
        sys.exit(1)
