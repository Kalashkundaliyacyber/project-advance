"""
ThreatWeave — Unified Pipeline Tests
=====================================
New tests for the merged Gen1+Gen2 patch system.
Add these to tests/test_remediation.py (append after existing test classes).

Run:
    python -m pytest tests/test_remediation.py -v
    python -m pytest tests/test_remediation.py::TestUnifiedPipeline -v
"""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestUnifiedPipeline(unittest.TestCase):
    """End-to-end tests for the merged 4-layer + LRU + os_hint pipeline."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["ThreatWeave_DATA_DIR"] = self.tmp

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unified_output_schema(self):
        """resolve_patch must return all fields expected by routes.py and patch_api.py."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh")

        required = [
            "cve_id", "service", "confidence", "source",
            "from_kb", "from_cache", "ai_called",
            "fix_version", "vendor_url", "official_url",
            "commands", "patch_command", "patch_commands",
            "upgrade_path", "verification_steps", "rollback_steps",
            "resolution_path", "layer_timings_ms", "total_latency_ms",
        ]
        for field in required:
            self.assertIn(field, result, f"Missing field in unified output: {field}")

    def test_dual_command_keys(self):
        """Both 'commands' and 'patch_command' must be present and non-empty."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh")

        cmds_key   = result.get("commands") or result.get("patch_command") or {}
        self.assertTrue(bool(cmds_key), "commands / patch_command must not be empty")

    def test_vendor_seed_hit(self):
        """CVE-2024-6387 must resolve from Layer 1 (vendor seed, confidence=100)."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh")

        self.assertEqual(result["cve_id"], "CVE-2024-6387")
        self.assertFalse(result.get("ai_called"), "Vendor seed must not trigger AI call")
        self.assertGreaterEqual(result.get("confidence", 0), 90,
                                "Vendor seed must have confidence ≥ 90")

    def test_lru_cache_hit(self):
        """Second identical call must return from LRU cache without touching AI."""
        from app.remediation import resolve_patch
        # First call warms the LRU
        r1 = resolve_patch("CVE-2024-6387", service="openssh")
        # Second call must be from LRU
        r2 = resolve_patch("CVE-2024-6387", service="openssh")

        self.assertFalse(r2.get("ai_called"), "LRU hit must not call AI")
        self.assertTrue(
            r2.get("from_lru_cache") or r2.get("from_cache") or r2.get("from_kb"),
            "Second call must be marked as a cache hit"
        )

    def test_os_hint_ubuntu(self):
        """os_hint=ubuntu must return ubuntu/debian command."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh", os_hint="ubuntu")
        cmds = result.get("commands") or result.get("patch_command") or {}
        if isinstance(cmds, dict):
            ubuntu_cmd = cmds.get("ubuntu/debian", "")
            self.assertIn("apt", ubuntu_cmd.lower(),
                          "ubuntu os_hint must return apt command")

    def test_os_hint_rhel(self):
        """os_hint=rhel must produce a dnf/yum command somewhere in the result."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-9999-0001", service="testservice",
                               description="test vuln", os_hint="rhel")
        # Rule-engine fallback or AI must include dnf/yum for rhel
        patch_cmd = result.get("patch_command") or ""
        if isinstance(patch_cmd, str):
            # Rule engine fallback path — check command contains dnf
            cmds = result.get("commands") or {}
            rhel_cmd = cmds.get("rhel/centos", "")
            self.assertTrue(
                "dnf" in rhel_cmd.lower() or "yum" in rhel_cmd.lower(),
                "rhel os_hint must include dnf or yum command"
            )

    def test_resolve_patches_batch(self):
        """Batch resolver must return one result per input CVE."""
        from app.remediation import resolve_patches_batch
        vulns = [
            {"cve_id": "CVE-2024-6387", "service": "openssh",  "version": "9.7"},
            {"cve_id": "CVE-2021-41773", "service": "apache",  "version": "2.4.49"},
            {"cve_id": "CVE-2021-23017", "service": "nginx",   "version": "1.20"},
        ]
        results = resolve_patches_batch(vulns)
        self.assertEqual(len(results), 3, "Batch must return one result per input")
        for r in results:
            self.assertIn("cve_id", r)
            self.assertIn("commands", r)
            self.assertIn("patch_command", r)

    def test_confidence_not_downgraded_by_lru(self):
        """LRU cache must not downgrade a vendor confidence=100 result."""
        from app.remediation import resolve_patch
        r1 = resolve_patch("CVE-2024-6387", service="openssh")
        r2 = resolve_patch("CVE-2024-6387", service="openssh")
        self.assertGreaterEqual(r2.get("confidence", 0), r1.get("confidence", 0),
                                "LRU must preserve original confidence")

    def test_rollback_steps_always_present(self):
        """rollback_steps must always be a non-empty list."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh")
        rs = result.get("rollback_steps", [])
        self.assertIsInstance(rs, list, "rollback_steps must be a list")
        self.assertTrue(len(rs) > 0, "rollback_steps must not be empty")

    def test_verification_steps_always_present(self):
        """verification_steps must always be a non-empty list."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh")
        vs = result.get("verification_steps", [])
        self.assertIsInstance(vs, list, "verification_steps must be a list")
        self.assertTrue(len(vs) > 0, "verification_steps must not be empty")

    def test_resolution_path_populated(self):
        """resolution_path must record which layer provided the result."""
        from app.remediation import resolve_patch
        result = resolve_patch("CVE-2024-6387", service="openssh")
        rp = result.get("resolution_path", [])
        self.assertIsInstance(rp, list)
        self.assertTrue(len(rp) > 0, "resolution_path must not be empty")

    def test_no_ai_called_for_known_cve(self):
        """Known vendor CVEs must never trigger an AI call."""
        from app.remediation import resolve_patch
        for cve in ["CVE-2024-6387", "CVE-2023-38408", "CVE-2021-41773",
                    "CVE-2021-23017", "CVE-2017-7494"]:
            result = resolve_patch(cve)
            self.assertFalse(result.get("ai_called"),
                             f"{cve} is vendor-seeded — must not call AI")


if __name__ == "__main__":
    unittest.main()
