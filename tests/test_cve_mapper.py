"""
Tests for the CVE mapping engine.
Run with: pytest tests/test_cve_mapper.py -v
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.cve.mapper import map_cves, _find_cves, _version_affected


class TestVersionAffected:
    def test_exact_prefix_match(self):
        assert _version_affected("7.4", ["7."]) is True

    def test_full_version_match(self):
        assert _version_affected("2.3.4", ["2.3.4"]) is True

    def test_no_match(self):
        assert _version_affected("9.8", ["7.", "6.", "5."]) is False

    def test_empty_version(self):
        assert _version_affected("", ["7."]) is False

    def test_partial_match(self):
        assert _version_affected("5.5.62", ["5.5."]) is True


class TestFindCVEs:
    def test_openssh_old_finds_cves(self):
        port = {"service": "ssh", "product": "OpenSSH", "version": "7.4"}
        cves = _find_cves(port)
        assert len(cves) > 0

    def test_openssh_returns_cve_fields(self):
        port = {"service": "ssh", "product": "OpenSSH", "version": "7.4"}
        cves = _find_cves(port)
        for cve in cves:
            assert "cve_id" in cve
            assert "cvss_score" in cve
            assert "severity" in cve
            assert "description" in cve
            assert "patch" in cve

    def test_no_exploit_in_cve_data(self):
        """Safety check: CVEs must not contain exploit instructions."""
        port = {"service": "ssh", "product": "OpenSSH", "version": "7.4"}
        cves = _find_cves(port)
        for cve in cves:
            desc = cve.get("description", "").lower()
            patch = cve.get("patch", "").lower()
            forbidden = ["exploit code", "payload", "shellcode", "weaponize", "metasploit module"]
            for word in forbidden:
                assert word not in desc, f"Exploit term '{word}' found in CVE description"
                assert word not in patch

    def test_vsftpd_backdoor_detected(self):
        port = {"service": "ftp", "product": "vsftpd", "version": "2.3.4"}
        cves = _find_cves(port)
        cve_ids = [c["cve_id"] for c in cves]
        assert "CVE-2011-2523" in cve_ids

    def test_apache_eol_version(self):
        port = {"service": "http", "product": "Apache httpd", "version": "2.2.34"}
        cves = _find_cves(port)
        assert len(cves) > 0

    def test_mysql_old_version(self):
        port = {"service": "mysql", "product": "MySQL", "version": "5.5.62"}
        cves = _find_cves(port)
        assert len(cves) > 0

    def test_unknown_service_no_crash(self):
        port = {"service": "unknown-svc", "product": "FooBar", "version": "1.0"}
        cves = _find_cves(port)
        assert isinstance(cves, list)

    def test_sorted_by_cvss_desc(self):
        port = {"service": "ssh", "product": "OpenSSH", "version": "7.4"}
        cves = _find_cves(port)
        if len(cves) >= 2:
            scores = [c["cvss_score"] for c in cves]
            assert scores == sorted(scores, reverse=True)

    def test_openssh_latest_fewer_cves(self):
        """Newer versions should match fewer CVEs."""
        old = _find_cves({"service": "ssh", "product": "OpenSSH", "version": "7.4"})
        new = _find_cves({"service": "ssh", "product": "OpenSSH", "version": "9.8"})
        assert len(old) >= len(new)


class TestMapCVEsIntegration:
    def _make_parsed(self, ports):
        return {
            "hosts": [{
                "ip": "192.168.1.10",
                "ports": ports,
                "hostnames": [],
                "os": None
            }],
            "scan_summary": {}
        }

    def test_cves_attached_to_ports(self):
        parsed = self._make_parsed([
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "version_analysis": {}}
        ])
        result = map_cves(parsed)
        port = result["hosts"][0]["ports"][0]
        assert "cves" in port
        assert isinstance(port["cves"], list)

    def test_multiple_ports_all_get_cves_field(self):
        parsed = self._make_parsed([
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "product": "OpenSSH", "version": "7.4", "version_analysis": {}},
            {"port": 80, "protocol": "tcp", "state": "open",
             "service": "http", "product": "Apache httpd", "version": "2.2.34", "version_analysis": {}},
        ])
        result = map_cves(parsed)
        for port in result["hosts"][0]["ports"]:
            assert "cves" in port

    def test_original_fields_preserved(self):
        parsed = self._make_parsed([
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "product": "OpenSSH", "version": "7.4", "version_analysis": {}}
        ])
        result = map_cves(parsed)
        port = result["hosts"][0]["ports"][0]
        assert port["port"] == 22
        assert port["service"] == "ssh"

    def test_empty_hosts(self):
        result = map_cves({"hosts": [], "scan_summary": {}})
        assert result["hosts"] == []

    def test_severity_values_valid(self):
        parsed = self._make_parsed([
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "product": "OpenSSH", "version": "7.4", "version_analysis": {}}
        ])
        result = map_cves(parsed)
        valid_severities = {"critical", "high", "medium", "low"}
        for cve in result["hosts"][0]["ports"][0]["cves"]:
            assert cve["severity"] in valid_severities

    def test_cvss_is_float(self):
        parsed = self._make_parsed([
            {"port": 21, "protocol": "tcp", "state": "open",
             "service": "ftp", "product": "vsftpd", "version": "2.3.4", "version_analysis": {}}
        ])
        result = map_cves(parsed)
        for cve in result["hosts"][0]["ports"][0]["cves"]:
            assert isinstance(cve["cvss_score"], (int, float))
