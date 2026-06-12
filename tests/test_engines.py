"""
Tests for Version Detection and Risk Prioritization engines.
Run with: pytest tests/test_engines.py -v
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.analysis.version_engine import analyze_versions, _analyze_port_version, _version_matches
from app.analysis.risk_engine import calculate_risk, _score_to_level, _calculate_port_risk


# ── Version Engine Tests ────────────────────────────────────────────────────

class TestVersionMatching:
    def test_exact_match(self):
        assert _version_matches("openssh 7.4", "OpenSSH 7.4") is True

    def test_prefix_match(self):
        assert _version_matches("apache httpd 2.2.34", "Apache httpd 2.2") is True

    def test_no_match(self):
        assert _version_matches("nginx 1.26", "Apache httpd 2.4") is False

    def test_case_insensitive(self):
        assert _version_matches("OPENSSH 9.8", "OpenSSH 9.8") is True


class TestPortVersionAnalysis:
    def test_known_outdated_openssh(self):
        port = {"service": "ssh", "product": "OpenSSH", "version": "7.4"}
        result = _analyze_port_version(port)
        assert result["status"] in ("outdated", "unsupported")
        assert result["confidence"] in ("high", "medium")

    def test_unsupported_apache(self):
        port = {"service": "http", "product": "Apache httpd", "version": "2.2.34"}
        result = _analyze_port_version(port)
        assert result["status"] == "unsupported"

    def test_vsftpd_backdoor_unsupported(self):
        port = {"service": "ftp", "product": "vsftpd", "version": "2.3.4"}
        result = _analyze_port_version(port)
        assert result["status"] == "unsupported"

    def test_no_version_returns_unknown(self):
        port = {"service": "ssh", "product": "", "version": ""}
        result = _analyze_port_version(port)
        assert result["status"] == "unknown"
        assert result["confidence"] == "low"

    def test_result_has_required_fields(self):
        port = {"service": "ssh", "product": "OpenSSH", "version": "7.4"}
        result = _analyze_port_version(port)
        assert "status" in result
        assert "confidence" in result
        assert "message" in result
        assert "version_string" in result

    def test_message_is_string(self):
        port = {"service": "mysql", "product": "MySQL", "version": "5.5.62"}
        result = _analyze_port_version(port)
        assert isinstance(result["message"], str)
        assert len(result["message"]) > 0

    def test_unknown_service_no_crash(self):
        port = {"service": "exotic-daemon", "product": "FooDB", "version": "3.1"}
        result = _analyze_port_version(port)
        assert result["status"] in ("unknown", "outdated")


class TestAnalyzeVersionsIntegration:
    def _make_parsed(self, ports):
        return {"hosts": [{"ip": "192.168.1.10", "ports": ports}], "scan_summary": {}}

    def test_version_analysis_added(self):
        parsed = self._make_parsed([
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "protocol": "tcp", "state": "open"}
        ])
        result = analyze_versions(parsed)
        port = result["hosts"][0]["ports"][0]
        assert "version_analysis" in port

    def test_all_ports_get_analysis(self):
        parsed = self._make_parsed([
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
             "protocol": "tcp", "state": "open"},
            {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.2.34",
             "protocol": "tcp", "state": "open"},
        ])
        result = analyze_versions(parsed)
        for port in result["hosts"][0]["ports"]:
            assert "version_analysis" in port

    def test_empty_hosts(self):
        result = analyze_versions({"hosts": [], "scan_summary": {}})
        assert result["hosts"] == []


# ── Risk Engine Tests ───────────────────────────────────────────────────────

class TestScoreToLevel:
    def test_critical(self):
        assert _score_to_level(9.5) == "critical"
        assert _score_to_level(8.5) == "critical"

    def test_high(self):
        assert _score_to_level(7.0) == "high"
        assert _score_to_level(6.5) == "high"

    def test_medium(self):
        assert _score_to_level(5.0) == "medium"
        assert _score_to_level(4.0) == "medium"

    def test_low(self):
        assert _score_to_level(3.0) == "low"
        assert _score_to_level(0.0) == "low"


class TestCalculatePortRisk:
    def _make_port(self, cvss=0, criticality="low", v_status="unknown", cve_count=0):
        cves = [{"cvss_score": cvss, "severity": "critical" if cvss >= 9 else "high"}] * cve_count
        return {
            "port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4",
            "cves": cves,
            "context": {
                "criticality": criticality,
                "criticality_reason": "test",
                "exposure_type": "commonly_exposed",
                "version_risk": {"latest": "low", "outdated": "medium", "unsupported": "high"}.get(v_status, "medium")
            },
            "version_analysis": {"status": v_status, "age_years": 7}
        }

    def test_critical_cvss_raises_risk(self):
        port = self._make_port(cvss=9.8, criticality="critical", v_status="unsupported", cve_count=1)
        result = _calculate_port_risk(port, "high")
        assert result["level"] in ("critical", "high")
        assert result["score"] > 5.0

    def test_no_cves_low_risk(self):
        port = self._make_port(cvss=0, criticality="low", v_status="latest", cve_count=0)
        result = _calculate_port_risk(port, "low")
        assert result["score"] < 6.0

    def test_result_has_required_fields(self):
        port = self._make_port(cvss=5.3, criticality="medium", v_status="outdated", cve_count=1)
        result = _calculate_port_risk(port, "medium")
        assert "score" in result
        assert "level" in result
        assert "reasons" in result
        assert "color" in result
        assert "max_cvss" in result

    def test_level_is_valid(self):
        port = self._make_port(cvss=7.5, criticality="high", v_status="outdated", cve_count=1)
        result = _calculate_port_risk(port, "medium")
        assert result["level"] in ("low", "medium", "high", "critical")

    def test_score_capped_at_10(self):
        port = self._make_port(cvss=10.0, criticality="critical", v_status="unsupported", cve_count=5)
        result = _calculate_port_risk(port, "high")
        assert result["score"] <= 10.0

    def test_reasons_is_list(self):
        port = self._make_port(cvss=9.8, criticality="critical", v_status="unsupported", cve_count=2)
        result = _calculate_port_risk(port, "high")
        assert isinstance(result["reasons"], list)
        assert len(result["reasons"]) > 0


class TestCalculateRiskIntegration:
    def _full_port(self):
        return {
            "port": 22, "protocol": "tcp", "service": "ssh",
            "product": "OpenSSH", "version": "7.4", "state": "open",
            "cves": [
                {"cve_id": "CVE-2018-15473", "cvss_score": 5.3, "severity": "medium",
                 "description": "Username enum", "patch": "Upgrade"}
            ],
            "context": {
                "criticality": "high",
                "criticality_reason": "Remote admin access",
                "exposure_type": "commonly_exposed",
                "version_risk": "medium",
                "total_open_ports": 3
            },
            "version_analysis": {"status": "outdated", "age_years": 9, "confidence": "high", "message": "Outdated"}
        }

    def test_risk_added_to_port(self):
        data = {
            "hosts": [{"ip": "192.168.1.10", "ports": [self._full_port()],
                        "context": {"exposure": "medium", "open_port_count": 1, "exposure_note": ""}}],
            "scan_summary": {}
        }
        result = calculate_risk(data)
        port = result["hosts"][0]["ports"][0]
        assert "risk" in port

    def test_host_risk_summary_added(self):
        data = {
            "hosts": [{"ip": "192.168.1.10", "ports": [self._full_port()],
                        "context": {"exposure": "medium", "open_port_count": 1, "exposure_note": ""}}],
            "scan_summary": {}
        }
        result = calculate_risk(data)
        host = result["hosts"][0]
        assert "risk_summary" in host
        rs = host["risk_summary"]
        assert "overall" in rs
        assert "counts" in rs

    def test_empty_hosts_no_crash(self):
        result = calculate_risk({"hosts": [], "scan_summary": {}})
        assert result["hosts"] == []
