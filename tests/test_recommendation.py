"""
Tests for Recommendation Engine and Explanation Layer.
Run with: pytest tests/test_recommendation.py -v
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.recommendation.recommender import get_recommendation
from app.explanation.explainer import generate_explanation


def _make_risk_data(has_version=True, has_outdated=False, has_critical_cve=False,
                    has_os=False, port_count=2):
    ports = []
    for i in range(port_count):
        port = {
            "port": 22 + i,
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "7.4" if has_version else "",
            "state": "open",
            "cves": [],
            "version_analysis": {
                "status": "outdated" if has_outdated else ("latest" if has_version else "unknown"),
                "message": "Outdated" if has_outdated else "Up to date",
                "confidence": "high",
                "age_years": 9 if has_outdated else 0
            },
            "context": {
                "criticality": "high",
                "criticality_reason": "Remote admin access",
                "exposure_type": "commonly_exposed",
                "version_risk": "medium",
                "total_open_ports": port_count
            },
            "risk": {"level": "medium", "score": 5.0, "reasons": [], "color": "#3B8BD4", "max_cvss": 0, "cve_count": 0}
        }
        if has_critical_cve:
            port["cves"] = [{"cve_id": "CVE-2023-38408", "cvss_score": 9.8, "severity": "critical",
                              "description": "RCE in OpenSSH", "patch": "Upgrade"}]
            port["risk"]["level"] = "critical"
        ports.append(port)

    host = {
        "ip": "192.168.1.10",
        "ports": ports,
        "os": {"name": "Linux 5.15", "accuracy": "97"} if has_os else None,
        "context": {"exposure": "medium", "open_port_count": port_count, "exposure_note": ""},
        "risk_summary": {"overall": "medium", "counts": {"critical": 0, "high": 0, "medium": 2, "low": 0}, "total_ports": port_count}
    }
    return {"hosts": [host], "scan_summary": {}}


class TestRecommendationEngine:
    def test_returns_dict(self):
        data = _make_risk_data()
        result = get_recommendation(data, "tcp_basic")
        assert isinstance(result, dict)

    def test_has_required_fields(self):
        data = _make_risk_data()
        result = get_recommendation(data, "tcp_basic")
        assert "title" in result
        assert "reason" in result

    def test_no_version_recommends_service_detect(self):
        data = _make_risk_data(has_version=False)
        result = get_recommendation(data, "tcp_basic")
        assert result.get("scan_type") == "service_detect"

    def test_critical_cve_recommends_scripts(self):
        data = _make_risk_data(has_version=True, has_critical_cve=True)
        result = get_recommendation(data, "tcp_basic")
        assert result.get("scan_type") == "enum_scripts"

    def test_outdated_version_recommends_version_deep(self):
        data = _make_risk_data(has_version=True, has_outdated=True, has_critical_cve=False)
        result = get_recommendation(data, "tcp_basic")
        # Should suggest version deep or scripts
        assert result.get("scan_type") in ("version_deep", "enum_scripts", "udp_scan")

    def test_already_did_udp_doesnt_suggest_udp(self):
        data = _make_risk_data(has_version=True)
        result = get_recommendation(data, "udp_scan")
        # Since we just did UDP, should not suggest UDP again
        assert result.get("scan_type") != "udp_scan"

    def test_empty_hosts_returns_all_complete(self):
        result = get_recommendation({"hosts": [], "scan_summary": {}}, "tcp_basic")
        assert result.get("scan_type") is None  # all_complete

    def test_alternatives_is_list(self):
        data = _make_risk_data()
        result = get_recommendation(data, "tcp_basic")
        assert isinstance(result.get("alternatives", []), list)

    def test_reason_is_non_empty_string(self):
        data = _make_risk_data()
        result = get_recommendation(data, "tcp_basic")
        assert isinstance(result["reason"], str)
        assert len(result["reason"]) > 10


class TestExplanationLayer:
    def setup_method(self):
        self.data = _make_risk_data(has_version=True, has_outdated=True, has_critical_cve=True)
        self.rec = {"title": "Script Enumeration", "reason": "Critical CVEs detected.", "scan_type": "enum_scripts"}

    def test_returns_dict(self):
        result = generate_explanation(self.data, self.rec)
        assert isinstance(result, dict)

    def test_has_required_fields(self):
        result = generate_explanation(self.data, self.rec)
        assert "summary" in result
        assert "findings" in result
        assert "defensive_guidance" in result
        assert "next_step" in result

    def test_summary_is_string(self):
        result = generate_explanation(self.data, self.rec)
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 20

    def test_findings_is_list(self):
        result = generate_explanation(self.data, self.rec)
        assert isinstance(result["findings"], list)

    def test_finding_fields(self):
        result = generate_explanation(self.data, self.rec)
        for finding in result["findings"]:
            assert "port" in finding
            assert "service" in finding
            assert "risk_level" in finding
            assert "what_was_found" in finding
            assert "why_it_matters" in finding
            assert "guidance" in finding

    def test_defensive_guidance_is_list(self):
        result = generate_explanation(self.data, self.rec)
        assert isinstance(result["defensive_guidance"], list)

    def test_no_exploit_in_guidance(self):
        """Safety check: guidance must never contain exploit instructions."""
        result = generate_explanation(self.data, self.rec)
        forbidden = ["exploit", "payload", "shellcode", "metasploit", "weaponize"]
        all_text = " ".join(result["defensive_guidance"]).lower()
        for word in forbidden:
            assert word not in all_text, f"Forbidden term '{word}' found in guidance"

    def test_empty_hosts_handled(self):
        result = generate_explanation({"hosts": [], "scan_summary": {}}, self.rec)
        assert "No live hosts" in result["summary"]
        assert result["findings"] == []

    def test_critical_flagged_in_summary(self):
        result = generate_explanation(self.data, self.rec)
        # Should mention critical or action required
        summary_lower = result["summary"].lower()
        assert any(w in summary_lower for w in ["critical", "immediate", "high"])

    def test_next_step_from_recommendation(self):
        result = generate_explanation(self.data, self.rec)
        assert result["next_step"] == self.rec["reason"]
