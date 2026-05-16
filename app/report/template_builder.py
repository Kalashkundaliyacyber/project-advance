"""Report Template Builder — generates structured JSON report from session data."""
import os
import json
import time

BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "sessions"
)


def build_report(session_id: str, analysis: dict) -> str:
    hosts = analysis.get("risk", {}).get("hosts", [])
    explanation = analysis.get("explanation", {})
    recommendation = analysis.get("recommendation", {})

    all_findings = []
    all_cves = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for host in hosts:
        for port in host.get("ports", []):
            risk = port.get("risk", {})
            level = risk.get("level", "low")
            severity_counts[level] = severity_counts.get(level, 0) + 1
            all_findings.append({
                "host":           host.get("ip"),
                "port":           port.get("port"),
                "protocol":       port.get("protocol"),
                "service":        port.get("service"),
                "version":        f"{port.get('product','')} {port.get('version','')}".strip(),
                "state":          port.get("state"),
                "risk_level":     level,
                "risk_score":     risk.get("score", 0),
                "version_status": port.get("version_analysis", {}).get("status", "unknown"),
                "cve_count":      len(port.get("cves", [])),
            })
            for cve in port.get("cves", []):
                all_cves.append({
                    "cve_id":      cve["cve_id"],
                    "service":     port.get("service"),
                    "port":        port.get("port"),
                    "cvss_score":  cve["cvss_score"],
                    "severity":    cve["severity"],
                    "description": cve["description"],
                    "patch":       cve.get("patch", ""),
                })

    all_cves.sort(key=lambda x: x["cvss_score"], reverse=True)

    report = {
        "report_metadata": {
            "title":        "ScanWise AI Security Assessment Report",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "session_id":   session_id,
            "tool":         "ScanWise AI v1.0",
        },
        "scan_information": {
            "target":           analysis.get("target"),
            "scan_type":        analysis.get("scan_type"),
            "duration_seconds": analysis.get("duration"),
            "scan_timestamp":   analysis.get("timestamp"),
        },
        "executive_summary": {
            "summary":            explanation.get("summary", ""),
            "total_hosts":        len(hosts),
            "total_open_ports":   sum(len(h.get("ports", [])) for h in hosts),
            "total_cves":         len(all_cves),
            "severity_breakdown": severity_counts,
            "overall_risk":       _overall(severity_counts),
        },
        "findings":           all_findings,
        "cve_details":        all_cves,
        "defensive_guidance": explanation.get("defensive_guidance", []),
        "recommendation": {
            "reason":     recommendation.get("reason"),
            "scan_type":  recommendation.get("scan_type"),
            "alternatives": recommendation.get("alternatives", []),
        },
        "conclusion": _build_conclusion(severity_counts, all_cves, analysis.get("target", "")),
    }

    report_dir = os.path.join(BASE_DIR, session_id, "report")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    return report_path


def _overall(counts: dict) -> str:
    if counts.get("critical", 0) > 0: return "CRITICAL"
    if counts.get("high", 0) > 0:     return "HIGH"
    if counts.get("medium", 0) > 0:   return "MEDIUM"
    return "LOW"


def _build_conclusion(counts: dict, cves: list, target: str) -> str:
    overall = _overall(counts)
    critical_cves = [c for c in cves if c["severity"] == "critical"]
    parts = [f"Assessment of {target} shows overall risk: {overall}."]
    if critical_cves:
        ids = ", ".join(c["cve_id"] for c in critical_cves[:3])
        parts.append(f"{len(critical_cves)} critical CVE(s) found ({ids}). Immediate remediation required.")
    elif cves:
        parts.append(f"{len(cves)} CVE(s) mapped. Patch and version upgrades recommended.")
    else:
        parts.append("No CVEs matched in this scan. Continue monitoring.")
    parts.append("Apply all patches, enforce firewall rules, and rescan after remediation.")
    return " ".join(parts)
