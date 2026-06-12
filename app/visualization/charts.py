"""
Visualization Module
Generates chart-ready JSON data for the frontend (Chart.js).
No server-side image generation — all rendering done in browser.
"""


def generate_chart_data(analysis: dict) -> dict:
    """
    Generate all chart datasets from a scan analysis dict.
    Returns JSON-serialisable chart configs for Chart.js.
    """
    hosts = analysis.get("risk", {}).get("hosts", [])

    return {
        "risk_distribution":   _risk_distribution(hosts),
        "service_distribution": _service_distribution(hosts),
        "severity_breakdown":  _severity_breakdown(hosts),
        "port_exposure":       _port_exposure(hosts),
        "cve_summary":         _cve_summary(hosts),
        "risk_gauge":          _risk_gauge(hosts),
    }


def generate_history_trends(sessions: list) -> dict:
    """
    Generate trend data from scan history for the history dashboard.
    sessions: list of dicts from list_sessions()
    """
    labels      = []
    critical_counts = []
    high_counts     = []
    medium_counts   = []
    low_counts      = []
    cve_totals      = []

    for s in sessions[:20]:  # last 20 sessions
        labels.append(s.get("timestamp", "")[:10])
        risk = s.get("overall_risk", "low")
        critical_counts.append(1 if risk == "critical" else 0)
        high_counts.append(1 if risk == "high" else 0)
        medium_counts.append(1 if risk == "medium" else 0)
        low_counts.append(1 if risk == "low" else 0)
        cve_totals.append(s.get("cve_count", 0))

    return {
        "labels": labels[::-1],
        "risk_trend": {
            "critical": critical_counts[::-1],
            "high":     high_counts[::-1],
            "medium":   medium_counts[::-1],
            "low":      low_counts[::-1],
        },
        "cve_trend": cve_totals[::-1],
    }


# ── Private helpers ────────────────────────────────────────────────────────────

def _risk_distribution(hosts: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for host in hosts:
        for port in host.get("ports", []):
            lvl = port.get("risk", {}).get("level", "low")
            counts[lvl] = counts.get(lvl, 0) + 1
    return {
        "type":   "doughnut",
        "title":  "Risk Distribution",
        "labels": ["Critical", "High", "Medium", "Low"],
        "data":   [counts["critical"], counts["high"], counts["medium"], counts["low"]],
        "colors": ["#E24B4A", "#EF9F27", "#378ADD", "#1D9E75"],
    }


def _service_distribution(hosts: list) -> dict:
    svc_counts = {}
    for host in hosts:
        for port in host.get("ports", []):
            svc = port.get("service", "unknown")
            svc_counts[svc] = svc_counts.get(svc, 0) + 1

    sorted_svcs = sorted(svc_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    labels = [s[0].upper() for s in sorted_svcs]
    data   = [s[1] for s in sorted_svcs]
    colors = ["#1f6feb","#388bfd","#7f77dd","#1D9E75",
              "#EF9F27","#E24B4A","#378ADD","#8b949e"]

    return {
        "type":   "bar",
        "title":  "Services Discovered",
        "labels": labels,
        "data":   data,
        "colors": colors[:len(labels)],
    }


def _severity_breakdown(hosts: list) -> dict:
    severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for host in hosts:
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                sev = cve.get("severity", "unknown")
                severity_map[sev] = severity_map.get(sev, 0) + 1
    return {
        "type":   "bar",
        "title":  "CVE Severity Breakdown",
        "labels": ["Critical", "High", "Medium", "Low", "Unknown"],
        "data":   [severity_map["critical"], severity_map["high"],
                   severity_map["medium"],   severity_map["low"],
                   severity_map["unknown"]],
        "colors": ["#E24B4A", "#EF9F27", "#378ADD", "#1D9E75", "#8b949e"],
    }


def _port_exposure(hosts: list) -> dict:
    well_known = 0
    common_exp = 0
    high_port  = 0
    for host in hosts:
        for port in host.get("ports", []):
            etype = port.get("context", {}).get("exposure_type", "high_port")
            if etype == "commonly_exposed":  common_exp += 1
            elif etype == "well_known_port": well_known += 1
            else:                            high_port  += 1
    return {
        "type":   "pie",
        "title":  "Port Exposure Type",
        "labels": ["Commonly Exposed", "Well-Known", "High Port"],
        "data":   [common_exp, well_known, high_port],
        "colors": ["#E24B4A", "#EF9F27", "#378ADD"],
    }


def _cve_summary(hosts: list) -> dict:
    total = 0
    by_service = {}
    for host in hosts:
        for port in host.get("ports", []):
            svc   = port.get("service", "unknown")
            count = len(port.get("cves", []))
            total += count
            if count > 0:
                by_service[svc] = by_service.get(svc, 0) + count

    sorted_svcs = sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:6]
    return {
        "type":        "bar",
        "title":       "CVEs per Service",
        "labels":      [s[0].upper() for s in sorted_svcs],
        "data":        [s[1] for s in sorted_svcs],
        "colors":      ["#E24B4A"] * len(sorted_svcs),
        "total_cves":  total,
    }


def _risk_gauge(hosts: list) -> dict:
    """Returns a 0-100 gauge score representing overall host risk."""
    all_scores = []
    for host in hosts:
        for port in host.get("ports", []):
            score = port.get("risk", {}).get("score", 0)
            all_scores.append(score)

    avg   = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0
    gauge = round(avg * 10)  # convert 0-10 to 0-100

    if gauge >= 85:   color, label = "#E24B4A", "Critical"
    elif gauge >= 65: color, label = "#EF9F27", "High"
    elif gauge >= 40: color, label = "#378ADD", "Medium"
    else:             color, label = "#1D9E75", "Low"

    return {
        "type":  "gauge",
        "title": "Overall Risk Score",
        "value": gauge,
        "label": label,
        "color": color,
    }
