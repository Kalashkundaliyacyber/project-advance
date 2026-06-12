"""
ThreatWeave — Vulnerability Timeline Engine (Phase 8)
=====================================================
Builds a chronological timeline of:
  - CVE publication dates
  - Patch release dates
  - Days vulnerable (exposure window)
  - KEV (Known Exploited Vulnerabilities) status
"""
import logging
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ThreatWeave.vuln_timeline")

# Known KEV CVEs (subset — updated via NVD/CISA feed)
# Source: CISA KEV catalog high-impact entries
_KEV_CVES = {
    "CVE-2024-6387", "CVE-2023-38408", "CVE-2021-41773", "CVE-2021-42013",
    "CVE-2021-44228", "CVE-2021-45046", "CVE-2017-7494", "CVE-2017-0144",
    "CVE-2019-0708", "CVE-2020-1472", "CVE-2021-34527", "CVE-2022-30190",
    "CVE-2023-23397", "CVE-2023-27350", "CVE-2023-4966", "CVE-2024-3400",
}

# Rough patch timeline reference (days after disclosure to patch available)
_AVG_PATCH_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def build_cve_timeline(cve_list: list) -> dict:
    """
    Build a vulnerability timeline from a list of CVE dicts.
    Each CVE dict should have: cve_id, published_date, cvss, severity, service
    Returns: {timeline, stats, kev_count, oldest_vuln, exposure_summary}
    """
    if not cve_list:
        return _empty_timeline()

    now  = datetime.now(timezone.utc)
    events = []

    for cve in cve_list:
        cve_id   = cve.get("cve_id", "") or cve.get("id", "")
        pub_date = _parse_date(cve.get("published") or cve.get("published_date", ""))
        severity = (cve.get("severity") or "medium").lower()
        cvss     = float(cve.get("cvss", 0) or 0)
        service  = cve.get("service", "")
        is_kev   = cve_id.upper() in _KEV_CVES

        days_since_pub  = (now - pub_date).days if pub_date else None
        expected_patch  = _AVG_PATCH_DAYS.get(severity, 90)
        overdue_days    = max(0, (days_since_pub or 0) - expected_patch) if days_since_pub else 0

        event = {
            "cve_id":          cve_id,
            "severity":        severity,
            "cvss":            cvss,
            "service":         service,
            "published":       pub_date.strftime("%Y-%m-%d") if pub_date else "Unknown",
            "days_since_pub":  days_since_pub,
            "expected_patch_days": expected_patch,
            "overdue_days":    overdue_days,
            "is_kev":          is_kev,
            "urgency":         _urgency(is_kev, cvss, overdue_days),
            "status":          "overdue" if overdue_days > 0 else "within_window",
        }
        events.append(event)

    # Sort: KEV first, then by urgency score desc
    events.sort(key=lambda e: (_urgency_score(e), e.get("cvss", 0)), reverse=True)

    stats = _compute_stats(events, now)
    oldest = max((e for e in events if e["days_since_pub"]),
                 key=lambda e: e["days_since_pub"], default=None)

    return {
        "timeline":         events,
        "stats":            stats,
        "kev_count":        sum(1 for e in events if e["is_kev"]),
        "overdue_count":    sum(1 for e in events if e["status"] == "overdue"),
        "oldest_vuln":      oldest,
        "generated_at":     now.strftime("%Y-%m-%d %H:%M UTC"),
    }


def _compute_stats(events: list, now: datetime) -> dict:
    by_sev = {}
    total_exposure = 0
    for e in events:
        s = e["severity"]
        by_sev[s] = by_sev.get(s, 0) + 1
        if e["days_since_pub"]:
            total_exposure += e["days_since_pub"]

    return {
        "total_cves":       len(events),
        "by_severity":      by_sev,
        "avg_exposure_days": round(total_exposure / len(events), 1) if events else 0,
        "kev_percentage":   round(sum(1 for e in events if e["is_kev"]) / len(events) * 100, 1) if events else 0,
    }


def _parse_date(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d", "%Y/%m/%d"):
        try:
            dt = datetime.strptime(date_str[:len(fmt)], fmt[:len(date_str)])
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def _urgency(is_kev: bool, cvss: float, overdue: int) -> str:
    if is_kev:            return "immediate"
    if cvss >= 9.0:       return "immediate"
    if cvss >= 7.0:       return "urgent"
    if overdue > 180:     return "urgent"
    if cvss >= 4.0:       return "moderate"
    return "routine"


def _urgency_score(event: dict) -> float:
    score = event.get("cvss", 0) * 10
    if event["is_kev"]:       score += 200
    if event["overdue_days"]: score += min(event["overdue_days"], 100)
    return score


def _empty_timeline() -> dict:
    return {"timeline": [], "stats": {}, "kev_count": 0,
            "overdue_count": 0, "oldest_vuln": None,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
