"""
ThreatWeave — NVD Response Parser
===================================
Parses NVD 2.0 API responses and extracts intelligence for patch resolution.
"""
from __future__ import annotations

import re
from typing import Optional


_VENDOR_TAG_KEYWORDS = ("Patch", "Vendor Advisory", "Mitigation", "Exploit",
                        "Third Party Advisory", "Release Notes")

_SEVERITY_MAP = {
    "critical": "critical", "high": "high",
    "medium": "medium", "low": "low", "none": "none",
}


def parse_nvd_item(item: dict) -> Optional[dict]:
    """
    Parse a single NVD vulnerability item into our normalized schema.

    Returns:
      {cve, cvss, severity, description, references, vendor_links,
       published, modified, patch_commands}
    """
    try:
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available."
        )

        # CVSS
        cvss, sev = _extract_cvss(cve.get("metrics", {}))

        # References
        all_refs = cve.get("references", [])
        refs = [r.get("url", "") for r in all_refs if r.get("url")][:10]
        vendor_links = [
            r.get("url", "") for r in all_refs
            if any(tag in (r.get("tags") or []) for tag in _VENDOR_TAG_KEYWORDS)
        ][:5]

        return {
            "cve_id":       cve_id,
            "cvss":         cvss,
            "severity":     sev,
            "description":  desc[:500],
            "references":   refs,
            "vendor_links": vendor_links,
            "published":    cve.get("published", "")[:10],
            "modified":     cve.get("lastModified", "")[:10],
        }
    except Exception:
        return None


def extract_patch_guidance(nvd_entry: dict, service: str = "") -> dict:
    """
    Extract patch guidance from a stored NVD entry.
    Builds upgrade commands from vendor_links and service hints.
    """
    vendor_links = nvd_entry.get("vendor_links", [])
    all_refs     = nvd_entry.get("references", [])
    svc          = service.lower()

    # Determine official URL
    official_url = vendor_links[0] if vendor_links else (
        f"https://nvd.nist.gov/vuln/detail/{nvd_entry.get('cve_id', '')}"
    )

    # Build commands from service hint
    cmds: dict = {}
    if svc in ("openssh", "ssh"):
        cmds = {"ubuntu/debian": "apt-get update && apt-get upgrade -y openssh-server",
                "rhel/centos":   "yum update openssh"}
    elif svc in ("apache", "httpd"):
        cmds = {"ubuntu/debian": "apt-get update && apt-get upgrade -y apache2",
                "rhel/centos":   "yum update httpd"}
    elif svc == "nginx":
        cmds = {"ubuntu/debian": "apt-get update && apt-get upgrade -y nginx",
                "rhel/centos":   "yum update nginx"}
    elif svc in ("php",):
        cmds = {"ubuntu/debian": "apt-get update && apt-get upgrade -y php",
                "rhel/centos":   "yum update php"}
    elif svc in ("mysql", "mariadb"):
        cmds = {"ubuntu/debian": f"apt-get update && apt-get upgrade -y {svc}-server"}
    elif svc:
        cmds = {"ubuntu/debian": f"apt-get update && apt-get upgrade -y {svc}"}

    return {
        "commands":     cmds,
        "patch_command": cmds,
        "vendor_url":   official_url,
        "official_url": official_url,
        "references":   all_refs[:5],
        "mitigation":   f"Check vendor advisory at {official_url}",
    }


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data  = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            sev   = (
                data.get("baseSeverity") or
                data.get("severity") or
                _score_to_sev(score)
            ).lower()
            return score, _SEVERITY_MAP.get(sev, "unknown")
    return 0.0, "unknown"


def _score_to_sev(s: float) -> str:
    if s >= 9: return "critical"
    if s >= 7: return "high"
    if s >= 4: return "medium"
    if s > 0:  return "low"
    return "none"
