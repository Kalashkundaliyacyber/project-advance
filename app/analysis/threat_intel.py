"""
ThreatWeave — Threat Intelligence Layer (Phase 8)
=================================================
Enriches scan findings with:
  - EPSS (Exploit Prediction Scoring System) scores
  - KEV (CISA Known Exploited Vulnerabilities) status
  - Threat actor associations (from static knowledge base)
  - Active exploitation indicators
  - Shodan-style exposure context

This layer is LOCAL-FIRST — no external API required.
EPSS/KEV data is bundled and updated via the CVE cache engine.
"""
import logging
from typing import Optional

logger = logging.getLogger("ThreatWeave.threat_intel")

# CISA KEV catalog (high-impact subset, statically bundled)
# Full list updated via cve_cache_engine when NVD is available
_KEV_DB = {
    "CVE-2024-6387": {
        "name": "OpenSSH regreSSHion", "vendor": "OpenSSH",
        "product": "OpenSSH", "date_added": "2024-07-01",
        "short_description": "Remote code execution via signal handler race condition",
        "known_ransomware": False, "urgency": "critical",
    },
    "CVE-2023-38408": {
        "name": "OpenSSH ssh-agent RCE", "vendor": "OpenSSH",
        "product": "OpenSSH", "date_added": "2023-07-19",
        "short_description": "Remote code execution via ssh-agent",
        "known_ransomware": False, "urgency": "critical",
    },
    "CVE-2021-44228": {
        "name": "Log4Shell", "vendor": "Apache",
        "product": "Log4j", "date_added": "2021-12-10",
        "short_description": "JNDI injection allowing RCE",
        "known_ransomware": True, "urgency": "critical",
    },
    "CVE-2017-0144": {
        "name": "EternalBlue", "vendor": "Microsoft",
        "product": "SMB", "date_added": "2017-05-12",
        "short_description": "SMB buffer overflow used by WannaCry/NotPetya",
        "known_ransomware": True, "urgency": "critical",
    },
    "CVE-2019-0708": {
        "name": "BlueKeep", "vendor": "Microsoft",
        "product": "RDP", "date_added": "2019-05-14",
        "short_description": "RDP pre-auth RCE, wormable",
        "known_ransomware": False, "urgency": "critical",
    },
    "CVE-2021-34527": {
        "name": "PrintNightmare", "vendor": "Microsoft",
        "product": "Windows Print Spooler", "date_added": "2021-07-02",
        "short_description": "Windows Print Spooler RCE/LPE",
        "known_ransomware": True, "urgency": "critical",
    },
    "CVE-2020-1472": {
        "name": "Zerologon", "vendor": "Microsoft",
        "product": "Netlogon", "date_added": "2020-09-14",
        "short_description": "Netlogon privilege escalation to domain admin",
        "known_ransomware": True, "urgency": "critical",
    },
    "CVE-2021-41773": {
        "name": "Apache Path Traversal/RCE", "vendor": "Apache",
        "product": "HTTP Server", "date_added": "2021-10-05",
        "short_description": "Path traversal allowing RCE via mod_cgi",
        "known_ransomware": False, "urgency": "critical",
    },
    "CVE-2021-42013": {
        "name": "Apache Path Traversal (bypass)", "vendor": "Apache",
        "product": "HTTP Server", "date_added": "2021-10-08",
        "short_description": "Bypass of CVE-2021-41773 fix",
        "known_ransomware": False, "urgency": "critical",
    },
    "CVE-2022-30190": {
        "name": "Follina/MSDT", "vendor": "Microsoft",
        "product": "MSDT", "date_added": "2022-06-01",
        "short_description": "MS Support Diagnostic Tool RCE via document",
        "known_ransomware": True, "urgency": "critical",
    },
    "CVE-2017-7494": {
        "name": "SambaCry", "vendor": "Samba",
        "product": "Samba", "date_added": "2017-05-25",
        "short_description": "SMB arbitrary shared library loading → RCE",
        "known_ransomware": False, "urgency": "critical",
    },
    "CVE-2023-4966": {
        "name": "Citrix Bleed", "vendor": "Citrix",
        "product": "NetScaler", "date_added": "2023-10-18",
        "short_description": "Session token leak allowing auth bypass",
        "known_ransomware": True, "urgency": "critical",
    },
    "CVE-2024-3400": {
        "name": "PAN-OS Command Injection", "vendor": "Palo Alto",
        "product": "PAN-OS", "date_added": "2024-04-12",
        "short_description": "Zero-day firewall RCE",
        "known_ransomware": False, "urgency": "critical",
    },
}

# Service → Threat Actor associations (simplified)
_THREAT_ACTOR_MAP = {
    "smb":        ["Lazarus Group", "FIN7", "LockBit"],
    "rdp":        ["Conti", "REvil", "LockBit", "BlackCat"],
    "ssh":        ["APT28", "APT41", "Scatter Swine"],
    "ftp":        ["FIN7", "APT33"],
    "telnet":     ["Mirai botnet", "IoT threat actors"],
    "vnc":        ["LockBit", "Ransomware groups"],
    "mysql":      ["Skidmap miners", "SQL injection actors"],
    "redis":      ["Cryptojacking actors", "XMRig deployers"],
    "mongodb":    ["Meow ransomware", "Data ransom actors"],
    "elasticsearch": ["Bob/Meow ransomware", "Data exposure actors"],
}

# EPSS static estimates (low/med/high probability bands by severity)
# Real EPSS requires API; these are conservative estimates for offline use
_EPSS_ESTIMATES = {
    "critical": 0.25,
    "high":     0.10,
    "medium":   0.03,
    "low":      0.005,
}


def enrich_with_threat_intel(cves: list, services: list = None) -> dict:
    """
    Enrich a list of CVEs with threat intelligence.
    Returns enriched CVE list + summary stats.
    """
    enriched = []
    kev_found = []
    high_epss  = []

    for cve in cves:
        cve_id   = (cve.get("cve_id") or cve.get("id") or "").upper()
        severity = (cve.get("severity") or "medium").lower()

        # KEV check
        kev_entry = _KEV_DB.get(cve_id)
        is_kev    = kev_entry is not None

        # EPSS estimate (real API would give precise value)
        epss = float(cve.get("epss", 0) or 0)
        if epss == 0:
            epss = _EPSS_ESTIMATES.get(severity, 0.03)
        epss_label = "High" if epss >= 0.15 else "Medium" if epss >= 0.05 else "Low"

        # Threat actors
        service     = (cve.get("service") or "").lower()
        threat_actors = _THREAT_ACTOR_MAP.get(service, [])

        enriched_cve = {
            **cve,
            "is_kev":          is_kev,
            "kev_details":     kev_entry,
            "epss_score":      round(epss, 4),
            "epss_label":      epss_label,
            "epss_percentile": _epss_to_percentile(epss),
            "threat_actors":   threat_actors,
            "active_exploit":  is_kev or epss >= 0.15,
            "known_ransomware": kev_entry.get("known_ransomware", False) if kev_entry else False,
            "threat_priority": _compute_threat_priority(is_kev, epss, severity),
        }

        if is_kev:
            kev_found.append(cve_id)
        if epss >= 0.15:
            high_epss.append(cve_id)

        enriched.append(enriched_cve)

    # Sort: KEV + high EPSS first
    enriched.sort(key=lambda c: (
        -int(c["is_kev"]),
        -c["epss_score"],
        -{"critical":4,"high":3,"medium":2,"low":1}.get(
            c.get("severity","").lower(), 0)
    ))

    # Service-level threat context
    service_threats = {}
    if services:
        for svc in services:
            svc_lower = svc.lower() if svc else ""
            actors = _THREAT_ACTOR_MAP.get(svc_lower, [])
            if actors:
                service_threats[svc] = actors

    return {
        "enriched_cves":    enriched,
        "kev_cves":         kev_found,
        "high_epss_cves":   high_epss,
        "service_threats":  service_threats,
        "kev_count":        len(kev_found),
        "active_exploit_count": sum(1 for c in enriched if c["active_exploit"]),
        "ransomware_associated": sum(1 for c in enriched if c["known_ransomware"]),
        "threat_summary":   _build_threat_summary(enriched, kev_found),
    }


def lookup_kev(cve_id: str) -> Optional[dict]:
    """Check if a CVE is in CISA KEV catalog."""
    return _KEV_DB.get(cve_id.upper())


def get_threat_actors(service: str) -> list:
    """Get known threat actors targeting a service."""
    return _THREAT_ACTOR_MAP.get(service.lower(), [])


def _epss_to_percentile(epss: float) -> str:
    if epss >= 0.50: return "Top 5%"
    if epss >= 0.15: return "Top 15%"
    if epss >= 0.05: return "Top 35%"
    return "Bottom 50%"


def _compute_threat_priority(is_kev: bool, epss: float, severity: str) -> str:
    if is_kev:                  return "P0-Immediate"
    if epss >= 0.15:            return "P1-Critical"
    if severity == "critical":  return "P1-Critical"
    if severity == "high":      return "P2-High"
    if epss >= 0.05:            return "P2-High"
    if severity == "medium":    return "P3-Medium"
    return "P4-Low"


def _build_threat_summary(enriched: list, kev_found: list) -> str:
    if not enriched:
        return "No CVEs to analyze."
    kev_str  = f"{len(kev_found)} in CISA KEV (actively exploited)" if kev_found else "none in CISA KEV"
    high_str = sum(1 for c in enriched if c["epss_score"] >= 0.15)
    return (f"{len(enriched)} CVEs analyzed: {kev_str}. "
            f"{high_str} with high exploit probability (EPSS ≥ 15%).")
