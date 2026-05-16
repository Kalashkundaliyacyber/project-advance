"""
ScanWise AI — Risk Correlation Engine
Correlates isolated findings into attack chains, exploit paths,
and privilege escalation sequences.

Why this matters:
  Real attackers chain vulnerabilities together.
  FTP anonymous login + weak SSH + outdated Apache = full compromise path.
  Without correlation, scanners show isolated findings with no attack narrative.

Architecture:
  1. Port/service data → Chain builder
  2. Chain builder → Scored attack paths
  3. Attack paths → Aggregated risk (chain score > individual scores)
  4. Chain narrative → surfaced in reports and chat
"""
from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger("scanwise.correlation")

# ── Attack chain rules ────────────────────────────────────────────────────────
# Each rule defines:
#   services:  set of service names that form the chain (match any subset >= 2)
#   ports:     optional port numbers that trigger this chain
#   name:      human-readable chain name
#   score:     aggregate risk boost (added to max individual score)
#   narrative: description for reports and chat
#   privesc:   does this chain enable privilege escalation?

CHAIN_RULES = [
    {
        "id":       "anon_ftp_ssh_rce",
        "services": {"ftp", "ssh"},
        "name":     "Anonymous FTP + SSH pivot",
        "score":    9.5,
        "narrative": (
            "Anonymous FTP access allows an attacker to read/write files. "
            "Combined with SSH access (even with password auth), stolen credentials "
            "or planted SSH keys enable full remote code execution."
        ),
        "privesc": True,
        "tags":    ["lateral_movement", "credential_theft", "rce"],
    },
    {
        "id":       "web_db_chain",
        "services": {"http", "mysql"},
        "name":     "Web + Database exposure",
        "score":    9.0,
        "narrative": (
            "An exposed web service combined with a directly accessible database "
            "creates a classic SQL injection → data exfiltration chain. "
            "If the web app has SSRF or RCE, database compromise is trivial."
        ),
        "privesc": False,
        "tags":    ["sqli", "data_exfil", "web"],
    },
    {
        "id":       "web_db_postgres",
        "services": {"http", "postgresql"},
        "name":     "Web + PostgreSQL exposure",
        "score":    9.0,
        "narrative": (
            "Exposed PostgreSQL alongside a web service enables SQL injection attacks "
            "and potential COPY TO/FROM PROGRAM for OS command execution."
        ),
        "privesc": True,
        "tags":    ["sqli", "rce", "postgres"],
    },
    {
        "id":       "telnet_rce",
        "services": {"telnet"},
        "name":     "Plaintext Telnet (standalone critical)",
        "score":    9.8,
        "narrative": (
            "Telnet exposes credentials in plaintext. Any network position "
            "between client and server enables credential capture and session hijacking."
        ),
        "privesc": True,
        "tags":    ["credential_theft", "mitm"],
    },
    {
        "id":       "smb_lateral",
        "services": {"smb"},
        "name":     "SMB lateral movement",
        "score":    9.5,
        "narrative": (
            "Exposed SMB enables EternalBlue, credential relay (NTLM), and ransomware "
            "deployment. Combined with any credential-theft vector this is a full "
            "network compromise path."
        ),
        "privesc": True,
        "tags":    ["ransomware", "lateral_movement", "ntlm_relay"],
    },
    {
        "id":       "rdp_privesc",
        "services": {"rdp"},
        "name":     "RDP remote desktop pivot",
        "score":    9.3,
        "narrative": (
            "Exposed RDP provides full graphical access. BlueKeep and DejaBlue "
            "(CVE-2019-0708, CVE-2019-1182) enable unauthenticated RCE. "
            "Credential stuffing via RDP is a primary ransomware entry vector."
        ),
        "privesc": True,
        "tags":    ["rce", "ransomware", "lateral_movement"],
    },
    {
        "id":       "redis_rce",
        "services": {"redis"},
        "name":     "Unauthenticated Redis RCE",
        "score":    9.8,
        "narrative": (
            "Redis without authentication allows arbitrary data writes. "
            "Attackers write SSH authorized_keys, cron jobs, or PHP webshells "
            "to achieve remote code execution with the Redis process owner privileges."
        ),
        "privesc": True,
        "tags":    ["rce", "config_write"],
    },
    {
        "id":       "mongodb_exfil",
        "services": {"mongodb"},
        "name":     "Unauthenticated MongoDB data exfiltration",
        "score":    9.0,
        "narrative": (
            "MongoDB exposed without authentication enables full database dump "
            "by any network-accessible attacker. PII, credentials, and application "
            "data are at immediate risk."
        ),
        "privesc": False,
        "tags":    ["data_exfil", "no_auth"],
    },
    {
        "id":       "snmp_recon_pivot",
        "services": {"snmp", "ssh"},
        "name":     "SNMP reconnaissance + SSH pivot",
        "score":    8.5,
        "narrative": (
            "SNMP v1/v2c with default community strings discloses network topology, "
            "running processes, and credentials. This intelligence dramatically "
            "accelerates targeted SSH brute-force or targeted exploitation."
        ),
        "privesc": False,
        "tags":    ["recon", "information_disclosure"],
    },
    {
        "id":       "ldap_domain_takeover",
        "services": {"ldap", "smb"},
        "name":     "LDAP + SMB domain compromise",
        "score":    9.9,
        "narrative": (
            "LDAP exposure alongside SMB enables full Active Directory enumeration "
            "and NTLM relay attacks. Combined with any credential leak, this path "
            "leads to domain admin compromise."
        ),
        "privesc": True,
        "tags":    ["ad_attack", "ntlm_relay", "domain_takeover"],
    },
    {
        "id":       "ftp_web_deface",
        "services": {"ftp", "http"},
        "name":     "FTP write + Web defacement/shell",
        "score":    9.2,
        "narrative": (
            "FTP write access to web root (a common misconfiguration) allows "
            "uploading webshells, defacing sites, or planting malware served "
            "to all site visitors."
        ),
        "privesc": False,
        "tags":    ["webshell", "defacement"],
    },
]

# Map service name aliases → canonical names
_SERVICE_ALIASES: dict[str, str] = {
    "microsoft-ds": "smb",
    "netbios-ssn":  "smb",
    "ms-wbt-server":"rdp",
    "domain":       "dns",
    "http-proxy":   "http",
    "https":        "http",   # treat HTTPS as http for chain matching
    "mysql":        "mysql",
    "postgres":     "postgresql",
    "ms-sql-s":     "mssql",
}


def _normalize_service(svc: str) -> str:
    s = svc.lower().strip()
    return _SERVICE_ALIASES.get(s, s)


def correlate(risk_data: dict) -> dict:
    """
    Main entry point.
    Input:  risk_data from calculate_risk() — contains hosts[].ports[]
    Output: risk_data enriched with:
              attack_chains: list of matched chain dicts
              chain_risk:    highest chain score
              chain_summary: one-line summary for the dashboard
    """
    # Collect all normalized services across all hosts
    all_services: set[str] = set()
    host_service_map: dict[str, list[str]] = {}  # ip → [services]

    for host in risk_data.get("hosts", []):
        ip  = host.get("ip", "unknown")
        svcs: list[str] = []
        for port in host.get("ports", []):
            svc = _normalize_service(port.get("service", ""))
            if svc:
                svcs.append(svc)
                all_services.add(svc)
        host_service_map[ip] = svcs

    matched_chains: list[dict[str, Any]] = []

    for rule in CHAIN_RULES:
        required = rule["services"]

        # Single-service rules (e.g. telnet standalone)
        if len(required) == 1:
            if required & all_services:
                matched_chains.append(_build_chain_entry(rule, list(required & all_services), host_service_map))
            continue

        # Multi-service: need at least 2 matching services
        matched_svcs = required & all_services
        if len(matched_svcs) >= 2:
            matched_chains.append(_build_chain_entry(rule, list(matched_svcs), host_service_map))
        elif len(matched_svcs) == 1 and len(required) == 2:
            # Partial match — surface as warning only if score >= 8
            if rule["score"] >= 8.0:
                partial = _build_chain_entry(rule, list(matched_svcs), host_service_map)
                partial["partial"] = True
                partial["score"]   = round(rule["score"] * 0.5, 1)
                partial["narrative"] = f"[Partial chain — missing: {list(required - all_services)}] " + rule["narrative"]
                matched_chains.append(partial)

    # Sort by score descending
    matched_chains.sort(key=lambda c: c["score"], reverse=True)

    chain_risk = matched_chains[0]["score"] if matched_chains else 0.0
    privesc    = any(c.get("privesc") for c in matched_chains)

    if matched_chains:
        top = matched_chains[0]
        summary = f"⚠ {len(matched_chains)} attack chain(s) detected. Highest: {top['name']} (score {top['score']})"
    else:
        summary = "No multi-vector attack chains detected."

    enriched = dict(risk_data)
    enriched["attack_chains"]  = matched_chains
    enriched["chain_risk"]     = chain_risk
    enriched["chain_summary"]  = summary
    enriched["privesc_risk"]   = privesc

    if matched_chains:
        logger.info(
            "Correlation: %d chain(s) detected. Top: %s (score=%.1f)",
            len(matched_chains), matched_chains[0]["name"], chain_risk,
        )
    return enriched


def _build_chain_entry(rule: dict, matched_services: list[str],
                       host_map: dict[str, list[str]]) -> dict:
    """Build a chain result entry."""
    # Find which hosts contribute to this chain
    involved_hosts: list[str] = []
    for ip, svcs in host_map.items():
        if any(s in matched_services for s in svcs):
            involved_hosts.append(ip)

    return {
        "chain_id":        rule["id"],
        "name":            rule["name"],
        "score":           rule["score"],
        "narrative":       rule["narrative"],
        "matched_services":matched_services,
        "involved_hosts":  involved_hosts,
        "privesc":         rule.get("privesc", False),
        "tags":            rule.get("tags", []),
        "partial":         False,
        "remediation_priority": "CRITICAL" if rule["score"] >= 9.0 else "HIGH",
    }
