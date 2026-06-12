"""
ThreatWeave — Prompt Builder
Builds optimized prompts for Qwen/Llama remediation requests.
Uses grouped vulnerability data to minimize token usage.
"""
import json


# ── Structured JSON schema expected from AI ───────────────────────────────────

PATCH_JSON_SCHEMA = """{
  "service": "<service name>",
  "severity": "<critical|high|medium|low>",
  "summary": "<one sentence risk summary>",
  "upgrade_command": "<apt/yum/pacman install command>",
  "restart_command": "<systemctl restart command>",
  "verify_command": "<command to verify fix>",
  "mitigation": "<one sentence mitigation if patch unavailable>",
  "engine": "ai"
}"""


def build_patch_prompt(service: str, port: int, version: str,
                       cve_id: str, severity: str) -> str:
    """Build a Qwen patch guidance prompt for a single service/CVE."""
    return f"""Fix this vulnerability. Return ONLY the JSON below, no extra text.

service={service} port={port} version={version} cve={cve_id} severity={severity}

{PATCH_JSON_SCHEMA}"""


def build_group_patch_prompt(service: str, summary: dict) -> str:
    """
    Build a Qwen prompt for a group of vulnerabilities on the same service.
    Generates ONE optimized remediation covering all CVEs in the group.
    """
    cve_list = "\n".join(
        f"  - {c.get('cve_id','unknown')} [{c.get('severity','?').upper()}] CVSS:{c.get('cvss_score',0)}: {c.get('description','')[:120]}"
        for c in summary.get("cves", [])[:8]
    )

    versions_str = ", ".join(summary.get("versions", ["unknown"])) or "unknown"
    ports_str = ", ".join(str(p) for p in summary.get("ports", []))

    return f"""Fix these vulnerabilities. Return ONLY the JSON below, no extra text.

service={service} ports={ports_str} versions={versions_str} severity={summary.get('severity','medium')}
cves={cve_list or "general hardening needed"}

{PATCH_JSON_SCHEMA}"""


def build_analysis_prompt(scan_input: dict) -> str:
    """Build Qwen scan analysis prompt."""
    return f"""You are an advanced network security analyst. Analyze this nmap scan data.

SCAN DATA:
{json.dumps(scan_input, indent=2)}

Identify open ports, running services, version information, CVE exposure, and risk posture.
Return ONLY this JSON schema — no markdown, no extra text:
{{
  "summary": "<2-3 sentence executive summary>",
  "overall_risk": "<critical|high|medium|low>",
  "findings": [{{"port": 0, "service": "", "version": "", "exposure": ""}}],
  "version_status": [{{"service": "", "version": "", "status": "<latest|outdated|unsupported|unknown>", "confidence": "<high|medium|low>", "note": ""}}],
  "cve_insight": [{{"service": "", "cve_id": "", "severity": "", "cvss_score": 0.0, "description": "", "confidence": ""}}],
  "risk_analysis": [{{"service": "", "port": 0, "risk_level": "", "score": 0.0, "reason": ""}}],
  "recommendations": [{{"service": "", "action": "", "priority": "<immediate|high|medium|low>"}}],
  "patches": [{{"service": "", "current_version": "", "recommended_version": "", "upgrade_command": "", "restart_command": "", "verify_command": ""}}],
  "next_scan": {{"type": "", "reason": "", "command_hint": ""}},
  "notes": []
}}"""


def build_chat_prompt(user_message: str, context: str = "") -> str:
    """Build Llama chat prompt with optional scan context."""
    base = (
        "You are ThreatWeave, a defensive cybersecurity assistant. "
        "Answer questions about network security, CVEs, and remediation. "
        "Never provide offensive techniques or exploit code."
    )
    if context:
        return f"{base}\n\nCurrent scan context:\n{context}\n\nUser: {user_message}"
    return f"{base}\n\nUser: {user_message}"


def build_summary_prompt(risk_data: dict) -> str:
    """Build executive summary prompt."""
    hosts = risk_data.get("hosts", [])
    total_ports = sum(len(h.get("ports", [])) for h in hosts)
    total_cves = sum(
        len(p.get("cves", [])) for h in hosts for p in h.get("ports", [])
    )
    return f"""Generate an executive security summary for this scan result.

Target: {risk_data.get('target', 'unknown')}
Overall risk: {risk_data.get('overall_risk', 'unknown')}
Hosts scanned: {len(hosts)}
Open services: {total_ports}
CVEs detected: {total_cves}

Write a concise 3-5 sentence executive summary suitable for a non-technical audience.
Focus on business risk and recommended next steps.
Return plain text only, no JSON."""
