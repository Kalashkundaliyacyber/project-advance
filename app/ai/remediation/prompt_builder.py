"""
ScanWise AI — Prompt Builder
Builds optimized prompts for Qwen/Llama remediation requests.
Uses grouped vulnerability data to minimize token usage.
"""
import json


# ── Structured JSON schema expected from AI ───────────────────────────────────

PATCH_JSON_SCHEMA = """{
  "service": "<service name>",
  "severity": "<critical|high|medium|low>",
  "affected_versions": ["<version string>"],
  "cves": ["<CVE-YYYY-NNNNN>"],
  "summary": "<2-3 sentence risk summary>",
  "risk": "<critical|high|medium|low>",
  "recommended_fixes": ["<specific actionable fix>"],
  "commands": ["<shell command>"],
  "verification_steps": ["<how to verify fix applied>"],
  "hardening_tips": ["<config hardening tip>"],
  "references": ["<official advisory URL>"]
}"""


def build_patch_prompt(service: str, port: int, version: str,
                       cve_id: str, severity: str) -> str:
    """Build a Qwen patch guidance prompt for a single service/CVE."""
    return f"""You are a cybersecurity hardening specialist. Generate patch guidance for this vulnerable service.

SERVICE: {service}
PORT: {port}
DETECTED VERSION: {version}
CVE: {cve_id}
SEVERITY: {severity}

Generate OS-aware remediation for Ubuntu/Debian, RHEL/CentOS, and Arch Linux where applicable.
Focus on defensive, actionable steps only. No offensive content.

Return ONLY this JSON schema, no markdown, no preamble:
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

    return f"""You are a cybersecurity hardening specialist. Generate consolidated patch guidance for this service group.

SERVICE: {service}
PORTS: {ports_str}
DETECTED VERSIONS: {versions_str}
SEVERITY: {summary.get('severity', 'medium').upper()}
CVSS: {summary.get('cvss', 0)}

VULNERABILITIES IN THIS GROUP:
{cve_list or "  - No specific CVEs detected; apply general hardening"}

Requirements:
- Generate OS-aware commands for Ubuntu/Debian, RHEL/CentOS, Arch Linux
- One consolidated remediation plan for ALL vulnerabilities in this group
- Actionable, copy-pasteable shell commands
- Defensive focus only

Return ONLY this JSON schema, no markdown, no preamble:
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
        "You are ScanWise AI, a defensive cybersecurity assistant. "
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
