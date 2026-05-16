"""
ScanWise AI — AI Analysis Module v5.1
Redesigned to use new modular AI architecture.

PRIMARY:  Qwen2.5-Coder 3B (via Ollama)
CHAT:     Llama 3.2 1B     (via Ollama)
CLOUD:    Gemini            (emergency only)
FINAL:    Rule-based engine (offline guarantee)

Llama 3.2 3B REMOVED — redundant, wastes RAM, adds fallback latency.
"""
import json
import logging

from app.ai.routing.ai_router           import ai_router
from app.ai.remediation.patch_generator  import get_patch_guidance, get_group_patch_guidance
from app.ai.remediation.prompt_builder   import build_analysis_prompt, build_summary_prompt
from app.ai.utils.json_sanitizer         import safe_parse_json

logger = logging.getLogger("scanwise.ai_analysis")


def analyze_scan(data: dict) -> dict:
    """
    Analyse parsed scan data with AI.
    Primary: Qwen2.5-Coder → Llama → Gemini → rule-based fallback.
    """
    try:
        scan_input = _build_prompt_input(data)
        prompt     = build_analysis_prompt(scan_input)
        system     = (
            "You are an advanced cybersecurity analyst. "
            "Return ONLY valid JSON matching the schema. "
            "No markdown fences, no preamble, no explanation text."
        )
        text, provider = ai_router.generate(
            prompt, system=system, expect_json=True, max_tokens=4096
        )
        result = safe_parse_json(text)
        if not isinstance(result, dict) or not result:
            raise ValueError(f"AI returned invalid JSON from {provider}")

        result["engine"] = provider
        logger.info("AI analysis complete via %s", provider)
        return result

    except Exception as e:
        logger.warning("AI analysis failed, using rule-based: %s", e)
        result = _rule_based_analyze(data)
        result["engine"]          = "rule-based-fallback"
        result["fallback_reason"] = str(e)
        return result


def explain_cve(cve_id: str, service: str, version: str = "unknown") -> dict:
    """Get AI explanation of a specific CVE."""
    prompt = f"""Explain this CVE from a defensive security perspective.
CVE: {cve_id}
Service: {service}
Detected version: {version}

Return ONLY this JSON:
{{
  "cve_id": "{cve_id}",
  "title": "<short title>",
  "severity": "<critical|high|medium|low>",
  "cvss_score": 0.0,
  "attack_vector": "<network|adjacent|local|physical>",
  "description": "<2-3 sentence defensive-focused explanation>",
  "affected_versions": "<version range>",
  "fixed_in": "<fixed version>",
  "mitigation": "<specific defensive action>",
  "references": ["<URL>"]
}}"""
    system = "You are a cybersecurity analyst. Return ONLY valid JSON. No markdown."

    try:
        text, provider = ai_router.generate(
            prompt, system=system, expect_json=True, max_tokens=1024
        )
        result = safe_parse_json(text)
        if isinstance(result, dict) and result:
            result["engine"] = provider
            return result
        raise ValueError("Invalid JSON")
    except Exception as e:
        logger.warning("CVE explain AI failed: %s", e)
        return {
            "cve_id":      cve_id,
            "title":       f"CVE explanation for {cve_id}",
            "severity":    "unknown",
            "description": f"Unable to fetch CVE details. Consult https://nvd.nist.gov/vuln/detail/{cve_id}",
            "mitigation":  f"Apply latest patches for {service}.",
            "engine":      "rule-based-fallback",
            "error":       str(e),
        }


def get_executive_summary(risk_data: dict) -> str:
    """Generate plain-text executive summary using Qwen."""
    try:
        prompt         = build_summary_prompt(risk_data)
        text, provider = ai_router.generate(
            prompt,
            system="You are a cybersecurity consultant. Write clear concise executive summaries.",
            expect_json=False, max_tokens=512
        )
        logger.info("Executive summary via %s", provider)
        return text.strip()
    except Exception as e:
        logger.warning("Executive summary failed: %s", e)
        return (
            f"Scan complete. Risk level: {risk_data.get('overall_risk', 'unknown').upper()}. "
            "Review findings and apply recommended patches immediately."
        )


def _build_prompt_input(data: dict) -> dict:
    if "services" in data and "host" in data:
        return data
    hosts = data.get("hosts", [])
    if not hosts:
        return {"host": "unknown", "services": []}
    host     = hosts[0]
    services = []
    for port in host.get("ports", []):
        va = port.get("version_analysis", {})
        services.append({
            "port":           port.get("port"),
            "service":        port.get("service", "unknown"),
            "version":        f"{port.get('product','')} {port.get('version','')}".strip() or "unknown",
            "exposure":       port.get("context", {}).get("exposure_type", "unknown"),
            "cves":           [c["cve_id"] for c in port.get("cves", [])[:3]],
            "version_status": va.get("status", "unknown"),
        })
    return {
        "host":     host.get("ip", "unknown"),
        "os":       host.get("os", {}).get("name", "unknown") if host.get("os") else "unknown",
        "services": services,
    }


def _rule_based_analyze(data: dict) -> dict:
    """Rule-based fallback — no AI dependency, always works."""
    prompt_input = _build_prompt_input(data)
    services     = prompt_input.get("services", [])

    findings, version_status, cve_insight, risk_analysis, recommendations, patches = [], [], [], [], [], []

    RISK_SERVICES = {
        "ftp":    ("high",     "FTP transmits credentials in plaintext"),
        "telnet": ("critical", "Telnet is unencrypted remote access"),
        "ssh":    ("medium",   "SSH is high-value but generally secure if patched"),
        "http":   ("medium",   "Unencrypted web traffic"),
        "https":  ("low",      "Encrypted web traffic — verify TLS version"),
        "mysql":  ("high",     "Database exposure — restrict to internal only"),
        "smb":    ("critical", "SMB is a primary ransomware vector"),
        "rdp":    ("critical", "RDP should never be exposed to the internet"),
        "snmp":   ("high",     "SNMPv1/v2c uses plaintext community strings"),
    }
    PATCH_CMDS = {
        "ftp":    ("apt update && apt install --only-upgrade vsftpd", "systemctl restart vsftpd", "vsftpd -v"),
        "telnet": ("apt remove telnetd && apt install openssh-server", "systemctl restart ssh", "ssh -V"),
        "ssh":    ("apt update && apt install --only-upgrade openssh-server", "systemctl restart ssh", "ssh -V"),
        "http":   ("apt update && apt install --only-upgrade apache2", "systemctl restart apache2", "apache2 -v"),
        "https":  ("apt update && apt install --only-upgrade nginx", "systemctl restart nginx", "nginx -v"),
        "mysql":  ("apt update && apt install --only-upgrade mysql-server", "systemctl restart mysql", "mysql --version"),
        "smb":    ("apt update && apt install --only-upgrade samba", "systemctl restart smbd", "samba --version"),
        "rdp":    ("Enable NLA in System Properties > Remote", "net stop termservice && net start termservice", "qwinsta"),
        "snmp":   ("apt update && apt install --only-upgrade snmpd", "systemctl restart snmpd", "snmpd --version"),
    }
    OUTDATED_HINTS = {
        "2.2": "outdated", "2.0": "unsupported", "5.5": "unsupported",
        "5.6": "unsupported", "7.": "outdated", "6.": "unsupported", "2.3.4": "unsupported",
    }
    overall_scores = []

    for svc in services:
        port     = svc.get("port", 0)
        name     = svc.get("service", "unknown")
        version  = svc.get("version", "unknown")
        exposure = svc.get("exposure", "unknown")

        findings.append({"port": port, "service": name, "version": version, "exposure": exposure})

        v_status = "unknown"
        for hint, status in OUTDATED_HINTS.items():
            if hint in version:
                v_status = status
                break
        version_status.append({
            "service": name, "version": version, "status": v_status,
            "confidence": "medium" if v_status != "unknown" else "low",
            "note": f"Version pattern matched as {v_status}" if v_status != "unknown" else "Run version_deep scan",
        })

        if "2.3.4" in version and name == "ftp":
            cve_insight.append({"service": name, "cve_id": "CVE-2011-2523", "severity": "critical",
                                 "cvss_score": 10.0, "description": "vsftpd 2.3.4 backdoor — remove immediately", "confidence": "high"})
        elif "2.2" in version and name in ("http", "https"):
            cve_insight.append({"service": name, "cve_id": "CVE-2017-7679", "severity": "critical",
                                 "cvss_score": 9.8, "description": "Apache 2.2 EOL with critical vulnerabilities", "confidence": "high"})
        else:
            cve_insight.append({"service": name, "cve_id": "unknown", "severity": "unknown",
                                 "cvss_score": 0.0, "description": "Run version_deep scan for CVE matching", "confidence": "low"})

        risk_level, reason = RISK_SERVICES.get(name, ("low", "Non-standard service"))
        score = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0}.get(risk_level, 2.0)
        if v_status == "unsupported": score = min(score + 1.5, 10.0)
        if v_status == "outdated":    score = min(score + 0.8, 10.0)
        actual = "critical" if score >= 8.5 else "high" if score >= 6.5 else "medium" if score >= 4.0 else "low"

        risk_analysis.append({"service": name, "port": port, "risk_level": actual, "score": round(score, 1), "reason": reason})
        overall_scores.append(score)
        recommendations.append({"service": name, "action": f"Apply latest patches for port {port}/{name}.", "priority": actual})

        if name in PATCH_CMDS:
            upg, rst, vrfy = PATCH_CMDS[name]
            patches.append({"service": name, "current_version": version,
                             "recommended_version": "latest stable",
                             "upgrade_command": upg, "restart_command": rst, "verify_command": vrfy})

    has_no_ver = any(s.get("version", "unknown") in ("unknown", "") for s in services)
    has_crit   = any(r["risk_level"] == "critical" for r in risk_analysis)
    next_scan  = (
        {"type": "service_detect",  "reason": "Some services have no version info.", "command_hint": "nmap -sV -T3 --open"} if has_no_ver else
        {"type": "enum_scripts",    "reason": "Critical risks found — NSE scripts needed.", "command_hint": "nmap -sC -sV -T3"} if has_crit else
        {"type": "udp_scan",        "reason": "TCP complete — check UDP services.", "command_hint": "nmap -sU --top-ports 100 -T3"}
    )

    max_score = max(overall_scores) if overall_scores else 0
    overall   = "critical" if max_score >= 8.5 else "high" if max_score >= 6.5 else "medium" if max_score >= 4.0 else "low"
    n         = len(services)
    crit_n    = sum(1 for r in risk_analysis if r["risk_level"] == "critical")

    return {
        "findings": findings, "version_status": version_status, "cve_insight": cve_insight,
        "risk_analysis": risk_analysis, "recommendations": recommendations,
        "patches": patches, "next_scan": next_scan,
        "notes": [
            "Rule-based fallback — no AI provider available.",
            "Run setup_env.sh to install Ollama and pull qwen2.5-coder:3b + llama3.2:1b",
        ],
        "engine":       "rule-based",
        "overall_risk": overall,
        "summary": (
            f"Scan found {n} open service(s) on {prompt_input.get('host','target')}. "
            f"{crit_n} critical risk(s) identified. "
            f"{'Immediate remediation required.' if crit_n > 0 else 'Review recommendations and apply patches.'}"
        ),
    }
