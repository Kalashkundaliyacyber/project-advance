"""
ThreatWeave — AI Patch Formatter
==================================
Normalizes AI-generated patch data into the standard patch response schema.

CHANGES v2:
  - build_ai_prompt() now accepts os_hint param (default "ubuntu").
    The prompt template includes the target OS so the AI generates
    platform-specific commands.  All existing callers that omit os_hint
    get the same ubuntu-focused prompt as before.
"""
from __future__ import annotations


CONFIDENCE_AI = 70

AI_PATCH_PROMPT_TEMPLATE = """Generate patch guidance for this vulnerability.

CVE: {cve_id}
Service: {service}
Version: {version}
Target OS: {os_hint}
Description: {description}

Return ONLY this JSON (no markdown, no preamble):
{{
  "title": "brief CVE title",
  "fix_version": "minimum safe version or 'latest'",
  "patch_command": "<single shell command for {os_hint}>",
  "commands": {{
    "ubuntu/debian": "apt-get command",
    "rhel/centos": "yum/dnf command",
    "arch": "pacman command or N/A"
  }},
  "upgrade_path": "version upgrade instructions",
  "verification_steps": ["step 1", "step 2"],
  "rollback_steps": ["step 1", "step 2"],
  "vendor_url": "official advisory URL",
  "mitigation": "temporary workaround if no patch available",
  "patch_type": "upgrade|config|workaround|unknown",
  "notes": "any important warnings"
}}"""


def build_ai_prompt(
    cve_id:      str,
    service:     str,
    version:     str,
    description: str = "",
    os_hint:     str = "ubuntu",
) -> str:
    """
    Build the structured prompt for AI patch generation.

    Args:
        cve_id:      CVE identifier
        service:     Service/product name
        version:     Affected version string
        description: CVE description (truncated to 300 chars)
        os_hint:     Target OS for generated commands (default "ubuntu").
                     Existing callers that omit this param are unchanged.
    """
    return AI_PATCH_PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        service=service or "unknown",
        version=version or "unknown",
        os_hint=os_hint,
        description=(description[:300] if description else
                     f"Security vulnerability in {service} {version}"),
    )


def format_ai_patch(raw: dict, cve_id: str, service: str,
                    provider: str = "ai") -> dict:
    """
    Convert raw AI output dict into normalized patch response.
    """
    cmds = raw.get("commands") or raw.get("patch_command") or raw.get("patch_commands") or {}

    return {
        "cve_id":              cve_id.upper(),
        "service":             service,
        "title":               raw.get("title", f"Patch {service} for {cve_id}"),
        "fix_version":         raw.get("fix_version", "latest"),
        "commands":            cmds,
        "patch_command":       cmds,
        "patch_commands":      cmds,
        "upgrade_path":        raw.get("upgrade_path", ""),
        "verification_steps":  raw.get("verification_steps", []),
        "rollback_steps":      raw.get("rollback_steps", []),
        "vendor_url":          raw.get("vendor_url", ""),
        "official_url":        raw.get("vendor_url", ""),
        "mitigation":          raw.get("mitigation", ""),
        "patch_type":          raw.get("patch_type", "upgrade"),
        "notes":               raw.get("notes", ""),
        "references":          raw.get("references", []),
        "confidence":          CONFIDENCE_AI,
        "source":              "ai",
        "provider":            provider,
        "layer":               "ai",
        "ai_called":           True,
        "patch_found":         True,
    }
