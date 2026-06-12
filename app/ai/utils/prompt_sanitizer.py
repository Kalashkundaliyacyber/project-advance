"""
ThreatWeave — Prompt Sanitizer
Strips sensitive network identifiers (IPs, ports, hostnames) from any
text or dict before it is sent to a cloud AI provider (OpenRouter).

RULE:
  Local providers (Qwen, Llama via Ollama) run entirely on your machine,
  so they receive the full prompt unchanged.

  Cloud providers (OpenRouter) receive a sanitized prompt where:
    - IPv4 addresses      →  [HOST]
    - IPv6 addresses      →  [HOST]
    - Port numbers        →  [PORT]   (only in scan-context patterns)
    - Hostnames/FQDNs     →  [HOST]
    - Port/protocol pairs →  [PORT]/tcp  →  [PORT]/[PROTO]

  CVE IDs, service names, versions, severity, CVSS scores are kept intact
  because the AI needs them to generate useful patch guidance.

USAGE:
    from app.ai.utils.prompt_sanitizer import sanitize_for_cloud, is_cloud_provider

    if is_cloud_provider(provider_name):
        prompt = sanitize_for_cloud(prompt)
        system = sanitize_for_cloud(system)
"""
from __future__ import annotations
import re
import logging

logger = logging.getLogger("ThreatWeave.ai.sanitizer")

# ── Provider classification ────────────────────────────────────────────────────

_CLOUD_PROVIDERS = {"nemotron", "gpt_oss", "llama33", "gemma4", "deepseek_flash"}
_LOCAL_PROVIDERS = {"qwen", "llama", "ollama", "rule-based"}


def is_cloud_provider(provider_name: str) -> bool:
    """Return True if this provider sends data to an external API."""
    return provider_name.lower() in _CLOUD_PROVIDERS


# ── Regex patterns ─────────────────────────────────────────────────────────────

# IPv4: matches 0.0.0.0 – 255.255.255.255 (with optional CIDR)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:/\d{1,2})?\b"
)

# IPv6: simplified — catches common forms like ::1, fe80::1, 2001:db8::
_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
    r"|\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F:]*)\b"
    r"|\b::1\b"
)

# Port numbers in scan context:
#   "port 22", "22/tcp", "80/http", ":8080", "PORT: 443"
_PORT_LABEL   = re.compile(r"\bport[:\s]+(\d{1,5})\b", re.IGNORECASE)
_PORT_PROTO   = re.compile(r"\b(\d{1,5})/(tcp|udp|sctp|http|https|ftp|ssh)\b", re.IGNORECASE)
# :8080 socket notation — but not after space (already handled by PORT_LABEL)
# and not after [ (already replaced placeholder)
_PORT_COLON   = re.compile(r"(?<![\d\s\[]):(\d{1,5})\b")

# Hostname / FQDN — conservative: only replace when it looks like a network target
# Matches things like "myserver.internal", "dc01.corp.lan", "router.home"
# Does NOT match single bare words like "apache" or "ssh"
_HOSTNAME = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:local|internal|lan|corp|intranet|home|localdomain|priv|private"
    r"|io|com|net|org|gov|edu|co|uk|de|fr|jp|au|in|ca)\b",
    re.IGNORECASE,
)

# MAC address — not usually in prompts but strip if present
_MAC = re.compile(r"\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b")


# ── Public API ─────────────────────────────────────────────────────────────────

def sanitize_for_cloud(text: str) -> str:
    """
    Remove network identifiers from a prompt string before sending to cloud AI.
    Preserves CVE IDs, service names, versions, severity labels.
    """
    if not text:
        return text

    original_len = len(text)

    # Order matters: most-specific patterns first
    text = _MAC.sub("[MAC]", text)
    text = _IPV6.sub("[HOST]", text)
    text = _IPV4.sub("[HOST]", text)
    text = _HOSTNAME.sub("[HOST]", text)
    text = _PORT_PROTO.sub(r"[PORT]/\2", text)          # keep proto (tcp/udp)
    text = _PORT_LABEL.sub(r"port [PORT]", text)
    text = _PORT_COLON.sub(":[PORT]", text)

    stripped = original_len - len(text) + text.count("[HOST]") * 6 + text.count("[PORT]") * 6
    if stripped > 0:
        logger.debug(
            "prompt_sanitizer: stripped ~%d chars of network identifiers for cloud AI",
            stripped,
        )

    return text


def sanitize_messages_for_cloud(messages: list[dict]) -> list[dict]:
    """
    Sanitize a list of chat message dicts {role, content} for cloud AI.
    Returns a new list — does not mutate the originals.
    """
    return [
        {"role": m["role"], "content": sanitize_for_cloud(m.get("content", ""))}
        for m in messages
    ]


def sanitize_scan_context_for_cloud(scan_ctx: dict) -> dict:
    """
    Build a cloud-safe version of a scan context dict.
    Keeps: overall_risk, score, cve_count, project_name, scan_type, timestamp.
    Strips: target IP/hostname, per-port details with port numbers.
    Returns a NEW dict — original is not mutated.
    """
    if not scan_ctx:
        return {}

    risk_d    = scan_ctx.get("risk", {})
    cve_count = sum(
        len(p.get("cves", []))
        for h in risk_d.get("hosts", [])
        for p in h.get("ports", [])
    )

    # Collect only CVE-safe service info — no IPs, no port numbers
    services_safe = []
    for h in risk_d.get("hosts", []):
        for p in h.get("ports", []):
            service  = p.get("service", "unknown")
            product  = p.get("product", "")
            version  = p.get("version", "")
            risk_lvl = p.get("risk", {}).get("level", "low")
            cves     = [c.get("cve_id", "") for c in p.get("cves", [])[:3] if c.get("cve_id")]
            services_safe.append({
                "service":  service,
                "version":  f"{product} {version}".strip() or "unknown",
                "risk":     risk_lvl,
                "cves":     cves,
            })

    return {
        "project_name": scan_ctx.get("project_name", ""),
        "scan_type":    scan_ctx.get("scan_type", "unknown"),
        "timestamp":    scan_ctx.get("timestamp", ""),
        "overall_risk": risk_d.get("overall_risk", "unknown"),
        "overall_score": risk_d.get("overall_score", "-"),
        "cve_count":    cve_count,
        "services":     services_safe,   # no IPs, no port numbers
    }


def sanitize_scan_input_for_cloud(scan_input: dict) -> dict:
    """
    Sanitize the dict passed to build_analysis_prompt() for cloud AI.
    Removes 'host' IP, replaces port numbers with a generic index.
    Keeps: service name, version, exposure type, CVE IDs, version_status.
    """
    safe = dict(scan_input)
    safe.pop("host", None)          # remove target IP entirely
    safe.pop("os", None)            # OS fingerprint can hint at target identity

    services = safe.get("services", [])
    safe_services = []
    for svc in services:
        safe_services.append({
            "service":        svc.get("service", "unknown"),
            "version":        svc.get("version", "unknown"),
            "exposure":       svc.get("exposure", "unknown"),
            "cves":           svc.get("cves", []),          # CVE IDs — allowed
            "version_status": svc.get("version_status", "unknown"),
            # "port" intentionally omitted
        })
    safe["services"] = safe_services
    return safe
