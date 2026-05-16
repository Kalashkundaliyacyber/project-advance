"""
ScanWise AI — Vulnerability Knowledge Base
Local structured knowledge: CVE→remediation mapping, exploitability scoring,
CIS hardening rules, service-specific remediation templates.

Why this matters:
  AI should ENHANCE remediation, not INVENT everything dynamically.
  A local knowledge base:
    - guarantees consistency across identical CVEs
    - reduces token usage by pre-populating known patches
    - eliminates hallucination for well-known CVEs
    - works completely offline
    - enables instant lookup (< 1ms vs 30–120s AI generation)

Architecture:
  CVE ID → lookup → KB entry → AI enhancement if needed
"""
from __future__ import annotations
import logging
from typing import Optional

logger = logging.getLogger("scanwise.ai.knowledge_base")

# ── CVE → Remediation Mapping ─────────────────────────────────────────────────
# Authoritative remediation for high-priority CVEs used across the scan engine.
# Fields: severity, cvss, fix_version, patch_command, description, references

CVE_REMEDIATION_MAP: dict[str, dict] = {
    # OpenSSH
    "CVE-2023-38408": {
        "service": "ssh", "severity": "critical", "cvss": 9.8,
        "title":   "OpenSSH ssh-agent RCE via PKCS#11 forwarding",
        "fix_version": "9.3p2",
        "patch_commands": {
            "ubuntu": "apt update && apt install --only-upgrade openssh-client openssh-server -y",
            "rhel":   "dnf update openssh -y",
        },
        "description": "Remote code execution when connecting to a malicious SSH server with agent forwarding enabled.",
        "mitigation":  "Disable ssh-agent forwarding: set ForwardAgent no in ~/.ssh/config",
        "references":  ["https://www.openssh.com/txt/release-9.3p2"],
    },
    "CVE-2024-6387": {
        "service": "ssh", "severity": "critical", "cvss": 8.1,
        "title":   "regreSSHion — OpenSSH GLIBC race condition RCE",
        "fix_version": "9.8p1",
        "patch_commands": {
            "ubuntu": "apt update && apt install --only-upgrade openssh-server -y",
            "rhel":   "dnf update openssh-server -y",
        },
        "description": "Signal handler race condition in OpenSSH's server (sshd) that allows unauthenticated RCE as root on glibc-based Linux.",
        "mitigation":  "Set LoginGraceTime 0 in sshd_config as temporary mitigation until patch is applied.",
        "references":  ["https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"],
    },
    # Apache HTTPd
    "CVE-2021-41773": {
        "service": "http", "severity": "critical", "cvss": 9.8,
        "title":   "Apache 2.4.49 path traversal and RCE",
        "fix_version": "2.4.51",
        "patch_commands": {
            "ubuntu": "apt update && apt install --only-upgrade apache2 -y",
            "rhel":   "dnf update httpd -y",
        },
        "description": "Path traversal allows reading files outside web root. With mod_cgi enabled, leads to RCE.",
        "mitigation":  "Upgrade immediately. Verify Require all denied in Directory blocks.",
        "references":  ["https://httpd.apache.org/security/vulnerabilities_24.html"],
    },
    "CVE-2021-42013": {
        "service": "http", "severity": "critical", "cvss": 9.8,
        "title":   "Incomplete fix for CVE-2021-41773 in Apache 2.4.50",
        "fix_version": "2.4.51",
        "patch_commands": {
            "ubuntu": "apt update && apt install --only-upgrade apache2 -y",
            "rhel":   "dnf update httpd -y",
        },
        "description": "The fix for CVE-2021-41773 in 2.4.50 was incomplete. Path traversal and RCE still possible.",
        "mitigation":  "Upgrade to 2.4.51+ immediately.",
        "references":  ["https://httpd.apache.org/security/vulnerabilities_24.html"],
    },
    # vsftpd
    "CVE-2011-2523": {
        "service": "ftp", "severity": "critical", "cvss": 10.0,
        "title":   "vsftpd 2.3.4 backdoor",
        "fix_version": "3.0.5",
        "patch_commands": {
            "ubuntu": "apt remove vsftpd -y && apt install vsftpd -y",
            "rhel":   "dnf remove vsftpd -y && dnf install vsftpd -y",
        },
        "description": "vsftpd 2.3.4 contains a supply-chain backdoor that opens a shell on port 6200.",
        "mitigation":  "Remove immediately. Never use vsftpd 2.3.4.",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    # MS17-010
    "CVE-2017-0144": {
        "service": "smb", "severity": "critical", "cvss": 9.8,
        "title":   "EternalBlue — SMBv1 RCE (MS17-010)",
        "fix_version": "KB4012212",
        "patch_commands": {
            "windows": "Install KB4012212 via Windows Update or WSUS",
        },
        "description": "Buffer overflow in SMBv1 enables unauthenticated RCE. Exploited by WannaCry and NotPetya.",
        "mitigation":  "Disable SMBv1 immediately: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        "references":  ["https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"],
    },
    # Log4Shell
    "CVE-2021-44228": {
        "service": "http", "severity": "critical", "cvss": 10.0,
        "title":   "Log4Shell — Apache Log4j2 RCE",
        "fix_version": "2.17.1",
        "patch_commands": {
            "ubuntu": "Update log4j2 dependency to 2.17.1+ in all Java applications",
        },
        "description": "JNDI injection in Log4j2 via user-controlled log input enables remote code execution.",
        "mitigation":  "Set log4j2.formatMsgNoLookups=true or upgrade to 2.17.1+",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
}

# ── CIS-style hardening rules by service ──────────────────────────────────────
# Deterministic hardening rules independent of AI generation.

CIS_RULES: dict[str, list[dict]] = {
    "ssh": [
        {"id": "CIS-SSH-1", "rule": "Disable root login", "command": "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config"},
        {"id": "CIS-SSH-2", "rule": "Disable password authentication", "command": "echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config"},
        {"id": "CIS-SSH-3", "rule": "Set MaxAuthTries to 3", "command": "echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config"},
        {"id": "CIS-SSH-4", "rule": "Set ClientAliveInterval", "command": "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config"},
        {"id": "CIS-SSH-5", "rule": "Restrict ciphers to strong only", "command": "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com' >> /etc/ssh/sshd_config"},
    ],
    "http": [
        {"id": "CIS-HTTP-1", "rule": "Disable server version disclosure", "command": "echo 'ServerTokens Prod' >> /etc/apache2/conf-available/security.conf"},
        {"id": "CIS-HTTP-2", "rule": "Disable directory listing", "command": "echo 'Options -Indexes' >> /etc/apache2/apache2.conf"},
        {"id": "CIS-HTTP-3", "rule": "Add X-Frame-Options header", "command": "echo 'Header always append X-Frame-Options SAMEORIGIN' >> /etc/apache2/conf-available/security.conf"},
        {"id": "CIS-HTTP-4", "rule": "Force HTTPS redirect", "command": "a2enmod rewrite ssl && systemctl restart apache2"},
    ],
    "ftp": [
        {"id": "CIS-FTP-1", "rule": "Disable anonymous FTP", "command": "echo 'anonymous_enable=NO' >> /etc/vsftpd.conf"},
        {"id": "CIS-FTP-2", "rule": "Enable SSL/TLS for FTP", "command": "echo 'ssl_enable=YES' >> /etc/vsftpd.conf"},
        {"id": "CIS-FTP-3", "rule": "Block FTP at firewall if unused", "command": "ufw deny 21/tcp"},
    ],
    "mysql": [
        {"id": "CIS-MYSQL-1", "rule": "Remove anonymous users", "command": "mysql -e \"DELETE FROM mysql.user WHERE User=''\""},
        {"id": "CIS-MYSQL-2", "rule": "Remove test database", "command": "mysql -e \"DROP DATABASE IF EXISTS test\""},
        {"id": "CIS-MYSQL-3", "rule": "Bind to localhost only", "command": "echo 'bind-address = 127.0.0.1' >> /etc/mysql/mysql.conf.d/mysqld.cnf"},
    ],
    "smb": [
        {"id": "CIS-SMB-1", "rule": "Disable SMBv1", "command": "echo 'min protocol = SMB2' >> /etc/samba/smb.conf"},
        {"id": "CIS-SMB-2", "rule": "Require message signing", "command": "echo 'server signing = mandatory' >> /etc/samba/smb.conf"},
    ],
    "redis": [
        {"id": "CIS-REDIS-1", "rule": "Require password authentication", "command": "echo 'requirepass CHANGE_THIS_STRONG_PASSWORD' >> /etc/redis/redis.conf"},
        {"id": "CIS-REDIS-2", "rule": "Bind to localhost only", "command": "sed -i 's/bind 0.0.0.0/bind 127.0.0.1/' /etc/redis/redis.conf"},
        {"id": "CIS-REDIS-3", "rule": "Disable dangerous commands", "command": "echo 'rename-command FLUSHALL \"\"' >> /etc/redis/redis.conf"},
    ],
    "rdp": [
        {"id": "CIS-RDP-1", "rule": "Enable Network Level Authentication", "command": "Set NLA via System Properties > Remote"},
        {"id": "CIS-RDP-2", "rule": "Restrict RDP to specific IPs via firewall", "command": "New-NetFirewallRule -DisplayName 'RDP Allow' -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress TRUSTED_IP -Action Allow"},
        {"id": "CIS-RDP-3", "rule": "Disable RDP if not required", "command": "Set-ItemProperty -Path 'HKLM:/System/CurrentControlSet/Control/Terminal Server' -Name 'fDenyTSConnections' -Value 1"},
    ],
}

# ── Exploitability scoring ─────────────────────────────────────────────────────
# Enriches CVE data with exploitability score based on known characteristics.

_KNOWN_EXPLOITED: set[str] = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-41773",  # Apache path traversal
    "CVE-2017-0144",   # EternalBlue
    "CVE-2011-2523",   # vsftpd backdoor
    "CVE-2023-38408",  # OpenSSH RCE
    "CVE-2024-6387",   # regreSSHion
    "CVE-2021-42013",  # Apache incomplete fix
}


def get_cve_remediation(cve_id: str) -> Optional[dict]:
    """
    Look up authoritative remediation for a CVE.
    Returns None if not in local KB (caller falls back to AI).
    """
    entry = CVE_REMEDIATION_MAP.get(cve_id)
    if entry:
        logger.debug("KB hit: %s", cve_id)
        return {
            **entry,
            "cve_id":          cve_id,
            "kb_hit":          True,
            "exploited_in_wild": cve_id in _KNOWN_EXPLOITED,
        }
    return None


def get_cis_rules(service: str) -> list[dict]:
    """Return CIS hardening rules for a service. Empty list if none known."""
    return CIS_RULES.get(service.lower(), [])


def score_exploitability(cve_id: str, cvss: float, service: str) -> dict:
    """
    Score exploitability 0.0–10.0 based on:
      - CVSS base score
      - Known active exploitation status
      - Service criticality
    """
    base    = cvss
    boost   = 1.5 if cve_id in _KNOWN_EXPLOITED else 0.0
    svc_mul = 1.1 if service.lower() in ("smb", "rdp", "ftp", "telnet") else 1.0
    score   = min(10.0, (base + boost) * svc_mul)
    return {
        "exploitability_score":   round(score, 1),
        "known_exploited":        cve_id in _KNOWN_EXPLOITED,
        "exploit_boost_applied":  boost > 0,
        "service_multiplier":     svc_mul,
    }


def normalize_cve_entry(raw: dict) -> dict:
    """
    Normalize a CVE entry from any source (local DB, NVD, AI) to a
    unified schema. Fills missing fields with safe defaults.
    """
    return {
        "cve_id":       raw.get("cve_id", "unknown"),
        "severity":     raw.get("severity", "medium"),
        "cvss":         float(raw.get("cvss", 0.0)),
        "description":  raw.get("description", ""),
        "patch":        raw.get("patch", raw.get("mitigation", "")),
        "published":    raw.get("published", ""),
        "references":   raw.get("references", []),
        "kb_hit":       raw.get("kb_hit", False),
    }
