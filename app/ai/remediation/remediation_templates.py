"""
ScanWise AI — Remediation Templates (Rule-Based Fallback)
Static deterministic remediation for common services.
Used when ALL AI providers fail — guarantees platform still works offline.
OS-aware: generates commands for Ubuntu/Debian, RHEL/CentOS, Arch Linux.
"""

# ── Service remediation templates ─────────────────────────────────────────────

TEMPLATES = {
    "ssh": {
        "summary": "SSH provides remote access. Ensure it is up-to-date and hardened.",
        "risk": "medium",
        "recommended_fixes": [
            "Upgrade OpenSSH to the latest stable version",
            "Disable root login: PermitRootLogin no in /etc/ssh/sshd_config",
            "Use key-based authentication only: PasswordAuthentication no",
            "Restrict SSH to specific users via AllowUsers directive",
            "Enable fail2ban to block brute-force attempts",
        ],
        "commands": {
            "ubuntu": "apt update && apt install --only-upgrade openssh-server -y",
            "rhel":   "dnf update openssh-server -y",
            "arch":   "pacman -Syu openssh --noconfirm",
        },
        "restart": "systemctl restart sshd",
        "verify":  "ssh -V",
        "hardening_tips": [
            "Set MaxAuthTries 3 in sshd_config",
            "Use AllowTcpForwarding no unless needed",
            "Set ClientAliveInterval 300 and ClientAliveCountMax 2",
        ],
        "references": [
            "https://www.openssh.com/security.html",
            "https://www.cisecurity.org/benchmark/distribution_independent_linux",
        ],
    },
    "http": {
        "summary": "Unencrypted HTTP exposes data in transit. Upgrade to HTTPS and patch the web server.",
        "risk": "medium",
        "recommended_fixes": [
            "Redirect all HTTP traffic to HTTPS",
            "Enable HSTS (Strict-Transport-Security header)",
            "Upgrade Apache/Nginx to the latest stable version",
            "Disable server version disclosure (ServerTokens Prod)",
            "Apply security headers: X-Frame-Options, CSP, X-Content-Type-Options",
        ],
        "commands": {
            "ubuntu": "apt update && apt install --only-upgrade apache2 nginx -y",
            "rhel":   "dnf update httpd nginx -y",
            "arch":   "pacman -Syu apache nginx --noconfirm",
        },
        "restart": "systemctl restart apache2 || systemctl restart nginx",
        "verify":  "apache2 -v || nginx -v",
        "hardening_tips": [
            "Enable ModSecurity WAF",
            "Disable directory listing: Options -Indexes",
            "Set upload file size limits",
        ],
        "references": [
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://nginx.org/en/security_advisories.html",
        ],
    },
    "https": {
        "summary": "HTTPS is in use. Verify TLS version and certificate configuration.",
        "risk": "low",
        "recommended_fixes": [
            "Ensure TLS 1.2+ only (disable TLS 1.0, 1.1, SSLv3)",
            "Use strong cipher suites (ECDHE + AES-GCM preferred)",
            "Verify certificate is valid and not self-signed in production",
            "Enable OCSP stapling",
            "Add HSTS with includeSubDomains and preload",
        ],
        "commands": {
            "ubuntu": "apt update && apt install --only-upgrade openssl -y",
            "rhel":   "dnf update openssl -y",
            "arch":   "pacman -Syu openssl --noconfirm",
        },
        "restart": "systemctl restart nginx || systemctl restart apache2",
        "verify":  "openssl s_client -connect localhost:443 -tls1_2",
        "hardening_tips": [
            "Test with SSL Labs: https://www.ssllabs.com/ssltest/",
            "Enable certificate transparency logging",
        ],
        "references": [
            "https://ssl-config.mozilla.org/",
            "https://www.ssllabs.com/projects/best-practices/",
        ],
    },
    "ftp": {
        "summary": "FTP transmits credentials and data in plaintext. Replace with SFTP immediately.",
        "risk": "high",
        "recommended_fixes": [
            "Replace FTP with SFTP (SSH File Transfer Protocol)",
            "If FTP must remain: enforce FTPS (FTP over TLS)",
            "Disable anonymous FTP login",
            "Restrict FTP to internal network via firewall",
            "Audit all FTP user accounts and remove unused ones",
        ],
        "commands": {
            "ubuntu": "apt remove vsftpd -y && apt install openssh-server -y",
            "rhel":   "dnf remove vsftpd -y && dnf install openssh-server -y",
            "arch":   "pacman -Rs vsftpd --noconfirm && pacman -S openssh --noconfirm",
        },
        "restart": "systemctl restart sshd",
        "verify":  "sftp localhost",
        "hardening_tips": [
            "Block port 21 via firewall: ufw deny 21",
            "Migrate all FTP users to SFTP accounts",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/search/results?query=vsftpd",
        ],
    },
    "telnet": {
        "summary": "Telnet is completely unencrypted. This is a critical risk — replace immediately with SSH.",
        "risk": "critical",
        "recommended_fixes": [
            "Remove telnet daemon immediately",
            "Install and configure OpenSSH as replacement",
            "Block port 23 via firewall",
            "Audit all remote access methods",
        ],
        "commands": {
            "ubuntu": "apt remove telnetd telnet -y && apt install openssh-server -y",
            "rhel":   "dnf remove telnet-server -y && dnf install openssh-server -y",
            "arch":   "pacman -Rs inetutils --noconfirm && pacman -S openssh --noconfirm",
        },
        "restart": "systemctl enable sshd && systemctl start sshd",
        "verify":  "ssh -V",
        "hardening_tips": [
            "ufw deny 23 && ufw allow 22",
            "Verify no telnet entries remain in /etc/inetd.conf or /etc/xinetd.d/",
        ],
        "references": [
            "https://www.cisa.gov/news-events/alerts/2022/09/27/cisa-releases-advisory-unencrypted-protocols",
        ],
    },
    "smb": {
        "summary": "SMB is a primary ransomware propagation vector. Harden or disable immediately.",
        "risk": "critical",
        "recommended_fixes": [
            "Block SMB ports (445, 139) at the network perimeter",
            "Disable SMBv1 completely",
            "Apply all Microsoft security patches for SMB",
            "Enable SMB signing",
            "Restrict SMB access to required hosts only",
        ],
        "commands": {
            "ubuntu": "apt update && apt install --only-upgrade samba -y",
            "rhel":   "dnf update samba -y",
            "arch":   "pacman -Syu samba --noconfirm",
        },
        "restart": "systemctl restart smbd nmbd",
        "verify":  "samba --version",
        "hardening_tips": [
            "Set 'min protocol = SMB2' in smb.conf",
            "Set 'server signing = mandatory' in smb.conf",
            "Use 'valid users' to restrict share access",
        ],
        "references": [
            "https://www.samba.org/samba/security/",
            "https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections",
        ],
    },
    "rdp": {
        "summary": "RDP exposed to the internet is critical risk for ransomware and credential attacks.",
        "risk": "critical",
        "recommended_fixes": [
            "Never expose RDP directly to the internet",
            "Place RDP behind a VPN",
            "Enable Network Level Authentication (NLA)",
            "Change default RDP port from 3389",
            "Enable account lockout policies",
        ],
        "commands": {
            "ubuntu": "ufw deny 3389 && ufw allow from 10.0.0.0/8 to any port 3389",
            "rhel":   "firewall-cmd --remove-port=3389/tcp --permanent && firewall-cmd --reload",
            "arch":   "ufw deny 3389",
        },
        "restart": "systemctl restart xrdp || net stop TermService && net start TermService",
        "verify":  "netstat -tlnp | grep 3389",
        "hardening_tips": [
            "Enable Windows Firewall RDP restrictions",
            "Require MFA for all RDP sessions",
            "Audit RDP event logs (Event ID 4625) for brute force",
        ],
        "references": [
            "https://www.cisa.gov/uscert/ncas/alerts/aa21-131a",
        ],
    },
    "mysql": {
        "summary": "Database exposed on network. Restrict access and upgrade to latest version.",
        "risk": "high",
        "recommended_fixes": [
            "Bind MySQL to localhost only (bind-address = 127.0.0.1)",
            "Remove anonymous accounts and test database",
            "Use strong passwords for all database users",
            "Upgrade MySQL to the latest stable version",
            "Enable MySQL audit logging",
        ],
        "commands": {
            "ubuntu": "apt update && apt install --only-upgrade mysql-server -y",
            "rhel":   "dnf update mysql-server -y",
            "arch":   "pacman -Syu mysql --noconfirm",
        },
        "restart": "systemctl restart mysql",
        "verify":  "mysql --version",
        "hardening_tips": [
            "Run mysql_secure_installation",
            "Set max_connect_errors = 5 in my.cnf",
            "Enable general_log for audit trail",
        ],
        "references": [
            "https://dev.mysql.com/doc/refman/8.0/en/security.html",
        ],
    },
    "snmp": {
        "summary": "SNMP with default community strings allows network reconnaissance and configuration changes.",
        "risk": "high",
        "recommended_fixes": [
            "Upgrade from SNMPv1/v2c to SNMPv3 (authentication + encryption)",
            "Change default community strings ('public', 'private')",
            "Restrict SNMP access to monitoring hosts only",
            "Disable SNMP write access if not required",
        ],
        "commands": {
            "ubuntu": "apt update && apt install --only-upgrade snmpd -y",
            "rhel":   "dnf update net-snmp -y",
            "arch":   "pacman -Syu net-snmp --noconfirm",
        },
        "restart": "systemctl restart snmpd",
        "verify":  "snmpd --version",
        "hardening_tips": [
            "Set rocommunity to something other than 'public'",
            "Add agentaddress 127.0.0.1 to restrict to local only",
        ],
        "references": [
            "https://www.cisa.gov/news-events/alerts/2017/06/05/reducing-risk-snmp-abuse",
        ],
    },
}

_DEFAULT_TEMPLATE = {
    "summary": "Apply latest security patches and review firewall rules for this service.",
    "risk": "medium",
    "recommended_fixes": [
        "Update the service to the latest stable version",
        "Restrict network access via firewall rules",
        "Review service configuration for security hardening",
        "Monitor service logs for anomalies",
    ],
    "commands": {
        "ubuntu": "apt update && apt upgrade -y",
        "rhel":   "dnf update -y",
        "arch":   "pacman -Syu --noconfirm",
    },
    "restart": "systemctl restart <service>",
    "verify":  "<service> --version",
    "hardening_tips": [
        "Apply principle of least privilege",
        "Enable logging and alerting",
    ],
    "references": [
        "https://nvd.nist.gov/",
    ],
}


def get_template(service: str, port: int = 0) -> dict:
    """Return the remediation template for a service. Defaults to generic template."""
    key = service.lower().strip()
    # Handle aliases
    aliases = {
        "apache": "http", "nginx": "https", "iis": "http",
        "openssh": "ssh", "samba": "smb", "mariadb": "mysql",
        "postgresql": "mysql",  # generic db template
    }
    key = aliases.get(key, key)
    return dict(TEMPLATES.get(key, _DEFAULT_TEMPLATE))


def build_patch_response(service: str, port: int, version: str,
                         cve_id: str = "unknown", severity: str = "medium",
                         os_hint: str = "ubuntu") -> dict:
    """
    Build a complete patch response dict from templates.
    Used as final fallback when all AI providers fail.
    """
    tmpl = get_template(service, port)
    cmds = tmpl.get("commands", {})

    # Pick OS-appropriate command
    os_key = "ubuntu"
    if any(k in os_hint.lower() for k in ("rhel", "centos", "fedora", "red hat")):
        os_key = "rhel"
    elif "arch" in os_hint.lower():
        os_key = "arch"

    upgrade_cmd = cmds.get(os_key, cmds.get("ubuntu", f"apt install --only-upgrade {service}"))

    # Enrich with CIS hardening rules from knowledge base
    try:
        from app.ai.remediation.knowledge_base import get_cis_rules
        cis_rules = get_cis_rules(service)
    except Exception:
        cis_rules = []

    return {
        "service":           service,
        "port":              port,
        "severity":          severity,
        "summary":           tmpl["summary"],
        "risk":              tmpl["risk"],
        "affected_versions": [version] if version and version != "unknown" else [],
        "cves":              [cve_id] if cve_id and cve_id != "unknown" else [],
        "recommended_fixes": tmpl["recommended_fixes"],
        "commands":          [upgrade_cmd, tmpl.get("restart", ""), tmpl.get("verify", "")],
        "verification_steps": [tmpl.get("verify", "")],
        "hardening_tips":    tmpl.get("hardening_tips", []),
        "cis_rules":         cis_rules,
        "references":        tmpl.get("references", []),
        # Legacy fields for backward compatibility
        "upgrade_command":   upgrade_cmd,
        "restart_command":   tmpl.get("restart", ""),
        "verify_command":    tmpl.get("verify", ""),
        "mitigation":        f"Restrict port {port} via firewall if patching is delayed.",
        "engine":            "rule-based-fallback",
    }
