"""
ThreatWeave — Vendor Patch Seed Data
=====================================
High-confidence vendor-confirmed patches seeded into patch_repository at startup.
Migrated from Gen1 patch_knowledge_base._SEED_PATCHES.

IMPORTANT: Do NOT import from app.remediation.* here.
This file is loaded during app.remediation package initialisation
(routes.py → app.remediation.__init__ → orchestrator → patch_repository → seed_data).
Any import from app.remediation at this point causes a circular import crash.
The constant 100 is CONFIDENCE_VENDOR — hardcoded to avoid that cycle.
"""

# CONFIDENCE_VENDOR = 100  (hardcoded — do NOT import from app.remediation.confidence)
_VENDOR = 100

SEED_PATCHES = [
    {
        "cve_id":        "CVE-2024-6387",
        "product":       "openssh",
        "vendor":        "openssh",
        "title":         "OpenSSH regreSSHion RCE (signal handler race)",
        "fix_version":   "9.8p1",
        "patch_command": {
            "ubuntu/debian": "apt-get update && apt-get install -y openssh-server",
            "rhel/centos":   "dnf update openssh",
            "arch":          "pacman -Syu openssh",
        },
        "commands": {
            "ubuntu/debian": "apt-get update && apt-get install -y openssh-server",
            "rhel/centos":   "dnf update openssh",
            "arch":          "pacman -Syu openssh",
        },
        "upgrade_path":       "Upgrade OpenSSH to 9.8p1 or later.",
        "vendor_url":         "https://www.openssh.com/txt/release-9.8",
        "official_url":       "https://www.openssh.com/txt/release-9.8",
        "mitigation":         "Set LoginGraceTime 0 in /etc/ssh/sshd_config as temporary mitigation.",
        "verification_steps": [
            "ssh -V  (confirm version >= 9.8p1)",
            "systemctl status sshd",
        ],
        "rollback_steps": [
            "apt-get install openssh-server=<previous_version>",
            "Restore sshd_config from backup.",
        ],
        "patch_type": "upgrade",
        "source":     "vendor",
        "confidence": _VENDOR,
    },
    {
        "cve_id":        "CVE-2023-38408",
        "product":       "openssh",
        "vendor":        "openssh",
        "title":         "OpenSSH ssh-agent Remote Code Execution",
        "fix_version":   "9.3p2",
        "patch_command": {
            "ubuntu/debian": "apt-get update && apt-get install -y openssh-server",
            "rhel/centos":   "yum update openssh",
            "arch":          "pacman -Syu openssh",
        },
        "commands": {
            "ubuntu/debian": "apt-get update && apt-get install -y openssh-server",
            "rhel/centos":   "yum update openssh",
            "arch":          "pacman -Syu openssh",
        },
        "upgrade_path":       "Upgrade OpenSSH to 9.3p2 or later.",
        "vendor_url":         "https://www.openssh.com/security.html",
        "official_url":       "https://www.openssh.com/security.html",
        "mitigation":         "Disable ssh-agent forwarding: AllowAgentForwarding no in sshd_config.",
        "verification_steps": [
            "ssh -V  (confirm version >= 9.3p2)",
            "grep AllowAgentForwarding /etc/ssh/sshd_config",
        ],
        "rollback_steps": [
            "apt-get install openssh-server=<previous_version>",
            "Restore sshd_config from backup.",
        ],
        "patch_type": "upgrade",
        "source":     "vendor",
        "confidence": _VENDOR,
    },
    {
        "cve_id":        "CVE-2021-41773",
        "product":       "apache",
        "vendor":        "apache",
        "title":         "Apache HTTP Server Path Traversal / RCE",
        "fix_version":   "2.4.50",
        "patch_command": {
            "ubuntu/debian": "apt-get update && apt-get install -y apache2",
            "rhel/centos":   "yum update httpd",
        },
        "commands": {
            "ubuntu/debian": "apt-get update && apt-get install -y apache2",
            "rhel/centos":   "yum update httpd",
        },
        "upgrade_path":       "Upgrade Apache HTTP Server to 2.4.50 or later.",
        "vendor_url":         "https://httpd.apache.org/security/vulnerabilities_24.html",
        "official_url":       "https://httpd.apache.org/security/vulnerabilities_24.html",
        "mitigation":         "Ensure 'Require all denied' is set in all Directory blocks.",
        "verification_steps": [
            "apache2 -v  (confirm version >= 2.4.50)",
            "systemctl status apache2",
        ],
        "rollback_steps": [
            "apt-get install apache2=<previous_version>",
            "Restore apache2.conf from backup.",
        ],
        "patch_type": "upgrade",
        "source":     "vendor",
        "confidence": _VENDOR,
    },
    {
        "cve_id":        "CVE-2021-23017",
        "product":       "nginx",
        "vendor":        "nginx",
        "title":         "nginx DNS resolver 1-byte memory overwrite",
        "fix_version":   "1.21.0",
        "patch_command": {
            "ubuntu/debian": "apt-get update && apt-get install -y nginx",
            "rhel/centos":   "yum update nginx",
        },
        "commands": {
            "ubuntu/debian": "apt-get update && apt-get install -y nginx",
            "rhel/centos":   "yum update nginx",
        },
        "upgrade_path":       "Upgrade nginx to 1.21.0 or later.",
        "vendor_url":         "https://nginx.org/en/security_advisories.html",
        "official_url":       "https://nginx.org/en/security_advisories.html",
        "mitigation":         "Use only local trusted DNS resolver; disable external resolver in nginx.conf.",
        "verification_steps": [
            "nginx -v  (confirm version >= 1.21.0)",
            "systemctl status nginx",
        ],
        "rollback_steps": [
            "apt-get install nginx=<previous_version>",
            "Restore nginx.conf from backup.",
        ],
        "patch_type": "upgrade",
        "source":     "vendor",
        "confidence": _VENDOR,
    },
    {
        "cve_id":        "CVE-2017-7494",
        "product":       "samba",
        "vendor":        "samba",
        "title":         "SambaCry Remote Code Execution",
        "fix_version":   "4.6.4",
        "patch_command": {
            "ubuntu/debian": "apt-get update && apt-get install -y samba",
            "rhel/centos":   "yum update samba",
        },
        "commands": {
            "ubuntu/debian": "apt-get update && apt-get install -y samba",
            "rhel/centos":   "yum update samba",
        },
        "upgrade_path":       "Upgrade Samba to 4.6.4 or later.",
        "vendor_url":         "https://www.samba.org/samba/security/CVE-2017-7494.html",
        "official_url":       "https://www.samba.org/samba/security/CVE-2017-7494.html",
        "mitigation":         "Add 'nt pipe support = no' to the [global] section of smb.conf.",
        "verification_steps": [
            "samba --version  (confirm version >= 4.6.4)",
            "systemctl status smbd",
        ],
        "rollback_steps": [
            "apt-get install samba=<previous_version>",
            "Restore smb.conf from backup.",
        ],
        "patch_type": "upgrade",
        "source":     "vendor",
        "confidence": _VENDOR,
    },
]
