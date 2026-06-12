"""
ThreatWeave — Vendor Advisory Models
======================================
Data models for normalized vendor security advisories.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VendorAdvisory:
    """Normalized vendor security advisory."""
    cve_id:          str
    vendor:          str
    product:         str
    affected_versions: list[str] = field(default_factory=list)
    fixed_version:   str = ""
    patch_commands:  dict = field(default_factory=dict)  # {os: command}
    advisory_url:    str = ""
    title:           str = ""
    severity:        str = "unknown"
    published:       str = ""
    confidence:      int = 100          # vendor = 100
    source:          str = "vendor"

    def to_dict(self) -> dict:
        return {
            "cve_id":           self.cve_id,
            "vendor":           self.vendor,
            "product":          self.product,
            "affected_version": ", ".join(self.affected_versions),
            "fixed_version":    self.fixed_version,
            "patch_command":    self.patch_commands,
            "commands":         self.patch_commands,
            "official_url":     self.advisory_url,
            "vendor_url":       self.advisory_url,
            "title":            self.title,
            "severity":         self.severity,
            "published":        self.published,
            "confidence":       self.confidence,
            "source":           self.source,
            "ai_called":        False,
            "layer":            "vendor",
            "patch_found":      True,
        }


# Vendor registry: maps service name patterns to vendor IDs
VENDOR_REGISTRY = {
    "ubuntu":    ["openssh", "apache", "nginx", "php", "mysql", "postgresql", "samba", "ftp"],
    "debian":    ["openssh", "apache", "nginx", "php", "mysql", "postgresql", "samba"],
    "redhat":    ["openssh", "apache", "nginx", "php", "mysql", "samba"],
    "microsoft": ["iis", "rdp", "smb", "exchange"],
    "cisco":     ["ios", "asa", "catalyst"],
    "apache":    ["httpd", "tomcat", "struts"],
    "nginx":     ["nginx"],
    "openssh":   ["openssh", "ssh"],
}

# Known vendor advisory URLs by service
VENDOR_ADVISORY_URLS = {
    "openssh":      "https://www.openssh.com/security.html",
    "apache":       "https://httpd.apache.org/security/vulnerabilities_24.html",
    "nginx":        "https://nginx.org/en/security_advisories.html",
    "ubuntu":       "https://ubuntu.com/security/notices",
    "debian":       "https://www.debian.org/security/",
    "redhat":       "https://access.redhat.com/security/security-updates/",
    "microsoft":    "https://msrc.microsoft.com/update-guide/",
    "cisco":        "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "samba":        "https://www.samba.org/samba/security/",
    "mysql":        "https://www.oracle.com/security-alerts/",
    "php":          "https://www.php.net/ChangeLog-8.php",
    "vsftpd":       "https://security.appspot.com/vsftpd.html",
    "proftpd":      "https://www.proftpd.org/docs/security.html",
}
