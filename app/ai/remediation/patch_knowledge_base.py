"""
ThreatWeave — Patch Knowledge Base (Phase 5/23)
================================================
Local-first patch lookup before calling AI.
Confidence scoring:
  Vendor Advisory = 100
  NVD Reference   = 90
  AI Generated    = 70

Workflow: CVE → Local KB → Vendor Sources → NVD → AI → Save
Storage:  data/patch_kb/patches.json
"""
import json
import logging
import os
import threading
import time
from typing import Optional

logger = logging.getLogger("ThreatWeave.patch.kb")

_BASE_DIR   = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "patch_kb")
_KB_FILE    = os.path.join(_BASE_DIR, "patches.json")
_KB_TTL     = 30 * 24 * 3600   # 30 days — patches are stable

CONFIDENCE_VENDOR = 100
CONFIDENCE_NVD    = 90
CONFIDENCE_AI     = 70

# Pre-seeded knowledge base for common CVEs/services
# This reduces AI calls immediately without any network access
_SEED_PATCHES = {
    "openssh": {
        "CVE-2023-38408": {
            "service": "openssh", "cve": "CVE-2023-38408",
            "title": "OpenSSH ssh-agent Remote Code Execution",
            "fix_version": "9.3p2",
            "commands": {"ubuntu/debian": "apt-get update && apt-get install -y openssh-server",
                         "rhel/centos": "yum update openssh",
                         "arch": "pacman -Syu openssh"},
            "vendor_url": "https://www.openssh.com/security.html",
            "mitigation": "Disable ssh-agent forwarding if not needed: AllowAgentForwarding no",
            "confidence": CONFIDENCE_VENDOR,
            "source": "vendor",
        },
        "CVE-2024-6387": {
            "service": "openssh", "cve": "CVE-2024-6387",
            "title": "OpenSSH regreSSHion RCE (signal handler race)",
            "fix_version": "9.8p1",
            "commands": {"ubuntu/debian": "apt-get update && apt-get install -y openssh-server",
                         "rhel/centos": "dnf update openssh",
                         "arch": "pacman -Syu openssh"},
            "vendor_url": "https://www.openssh.com/txt/release-9.8",
            "mitigation": "Set LoginGraceTime 0 in /etc/ssh/sshd_config as temporary mitigation",
            "confidence": CONFIDENCE_VENDOR,
            "source": "vendor",
        },
    },
    "apache": {
        "CVE-2021-41773": {
            "service": "apache", "cve": "CVE-2021-41773",
            "title": "Apache HTTP Server Path Traversal / RCE",
            "fix_version": "2.4.50",
            "commands": {"ubuntu/debian": "apt-get update && apt-get install -y apache2",
                         "rhel/centos": "yum update httpd"},
            "vendor_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
            "mitigation": "Ensure 'Require all denied' in Directory blocks",
            "confidence": CONFIDENCE_VENDOR,
            "source": "vendor",
        },
    },
    "nginx": {
        "CVE-2021-23017": {
            "service": "nginx", "cve": "CVE-2021-23017",
            "title": "nginx DNS resolver 1-byte memory overwrite",
            "fix_version": "1.21.0",
            "commands": {"ubuntu/debian": "apt-get update && apt-get install -y nginx",
                         "rhel/centos": "yum update nginx"},
            "vendor_url": "https://nginx.org/en/security_advisories.html",
            "mitigation": "Use local trusted DNS resolver only",
            "confidence": CONFIDENCE_VENDOR,
            "source": "vendor",
        },
    },
    "samba": {
        "CVE-2017-7494": {
            "service": "samba", "cve": "CVE-2017-7494",
            "title": "SambaCry Remote Code Execution",
            "fix_version": "4.6.4",
            "commands": {"ubuntu/debian": "apt-get update && apt-get install -y samba",
                         "rhel/centos": "yum update samba"},
            "vendor_url": "https://www.samba.org/samba/security/CVE-2017-7494.html",
            "mitigation": "Add 'nt pipe support = no' to smb.conf [global]",
            "confidence": CONFIDENCE_VENDOR,
            "source": "vendor",
        },
    },
}


class PatchKnowledgeBase:
    """
    Local-first patch knowledge base.
    Seeded with common CVEs. Grows as AI generates patches.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict = {}      # cve_id → patch entry
        self._service_idx: dict = {}  # service → [cve_ids]
        os.makedirs(_BASE_DIR, exist_ok=True)
        self._load()
        self._seed()

    def lookup_cve(self, cve_id: str) -> Optional[dict]:
        """Return patch entry for CVE ID, or None."""
        with self._lock:
            return self._data.get(cve_id.upper())

    def lookup_service(self, service: str, version: str = "") -> list:
        """Return all known patches for a service."""
        svc = service.lower()
        with self._lock:
            cve_ids = self._service_idx.get(svc, [])
            patches = [self._data[c] for c in cve_ids if c in self._data]
        return patches

    def save_patch(self, cve_id: str, patch_data: dict,
                   source: str = "ai", confidence: int = CONFIDENCE_AI) -> None:
        """
        Save a patch entry (from AI or NVD). Confidence sets priority.
        Higher confidence entries are not overwritten by lower ones.
        """
        cve_upper = cve_id.upper()
        with self._lock:
            existing = self._data.get(cve_upper)
            if existing and existing.get("confidence", 0) >= confidence:
                return   # Don't overwrite better-sourced data
            entry = {
                **patch_data,
                "cve": cve_upper,
                "source": source,
                "confidence": confidence,
                "saved_at": time.time(),
            }
            self._data[cve_upper] = entry
            svc = entry.get("service", "").lower()
            if svc:
                self._service_idx.setdefault(svc, [])
                if cve_upper not in self._service_idx[svc]:
                    self._service_idx[svc].append(cve_upper)
        self._save_async()

    def stats(self) -> dict:
        with self._lock:
            total     = len(self._data)
            by_source = {}
            for e in self._data.values():
                s = e.get("source", "unknown")
                by_source[s] = by_source.get(s, 0) + 1
        return {"total_patches": total, "by_source": by_source,
                "services_indexed": len(self._service_idx)}

    # ── Internal ──────────────────────────────────────────────────────────────

    def _seed(self):
        """Load built-in seed data for common services."""
        count = 0
        for svc_patches in _SEED_PATCHES.values():
            for cve_id, patch in svc_patches.items():
                cve_upper = cve_id.upper()
                with self._lock:
                    if cve_upper not in self._data:
                        self._data[cve_upper] = {**patch, "cve": cve_upper, "saved_at": time.time()}
                        svc = patch.get("service", "").lower()
                        if svc:
                            self._service_idx.setdefault(svc, [])
                            if cve_upper not in self._service_idx[svc]:
                                self._service_idx[svc].append(cve_upper)
                        count += 1
        if count:
            logger.info("Patch KB seeded with %d built-in entries", count)

    def _load(self):
        try:
            if os.path.exists(_KB_FILE):
                with open(_KB_FILE) as f:
                    saved = json.load(f)
                self._data      = saved.get("patches", {})
                self._service_idx = saved.get("service_index", {})
                logger.info("Patch KB loaded: %d entries", len(self._data))
        except Exception as e:
            logger.warning("Patch KB load failed: %s — starting fresh", e)

    def _save_async(self):
        threading.Thread(target=self._save, daemon=True).start()

    def _save(self):
        try:
            with self._lock:
                payload = {"patches": dict(self._data), "service_index": dict(self._service_idx)}
            os.makedirs(os.path.dirname(_KB_FILE), exist_ok=True)
            with open(_KB_FILE, "w") as f:
                json.dump(payload, f, indent=2)
            logger.debug("Patch KB saved: %d entries to %s", len(self._data), _KB_FILE)
        except Exception as e:
            logger.warning("Patch KB save failed: %s", e)


# Singleton
patch_kb = PatchKnowledgeBase()
