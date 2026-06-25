"""
auth_scanner.py
================
Phase 7 of the reconstruction — optional authenticated scanning.

This module does NOTHING unless credentials are explicitly provided at scan
time (request body fields, not a slash command — same rule Phase 0 set for
the rest of the pipeline). With no credentials, run_auth_checks() returns an
empty list immediately and never blocks or slows the pipeline.

Both SSH and SMB support degrade gracefully if their library isn't
installed (paramiko / impacket-or-smbprotocol) — logs a clear reason and
returns no findings for that half, rather than crashing the scan.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger("ThreatWeave.auth_scanner")

# Same finding shape every other module in this pipeline returns
# (misconfig_checker, soplib) — {type, name, severity, evidence, remediation}.


def _finding(name: str, severity: str, evidence: str, remediation: str) -> dict:
    return {
        "type": "AUTHENTICATED_FINDING",
        "name": name,
        "severity": severity,
        "evidence": evidence[:1000],
        "remediation": remediation,
    }


# ── SSH checks ───────────────────────────────────────────────────────────────

def _ssh_checks(target: str, username: str, password: str | None, key_path: str | None,
                 known_external_ports: set[int]) -> list[dict]:
    try:
        import paramiko
    except ImportError:
        logger.warning("auth_scanner: paramiko not installed — skipping SSH checks "
                        "(`pip install paramiko` to enable)")
        return []

    findings: list[dict] = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs = {"username": username, "timeout": 10, "banner_timeout": 10}
        if key_path:
            connect_kwargs["key_filename"] = key_path
        else:
            connect_kwargs["password"] = password
        client.connect(target, **connect_kwargs)
    except Exception as e:
        logger.warning("auth_scanner: SSH connect to %s failed: %s", target, e)
        return [_finding(
            "ssh_auth_failed", "LOW",
            f"Could not authenticate to {target} via SSH with the provided credentials: {e}",
            "Verify the username/password/key path provided to the scanner are correct.",
        )]

    def _run(cmd: str) -> str:
        try:
            _, stdout, _ = client.exec_command(cmd, timeout=15)
            return stdout.read().decode(errors="replace")
        except Exception as e:
            logger.debug("auth_scanner: SSH command '%s' failed: %s", cmd, e)
            return ""

    try:
        # ── uname -a — kernel version, cross-check against known CVEs ──────
        uname = _run("uname -a").strip()
        if uname:
            findings.append(_finding(
                "kernel_version", "LOW", uname,
                "Cross-reference this kernel version against the CVE database for the "
                "distribution; apply available kernel security updates.",
            ))

        # ── installed packages — flag obviously outdated ones ───────────────
        pkgs = _run("dpkg -l 2>/dev/null || rpm -qa 2>/dev/null").strip()
        if pkgs:
            outdated_markers = ["openssl 1.0", "openssh 4.", "openssh 5.", "openssh 6.",
                                 "php5", "python2.7"]
            hits = [line for line in pkgs.splitlines()
                    if any(m in line.lower() for m in outdated_markers)]
            if hits:
                findings.append(_finding(
                    "outdated_packages", "MEDIUM",
                    "\n".join(hits[:10]),
                    "Upgrade the flagged packages — they correspond to EOL or known-vulnerable major versions.",
                ))

        # ── SUID binaries — flag unusual ones ───────────────────────────────
        suid = _run("find / -xdev -perm -4000 -type f 2>/dev/null").strip()
        if suid:
            expected = {
                "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/gpasswd",
                "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/mount",
                "/usr/bin/umount", "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
            }
            unusual = [line for line in suid.splitlines() if line.strip() not in expected]
            if unusual:
                findings.append(_finding(
                    "unusual_suid_binaries", "HIGH",
                    "\n".join(unusual[:20]),
                    "Review each unexpected SUID binary — unnecessary SUID bits are a common "
                    "privilege-escalation vector. Remove the bit (`chmod -s`) where not required.",
                ))

        # ── /etc/passwd — unexpected accounts ───────────────────────────────
        passwd = _run("cat /etc/passwd").strip()
        if passwd:
            system_prefixes = ("root:", "daemon:", "bin:", "sys:", "sync:", "games:",
                                "man:", "lp:", "mail:", "news:", "uucp:", "proxy:",
                                "www-data:", "backup:", "list:", "irc:", "gnats:",
                                "nobody:", "systemd-", "_apt:", "messagebus:", "sshd:")
            shell_accounts = []
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                uid, shell = parts[2], parts[6]
                if line.startswith(system_prefixes):
                    continue
                if shell.strip() in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                    continue
                shell_accounts.append(line)
            if shell_accounts:
                findings.append(_finding(
                    "passwd_accounts_review", "LOW",
                    "\n".join(shell_accounts[:20]),
                    "Review these non-system accounts with login shells — confirm each is "
                    "expected and still needed; disable/remove any that aren't.",
                ))

        # ── listening services vs what nmap saw externally ─────────────────
        listening = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null").strip()
        if listening:
            internal_ports = set(int(m) for m in re.findall(r":(\d+)\s", listening))
            internal_only = internal_ports - known_external_ports
            if internal_only:
                findings.append(_finding(
                    "internal_only_listeners", "LOW",
                    f"Ports listening locally but not seen in the external scan: "
                    f"{sorted(internal_only)}",
                    "These services may be firewalled from the network the scan ran from, or "
                    "bound to loopback/an internal interface — confirm that's intentional.",
                ))
    finally:
        try:
            client.close()
        except Exception:
            pass

    return findings


# ── SMB checks ───────────────────────────────────────────────────────────────

def _smb_checks(target: str, username: str, password: str) -> list[dict]:
    try:
        from smb.SMBConnection import SMBConnection
    except ImportError:
        try:
            from impacket.smbconnection import SMBConnection as _ImpacketConn  # noqa: F401
        except ImportError:
            logger.warning("auth_scanner: no SMB library installed — skipping SMB checks "
                            "(`pip install pysmb` or `pip install impacket` to enable)")
            return []
        return _smb_checks_impacket(target, username, password)

    findings: list[dict] = []
    try:
        conn = SMBConnection(username, password, "threatweave-auth-scanner", target,
                              use_ntlm_v2=True, is_direct_tcp=True)
        if not conn.connect(target, 445, timeout=10):
            return [_finding(
                "smb_auth_failed", "LOW",
                f"Could not authenticate to {target} via SMB with the provided credentials.",
                "Verify the username/password provided to the scanner are correct.",
            )]

        shares = conn.listShares(timeout=10)
        writable, guest_accessible = [], []
        for share in shares:
            name = share.name
            if name.endswith("$") and name not in ("C$", "ADMIN$"):
                continue
            try:
                files = conn.listPath(name, "/", timeout=10)
                guest_accessible.append(name)
                # Heuristic writability probe: attempt to create+delete a marker file.
                try:
                    import io
                    marker = "__threatweave_write_test__.tmp"
                    conn.storeFile(name, marker, io.BytesIO(b"test"), timeout=10)
                    conn.deleteFiles(name, marker, timeout=10)
                    writable.append(name)
                except Exception:
                    pass
            except Exception:
                continue

        if guest_accessible:
            findings.append(_finding(
                "smb_shares_accessible", "MEDIUM",
                f"Shares accessible with the provided credentials: {', '.join(guest_accessible)}",
                "Confirm each listed share genuinely requires access for this account; "
                "restrict ACLs on any that don't.",
            ))
        if writable:
            findings.append(_finding(
                "smb_writable_shares", "HIGH",
                f"Shares writable with the provided credentials: {', '.join(writable)}",
                "Writable shares are a common ransomware/lateral-movement vector — restrict "
                "write access to only the accounts/groups that genuinely need it.",
            ))
        conn.close()
    except Exception as e:
        logger.warning("auth_scanner: SMB check failed for %s: %s", target, e)
        return [_finding(
            "smb_check_error", "LOW", str(e),
            "Re-run with verbose logging if this persists; the SMB stack returned an unexpected error.",
        )]

    return findings


def _smb_checks_impacket(target: str, username: str, password: str) -> list[dict]:
    """impacket fallback when pysmb isn't installed but impacket is."""
    from impacket.smbconnection import SMBConnection
    findings: list[dict] = []
    try:
        conn = SMBConnection(target, target, timeout=10)
        conn.login(username, password)
        shares = conn.listShares()
        accessible = []
        for s in shares:
            name = s["shi1_netname"].rstrip("\x00")
            if name.endswith("$") and name not in ("C$", "ADMIN$"):
                continue
            try:
                conn.listPath(name, "*")
                accessible.append(name)
            except Exception:
                continue
        if accessible:
            findings.append(_finding(
                "smb_shares_accessible", "MEDIUM",
                f"Shares accessible with the provided credentials: {', '.join(accessible)}",
                "Confirm each listed share genuinely requires access for this account; "
                "restrict ACLs on any that don't.",
            ))
        conn.close()
    except Exception as e:
        logger.warning("auth_scanner: impacket SMB check failed for %s: %s", target, e)
    return findings


# ── Main entry point ─────────────────────────────────────────────────────────

def run_auth_checks(
    target: str,
    known_external_ports: set[int] | None = None,
    ssh_username: str | None = None,
    ssh_password: str | None = None,
    ssh_key_path: str | None = None,
    smb_username: str | None = None,
    smb_password: str | None = None,
) -> list[dict]:
    """
    Phase 7 main entry point.

    Optional by design: if neither ssh_* nor smb_* credentials are supplied,
    returns [] immediately — this module never blocks or slows the
    unauthenticated pipeline. Credentials come from scan-time request
    fields (see ScanRequest), never a slash command.
    """
    findings: list[dict] = []
    known_external_ports = known_external_ports or set()

    if ssh_username and (ssh_password or ssh_key_path):
        try:
            findings.extend(_ssh_checks(target, ssh_username, ssh_password, ssh_key_path,
                                          known_external_ports))
        except Exception as e:
            logger.warning("auth_scanner: SSH checks raised unexpectedly: %s", e)

    if smb_username and smb_password:
        try:
            findings.extend(_smb_checks(target, smb_username, smb_password))
        except Exception as e:
            logger.warning("auth_scanner: SMB checks raised unexpectedly: %s", e)

    logger.info("auth_scanner: %d authenticated findings for %s (ssh=%s, smb=%s)",
                len(findings), target, bool(ssh_username), bool(smb_username))
    return findings
