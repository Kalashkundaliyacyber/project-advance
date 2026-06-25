"""
service_prober.py
==================
Phase 2 of the reconstruction — active service probing.

Takes the unified scan output from Phase 0/1 (scanner_core.run_full_scan) and
independently re-verifies each open port nmap found, by actually talking to
it — not just trusting nmap's banner-grab/version-detection heuristics.

This is purely ADDITIVE. Per the original spec ("Failures must be caught
silently — if a probe fails, keep the nmap value"), probe results are never
used to overwrite port["service"]/port["product"]/port["version"] — the
existing CVE-matching pipeline (app/cve/mapper.py, app/vuln/nvd_client.py)
already keys off those fields and is tested against that shape. Instead,
results land in a separate `probed` dict that downstream consumers (the
confirmation router, the report builder) can use as a *cross-check* signal,
without risking a wrong probe destabilizing the existing CVE pipeline.

Runs automatically as the next pipeline stage right after the scan completes
— see app/api/routes.py::_run_scan_pipeline. No slash command, no manual
trigger.
"""
from __future__ import annotations

import logging
import socket
import ssl

logger = logging.getLogger("ThreatWeave.service_prober")

PROBE_TIMEOUT = 3.0          # seconds — never hang, per spec
MAX_BANNER_BYTES = 256

HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
SSH_PORTS = {22}
FTP_PORTS = {21}
SMB_PORTS = {445}


def _safe_recv(sock: socket.socket, n: int = MAX_BANNER_BYTES) -> bytes:
    try:
        sock.settimeout(PROBE_TIMEOUT)
        return sock.recv(n)
    except Exception:
        return b""


def _probe_http(target: str, port: int, use_tls: bool) -> dict:
    """GET / over HTTP or HTTPS — read headers + a banner-worthy excerpt."""
    raw = ""
    try:
        sock = socket.create_connection((target, port), timeout=PROBE_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target)
        sock.settimeout(PROBE_TIMEOUT)
        req = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\nUser-Agent: ThreatWeave-Prober/1.0\r\n\r\n"
        sock.sendall(req.encode())
        chunks = []
        try:
            while len(b"".join(chunks)) < 8192:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                chunks.append(chunk)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        raw = b"".join(chunks).decode(errors="replace")
    except Exception as e:
        logger.debug("HTTP probe %s:%d failed silently: %s", target, port, e)
        return {}

    if not raw:
        return {}

    headers_section = raw.split("\r\n\r\n", 1)[0]
    status_line = headers_section.split("\r\n", 1)[0] if headers_section else ""
    headers = {}
    for line in headers_section.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    server_hdr = headers.get("server", "")
    confirmed_service = "https" if use_tls else "http"
    confirmed_version = server_hdr

    return {
        "confirmed_service": confirmed_service,
        "confirmed_version": confirmed_version,
        "banner": status_line[:MAX_BANNER_BYTES],
        "raw_response": headers_section[:2000],
    }


def _probe_ssh(target: str, port: int) -> dict:
    """Connect and read the SSH identification banner string."""
    try:
        sock = socket.create_connection((target, port), timeout=PROBE_TIMEOUT)
        banner_bytes = _safe_recv(sock)
        try:
            sock.close()
        except Exception:
            pass
        banner = banner_bytes.decode(errors="replace").strip()
        if not banner:
            return {}
        # "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        version = banner.split("SSH-")[-1] if "SSH-" in banner else banner
        return {
            "confirmed_service": "ssh",
            "confirmed_version": version,
            "banner": banner[:MAX_BANNER_BYTES],
            "raw_response": banner,
        }
    except Exception as e:
        logger.debug("SSH probe %s:%d failed silently: %s", target, port, e)
        return {}


def _probe_ftp(target: str, port: int) -> dict:
    """Connect and read the FTP welcome banner."""
    try:
        sock = socket.create_connection((target, port), timeout=PROBE_TIMEOUT)
        banner_bytes = _safe_recv(sock)
        try:
            sock.close()
        except Exception:
            pass
        banner = banner_bytes.decode(errors="replace").strip()
        if not banner:
            return {}
        return {
            "confirmed_service": "ftp",
            "confirmed_version": banner.split("\n")[0][:160],
            "banner": banner[:MAX_BANNER_BYTES],
            "raw_response": banner,
        }
    except Exception as e:
        logger.debug("FTP probe %s:%d failed silently: %s", target, port, e)
        return {}


def _probe_smb(target: str, port: int) -> dict:
    """
    Minimal SMB negotiation — send an SMB1 Negotiate Protocol Request and
    confirm the response actually carries the \\xffSMB or \\xfeSMB magic
    bytes, i.e. this really is SMB and not something else squatting on 445.
    """
    # Classic SMB1 negotiate request requesting a small set of dialects —
    # enough to elicit a valid SMB response header from virtually any
    # Samba/Windows SMB stack without needing a full session setup.
    negotiate = bytes.fromhex(
        "00000085ff534d4272000000001853c00000000000000000000000000000fffe0000"
        "00004500024e54204c4d20302e313200"
    )
    try:
        sock = socket.create_connection((target, port), timeout=PROBE_TIMEOUT)
        sock.settimeout(PROBE_TIMEOUT)
        try:
            sock.sendall(negotiate)
            resp = sock.recv(MAX_BANNER_BYTES)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        if resp and (b"\xffSMB" in resp[:8] or b"\xfeSMB" in resp[:8]):
            return {
                "confirmed_service": "smb",
                "confirmed_version": "SMB negotiation succeeded (dialect not parsed)",
                "banner": "SMB magic bytes confirmed",
                "raw_response": resp.hex(),
            }
        return {}
    except Exception as e:
        logger.debug("SMB probe %s:%d failed silently: %s", target, port, e)
        return {}


def _probe_raw(target: str, port: int) -> dict:
    """Anything else: raw connect, read up to 256 bytes, treat as banner."""
    try:
        sock = socket.create_connection((target, port), timeout=PROBE_TIMEOUT)
        banner_bytes = _safe_recv(sock)
        try:
            sock.close()
        except Exception:
            pass
        if not banner_bytes:
            return {}
        banner = banner_bytes.decode(errors="replace").strip()
        return {
            "confirmed_service": "",
            "confirmed_version": "",
            "banner": banner[:MAX_BANNER_BYTES],
            "raw_response": banner,
        }
    except Exception as e:
        logger.debug("Raw probe %s:%d failed silently: %s", target, port, e)
        return {}


def probe_port(target: str, port: int) -> dict:
    """Dispatch one port to the right probe. Never raises."""
    try:
        if port in HTTPS_PORTS:
            return _probe_http(target, port, use_tls=True)
        if port in HTTP_PORTS:
            return _probe_http(target, port, use_tls=False)
        if port in SSH_PORTS:
            return _probe_ssh(target, port)
        if port in FTP_PORTS:
            return _probe_ftp(target, port)
        if port in SMB_PORTS:
            return _probe_smb(target, port)
        return _probe_raw(target, port)
    except Exception as e:
        # Belt-and-suspenders: probe_port itself must never raise, even if a
        # probe function has a bug — Phase 0's pipeline must keep moving.
        logger.debug("probe_port(%s, %d) unexpected error: %s", target, port, e)
        return {}


def probe_all_ports(scan_result: dict) -> dict:
    """
    Phase 2 entry point.

    Input:  the unified object from scanner_core.run_full_scan() (or just
            its ["parsed"] dict — both work, see _extract_target_and_ports).
    Output: {port: {confirmed_service, confirmed_version, banner, raw_response}}
            — only for ports a probe actually confirmed something on. Ports
            where the probe failed/timed out are simply absent from the
            dict; callers should fall back to the nmap-reported value, which
            is exactly the "keep the nmap value on failure" requirement.
    """
    target, ports = _extract_target_and_ports(scan_result)
    if not target or not ports:
        return {}

    results = {}
    for p in ports:
        port_num = p.get("port")
        if port_num is None or p.get("state") not in ("open", "open|filtered"):
            continue
        probed = probe_port(target, int(port_num))
        if probed:
            results[int(port_num)] = probed
    logger.info("service_prober: %d/%d open ports actively confirmed on %s",
                len(results), len(ports), target)
    return results


def _extract_target_and_ports(scan_result: dict):
    """Accept either the full scanner_core output or a bare parsed dict."""
    parsed = scan_result.get("parsed", scan_result)
    target = scan_result.get("target") or parsed.get("target") or ""
    ports = []
    for host in parsed.get("hosts", []):
        if not target:
            target = host.get("ip") or host.get("address") or target
        ports.extend(host.get("ports", []))
    return target, ports


def merge_into_parsed(parsed: dict, probed: dict) -> dict:
    """
    Attach probe results onto the parsed dict as port["probed"], without
    touching port["service"]/port["product"]/port["version"] — additive
    cross-check data only, per the "keep the nmap value on failure" design.
    """
    for host in parsed.get("hosts", []):
        for port in host.get("ports", []):
            p = probed.get(int(port.get("port", -1)))
            if p:
                port["probed"] = p
    return parsed
