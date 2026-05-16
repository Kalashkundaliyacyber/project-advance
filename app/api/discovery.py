"""
FIX9: Network Discovery Workflow
Implements subnet ping sweep (-sn) to discover live hosts,
then returns selectable list for deep scanning.
"""
import asyncio
import logging
import re
import ipaddress
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.scanner.executor import execute_scan as _execute_scan

logger = logging.getLogger("scanwise.discovery")
router = APIRouter()


class DiscoveryRequest(BaseModel):
    subnet: str          # e.g. "192.168.1.0/24" or "10.0.0.1-254"
    timeout: Optional[int] = 30   # seconds, capped at 120


@router.post("/discover")
async def discover_hosts(req: DiscoveryRequest):
    """
    FIX9: Run nmap -sn ping sweep on the given subnet.
    Returns a list of live hosts ready for deep scanning.
    """
    subnet = req.subnet.strip()
    timeout = min(req.timeout or 30, 120)

    # Validate subnet is a plausible CIDR or range — never allow shell injection
    if not re.match(r'^[\d./\-: ]+$', subnet):
        raise HTTPException(status_code=400, detail="Invalid subnet format")

    # Safety: block /8 or broader sweeps to prevent runaway scans
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        if net.prefixlen < 16:
            raise HTTPException(status_code=400, detail="Subnet too broad — use /16 or narrower")
    except ValueError:
        pass   # Range notation like "192.168.1.1-254" — let nmap validate it

    logger.info("FIX9: discovery sweep on %s", subnet)

    try:
        # -sn = ping sweep (no port scan), -T4 = aggressive timing
        # Build the nmap -sn command directly as a safe list (no shell=True)
        cmd = ["nmap", "-sn", "-T4", subnet]
        raw_tuple = await asyncio.wait_for(
            asyncio.to_thread(_execute_scan, cmd, subnet, "ping_sweep"),
            timeout=timeout
        )
        raw = raw_tuple[0] if isinstance(raw_tuple, tuple) else raw_tuple
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Discovery timed out — try a smaller subnet")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Discovery failed: {e}")

    # Parse nmap output: "Nmap scan report for 192.168.1.1" lines
    live_hosts = []
    host_pattern = re.compile(
        r'Nmap scan report for (?:([^\s(]+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?'
    )
    latency_pattern = re.compile(r'Host is up \(([0-9.]+)s latency\)')

    lines = raw.splitlines() if isinstance(raw, str) else []
    current_host = None

    for line in lines:
        m = host_pattern.search(line)
        if m:
            hostname = m.group(1) or ""
            ip       = m.group(2)
            current_host = {"ip": ip, "hostname": hostname, "latency_ms": None}
            live_hosts.append(current_host)
            continue

        if current_host:
            lm = latency_pattern.search(line)
            if lm:
                current_host["latency_ms"] = round(float(lm.group(1)) * 1000, 1)

    logger.info("FIX9: %d live hosts found in %s", len(live_hosts), subnet)

    return {
        "subnet":     subnet,
        "live_count": len(live_hosts),
        "hosts":      live_hosts,
    }
