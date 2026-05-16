"""
Scan Executor
Runs nmap as a safe subprocess. Falls back to simulation if nmap not installed.
shell=False always. No arbitrary command execution.
"""
import subprocess
import time
import shutil

# Lazy import to avoid circular dep
def _get_scan_state():
    try:
        from app.api.scan_control import scan_state
        return scan_state
    except Exception:
        return None

# Per-scan-type timeouts (seconds).  Long scans like full_tcp / ultimate_recon
# legitimately need 30-120 minutes; never kill them with a 5-minute wall.
SCAN_TIMEOUTS = {
    # Quick scans
    "ping_sweep":         120,
    "host_discovery":     120,
    "arp_discovery":      120,
    "tcp_basic":          300,
    "tcp_syn":            300,
    "stealth_syn":        600,
    # All-port scans — slow by design
    "full_tcp":          5400,   # 90 min
    "udp_scan":          7200,   # 120 min
    # Service / version
    "service_detect":     600,
    "full_service_enum":  900,
    "banner_grab":        300,
    "db_discovery":       300,
    "os_detect":          600,
    "version_deep":       900,
    "port_range":         600,
    # Vuln assessment
    "vuln_scan":         1800,   # 30 min
    "smb_audit":          600,
    "ftp_audit":          300,
    "ssh_audit":          300,
    "web_pentest":       1200,
    # Advanced
    "aggressive_pentest":3600,   # 60 min
    "firewall_evasion":   900,
    "frag_scan":          600,
    "decoy_scan":         600,
    "timing_manipulation":1800,
    "ultimate_recon":    7200,   # 120 min
    "enum_scripts":      1800,
}
DEFAULT_SCAN_TIMEOUT = 1800   # 30-min fallback for unknown types


def _timeout_for(scan_type: str) -> int:
    return SCAN_TIMEOUTS.get(scan_type, DEFAULT_SCAN_TIMEOUT)


def execute_scan(cmd: list, target: str, scan_type: str):
    """
    Execute a safe nmap command list.
    Returns (raw_text_output, xml_output, duration_seconds)
    """
    if not shutil.which("nmap"):
        return _simulated_scan(target, scan_type)

    # Inject --stats-every so nmap emits "% done" lines every 5 s on long scans
    if "--stats-every" not in cmd:
        cmd = cmd[:1] + ["--stats-every", "5s"] + cmd[1:]

    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            text=True
        )
        # Register PID with scan_state for stop functionality
        _ss = _get_scan_state()
        if _ss:
            _ss.start(proc.pid, scan_type, target)

        timeout = _timeout_for(scan_type)

        # Read stderr line-by-line in a background thread so nmap's real "% done"
        # progress lines reach the progress worker without blocking communicate().
        stderr_lines: list = []

        def _read_stderr():
            for line in proc.stderr:
                stderr_lines.append(line)
                if _ss and ("% done" in line or "% Done" in line):
                    _ss._last_nmap_line = line

        import threading as _threading
        _stderr_thread = _threading.Thread(target=_read_stderr, daemon=True)
        _stderr_thread.start()

        try:
            stdout, _ = proc.communicate(timeout=timeout)
            _stderr_thread.join(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()   # drain pipes to avoid zombie
            raise RuntimeError(
                f"Scan timed out after {timeout}s. "
                f"'{scan_type}' has a {timeout//60}-minute limit. "
                f"Try a faster scan type or narrow the target."
            )

        stderr     = "".join(stderr_lines)
        duration   = round(time.time() - start, 2)
        xml_output = stdout
        raw_output = stderr + "\n" + xml_output

        if _ss:
            _ss._last_nmap_line = ""   # clear for next scan
            if _ss.status == "stopped":
                raise RuntimeError("Scan stopped by user")
            _ss.complete()

        if proc.returncode not in (0, 1, -15):
            raise RuntimeError(f"nmap exit {proc.returncode}: {stderr[:200]}")
        return raw_output, xml_output, duration
    except FileNotFoundError:
        raise RuntimeError("nmap not found. Install: sudo apt install nmap")


def _simulated_scan(target: str, scan_type: str):
    """Realistic simulated output when nmap is not installed."""
    _ss = _get_scan_state()
    if _ss:
        _ss.start(None, scan_type, target)
    time.sleep(1.2)
    sims = {
        # Port scanning
        "tcp_basic":          _sim_tcp(target),
        "tcp_syn":            _sim_tcp(target),
        "full_tcp":           _sim_tcp(target),
        "stealth_syn":        _sim_tcp(target),
        "port_range":         _sim_tcp(target),
        # Enumeration
        "service_detect":     _sim_service(target),
        "version_deep":       _sim_service(target),
        "enum_scripts":       _sim_service(target),
        "full_service_enum":  _sim_service(target),
        "banner_grab":        _sim_service(target),
        "db_discovery":       _sim_service(target),
        # Discovery
        "ping_sweep":         _sim_tcp(target),
        "host_discovery":     _sim_tcp(target),
        "arp_discovery":      _sim_tcp(target),
        # UDP / OS
        "udp_scan":           _sim_udp(target),
        "os_detect":          _sim_os(target),
        # Vuln assessment
        "vuln_scan":          _sim_service(target),
        "smb_audit":          _sim_service(target),
        "ftp_audit":          _sim_service(target),
        "ssh_audit":          _sim_service(target),
        "web_pentest":        _sim_service(target),
        # Advanced
        "aggressive_pentest": _sim_service(target),
        "firewall_evasion":   _sim_tcp(target),
        "frag_scan":          _sim_tcp(target),
        "decoy_scan":         _sim_tcp(target),
        "timing_manipulation":_sim_tcp(target),
        "ultimate_recon":     _sim_service(target),
    }
    xml = sims.get(scan_type, _sim_service(target))
    raw = f"[SIMULATED - nmap not installed]\nTarget: {target}\nType: {scan_type}\n\n{xml}"
    if _ss:
        _ss.complete()
    return raw, xml, 1.2


def _sim_service(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV {target}" version="7.95" xmloutputversion="1.05">
<host starttime="1720000000" endtime="1720000010">
<status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<hostnames><hostname name="{target}" type="user"/></hostnames>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.2.34" extrainfo="(Unix)" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="open" reason="syn-ack"/>
    <service name="https" product="Apache httpd" version="2.2.34" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="3306">
    <state state="open" reason="syn-ack"/>
    <service name="mysql" product="MySQL" version="5.5.62" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="21">
    <state state="open" reason="syn-ack"/>
    <service name="ftp" product="vsftpd" version="2.3.4" conf="10" method="probed"/>
  </port>
</ports>
<times srtt="500" rttvar="250" to="100000"/>
</host>
<runstats>
  <finished elapsed="10.00" exit="success" summary="1 IP address scanned"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""


def _sim_tcp(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT {target}" version="7.95" xmloutputversion="1.05">
<host starttime="1720000000" endtime="1720000005">
<status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" conf="3" method="table"/></port>
  <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" conf="3" method="table"/></port>
  <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" conf="3" method="table"/></port>
  <port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" conf="3" method="table"/></port>
  <port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" conf="3" method="table"/></port>
  <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/><service name="http-proxy" conf="3" method="table"/></port>
</ports>
</host>
<runstats><finished elapsed="5.00" exit="success" summary="1 IP address scanned"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


def _sim_udp(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sU {target}" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<ports>
  <port protocol="udp" portid="53">
    <state state="open" reason="udp-response"/>
    <service name="domain" product="ISC BIND" version="9.9.5" conf="10" method="probed"/>
  </port>
  <port protocol="udp" portid="161">
    <state state="open" reason="udp-response"/>
    <service name="snmp" product="net-snmp" version="5.7.2" conf="10" method="probed"/>
  </port>
</ports>
</host>
<runstats><finished elapsed="20.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""


def _sim_os(target):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O {target}" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="{target}" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" conf="3" method="table"/></port>
  <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" conf="3" method="table"/></port>
</ports>
<os>
  <osmatch name="Linux 5.4 - 5.15" accuracy="96" line="58447">
    <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/>
  </osmatch>
</os>
</host>
<runstats><finished elapsed="8.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""

