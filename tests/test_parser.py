"""
Tests for the nmap output parser.
Run with: pytest tests/test_parser.py -v
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.parser.nmap_parser import parse_nmap_output

SAMPLE_XML_BASIC = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT 192.168.1.10" version="7.95" xmloutputversion="1.05">
<host starttime="1720000000" endtime="1720000010">
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="testhost" type="user"/></hostnames>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="7.4" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="Apache httpd" version="2.2.34" conf="10" method="probed"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="closed" reason="reset"/>
    <service name="https" conf="3" method="table"/>
  </port>
</ports>
</host>
<runstats>
  <finished elapsed="10.00" exit="success" summary="1 IP scanned"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""

SAMPLE_XML_NO_HOSTS = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<runstats>
  <finished elapsed="5.00" exit="success"/>
  <hosts up="0" down="1" total="1"/>
</runstats>
</nmaprun>"""

SAMPLE_XML_WITH_OS = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
  <service name="ssh" product="OpenSSH" version="8.9" conf="10" method="probed"/></port>
</ports>
<os><osmatch name="Linux 5.15" accuracy="97" line="58447">
  <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="97"/>
</osmatch></os>
</host>
<runstats><finished elapsed="8.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""

SAMPLE_XML_UDP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
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


class TestParseBasic:
    def setup_method(self):
        self.result = parse_nmap_output(SAMPLE_XML_BASIC, "raw output here")

    def test_returns_dict(self):
        assert isinstance(self.result, dict)

    def test_has_hosts(self):
        assert "hosts" in self.result
        assert len(self.result["hosts"]) == 1

    def test_host_ip(self):
        assert self.result["hosts"][0]["ip"] == "192.168.1.10"

    def test_host_hostnames(self):
        assert "testhost" in self.result["hosts"][0]["hostnames"]

    def test_only_open_ports(self):
        """Closed ports should be excluded."""
        ports = self.result["hosts"][0]["ports"]
        port_nums = [p["port"] for p in ports]
        assert 443 not in port_nums  # was closed
        assert 22 in port_nums
        assert 80 in port_nums

    def test_port_count(self):
        assert len(self.result["hosts"][0]["ports"]) == 2

    def test_port_22_fields(self):
        ports = {p["port"]: p for p in self.result["hosts"][0]["ports"]}
        p22 = ports[22]
        assert p22["protocol"] == "tcp"
        assert p22["service"] == "ssh"
        assert p22["product"] == "OpenSSH"
        assert p22["version"] == "7.4"
        assert p22["state"] == "open"
        assert p22["confidence"] == 10

    def test_port_80_apache(self):
        ports = {p["port"]: p for p in self.result["hosts"][0]["ports"]}
        p80 = ports[80]
        assert p80["service"] == "http"
        assert "Apache" in p80["product"]
        assert p80["version"] == "2.2.34"

    def test_scan_summary(self):
        s = self.result["scan_summary"]
        assert "elapsed" in s
        assert s["hosts_up"] == "1"

    def test_simulated_flag_false(self):
        assert self.result["simulated"] is False


class TestNoHosts:
    def test_empty_hosts(self):
        result = parse_nmap_output(SAMPLE_XML_NO_HOSTS, "")
        assert result["hosts"] == []
        assert result["scan_summary"]["hosts_up"] == "0"


class TestOSDetection:
    def setup_method(self):
        self.result = parse_nmap_output(SAMPLE_XML_WITH_OS, "")

    def test_os_detected(self):
        host = self.result["hosts"][0]
        assert host["os"] is not None
        assert "Linux" in host["os"]["name"]

    def test_os_accuracy(self):
        host = self.result["hosts"][0]
        assert host["os"]["accuracy"] == "97"


class TestUDPPorts:
    def setup_method(self):
        self.result = parse_nmap_output(SAMPLE_XML_UDP, "")

    def test_udp_ports_parsed(self):
        ports = self.result["hosts"][0]["ports"]
        assert len(ports) == 2

    def test_udp_protocol(self):
        for p in self.result["hosts"][0]["ports"]:
            assert p["protocol"] == "udp"

    def test_dns_port(self):
        ports = {p["port"]: p for p in self.result["hosts"][0]["ports"]}
        assert 53 in ports
        assert ports[53]["service"] == "domain"

    def test_snmp_port(self):
        ports = {p["port"]: p for p in self.result["hosts"][0]["ports"]}
        assert 161 in ports
        assert ports[161]["service"] == "snmp"


class TestMalformedXML:
    def test_bad_xml_no_crash(self):
        result = parse_nmap_output("<bad xml>>>", "raw")
        assert "parse_error" in result
        assert result["hosts"] == []

    def test_empty_string(self):
        result = parse_nmap_output("", "")
        assert "parse_error" in result

    def test_simulated_flag(self):
        result = parse_nmap_output(SAMPLE_XML_BASIC, "[SIMULATED - nmap not installed]")
        assert result["simulated"] is True
