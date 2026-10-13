"""Host inventory: MAC, hostnames, OS per host (issue #245)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_host_inventory_has_mac_and_vendor(analyze_capture) -> None:
    """MAC address and OUI vendor are populated on hosts."""
    result = analyze_capture(fixture("devices.pcap"))
    by_ip = {h.ip: h for h in result.index.hosts.values()}
    
    # The devices.pcap has 3 hosts with known MAC->IP mappings
    assert "10.40.0.1" in by_ip
    assert "10.40.0.2" in by_ip
    assert "10.40.0.3" in by_ip
    
    # MAC addresses should be populated
    assert by_ip["10.40.0.1"].mac == "00:1a:11:aa:bb:01"
    assert by_ip["10.40.0.2"].mac == "b8:27:eb:12:34:56"
    assert by_ip["10.40.0.3"].mac == "02:00:00:00:00:0c"
    
    # Vendor names should be resolved
    assert "Google" in (by_ip["10.40.0.1"].vendor or "")
    assert "Raspberry" in (by_ip["10.40.0.2"].vendor or "")
    # Locally administered MAC has no vendor
    assert by_ip["10.40.0.3"].vendor is None


@requires_tshark
def test_host_inventory_has_os_guess(analyze_capture) -> None:
    """OS guess from initial TTL is populated on hosts."""
    result = analyze_capture(fixture("os_ttls.pcap"))
    by_ip = {h.ip: h for h in result.index.hosts.values()}
    
    # os_ttls.pcap has 3 hosts with different TTLs
    assert "10.95.0.10" in by_ip
    assert "10.95.0.20" in by_ip
    assert "10.95.0.30" in by_ip
    
    # OS guesses based on TTL
    assert by_ip["10.95.0.10"].os_guess == "Windows"
    assert by_ip["10.95.0.20"].os_guess == "Linux/Unix/Android/macOS"
    assert by_ip["10.95.0.30"].os_guess == "network device"


@requires_tshark
def test_host_inventory_hostname_from_dhcp(analyze_capture) -> None:
    """Hostname from DHCP option 12."""
    # This test will need a fixture with DHCP hostname
    # For now, check that hosts don't crash when no hostname is present
    result = analyze_capture(fixture("devices.pcap"))
    for host in result.index.hosts.values():
        # hostname should be a string (possibly empty)
        assert isinstance(host.hostname, (str, type(None)))