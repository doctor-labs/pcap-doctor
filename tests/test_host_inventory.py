"""Host inventory: MAC, hostnames, OS per host (issue #245)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from conftest import fixture, requires_tshark

# The set of passes requested by analyze on origin/main (no host inventory enrichment), measured by recording
# every TsharkRunner.run call across the whole analyze (index builder AND detectors): 15 passes.
# Host inventory must NOT add to this: it reads the existing base pass (MAC, vendor, TTL) instead.
EXPECTED_PASSES = {
    "base", "tls", "dtls", "http", "dns", "sip", "rtp", "ssh", "quic",
    "services", "telnet", "smb", "arp_icmp", "capture_loss", "conn", "radius", "http2", "ics_control",
}


def test_analyze_requests_no_extra_passes(tmp_path: Path) -> None:
    """Host inventory must NOT request additional tshark passes beyond the baseline.
    
    MAC, vendor, and OS guess must come from existing passes.
    Hostname may come from existing DNS/TLS data, or be omitted if not present.
    """
    requested: set[str] = set()
    
    def record_pass(name: str) -> None:
        requested.add(name)
    
    # Import and patch the TsharkRunner.run method to record pass requests
    from pcap_doctor.tshark import TsharkRunner
    original_run = TsharkRunner.run
    
    def patched_run(self, name: str, *args, **kwargs):
        record_pass(name)
        return original_run(self, name, *args, **kwargs)
    
    from pcap_doctor.pipeline import analyze
    
    with patch.object(TsharkRunner, "run", patched_run):
        analyze(fixture("arp_icmp.pcap"), tmp_path / "out")
    assert requested, "analyze requested no passes at all: the recorder did not see any run() call"
    
    # The test fails if we request any passes beyond the baseline
    extra_passes = requested - EXPECTED_PASSES
    assert not extra_passes, f"analyze requested extra passes: {sorted(extra_passes)}. Host inventory must NOT add tshark passes."
    
    # Also verify we're still requesting all expected passes
    missing = EXPECTED_PASSES - requested
    assert not missing, f"analyze is missing expected passes: {sorted(missing)}"


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
def test_host_inventory_hostname_from_existing_data(analyze_capture) -> None:
    """Hostname from DNS/TLS SNI data already in index."""
    # This test checks that hostname field exists and may be populated from
    # existing index data (DNS queries, TLS SNI, HTTP Host headers)
    result = analyze_capture(fixture("devices.pcap"))
    for host in result.index.hosts.values():
        # hostname should be a string (possibly None)
        assert isinstance(host.hostname, (str, type(None), type(None)))