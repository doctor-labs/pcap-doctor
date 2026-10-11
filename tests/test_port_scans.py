"""Port scans beyond the SYN-only shape: completed connect scans, vertical and horizontal (issue #242)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_connect_scans_are_reported_vertical_and_horizontal(analyze_capture) -> None:
    findings = analyze_capture(fixture("connect_scans.pcap")).report.findings
    vertical = [f for f in findings if f.code == "PORT_SCAN_VERTICAL"]
    horizontal = [f for f in findings if f.code == "PORT_SCAN_HORIZONTAL"]
    assert len(vertical) == 1 and len(horizontal) == 1, [f.code for f in findings]
    assert "10.90.0.66" in vertical[0].subjects and "10.90.0.10" in vertical[0].summary and "20 ports" in vertical[0].summary
    assert "10.90.0.66" in horizontal[0].subjects and "445" in horizontal[0].summary and "20 hosts" in horizontal[0].summary
    assert vertical[0].severity == horizontal[0].severity == "medium"


@requires_tshark
def test_ordinary_traffic_is_not_a_scan(analyze_capture) -> None:
    for name in ("tunnels.pcap", "tcp_health.pcap", "http_basic.pcap"):
        codes = {f.code for f in analyze_capture(fixture(name)).report.findings}
        assert not codes & {"PORT_SCAN_VERTICAL", "PORT_SCAN_HORIZONTAL"}, name
