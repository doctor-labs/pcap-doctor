"""d25 dns_zone_transfer: cleartext AXFR/IXFR zone transfer requests (#195)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_flags_axfr_and_ixfr_requests(analyze_capture) -> None:
    result = analyze_capture(fixture("dns_zone_transfer.pcap"))
    found = [f for f in result.report.findings if f.code == "DNS_ZONE_TRANSFER_REQUEST"]
    assert {(f.subjects[2], f.evidence[0].value.split()[0]) for f in found} == {
        ("corp.example", "AXFR"),
        ("corp.example", "IXFR"),
    }


@requires_tshark
def test_evidence_points_at_real_frame(analyze_capture) -> None:
    result = analyze_capture(fixture("dns_zone_transfer.pcap"))
    for finding in (f for f in result.report.findings if f.code == "DNS_ZONE_TRANSFER_REQUEST"):
        assert finding.evidence and finding.evidence[0].frame > 0
        assert finding.remediation and finding.references


@requires_tshark
def test_negative_on_ordinary_dns(analyze_capture) -> None:
    result = analyze_capture(fixture("dns_tunnel.pcap"))
    assert "DNS_ZONE_TRANSFER_REQUEST" not in {f.code for f in result.report.findings}
