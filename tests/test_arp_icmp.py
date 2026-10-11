"""ARP spoofing (one IP claimed by two MACs) and ICMP redirects (issue #280)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_an_ip_claimed_by_two_macs_is_one_spoofing_finding(analyze_capture) -> None:
    findings = [f for f in analyze_capture(fixture("arp_icmp.pcap")).report.findings if f.code == "ARP_SPOOFING_SUSPECTED"]
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.severity == "high"
    assert "10.0.0.1" in f.summary
    assert "02:00:00:00:00:01" in f.summary and "02:00:00:00:00:66" in f.summary
    assert f.evidence[0].frame == 2  # the first conflicting claim
    assert "10.0.0.30" not in " ".join(x.summary for x in findings)


@requires_tshark
def test_an_icmp_redirect_names_the_sender_and_the_new_gateway(analyze_capture) -> None:
    findings = [f for f in analyze_capture(fixture("arp_icmp.pcap")).report.findings if f.code == "ICMP_REDIRECT"]
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.severity == "medium"
    assert "10.0.0.254" in f.summary and "10.0.0.66" in f.summary
    assert f.evidence[0].frame == 5
