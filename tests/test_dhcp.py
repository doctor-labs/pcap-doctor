"""DHCP and DHCPv6: host inventory, a rogue second server, and what the request leaks (#220)."""

from __future__ import annotations

from conftest import fixture, requires_tshark

MY_CODES = (
    "DHCP_CLIENT_INVENTORY",
    "DHCPV6_CLIENT_INVENTORY",
    "DHCP_ROGUE_SERVER",
    "DHCP_DOMAIN_LEAK",
    "DHCP_VENDOR_FINGERPRINT",
)


def _by_code(result) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in result.findings:
        if f.code in MY_CODES:
            out.setdefault(f.code, []).append(f)
    return out


@requires_tshark
def test_a_dhcp_exchange_is_inventoried(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("dhcp_rogue.pcap")))
    assert "DHCP_CLIENT_INVENTORY" in found
    inventory = found["DHCP_CLIENT_INVENTORY"][0]
    assert inventory.severity == "info"
    assert "aa:bb:cc:dd:ee:ff" in inventory.summary
    assert "iot-sensor-01" in inventory.summary
    assert "10.0.7.42" in inventory.summary
    assert inventory.evidence and inventory.evidence[0].frame > 0
    assert inventory.evidence[0].value
    assert inventory.references and inventory.remediation


@requires_tshark
def test_two_servers_answering_the_same_transaction_are_reported(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("dhcp_rogue.pcap")))
    assert "DHCP_ROGUE_SERVER" in found
    rogue = found["DHCP_ROGUE_SERVER"][0]
    assert rogue.severity == "high"
    assert rogue.confidence == "high"
    assert "10.0.0.1" in rogue.summary and "10.0.0.66" in rogue.summary
    assert rogue.evidence and rogue.evidence[0].frame > 0
    assert rogue.remediation and rogue.references


@requires_tshark
def test_the_domain_and_the_vendor_class_are_reported_as_leaks(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("dhcp_rogue.pcap")))
    assert "DHCP_DOMAIN_LEAK" in found
    assert "corp.internal" in found["DHCP_DOMAIN_LEAK"][0].summary
    assert found["DHCP_DOMAIN_LEAK"][0].severity == "low"
    assert "DHCP_VENDOR_FINGERPRINT" in found
    assert "ubiquiti" in found["DHCP_VENDOR_FINGERPRINT"][0].summary
    assert found["DHCP_VENDOR_FINGERPRINT"][0].severity == "info"


@requires_tshark
def test_a_dhcpv6_exchange_is_inventoried(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("dhcpv6.pcap")))
    assert "DHCPV6_CLIENT_INVENTORY" in found
    inventory = found["DHCPV6_CLIENT_INVENTORY"][0]
    assert inventory.severity == "info"
    assert inventory.evidence and inventory.evidence[0].frame > 0
    assert inventory.references


@requires_tshark
def test_the_detector_is_quiet_without_dhcp(analyze_capture) -> None:
    assert not _by_code(analyze_capture(fixture("strong_tls13.pcap")))


@requires_tshark
def test_the_codes_are_stable_across_runs(analyze_capture) -> None:
    first = analyze_capture(fixture("dhcp_rogue.pcap"))
    second = analyze_capture(fixture("dhcp_rogue.pcap"))
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
