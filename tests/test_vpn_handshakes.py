"""VPN handshake identification: IKE/IPsec, WireGuard and OpenVPN (issue #223)."""

from __future__ import annotations

from conftest import codes, fixture, requires_tshark


@requires_tshark
def test_vpn_handshakes_fixture_reports_all_three_protocols(analyze_capture) -> None:
    """The fixture carries an IKE SA_INIT on UDP 500, a WireGuard handshake on UDP 51820 and an
    OpenVPN control packet on UDP 1194; each must produce its own informational finding."""
    result = analyze_capture(fixture("vpn_handshakes.pcap"))
    found = codes(result)
    assert "VPN_IKE_HANDSHAKE" in found
    assert "VPN_WIREGUARD_HANDSHAKE" in found
    assert "VPN_OPENVPN_HANDSHAKE" in found


@requires_tshark
def test_vpn_findings_are_informational(analyze_capture) -> None:
    """VPN handshake presence is inventory, not a defect: severity is info, confidence high."""
    result = analyze_capture(fixture("vpn_handshakes.pcap"))
    for finding in result.report.findings:
        if finding.code.startswith("VPN_"):
            assert finding.severity == "info", f"{finding.code} is {finding.severity}"
            assert finding.confidence == "high"
            assert finding.evidence, f"{finding.code} has no evidence"
            assert finding.evidence[0].frame > 0


@requires_tshark
def test_vpn_findings_carry_real_frame_references(analyze_capture) -> None:
    """Every VPN finding cites a frame the analyst can open in Wireshark (#4)."""
    result = analyze_capture(fixture("vpn_handshakes.pcap"))
    vpn = [f for f in result.report.findings if f.code.startswith("VPN_")]
    assert len(vpn) == 3
    for finding in vpn:
        assert finding.evidence[0].frame > 0
        assert finding.evidence[0].field
        assert finding.evidence[0].value


@requires_tshark
def test_vpn_ike_finding_naming_the_exchange(analyze_capture) -> None:
    """The IKE finding reports the exchange type decoded from isakmp.exchangetype (= 34 = IKE_SA_INIT)."""
    result = analyze_capture(fixture("vpn_handshakes.pcap"))
    (ike,) = [f for f in result.report.findings if f.code == "VPN_IKE_HANDSHAKE"]
    assert "500" in ike.summary  # port 500
    assert "IKE_SA_INIT" in ike.summary


@requires_tshark
def test_vpn_wireguard_finding_names_the_message_type(analyze_capture) -> None:
    """The WireGuard finding reports the decoded message type seen in the payload."""
    result = analyze_capture(fixture("vpn_handshakes.pcap"))
    (wg,) = [f for f in result.report.findings if f.code == "VPN_WIREGUARD_HANDSHAKE"]
    assert "51820" in wg.summary
    assert "Handshake Initiation" in wg.summary
