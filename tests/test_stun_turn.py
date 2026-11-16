"""D25 -- STUN/TURN, WebRTC, RTSP and SCTP dissection (#224)."""

from __future__ import annotations

from conftest import codes, fixture, requires_tshark


@requires_tshark
def test_stun_binding_and_xor_mapped_address(analyze_capture) -> None:
    result = analyze_capture(fixture("stun_rtsp.pcap"))
    found = codes(result)
    assert "STUN_BINDING_TRANSACTION" in found
    assert "STUN_XOR_MAPPED_ADDRESS" in found
    assert "RTSP_CONTROL_EXCHANGE" in found
    xor = [f for f in result.report.findings if f.code == "STUN_XOR_MAPPED_ADDRESS"]
    assert xor and any("192.0.2.33" in e.value or "4432" in e.value for f in xor for e in f.evidence)
    assert all(f.evidence and f.evidence[0].frame > 0 for f in result.report.findings if f.code.startswith("STUN_") or f.code.startswith("RTSP_") or f.code.startswith("WEBRTC_"))


@requires_tshark
def test_rtsp_url_credentials_and_play_exchange(analyze_capture) -> None:
    result = analyze_capture(fixture("rtsp_auth.pcap"))
    found = codes(result)
    assert "RTSP_CONTROL_EXCHANGE" in found
    assert "RTSP_CLEARTEXT_CREDENTIAL_URL" in found
    creds = [f for f in result.report.findings if f.code == "RTSP_CLEARTEXT_CREDENTIAL_URL"]
    assert creds and all(f.severity == "critical" for f in creds)
    assert any("userinfo" in e.field or "rtsp.url" in e.field for f in creds for e in f.evidence)


@requires_tshark
def test_no_findings_on_unrelated_capture(analyze_capture) -> None:
    found = codes(analyze_capture(fixture("strong_tls13.pcap")))
    assert "STUN_BINDING_TRANSACTION" not in found
    assert "STUN_XOR_MAPPED_ADDRESS" not in found
    assert "RTSP_CONTROL_EXCHANGE" not in found
    assert "RTSP_CLEARTEXT_CREDENTIAL_URL" not in found
    assert "WEBRTC_DTLS_ASSOCIATION" not in found
    assert "WEBRTC_MEDIA_UNPROTECTED" not in found
