"""ECH (Encrypted Client Hello) and TLS 1.3 0-RTT early-data checks (#270)."""

from __future__ import annotations

from conftest import FIXTURES, requires_tshark
from pcap_doctor.detectors.ech_early_data import EchEarlyDataDetector
from pcap_doctor.index import CaptureIndex
from pcap_doctor.models import CaptureInfo, Flow, Handshake, TlsSession, endpoints_of, flow_key


def _index(**session: object) -> tuple[CaptureIndex, str]:
    info = CaptureInfo(path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0,
                       packets=6, bytes=0, first_seen=1_700_000_000.0, last_seen=1_700_000_010.0, duration=10.0)
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a,
                            endpoint_b=b, port_b=port_b, app_proto="tls", first_frame=1)
    base: dict[str, object] = dict(
        key=key, negotiated_version="TLS 1.3", complete=True,
        client_hello=Handshake(type=1, frame=3, sni="shop.example"),
        server_hello=Handshake(type=2, frame=4, extensions=[43, 51]),
        sni="shop.example",
    )
    base.update(session)
    index.tls[key] = TlsSession(**base)  # type: ignore[arg-type]
    return index, key


def _codes(index: CaptureIndex) -> dict[str, object]:
    return {f.code: f for f in EchEarlyDataDetector().detect(index)}


def test_ech_extension_detected() -> None:
    """ClientHello with ECH extension (0xfe0d = 65037) reports TLS_ECH_OFFERED."""
    idx = _index(client_hello=Handshake(type=1, frame=3, sni="shop.example",
                                        extensions=[0, 42, 43, 51, 65037]))[0]
    found = _codes(idx)
    f = found["TLS_ECH_OFFERED"]
    assert f.severity == "low"  # type: ignore[attr-defined]
    assert f.evidence[0].frame == 3  # type: ignore[attr-defined]
    assert "65037" in f.evidence[0].value  # type: ignore[attr-defined]


def test_early_data_extension_detected() -> None:
    """ClientHello with early_data extension (42) reports TLS_EARLY_DATA_OFFERED."""
    idx = _index(client_hello=Handshake(type=1, frame=3, sni="shop.example",
                                        extensions=[0, 42, 43, 51]))[0]
    found = _codes(idx)
    f = found["TLS_EARLY_DATA_OFFERED"]
    assert f.severity == "low"  # type: ignore[attr-defined]
    assert f.evidence[0].frame == 3  # type: ignore[attr-defined]
    assert "42" in f.evidence[0].value  # type: ignore[attr-defined]


def test_no_findings_when_neither_offered() -> None:
    idx = _index(client_hello=Handshake(type=1, frame=3, sni="shop.example",
                                        extensions=[0, 43, 51]))[0]
    assert _codes(idx) == {}


def test_no_findings_without_client_hello() -> None:
    idx = _index(client_hello=None)[0]
    assert _codes(idx) == {}


@requires_tshark
def test_fixture_produces_both_findings(analyze_capture) -> None:
    result = analyze_capture(FIXTURES / "ech_0rtt_handshake.pcap")
    codes = {f.code for f in result.report.findings}
    assert "TLS_ECH_OFFERED" in codes
    assert "TLS_EARLY_DATA_OFFERED" in codes
