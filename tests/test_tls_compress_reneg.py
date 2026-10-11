"""TLS compression (CRIME) and insecure renegotiation are scored (issue #243)."""

from __future__ import annotations

from conftest import CAPTURES, requires_tshark
from pcap_doctor.detectors.tls_cipher import TlsCipherDetector
from pcap_doctor.index import CaptureIndex
from pcap_doctor.models import CaptureInfo, Flow, Handshake, TlsSession, endpoints_of, flow_key


def _codes(**session: object) -> dict[str, object]:
    info = CaptureInfo(path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0, packets=6, bytes=0,
                       first_seen=1_700_000_000.0, last_seen=1_700_000_010.0, duration=10.0)
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
                            app_proto="tls", first_frame=1)
    base: dict[str, object] = dict(
        key=key, negotiated_version="TLS 1.2", complete=True,
        client_hello=Handshake(type=1, frame=3, cipher_suites=[0xC02F], compression_methods=[1, 0], extensions=[0, 65281]),
        server_hello=Handshake(type=2, frame=4, cipher_suite=0xC02F, compression_methods=[0], extensions=[65281, 23]),
    )
    base.update(session)
    index.tls[key] = TlsSession(**base)  # type: ignore[arg-type]
    return {f.code: f for f in TlsCipherDetector().detect(index)}


def test_server_chosen_compression_is_crime() -> None:
    sh = Handshake(type=2, frame=4, cipher_suite=0xC02F, compression_methods=[1], extensions=[65281, 23])
    f = _codes(server_hello=sh)["TLS_COMPRESSION_ENABLED"]
    assert f.severity == "high" and f.evidence[0].frame == 4  # type: ignore[attr-defined]
    assert "TLS_COMPRESSION_ENABLED" not in _codes()


def test_renegotiation_without_renegotiation_info_or_scsv_is_insecure() -> None:
    ch = Handshake(type=1, frame=3, cipher_suites=[0xC02F], compression_methods=[0], extensions=[0])
    sh = Handshake(type=2, frame=4, cipher_suite=0xC02F, compression_methods=[0], extensions=[23])
    f = _codes(client_hello=ch, server_hello=sh)["TLS_INSECURE_RENEGOTIATION"]
    assert f.severity == "medium"  # type: ignore[attr-defined]
    assert "TLS_INSECURE_RENEGOTIATION" not in _codes()  # the server echoes renegotiation_info
    scsv = Handshake(type=1, frame=3, cipher_suites=[0xC02F, 0x00FF], compression_methods=[0], extensions=[0])
    assert "TLS_INSECURE_RENEGOTIATION" in _codes(client_hello=scsv, server_hello=sh)  # SCSV offered but not acknowledged
    assert "TLS_INSECURE_RENEGOTIATION" not in _codes(negotiated_version="TLS 1.3", client_hello=ch, server_hello=sh)


@requires_tshark
def test_compression_methods_are_read_from_the_capture(analyze_capture) -> None:
    result = analyze_capture(CAPTURES / "tls-renegotiation.pcap")
    (s,) = result.index.tls.values()
    assert s.server_hello is not None and s.server_hello.compression_methods == [0]
    assert s.client_hello is not None and 0 in s.client_hello.compression_methods
    codes = {f.code for f in result.report.findings}
    assert "TLS_COMPRESSION_ENABLED" not in codes and "TLS_INSECURE_RENEGOTIATION" not in codes
