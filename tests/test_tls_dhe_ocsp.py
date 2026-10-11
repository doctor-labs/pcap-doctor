"""Weak DHE group (Logjam, #266) and a server that does not staple OCSP when asked (#261)."""

from __future__ import annotations

from conftest import CAPTURES, requires_tshark
from pcap_doctor.detectors.tls_cipher import TlsCipherDetector
from pcap_doctor.index import CaptureIndex
from pcap_doctor.models import CaptureInfo, Flow, Handshake, TlsSession, endpoints_of, flow_key


def _index(**session: object) -> CaptureIndex:
    info = CaptureInfo(path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0, packets=6, bytes=0,
                       first_seen=1_700_000_000.0, last_seen=1_700_000_010.0, duration=10.0)
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
                            app_proto="tls", first_frame=1)
    base: dict[str, object] = dict(
        key=key, negotiated_version="TLS 1.2", complete=True,
        client_hello=Handshake(type=1, frame=3, extensions=[0, 5, 10, 11, 13, 23]),
        server_hello=Handshake(type=2, frame=4, extensions=[23, 65281]),
    )
    base.update(session)
    index.tls[key] = TlsSession(**base)  # type: ignore[arg-type]
    return index


def _found(index: CaptureIndex) -> dict[str, object]:
    return {f.code: f for f in TlsCipherDetector().detect(index)}


def test_dhe_group_strength() -> None:
    f = _found(_index(dh_bits=1024, dh_frame=5))["TLS_WEAK_DH_GROUP"]
    assert f.severity == "medium" and f.evidence[0].frame == 5  # type: ignore[attr-defined]
    assert _found(_index(dh_bits=512, dh_frame=5))["TLS_WEAK_DH_GROUP"].severity == "high"  # type: ignore[attr-defined]
    assert "TLS_WEAK_DH_GROUP" not in _found(_index(dh_bits=2048, dh_frame=5))
    assert "TLS_WEAK_DH_GROUP" not in _found(_index())


def test_ocsp_staple_missing_only_when_the_client_asked() -> None:
    f = _found(_index())["TLS_NO_OCSP_STAPLE"]
    assert f.severity == "low" and f.evidence[0].frame == 4  # type: ignore[attr-defined]
    assert "TLS_NO_OCSP_STAPLE" not in _found(_index(ocsp_stapled=True))
    asked_not = Handshake(type=1, frame=3, extensions=[0, 10, 11])
    assert "TLS_NO_OCSP_STAPLE" not in _found(_index(client_hello=asked_not))
    stapled_ext = Handshake(type=2, frame=4, extensions=[5, 23])
    assert "TLS_NO_OCSP_STAPLE" not in _found(_index(server_hello=stapled_ext))
    assert "TLS_NO_OCSP_STAPLE" not in _found(_index(negotiated_version="TLS 1.3"))


@requires_tshark
def test_dh_bits_come_from_the_server_key_exchange(analyze_capture) -> None:
    sessions = analyze_capture(CAPTURES / "tls12-chacha20poly1305.pcap").index.tls.values()
    assert sorted(s.dh_bits for s in sessions if s.dh_bits) == [2048, 3072]
