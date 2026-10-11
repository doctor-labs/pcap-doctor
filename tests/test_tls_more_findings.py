"""Certificate not yet valid, SNI not covered by the certificate, and no extended master secret (#262, #263, #267)."""

from __future__ import annotations

from conftest import CAPTURES, requires_tshark
from pcap_doctor.detectors.tls_cipher import TlsCipherDetector
from pcap_doctor.index import CaptureIndex
from pcap_doctor.models import CaptureInfo, Cert, Flow, Handshake, TlsSession, endpoints_of, flow_key


def _index(**session: object) -> tuple[CaptureIndex, str]:
    info = CaptureInfo(path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0, packets=6, bytes=0,
                       first_seen=1_700_000_000.0, last_seen=1_700_000_010.0, duration=10.0)  # 2023-11-14
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
                            app_proto="tls", first_frame=1)
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
    return {f.code: f for f in TlsCipherDetector().detect(index)}


def test_certificate_not_yet_valid_at_capture_time() -> None:
    cert = Cert(chain_index=0, common_names=["shop.example"], san_dns=["shop.example"],
                not_before="2030-01-01 00:00:00 (UTC)", not_after="2031-01-01 00:00:00 (UTC)", frame=5)
    found = _codes(_index(certs=[cert], hostname_match=True)[0])
    f = found["TLS_CERT_NOT_YET_VALID"]
    assert f.severity == "high" and f.evidence[0].frame == 5  # type: ignore[attr-defined]
    ok = Cert(chain_index=0, common_names=["shop.example"], not_before="2023-01-01 00:00:00 (UTC)",
              not_after="2031-01-01 00:00:00 (UTC)", frame=5)
    assert "TLS_CERT_NOT_YET_VALID" not in _codes(_index(certs=[ok], hostname_match=True)[0])


def test_sni_not_covered_by_the_leaf_certificate() -> None:
    cert = Cert(chain_index=0, common_names=["other.example"], san_dns=["other.example"],
                not_before="2023-01-01 00:00:00 (UTC)", not_after="2031-01-01 00:00:00 (UTC)", frame=5)
    found = _codes(_index(certs=[cert], hostname_match=False)[0])
    f = found["TLS_SNI_CERT_MISMATCH"]
    assert f.severity == "medium" and "shop.example" in f.summary  # type: ignore[attr-defined]
    assert {e.frame for e in f.evidence} == {3, 5}  # type: ignore[attr-defined]
    assert "TLS_SNI_CERT_MISMATCH" not in _codes(_index(certs=[cert], hostname_match=True)[0])
    assert "TLS_SNI_CERT_MISMATCH" not in _codes(_index(certs=[cert], hostname_match=None)[0])


def test_tls12_without_extended_master_secret_but_not_tls13() -> None:
    tls12 = _index(negotiated_version="TLS 1.2", server_hello=Handshake(type=2, frame=4, extensions=[65281]))[0]
    f = _codes(tls12)["TLS_NO_EXTENDED_MASTER_SECRET"]
    assert f.evidence[0].frame == 4  # type: ignore[attr-defined]
    with_ems = _index(negotiated_version="TLS 1.2", server_hello=Handshake(type=2, frame=4, extensions=[23, 65281]))[0]
    assert "TLS_NO_EXTENDED_MASTER_SECRET" not in _codes(with_ems)
    assert "TLS_NO_EXTENDED_MASTER_SECRET" not in _codes(_index()[0])  # TLS 1.3 always derives keys per RFC 8446


@requires_tshark
def test_server_hello_extensions_come_from_the_capture(analyze_capture) -> None:
    result = analyze_capture(CAPTURES / "tls12-aes256gcm.pcap")
    (session,) = result.index.tls.values()
    assert session.server_hello is not None and session.server_hello.extensions == [65281]
    assert "TLS_NO_EXTENDED_MASTER_SECRET" in {f.code for f in result.report.findings}
