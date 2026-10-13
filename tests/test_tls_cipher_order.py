"""Server cipher-order preference (#272): does the server honour the client's cipher
list order, or impose its own?"""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.detectors.tls_cipher import TlsCipherDetector
from pcap_doctor.index import CaptureIndex
from pcap_doctor.models import CaptureInfo, Flow, Handshake, TlsSession, endpoints_of, flow_key

pytestmark = requires_tshark


def _index(**session: object) -> tuple[CaptureIndex, str]:
    info = CaptureInfo(path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0, packets=6, bytes=0,
                       first_seen=1_700_000_000.0, last_seen=1_700_000_010.0, duration=10.0)  # 2023-11-14
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
                            app_proto="tls", first_frame=1)
    base: dict[str, object] = dict(
        key=key, negotiated_version="TLS 1.2", complete=True,
    )
    base.update(session)
    index.tls[key] = TlsSession(**base)  # type: ignore[arg-type]
    return index, key


def _codes_from_index(index: CaptureIndex) -> set[str]:
    return {f.code for f in TlsCipherDetector().detect(index)}


# -- unit-level: build a TlsSession with known cipher order -------------------

def test_server_picks_non_first_cipher_reports_preference() -> None:
    """Client offers AES128-SHA then ECDHE-GCM; server picks ECDHE-GCM (not first)."""
    ch = Handshake(type=1, frame=3, cipher_suites=[0x002F, 0xC02F])
    sh = Handshake(type=2, frame=4, cipher_suite=0xC02F)
    index, _ = _index(client_hello=ch, server_hello=sh, offered_ciphers=[0x002F, 0xC02F],
                      chosen_cipher=0xC02F)
    assert "TLS_SERVER_CIPHER_PREFERENCE" in _codes_from_index(index)


def test_server_picks_first_cipher_is_not_reported() -> None:
    """Client offers AES128-SHA then ECDHE-GCM; server picks AES128-SHA (first)."""
    ch = Handshake(type=1, frame=3, cipher_suites=[0x002F, 0xC02F])
    sh = Handshake(type=2, frame=4, cipher_suite=0x002F)
    index, _ = _index(client_hello=ch, server_hello=sh, offered_ciphers=[0x002F, 0xC02F],
                      chosen_cipher=0x002F)
    assert "TLS_SERVER_CIPHER_PREFERENCE" not in _codes_from_index(index)


def test_no_cipher_order_finding_when_offered_is_empty() -> None:
    sh = Handshake(type=2, frame=4, cipher_suite=0xC02F)
    index, _ = _index(server_hello=sh, offered_ciphers=[], chosen_cipher=0xC02F)
    assert "TLS_SERVER_CIPHER_PREFERENCE" not in _codes_from_index(index)


# -- fixture-level: real handshake via tshark -------------------------------

def test_server_cipher_order_fixture(analyze_capture) -> None:
    """The server_cipher_order.pcap fixture: client offers AES128-SHA first, server picks ECDHE-GCM."""
    result = analyze_capture(fixture("server_cipher_order.pcap"))
    found = {f.code for f in result.report.findings}
    (session,) = result.index.tls.values()
    assert session.chosen_cipher == 0xC02F  # ECDHE_RSA_AES_128_GCM_SHA256
    assert session.offered_ciphers[0] == 0x002F  # AES128-SHA is first in the client list
    assert session.offered_ciphers[1] == 0xC02F  # ECDHE-GCM is second
    assert "TLS_SERVER_CIPHER_PREFERENCE" in found
