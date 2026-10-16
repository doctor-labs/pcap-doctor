"""Certificate Transparency SCT presence check (#265).

Per RFC 6962 section 6.1, a certificate should carry the SignedCertificateTimestampList
extension (OID 1.3.6.1.4.1.11129.2.4.2) whose entries are SCTs from CT logs. Their
absence does not by itself mean the certificate is untrusted, but it removes the
transparency guarantee that CT is supposed to provide.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from conftest import requires_tshark
from pcap_doctor.detectors.tls_cipher import TlsCipherDetector
from pcap_doctor.index import CaptureIndex
from pcap_doctor.models import CaptureInfo, Cert, Flow, Handshake, TlsSession, endpoints_of, flow_key

#: OID 1.3.6.1.4.1.11129.2.4.2 in DER TLV form: tag 06, length 0a, arc bytes.
#: Verified with ``openssl asn1parse`` (decodes to "CT Precertificate SCTs").
SCT_OID_DER = bytes.fromhex("060a2b06010401d679020402")

FIXTURE_CERTS = Path(__file__).resolve().parents[1] / "scripts" / "fixture_certs"


def _der_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _cert_with_sct() -> bytes:
    """DER of the committed fixture cert that carries the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)."""
    out = subprocess.run(
        ["openssl", "x509", "-in", str(FIXTURE_CERTS / "sct.example.crt"), "-outform", "DER"],
        capture_output=True, check=True,
    )
    assert SCT_OID_DER in out.stdout, "fixture cert must carry the SCT extension"
    return out.stdout


def _cert_without_sct() -> bytes:
    """DER of the committed strong fixture cert, which has no SCT extension."""
    out = subprocess.run(
        ["openssl", "x509", "-in", str(FIXTURE_CERTS / "strong.example.crt"), "-outform", "DER"],
        capture_output=True, check=True,
    )
    assert SCT_OID_DER not in out.stdout, "fixture cert must not carry the SCT extension"
    return out.stdout


def _index(leaf_der: bytes | None = None, **session: object) -> CaptureIndex:
    info = CaptureInfo(path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0, packets=6, bytes=0,
                       first_seen=1_700_000_000.0, last_seen=1_700_000_010.0, duration=10.0)
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
                            app_proto="tls", first_frame=1)
    if leaf_der is not None:
        fp = _der_fingerprint(leaf_der)
        index.cert_der[fp] = leaf_der
        cert = Cert(chain_index=0, common_names=["sct.example"], fingerprint=fp, frame=4)
        certs = [cert]
    else:
        certs = []
    base: dict[str, object] = dict(
        key=key, negotiated_version="TLS 1.2", complete=True,
        client_hello=Handshake(type=1, frame=3, extensions=[0, 5, 10, 11, 13, 23]),
        server_hello=Handshake(type=2, frame=4, extensions=[23, 65281]),
        certs=certs,
    )
    base.update(session)
    index.tls[key] = TlsSession(**base)  # type: ignore[arg-type]
    return index


def _found(index: CaptureIndex) -> dict[str, object]:
    return {f.code: f for f in TlsCipherDetector().detect(index)}


def test_cert_with_sct_does_not_flag() -> None:
    assert "TLS_NO_SCT" not in _found(_index(_cert_with_sct()))


def test_cert_without_sct_is_flagged() -> None:
    f = _found(_index(_cert_without_sct()))["TLS_NO_SCT"]
    assert f.severity == "low"
    assert f.evidence[0].frame == 4  # type: ignore[attr-defined]


def test_no_cert_is_not_flagged() -> None:
    # No certificate at all: nothing to check, not a silent pass of the check itself.
    assert "TLS_NO_SCT" not in _found(_index())


@requires_tshark
def test_fixture_sct_cert_has_no_sct_finding(analyze_capture) -> None:
    """A real TLS capture whose leaf cert carries the CT SCT extension must not raise TLS_NO_SCT."""
    result = analyze_capture(Path("tests/fixtures/sct_tls12.pcap"))
    codes = {f.code for f in result.report.findings}
    assert "TLS_NO_SCT" not in codes


@requires_tshark
def test_existing_fixtures_still_flag_missing_sct(analyze_capture) -> None:
    """no_pfs_tls12.pcap uses a cert with no SCT extension and must raise TLS_NO_SCT."""
    result = analyze_capture(Path("tests/fixtures/no_pfs_tls12.pcap"))
    codes = {f.code for f in result.report.findings}
    assert "TLS_NO_SCT" in codes
