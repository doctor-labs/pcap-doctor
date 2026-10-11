"""Certificate export: every TLS certificate seen is written as PEM, named by its SHA-256 (issue #212)."""

from __future__ import annotations

import hashlib
import ssl
from pathlib import Path

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows
from pcap_doctor.pipeline import analyze


@requires_tshark
def test_certificates_are_exported_as_pem_named_by_fingerprint(tmp_path: Path) -> None:
    result = analyze(fixture("weak_tls.pcap"), tmp_path / "out")
    pems = sorted((tmp_path / "out" / "certificates").glob("*.pem"))
    assert pems, "at least one certificate is exported"
    for pem in pems:
        der = ssl.PEM_cert_to_DER_cert(pem.read_text())
        assert hashlib.sha256(der).hexdigest() == pem.stem, pem.name
    # the x509 log names the same certificates by the same fingerprint
    fingerprints = {r["fingerprint"] for r in log_rows(result.index, "x509") if r.get("fingerprint")}
    assert fingerprints == {p.stem for p in pems}


@requires_tshark
def test_a_capture_without_tls_exports_no_certificates(tmp_path: Path) -> None:
    analyze(fixture("tunnels.pcap"), tmp_path / "out")
    assert not list((tmp_path / "out" / "certificates").glob("*.pem"))
