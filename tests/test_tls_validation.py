"""TLS chain validation status and SNI hostname match (issue #260)."""

from __future__ import annotations

import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.certificates import hostname_matches, verify_chain

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")


def _chain(tmp: Path) -> tuple[Path, str]:
    """A throwaway root CA and a leaf for svc.example it signed; returns (ca.pem, leaf DER hex)."""
    def run(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=tmp)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "3650",
        "-subj", "/CN=Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=svc.example")
    (tmp / "ext").write_text("subjectAltName=DNS:svc.example,DNS:*.svc.example\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "leaf.pem",
        "-days", "365", "-extfile", "ext")
    return tmp / "ca.pem", ssl.PEM_cert_to_DER_cert((tmp / "leaf.pem").read_text()).hex()


@needs_openssl
def test_verify_chain_uses_the_bundle_and_the_capture_time(tmp_path, monkeypatch) -> None:
    ca, leaf = _chain(tmp_path)
    monkeypatch.delenv("PCAP_DOCTOR_CA_BUNDLE", raising=False)
    assert verify_chain([leaf]) == "unable to get local issuer certificate"
    monkeypatch.setenv("PCAP_DOCTOR_CA_BUNDLE", str(ca))
    assert verify_chain([leaf]) == "ok"
    assert verify_chain([leaf], 4102444800.0) == "certificate has expired"  # checked as of 2100-01-01
    assert verify_chain([]) is None


def test_hostname_match_follows_rfc6125_wildcards() -> None:
    names = ["svc.example", "*.svc.example"]
    assert hostname_matches("svc.example", names) and hostname_matches("A.SVC.example.", names)
    assert not hostname_matches("a.b.svc.example", names)
    assert not hostname_matches("evil.example", names)


@requires_tshark
@needs_openssl
def test_self_signed_session_is_reported_and_its_name_matches(analyze_capture) -> None:
    (s,) = analyze_capture(fixture("weak_tls.pcap")).index.tls.values()
    assert s.validation_status is not None and "self" in s.validation_status and "signed" in s.validation_status
    assert s.sni == "weak.example" and s.hostname_match is True
