"""Decode-as: dissect a port as a given protocol, like Wireshark's Decode As / tshark -d (issue #254)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.pipeline import analyze


def _codes(tmp_path: Path, name: str, **kwargs: object) -> set[str]:
    result = analyze(fixture("ftp_odd_port.pcap"), tmp_path / name, **kwargs)  # type: ignore[arg-type]
    return {f.code for f in result.report.findings}


@requires_tshark
def test_an_ftp_login_on_an_odd_port_is_seen_only_with_decode_as(tmp_path: Path) -> None:
    assert "CLEARTEXT_CREDENTIAL" not in _codes(tmp_path, "plain")
    # the same capture, same cache directory: decode-as results must not be served from the plain run's cache
    assert "CLEARTEXT_CREDENTIAL" in _codes(tmp_path, "decoded", decode_as=("tcp.port==2121,ftp",))


@pytest.mark.parametrize("spec", ["tcp.port=2121,ftp", "tcp.port==2121", "tcp.port==2121,ftp;rm", "-o x", ""])
def test_a_malformed_decode_as_spec_is_refused(tmp_path: Path, spec: str) -> None:
    with pytest.raises(ValueError, match="decode-as"):
        analyze(fixture("ftp_odd_port.pcap"), tmp_path / "bad", decode_as=(spec,))
