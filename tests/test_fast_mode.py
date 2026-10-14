"""Opt-in ``--fast``: BPF pre-split for port-based passes (issue #334).

Default (no ``--fast``) behaviour is byte-identical to before: the tshark command
for every pass is unchanged. With ``--fast``, passes whose protocols live on
well-known ports are pre-split with a tcpdump BPF filter so tshark only touches
the small sub-capture; findings on standard ports are identical, protocols on
non-standard ports are documented as missed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.pipeline import analyze
from pcap_doctor.tshark import PASSES, TsharkRunner

pytestmark = requires_tshark


def _has_tcpdump() -> bool:
    return shutil.which("tcpdump") is not None


def test_commands_without_fast_are_unchanged() -> None:
    """Without --fast the tshark argv for every pass is the full-capture command."""
    runner = TsharkRunner(fixture("dns_tunnel.pcap"), use_cache=False)
    for pass_name in ("dns", "sip", "ssh", "services", "telnet", "smb"):
        cmd = runner._command(PASSES[pass_name])
        assert str(fixture("dns_tunnel.pcap")) in cmd
        assert "-r" in cmd


def test_fast_equal_findings_on_standard_port_fixture(tmp_path: Path) -> None:
    """With --fast on a standard-port fixture, findings equal the normal run."""
    if not _has_tcpdump():
        pytest.skip("tcpdump is not installed")
    normal = analyze(fixture("dns_tunnel.pcap"), tmp_path / "normal")
    fast = analyze(fixture("dns_tunnel.pcap"), tmp_path / "fast", fast=True)
    assert {f.code for f in normal.report.findings} == {f.code for f in fast.report.findings}


def test_fast_misses_dns_on_nonstandard_port(tmp_path: Path) -> None:
    """With --fast, DNS on a non-standard port (5354) is missed: the normal run
    finds DNS_CLEARTEXT, the fast run does not. Non-standard ports are out of
    scope for the port-53 BPF filter (issue #334)."""
    if not _has_tcpdump():
        pytest.skip("tcpdump is not installed")
    normal = analyze(fixture("dns_odd_port.pcap"), tmp_path / "normal")
    assert "DNS_CLEARTEXT" in {f.code for f in normal.report.findings}
    fast = analyze(fixture("dns_odd_port.pcap"), tmp_path / "fast", fast=True)
    assert "DNS_CLEARTEXT" not in {f.code for f in fast.report.findings}
    # the fast run documents the miss as a note
    notes = " ".join(fast.index.notes)
    assert "--fast" in notes


def test_fast_falls_back_without_tcpdump(tmp_path: Path, monkeypatch) -> None:
    """Without tcpdump, --fast prints a note and falls back to the normal path."""
    if _has_tcpdump():
        monkeypatch.setattr(
            "pcap_doctor.tshark.shutil.which", lambda name: None if name == "tcpdump" else shutil.which(name)
        )
    fast = analyze(fixture("dns_tunnel.pcap"), tmp_path / "fast", fast=True)
    notes = " ".join(fast.index.notes)
    assert "tcpdump" in notes.lower()
    assert "DNS_CLEARTEXT" in {f.code for f in fast.report.findings}
