"""Session search and per-session PCAP retrieval (issue #251)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.index import IndexBuilder
from pcap_doctor.sessions import search_sessions, session_pcap
from pcap_doctor.tshark import TsharkRunner

PCAP = "http_basic.pcap"


def _index(path: Path):
    return IndexBuilder(TsharkRunner(path, use_cache=False)).build()


def _first_stream(index) -> object:
    return next(f for f in index.flows.values() if f.stream_index is not None)


@requires_tshark
def test_search_finds_session_by_http_host_and_misses_unknown_text() -> None:
    index = _index(fixture(PCAP))
    exchange = index.http[0]
    assert exchange.key in [f.key for f in search_sessions(index, exchange.host)]
    assert search_sessions(index, "no-such-session-anywhere") == []


@requires_tshark
def test_empty_query_lists_every_session() -> None:
    index = _index(fixture(PCAP))
    assert len(search_sessions(index)) == len(index.flows)


@requires_tshark
def test_session_pcap_holds_only_that_session(tmp_path: Path) -> None:
    flow = _first_stream(_index(fixture(PCAP)))
    out = tmp_path / "one.pcapng"
    assert session_pcap(fixture(PCAP), flow, out) == flow.packets
    assert list(_index(out).flows) == [flow.key]


@requires_tshark
def test_cli_lists_then_extracts_one_session(tmp_path: Path) -> None:
    runner = CliRunner()
    flow = _first_stream(_index(fixture(PCAP)))
    listed = runner.invoke(app, ["session", str(fixture(PCAP)), "--json", "--limit", "0"])
    assert listed.exit_code == 0 and flow.key in listed.output
    out = tmp_path / "s.pcapng"
    done = runner.invoke(app, ["session", str(fixture(PCAP)), "--key", flow.key, "--out", str(out)])
    assert done.exit_code == 0 and out.exists()
    assert runner.invoke(app, ["session", str(fixture(PCAP)), "--key", flow.key]).exit_code == 2
