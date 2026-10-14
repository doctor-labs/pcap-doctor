"""Keyword / byte-pattern search across packet payloads (issue #215)."""

from __future__ import annotations

import json

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.search import search_payloads


@requires_tshark
def test_search_finds_a_literal_keyword_in_a_tcp_payload(cli_runner, tmp_path) -> None:
    pcap = fixture("search_bytes.pcap")
    out = cli_runner.invoke(app, ["search", str(pcap), "secret-token", "--json"]).output
    data = json.loads(out)
    assert data["matches"] == 1
    assert data["pattern"] == "secret-token" and data["hex"] is False
    m = data["results"][0]
    assert (m["frame"], m["proto"], m["offset"], m["length"], m["direction"]) == (
        4,
        "tcp",
        8,
        12,
        "client->server",
    )
    assert (m["src"], m["dst"], m["sport"], m["dport"]) == ("10.20.0.10", "10.20.0.1", 40000, 80)
    # bytes surface as hex, never as raw text, in JSON
    assert m["snippet"] == b"secret-token".hex()


@requires_tshark
def test_search_hex_pattern_finds_a_udp_payload(cli_runner, tmp_path) -> None:
    pcap = fixture("search_bytes.pcap")
    out = cli_runner.invoke(app, ["search", str(pcap), "deadbeef", "--hex", "--json"]).output
    data = json.loads(out)
    assert data["matches"] == 1 and data["hex"] is True
    m = data["results"][0]
    assert (m["frame"], m["proto"], m["offset"], m["length"], m["direction"]) == (
        11,
        "udp",
        0,
        4,
        "client->server",
    )
    assert (m["src"], m["dst"], m["sport"], m["dport"]) == ("10.20.0.10", "10.20.0.1", 53000, 53)
    assert m["snippet"] == "deadbeef"


@requires_tshark
def test_search_keyword_not_present_reports_zero_and_exits_1(cli_runner, tmp_path) -> None:
    pcap = fixture("search_bytes.pcap")
    result = cli_runner.invoke(app, ["search", str(pcap), "no-such-thing-here"])
    assert result.exit_code == 1
    assert "0 match" in result.output


@requires_tshark
def test_search_payloads_returns_frame_offset_and_snippet() -> None:
    pcap = fixture("search_bytes.pcap")
    matches = search_payloads(pcap, b"secret-token")
    assert len(matches) == 1
    m = matches[0]
    assert (m.frame, m.proto, m.offset, m.length, m.snippet) == (4, "tcp", 8, 12, b"secret-token")


@requires_tshark
def test_search_reports_every_offset_when_a_pattern_repeats() -> None:
    pcap = fixture("search_bytes.pcap")
    # "echo:" is a substring of "echo: password"; ensure multiple offset hits within one frame are all listed
    matches = search_payloads(pcap, b"echo")
    assert {m.frame for m in matches} == {6}
    assert len(matches) == 1 and matches[0].offset == 0 and matches[0].proto == "tcp"


@requires_tshark
def test_search_empty_pattern_is_rejected(cli_runner, tmp_path) -> None:
    # An empty pattern matches nothing meaningful and is rejected at the boundary, never a silent pass.
    pcap = fixture("search_bytes.pcap")
    result = cli_runner.invoke(app, ["search", str(pcap), "", "--hex"])
    assert result.exit_code == 2
    assert "pattern" in result.output.lower()


@requires_tshark
def test_search_marks_server_replies_as_server_to_client(cli_runner) -> None:
    # Frame 6 is the server's reply ("echo:..."); its well-known port (80) is the source, so direction flips.
    matches = search_payloads(fixture("search_bytes.pcap"), b"echo")
    m = matches[0]
    assert m.frame == 6 and m.proto == "tcp"
    assert m.src == "10.20.0.1" and m.sport == 80 and m.dst == "10.20.0.10" and m.dport == 40000
    assert m.direction == "server->client"
