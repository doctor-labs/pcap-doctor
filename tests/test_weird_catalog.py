"""Zeek weird names for the tshark expert messages that have an exact Zeek equivalent (issue #210)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import ZEEK_WEIRD, log_rows, zeek_weird_name


@requires_tshark
def test_weird_log_uses_zeek_names_for_exact_matches(analyze_capture) -> None:
    names = {w["name"] for w in log_rows(analyze_capture(fixture("weird_mix.pcap")).index, "weird")}
    assert {"UDP_datagram_length_mismatch", "TCP_scale_range", "HTTP_content_length_and_chunked"} <= names, names


def test_unmapped_messages_keep_their_slug_and_the_table_is_exact_only() -> None:
    assert zeek_weird_name("Bad length value 66 > IP payload length") == "UDP_datagram_length_mismatch"
    assert zeek_weird_name("Window scale shift exceeds 14") == "TCP_scale_range"
    assert zeek_weird_name("Bogus TCP Header length (12, must be at least 20)") == "bad_TCP_header_len"
    assert zeek_weird_name("TCP Zero Window segment") == "tcp_zero_window_segment"
    assert all(name and name == name.strip() for name in ZEEK_WEIRD.values())
