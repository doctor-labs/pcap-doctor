"""TCP stream health and checksum validation in conn.log and weird.log (issues #208, #209)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_conn_history_carries_gap_retransmit_zero_window_and_checksum_letters(analyze_capture) -> None:
    index = analyze_capture(fixture("tcp_health.pcap")).index
    conns = {r["id.orig_p"]: r for r in log_rows(index, "conn")}
    tcp, udp = conns[47000], conns[47001]
    assert tcp["history"] == "ShADaDTDGDawadACFfA"
    assert (tcp["missed_bytes"], tcp["dup_acks"], tcp["out_of_order"]) == (100, 1, 0)
    assert udp["history"] == "C" and udp["missed_bytes"] == 0


@requires_tshark
def test_bad_checksums_use_zeek_weird_names(analyze_capture) -> None:
    names = [w["name"] for w in log_rows(analyze_capture(fixture("tcp_health.pcap")).index, "weird")]
    assert "bad_TCP_checksum" in names and "bad_UDP_checksum" in names
    assert "tcp_zero_window_segment" in names
