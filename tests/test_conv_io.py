"""Conversation statistics (#248) and an IO time series (#249)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_conversations_count_frames_and_bytes_per_outer_ip_pair(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("tunnels.pcap")).index, "conversations")
    by_pair = {(r["a"], r["b"]): r for r in rows}
    # the OUTER addresses of each frame; a and b are sorted so both directions land in one row
    assert set(by_pair) == {("10.10.0.1", "10.10.0.2"), ("10.20.0.1", "10.20.0.2"), ("10.30.0.1", "10.30.0.2")}, rows
    gre = by_pair[("10.10.0.1", "10.10.0.2")]
    assert (gre["frames"], gre["bytes"], gre["duration"]) == (1, 74, 0.0)
    assert [r["bytes"] for r in rows] == sorted((r["bytes"] for r in rows), reverse=True)  # biggest first


@requires_tshark
def test_io_series_buckets_frames_and_bytes_per_second(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("tunnels.pcap")).index, "io")
    assert len(rows) == 1, rows  # the three frames fall in the same one-second bucket
    assert (rows[0]["frames"], rows[0]["bytes"], rows[0]["offset"]) == (3, 232, 0)
