"""Zeek-style stun.log and rtsp.log (issue #224)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_stun_log_records_message_type_and_xor_mapped_address(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("stun_rtsp.pcap")).index, "stun")
    # frame 1: binding request (0x0001), no mapped address; frame 2: success response with XOR-MAPPED-ADDRESS.
    assert [(r["type"], r["mapped_ip"], r["mapped_port"]) for r in rows] == [
        ("0x0001", None, None),
        ("0x0101", "192.0.2.33", 4432),
    ]
    assert rows[0]["id.orig_h"] == "10.10.0.1" and rows[1]["id.resp_h"] == "10.10.0.2"


@requires_tshark
def test_rtsp_log_pairs_request_with_response_method_url_and_status(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("stun_rtsp.pcap")).index, "rtsp")
    # OPTIONS -> 200, DESCRIBE -> 404: one row per request carrying its response status.
    assert [(r["method"], r["url"], r["status"]) for r in rows] == [
        ("OPTIONS", "*", 200),
        ("DESCRIBE", "rtsp://10.10.0.2:554/stream/track1", 404),
    ]
    assert all(r["id.orig_h"] == "10.10.0.1" for r in rows)
