"""Zeek-style enip.log (issue #206): encapsulation commands, session handles and CIP services."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_enip_log_has_one_row_per_encapsulation_packet(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("enip.pcap")).index, "enip")
    assert [(r["command"], r["session"], r["cip_service"], r["cip_reply"], r["cip_class"]) for r in rows] == [
        ("List Identity", 0, None, None, None),
        ("List Identity", 0, None, None, None),
        ("Register Session", 0, None, None, None),
        ("Register Session", 0x1A2B3C4D, None, None, None),
        ("Send RR Data", 0x1A2B3C4D, "Get Attribute Single", False, 1),
        ("Send RR Data", 0x1A2B3C4D, "Get Attribute Single", True, 1),  # tshark ties the reply to its request class
    ]
    assert all(r["id.resp_p"] == 44818 and r["id.orig_h"] == "10.13.0.5" for r in rows)
