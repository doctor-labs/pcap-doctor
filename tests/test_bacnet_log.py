"""Zeek-style bacnet.log (issue #206): BVLC functions, APDU types, services and invoke ids."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_bacnet_log_pairs_requests_with_acknowledgements(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("bacnet.pcap")).index, "bacnet")
    assert [(r["bvlc_function"], r["apdu_type"], r["service"], r["invoke_id"]) for r in rows] == [
        ("Original-Broadcast-NPDU", "Unconfirmed-REQ", "who-Is", None),
        ("Original-Unicast-NPDU", "Unconfirmed-REQ", "i-Am", None),
        ("Original-Unicast-NPDU", "Confirmed-REQ", "readProperty", 1),
        ("Original-Unicast-NPDU", "Complex-ACK", "readProperty", 1),
        ("Original-Unicast-NPDU", "Confirmed-REQ", "writeProperty", 2),
        ("Original-Unicast-NPDU", "Simple-ACK", "writeProperty", 2),
    ]
    assert all(r["id.resp_p"] == 47808 for r in rows)
