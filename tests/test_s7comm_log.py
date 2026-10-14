"""Zeek-style s7comm.log (issue #206): ROSCTR, functions, memory areas and data blocks."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_s7comm_log_has_one_row_per_pdu(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("s7comm.pcap")).index, "s7comm")
    assert [(r["rosctr"], r["function"], r["item_count"], r["area"], r["db"]) for r in rows] == [
        ("Job", "Setup communication", None, None, None),
        ("Ack", None, None, None, None),
        ("Job", "Read Var", 1, "Data blocks (DB)", 1),
        ("Ack_Data", "Read Var", 1, None, None),
        ("Job", "Write Var", 1, "Data blocks (DB)", 2),
        ("Ack", None, None, None, None),
    ]
    assert all(r["id.resp_p"] == 102 and r["id.orig_h"] == "10.16.0.5" for r in rows)
