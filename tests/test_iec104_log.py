"""Zeek-style iec104.log (issue #206): APCI frame types, ASDU types, causes and addresses."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_iec104_log_has_one_row_per_apdu(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("iec104.pcap")).index, "iec104")
    assert [(r["apci"], r["u_function"], r["asdu_type"], r["cause"], r["common_addr"], r["ioa"]) for r in rows] == [
        ("U", "STARTDT act", None, None, None, None),
        ("U", "STARTDT con", None, None, None, None),
        ("I", None, "C_IC_NA_1", "Act", 1, 0),
        ("I", None, "M_SP_NA_1", "Spont", 1, 1),
        ("S", None, None, None, None, None),
        ("I", None, "C_SC_NA_1", "Act", 1, 101),
        ("U", "TESTFR act", None, None, None, None),
        ("U", "TESTFR con", None, None, None, None),
    ]
    assert all(r["id.resp_p"] == 2404 and r["id.orig_h"] == "10.14.0.5" for r in rows)
