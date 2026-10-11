"""Zeek-style modbus.log and dnp3.log (issue #206, part 1)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_modbus_log_has_one_row_per_reply_with_function_and_exception(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("ics_mix.pcap")).index, "modbus")
    assert [(r["func"], r["exception"]) for r in rows] == [
        ("READ_HOLDING_REGISTERS", None),
        ("WRITE_SINGLE_REGISTER", None),
        ("READ_HOLDING_REGISTERS", "ILLEGAL_DATA_ADDRESS"),
    ]
    assert all(r["id.resp_p"] == 502 and r["id.orig_h"] == "10.8.0.10" for r in rows)


@requires_tshark
def test_dnp3_log_pairs_requests_with_replies(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("ics_mix.pcap")).index, "dnp3")
    assert [(r["fc_request"], r["fc_reply"], r["iin"]) for r in rows] == [
        ("READ", "RESPONSE", 0),
        ("COLD_RESTART", "RESPONSE", 0x8000),
    ]
    assert all(r["id.resp_p"] == 20000 for r in rows)
