"""Zeek-style opcua.log (issue #206): transport messages and the services they carry."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_opcua_log_has_one_row_per_transport_message(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("opcua.pcap")).index, "opcua")
    assert [(r["transport"], r["service"]) for r in rows] == [
        ("HEL", None),
        ("ACK", None),
        ("OPN", "OpenSecureChannelRequest"),
        ("MSG", "CreateSessionRequest"),
        ("MSG", "BrowseRequest"),
    ]
    assert all(r["id.resp_p"] == 4840 and r["id.orig_h"] == "10.17.0.5" for r in rows)
