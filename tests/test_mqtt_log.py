"""Zeek-style mqtt.log (issue #206): control packets, client ids, topics and CONNACK return codes, never passwords."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_mqtt_log_has_one_row_per_control_packet(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("mqtt.pcap")).index, "mqtt")
    assert [(r["msg_type"], r["client_id"], r["username"], r["topic"], r["return_code"]) for r in rows] == [
        ("Connect Command", "pf-sensor-7", "plant", None, None),
        ("Connect Ack", None, None, None, 0),
        ("Publish Message", None, None, "plant/line1/temp", None),
        ("Publish Message", None, None, "plant/line1/temp", None),
        ("Ping Request", None, None, None, None),
        ("Ping Response", None, None, None, None),
        ("Disconnect Req", None, None, None, None),
        ("Connect Command", "scanner", "admin", None, None),
        ("Connect Ack", None, None, None, 5),
    ]
    assert all(r["version"] == 4 for r in rows if r["msg_type"] == "Connect Command")
    assert all(r["id.resp_p"] == 1883 for r in rows)
    assert {r["id.orig_h"] for r in rows} == {"10.12.0.5", "10.12.0.66"}


@requires_tshark
def test_mqtt_log_never_carries_the_password(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("mqtt.pcap")).index, "mqtt")
    assert "hunter2" not in repr(rows)
    assert all(set(r) <= {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "msg_type",
                          "client_id", "username", "topic", "return_code"} for r in rows)
