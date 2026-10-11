"""An expert log: every Wireshark expert-info item with its severity and group (issue #211)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_expert_log_keeps_every_severity_and_names_the_group(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("capture_loss.pcap")).index, "expert")
    assert [r["severity"] for r in rows] == ["chat", "chat", "warn", "warn"], rows
    assert {r["group"] for r in rows} == {"sequence"}
    assert rows[0]["message"].startswith("Connection establish request (SYN)")
    assert rows[2]["message"].startswith("Previous segment(s) not captured")
    # the weird log is unchanged: only warn and error
    assert {r["severity"] for r in log_rows(analyze_capture(fixture("capture_loss.pcap")).index, "weird")} <= {"warn", "error"}
