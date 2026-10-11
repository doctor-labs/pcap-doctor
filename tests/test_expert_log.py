"""An expert log: every Wireshark expert-info item with its severity and group (issue #211)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_expert_log_keeps_every_severity_and_names_the_group(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("capture_loss.pcap")).index, "expert")
    severities = [r["severity"] for r in rows]
    # SYN and SYN+ACK are chat; the lost segment gives one or two warns depending on the tshark version
    assert severities[:2] == ["chat", "chat"] and set(severities[2:]) == {"warn"} and len(severities) >= 3, rows
    assert {r["group"] for r in rows} == {"sequence"}
    assert rows[0]["message"].startswith("Connection establish request (SYN)")
    assert any(r["severity"] == "warn" and "not captured" in r["message"] for r in rows), rows
    # the weird log is unchanged: only warn and error
    assert {r["severity"] for r in log_rows(analyze_capture(fixture("capture_loss.pcap")).index, "weird")} <= {"warn", "error"}
