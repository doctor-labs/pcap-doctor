"""Zeek-style capture_loss.log and a CAPTURE_LOSS finding: segments after a mid-stream hole (issue #240)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_acked_unseen_data_is_measured_and_reported(analyze_capture) -> None:
    result = analyze_capture(fixture("capture_loss.pcap"))
    (row,) = log_rows(result.index, "capture_loss")
    assert (row["acks"], row["gaps"], row["percent_lost"]) == (5, 1, 20.0)
    findings = [f for f in result.report.findings if f.code == "CAPTURE_LOSS"]
    assert len(findings) == 1, findings
    assert findings[0].severity == "low"
    assert "20.0%" in findings[0].summary
    assert findings[0].evidence[0].frame == 5  # the segment after the hole


@requires_tshark
def test_a_capture_without_tcp_gaps_has_no_loss_finding(analyze_capture) -> None:
    result = analyze_capture(fixture("tunnels.pcap"))
    assert not [f for f in result.report.findings if f.code == "CAPTURE_LOSS"]
