"""Heartbleed probes: a heartbeat request whose payload_length is larger than its record (#234, #264)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_heartbleed_probe_is_flagged_and_an_honest_heartbeat_is_not(analyze_capture) -> None:
    found = [f for f in analyze_capture(fixture("heartbleed.pcap")).report.findings if f.code == "TLS_HEARTBLEED_PROBE"]
    assert len(found) == 1, found
    (f,) = found
    assert f.severity == "high" and f.confidence == "high"
    assert f.flow_key is not None and f.flow_key.endswith(":49300")
    assert (f.evidence[0].frame, f.evidence[0].value) == (4, "16384")
    assert "10.9.0.66" in f.subjects
