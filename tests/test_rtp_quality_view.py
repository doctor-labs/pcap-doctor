"""RTP quality view detector: per-stream loss, jitter, MOS and summary (issue #253)."""

from __future__ import annotations

import pytest

from conftest import codes, fixture, requires_tshark


@requires_tshark
@pytest.mark.parametrize(
    "pcap, expected_subset",
    [
        (
            "rtp_quality.pcap",
            {"RTP_STREAM_SUMMARY", "RTP_PACKET_LOSS_HIGH", "RTP_MOS_POOR"},
        ),
        (
            "rtp_quality_clean.pcap",
            {"RTP_STREAM_SUMMARY"},
        ),
        (
            "rtp_quality_lossy.pcap",
            {
                "RTP_STREAM_SUMMARY",
                "RTP_PACKET_LOSS_HIGH",
                "RTP_JITTER_HIGH",
                "RTP_MOS_POOR",
            },
        ),
    ],
)
def test_rtp_quality_view_codes(analyze_capture, pcap, expected_subset):
    result = analyze_capture(fixture(pcap))
    found = codes(result)
    assert expected_subset <= found


@requires_tshark
def test_rtp_quality_view_negative_no_rtp(analyze_capture):
    # Captures without RTP media must not produce RTP quality-view findings.
    result = analyze_capture(fixture("strong_tls13.pcap"))
    found = codes(result)
    assert "RTP_STREAM_SUMMARY" not in found
    assert "RTP_PACKET_LOSS_HIGH" not in found
    assert "RTP_JITTER_HIGH" not in found
    assert "RTP_MOS_POOR" not in found


@requires_tshark
def test_rtp_quality_clean_has_no_warning_findings(analyze_capture):
    result = analyze_capture(fixture("rtp_quality_clean.pcap"))
    found = codes(result)
    assert "RTP_PACKET_LOSS_HIGH" not in found
    assert "RTP_JITTER_HIGH" not in found
    assert "RTP_MOS_POOR" not in found
    assert "RTP_STREAM_SUMMARY" in found
