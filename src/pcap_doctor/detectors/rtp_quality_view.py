"""D25 -- RTP quality view: loss, jitter, MOS and a playable stream summary.

Surfaces the per-stream metrics the core ``rtp_quality`` helpers already compute
(packet loss from sequence gaps, interarrival jitter and an estimated MOS) so an
analyst can see voice quality problems without re-deriving the maths.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding, RtpStream
from .base import Detector, ev

# Quality thresholds. Loss below 1% and jitter below 30 ms are generally
# imperceptible on a typical VoIP call (well inside a normal jitter buffer and
# below the point where concealment is audible). MOS is reported in ITU-T bands;
# < 3.6 is "poor/bad" and worth calling out explicitly.
LOSS_WARN_PERCENT = 1.0
JITTER_WARN_MS = 30.0
MOS_POOR = 3.6


def _mos_band(mos: float) -> str:
    if mos >= 4.3:
        return "excellent"
    if mos >= 4.0:
        return "good"
    if mos >= 3.6:
        return "fair"
    if mos >= 3.1:
        return "poor"
    return "bad"


def _gap_count(stream: RtpStream) -> int:
    """Lost packets implied by the measured loss percentage (sequence gaps)."""
    loss = stream.loss_percent
    if loss <= 0.0:
        return 0
    if loss >= 100.0:
        return stream.packets
    # loss% = lost/(received+lost)*100  =>  lost = received*loss/(100-loss)
    return round(stream.packets * loss / (100.0 - loss))


def _stream_label(stream: RtpStream) -> str:
    src = stream.from_ip or "?"
    dst = stream.to_ip or "?"
    payload = stream.payload_name or (
        f"pt {stream.payload_type}" if stream.payload_type is not None else "unknown payload"
    )
    return f"{src} -> {dst} ({payload})"


class RtpQualityViewDetector(Detector):
    name: ClassVar[str] = "d25.rtp_quality_view"
    title: ClassVar[str] = "RTP stream quality: loss, jitter and MOS"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "voice"
    description: ClassVar[str] = (
        "Surfaces per-stream RTP packet loss, interarrival jitter and the "
        "estimated MOS (ITU-T G.107) computed by the core rtp_quality helpers, "
        "plus a playable stream summary for each flow."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        for stream in index.rtp:
            findings.append(self._summary(stream))
            findings.extend(self._quality_findings(stream))
        return findings

    # -- helpers ------------------------------------------------------------
    def _summary(self, stream: RtpStream) -> Finding:
        payload = stream.payload_name or (
            f"pt {stream.payload_type}" if stream.payload_type is not None else "unknown"
        )
        label = _stream_label(stream)
        summary = (
            f"RTP stream {label} on {stream.key}: SSRC {stream.ssrc}, "
            f"payload {payload} (type {stream.payload_type}), "
            f"{stream.packets} packets, {stream.bytes} bytes, "
            f"duration {stream.duration:.3f}s, "
            f"loss {stream.loss_percent:.2f}% ({_gap_count(stream)} gaps), "
            f"jitter {stream.jitter:.3f} ms, "
            f"MOS {stream.mos:.2f} ({_mos_band(stream.mos)})."
        )
        return self.finding(
            code="RTP_STREAM_SUMMARY",
            title=f"RTP stream summary {label}",
            severity="info",
            confidence="high",
            summary=summary,
            scope=f"{stream.key}|quality|{stream.ssrc}|summary",
            flow_key=stream.key,
            subjects=[x for x in (stream.from_ip, stream.to_ip) if x],
            evidence=[
                ev(stream.first_frame, "rtp.ssrc", stream.ssrc),
                ev(
                    stream.first_frame,
                    "rtp.summary",
                    f"{stream.packets} pkts, {stream.bytes} B, {stream.duration:.3f}s",
                ),
                ev(
                    stream.first_frame,
                    "rtp.p_type",
                    f"{stream.payload_type} {payload}".strip(),
                ),
            ],
            remediation=(
                "No action required; use this summary to identify the stream when "
                "following the call or correlating quality issues."
            ),
            references=["RFC 3550"],
            tags=["rtp", "quality", "summary"],
        )

    def _quality_findings(self, stream: RtpStream) -> list[Finding]:
        out: list[Finding] = []
        label = _stream_label(stream)
        gaps = _gap_count(stream)
        subjects = [x for x in (stream.from_ip, stream.to_ip) if x]

        if stream.loss_percent >= LOSS_WARN_PERCENT:
            out.append(
                self.finding(
                    code="RTP_PACKET_LOSS_HIGH",
                    title=f"RTP packet loss {stream.loss_percent:.2f}% on {label}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"RTP stream {label} on {stream.key} lost {gaps} packet(s) "
                        f"({stream.loss_percent:.2f}% of expected) based on sequence-number "
                        "gaps (RFC 3550). Missing packets audibly degrade voice quality."
                    ),
                    scope=f"{stream.key}|quality|{stream.ssrc}|loss",
                    flow_key=stream.key,
                    subjects=subjects,
                    evidence=[
                        ev(stream.first_frame, "rtp.ssrc", stream.ssrc),
                        ev(
                            stream.first_frame,
                            "rtp.loss",
                            f"{stream.loss_percent:.2f}% ({gaps} gaps, {stream.packets} received)",
                        ),
                    ],
                    remediation=(
                        "Investigate network congestion, drops or capture loss on the path "
                        "between the endpoints and reduce loss below 1% for intelligible audio."
                    ),
                    references=["RFC 3550"],
                    tags=["rtp", "quality", "loss"],
                )
            )

        if stream.jitter >= JITTER_WARN_MS:
            out.append(
                self.finding(
                    code="RTP_JITTER_HIGH",
                    title=f"RTP interarrival jitter {stream.jitter:.2f} ms on {label}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"RTP stream {label} on {stream.key} shows interarrival jitter of "
                        f"{stream.jitter:.2f} ms (RFC 3550 A.8). High jitter exhausts the "
                        "receiver jitter buffer and causes choppy or clipped audio."
                    ),
                    scope=f"{stream.key}|quality|{stream.ssrc}|jitter",
                    flow_key=stream.key,
                    subjects=subjects,
                    evidence=[
                        ev(stream.first_frame, "rtp.ssrc", stream.ssrc),
                        ev(stream.first_frame, "rtp.jitter_ms", f"{stream.jitter:.3f} ms"),
                    ],
                    remediation=(
                        "Check for variable queuing delay, Wi-Fi contention or competing "
                        "traffic on the path and keep interarrival jitter comfortably below 30 ms."
                    ),
                    references=["RFC 3550"],
                    tags=["rtp", "quality", "jitter"],
                )
            )

        if stream.mos < MOS_POOR:
            band = _mos_band(stream.mos)
            out.append(
                self.finding(
                    code="RTP_MOS_POOR",
                    title=f"RTP estimated MOS {stream.mos:.2f} ({band}) on {label}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"RTP stream {label} on {stream.key} has an estimated MOS of "
                        f"{stream.mos:.2f} ({band} band, ITU-T G.107 E-model from "
                        f"{stream.loss_percent:.2f}% loss). MOS below 3.6 indicates poor or "
                        "bad perceived call quality."
                    ),
                    scope=f"{stream.key}|quality|{stream.ssrc}|mos",
                    flow_key=stream.key,
                    subjects=subjects,
                    evidence=[
                        ev(stream.first_frame, "rtp.ssrc", stream.ssrc),
                        ev(
                            stream.first_frame,
                            "rtp.mos",
                            f"{stream.mos:.2f} ({band}), loss {stream.loss_percent:.2f}%",
                        ),
                    ],
                    remediation=(
                        "Reduce packet loss and delay variation on the media path; MOS is "
                        "driven here by measured loss, so fixing drops will raise the score."
                    ),
                    references=["RFC 3550"],
                    tags=["rtp", "quality", "mos"],
                )
            )

        return out
