"""D13 -- Zeek-style capture loss: segments that follow a mid-stream hole the capture missed (#240)."""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..logs import capture_loss_stats
from ..models import Finding
from .base import Detector, ev

#: Like Zeek's CaptureLoss::minimum_acks: below this many ACKs a capture is too small to say anything about
#: loss (a lone handshake with one hole would read as 25%).
MIN_ACKS = 5


class CaptureLossDetector(Detector):
    name: ClassVar[str] = "d13.capture_loss"
    title: ClassVar[str] = "Capture loss"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    description: ClassVar[str] = "TCP segments that follow a mid-stream hole the capture missed (Zeek capture-loss)."
    enabled: ClassVar[bool] = True

    def detect(self, index: CaptureIndex) -> list[Finding]:
        if index.runner is None:
            return []

        acks, gaps, frame = capture_loss_stats(index.runner.run("capture_loss"))
        if acks >= MIN_ACKS and 100 * gaps / acks > 10:
            pct = 100 * gaps / acks
            return [
                self.finding(
                    code="CAPTURE_LOSS",
                    title="Capture loss",
                    severity="low",
                    confidence="high",
                    scope="capture-loss",
                    evidence=[ev(frame or 0, "tcp.analysis.lost_segment", "1")],
                    summary=f"{pct:.1f}% of TCP ACKs ({gaps} of {acks}) follow a hole in their stream, so flows and findings may be incomplete",
                    remediation="Capture closer to the hosts, raise the capture buffer, or check the tap/SPAN for drops.",
                    references=["docs/zeek-logs.md"],
                    tags=["capture"],
                )
            ]
        return []
