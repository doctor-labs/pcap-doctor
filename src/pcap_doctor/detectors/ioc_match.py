"""D15 -- matches of the local indicator files (``analyze --ioc``, issue #236).

The pipeline matches the indicators against the index and stores the hits on it; this detector only turns them
into findings, so it stays a pure function of the index. Confidence is medium: a hit proves the name or address
appeared in the capture, not that the indicator is still current or that the traffic is malicious.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev


class IocMatchDetector(Detector):
    name: ClassVar[str] = "d21.ioc_match"
    title: ClassVar[str] = "Local indicator matches"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "signature"
    description: ClassVar[str] = "Reports IPs, domains and URLs seen in the capture that match an indicator file given with --ioc."

    def detect(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for hit in index.ioc_hits:
            label = f" ({hit.label})" if hit.label else ""
            out.append(
                self.finding(
                    code="IOC_MATCH",
                    title=f"Indicator match ({hit.kind}): {hit.subject}",
                    severity="high",
                    confidence="medium",
                    summary=f"{hit.subject} seen via {hit.source} matched {hit.kind} indicator {hit.indicator}{label}",
                    scope=f"{hit.kind}:{hit.indicator}:{hit.subject}",
                    flow_key=hit.flow_key,
                    subjects=[hit.subject],
                    evidence=[ev(hit.frame, "ioc", f"{hit.kind}:{hit.indicator}")],
                    remediation="Confirm the indicator is current and relevant to this network, then investigate the flow and host that produced it; isolate the host if the match is confirmed.",
                    references=[],
                    tags=["ioc", f"ioc:{hit.kind}"],
                )
            )
        return out
