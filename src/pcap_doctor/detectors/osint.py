"""D25 -- opt-in OSINT lookups (issue #277).

The operator runs ``pcap-doctor osint`` explicitly and may provide ``--endpoint`` to
contact a lookup service. This detector only reports lookups that were actually
performed and stored on the index by that command. It never contacts the network and
never runs during a normal analysis, because no opt-in lookup data is attached then.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev


class OsintDetector(Detector):
    name: ClassVar[str] = "d25.osint"
    title: ClassVar[str] = "Opt-in OSINT lookups"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "signatures"
    description: ClassVar[str] = (
        "Reports indicators looked up through an explicit opt-in OSINT endpoint, without inventing a verdict."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        # Opt-in only: the osint command attaches performed lookups here. A plain
        # analyze never sets this, so the detector stays silent and no network work
        # happens on any other code path.
        lookups: list[dict[str, Any]] = getattr(index, "osint_lookups", [])
        if not lookups:
            return []
        out: list[Finding] = []
        for item in lookups:
            indicator = str(item.get("indicator", ""))
            kind = str(item.get("kind", "indicator"))
            result = str(item.get("result", ""))
            endpoint = str(item.get("endpoint", ""))
            frame = int(item.get("frame", 1) or 1)
            summary = f"Looked up {kind} {indicator} via {endpoint}; result: {result}"
            out.append(
                self.finding(
                    code="OSINT_LOOKUP_PERFORMED",
                    title=f"OSINT lookup ({kind}): {indicator}",
                    severity="info",
                    confidence="low",
                    summary=summary,
                    scope=f"{kind}:{indicator}:{endpoint}",
                    subjects=[indicator],
                    evidence=[
                        ev(frame, "osint.indicator", indicator),
                        ev(frame, "osint.endpoint", endpoint),
                        ev(frame, "osint.result", result),
                    ],
                    remediation=(
                        "Review the lookup result in the context of this capture. The finding reports what "
                        "the endpoint returned and does not assert that the indicator is malicious."
                    ),
                    references=[],
                    tags=["osint", f"osint:{kind}"],
                )
            )
        return out
