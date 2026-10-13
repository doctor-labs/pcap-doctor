"""D5 -- HTTP/2 posture.

The smallest useful slice of #226: cleartext HTTP/2 (h2c, prior-knowledge). The
detector reports one finding per cleartext h2c flow, recording the :method,
:path, :authority and :status pseudo-headers that tshark decoded from HPACK.

TLS-encrypted HTTP/2 is out of scope: those flows are already marked encrypted
by the TLS pass and reported through the TLS path, so this detector ignores them.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding, Http2Exchange
from .base import Detector, ev


class Http2Detector(Detector):
    name: ClassVar[str] = "d5.http2"
    title: ClassVar[str] = "HTTP/2 posture"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "cleartext"
    description: ClassVar[str] = (
        "Reports cleartext HTTP/2 (h2c prior-knowledge) flows with their decoded "
        "HPACK pseudo-headers (:method, :path, :authority, :status). Encrypted HTTP/2 is out of scope."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        by_flow: dict[str, list[Http2Exchange]] = {}
        for exch in index.http2:
            if exch.is_encrypted:
                continue
            by_flow.setdefault(exch.key, []).append(exch)
        for key, exchanges in by_flow.items():
            flow = index.flows.get(key)
            if flow is None:
                continue
            endpoints = [flow.endpoint_a, flow.endpoint_b] if flow else []
            sample = exchanges[0]
            what = f"HTTP/2 h2c {sample.method or '?'} {sample.authority or ''}{sample.path or ''}".strip()
            statuses = [e.status for e in exchanges if e.status]
            status_str = ", ".join(statuses) if statuses else "no response"
            findings.append(
                self.finding(
                    code="HTTP2_CLEARTEXT",
                    title=f"HTTP/2 over cleartext (h2c) on {key}",
                    severity="high",
                    confidence="high",
                    summary=(
                        f"{what} was exchanged without TLS on "
                        f"{flow.endpoint_a}:{flow.port_a} <-> {flow.endpoint_b}:{flow.port_b} "
                        f"({len(exchanges)} stream(s); response status(es): {status_str}). "
                        "Request URLs, pseudo-headers and bodies are readable and modifiable on-path."
                    ),
                    scope=f"{key}|h2c",
                    flow_key=key,
                    subjects=endpoints,
                    evidence=[
                        ev(
                            e.frame,
                            "http2.headers.method",
                            f"{e.method or '?'} {e.authority or ''}{e.path or ''}",
                        )
                        for e in exchanges[:8]
                    ]
                    + [
                        ev(e.frame, "http2.headers.status", e.status or "") for e in exchanges[:8] if e.status
                    ],
                    remediation=(
                        "Serve HTTP/2 behind TLS (h2 over TLS with ALPN); if h2c must stay inside a trusted zone, "
                        "carry no credentials or sensitive payloads and integrity-check any downloaded artifact."
                    ),
                    references=["RFC 7540", "RFC 9113", "CWE-319", "CWE-494"],
                    tags=["http", "http2", "cleartext"],
                )
            )
        return findings
