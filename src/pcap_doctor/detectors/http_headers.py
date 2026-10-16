"""D14 -- HTTP responses missing recommended security headers (#271)."""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev

#: The four headers every cleartext HTTP response should carry so a browser
#: will enforce transport security, script/content restrictions, MIME sniffing
#: and framing defences.
REQUIRED_HEADERS: frozenset[str] = frozenset(
    {
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
    }
)

#: Proper-case spelling for human-readable output.
PROPER_CASE: dict[str, str] = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
}


class HttpHeadersDetector(Detector):
    name: ClassVar[str] = "d15.http_headers"
    title: ClassVar[str] = "HTTP security headers"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    description: ClassVar[str] = "Cleartext HTTP responses missing recommended security headers."
    enabled: ClassVar[bool] = True

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for exch in index.http:
            # Only responses (status is not None) over cleartext transports.
            if exch.status is None or exch.is_encrypted:
                continue
            missing = sorted(
                h for h in REQUIRED_HEADERS if h not in exch.response_header_names
            )
            if not missing:
                continue
            # The client is the endpoint whose port is the ephemeral one.
            flow = index.flows.get(exch.key)
            if flow is not None:
                if flow.port_a < flow.port_b:
                    client = flow.endpoint_b
                    server = flow.endpoint_a
                else:
                    client = flow.endpoint_a
                    server = flow.endpoint_b
            else:
                client = ""
                server = ""
            dedupe_key = f"{client}->{server}:{','.join(missing)}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            proper = [PROPER_CASE[h] for h in missing]
            scope = f"{client}->{server}"
            findings.append(
                self.finding(
                    code="HTTP_MISSING_SECURITY_HEADERS",
                    title=f"HTTP response from {client} missing security headers",
                    severity="low",
                    confidence="high",
                    summary=(
                        f"HTTP response from client {client} is missing security headers: "
                        + ", ".join(proper)
                    ),
                    scope=scope,
                    evidence=[
                        ev(
                            exch.frame,
                            "http.response.line",
                            "missing: " + ", ".join(proper),
                        )
                    ],
                    subjects=[client, server],
                    remediation=(
                        "Set Strict-Transport-Security, Content-Security-Policy, "
                        "X-Content-Type-Options and X-Frame-Options on all HTTP responses, "
                        "or migrate the endpoint to HTTPS so HSTS applies."
                    ),
                    references=[
                        "OWASP secure-headers-project",
                        "RFC 6797",
                        "RFC 7034",
                    ],
                    tags=["http"],
                )
            )
        findings.sort(key=lambda f: f.title)
        return findings
