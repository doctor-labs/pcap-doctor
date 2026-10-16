"""D14 -- ECH and 0-RTT early-data visibility checks.

Detects ECH (Encrypted Client Hello, extension type 0xfe0d per RFC 9849) and
TLS 1.3 0-RTT early data (early_data extension type 42 per RFC 8446) offered
in a ClientHello. Both are passive observations of what the client advertised;
a passive tool cannot decrypt either.
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding, TlsSession
from .base import Detector, ev

#: Hello extension type for Encrypted Client Hello (RFC 9849, formerly draft-ietf-tls-esni).
ECH_EXTENSION: int = 0xFE0D  # 65037

#: Hello extension type for early_data (RFC 8446 section 4.2.10).
EARLY_DATA_EXTENSION: int = 42


class EchEarlyDataDetector(Detector):
    name: ClassVar[str] = "d17.ech_early_data"
    title: ClassVar[str] = "ECH and TLS 1.3 0-RTT early-data checks"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "crypto"
    enabled: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Detects Encrypted Client Hello (ECH, extension 0xfe0d per RFC 9849) and "
        "TLS 1.3 0-RTT early data (early_data extension 42 per RFC 8446) offered in ClientHellos."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        for key, session in index.tls.items():
            flow = index.flows.get(key)
            subjects = [flow.endpoint_a, flow.endpoint_b] if flow is not None else []
            findings += self._ech(session, subjects)
            findings += self._early_data(session, subjects)
        return findings

    # -- checks -------------------------------------------------------------
    def _ech(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        client_hello = session.client_hello
        if client_hello is None:
            return []
        if ECH_EXTENSION not in client_hello.extensions:
            return []
        frame = client_hello.frame
        return [
            self.finding(
                code="TLS_ECH_OFFERED",
                title=f"Encrypted Client Hello (ECH) offered on {session.key}",
                severity="low",
                confidence="high",
                summary=(
                    f"The ClientHello on {session.key} offers the ECH extension "
                    f"(type 0x{ECH_EXTENSION:04x} / {ECH_EXTENSION}) per RFC 9849. "
                    "A passive observer can see that ECH is in use but cannot decrypt the inner ClientHello."
                ),
                scope=f"{session.key}|ech",
                flow_key=session.key,
                subjects=subjects,
                evidence=[ev(frame, "tls.handshake.extension.type", f"0x{ECH_EXTENSION:04x} ({ECH_EXTENSION})")],
                remediation="None required: ECH is a privacy improvement. Note that ECH hides the SNI from passive observers.",
                references=["RFC 9849"],
                tags=["tls", "ech", "privacy"],
            )
        ]

    def _early_data(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        client_hello = session.client_hello
        if client_hello is None:
            return []
        if EARLY_DATA_EXTENSION not in client_hello.extensions:
            return []
        frame = client_hello.frame
        return [
            self.finding(
                code="TLS_EARLY_DATA_OFFERED",
                title=f"TLS 1.3 0-RTT early data offered on {session.key}",
                severity="low",
                confidence="high",
                summary=(
                    f"The ClientHello on {session.key} offers the early_data extension (type 42) per RFC 8446. "
                    "This means the client is offering to send 0-RTT data, which is replayable by a MITM and is "
                    "not forward secret against an attacker who later obtains the PSK."
                ),
                scope=f"{session.key}|early-data",
                flow_key=session.key,
                subjects=subjects,
                evidence=[ev(frame, "tls.handshake.extension.type", f"0x{EARLY_DATA_EXTENSION:04x} ({EARLY_DATA_EXTENSION})")],
                remediation=(
                    "0-RTT data must be idempotent and safe to replay. See RFC 8446 section 8 for replay mitigation. "
                    "Disable 0-RTT (max_early_data_size=0) if the application cannot tolerate replay."
                ),
                references=["RFC 8446", "RFC 9849"],
                tags=["tls", "0rtt", "replay"],
            )
        ]
