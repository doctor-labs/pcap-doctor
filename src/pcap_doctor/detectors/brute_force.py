"""D11 -- Password guessing: repeated failed FTP/HTTP/SMB logins from one client to one server (#207)."""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev


class BruteForceDetector(Detector):
    name: ClassVar[str] = "d11.brute_force"
    title: ClassVar[str] = "Password guessing"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    description: ClassVar[str] = (
        "Repeated failed logins from one client to one server and service (FTP, HTTP, SMB)."
    )
    enabled: ClassVar[bool] = True

    def detect(self, index: CaptureIndex) -> list[Finding]:
        limits = {"ftp": 20, "http": 10, "smb": 10}

        # (service, flow_key, frame, evidence_field, evidence_value)
        failures: list[tuple[str, str, int, str, str]] = []
        for h in index.http:
            if h.status == 401 and h.auth_present:
                failures.append(("http", h.key, h.frame, "http.response.code", "401"))
        for s in index.services:
            if s.detail and "ftp.response.code=530" in s.detail:
                failures.append(("ftp", s.key, s.frame, "ftp.response.code", "530"))
        for op in index.smb:
            if op.command == "SESSION_SETUP" and op.response and (op.status or "").lower() == "0xc000006d":
                failures.append(("smb", op.key, op.frame, "smb2.nt_status", "0xc000006d"))

        groups: dict[tuple[str, str, str], list[tuple[str, int, str, str]]] = defaultdict(list)
        for service, flow_key, frame, field, value in failures:
            flow = index.flows.get(flow_key)
            if flow is None:
                continue
            if flow.port_a <= flow.port_b:
                server, client = flow.endpoint_a, flow.endpoint_b
            else:
                server, client = flow.endpoint_b, flow.endpoint_a
            # keep flow_key alongside the evidence so the first failure carries its own flow_key
            groups[(client, server, service)].append((flow_key, frame, field, value))

        findings: list[Finding] = []
        for (client, server, service), items in groups.items():
            count = len(items)
            limit = limits.get(service, 0)
            if limit and count >= limit:
                ordered = sorted(items, key=lambda t: t[1])
                first_flow_key = ordered[0][0]
                findings.append(
                    self.finding(
                        code="BRUTE_FORCE_SUSPECTED",
                        title=f"{count} failed {service.upper()} logins from {client} to {server}",
                        severity="high",
                        confidence="medium",
                        summary=f"{client} failed {count} {service.upper()} logins against {server}, "
                        "the shape of password guessing. If one of them succeeded the account may be compromised.",
                        scope=f"{client}->{server}:{service}",
                        flow_key=first_flow_key,
                        subjects=[client, server],
                        evidence=[ev(frame, field, value) for _fk, frame, field, value in ordered[:5]],
                        remediation="Lock out or rate-limit repeated failed logins on the server, check whether any "
                        "login from this client succeeded, and block the client if it is not expected.",
                        references=["MITRE ATT&CK T1110"],
                        tags=["brute-force"],
                    )
                )
        findings.sort(key=lambda f: f.title)
        return findings
