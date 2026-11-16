# d25 -- DNS zone transfer requests (AXFR/IXFR) in cleartext.
# A zone transfer returns the full contents of a DNS zone; requesting one over
# unencrypted DNS exposes internal hostnames and topology and is a common
# reconnaissance step. Flagged per (source, destination, zone, qtype).

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev

# tshark may report dns.qry.type as the symbolic name or its numeric value.
_ZONE_QTYPES = {"AXFR": "AXFR", "IXFR": "IXFR", "252": "AXFR", "251": "IXFR"}


class DnsZoneTransferDetector(Detector):
    name: ClassVar[str] = "d25.dns_zone_transfer"
    title: ClassVar[str] = "DNS zone transfer request"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "dns"
    description: ClassVar[str] = (
        "Flags cleartext DNS zone transfer requests (AXFR/IXFR), which can disclose "
        "an entire zone to anyone on the path or to an unauthorized resolver."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        seen: set[tuple[str, str, str, str]] = set()
        findings: list[Finding] = []
        for query in index.dns:
            if query.is_response or query.over_tls:
                continue
            qtype = _ZONE_QTYPES.get(query.qtype.upper())
            if qtype is None:
                continue
            flow = index.flows.get(query.key)
            if flow is not None and flow.encrypted:
                continue
            if flow is not None and flow.port_b in (53, 853):
                src, dst = flow.endpoint_a, flow.endpoint_b
            elif flow is not None and flow.port_a in (53, 853):
                src, dst = flow.endpoint_b, flow.endpoint_a
            elif flow is not None:
                src, dst = flow.endpoint_a, flow.endpoint_b
            else:
                src, dst = "?", "?"
            scope_key = (src, dst, query.name.lower(), qtype)
            if scope_key in seen:
                continue
            seen.add(scope_key)
            findings.append(
                self.finding(
                    code="DNS_ZONE_TRANSFER_REQUEST",
                    title=f"Cleartext DNS zone transfer ({qtype}) requested for {query.name}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"{src} requested a {qtype} zone transfer for {query.name} from {dst} over "
                        "unencrypted DNS. A successful transfer exposes the full contents of the zone "
                        "(hostnames, addresses and record data) to anyone on the path and to the "
                        "responding server."
                    ),
                    scope=f"{src}>{dst}|{query.name.lower()}|{qtype}",
                    flow_key=query.key,
                    subjects=[src, dst, query.name],
                    evidence=[ev(query.frame, "dns.qry.type", f"{qtype} {query.name}")],
                    remediation=(
                        "Restrict zone transfers to explicitly authorized secondary servers (TSIG/IP "
                        "ACLs) and block AXFR/IXFR from untrusted clients. Where possible, avoid "
                        "exposing zone data over cleartext networks."
                    ),
                    references=["RFC 5936", "RFC 1995", "CWE-200"],
                    tags=["dns", "zone-transfer", "recon"],
                )
            )
        return findings
