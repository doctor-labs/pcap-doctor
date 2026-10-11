"""D12 -- ARP spoofing (one IPv4 claimed by two MACs) and ICMP redirects (#280)."""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex, first
from ..models import Finding
from ..tshark import to_int
from .base import Detector, ev


class ArpIcmpDetector(Detector):
    name: ClassVar[str] = "d12.arp_icmp"
    title: ClassVar[str] = "ARP spoofing and ICMP redirects"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    description: ClassVar[str] = "ARP replies that claim an IPv4 address from two different MACs, and ICMP redirect messages."
    enabled: ClassVar[bool] = True

    def detect(self, index: CaptureIndex) -> list[Finding]:
        if index.runner is None:
            return []

        rows = index.runner.run("arp_icmp")
        findings: list[Finding] = []

        # ARP: in frame order, map ip -> first MAC seen. When a later reply claims that
        # ip with a different MAC, emit ONE finding per (ip, new MAC).
        first_mac_by_ip: dict[str, str] = {}
        # track which (ip, new_mac) pairs already emitted a finding to avoid duplicates
        seen: set[tuple[str, str]] = set()
        for row in rows:
            if first(row, "arp.opcode") != "2":
                continue
            ip = first(row, "arp.src.proto_ipv4")
            mac = first(row, "arp.src.hw_mac")
            if not ip or not mac:
                continue
            frame = to_int(first(row, "frame.number")) or 0
            if ip in first_mac_by_ip:
                original_mac = first_mac_by_ip[ip]
                if mac != original_mac and (ip, mac) not in seen:
                    seen.add((ip, mac))
                    findings.append(
                        self.finding(
                            code="ARP_SPOOFING_SUSPECTED",
                            title=f"{ip} claimed by {original_mac} and then by {mac}",
                            severity="high",
                            confidence="medium",
                            scope=f"arp|{ip}|{mac}",
                            subjects=[ip],
                            evidence=[ev(frame, "arp.src.hw_mac", mac)],
                            summary=f"{ip} was claimed by {original_mac} and then by {mac} "
                            "(ARP spoofing or a duplicate address)",
                            remediation=f"Find which host owns {ip}; enable Dynamic ARP Inspection or static ARP for gateways.",
                            references=["CWE-291", "MITRE ATT&CK T1557.002"],
                            tags=["network"],
                        )
                    )
            else:
                first_mac_by_ip[ip] = mac

        # ICMP redirects: one finding per (sender, gateway).
        seen_redirects: set[tuple[str, str]] = set()
        for row in rows:
            if first(row, "icmp.type") != "5":
                continue
            sender = first(row, "ip.src")
            gw = first(row, "icmp.redir_gw")
            if not sender or not gw:
                continue
            if (sender, gw) in seen_redirects:
                continue
            seen_redirects.add((sender, gw))
            frame = to_int(first(row, "frame.number")) or 0
            findings.append(
                self.finding(
                    code="ICMP_REDIRECT",
                    title=f"ICMP redirect from {sender} to gateway {gw}",
                    severity="medium",
                    confidence="high",
                    scope=f"icmp-redirect|{sender}|{gw}",
                    subjects=[sender],
                    evidence=[ev(frame, "icmp.redir_gw", gw)],
                    summary=f"{sender} sent an ICMP redirect telling hosts to route through {gw}",
                    remediation="Ignore ICMP redirects on hosts (accept_redirects=0) and find the sender.",
                    references=["CWE-940"],
                    tags=["network"],
                )
            )

        return findings
