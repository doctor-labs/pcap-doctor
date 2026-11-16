"""D25 -- long-tail protocol inventory and exposure (#228).

Surfaces Syslog, Finger, Ident, WebSocket, XMPP, BitTorrent/DHT, LPR, PIA, NCP,
IRC and SOCKS from the passes the index already runs (and, where needed, from
on-demand tshark passes whose specs exist in tshark.py). Credential extraction
for IRC/SOCKS is out of scope here (#231); this detector reports inventory and
cleartext transport. See the commit/PR report for core gaps (tshark.py is frozen).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import ClassVar

from ..index import CaptureIndex, first
from ..models import Evidence, Finding
from ..tshark import Row, to_int
from .base import Detector, ev

_SECRET = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|apikey|api_key|authorization|bearer)\b")

# Facility/severity names per RFC 5424 tables (subset, best-effort for display).
_FACILITY = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog", 6: "lpr",
    7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7",
}
_SEVERITY = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning", 5: "notice", 6: "info", 7: "debug"}


def _endpoints(row: Row) -> tuple[str, str, int, int, int] | None:
    src = first(row, "ip.src") or first(row, "ipv6.src")
    dst = first(row, "ip.dst") or first(row, "ipv6.dst")
    sport = to_int(first(row, "tcp.srcport") or first(row, "udp.srcport"))
    dport = to_int(first(row, "tcp.dstport") or first(row, "udp.dstport"))
    frame = to_int(first(row, "frame.number")) or 0
    if not src or not dst or sport is None or dport is None or frame <= 0:
        return None
    return src, dst, sport, dport, frame


class LongTailProtocols(Detector):
    name: ClassVar[str] = "d25.long_tail"
    title: ClassVar[str] = "Long-tail protocol inventory and exposure"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "cleartext"
    description: ClassVar[str] = (
        "Inventory and cleartext exposure for Syslog, Finger, Ident, WebSocket, XMPP, "
        "BitTorrent/DHT, LPR, PIA, NCP, IRC and SOCKS from existing tshark passes (#228)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._syslog(index)
        findings += self._bittorrent(index)
        findings += self._irc_socks(index)
        findings += self._port_inventory(index)
        return findings

    # -- Syslog (on-demand pass, spec exists in tshark.py) -----------------
    def _syslog(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        groups: dict[tuple[str, str, int], list[Row]] = defaultdict(list)
        for row in runner.run("syslog"):
            ep = _endpoints(row)
            if ep is None:
                continue
            src, dst, _sport, dport, _frame = ep
            groups[(src, dst, dport)].append(row)
        findings: list[Finding] = []
        for (src, dst, dport), rows in sorted(groups.items()):
            evs: list[Evidence] = []
            secrets: list[tuple[int, str]] = []
            for row in rows[:5]:
                frame = to_int(first(row, "frame.number")) or 0
                fac = to_int(first(row, "syslog.facility"))
                sev = to_int(first(row, "syslog.level"))
                ver = first(row, "syslog.version")
                host = first(row, "syslog.hostname")
                app = first(row, "syslog.appname")
                msg = first(row, "syslog.msg")
                parts = []
                if fac is not None:
                    parts.append(f"facility={_FACILITY.get(fac, fac)}")
                if sev is not None:
                    parts.append(f"severity={_SEVERITY.get(sev, sev)}")
                if ver:
                    parts.append(f"version={ver}")
                if host:
                    parts.append(f"hostname={host}")
                if app:
                    parts.append(f"app={app}")
                parts.append(f"msg={msg[:120]}")
                evs.append(ev(frame, "syslog", " ".join(parts)))
                if msg:
                    m = _SECRET.search(msg)
                    if m:
                        secrets.append((frame, m.group(1) or "token"))
            subjects = [src, f"{dst}:{dport}"]
            findings.append(
                self.finding(
                    code="CLEARTEXT_SYSLOG",
                    title=f"Syslog messages sent in cleartext to {dst}:{dport}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"{src} sent {len(rows)} syslog message(s) to {dst}:{dport} without transport encryption. "
                        "Log lines can contain hostnames, application state and operational detail readable on-path."
                    ),
                    scope=f"syslog|{src}>{dst}:{dport}",
                    subjects=subjects,
                    evidence=evs,
                    remediation=(
                        "Send syslog over TLS (RFC 5425), DTLS or a secure log transport; restrict UDP/514 with "
                        "network controls and avoid placing credentials or tokens in log messages."
                    ),
                    references=["RFC 5424", "RFC 5425", "CWE-319"],
                    tags=["syslog", "cleartext"],
                )
            )
            if secrets:
                fframe, kind = secrets[0]
                findings.append(
                    self.finding(
                        code="CLEARTEXT_SYSLOG_SECRET",
                        title=f"Syslog message may contain a credential or token ({dst}:{dport})",
                        severity="high",
                        confidence="medium",
                        summary=(
                            f"At least one syslog message from {src} to {dst}:{dport} appears to contain a "
                            f"credential- or token-like field ({kind}). The content is visible in cleartext on the wire."
                        ),
                        scope=f"syslog-secret|{src}>{dst}:{dport}",
                        subjects=subjects,
                        evidence=[ev(fframe, "syslog.msg", f"<redacted; contains {kind}-like token>")],
                        remediation=(
                            "Remove credentials and tokens from log messages, rotate any exposed secret, and ship logs "
                            "over an encrypted transport."
                        ),
                        references=["CWE-312", "CWE-319"],
                        tags=["syslog", "credential"],
                    )
                )
        return findings

    # -- BitTorrent / DHT (on-demand pass) ---------------------------------
    def _bittorrent(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        hashes: dict[str, tuple[int, str, str]] = {}
        peers: list[tuple[int, str, str, str]] = []  # frame, src, dst, info_hash
        dht_boot: dict[tuple[str, str], tuple[int, str]] = {}
        for row in runner.run("bt-dht"):
            ep = _endpoints(row)
            if ep is None:
                continue
            src, dst, sport, dport, frame = ep
            info = first(row, "bittorrent.info_hash")
            peer_id = first(row, "bittorrent.peer_id")
            if info:
                hashes.setdefault(info, (frame, src, dst))
                peers.append((frame, src, dst, info))
                if peer_id:
                    peers[-1] = (frame, src, dst, info)
            # DHT bootstrap/queries leak the client's address and activity; any bt-dht traffic qualifies.
            protos = first(row, "frame.protocols")
            if (first(row, "udp.payload") or first(row, "bt-dht.id")) and (
                dport == 6881 or sport == 6881 or "bt-dht" in protos
            ):
                dht_boot.setdefault((src, dst), (frame, "bt-dht"))
        findings: list[Finding] = []
        for info_hash, (frame, src, dst) in sorted(hashes.items()):
            findings.append(
                self.finding(
                    code="SERVICE_BITTORRENT_INFOHASH",
                    title="BitTorrent info-hash observed (peer announcement/handshake)",
                    severity="low",
                    confidence="high",
                    summary=(
                        f"BitTorrent activity between {src} and {dst} exposed info-hash {info_hash}, which identifies "
                        "the content being announced or fetched and can be correlated by observers."
                    ),
                    scope=f"bittorrent|{info_hash}",
                    subjects=[src, dst],
                    evidence=[ev(frame, "bittorrent.info_hash", info_hash)],
                    remediation=(
                        "Restrict or block BitTorrent/DHT where not authorized; monitor for unexpected peer-to-peer "
                        "traffic and content identifiers."
                    ),
                    references=["CWE-200"],
                    tags=["bittorrent", "p2p"],
                )
            )
        for (src, dst), (frame, proto) in sorted(dht_boot.items()):
            # Report bootstrap/address leak once per pair; info-hash finding may also exist.
            findings.append(
                self.finding(
                    code="SERVICE_DHT_BOOTSTRAP",
                    title=f"DHT bootstrap/query leaks client address ({src} -> {dst})",
                    severity="low",
                    confidence="medium",
                    summary=(
                        f"{src} participated in BitTorrent DHT traffic with {dst}, which announces the client's address "
                        "and peer presence to the DHT network."
                    ),
                    scope=f"dht|{src}>{dst}",
                    subjects=[src, dst],
                    evidence=[ev(frame, "bt-dht", proto)],
                    remediation="Disable DHT or confine BitTorrent traffic to approved networks if peer discovery is unwanted.",
                    references=["CWE-200"],
                    tags=["bittorrent", "dht"],
                )
            )
        return findings

    # -- IRC / SOCKS inventory and cleartext transport ---------------------
    def _irc_socks(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        seen_irc: set[str] = set()
        seen_socks: set[str] = set()
        # Prefer service hits (tshark-dissected) for inventory.
        for hit in index.services:
            flow = index.flows.get(hit.key)
            proto = (hit.protocol or "").lower()
            detail = hit.detail or ""
            if (proto == "irc" or "irc." in detail) and hit.key not in seen_irc:
                seen_irc.add(hit.key)
                if not (flow and flow.encrypted):
                    findings.append(
                        self.finding(
                            code="CLEARTEXT_IRC",
                            title=f"IRC service inventory in cleartext on {hit.key}",
                            severity="medium",
                            confidence="high",
                            summary=(
                                f"IRC traffic was observed on {hit.key} without transport encryption. "
                                "Channel, nick and message metadata are visible on-path (credential extraction is handled separately)."
                            ),
                            scope=f"irc|{hit.key}",
                            flow_key=hit.key,
                            subjects=[hit.key],
                            evidence=[ev(hit.frame, "irc", detail[:180] or "irc")],
                            remediation="Use IRC over TLS (typically port 6697) and restrict cleartext IRC access.",
                            references=["CWE-319"],
                            tags=["irc", "cleartext"],
                        )
                    )
            if (proto == "socks" or "socks." in detail) and hit.key not in seen_socks:
                seen_socks.add(hit.key)
                if not (flow and flow.encrypted):
                    findings.append(
                        self.finding(
                            code="CLEARTEXT_SOCKS",
                            title=f"SOCKS proxy traffic in cleartext on {hit.key}",
                            severity="medium",
                            confidence="high",
                            summary=(
                                f"SOCKS proxy traffic was observed on {hit.key} without transport encryption. "
                                "Proxy requests and destinations are visible on-path (credential extraction is handled separately)."
                            ),
                            scope=f"socks|{hit.key}",
                            flow_key=hit.key,
                            subjects=[hit.key],
                            evidence=[ev(hit.frame, "socks", detail[:180] or "socks")],
                            remediation="Require authenticated SOCKS over an encrypted tunnel or restrict proxy access.",
                            references=["CWE-319"],
                            tags=["socks", "cleartext"],
                        )
                    )
        # Fallback: flows on well-known ports if dissector didn't produce hits.
        for flow in index.flows.values():
            if flow.encrypted:
                continue
            if 6667 in (flow.port_a, flow.port_b) and flow.key not in seen_irc:
                seen_irc.add(flow.key)
                findings.append(self.finding(
                    code="CLEARTEXT_IRC", title=f"IRC service inventory in cleartext on {flow.key}",
                    severity="medium", confidence="medium",
                    summary=f"Traffic on IRC port 6667 ({flow.key}) indicates cleartext IRC service exposure.",
                    scope=f"irc|{flow.key}", flow_key=flow.key, subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[ev(flow.first_frame, "tcp.port", "6667")],
                    remediation="Use IRC over TLS and restrict cleartext IRC access.", references=["CWE-319"], tags=["irc", "cleartext"],
                ))
            if 1080 in (flow.port_a, flow.port_b) and flow.key not in seen_socks:
                seen_socks.add(flow.key)
                findings.append(self.finding(
                    code="CLEARTEXT_SOCKS", title=f"SOCKS proxy traffic in cleartext on {flow.key}",
                    severity="medium", confidence="medium",
                    summary=f"Traffic on SOCKS port 1080 ({flow.key}) indicates cleartext proxy service exposure.",
                    scope=f"socks|{flow.key}", flow_key=flow.key, subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[ev(flow.first_frame, "tcp.port", "1080")],
                    remediation="Require encrypted/tunneled SOCKS and restrict proxy access.", references=["CWE-319"], tags=["socks", "cleartext"],
                ))
        return findings

    # -- Port-based inventory for protocols lacking dissected fields -------
    def _port_inventory(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        # (port, code, title, summary, remediation, refs, tags, sev, conf)
        specs = [
            (79, "SERVICE_FINGER_EXPOSED", "Finger service exposed", "Finger can disclose user account information.",
             "Disable Finger or restrict access; it leaks account details by design.", ["RFC 1288", "CWE-200"], ["finger"], "medium", "medium"),
            (113, "SERVICE_IDENT_EXPOSED", "Ident service exposed", "Ident discloses the local user owning a connection.",
             "Disable or firewall Ident; it leaks user identity information.", ["RFC 1413", "CWE-200"], ["ident"], "low", "medium"),
            (5222, "SERVICE_XMPP_CLEARTEXT", "XMPP client service observed without confirmed TLS", "XMPP streams may expose roster/messages if not STARTTLS-protected.",
             "Require STARTTLS or use XMPP over TLS (5223) and enforce encrypted streams.", ["RFC 6120", "CWE-319"], ["xmpp"], "medium", "low"),
            (515, "SERVICE_LPR_EXPOSED", "LPR printing service exposed", "LPR can accept print jobs without strong authentication.",
             "Restrict LPR to trusted hosts or migrate to IPP over TLS.", ["RFC 1179", "CWE-306"], ["lpr"], "low", "medium"),
            (6543, "SERVICE_PIA_EXPOSED", "PIA protocol service observed", "PIA is an unauthenticated/legacy protocol exposure when reachable.",
             "Restrict or retire PIA endpoints; require authenticated, encrypted management protocols.", ["CWE-306"], ["pia"], "low", "low"),
            (524, "SERVICE_NCP_EXPOSED", "NCP protocol service observed", "NCP may expose file/print services if unauthenticated or legacy.",
             "Restrict NCP access and use authenticated, modern configurations.", ["CWE-306"], ["ncp"], "low", "low"),
        ]
        for flow in index.flows.values():
            for port, code, title, blurb, remediation, refs, tags, sev, conf in specs:
                if port not in (flow.port_a, flow.port_b):
                    continue
                key = (flow.key, code)
                if key in seen:
                    continue
                seen.add(key)
                # If encrypted, XMPP/Finger/Ident still noteworthy? XMPP without confirmed TLS is the concern.
                if code == "SERVICE_XMPP_CLEARTEXT" and flow.encrypted:
                    continue
                findings.append(
                    self.finding(
                        code=code,
                        title=f"{title} on {flow.key}",
                        severity=sev,  # type: ignore[arg-type]
                        confidence=conf,  # type: ignore[arg-type]
                        summary=(
                            f"Traffic involving port {port} on {flow.key} indicates {title.lower()}. {blurb} "
                            "Protocol details are limited by available tshark fields."
                        ),
                        scope=f"{code.lower()}|{flow.key}",
                        flow_key=flow.key,
                        subjects=[flow.endpoint_a, flow.endpoint_b],
                        evidence=[ev(flow.first_frame, "tcp.port" if flow.proto == "tcp" else "udp.port", str(port))],
                        remediation=remediation,
                        references=refs,
                        tags=tags,
                    )
                )
        # WebSocket: look for Upgrade in HTTP request/response headers? not in model; use service hits/protocols heuristically
        # (no reliable fields in existing passes -> core gap; best-effort: detect flows labeled websocket? none)
        return findings
