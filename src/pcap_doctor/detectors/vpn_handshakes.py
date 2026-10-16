"""D14 -- VPN handshake identification: IKE/IPsec, WireGuard and OpenVPN."""

from __future__ import annotations

import struct
from typing import ClassVar

from ..index import CaptureIndex, first
from ..models import Finding, flow_key
from ..tshark import Row, TsharkRunner, to_int
from .base import Detector, ev

#: UDP ports that carry IKE/ISAKMP (RFC 7241 / RFC 7422).
IKE_PORTS: frozenset[int] = frozenset({500, 4500})

#: The IANA-assigned WireGuard port (RFC 8439).
WIREGUARD_PORT: int = 51820

#: The IANA-assigned OpenVPN port (TCP and UDP).
OPENVPN_PORT: int = 1194

#: WireGuard message types (protocol.h in wireguard-tools).
#: Only types 1-4 are valid on the wire; 0 and 5+ are malformed.
WG_HANDSHAKE_TYPES: frozenset[int] = frozenset({1, 2, 3, 4})

#: ISAKMP exchange-type names (verified from ``tshark -G values``).
_IKE_EXCHANGE_NAMES: dict[str, str] = {
    "1": "Base",
    "2": "Main Mode",
    "3": "Authentication Only",
    "4": "Aggressive",
    "5": "Informational",
    "32": "Quick Mode",
    "34": "IKE_SA_INIT",
    "35": "IKE_AUTH",
    "36": "CREATE_CHILD_SA",
}

_WG_TYPE_NAMES: dict[int, str] = {
    1: "Handshake Initiation",
    2: "Handshake Response",
    3: "Cookie Reply",
    4: "Transport Data",
}


class VpnHandshakesDetector(Detector):
    name: ClassVar[str] = "d19.vpn_handshakes"
    title: ClassVar[str] = "VPN handshake identification"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "network"
    enabled: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Identifies IKE/IPsec (ISAKMP on UDP 500/4500), WireGuard "
        "(handshake messages on UDP 51820), and OpenVPN "
        "(control-channel traffic on UDP/TCP 1194)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        findings: list[Finding] = []
        findings += self._ike(runner)
        findings += self._wireguard(runner)
        findings += self._openvpn(runner)
        return findings

    # -- IKE/IPsec ----------------------------------------------------------
    def _ike(self, runner: TsharkRunner) -> list[Finding]:
        """IKE/IPsec: ISAKMP on UDP 500/4500."""
        out: list[Finding] = []
        # The base pass does not request isakmp.exchangetype; ask for it explicitly
        # so the finding can name the exchange type (verified against tshark -G values).
        rows = runner.run("base", extra_args=("-e", "isakmp.exchangetype"))
        seen: set[str] = set()
        for row in rows:
            protocols = first(row, "frame.protocols")
            if "isakmp" not in protocols:
                continue
            src = first(row, "ip.src") or first(row, "ipv6.src")
            dst = first(row, "ip.dst") or first(row, "ipv6.dst")
            sport = to_int(first(row, "udp.srcport"))
            dport = to_int(first(row, "udp.dstport"))
            if not src or not dst or sport is None or dport is None:
                continue
            if sport not in IKE_PORTS and dport not in IKE_PORTS:
                continue
            key = flow_key("udp", src, sport, dst, dport)
            if key in seen:
                continue
            seen.add(key)
            exch = first(row, "isakmp.exchangetype")
            exchange_label = _IKE_EXCHANGE_NAMES.get(exch.strip(), f"exchange type {exch}")
            evidence_frame = to_int(first(row, "frame.number")) or 0
            out.append(
                self.finding(
                    code="VPN_IKE_HANDSHAKE",
                    title=f"IKE/ISAKMP handshake on {key}",
                    severity="info",
                    confidence="high",
                    summary=(
                        f"{src}:{sport} <-> {dst}:{dport} carries ISAKMP/IKE traffic on UDP {sport}/{dport}. "
                        f"The exchange type is {exchange_label} ({exch}). "
                        "IKE negotiates IPsec Security Associations; if the peer was not expected, investigate it."
                    ),
                    scope=f"{key}|ike",
                    flow_key=key,
                    subjects=[src, dst],
                    evidence=[ev(evidence_frame, "isakmp.exchangetype", exchange_label)],
                    remediation="Confirm the peer is an authorised IPsec gateway; block UDP 500/4500 elsewhere.",
                    references=["RFC 2408", "RFC 7241", "CWE-290"],
                    tags=["ike", "ipsec", "vpn"],
                )
            )
        return out

    # -- WireGuard ----------------------------------------------------------
    def _wireguard(self, runner: TsharkRunner) -> list[Finding]:
        """WireGuard: handshake messages on UDP 51820, recognised by the message-type magic."""
        out: list[Finding] = []
        base_rows = runner.run("base")
        # Collect candidate frames on port 51820, grouped by flow key.
        candidates: dict[str, list[int]] = {}  # flow_key -> [frame numbers]
        flow_info: dict[str, tuple[str, str, int, int]] = {}
        for row in base_rows:
            sport = to_int(first(row, "udp.srcport"))
            dport = to_int(first(row, "udp.dstport"))
            if sport is None or dport is None:
                continue
            if sport != WIREGUARD_PORT and dport != WIREGUARD_PORT:
                continue
            src = first(row, "ip.src") or first(row, "ipv6.src")
            dst = first(row, "ip.dst") or first(row, "ipv6.dst")
            if not src or not dst:
                continue
            frame = to_int(first(row, "frame.number")) or 0
            key = flow_key("udp", src, sport, dst, dport)
            candidates.setdefault(key, []).append(frame)
            flow_info[key] = (src, dst, sport, dport)

        if not candidates:
            return out

        # Read the payload pass to inspect the first 4 bytes of each candidate frame.
        payload_rows = runner.run("payload")
        candidate_frames = {f for frames in candidates.values() for f in frames}
        # Collect all valid WireGuard hits: (flow_key, frame, msg_type).
        wg_hits: list[tuple[str, int, int]] = []
        for row in payload_rows:
            frame = to_int(first(row, "frame.number")) or 0
            if frame not in candidate_frames:
                continue
            payload_hex = first(row, "udp.payload")
            if not payload_hex:
                continue
            raw = bytes.fromhex(payload_hex.replace(":", ""))
            if len(raw) < 4:
                continue
            msg_type = struct.unpack("<I", raw[:4])[0]
            if msg_type not in WG_HANDSHAKE_TYPES:
                continue
            # Match this frame back to a flow key using port info.
            src = first(row, "ip.src") or first(row, "ipv6.src")
            dst = first(row, "ip.dst") or first(row, "ipv6.dst")
            sport = to_int(first(row, "udp.srcport"))
            dport = to_int(first(row, "udp.dstport"))
            if not src or not dst or sport is None or dport is None:
                continue
            key = flow_key("udp", src, sport, dst, dport)
            if key not in candidates:
                continue
            wg_hits.append((key, frame, msg_type))

        seen: set[str] = set()
        for key, frame, msg_type in wg_hits:
            if key in seen:
                continue
            seen.add(key)
            src, dst, sport, dport = flow_info[key]
            label = _WG_TYPE_NAMES.get(msg_type, f"unknown({msg_type})")
            out.append(
                self.finding(
                    code="VPN_WIREGUARD_HANDSHAKE",
                    title=f"WireGuard handshake on {key}",
                    severity="info",
                    confidence="high",
                    summary=(
                        f"{src}:{sport} <-> {dst}:{dport} carries WireGuard traffic on UDP {sport}/{dport}. "
                        f"The first message is a {label} (type {msg_type}). "
                        "WireGuard is a modern VPN tunnel protocol; if this flow was not expected, investigate it."
                    ),
                    scope=f"{key}|wireguard",
                    flow_key=key,
                    subjects=[src, dst],
                    evidence=[ev(frame, "wg.type", label)],
                    remediation="Confirm the endpoint is an expected WireGuard peer.",
                    references=["RFC 8439", "CWE-290"],
                    tags=["wireguard", "vpn"],
                )
            )
        return out

    # -- OpenVPN ------------------------------------------------------------
    def _openvpn(self, runner: TsharkRunner) -> list[Finding]:
        """OpenVPN: recognised by tshark's openvpn dissector on UDP/TCP 1194."""
        out: list[Finding] = []
        rows: list[Row] = runner.run("base")
        seen: set[str] = set()
        for row in rows:
            protocols = first(row, "frame.protocols")
            if "openvpn" not in protocols:
                continue
            src = first(row, "ip.src") or first(row, "ipv6.src")
            dst = first(row, "ip.dst") or first(row, "ipv6.dst")
            udp_sport = to_int(first(row, "udp.srcport"))
            udp_dport = to_int(first(row, "udp.dstport"))
            tcp_sport = to_int(first(row, "tcp.srcport"))
            tcp_dport = to_int(first(row, "tcp.dstport"))
            if not src or not dst:
                continue
            if first(row, "udp.srcport") and udp_sport is not None and udp_dport is not None:
                proto, sport, dport = "udp", udp_sport, udp_dport
            elif first(row, "tcp.srcport") and tcp_sport is not None and tcp_dport is not None:
                proto, sport, dport = "tcp", tcp_sport, tcp_dport
            else:
                continue
            key = flow_key(proto, src, sport, dst, dport)
            if key in seen:
                continue
            seen.add(key)
            evidence_frame = to_int(first(row, "frame.number")) or 0
            out.append(
                self.finding(
                    code="VPN_OPENVPN_HANDSHAKE",
                    title=f"OpenVPN handshake on {key}",
                    severity="info",
                    confidence="high",
                    summary=(
                        f"{src}:{sport} <-> {dst}:{dport} carries OpenVPN control-channel traffic on {proto.upper()} {sport}/{dport}. "
                        "OpenVPN establishes an encrypted tunnel with its own control protocol; "
                        "tshark recognised the VPN handshake, so this peer is negotiating a tunnel."
                    ),
                    scope=f"{key}|openvpn",
                    flow_key=key,
                    subjects=[src, dst],
                    evidence=[ev(evidence_frame, "openvpn.opcode", "handshake control message")],
                    remediation="Confirm the endpoint is an expected OpenVPN peer.",
                    references=["CWE-290"],
                    tags=["openvpn", "vpn"],
                )
            )
        return out
