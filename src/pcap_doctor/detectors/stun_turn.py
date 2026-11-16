# D25 -- STUN/TURN/WebRTC/RTSP/SCTP dissection (#224). Reads the on-demand stun and rtsp tshark passes
# (their field lists are fixed in tshark.py) and correlates with indexed flows, DTLS/TLS sessions and RTP
# streams. Fields the issue asks for but the passes do not expose are recorded as notes, not guessed.

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar
from urllib.parse import urlsplit

from ..index import CaptureIndex, first
from ..models import Finding
from ..tshark import Row, to_int, to_int_auto
from .base import Detector, ev


def _redact_userinfo(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not (parts.username or parts.password):
        return url
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    netloc = f"<redacted>@{netloc}" if netloc else "<redacted>@"
    return parts._replace(netloc=netloc).geturl()

_STUN_REQUESTS = {0x0001, 0x0003}  # Binding, Allocate (TURN)
_STUN_RESPONSES = {0x0101, 0x0103}  # Binding/Allocate success


def _ep(row: Row) -> tuple[str, str, int, int, int] | None:
    src = first(row, "ip.src") or first(row, "ipv6.src")
    dst = first(row, "ip.dst") or first(row, "ipv6.dst")
    sport = to_int(first(row, "tcp.srcport") or first(row, "udp.srcport"))
    dport = to_int(first(row, "tcp.dstport") or first(row, "udp.dstport"))
    frame = to_int(first(row, "frame.number")) or 0
    if not src or not dst or sport is None or dport is None or frame <= 0:
        return None
    return src, dst, sport, dport, frame


def _flow_key(proto_guess: str, src: str, dst: str, sport: int, dport: int) -> str:
    # STUN runs over UDP or TCP; choose the key form that matches an indexed flow when possible.
    # Fall back to a stable undirected key.
    a, b = (src, sport), (dst, dport)
    if b < a:
        a, b = b, a
    return f"{proto_guess}:{a[0]}:{a[1]}<->{b[0]}:{b[1]}"


def _user_in_url(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.username or parts.password:
        user = parts.username or ""
        return user or "present"
    return None


class StunTurnDetector(Detector):
    name: ClassVar[str] = "d25.stun_turn"
    title: ClassVar[str] = "STUN/TURN, WebRTC, RTSP and SCTP signalling"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "protocol"
    description: ClassVar[str] = (
        "Surfaces STUN/TURN binding transactions and reflexive addresses, RTSP control exchanges and "
        "cleartext credentials in URLs, and WebRTC media exposure signals from DTLS/RTP context (#224)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        seen = runner._seen_protocols or set()
        findings: list[Finding] = []
        stun_rows = runner.run("stun") if "stun" in seen else []
        rtsp_rows = runner.run("rtsp") if "rtsp" in seen else []
        findings.extend(self._stun(index, stun_rows))
        findings.extend(self._rtsp(index, rtsp_rows))
        findings.extend(self._webrtc(index, stun_rows))
        self._sctp_note(index)
        self._credential_gap_note(index, stun_rows)
        return findings

    def _stun(self, index: CaptureIndex, rows: list[Row]) -> list[Finding]:
        if not rows:
            return []
        # Group by undirected endpoint pair so request/response form a transaction view.
        by_pair: dict[tuple[str, int, str, int], list[tuple[int, int, str, str, Row]]] = defaultdict(list)
        for row in rows:
            ep = _ep(row)
            stype = to_int_auto(first(row, "stun.type"))
            if ep is None or stype is None:
                self.note(index, "skipped a STUN row missing endpoints or message type")
                continue
            src, dst, sport, dport, frame = ep
            left, right = (src, sport), (dst, dport)
            if right < left:
                left, right = right, left
            by_pair[(left[0], left[1], right[0], right[1])].append((stype, frame, src, dst, row))
        findings: list[Finding] = []
        for pair, msgs in sorted(by_pair.items()):
            reqs = [(t, f, s, d, r) for t, f, s, d, r in msgs if t in _STUN_REQUESTS]
            resps = [(t, f, s, d, r) for t, f, s, d, r in msgs if t in _STUN_RESPONSES]
            proto = "udp"
            flow_key = _flow_key(proto, pair[0], pair[2], pair[1], pair[3])
            if flow_key not in index.flows:
                flow_key = _flow_key("tcp", pair[0], pair[2], pair[1], pair[3])
            subjects = [f"{pair[0]}:{pair[1]}", f"{pair[2]}:{pair[3]}"]
            if reqs and resps:
                evidence = [ev(reqs[0][1], "stun.type", f"0x{reqs[0][0]:04x} request"),
                            ev(resps[0][1], "stun.type", f"0x{resps[0][0]:04x} response")]
                findings.append(self.finding(
                    code="STUN_BINDING_TRANSACTION",
                    title="STUN/TURN binding transaction observed",
                    severity="info",
                    confidence="high",
                    summary=(
                        f"Observed {len(reqs)} STUN/TURN request(s) and {len(resps)} response(s) between "
                        f"{subjects[0]} and {subjects[1]}; binding request/response pairing is visible in the capture."
                    ),
                    scope=f"stun|{flow_key}",
                    flow_key=flow_key if flow_key in index.flows else None,
                    subjects=subjects,
                    evidence=evidence,
                    remediation=(
                        "Ensure STUN/TURN traffic is expected for this host pair. Use long-term credentials and "
                        "MESSAGE-INTEGRITY on TURN allocations, and prefer TLS (TURN over TLS/443) where feasible."
                    ),
                    references=["RFC 5389", "RFC 5766"],
                    tags=["stun", "turn", "webrtc"],
                ))
            for stype, frame, _src, _dst, row in resps:
                mapped = first(row, "stun.att.ipv4") or first(row, "stun.att.ipv6")
                mport = to_int_auto(first(row, "stun.att.port"))
                family = first(row, "stun.att.family")
                if mapped and mport is not None:
                    findings.append(self.finding(
                        code="STUN_XOR_MAPPED_ADDRESS",
                        title="STUN XOR-MAPPED-ADDRESS observed",
                        severity="info",
                        confidence="high",
                        summary=(
                            f"STUN response 0x{stype:04x} at frame {frame} reports a reflexive transport address "
                            f"{mapped}:{mport} (family {family or 'unknown'}) for {subjects[0]} <-> {subjects[1]}."
                        ),
                        scope=f"stun-xor|{flow_key}|{mapped}:{mport}|{frame}",
                        flow_key=flow_key if flow_key in index.flows else None,
                        subjects=[*subjects, f"{mapped}:{mport}"],
                        evidence=[
                            ev(frame, "stun.type", f"0x{stype:04x}"),
                            ev(frame, "stun.att.ip", mapped),
                            ev(frame, "stun.att.port", mport),
                        ],
                        remediation=(
                            "Reflexive addresses are a normal part of ICE/STUN. Limit exposure by restricting STUN/TURN "
                            "to required endpoints and monitoring for unexpected external reflexive addresses."
                        ),
                        references=["RFC 5389", "RFC 8445"],
                        tags=["stun", "ice", "webrtc"],
                    ))
        return findings

    def _rtsp(self, index: CaptureIndex, rows: list[Row]) -> list[Finding]:
        if not rows:
            return []
        by_flow: dict[str, list[tuple[int, str, str, str | None, Row]]] = defaultdict(list)
        for row in rows:
            ep = _ep(row)
            if ep is None:
                continue
            src, dst, sport, dport, frame = ep
            flow_key = _flow_key("tcp", src, dst, sport, dport)
            if flow_key not in index.flows:
                flow_key = _flow_key("udp", src, dst, sport, dport)
            method = first(row, "rtsp.method")
            url = first(row, "rtsp.url")
            status = first(row, "rtsp.status") or None
            by_flow[flow_key].append((frame, method, url, status, row))
        findings: list[Finding] = []
        for flow_key, msgs in sorted(by_flow.items()):
            flow = index.flows.get(flow_key)
            subjects = [f"{flow.endpoint_a}:{flow.port_a}", f"{flow.endpoint_b}:{flow.port_b}"] if flow else []
            methods = sorted({m for _, m, _, _, _ in msgs if m})
            if "DESCRIBE" in methods or "PLAY" in methods:
                wanted = [m for m in msgs if m[1] in {"DESCRIBE", "PLAY"}] or msgs[:2]
                findings.append(self.finding(
                    code="RTSP_CONTROL_EXCHANGE",
                    title="RTSP DESCRIBE/PLAY control exchange observed",
                    severity="info",
                    confidence="high",
                    summary=(
                        f"RTSP control traffic with methods {', '.join(methods)} observed on {flow_key}; "
                        "session setup/control is visible in cleartext."
                    ),
                    scope=f"rtsp|{flow_key}",
                    flow_key=flow_key if flow_key in index.flows else None,
                    subjects=subjects,
                    evidence=[
                        ev(frame, "rtsp.method", method or f"status {status}")
                        for frame, method, _url, status, _ in wanted[:4]
                    ],
                    remediation=(
                        "Protect RTSP control channels with RTSPS/TLS where supported, require authentication, and "
                        "avoid embedding credentials in URLs. Restrict camera/stream access to trusted networks."
                    ),
                    references=["RFC 2326", "CWE-319"],
                    tags=["rtsp"],
                ))
            for frame, method, url, _status, _ in msgs:
                user = _user_in_url(url) if url else None
                if user and url:
                    findings.append(self.finding(
                        code="RTSP_CLEARTEXT_CREDENTIAL_URL",
                        title="RTSP URL contains credentials",
                        severity="critical",
                        confidence="high",
                        summary=(
                            f"RTSP {method or 'request'} at frame {frame} includes user information in the URL; "
                            "credentials in URLs traverse the network path and are commonly logged."
                        ),
                        scope=f"rtsp-cred|{flow_key}|{frame}",
                        flow_key=flow_key if flow_key in index.flows else None,
                        subjects=subjects,
                        evidence=[ev(frame, "rtsp.url", _redact_userinfo(url)), ev(frame, "rtsp.userinfo", "<redacted>")],
                        remediation=(
                            "Remove credentials from RTSP URLs. Use digest/basic authentication over a protected channel "
                            "or token-based access, and rotate exposed credentials."
                        ),
                        references=["RFC 2326", "CWE-522", "CWE-319"],
                        tags=["rtsp", "credentials", "cleartext"],
                    ))
        return findings

    def _webrtc(self, index: CaptureIndex, stun_rows: list[Row]) -> list[Finding]:
        findings: list[Finding] = []
        dtls = [s for s in index.tls.values() if getattr(s, "proto", "tls") == "dtls"]
        if dtls and stun_rows:
            key = dtls[0].key
            frame = dtls[0].frames[0] if dtls[0].frames else (dtls[0].client_hello.frame if dtls[0].client_hello else 1)
            findings.append(self.finding(
                code="WEBRTC_DTLS_ASSOCIATION",
                title="DTLS association observed alongside STUN/ICE traffic",
                severity="info",
                confidence="medium",
                summary=(
                    f"Observed {len(dtls)} DTLS session(s) and {len(stun_rows)} STUN packet(s) in the capture, "
                    "consistent with a WebRTC DTLS/SRTP association context; SRTP protection cannot be confirmed "
                    "from the available tshark fields."
                ),
                scope=f"webrtc-dtls|{key}",
                flow_key=key,
                subjects=[],
                evidence=[ev(frame, "dtls.session", key), ev(to_int(first(stun_rows[0], "frame.number")) or 1, "stun.packet", "present")],
                remediation=(
                    "Verify that media is protected with SRTP/DTLS-SRTP end to end. Disable legacy SDES where possible "
                    "and require authenticated ICE."
                ),
                references=["RFC 5764", "RFC 8827"],
                tags=["webrtc", "dtls", "srtp"],
            ))
        # Report unprotected RTP only in a WebRTC-signalled context to avoid duplicating SIP/RTP findings broadly.
        if stun_rows or dtls:
            for stream in index.rtp:
                findings.append(self.finding(
                    code="WEBRTC_MEDIA_UNPROTECTED",
                    title="RTP media observed without SRTP protection",
                    severity="high",
                    confidence="high",
                    summary=(
                        f"RTP stream {stream.key} (SSRC {stream.ssrc}, {stream.packets} packets) is observable in cleartext; "
                        "media confidentiality and integrity are not protected by SRTP in this capture."
                    ),
                    scope=f"webrtc-rtp|{stream.key}|{stream.ssrc}",
                    flow_key=stream.key,
                    subjects=[s for s in (stream.from_ip, stream.to_ip) if s],
                    evidence=[ev(stream.first_frame or 1, "rtp.ssrc", stream.ssrc), ev(stream.first_frame or 1, "rtp.pt", stream.payload_type)],
                    remediation=(
                        "Use SRTP with DTLS-SRTP keying for WebRTC/media streams. Disable plaintext RTP on the media path "
                        "and enforce secure transport policies."
                    ),
                    references=["RFC 3711", "RFC 5764", "CWE-319"],
                    tags=["webrtc", "rtp", "srtp", "cleartext"],
                ))
        return findings

    def _sctp_note(self, index: CaptureIndex) -> None:
        self.note(
            index,
            "SCTP chunk types and association setup are not covered because no SCTP tshark pass or indexed SCTP "
            "fields exist in this build (core gap); SCTP port inventory cannot be reported from available data."
        )

    def _credential_gap_note(self, index: CaptureIndex, stun_rows: list[Row]) -> None:
        if not stun_rows:
            return
        self.note(
            index,
            "STUN long-term credential attributes (USERNAME, MESSAGE-INTEGRITY, NONCE, REALM) and attributes such as "
            "SOFTWARE/FINGERPRINT and TURN RTCP demultiplexing fields are not exposed by the current stun tshark "
            "pass; credential leakage and those attributes cannot be confirmed or denied from available fields."
        )
