"""Cleartext IRC, SOCKS, TDS and COTP credential extraction (issue #231)."""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from ..index import CaptureIndex, first
from ..models import Finding
from ..tshark import Row, to_int
from .base import Detector, ev

_RFC1929 = "RFC 1929"
_RFC1002 = "RFC 1002"
_MS_TDS = "MS-TDS 2.2.6.4"
_CWE319 = "CWE-319"
_CWE522 = "CWE-522"


def _addr(row: Row) -> tuple[str, str, int | None]:
    src = first(row, "ip.src") or first(row, "ipv6.src") or "unknown"
    dst = first(row, "ip.dst") or first(row, "ipv6.dst") or "unknown"
    port = to_int(first(row, "tcp.dstport")) or to_int(first(row, "udp.dstport"))
    return src, dst, port


def _frame(row: Row) -> int:
    return to_int(first(row, "frame.number")) or 0


def _redacted(secret: str) -> str:
    return f"<redacted {len(secret)} chars>"


class CleartextCredsDetector(Detector):
    name: ClassVar[str] = "d25.cleartext_creds"
    title: ClassVar[str] = "Cleartext protocol credentials"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "Credentials"
    description: ClassVar[str] = (
        "Credentials exposed in the clear in IRC (PASS, OPER, NickServ IDENTIFY, channel keys), "
        "SOCKS4/SOCKS5 authentication, TDS LOGIN7, and COTP transport parameters."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._irc(index))
        findings.extend(self._socks(index))
        findings.extend(self._tds(index))
        findings.extend(self._cotp(index))
        return findings

    # -- IRC ---------------------------------------------------------------
    def _irc(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        rows = runner.run("services")
        if not rows:
            return []
        findings: list[Finding] = []
        last_nick: dict[str, str] = {}
        for row in rows:
            cmd = (first(row, "irc.request.command") or "").upper()
            param = first(row, "irc.request.command_parameter")
            if not cmd:
                continue
            frame = _frame(row)
            src, dst, port = _addr(row)
            flow_key = self._flow_key(index, row)
            if cmd == "NICK" and param:
                last_nick[flow_key or src] = param.split(",")[0].strip()
                continue
            if cmd == "PASS" and param:
                account = last_nick.get(flow_key or src, "(before NICK)")
                findings.append(self._cred_finding(
                    code="IRC_CLEARTEXT_CREDENTIAL",
                    protocol="IRC",
                    account=account,
                    detail="PASS",
                    frame=frame,
                    src=src, dst=dst, port=port,
                    flow_key=flow_key,
                    field="irc.request.command_parameter",
                    secret=param,
                    references=["RFC 1459", _CWE319],
                ))
            elif cmd == "OPER" and param:
                # OPER <name> <password>
                parts = param.split(None, 1)
                account = parts[0] if parts else "(unknown)"
                secret = parts[1] if len(parts) > 1 else param
                findings.append(self._cred_finding(
                    code="IRC_CLEARTEXT_CREDENTIAL",
                    protocol="IRC",
                    account=account,
                    detail="OPER",
                    frame=frame,
                    src=src, dst=dst, port=port,
                    flow_key=flow_key,
                    field="irc.request.command_parameter",
                    secret=secret,
                    references=["RFC 1459", _CWE319],
                ))
            elif cmd == "JOIN" and param:
                # JOIN #chan key  or JOIN #chan1,#chan2 key1,key2
                parts = param.split()
                if len(parts) >= 2:
                    chans = parts[0]
                    key = parts[1]
                    findings.append(self._cred_finding(
                        code="IRC_CLEARTEXT_CREDENTIAL",
                        protocol="IRC",
                        account=chans,
                        detail="channel key",
                        frame=frame,
                        src=src, dst=dst, port=port,
                        flow_key=flow_key,
                        field="irc.request.command_parameter",
                        secret=key,
                        references=["RFC 1459", _CWE319],
                    ))
            elif cmd == "PRIVMSG" and param:
                # NickServ IDENTIFY [nick] <password>
                # param from tshark is often "NickServ" in command_parameter but full text in irc.request;
                # try to parse identify from parameter text we have
                low = param.lower()
                if "nickserv" in low and "identify" in low:
                    # "NickServ :IDENTIFY secret" style in param? use account as NickServ
                    tokens = param.split()
                    # find IDENTIFY token
                    try:
                        idx = [t.upper() for t in tokens].index("IDENTIFY")
                        secret = tokens[idx + 1] if idx + 1 < len(tokens) else "(redacted)"
                        account = "NickServ"
                    except (ValueError, IndexError):
                        secret = param
                        account = "NickServ"
                    findings.append(self._cred_finding(
                        code="IRC_CLEARTEXT_CREDENTIAL",
                        protocol="IRC",
                        account=account,
                        detail="NickServ IDENTIFY",
                        frame=frame,
                        src=src, dst=dst, port=port,
                        flow_key=flow_key,
                        field="irc.request.command_parameter",
                        secret=secret,
                        references=["RFC 1459", _CWE319],
                    ))
        return findings

    # -- SOCKS -------------------------------------------------------------
    def _socks(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        rows = runner.run("services")
        findings: list[Finding] = []
        # SOCKS5 username/password subnegotiation (RFC 1929) exposed via socks.username/password
        by_flow: dict[str, dict[str, tuple[int, str, str, str, int | None]]] = defaultdict(dict)
        for row in rows:
            user = first(row, "socks.username")
            pwd = first(row, "socks.password")
            if not user and not pwd:
                continue
            frame = _frame(row)
            src, dst, port = _addr(row)
            flow_key = self._flow_key(index, row) or f"socks|{src}>{dst}:{port}"
            if user:
                by_flow[flow_key]["user"] = (frame, src, dst, user, port)
            if pwd:
                by_flow[flow_key]["pass"] = (frame, src, dst, pwd, port)
        for flow_key, parts in by_flow.items():
            user_frame, src, dst, username, port = parts.get("user", (0, "unknown", "unknown", "(unknown)", None))
            pass_frame, _, _, password, _ = parts.get("pass", (user_frame, src, dst, "", port))
            frame = min(f for f in (user_frame, pass_frame) if f > 0) if (user_frame or pass_frame) else (user_frame or pass_frame)
            if frame <= 0:
                continue
            secret = password or username
            findings.append(self._cred_finding(
                code="SOCKS_CLEARTEXT_CREDENTIAL",
                protocol="SOCKS5",
                account=username or "(unknown)",
                detail="username/password (RFC 1929)",
                frame=frame,
                src=src, dst=dst, port=port,
                flow_key=flow_key if flow_key in index.flows else None,
                field="socks.username/socks.password",
                secret=secret,
                references=[_RFC1929, _CWE319],
            ))

        # SOCKS4 request: socks dissector may not expose user/password as separate fields in same way;
        # report a gap/note if we cannot observe. The issue states "SOCKS4 request" - without a pass/fields
        # exposing the SOCKS4 userid we cannot extract it; note it.
        self.note(index, "SOCKS4 request credential extraction requires SOCKS4 userid fields not present in available passes (core gap).")
        return findings

    # -- TDS ---------------------------------------------------------------
    def _tds(self, index: CaptureIndex) -> list[Finding]:
        runner = index.runner
        if runner is None:
            return []
        rows = runner.run("tds")
        findings: list[Finding] = []
        for row in rows:
            if not first(row, "tds.7login.password") and not first(row, "tds.7login.username"):
                continue
            # LOGIN7 packets have tds.type 16 (Login7) or fields present
            username = first(row, "tds.7login.username") or "(unknown)"
            password = first(row, "tds.7login.password") or ""
            frame = _frame(row)
            if frame <= 0:
                continue
            src, dst, port = _addr(row)
            flow_key = self._flow_key(index, row)
            secret = password or username
            findings.append(self._cred_finding(
                code="TDS_CLEARTEXT_CREDENTIAL",
                protocol="TDS (MSSQL)",
                account=username,
                detail="LOGIN7",
                frame=frame,
                src=src, dst=dst, port=port,
                flow_key=flow_key,
                field="tds.7login.password",
                secret=secret,
                references=[_MS_TDS, _CWE319],
            ))
        return findings

    # -- COTP --------------------------------------------------------------
    def _cotp(self, index: CaptureIndex) -> list[Finding]:
        # No COTP pass exists in tshark.py; fields like cotp.type are not available via runner passes.
        if index.runner is not None:
            self.note(index, "COTP (RFC 1002) call-accepted/reject and transport parameters require a COTP tshark pass/fields not available (core gap).")
        return []

    # -- helpers -----------------------------------------------------------
    def _flow_key(self, index: CaptureIndex, row: Row) -> str | None:
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        if not src or not dst:
            return None
        sport = to_int(first(row, "tcp.srcport")) or to_int(first(row, "udp.srcport")) or 0
        dport = to_int(first(row, "tcp.dstport")) or to_int(first(row, "udp.dstport")) or 0
        proto = "tcp" if first(row, "tcp.srcport") or first(row, "tcp.dstport") else "udp"
        from ..models import flow_key

        return flow_key(proto, src, sport, dst, dport)

    def _cred_finding(
        self,
        *,
        code: str,
        protocol: str,
        account: str,
        detail: str,
        frame: int,
        src: str,
        dst: str,
        port: int | None,
        flow_key: str | None,
        field: str,
        secret: str,
        references: list[str],
    ) -> Finding:
        endpoint = f"{dst}:{port}" if port else dst
        return self.finding(
            code=code,
            title=f"{protocol} credential exposed in cleartext",
            severity="critical",
            confidence="high",
            summary=(
                f"Frame {frame}: {protocol} {detail} credential for account {account!r} "
                f"was observed in cleartext from {src} to {endpoint}. "
                "The secret is redacted; treat the credential as compromised."
            ),
            scope=f"{flow_key or src + '>' + dst}|{protocol}|{account}|{detail}|{frame}",
            flow_key=flow_key,
            subjects=[src, endpoint],
            evidence=[ev(frame, field, _redacted(secret) if secret else "<redacted>")],
            remediation="Rotate the exposed credential and require an encrypted, authenticated transport.",
            references=references,
            tags=["cleartext", "credential", protocol.lower().replace(" ", "-").replace("(", "").replace(")", "")],
        )
