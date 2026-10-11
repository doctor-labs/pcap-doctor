"""Zeek-style per-protocol logs (TSV or JSON): conn, dns, http, ssl, x509, files, notice, weird, dhcp, ftp, smtp,
ssh, smb (issue #199).

The tables are built on demand from the :class:`CaptureIndex` plus a few extra tshark passes (``conn``, ``dhcp``,
``ftp``, ``smtp``, ``smb``, ``weird``) that ``analyze`` never runs. The column names and types follow Zeek's, so
``zeek-cut``, Brim and the usual SIEM parsers read them. Where tshark cannot supply what Zeek knows (a TCP
``history`` string is approximated from the flags, payload bytes come from the TCP/UDP length fields) the column
says so in ``docs/zeek-logs.md`` rather than guessing.

Secrets stay out: FTP ``PASS`` arguments, HTTP credentials and SMTP AUTH data are never written.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from .data_ciphers import registry
from .index import CaptureIndex, first, many
from .models import flow_key, stable_id
from .prompts import clean_capture_text
from .smb import unc, unescape
from .tshark import CHECKSUM_ARGS, Row, to_float, to_int, to_int_auto

Column = tuple[str, str]  # (zeek field name, zeek type)


@dataclass
class LogTable:
    name: str
    columns: list[Column]
    rows: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------- context
class _Ctx:
    def __init__(self, index: CaptureIndex) -> None:
        if index.runner is None:
            raise ValueError("this index was not built by IndexBuilder; no tshark runner to read more passes from")
        self.index = index
        self.runner = index.runner
        self.times: dict[int, float] = {}
        for row in self.runner.run("base"):
            n, t = to_int(first(row, "frame.number")), to_float(first(row, "frame.time_epoch"))
            if n is not None and t is not None:
                self.times[n] = t
        self._conn: dict[str, _Conn] | None = None

    def ts(self, frame: int | None) -> float | None:
        return self.times.get(frame) if frame else None

    @property
    def conns(self) -> dict[str, _Conn]:
        if self._conn is None:
            self._conn = _read_conns(self.runner.run("conn", CHECKSUM_ARGS))
        return self._conn

    def ids(self, key: str) -> dict[str, Any]:
        """``uid`` and the four ``id.*`` columns for a (canonical) flow key; originator first, like Zeek."""
        conn = self.conns.get(key)
        if conn:
            return conn.ids()
        _proto, a, ap, b, bp = _endpoints(key)
        return {"uid": _uid(key), "id.orig_h": a, "id.orig_p": ap, "id.resp_h": b, "id.resp_p": bp}

    def row_key(self, row: Row, proto: str) -> str | None:
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        sp = to_int(first(row, f"{proto}.srcport"))
        dp = to_int(first(row, f"{proto}.dstport"))
        if not src or not dst or sp is None or dp is None:
            return None
        return flow_key(proto, src, sp, dst, dp)


def _endpoints(key: str) -> tuple[str, str, int, str, int]:
    from .models import endpoints_of

    return endpoints_of(key)


def _uid(key: str) -> str:
    return "C" + stable_id("uid", key)[:16]


ID_COLS: list[Column] = [
    ("uid", "string"), ("id.orig_h", "addr"), ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
]


@dataclass
class _Conn:
    key: str
    proto: str
    orig: tuple[str, int]
    resp: tuple[str, int]
    first_ts: float = 0.0
    last_ts: float = 0.0
    pkts: list[int] = field(default_factory=lambda: [0, 0])
    payload: list[int] = field(default_factory=lambda: [0, 0])
    ip_bytes: list[int] = field(default_factory=lambda: [0, 0])
    syn: list[int] = field(default_factory=lambda: [0, 0])
    synack: list[int] = field(default_factory=lambda: [0, 0])
    fin: list[int] = field(default_factory=lambda: [0, 0])
    rst: list[int] = field(default_factory=lambda: [0, 0])
    history: list[str] = field(default_factory=list)
    missed: int = 0  # bytes in content gaps (Zeek missed_bytes)
    dup_acks: int = 0
    out_of_order: int = 0
    events: dict[str, int] = field(default_factory=dict)  # history letter -> times seen
    next_seq: list[int] = field(default_factory=lambda: [0, 0])

    def flag(self, letter: str) -> None:
        """Zeek's repeatable history letters (C, G, T, W) are logged at the 1st, 10th, 100th... occurrence."""
        n = self.events[letter] = self.events.get(letter, 0) + 1
        if str(n) == "1" + "0" * (len(str(n)) - 1):
            self.history.append(letter)

    def ids(self) -> dict[str, Any]:
        return {"uid": _uid(self.key), "id.orig_h": self.orig[0], "id.orig_p": self.orig[1],
                "id.resp_h": self.resp[0], "id.resp_p": self.resp[1]}

    def state(self) -> str:
        """Zeek's connection state, from the flag counts of both sides (index 0 = originator)."""
        if self.proto == "udp":
            return "SF" if self.pkts[1] else "S0"
        o_syn, r_synack = self.syn[0] > 0, self.synack[1] > 0
        if not o_syn:
            return "OTH"
        if not r_synack:
            if self.rst[1]:
                return "REJ"
            return "RSTOS0" if self.rst[0] else "S0"
        if self.rst[0]:
            return "RSTO"
        if self.rst[1]:
            return "RSTR"
        if self.fin[0] and self.fin[1]:
            return "SF"
        if self.fin[0]:
            return "S2"
        if self.fin[1]:
            return "S3"
        return "S1"


def _read_conns(rows: list[Row]) -> dict[str, _Conn]:
    conns: dict[str, _Conn] = {}
    for row in rows:
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        sp, dp = to_int(first(row, f"{proto}.srcport")), to_int(first(row, f"{proto}.dstport"))
        if not src or not dst or sp is None or dp is None:
            continue
        key = flow_key(proto, src, sp, dst, dp)
        ts = to_float(first(row, "frame.time_epoch")) or 0.0
        conn = conns.get(key)
        if conn is None:
            conn = conns[key] = _Conn(key, proto, (src, sp), (dst, dp), ts, ts)
        side = 0 if (src, sp) == conn.orig else 1
        conn.last_ts = max(conn.last_ts, ts)
        conn.pkts[side] += 1
        if proto == "tcp":
            payload = to_int(first(row, "tcp.len")) or 0
        else:
            payload = max(0, (to_int(first(row, "udp.length")) or 8) - 8)
        conn.payload[side] += payload
        ip_len = to_int(first(row, "ip.len"))
        if ip_len is None:
            ip_len = (to_int(first(row, "ipv6.plen")) or 0) + 40
        conn.ip_bytes[side] += ip_len
        if first(row, f"{proto}.checksum.status") == "0":  # noted, then ignored, as Zeek drops the packet
            conn.flag("C" if side == 0 else "c")
            continue
        if proto != "tcp":
            continue
        seq, nxt = to_int(first(row, "tcp.seq")), to_int(first(row, "tcp.nxtseq"))
        if first(row, "tcp.analysis.lost_segment") and seq is not None and conn.next_seq[side]:
            conn.missed += max(0, seq - conn.next_seq[side])
        if nxt:
            conn.next_seq[side] = max(conn.next_seq[side], nxt)
        for field_name, letter in (("tcp.analysis.lost_segment", "G"), ("tcp.analysis.retransmission", "T"),
                                   ("tcp.analysis.zero_window", "W")):
            if first(row, field_name):
                conn.flag(letter if side == 0 else letter.lower())
        conn.dup_acks += bool(first(row, "tcp.analysis.duplicate_ack"))
        conn.out_of_order += bool(first(row, "tcp.analysis.out_of_order"))
        syn, ack = first(row, "tcp.flags.syn") in ("1", "True"), first(row, "tcp.flags.ack") in ("1", "True")
        fin, rst = first(row, "tcp.flags.fin") in ("1", "True"), first(row, "tcp.flags.reset") in ("1", "True")
        letters = []
        if syn and not ack:
            conn.syn[side] += 1
            letters.append("S")
        elif syn:
            conn.synack[side] += 1
            letters.append("H")
        if fin:
            conn.fin[side] += 1
            letters.append("F")
        if rst:
            conn.rst[side] += 1
            letters.append("R")
        if not (syn or fin or rst):
            letters.append("D" if payload else "A")
        for letter in letters:
            letter = letter if side == 0 else letter.lower()
            if not conn.history or conn.history[-1] != letter:  # repeated ACK / data packets collapse to one letter
                conn.history.append(letter)
    return conns


# ---------------------------------------------------------------------------- builders
_SERVICE = {"tls": "ssl", "dtls": "dtls", "http": "http", "dns": "dns", "ssh": "ssh", "ftp": "ftp", "smtp": "smtp",
            "smb": "smb", "smb2": "smb", "dhcp": "dhcp", "ntp": "ntp", "snmp": "snmp", "telnet": "telnet",
            "ldap": "ldap", "sip": "sip", "quic": "quic", "mysql": "mysql", "modbus": "modbus", "mqtt": "mqtt"}

_PORT_SERVICE = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 67: "dhcp", 80: "http", 123: "ntp", 161: "snmp",
                 389: "ldap", 443: "ssl", 445: "smb", 502: "modbus", 1883: "mqtt", 5060: "sip", 8080: "http"}

CONN_COLS: list[Column] = [
    ("ts", "time"), *ID_COLS, ("proto", "enum"), ("service", "string"), ("duration", "interval"),
    ("orig_bytes", "count"), ("resp_bytes", "count"), ("conn_state", "string"), ("missed_bytes", "count"),
    ("history", "string"), ("orig_pkts", "count"), ("orig_ip_bytes", "count"), ("resp_pkts", "count"),
    ("resp_ip_bytes", "count"), ("dup_acks", "count"), ("out_of_order", "count"),
]


def _conn_log(ctx: _Ctx) -> LogTable:
    table = LogTable("conn", CONN_COLS)
    for key, c in sorted(ctx.conns.items(), key=lambda kv: (kv[1].first_ts, kv[0])):
        flow = ctx.index.flows.get(key)
        table.rows.append({
            "ts": c.first_ts, **c.ids(), "proto": c.proto,
            "service": (_SERVICE.get(flow.app_proto) if flow else None) or _PORT_SERVICE.get(c.resp[1]),
            "duration": round(c.last_ts - c.first_ts, 6), "orig_bytes": c.payload[0], "resp_bytes": c.payload[1],
            "conn_state": c.state(), "missed_bytes": c.missed, "history": "".join(c.history) or None,
            "orig_pkts": c.pkts[0], "orig_ip_bytes": c.ip_bytes[0], "resp_pkts": c.pkts[1],
            "resp_ip_bytes": c.ip_bytes[1], "dup_acks": c.dup_acks, "out_of_order": c.out_of_order,
        })
    return table


_QTYPES = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA",
           "33": "SRV", "43": "DS", "46": "RRSIG", "48": "DNSKEY", "64": "SVCB", "65": "HTTPS", "257": "CAA", "255": "*"}
_RCODES = {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED"}


def _dns_log(ctx: _Ctx) -> LogTable:
    table = LogTable("dns", [
        ("ts", "time"), *ID_COLS, ("proto", "enum"), ("query", "string"), ("qtype_name", "string"),
        ("rcode_name", "string"), ("answers", "vector[string]"), ("rejected", "bool"),
        ("edns_udp_size", "count")])
    for q in ctx.index.dns:
        if q.is_response:
            continue
        rcode = q.rcode
        table.rows.append({
            "ts": ctx.ts(q.frame), **ctx.ids(q.key), "proto": q.key.split(":", 1)[0], "query": q.name,
            "qtype_name": _QTYPES.get(q.qtype, q.qtype),
            "rcode_name": _RCODES.get(rcode, rcode) if rcode is not None else None, "answers": q.answers or None,
            "rejected": None if rcode is None else _RCODES.get(rcode, rcode) != "NOERROR",
            "edns_udp_size": q.edns_udp_size,
        })
    return table


def _http_log(ctx: _Ctx) -> LogTable:
    table = LogTable("http", [
        ("ts", "time"), *ID_COLS, ("method", "string"), ("host", "string"), ("uri", "string"), ("version", "string"),
        ("user_agent", "string"), ("status_code", "count"), ("resp_mime_types", "vector[string]"),
        ("resp_filenames", "vector[string]"), ("auth_scheme", "string"), ("encrypted", "bool")])
    for h in ctx.index.http:
        table.rows.append({
            "ts": ctx.ts(h.frame), **ctx.ids(h.key), "method": h.method, "host": h.host, "uri": h.uri,
            "version": h.version, "user_agent": h.user_agent, "status_code": h.status,
            "resp_mime_types": h.content_types or None, "resp_filenames": h.download_names or None,
            "auth_scheme": h.auth_scheme, "encrypted": h.is_encrypted,
        })
    return table


def _fuid(*parts: object) -> str:
    return "F" + stable_id(*parts)[:16]


def _ssl_log(ctx: _Ctx) -> LogTable:
    suites = registry()
    table = LogTable("ssl", [
        ("ts", "time"), *ID_COLS, ("version", "string"), ("cipher", "string"), ("curve", "string"),
        ("server_name", "string"), ("resumed", "bool"), ("next_protocol", "string"), ("established", "bool"),
        ("cert_chain_fuids", "vector[string]"), ("ja3", "string"), ("ja3s", "string"), ("ja4", "string"),
        ("ja4s", "string"), ("validation_status", "string"), ("hostname_match", "bool")])
    for s in ctx.index.tls.values():
        suite = suites.get(s.chosen_cipher) if s.chosen_cipher is not None else None
        table.rows.append({
            "ts": ctx.ts(s.frames[0] if s.frames else None), **ctx.ids(s.key), "version": s.negotiated_version,
            "cipher": suite.name if suite else None, "curve": s.groups[0] if s.groups else None,
            "server_name": s.sni, "resumed": s.resumption, "next_protocol": s.alpn[0] if s.alpn else None,
            "established": s.complete, "cert_chain_fuids": [_fuid(s.key, c.chain_index) for c in s.certs] or None,
            "ja3": s.ja3, "ja3s": s.ja3s, "ja4": s.ja4, "ja4s": s.ja4s,
            "validation_status": s.validation_status, "hostname_match": s.hostname_match,
        })
    return table


def _x509_log(ctx: _Ctx) -> LogTable:
    table = LogTable("x509", [
        ("ts", "time"), ("id", "string"), ("fingerprint", "string"),
        ("certificate.subject", "string"), ("certificate.issuer", "string"),
        ("certificate.not_valid_before", "string"), ("certificate.not_valid_after", "string"),
        ("certificate.key_alg", "string"), ("certificate.key_length", "count"), ("certificate.sig_alg", "string"),
        ("certificate.curve", "string"), ("san.dns", "vector[string]"), ("spki_sha256", "string")])
    for s in ctx.index.tls.values():
        for c in s.certs:
            table.rows.append({
                "ts": ctx.ts(c.frame), "id": _fuid(s.key, c.chain_index), "fingerprint": c.fingerprint,
                "certificate.subject": c.subject,
                "certificate.issuer": c.issuer, "certificate.not_valid_before": c.not_before,
                "certificate.not_valid_after": c.not_after, "certificate.key_alg": c.key_algorithm,
                "certificate.key_length": c.public_key_bits, "certificate.sig_alg": c.signature_algorithm_oid,
                "certificate.curve": c.key_curve, "san.dns": c.san_dns or None, "spki_sha256": c.spki_sha256,
            })
    return table


def _ssh_log(ctx: _Ctx) -> LogTable:
    table = LogTable("ssh", [
        ("ts", "time"), *ID_COLS, ("version", "count"), ("client", "string"), ("server", "string"),
        ("cipher_alg", "string"), ("mac_alg", "string"), ("compression_alg", "string"), ("kex_alg", "string"),
        ("host_key_alg", "string"), ("hassh", "string"), ("hasshAlgorithms", "string"),
        ("hasshServer", "string"), ("hasshServerAlgorithms", "string")])
    for s in ctx.index.ssh:
        table.rows.append({
            "ts": ctx.ts(s.frame), **ctx.ids(s.key), "version": 2, "client": s.client_version,
            "server": s.server_version, "cipher_alg": s.ciphers[0] if s.ciphers else None,
            "mac_alg": s.macs[0] if s.macs else None, "compression_alg": s.compression[0] if s.compression else None,
            "kex_alg": s.kex_algorithms[0] if s.kex_algorithms else None,
            "host_key_alg": s.host_key_algorithms[0] if s.host_key_algorithms else None,
            "hassh": s.hassh, "hasshAlgorithms": s.hassh_algorithms,
            "hasshServer": s.hassh_server, "hasshServerAlgorithms": s.hassh_server_algorithms,
        })
    return table


def _files_log(ctx: _Ctx) -> LogTable:
    """Every file the extractor recovers (HTTP, FTP, SMB, TFTP, mail), hashed and typed by magic bytes."""
    import tempfile

    from .extract import extract, safe_name

    table = LogTable("files", [
        ("ts", "time"), ("fuid", "string"), ("tx_hosts", "set[addr]"), ("rx_hosts", "set[addr]"),
        ("conn_uids", "set[string]"), ("source", "string"), ("mime_type", "string"), ("filename", "string"),
        ("seen_bytes", "count"), ("md5", "string"), ("sha1", "string"), ("sha256", "string")])
    exchanges = {safe_name((h.uri or "").split("?", 1)[0]): h for h in ctx.index.http if h.status and h.uri}
    with tempfile.TemporaryDirectory() as tmp:
        for f in extract(ctx.index.capture_path, Path(tmp)):
            if f.info is None:
                continue
            row: dict[str, Any] = {
                "ts": None, "fuid": _fuid(f.protocol, f.info.sha256, f.name), "source": f.protocol.upper(),
                "mime_type": f.info.mime_type, "filename": f.name, "seen_bytes": f.info.size, "md5": f.info.md5,
                "sha1": f.info.sha1, "sha256": f.info.sha256,
            }
            h = exchanges.get(safe_name(f.name)) if f.protocol == "http" else None
            if h:
                ids = ctx.ids(h.key)
                row.update(ts=ctx.ts(h.frame), tx_hosts=[ids["id.resp_h"]], rx_hosts=[ids["id.orig_h"]],
                           conn_uids=[ids["uid"]])
            table.rows.append(row)
    return table


def _notice_log(ctx: _Ctx) -> LogTable:
    from .registry import enabled_detectors

    table = LogTable("notice", [
        ("ts", "time"), *ID_COLS, ("note", "string"), ("msg", "string"), ("sub", "string"), ("severity", "string")])
    for detector in enabled_detectors():
        try:
            found = detector.detect(ctx.index)
        except Exception:  # one bad detector must not sink the logs, as in the pipeline
            continue
        for f in found:
            frame = f.evidence[0].frame if f.evidence else None
            table.rows.append({
                "ts": ctx.ts(frame), **(ctx.ids(f.flow_key) if f.flow_key else {}), "note": f.code,
                "msg": f.title, "sub": f.summary[:200], "severity": f.severity,
            })
    table.rows.sort(key=lambda r: (r["ts"] is None, r["ts"] or 0.0, r["note"]))
    return table


_SEVERITY = {0x600000: "warn", 0x800000: "error"}

#: Wireshark epan/proto.h expert-info severity bits (0x00100000..0x00800000).
_EXPERT_SEVERITY: dict[int, str] = {
    0x00100000: "comment", 0x00200000: "chat", 0x00400000: "note",
    0x00600000: "warn", 0x00800000: "error",
}

#: Wireshark epan/proto.h expert-info group bits (0x01000000..0x0e000000).
_EXPERT_GROUP: dict[int, str] = {
    0x01000000: "checksum", 0x02000000: "sequence", 0x03000000: "response-code",
    0x04000000: "request-code", 0x05000000: "undecoded", 0x06000000: "reassemble",
    0x07000000: "malformed", 0x08000000: "debug", 0x09000000: "protocol",
    0x0a000000: "security", 0x0b000000: "comments", 0x0c000000: "decryption",
    0x0d000000: "assumption", 0x0e000000: "deprecated",
}


#: tshark expert message prefix -> Zeek weird name, only where the two mean exactly the same thing (#210). Everything
#: else keeps the slug of tshark's own message; docs/zeek-logs.md lists both.
ZEEK_WEIRD: dict[str, str] = {
    "Bad length value": "UDP_datagram_length_mismatch",
    "Bogus TCP Header length": "bad_TCP_header_len",
    "Window scale shift exceeds 14": "TCP_scale_range",
    "The Content-Length and Transfer-Encoding header must not be set together": "HTTP_content_length_and_chunked",
}


def zeek_weird_name(message: str) -> str:
    """The Zeek weird name for a tshark expert message, else the message's slug."""
    for prefix, name in ZEEK_WEIRD.items():
        if message.startswith(prefix):
            return name
    return _slug(message)


def _slug(message: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", message.lower()).strip("_")[:80]


def _weird_log(ctx: _Ctx) -> LogTable:
    table = LogTable("weird", [("ts", "time"), *ID_COLS, ("name", "string"), ("addl", "string"), ("severity", "string")])
    for row in ctx.runner.run("weird", CHECKSUM_ARGS):
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        key = ctx.row_key(row, proto)
        ts = to_float(first(row, "frame.time_epoch"))
        ids = ctx.ids(key) if key else {}
        # Zeek names bad checksums bad_<PROTO>_checksum; hand them out in header order, outermost first (#209)
        bad = [p.upper() for p in ("ip", "tcp", "udp", "icmp") if first(row, f"{p}.checksum.status") == "0"]
        for message, sev in zip(many(row, "_ws.expert.message"), many(row, "_ws.expert.severity"), strict=False):
            level = _SEVERITY.get(to_int(sev) or 0)
            name = f"bad_{bad.pop(0)}_checksum" if bad and message.startswith("Bad checksum") else zeek_weird_name(message)
            if level:
                table.rows.append({"ts": ts, **ids, "name": name, "addl": message, "severity": level})
    return table


def _expert_log(ctx: _Ctx) -> LogTable:
    table = LogTable("expert", [("ts", "time"), *ID_COLS, ("severity", "string"), ("group", "string"), ("message", "string")])
    for row in ctx.runner.run("weird", CHECKSUM_ARGS):
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        key = ctx.row_key(row, proto)
        ts = to_float(first(row, "frame.time_epoch"))
        ids = ctx.ids(key) if key else {}
        for message, sev, grp in zip(many(row, "_ws.expert.message"), many(row, "_ws.expert.severity"),
                                     many(row, "_ws.expert.group"), strict=False):
            level = _EXPERT_SEVERITY.get(to_int(sev) or 0, f"severity-{to_int(sev) or 0:#x}")
            group = _EXPERT_GROUP.get(to_int(grp) or 0, f"group-{to_int(grp) or 0:#x}")
            table.rows.append({"ts": ts, **ids, "severity": level, "group": group, "message": message})
    table.rows.sort(key=lambda r: (r["ts"] is None, r["ts"] or 0.0))
    return table


_DHCP_TYPES = {"1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE", "5": "ACK", "6": "NAK",
               "7": "RELEASE", "8": "INFORM"}


def _dhcp_log(ctx: _Ctx) -> LogTable:
    table = LogTable("dhcp", [
        ("ts", "time"), ("uids", "set[string]"), ("client_addr", "addr"), ("server_addr", "addr"), ("mac", "string"),
        ("host_name", "string"), ("domain", "string"), ("requested_addr", "addr"), ("assigned_addr", "addr"),
        ("lease_time", "interval"), ("msg_types", "vector[string]"), ("vendor_class", "string")])
    by_xid: dict[str, dict[str, Any]] = {}
    for row in ctx.runner.run("dhcp"):
        xid = first(row, "dhcp.id") or str(len(by_xid))
        t = _DHCP_TYPES.get(first(row, "dhcp.option.dhcp"))
        proto = "udp"
        key = ctx.row_key(row, proto)
        r = by_xid.setdefault(xid, {"ts": to_float(first(row, "frame.time_epoch")), "uids": [], "msg_types": []})
        if key:
            uid = ctx.ids(key)["uid"]
            if uid not in r["uids"]:
                r["uids"].append(uid)
        if t:
            r["msg_types"].append(t)
        client_ip = first(row, "dhcp.ip.client")
        if client_ip and client_ip != "0.0.0.0":
            r["client_addr"] = client_ip
        server = first(row, "dhcp.option.dhcp_server_id")
        if server:
            r["server_addr"] = server
        for src, dst in (("dhcp.hw.mac_addr", "mac"), ("dhcp.option.hostname", "host_name"),
                         ("dhcp.option.domain_name", "domain"), ("dhcp.option.requested_ip_address", "requested_addr"),
                         ("dhcp.option.vendor_class_id", "vendor_class")):
            if first(row, src):
                r[dst] = first(row, src)
        yiaddr = first(row, "dhcp.ip.your")
        if yiaddr and yiaddr != "0.0.0.0" and t in ("ACK", "OFFER"):
            r["assigned_addr"] = r.get("assigned_addr") if t == "OFFER" and "assigned_addr" in r else yiaddr
        lease = to_float(first(row, "dhcp.option.ip_address_lease_time"))
        if lease is not None:
            r["lease_time"] = lease
    table.rows = [r for r in by_xid.values() if r["msg_types"]]
    return table


def _ftp_log(ctx: _Ctx) -> LogTable:
    table = LogTable("ftp", [
        ("ts", "time"), *ID_COLS, ("user", "string"), ("command", "string"), ("arg", "string"),
        ("reply_code", "count"), ("reply_msg", "string")])
    pending: dict[str, dict[str, Any]] = {}
    user: dict[str, str] = {}
    for row in ctx.runner.run("ftp"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        stream = first(row, "tcp.stream") or key
        cmd = first(row, "ftp.request.command")
        code = to_int(first(row, "ftp.response.code"))
        if cmd:
            arg = first(row, "ftp.request.arg")
            if cmd.upper() == "USER":
                user[stream] = arg
            if cmd.upper() == "PASS":
                arg = "<hidden>"
            rec = {"ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key), "user": user.get(stream),
                   "command": cmd, "arg": arg}
            pending[stream] = rec
            table.rows.append(rec)
        elif code is not None and stream in pending and "reply_code" not in pending[stream]:
            pending[stream]["reply_code"] = code
            pending[stream]["reply_msg"] = first(row, "ftp.response.arg")
    return table


def _smtp_log(ctx: _Ctx) -> LogTable:
    table = LogTable("smtp", [
        ("ts", "time"), *ID_COLS, ("trans_depth", "count"), ("helo", "string"), ("mailfrom", "string"),
        ("rcptto", "set[string]"), ("date", "string"), ("from", "string"), ("to", "set[string]"),
        ("subject", "string"), ("msg_id", "string"), ("last_reply", "string")])
    cur: dict[str, dict[str, Any]] = {}
    helo: dict[str, str] = {}
    depth: dict[str, int] = defaultdict(int)

    def clean_addr(v: str) -> str:
        return v.strip().strip("<>").split(":", 1)[-1].strip().strip("<>") if v else v

    for row in ctx.runner.run("smtp"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        stream = first(row, "tcp.stream") or key
        cmd = first(row, "smtp.req.command").upper()
        param = first(row, "smtp.req.parameter")
        code = first(row, "smtp.response.code")
        tx = cur.get(stream)
        if cmd in ("HELO", "EHLO"):
            helo[stream] = param
        elif cmd == "MAIL":
            depth[stream] += 1
            tx = cur[stream] = {"ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
                                "trans_depth": depth[stream], "helo": helo.get(stream), "mailfrom": clean_addr(param),
                                "rcptto": []}
            table.rows.append(tx)
        elif cmd == "RCPT" and tx is not None:
            tx["rcptto"].append(clean_addr(param))
        if first(row, "imf.from") and tx is not None:
            tx["from"] = first(row, "imf.from")
            tx["to"] = many(row, "imf.to") or None
            tx["subject"] = first(row, "imf.subject") or None
            tx["date"] = first(row, "imf.date") or None
            tx["msg_id"] = first(row, "imf.message_id") or None
        if code and tx is not None:
            tx["last_reply"] = f"{code} {first(row, 'smtp.rsp.parameter')}".strip()
    for r in table.rows:
        r["rcptto"] = r["rcptto"] or None
    return table


_SMB2_CMDS = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT", 5: "CREATE",
              6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO",
              14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK"}


def _smb_log(ctx: _Ctx) -> LogTable:
    table = LogTable("smb", [
        ("ts", "time"), *ID_COLS, ("version", "string"), ("command", "string"), ("response", "bool"),
        ("status", "string"), ("tree", "string"), ("filename", "string"), ("username", "string"),
        ("domain", "string"), ("hostname", "string")])
    for row in ctx.runner.run("smb"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        cmds = many(row, "smb2.cmd")
        version = "SMB2" if cmds or first(row, "smb2.sesid") else "SMB1"
        names = [_SMB2_CMDS.get(n, f"CMD_{c}") if (n := to_int(c)) is not None else f"CMD_{c}" for c in cmds] or [
            f"CMD_{c}" for c in many(row, "smb.cmd")]
        responses = many(row, "smb2.flags.response")
        for i, name in enumerate(names or ["?"]):
            table.rows.append({
                "ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key), "version": version, "command": name,
                "response": (responses[i] if i < len(responses) else (responses[0] if responses else "")) in ("1", "True") if responses else None,
                "status": first(row, "smb2.nt_status") or first(row, "smb.nt_status") or None,
                "tree": unc(first(row, "smb2.tree")) or None,
                "filename": unescape(first(row, "smb2.filename") or first(row, "smb.file")) or None,
                "username": first(row, "ntlmssp.auth.username") or None,
                "domain": first(row, "ntlmssp.auth.domain") or None,
                "hostname": first(row, "ntlmssp.auth.hostname") or None,
            })
    return table


_KRB_ERRORS = {6: "KDC_ERR_C_PRINCIPAL_UNKNOWN", 7: "KDC_ERR_S_PRINCIPAL_UNKNOWN", 12: "KDC_ERR_POLICY",
               14: "KDC_ERR_ETYPE_NOSUPP", 18: "KDC_ERR_CLIENT_REVOKED", 23: "KDC_ERR_KEY_EXPIRED",
               24: "KDC_ERR_PREAUTH_FAILED", 25: "KDC_ERR_PREAUTH_REQUIRED", 32: "KRB_AP_ERR_TKT_EXPIRED",
               37: "KRB_AP_ERR_SKEW", 41: "KRB_AP_ERR_MODIFIED", 68: "KDC_ERR_WRONG_REALM"}
_KRB_ETYPES = {1: "des-cbc-crc", 3: "des-cbc-md5", 17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
               19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192", 23: "rc4-hmac"}


def _kerberos_log(ctx: _Ctx) -> LogTable:
    """One row per AS/TGS request, completed by its reply or KRB-ERROR (#205). Names only, never key material."""
    table = LogTable("kerberos", [
        ("ts", "time"), *ID_COLS, ("request_type", "string"), ("client", "string"), ("service", "string"),
        ("success", "bool"), ("error_msg", "string"), ("cipher", "string")])
    pending: dict[str, dict[str, Any]] = {}
    for row in ctx.runner.run("kerberos"):
        msg = to_int(first(row, "kerberos.msg_type"))
        if msg not in (10, 11, 12, 13, 30):
            continue
        key = ctx.row_key(row, "tcp" if first(row, "tcp.srcport") else "udp")
        if not key:
            continue
        realm = first(row, "kerberos.crealm") or first(row, "kerberos.realm")
        cname = first(row, "kerberos.CNameString")
        client = f"{cname}/{realm}" if cname and realm else cname or None
        entry = None if msg in (10, 12) else pending.pop(key, None)
        if entry is None:
            entry = {"ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
                     "request_type": "AS" if msg in (10, 11) else "TGS" if msg in (12, 13) else None,
                     "client": client, "service": "/".join(many(row, "kerberos.SNameString")) or None,
                     "success": None, "error_msg": None, "cipher": None}
            table.rows.append(entry)
        if msg in (10, 12):
            pending[key] = entry
            continue
        entry["client"] = entry["client"] or client
        entry["success"] = msg != 30
        if msg == 30:
            code = to_int(first(row, "kerberos.error_code")) or 0
            entry["error_msg"] = _KRB_ERRORS.get(code, f"KRB_ERROR_{code}")
        elif (etype := to_int(first(row, "kerberos.etype"))) is not None:
            entry["cipher"] = _KRB_ETYPES.get(etype, str(etype))
    return table


def _ntlm_name(value: str) -> str | None:
    return None if value in ("", "NULL") else value


def _ntlm_log(ctx: _Ctx) -> LogTable:
    """One row per NTLM AUTHENTICATE, with the server names from the CHALLENGE before it (#205). No responses."""
    table = LogTable("ntlm", [
        ("ts", "time"), *ID_COLS, ("username", "string"), ("hostname", "string"), ("domainname", "string"),
        ("server_nb_computer_name", "string"), ("server_dns_computer_name", "string"), ("server_tree_name", "string")])
    challenges: dict[str, Row] = {}
    for row in ctx.runner.run("ntlm"):
        key = ctx.row_key(row, "tcp" if first(row, "tcp.srcport") else "udp")
        if not key:
            continue
        types = {to_int(t, 16) for t in many(row, "ntlmssp.messagetype")}
        if 2 in types:
            challenges[key] = row
        if 3 not in types:
            continue
        challenge = challenges.get(key, {})
        table.rows.append({
            "ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
            "username": _ntlm_name(first(row, "ntlmssp.auth.username")),
            "hostname": _ntlm_name(first(row, "ntlmssp.auth.hostname")),
            "domainname": _ntlm_name(first(row, "ntlmssp.auth.domain")),
            "server_nb_computer_name": first(challenge, "ntlmssp.challenge.target_info.nb_computer_name") or None,
            "server_dns_computer_name": first(challenge, "ntlmssp.challenge.target_info.dns_computer_name") or None,
            "server_tree_name": first(challenge, "ntlmssp.challenge.target_name") or None,
        })
    return table


_MODBUS_FUNCS = {1: "READ_COILS", 2: "READ_DISCRETE_INPUTS", 3: "READ_HOLDING_REGISTERS", 4: "READ_INPUT_REGISTERS",
    5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER", 7: "READ_EXCEPTION_STATUS", 8: "DIAGNOSTICS", 11: "GET_COMM_EVENT_COUNTER",
    12: "GET_COMM_EVENT_LOG", 15: "WRITE_MULTIPLE_COILS", 16: "WRITE_MULTIPLE_REGISTERS", 17: "REPORT_SLAVE_ID",
    20: "READ_FILE_RECORD", 21: "WRITE_FILE_RECORD", 22: "MASK_WRITE_REGISTER", 23: "READ_WRITE_MULTIPLE_REGISTERS",
    24: "READ_FIFO_QUEUE", 43: "ENCAP_INTERFACE_TRANSPORT"}
_MODBUS_EXCEPTIONS = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS", 3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE",
    5: "ACKNOWLEDGE", 6: "SLAVE_DEVICE_BUSY", 8: "MEMORY_PARITY_ERROR", 10: "GATEWAY_PATH_UNAVAILABLE",
    11: "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND"}
_DNP3_FUNCS = {0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE", 8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR", 10: "FREEZE_CLEAR_NR", 11: "FREEZE_AT_TIME",
    12: "FREEZE_AT_TIME_NR", 13: "COLD_RESTART", 14: "WARM_RESTART", 15: "INITIALIZE_DATA", 16: "INITIALIZE_APPL",
    17: "START_APPL", 18: "STOP_APPL", 19: "SAVE_CONFIG", 20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS", 23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME", 25: "OPEN_FILE", 26: "CLOSE_FILE",
    27: "DELETE_FILE", 28: "GET_FILE_INFO", 29: "AUTHENTICATE_FILE", 30: "ABORT_FILE", 31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ", 33: "AUTHENTICATE_REQ_NR", 129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP"}


def _modbus_log(ctx: _Ctx) -> LogTable:
    table = LogTable("modbus", [("ts", "time"), *ID_COLS, ("func", "string"), ("exception", "string")])
    for row in ctx.runner.run("modbus"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        dst = to_int(first(row, "tcp.dstport"))
        if dst == 502:
            continue
        code = to_int(first(row, "modbus.func_code"))
        exc = to_int(first(row, "modbus.exception_code"))
        table.rows.append({
            "ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
            "func": _MODBUS_FUNCS.get(code, f"UNKNOWN_{code}") if code is not None else None,
            "exception": _MODBUS_EXCEPTIONS.get(exc, f"UNKNOWN_{exc}") if exc is not None else None,
        })
    return table


def _dnp3_log(ctx: _Ctx) -> LogTable:
    table = LogTable("dnp3", [("ts", "time"), *ID_COLS, ("fc_request", "string"), ("fc_reply", "string"), ("iin", "count")])
    pending: dict[str, dict[str, Any]] = {}
    for row in ctx.runner.run("dnp3"):
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        key = ctx.row_key(row, proto)
        if not key:
            continue
        func = to_int(first(row, "dnp3.al.func"))
        if func is None:
            continue
        if func < 128:
            entry: dict[str, Any] = {"ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
                                     "fc_request": _DNP3_FUNCS.get(func, f"UNKNOWN_{func}"), "fc_reply": None, "iin": None}
            table.rows.append(entry)
            pending[key] = entry
        else:
            entry = pending.pop(key) if key in pending else {
                "ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
                "fc_request": None, "fc_reply": None, "iin": None}
            entry["fc_reply"] = _DNP3_FUNCS.get(func, f"UNKNOWN_{func}")
            iin_raw = first(row, "dnp3.al.iin")
            entry["iin"] = to_int_auto(iin_raw) if iin_raw else None
            if entry["fc_request"] is None:  # a reply whose request is not in the capture
                table.rows.append(entry)
    return table


_TUNNEL_TYPE = {
    "gre": "Tunnel::GRE", "vxlan": "Tunnel::VXLAN", "geneve": "Tunnel::GENEVE", "gtp": "Tunnel::GTPv1",
    "mpls": "Tunnel::MPLS", "erspan": "Tunnel::ERSPAN", "pppoes": "Tunnel::PPPOE", "vlan": "VLAN",
}

#: The tunnel_id field for each tunnel type, in priority order for GRE (which has none -> empty).
_TUNNEL_ID_FIELD = {
    "vxlan": "vxlan.vni", "geneve": "geneve.vni", "gtp": "gtp.teid", "mpls": "mpls.label",
    "erspan": "erspan.spanid", "pppoes": "pppoe.session_id", "vlan": "vlan.id",
}


def _tunnel_log(ctx: _Ctx) -> LogTable:
    """Zeek ``tunnel.log``: one row per distinct encapsulation seen at its outer endpoints (#227)."""
    table = LogTable("tunnel", [("ts", "time"), *ID_COLS, ("tunnel_type", "string"), ("action", "string"), ("tunnel_id", "string")])
    seen: set[tuple[str, str, int, str, int, str]] = set()
    for row in ctx.runner.run("tunnel"):
        protocols = (first(row, "frame.protocols") or "").split(":")
        tunnel_type = None
        tunnel_field = None
        for layer in protocols:
            mapped = _TUNNEL_TYPE.get(layer)
            if mapped:
                tunnel_type = mapped
                tunnel_field = _TUNNEL_ID_FIELD.get(layer)
                break
        if tunnel_type is None:
            continue
        ts = to_float(first(row, "frame.time_epoch"))
        if ts is None:
            continue
        outer_orig = first(row, "ip.src") or first(row, "ipv6.src")
        outer_resp = first(row, "ip.dst") or first(row, "ipv6.dst")
        if not outer_orig or not outer_resp:
            continue
        # outer ports: the first UDP ports when the tunnel rides on UDP (a `udp`
        # layer appears before the tunnel layer), else 0. GRE's own payload may
        # carry an inner UDP that is NOT the outer transport.
        tunnel_idx = protocols.index(layer)
        on_udp = "udp" in protocols[:tunnel_idx]
        outer_orig_p = to_int(first(row, "udp.srcport")) or 0 if on_udp and first(row, "udp.srcport") else 0
        outer_resp_p = to_int(first(row, "udp.dstport")) or 0 if on_udp and first(row, "udp.dstport") else 0
        tunnel_id = first(row, tunnel_field) if tunnel_field else ""
        # id.orig/resp come from the outer 4-tuple; find the outer conn uid when one exists.
        proto = "udp" if on_udp else "gre"
        key = flow_key(proto, outer_orig, outer_orig_p, outer_resp, outer_resp_p)
        ids = ctx.ids(key)
        sig = (tunnel_type, ids["id.orig_h"], ids["id.orig_p"], ids["id.resp_h"], ids["id.resp_p"], tunnel_id)
        if sig in seen:
            continue
        seen.add(sig)
        table.rows.append({
            "ts": ts, **ids, "tunnel_type": tunnel_type, "action": "Tunnel::DISCOVER", "tunnel_id": tunnel_id or None,
        })
    table.rows.sort(key=lambda r: (r["ts"] is None, r["ts"] or 0.0))
    return table


def _device_log(ctx: _Ctx) -> LogTable:
    """Zeek-style ``device.log`` (an extension; Zeek's known_devices is similar).

    One row per distinct sender MAC: first-seen time, OUI vendor, distinct IPs,
    and packet count.
    """
    table = LogTable("device", [("ts", "time"), ("mac", "string"), ("vendor", "string"),
                                ("ips", "set[string]"), ("packets", "count")])
    # mac -> {"ts": float, "vendor": str | None, "ips": set[str], "packets": int}
    devs: dict[str, dict[str, Any]] = {}
    for row in ctx.runner.run("device"):
        mac = first(row, "eth.src")
        if not mac:
            continue
        mac = mac.lower()
        ts = to_float(first(row, "frame.time_epoch"))
        ip = first(row, "ip.src") or first(row, "ipv6.src")
        oui = first(row, "eth.src.oui_resolved")
        resolved = first(row, "eth.src_resolved")
        vendor = _resolve_vendor(oui, resolved, mac)
        info = devs.get(mac)
        if info is None:
            info = {"ts": ts, "vendor": vendor, "ips": set(), "packets": 0}
            devs[mac] = info
        if ts is not None and (info["ts"] is None or ts < info["ts"]):
            info["ts"] = ts
        if ip:
            info["ips"].add(ip)
        info["packets"] += 1
    for mac, info in devs.items():
        table.rows.append({
            "ts": info["ts"], "mac": mac, "vendor": info["vendor"],
            "ips": sorted(info["ips"]), "packets": info["packets"],
        })
    table.rows.sort(key=lambda r: (r["ts"] is None, r["ts"] or 0.0))
    return table


def capture_loss_stats(rows: list[Row]) -> tuple[int, int, int | None]:
    """Aggregate a ``capture_loss`` pass into (acks, gaps, first_gap_frame).

    * ``acks`` is the number of ACK rows seen.
    * ``gaps`` is the number of segments that arrive after a hole in their own stream (tshark's
      ``tcp.analysis.lost_segment``): data was captured on both sides of the hole, so it is real
      mid-stream loss. ACKs of data never seen at all (``ack_lost_segment``) are not counted: they
      are what any capture that starts mid-connection looks like.
    * ``first_gap_frame`` is the frame number of the first such segment, or ``None``.
    """
    acks = len(rows)
    gaps = 0
    first_gap_frame: int | None = None
    for row in rows:
        if first(row, "tcp.analysis.lost_segment"):
            gaps += 1
            if first_gap_frame is None:
                first_gap_frame = to_int(first(row, "frame.number"))
    return acks, gaps, first_gap_frame


def _capture_loss_log(ctx: _Ctx) -> LogTable:
    """Zeek-style capture_loss.log: ACKs, gaps (segments after a mid-stream hole) and percent lost (issue #240)."""
    rows = ctx.runner.run("capture_loss")
    acks, gaps, _first_gap_frame = capture_loss_stats(rows)
    rows_sorted = sorted(rows, key=lambda r: (to_int(first(r, "frame.number")) or 0))
    ts = to_float(first(rows_sorted[0], "frame.time_epoch")) if rows_sorted else None
    table = LogTable(
        "capture_loss",
        [("ts", "time"), ("acks", "count"), ("gaps", "count"), ("percent_lost", "double")],
        rows=[{"ts": ts, "acks": acks, "gaps": gaps, "percent_lost": round(100 * gaps / acks, 1) if acks else 0.0}],
    )
    return table


def _resolve_vendor(oui_resolved: str | None, src_resolved: str | None, mac: str) -> str | None:
    """Pick a vendor string for a MAC.

    * eth.src.oui_resolved when non-empty;
    * else eth.src_resolved when it is not the MAC itself: the part before the
      last ``_`` (e.g. ``"Google_aa:bb:01"`` -> ``"Google"``);
    * else None.
    """
    if oui_resolved:
        return oui_resolved
    if src_resolved and src_resolved != mac:
        idx = src_resolved.rfind("_")
        if idx > 0:
            return src_resolved[:idx]
    return None


def _parse_http_version(value: str) -> tuple[str | None, str | None]:
    """HTTP 'Name/Version rest' -> (name, version).

    No '/' -> name is the whole value (stripped), version is None.
    """
    if not value:
        return None, None
    value = value.strip()
    if not value:
        return None, None
    if "/" not in value:
        return value, None
    name, rest = value.split("/", 1)
    # version stops at the first space or "("
    version_str = rest
    for marker in (" ", "("):
        idx = version_str.find(marker)
        if idx != -1:
            version_str = version_str[:idx]
    version_str = version_str.strip()
    version = version_str or None
    return name.strip() or None, version


def _parse_ssh_version(value: str) -> tuple[str | None, str | None]:
    """SSH 'SSH-2.0-<software>' -> (name, version).

    software 'OpenSSH_7.4' -> name 'OpenSSH', version '7.4' (split on first '_').
    No '_' -> name = software, version None.
    """
    if not value:
        return None, None
    value = value.strip()
    # "SSH-<protoversion>-<softwareversion> <comments>": drop the prefix, stop at the comments.
    parts = value.split("-", 2)
    software = parts[2] if len(parts) == 3 and parts[0] == "SSH" else value
    software = software.split(" ", 1)[0]
    if not software:
        return None, None
    if "_" not in software:
        head, dash, tail = software.rpartition("-")  # Cisco-1.25
        if dash and head and tail[:1].isdigit():
            return head, tail
        return software, None
    name, version = software.split("_", 1)
    return name or None, version or None


def _software_log(ctx: _Ctx) -> LogTable:
    """Zeek-style ``software.log``: versioned software from HTTP Server / User-Agent headers and SSH banners."""
    table = LogTable("software", [
        ("ts", "time"), ("host", "addr"), ("host_p", "port"), ("software_type", "string"),
        ("name", "string"), ("version", "string"), ("unparsed_version", "string")])
    # key -> {"ts": float|None, "software_type": str, "name": str|None, "version": str|None, "unparsed_version": str}
    seen: dict[tuple[str, int | None, str, str], dict[str, Any]] = {}
    for row in ctx.runner.run("software"):
        ts = to_float(first(row, "frame.time_epoch"))
        src = first(row, "ip.src") or first(row, "ipv6.src")
        srcport = to_int(first(row, "tcp.srcport"))
        dstport = to_int(first(row, "tcp.dstport"))
        if not src:
            continue
        server = first(row, "http.server")
        agent = first(row, "http.user_agent")
        banner = first(row, "ssh.protocol")
        entries: list[tuple[str, str, str | None, str | None, str]] = []
        if server:
            name, version = _parse_http_version(server)
            entries.append(("HTTP::SERVER", server, name, version, server))
        if agent:
            name, version = _parse_http_version(agent)
            entries.append(("HTTP::BROWSER", agent, name, version, agent))
        if banner:
            name, version = _parse_ssh_version(banner)
            # Determine server vs client: the side whose tcp.srcport is lower / is 22 is the server.
            if srcport is not None and dstport is not None:
                stype = "SSH::SERVER" if srcport == 22 or srcport < dstport else "SSH::CLIENT"
            elif srcport == 22:
                stype = "SSH::SERVER"
            else:
                stype = "SSH::CLIENT"
            entries.append((stype, banner, name, version, banner))
        for stype, unparsed, name, version, raw in entries:
            # Client sides have no port: they are the originator behind NAT / a shared address.
            # host_p is None for HTTP::BROWSER and SSH::CLIENT; otherwise the src port.
            is_client = stype in ("HTTP::BROWSER", "SSH::CLIENT")
            host_p = None if is_client else srcport
            key = (src, host_p, stype, unparsed)
            info = seen.get(key)
            if info is None:
                info = {"ts": ts, "software_type": stype, "name": name, "version": version,
                        "unparsed_version": raw}
                seen[key] = info
            elif ts is not None and (info["ts"] is None or ts < info["ts"]):
                info["ts"] = ts
    for (host, host_p, _stype, _unparsed), info in sorted(seen.items(), key=lambda kv: (kv[1]["ts"] is None, kv[1]["ts"] or 0.0, kv[0][0])):
        table.rows.append({
            "ts": info["ts"], "host": host, "host_p": host_p,
            "software_type": info["software_type"], "name": info["name"], "version": info["version"],
            "unparsed_version": info["unparsed_version"],
        })
    return table


def _protocols_log(ctx: _Ctx) -> LogTable:
    """Protocol hierarchy breakdown: frames and bytes per protocol layer (issue #279)."""
    table = LogTable("protocols", [("protocol", "string"), ("frames", "count"), ("bytes", "count"), ("percent_frames", "double")])
    counts: dict[str, list[int]] = {}  # protocol -> [frames, bytes]
    total_frames = 0
    for row in ctx.runner.run("protocols"):
        protocols = (first(row, "frame.protocols") or "").split(":")
        layers = set(protocols) - {"ethertype", ""}
        length = to_int(first(row, "frame.len")) or 0
        total_frames += 1
        for layer in layers:
            entry = counts.setdefault(layer, [0, 0])
            entry[0] += 1
            entry[1] += length
    for protocol, (frames, byte_count) in counts.items():
        percent = round(100 * frames / total_frames, 1) if total_frames else 0.0
        table.rows.append({"protocol": protocol, "frames": frames, "bytes": byte_count, "percent_frames": percent})
    table.rows.sort(key=lambda r: (-r["frames"], r["protocol"]))
    return table


def _conversations_log(ctx: _Ctx) -> LogTable:
    """Per IP-pair frame/byte/duration summary, both directions together (issues #248)."""
    table = LogTable("conversations", [("a", "addr"), ("b", "addr"), ("frames", "count"),
                                       ("bytes", "count"), ("first_ts", "time"), ("duration", "interval")])
    agg: dict[tuple[str, str], list[Any]] = {}  # (a, b) -> [frames, bytes, min_epoch, max_epoch]
    for row in ctx.runner.run("frames"):
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        if not src or not dst:
            continue
        a, b = sorted((src, dst))
        length = to_int(first(row, "frame.len")) or 0
        epoch = to_float(first(row, "frame.time_epoch"))
        entry = agg.setdefault((a, b), [0, 0, None, None])
        entry[0] += 1
        entry[1] += length
        if epoch is not None:
            if entry[2] is None or epoch < entry[2]:
                entry[2] = epoch
            if entry[3] is None or epoch > entry[3]:
                entry[3] = epoch
    for (a, b), (frames, byte_count, first_epoch, last_epoch) in agg.items():
        duration = round(last_epoch - first_epoch, 6) if first_epoch is not None and last_epoch is not None else 0.0
        table.rows.append({"a": a, "b": b, "frames": frames, "bytes": byte_count,
                           "first_ts": first_epoch, "duration": duration})
    table.rows.sort(key=lambda r: (-r["bytes"], r["a"], r["b"]))
    return table


def _io_log(ctx: _Ctx) -> LogTable:
    """Frames and bytes per one-second bucket (issue #249, like Wireshark's IO graph)."""
    table = LogTable("io", [("offset", "count"), ("ts", "time"), ("frames", "count"), ("bytes", "count")])
    buckets: dict[int, list[Any]] = {}  # offset -> [frames, bytes, first_epoch]
    for row in ctx.runner.run("frames"):
        relative = to_float(first(row, "frame.time_relative"))
        if relative is None:
            continue
        offset = int(relative)
        length = to_int(first(row, "frame.len")) or 0
        epoch = to_float(first(row, "frame.time_epoch"))
        entry = buckets.setdefault(offset, [0, 0, None])
        entry[0] += 1
        entry[1] += length
        if epoch is not None and (entry[2] is None or epoch < entry[2]):
            entry[2] = epoch
    for offset, (frames, byte_count, first_epoch) in sorted(buckets.items()):
        table.rows.append({"offset": offset, "ts": first_epoch, "frames": frames, "bytes": byte_count})
    return table


BUILDERS: dict[str, Callable[[_Ctx], LogTable]] = {
    "conn": _conn_log, "dns": _dns_log, "http": _http_log, "ssl": _ssl_log, "x509": _x509_log, "files": _files_log,
    "notice": _notice_log, "weird": _weird_log, "expert": _expert_log, "dhcp": _dhcp_log, "ftp": _ftp_log, "smtp": _smtp_log,
    "ssh": _ssh_log, "smb": _smb_log, "kerberos": _kerberos_log, "ntlm": _ntlm_log,
    "modbus": _modbus_log, "dnp3": _dnp3_log, "tunnel": _tunnel_log,
    "device": _device_log, "software": _software_log, "protocols": _protocols_log, "capture_loss": _capture_loss_log,
    "conversations": _conversations_log, "io": _io_log,
}
LOG_NAMES = tuple(BUILDERS)


def build_logs(index: CaptureIndex, names: tuple[str, ...] = ()) -> dict[str, LogTable]:
    unknown = [n for n in names if n not in BUILDERS]
    if unknown:
        raise ValueError(f"unknown log(s) {', '.join(unknown)}; logs: {', '.join(LOG_NAMES)}")
    ctx = _Ctx(index)
    return {n: BUILDERS[n](ctx) for n in (names or LOG_NAMES)}


#: Cached per index: the sources registered with the query language build a table once per run.
def log_rows(index: CaptureIndex, name: str) -> list[dict[str, Any]]:
    return build_logs(index, (name,))[name].rows


# ---------------------------------------------------------------------------- writers
def _tsv_value(value: Any, ztype: str) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "T" if value else "F"
    if isinstance(value, list):
        text = ",".join(str(v) for v in value)
        return text or "(empty)"
    if ztype in ("time", "interval") and isinstance(value, float):
        return f"{value:.6f}"
    text = clean_capture_text(str(value), 2000)
    # the field separator and the set separator must not occur inside a value
    text = text.replace(",", "\\x2c") if ztype.startswith(("set", "vector")) else text
    return text if text != "" else "(empty)"


def write_tsv(table: LogTable, outdir: Path, first_ts: float, last_ts: float) -> Path:
    from datetime import UTC, datetime

    def stamp(t: float) -> str:
        return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d-%H-%M-%S")

    path = outdir / f"{table.name}.log"
    lines = [
        "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", f"#path\t{table.name}",
        f"#open\t{stamp(first_ts)}", "#fields\t" + "\t".join(n for n, _ in table.columns),
        "#types\t" + "\t".join(t for _, t in table.columns),
    ]
    for row in table.rows:
        lines.append("\t".join(_tsv_value(row.get(n), t) for n, t in table.columns))
    lines.append(f"#close\t{stamp(last_ts)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _json_value(value: Any) -> Any:
    return clean_capture_text(value, 2000) if isinstance(value, str) else value


def write_json(table: LogTable, outdir: Path) -> Path:
    path = outdir / f"{table.name}.json.log"
    with path.open("w", encoding="utf-8") as fh:
        for row in table.rows:
            fh.write(json.dumps({n: _json_value(row[n]) for n, _ in table.columns if row.get(n) is not None},
                                ensure_ascii=False) + "\n")
    return path


def write_logs(tables: dict[str, LogTable], outdir: Path, fmt: str, first_ts: float, last_ts: float) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for table in tables.values():
        if fmt in ("tsv", "both"):
            written.append(write_tsv(table, outdir, first_ts, last_ts))
        if fmt in ("json", "both"):
            written.append(write_json(table, outdir))
    return written


def register_query_sources() -> None:
    """Make every log table queryable (``query CAPTURE EXPR -s conn``)."""
    from .query import SOURCES

    for name in LOG_NAMES:
        SOURCES.setdefault(f"log:{name}", partial(log_rows, name=name))
