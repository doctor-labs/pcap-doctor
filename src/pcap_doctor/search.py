"""Keyword / byte-pattern search across packet payloads (issue #215).

``search_payloads`` runs one on-demand tshark pass over the capture, reassembling TCP payloads and
reading UDP ``data`` payloads per frame, then reports every offset where a byte pattern occurs.
It is the extraction command, not a detector: it produces no findings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .ondemand import run_fields

#: One tshark -T fields pass (occurrence=a): reassembled per frame, hex-lowered, tab separated.
_FIELDS = (
    "frame.number",
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.payload",
    "udp.srcport",
    "udp.dstport",
    "udp.payload",
)
# Column indices into run_fields rows for the fields above.
(
    _FRAME,
    _PROTO_STACK,
    _IPSRC,
    _IP6SRC,
    _IPDST,
    _IP6DST,
    _TCP_SPORT,
    _TCP_DPORT,
    _TCP_PAY,
    _UDP_SPORT,
    _UDP_DPORT,
    _UDP_PAY,
) = range(12)


@dataclass
class Match:
    frame: int
    proto: str  # "tcp" | "udp"
    src: str
    dst: str
    sport: int
    dport: int
    direction: str  # "client->server" | "server->client"
    offset: int
    length: int
    snippet: bytes  # raw matching bytes; hex in JSON, never interpreted as text


def _addr(row: list[str], lo: int, hi: int) -> str:
    return row[lo] or row[hi]


def search_payloads(pcap: Path, pattern: bytes) -> list[Match]:
    """Find every occurrence of ``pattern`` in TCP/UDP payload bytes, one :class:`Match` per offset.

    ``pattern`` is matched literally as bytes; the CLI layer decodes a user literal or hex string into it.
    A frame may produce several matches (a pattern that repeats). Results are ordered by frame, then offset.
    """
    if not pattern:
        raise ValueError("search pattern is empty")
    rows = run_fields(pcap, list(_FIELDS), "tcp.payload || udp.payload")
    out: list[Match] = []
    for r in rows:
        if not r[_FRAME].lstrip("-").isdigit():
            continue
        frame = int(r[_FRAME])
        is_tcp = bool(r[_TCP_PAY])
        if is_tcp:
            payload_hex = r[_TCP_PAY]
            proto = "tcp"
            sport = int(r[_TCP_SPORT]) if r[_TCP_SPORT] else 0
            dport = int(r[_TCP_DPORT]) if r[_TCP_DPORT] else 0
        else:
            payload_hex = r[_UDP_PAY]
            proto = "udp"
            sport = int(r[_UDP_SPORT]) if r[_UDP_SPORT] else 0
            dport = int(r[_UDP_DPORT]) if r[_UDP_DPORT] else 0
        src, dst = _addr(r, _IPSRC, _IP6SRC), _addr(r, _IPDST, _IP6DST)
        # Direction is a heuristic: the side on a well-known port (<=1024) is "server".
        direction = "client->server" if _is_server_port(dport) else "server->client"
        payload = bytes.fromhex(payload_hex) if payload_hex else b""
        start = 0
        while True:
            at = payload.find(pattern, start)
            if at < 0:
                break
            out.append(
                Match(
                    frame=frame,
                    proto=proto,
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    direction=direction,
                    offset=at,
                    length=len(pattern),
                    snippet=payload[at : at + len(pattern)],  # the matched bytes themselves (hex in JSON)
                )
            )
            start = at + 1
    out.sort(key=lambda m: (m.frame, m.offset))
    return out


def _is_server_port(port: int) -> bool:
    """Heuristic: a listener on a well-known port (<=1024) is the server side of a flow."""
    return port <= 1024


def match_to_dict(m: Match) -> dict[str, object]:
    """JSON shape: raw bytes surfaced as hex (JSON has no markup, so backticks are not stripped)."""
    d = asdict(m)
    d["snippet"] = m.snippet.hex()
    return d
