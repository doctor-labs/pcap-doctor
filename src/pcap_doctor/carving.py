"""Per-frame magic-byte carving of raw packet payloads (issue #216).

``scan_payload`` looks for every file signature in the existing ``filetypes.MAGIC`` table inside one
blob of raw payload bytes and reports, per signature, the MIME name and the byte offset where it
occurred; ``carve`` runs it over the payload bytes of every packet in a capture (the tshark
``payload`` pass, which carries both ``tcp.payload`` and ``udp.payload``), so reassembled streams are
not a precondition and UDP datagrams are carved too. The offsets are where the magic bytes sit in the
payload, so a hit at offset 0 is a payload that *is* the file, while a hit at offset 2 is a file buried
two bytes in (as the tests pin down with tshark-verified hand-built captures).

This is a library function: it returns structured hits, it creates no findings, and nothing in the
report pipeline touches it. Callers that want to carve from disk reassembled streams (issue #216's
rest) keep those bytes and call ``scan_payload`` directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from .filetypes import MAGIC
from .index import CaptureIndex, first
from .tshark import to_int


@dataclass(frozen=True)
class CarveHit:
    frame: int  # the packet the payload came from
    signature: str  # the MIME name from the MAGIC table entry that matched
    offset: int  # byte offset of the magic bytes inside the payload
    protocol: str  # "tcp" or "udp"


def scan_payload(payload: bytes) -> list[tuple[str, int]]:
    """Every ``(MIME type, byte offset)`` pair at which a ``MAGIC`` signature occurs in ``payload``.

    Offset-0 signatures are searched anywhere in the payload (their leftmost occurrence is the one
    reported); fixed-offset entries, like ``ustar`` at 257, are checked at exactly that offset, as
    ``filetypes.sniff`` does. A payload shorter than the signature never matches and never raises.
    """
    hits: list[tuple[str, int]] = []
    for offset, sig, mime in MAGIC:
        pos = payload.find(sig) if offset == 0 else (offset if payload[offset : offset + len(sig)] == sig else -1)
        if pos >= 0 and (mime, pos) not in hits:
            hits.append((mime, pos))
    return hits


def carve(index: CaptureIndex) -> list[CarveHit]:
    """Carve the raw payload bytes of every packet in ``index``.

    Needs an index built by ``IndexBuilder`` (it carries the tshark runner); scans the ``payload``
    pass, which lists every TCP/UDP payload of the capture. No payload, no hit; undecodable payload
    hex is skipped, never guessed.
    """
    if index.runner is None:
        return []
    out: list[CarveHit] = []
    for row in index.runner.run("payload"):
        frame = to_int(first(row, "frame.number")) or 0
        protocol = "tcp" if first(row, "tcp.srcport") else "udp"
        field = "tcp.payload" if protocol == "tcp" else "udp.payload"
        raw = first(row, field)
        if not raw:
            continue
        try:
            data = bytes.fromhex(raw.replace(":", ""))
        except ValueError:
            continue
        for signature, offset in scan_payload(data):
            out.append(CarveHit(frame, signature, offset, protocol))
    return out
