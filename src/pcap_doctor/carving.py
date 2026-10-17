"""Magic-byte carving of packet and stream payloads (issue #216).

``scan_payload`` looks for every file signature in the existing ``filetypes.MAGIC`` table inside one
blob of payload bytes and reports, per signature, the MIME name and the byte offset where it occurred.
``carve_runner`` runs it over the payload of every packet (the tshark ``payload`` pass, which carries
``tcp.payload`` and ``udp.payload``), so UDP is carved too and no reassembly is needed. ``carve_streams``
runs it over the reassembled payload of each TCP stream and direction, so a file split across segments
is found whole. ``write_hits`` extracts the carved bytes to a directory.

Carved bytes are untrusted: they are written 0600, under names built from integers and a fixed extension,
and never opened or executed.
"""

from __future__ import annotations

import mimetypes
import re
from dataclasses import dataclass, field
from pathlib import Path

from .filetypes import MAGIC
from .follow import follow, list_streams
from .index import CaptureIndex, first
from .tshark import TsharkRunner, to_int


@dataclass(frozen=True)
class CarveHit:
    frame: int  # the packet the payload came from; 0 for a stream hit
    signature: str  # the MIME name from the MAGIC table entry that matched
    offset: int  # byte offset of the magic bytes inside the payload
    protocol: str  # "tcp" or "udp"
    payload: bytes = field(default=b"", repr=False, compare=False)  # the blob the hit was found in
    stream: int | None = None  # tshark TCP stream number, for a stream hit
    direction: str = ""  # "c2s" or "s2c", for a stream hit


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
    return carve_runner(index.runner)


def carve_runner(runner: TsharkRunner) -> list[CarveHit]:
    """``carve`` without the full index: the CLI only needs the payload pass, not every pass."""
    out: list[CarveHit] = []
    for row in runner.run("payload"):
        frame = to_int(first(row, "frame.number")) or 0
        protocol = "tcp" if first(row, "tcp.srcport") else "udp"
        field_name = "tcp.payload" if protocol == "tcp" else "udp.payload"
        raw = first(row, field_name)
        if not raw:
            continue
        try:
            data = bytes.fromhex(raw.replace(":", ""))
        except ValueError:
            continue
        for signature, offset in scan_payload(data):
            out.append(CarveHit(frame, signature, offset, protocol, data))
    return out


def carve_streams(pcap: Path) -> list[CarveHit]:
    """Carve each TCP stream's reassembled payload, one direction at a time.

    One tshark ``follow`` per TCP stream, so this is slow on captures with many streams. A file whose
    magic or body crosses a segment boundary is found here, unlike with ``carve_runner``.
    """
    out: list[CarveHit] = []
    for info in list_streams(pcap, "tcp"):
        stream = follow(pcap, "tcp", info.index)
        for to_client, label in ((False, "c2s"), (True, "s2c")):
            data = b"".join(seg.data for seg in stream.segments if seg.to_client == to_client)
            for signature, offset in scan_payload(data):
                out.append(CarveHit(0, signature, offset, "tcp", data, info.index, label))
    return out


def extension_for(signature: str) -> str:
    """A file extension for a MIME name; anything unusual or unknown becomes ``.bin``."""
    ext = mimetypes.guess_extension(signature) or ""
    return ext if re.fullmatch(r"\.[a-z0-9]{1,8}", ext) else ".bin"


def write_hits(hits: list[CarveHit], outdir: Path) -> list[Path]:
    """Write each hit's bytes, from its offset to the end of its payload, into ``outdir``.

    Names are ``frame<N>-<offset>.<ext>`` for packet hits and ``stream<N>-<dir>-<offset>.<ext>`` for stream
    hits, so the names are built from integers and a checked extension, never from capture text. Existing
    files are never overwritten (a ``-<n>`` suffix is added). Each written path is re-checked to sit directly
    inside ``outdir``.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    root = outdir.resolve()
    written: list[Path] = []
    for hit in hits:
        stem = (f"stream{hit.stream}-{hit.direction}-{hit.offset}" if hit.stream is not None
                else f"frame{hit.frame}-{hit.offset}")
        ext = extension_for(hit.signature)
        dest = root / f"{stem}{ext}"
        n = 1
        while dest.exists():
            dest = root / f"{stem}-{n}{ext}"
            n += 1
        if dest.parent != root:
            raise ValueError(f"refusing to write outside {root}: {dest}")
        dest.write_bytes(hit.payload[hit.offset:])
        dest.chmod(0o600)
        written.append(dest)
    return written
