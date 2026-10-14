"""Cut a subset capture out of a classic pcap by host, frame numbers or flow.

Frames are copied byte for byte and keep their timestamps and the input's link type. Only
Ethernet/IPv4 TCP and UDP frames can match a host or flow selector; any other frame is never
selected by those, but ``frame=`` selects by position and so works for every frame.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

# (magic as read little-endian) -> struct byte order. Nanosecond variants share the layout.
_ORDERS = {0xA1B2C3D4: "<", 0xA1B23C4D: "<", 0xD4C3B2A1: ">", 0x4D3CB2A1: ">"}
Endpoint = tuple[str, int]


@dataclass
class SliceResult:
    frames: list[int]  # 1-based frame numbers written, in output order
    total_frames: int  # frames in the input
    path: Path


def _read(src: Path) -> tuple[str, bytes, list[tuple[bytes, bytes]]]:
    """(byte order, 24-byte global header, [(16-byte record header, frame bytes)])."""
    raw = Path(src).read_bytes()
    if len(raw) < 24:
        raise ValueError(f"{src} is not a pcap capture")
    order = _ORDERS.get(struct.unpack("<I", raw[:4])[0])
    if order is None:
        raise ValueError(f"{src} is not a classic pcap capture")
    records, pos = [], 24
    while pos + 16 <= len(raw):
        incl = struct.unpack(order + "I", raw[pos + 8 : pos + 12])[0]
        if pos + 16 + incl > len(raw):
            break  # truncated final record: drop it
        records.append((raw[pos : pos + 16], raw[pos + 16 : pos + 16 + incl]))
        pos += 16 + incl
    return order, raw[:24], records


def _endpoints(frame: bytes) -> tuple[Endpoint, Endpoint] | None:
    """(source, destination) of an Ethernet/IPv4 TCP or UDP frame, else None."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        return None
    ihl = (frame[14] & 0x0F) * 4
    l4 = 14 + ihl
    proto = frame[23]
    if ihl < 20 or proto not in (6, 17) or len(frame) < l4 + 4:
        return None
    sport, dport = struct.unpack("!HH", frame[l4 : l4 + 4])
    src, dst = ".".join(map(str, frame[26:30])), ".".join(map(str, frame[30:34]))
    return (src, sport), (dst, dport)


def _parse_flow(flow: str) -> set[Endpoint]:
    """``a.b.c.d:port-e.f.g.h:port`` -> its two endpoints (direction does not matter)."""
    try:
        ends = set()
        for side in flow.split("-"):
            ip, port = side.rsplit(":", 1)
            ends.add((ip, int(port)))
        if len(ends) == 2:
            return ends
    except ValueError:
        pass
    raise ValueError(f"flow must look like 10.0.0.1:40000-10.0.0.2:80, got {flow!r}")


def slice_capture(
    src: Path,
    dst: Path,
    *,
    host: str | None = None,
    frame: list[int] | None = None,
    flow: str | None = None,
) -> SliceResult:
    """Write the selected frames of ``src`` to ``dst``; exactly one selector is required."""
    if sum(x is not None for x in (host, frame, flow)) != 1:
        raise ValueError("exactly one of host, frame, flow is required")
    _, header, records = _read(src)
    total = len(records)
    if frame is not None:
        for n in frame:
            if not 1 <= n <= total:
                raise ValueError(f"frame {n} is not in a capture of {total} frames")
        picked = list(frame)
    else:
        want = _parse_flow(flow) if flow is not None else set()
        picked = []
        for i, (_, data) in enumerate(records, 1):
            ends = _endpoints(data)
            if ends is None:
                continue
            if (host is not None and host in (ends[0][0], ends[1][0])) or (
                flow is not None and set(ends) == want
            ):
                picked.append(i)
        if flow is not None and not picked:
            raise ValueError(f"no flow {flow} in this capture")
    out = Path(dst)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(header + b"".join(records[i - 1][0] + records[i - 1][1] for i in picked))
    return SliceResult(frames=picked, total_frames=total, path=out)
