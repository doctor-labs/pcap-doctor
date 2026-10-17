"""RDP reconstruction: typed keys and the screen from bitmap updates, when the session is readable (issue #217).

Works on the reassembled byte streams of one TCP connection. The X.224 negotiation names the security layer. A
session negotiated to TLS, CredSSP or RDSTLS is encrypted from the first byte after the negotiation: its keys are
not in the capture, so nothing in it is rebuilt and the reason is recorded. A plain (Standard RDP security) session
carries fast-path input PDUs (keys) and fast-path output PDUs (bitmap updates) in the clear. Only uncompressed 16-
and 32-bit bitmaps in single-fragment updates are drawn; compressed bitmaps, fragments and surface commands are
recorded as notes. The keyboard layout is not in the capture, so US QWERTY is assumed.

Constants marked [V] were checked against the value strings of tshark's RDP dissector. Constants marked [U] were
not checked against a source on this machine: verify them against MS-RDPBCGR before relying on them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .ondemand import run_fields
from .tshark import TsharkRunError
from .vnc import _Cursor, encode_png

RDP_PORT = 3389
X224_CR, X224_CC = 0xE0, 0xD0  # [U] X.224 connection request and confirm codes
NEG_REQ, NEG_RSP, NEG_FAILURE = 0x01, 0x02, 0x03  # [V] rdp.neg_type
PROTOCOLS = {  # [V] rdp.negReq.selectedProtocol
    0x0: "Standard RDP security", 0x1: "TLS", 0x2: "CredSSP", 0x4: "RDSTLS",
    0x8: "CredSSP with early user authorization", 0x10: "RDS AAD auth",
}
EV_SCANCODE, EV_MOUSE, EV_MOUSEX, EV_SYNC, EV_UNICODE, EV_RELMOUSE = 0, 1, 2, 3, 4, 5  # [V] input event codes
EVENT_BODY = {EV_MOUSE: 6, EV_MOUSEX: 6, EV_SYNC: 0, EV_RELMOUSE: 4}  # [U] fixed body sizes of the other events
UPD_BITMAP, UPD_SURFACE = 1, 4  # [V] server update codes
FRAG_SINGLE = 0  # [V] rdp.fastpath.serverfragmentation
KBD_RELEASE, KBD_EXTENDED = 0x01, 0x02  # [U] keyboard event flags
COMPRESSION_USED = 0x2  # [U] compression bits of the update header
BITMAP_COMPRESSED = 0x0001  # [U] TS_BITMAP_DATA flags
MAX_PIXELS = 16 * 1024 * 1024

NAMED = {0x01: "<ESC>", 0x0E: "<BS>", 0x0F: "<TAB>", 0x1C: "<RET>"}
EXT_NAMED = {0x1C: "<RET>", 0x47: "<HOME>", 0x48: "<UP>", 0x49: "<PGUP>", 0x4B: "<LEFT>", 0x4D: "<RIGHT>",
             0x4F: "<END>", 0x50: "<DOWN>", 0x51: "<PGDN>", 0x52: "<INS>", 0x53: "<DEL>"}
MODIFIERS = {0x2A, 0x36, 0x1D, 0x38, 0x3A, 0x5B, 0x5C}  # shift, ctrl, alt, caps lock, win: no text of their own


def _us_layout() -> dict[int, tuple[str, str]]:
    # ponytail: caps lock is ignored; add it when a capture shows it matters.
    rows = {
        0x02: ("1234567890-=", "!@#$%^&*()_+"),
        0x10: ("qwertyuiop[]", "QWERTYUIOP{}"),
        0x1E: ("asdfghjkl;'`", 'ASDFGHJKL:"~'),
        0x2B: ("\\zxcvbnm,./", "|ZXCVBNM<>?"),
    }
    table = {base + i: (p, s) for base, (plain, shifted) in rows.items() for i, (p, s) in enumerate(zip(plain, shifted, strict=True))}
    table[0x39] = (" ", " ")
    return table


US_LAYOUT = _us_layout()


@dataclass
class _Keys:
    shift: bool = False
    typed: list[str] = field(default_factory=list)

    def press(self, code: int, extended: bool, release: bool) -> None:
        if code in (0x2A, 0x36) and not extended:
            self.shift = not release
        if release or code in MODIFIERS:
            return
        names = EXT_NAMED if extended else NAMED
        if code in names:
            self.typed.append(names[code])
        elif code in US_LAYOUT:
            plain, shifted = US_LAYOUT[code]
            self.typed.append(shifted if self.shift else plain)
        else:
            self.typed.append(f"<sc:0x{code:02x}>")


@dataclass
class RdpReplay:
    negotiated: str = ""
    keystrokes: str = ""
    width: int = 0
    height: int = 0
    notes: list[str] = field(default_factory=list)
    _tiles: list[tuple[int, int, int, int, bytes]] = field(default_factory=list, repr=False)

    @property
    def rects(self) -> int:
        return len(self._tiles)

    def png(self) -> bytes | None:
        if not self._tiles:
            return None
        canvas = bytearray(self.width * self.height * 3)
        for left, top, w, h, rgb in self._tiles:  # later updates paint over earlier ones
            row = w * 3
            for r in range(h):
                dst = ((top + r) * self.width + left) * 3
                canvas[dst : dst + row] = rgb[r * row : (r + 1) * row]
        return encode_png(self.width, self.height, bytes(canvas))


def _note(out: RdpReplay, text: str) -> None:
    if text not in out.notes:
        out.notes.append(text)


def _x224(data: bytes) -> tuple[int, bytes, int] | None:
    """(TPDU code, variable part, end offset) of the TPKT-framed X.224 TPDU that starts ``data``, or None."""
    if len(data) < 6 or data[0] != 3 or data[4] < 6 or len(data) < 5 + data[4]:
        return None
    return data[5], data[11 : 5 + data[4]], 5 + data[4]


def _is_cr(data: bytes) -> bool:
    tpdu = _x224(data)
    return tpdu is not None and tpdu[0] == X224_CR


def _negotiation(var: bytes) -> tuple[int, int] | None:
    """(type, value) of an 8-byte RDP_NEG_* structure in an X.224 variable part (little-endian)."""
    if len(var) < 8 or struct.unpack("<H", var[2:4])[0] != 8:
        return None
    return var[0], struct.unpack("<I", var[4:8])[0]


def _fast_path_pdus(data: bytes, out: RdpReplay, side: str) -> list[tuple[int, bytes]]:
    """(header byte, body) of each fast-path PDU in one direction. Slow-path TPKT frames are skipped. Anything
    unreadable (TLS records, an encrypted or checksummed PDU, a cut-off tail) ends the walk with a note."""
    c = _Cursor(data)
    pdus: list[tuple[int, bytes]] = []
    while True:
        first = c.take(1)
        if first is None:
            break
        if first[0] & 3 == 3:  # TPKT: MCS and the security exchange are not decoded
            c.i -= 1
            hdr = c.take(4)
            length = struct.unpack(">H", hdr[2:4])[0] if hdr is not None else 0
            if hdr is None or length < 4 or c.take(length - 4) is None:
                _note(out, f"{side}: slow-path frame cut short: stream not read further")
                break
            continue
        if first[0] & 3 != 0:
            _note(out, f"{side}: unknown PDU action {first[0] & 3}: stream not read further")
            break
        len1 = c.take(1)
        if len1 is None:
            break
        if len1[0] & 0x80:  # 2-byte length, big-endian
            len2 = c.take(1)
            if len2 is None:
                break
            total, hdr_len = ((len1[0] & 0x7F) << 8) | len2[0], 3
        else:
            total, hdr_len = len1[0], 2
        body = c.take(total - hdr_len) if total >= hdr_len else None
        if body is None:
            _note(out, f"{side}: fast-path PDU cut short: stream not read further")
            break
        if first[0] >> 6:
            _note(out, f"{side}: encrypted or checksummed fast-path PDU: the keys are needed, stream not read further")
            break
        pdus.append((first[0], body))
    return pdus


def _input_events(body: bytes, count: int, keys: _Keys, out: RdpReplay) -> None:
    c = _Cursor(body)
    for _ in range(count):
        head = c.take(1)
        if head is None:
            return
        code, flags = head[0] >> 5, head[0] & 0x1F
        if code == EV_SCANCODE:
            key = c.take(1)
            if key is None:
                return
            keys.press(key[0], bool(flags & KBD_EXTENDED), bool(flags & KBD_RELEASE))
        elif code == EV_UNICODE:  # [U] the code unit is taken as little-endian UTF-16
            unit = c.take(2)
            if unit is None:
                return
            value = struct.unpack("<H", unit)[0]
            if not flags & KBD_RELEASE:
                keys.typed.append(chr(value) if value >= 0x20 else f"<U+{value:04X}>")
        elif code in EVENT_BODY:
            if c.take(EVENT_BODY[code]) is None:
                return
        else:
            _note(out, f"input event code {code} not known: rest of that PDU not read")
            return


def _bitmaps(data: bytes, out: RdpReplay) -> None:
    c = _Cursor(data)
    count = c.take(2)
    if count is None:
        return
    for _ in range(struct.unpack("<H", count)[0]):
        head = c.take(18)
        if head is None:
            _note(out, "bitmap update cut short")
            return
        left, top, _right, _bottom, w, h, bpp, flags, length = struct.unpack("<9H", head)
        body = c.take(length)
        if body is None:
            _note(out, "bitmap update cut short")
            return
        if flags & BITMAP_COMPRESSED:
            _note(out, f"compressed {bpp}-bpp bitmap not decoded")
            continue
        if bpp not in (16, 32) or length != w * h * bpp // 8:
            _note(out, f"{bpp}-bpp bitmap not decoded")
            continue
        out._tiles.append((left, top, w, h, _to_rgb(body, w, h, bpp)))


def _to_rgb(data: bytes, w: int, h: int, bpp: int) -> bytes:
    step = bpp // 8
    stride = w * step
    rgb = bytearray()
    for row in reversed(range(h)):  # [U] uncompressed rows are stored bottom-up
        line = data[row * stride : (row + 1) * stride]
        for i in range(0, stride, step):
            px = line[i : i + step]
            if step == 4:  # [U] little-endian B, G, R, X
                rgb += bytes((px[2], px[1], px[0]))
            else:  # [U] RGB565, little-endian
                v = px[0] | (px[1] << 8)
                rgb += bytes((((v >> 11) & 31) * 255 // 31, ((v >> 5) & 63) * 255 // 63, (v & 31) * 255 // 31))
    return bytes(rgb)


def _updates(body: bytes, out: RdpReplay) -> None:
    c = _Cursor(body)
    while True:
        head = c.take(1)
        if head is None:
            return
        code, frag, compressed = head[0] & 0xF, (head[0] >> 4) & 3, bool(head[0] >> 6 & COMPRESSION_USED)
        if compressed and c.take(1) is None:  # compressionFlags
            return
        size = c.take(2)
        data = c.take(struct.unpack("<H", size)[0]) if size is not None else None
        if data is None:
            _note(out, "server update cut short: screen stops here")
            return
        if compressed:
            _note(out, "bulk-compressed update not decoded")
        elif frag != FRAG_SINGLE:
            _note(out, "fragmented update not reassembled")
        elif code == UPD_SURFACE:
            _note(out, "surface commands not decoded")
        elif code == UPD_BITMAP:
            _bitmaps(data, out)


def _size(out: RdpReplay) -> None:
    if not out._tiles:
        return
    out.width = max(left + w for left, _t, w, _h, _rgb in out._tiles)
    out.height = max(top + h for _l, top, _w, h, _rgb in out._tiles)
    if out.width * out.height > MAX_PIXELS:
        out._tiles.clear()
        out.width = out.height = 0
        _note(out, "screen larger than 16 Mpx: not rendered")


def parse_rdp(client: bytes, server: bytes) -> RdpReplay:
    """Replay one RDP connection from its reassembled client and server byte streams."""
    out = RdpReplay()
    req, rsp = _x224(client), _x224(server)
    if req is None or rsp is None or req[0] != X224_CR or rsp[0] != X224_CC:
        _note(out, "no X.224 connection request and confirm at the start of the streams")
        return out
    neg = _negotiation(rsp[1])
    if neg is not None and neg[0] == NEG_FAILURE:
        _note(out, f"server refused the negotiation (failure code 0x{neg[1]:x})")
        return out
    selected = neg[1] if neg is not None and neg[0] == NEG_RSP else 0
    out.negotiated = PROTOCOLS.get(selected, f"protocol 0x{selected:x}")
    if selected:
        _note(out, f"{out.negotiated}: encrypted from here on; the keys are not in the capture, so no keys or screen")
        return out
    keys = _Keys()
    for head, body in _fast_path_pdus(client[req[2] :], out, "client"):
        count = (head >> 2) & 0xF
        if count == 0 and body:  # the event count did not fit in the header: it is the next byte
            count, body = body[0], body[1:]
        _input_events(body, count, keys, out)
    out.keystrokes = "".join(keys.typed)
    for _head, body in _fast_path_pdus(server[rsp[2] :], out, "server"):
        _updates(body, out)
    _size(out)
    return out


@dataclass
class RdpSession:
    stream: int
    server: str
    client: str
    replay: RdpReplay


def _candidate_streams(pcap: Path) -> list[int]:
    rows = run_fields(pcap, ["tcp.stream"], f"tcp.port == {RDP_PORT} && tcp.len > 0")
    return sorted({int(row[0]) for row in rows if row[0].isdigit()})


def reconstruct(pcap: Path, stream: int | None = None) -> list[RdpSession]:
    """Every RDP session on TCP port 3389, or the one ``stream`` given.

    A stream is kept only when one side opens with an X.224 connection request, so a stray flow on the port is not
    reported. An explicit ``stream`` is tried whatever its port, and is reported even without a request.
    """
    from .follow import follow

    sessions: list[RdpSession] = []
    for number in [stream] if stream is not None else _candidate_streams(pcap):
        try:
            followed = follow(pcap, "tcp", number)
        except TsharkRunError:
            continue
        node0, node1 = followed.payload("client"), followed.payload("server")
        if _is_cr(node0):
            client_bytes, server_bytes, client_end, server_end = node0, node1, followed.node0, followed.node1
        elif _is_cr(node1):
            client_bytes, server_bytes, client_end, server_end = node1, node0, followed.node1, followed.node0
        elif stream is None:
            continue
        else:
            client_bytes, server_bytes, client_end, server_end = node0, node1, followed.node0, followed.node1
        sessions.append(RdpSession(number, server_end, client_end, parse_rdp(client_bytes, server_bytes)))
    return sessions
