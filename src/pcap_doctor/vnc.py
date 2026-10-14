"""VNC (RFB) reconstruction: typed keys, clipboard text and the screen as PNG (issue #217).

Works on the reassembled byte streams of one TCP connection (``follow``). Coverage is deliberately narrow:
RFB 3.8, the None and VNC-authentication security types (the DES password itself is never recovered, the
messages after it are cleartext), true-colour pixel formats, and the Raw, CopyRect and DesktopSize
encodings. Any other encoding ends the screen reconstruction at that point and the reason is recorded;
keystrokes and clipboard are read from the client stream regardless. RDP is not handled.

Message layouts follow RFC 6143 section 7 (the RFB protocol); keysyms follow the X11 keysym table.
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .ondemand import run_fields
from .tshark import TsharkRunError

RFB_BANNER = re.compile(rb"^RFB (\d{3})\.(\d{3})\n")
VNC_PORTS = (5900, 5999)  # display :0 to :99
SEC_NONE, SEC_VNC_AUTH = 1, 2
ENC_RAW, ENC_COPYRECT, ENC_DESKTOP_SIZE = 0, 1, -223
MAX_PIXELS = 16 * 1024 * 1024

#: X11 keysyms that have a name rather than a character.
NAMED_KEYSYMS = {
    0xFF08: "<BS>", 0xFF09: "<TAB>", 0xFF0D: "<RET>", 0xFF1B: "<ESC>", 0xFFFF: "<DEL>",
    0xFF50: "<HOME>", 0xFF51: "<LEFT>", 0xFF52: "<UP>", 0xFF53: "<RIGHT>", 0xFF54: "<DOWN>",
    0xFF57: "<END>", 0xFF55: "<PGUP>", 0xFF56: "<PGDN>", 0xFF63: "<INS>",
}


def keysym_text(keysym: int) -> str:
    """The text one key press produces. Modifier presses produce nothing; unknown keysyms stay visible."""
    if keysym in NAMED_KEYSYMS:
        return NAMED_KEYSYMS[keysym]
    if 0x20 <= keysym <= 0x7E or 0xA0 <= keysym <= 0xFF:
        return chr(keysym)
    if 0x01000100 <= keysym <= 0x0110FFFF:  # Unicode keysym: 0x01000000 + code point
        return chr(keysym - 0x01000000)
    if 0xFFE1 <= keysym <= 0xFFEE or keysym == 0xFE03:  # Shift, Control, Meta, Alt, Super, ISO_Level3_Shift
        return ""
    return f"<0x{keysym:x}>"


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes | None:
        if n < 0 or self.i + n > len(self.d):
            return None
        chunk = self.d[self.i : self.i + n]
        self.i += n
        return chunk

    @property
    def done(self) -> bool:
        return self.i >= len(self.d)


@dataclass(frozen=True)
class PixelFormat:
    bpp: int
    big: bool
    true_colour: bool
    rmax: int
    gmax: int
    bmax: int
    rshift: int
    gshift: int
    bshift: int

    @classmethod
    def parse(cls, raw: bytes) -> PixelFormat:
        bpp, _depth, big, true, rmax, gmax, bmax, rs, gs, bs = struct.unpack(">BBBBHHHBBB", raw[:13])
        usable = bpp in (8, 16, 32) and bool(true) and min(rmax, gmax, bmax) > 0
        return cls(bpp, bool(big), usable, rmax, gmax, bmax, rs, gs, bs)

    def to_rgb(self, data: bytes) -> bytes:
        # ponytail: per-pixel Python loop. Fine for screenshots; switch to a bytes-level table if big screens are slow.
        step = self.bpp // 8
        order: Literal["big", "little"] = "big" if self.big else "little"
        out = bytearray()
        for i in range(0, len(data) - step + 1, step):
            v = int.from_bytes(data[i : i + step], order)
            out += bytes((
                ((v >> self.rshift) & self.rmax) * 255 // self.rmax,
                ((v >> self.gshift) & self.gmax) * 255 // self.gmax,
                ((v >> self.bshift) & self.bmax) * 255 // self.bmax,
            ))
        return bytes(out)


def encode_png(width: int, height: int, rgb: bytes) -> bytes:
    rows = b"".join(b"\x00" + rgb[y * width * 3 : (y + 1) * width * 3] for y in range(height))

    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit truecolour RGB
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b"")


@dataclass
class VncReplay:
    version: str = ""
    security: int | None = None
    width: int = 0
    height: int = 0
    name: str = ""
    keystrokes: str = ""
    clipboard: list[str] = field(default_factory=list)
    rects: int = 0
    notes: list[str] = field(default_factory=list)
    _screen: bytearray = field(default_factory=bytearray, repr=False)

    def png(self) -> bytes | None:
        if not self.width or not self.height or len(self._screen) != self.width * self.height * 3:
            return None
        return encode_png(self.width, self.height, bytes(self._screen))

    # -- screen helpers --------------------------------------------------------------------------
    def _resize(self, w: int, h: int) -> None:
        self.width, self.height = w, h
        if w * h > MAX_PIXELS:  # the size comes from the capture: never allocate it blindly
            self._screen = bytearray()
            self.notes.append(f"{w}x{h} framebuffer too large to reconstruct: screen not rendered")
        else:
            self._screen = bytearray(w * h * 3)

    def _inside(self, x: int, y: int, w: int, h: int) -> bool:
        return x + w <= self.width and y + h <= self.height

    def _paste(self, x: int, y: int, w: int, h: int, rgb: bytes) -> None:
        row = w * 3
        for r in range(h):
            dst = ((y + r) * self.width + x) * 3
            self._screen[dst : dst + row] = rgb[r * row : (r + 1) * row]

    def _copy(self, x: int, y: int, w: int, h: int, sx: int, sy: int) -> None:
        row = w * 3
        block = [bytes(self._screen[((sy + r) * self.width + sx) * 3 : ((sy + r) * self.width + sx) * 3 + row]) for r in range(h)]
        self._paste(x, y, w, h, b"".join(block))


def _client_messages(c: _Cursor, out: VncReplay) -> list[PixelFormat]:
    """Keys, clipboard and pixel-format changes from the client stream. Returns the pixel formats it set."""
    formats: list[PixelFormat] = []
    keys: list[str] = []
    while not c.done:
        kind = c.take(1)
        assert kind is not None
        if kind[0] == 0:  # SetPixelFormat: 3 pad + 16 format
            body = c.take(19)
            if body is None:
                break
            formats.append(PixelFormat.parse(body[3:]))
        elif kind[0] == 2:  # SetEncodings: pad + count + 4 bytes each
            head = c.take(3)
            if head is None or c.take(4 * struct.unpack(">H", head[1:3])[0]) is None:
                break
        elif kind[0] == 3:  # FramebufferUpdateRequest: incremental + x, y, w, h
            if c.take(9) is None:
                break
        elif kind[0] == 4:  # KeyEvent: down flag, 2 pad, keysym
            body = c.take(7)
            if body is None:
                break
            if body[0]:
                keys.append(keysym_text(struct.unpack(">I", body[3:7])[0]))
        elif kind[0] == 5:  # PointerEvent: button mask, x, y
            if c.take(5) is None:
                break
        elif kind[0] == 6:  # ClientCutText: 3 pad + length + Latin-1 text
            head = c.take(7)
            if head is None:
                break
            text = c.take(struct.unpack(">I", head[3:7])[0])
            if text is None:
                break
            out.clipboard.append(text.decode("latin-1"))
        else:
            out.notes.append(f"unknown client message type {kind[0]} at byte {c.i - 1}: client stream not read further")
            break
    out.keystrokes = "".join(keys)
    return formats


def _server_messages(s: _Cursor, out: VncReplay, pf: PixelFormat) -> None:
    while not s.done:
        kind = s.take(1)
        assert kind is not None
        if kind[0] == 0:  # FramebufferUpdate
            head = s.take(3)
            if head is None:
                return
            for _ in range(struct.unpack(">H", head[1:3])[0]):
                rect = s.take(12)
                if rect is None:
                    return
                x, y, w, h, enc = struct.unpack(">HHHHi", rect)
                if enc == ENC_DESKTOP_SIZE:
                    out._resize(w, h)
                    continue
                if not pf.true_colour:
                    out.notes.append("colour-mapped pixel format: screen not rendered")
                    return
                if enc == ENC_RAW:
                    data = s.take(w * h * pf.bpp // 8)
                    if data is None:
                        return
                    if not out._inside(x, y, w, h) or not out._screen:
                        out.notes.append("rectangle outside the framebuffer: screen reconstruction stopped")
                        return
                    out._paste(x, y, w, h, pf.to_rgb(data))
                elif enc == ENC_COPYRECT:
                    src = s.take(4)
                    if src is None:
                        return
                    sx, sy = struct.unpack(">HH", src)
                    if not (out._inside(x, y, w, h) and out._inside(sx, sy, w, h)):
                        out.notes.append("CopyRect outside the framebuffer: screen reconstruction stopped")
                        return
                    out._copy(x, y, w, h, sx, sy)
                else:
                    out.notes.append(f"encoding {enc} not decoded: screen reconstruction stops here")
                    return
                out.rects += 1
        elif kind[0] == 1:  # SetColourMapEntries: not decoded, the screen stops being rendered
            out.notes.append("SetColourMapEntries: screen not rendered past this point")
            return
        elif kind[0] == 2:  # Bell
            pass
        elif kind[0] == 3:  # ServerCutText
            head = s.take(7)
            if head is None:
                return
            if s.take(struct.unpack(">I", head[3:7])[0]) is None:
                return
        else:
            out.notes.append(f"unknown server message type {kind[0]}: server stream not read further")
            return


def parse_rfb(client: bytes, server: bytes) -> VncReplay:
    """Replay one RFB 3.8 connection from its reassembled client and server byte streams."""
    out = VncReplay()
    banner = RFB_BANNER.match(server)
    if banner is None:
        out.notes.append("server stream has no RFB banner")
        return out
    out.version = f"{int(banner[1])}.{int(banner[2])}"
    if out.version != "3.8":
        out.notes.append(f"RFB {out.version} is not decoded (3.8 only)")
        return out
    s, c = _Cursor(server), _Cursor(client)
    if s.take(12) is None or c.take(12) is None:
        out.notes.append("connection ends inside the version handshake")
        return out
    count = s.take(1)
    if count is None:
        out.notes.append("connection ends inside the security handshake")
        return out
    if count[0] == 0:  # server refused: u32 length + reason
        length = s.take(4)
        reason = s.take(struct.unpack(">I", length)[0]) if length else None
        out.notes.append("server refused the connection: " + (reason or b"").decode("latin-1"))
        return out
    offered = s.take(count[0]) or b""
    chosen = c.take(1)
    if chosen is None or chosen[0] not in offered:
        out.notes.append("client chose no security type the server offered")
        return out
    out.security = chosen[0]
    if chosen[0] == SEC_VNC_AUTH:
        if s.take(16) is None or c.take(16) is None:
            out.notes.append("connection ends inside VNC authentication")
            return out
    elif chosen[0] != SEC_NONE:
        out.notes.append(f"security type {chosen[0]} not decoded")
        return out
    if s.take(4) != b"\x00\x00\x00\x00":
        out.notes.append("security handshake failed")
        return out
    init = s.take(24)
    if init is None:
        out.notes.append("connection ends before ServerInit")
        return out
    server_pf = PixelFormat.parse(init[4:20])
    name = s.take(struct.unpack(">I", init[20:24])[0]) or b""
    out.name = name.decode("latin-1")
    if c.take(1) is None:
        out.notes.append("connection ends before ClientInit")
        return out
    out._resize(*struct.unpack(">HH", init[:4]))

    formats = _client_messages(c, out)
    pf = formats[0] if formats else server_pf
    if len(formats) > 1:
        out.notes.append("pixel format changed mid-session: only the first change is applied to the screen")
    _server_messages(s, out, pf)
    return out


@dataclass
class VncSession:
    stream: int
    server: str
    client: str
    replay: VncReplay


def _candidate_streams(pcap: Path) -> list[int]:
    seen: set[int] = set()
    rows = run_fields(pcap, ["tcp.stream"], f"tcp.port >= {VNC_PORTS[0]} && tcp.port <= {VNC_PORTS[1]} && tcp.len > 0")
    for row in rows:
        if row[0].isdigit():
            seen.add(int(row[0]))
    return sorted(seen)


def reconstruct(pcap: Path, stream: int | None = None) -> list[VncSession]:
    """Every VNC session in the capture (TCP streams on ports 5900-5999), or the one ``stream`` given.

    A stream is kept only when one of its directions starts with an RFB banner, so a stray flow on a VNC port
    is not reported as a session. An explicit ``stream`` is tried whatever its port.
    """
    from .follow import follow

    sessions: list[VncSession] = []
    for number in [stream] if stream is not None else _candidate_streams(pcap):
        try:
            followed = follow(pcap, "tcp", number)
        except TsharkRunError:
            continue
        # Both banners read "RFB ...", so the content cannot tell the sides apart. The server listens on the VNC
        # port; the initiator (node 0, the side that sent the first packet) is the client unless the port says otherwise.
        server_is_node0 = _port(followed.node0) in range(VNC_PORTS[0], VNC_PORTS[1] + 1) and (
            _port(followed.node1) not in range(VNC_PORTS[0], VNC_PORTS[1] + 1)
        )
        node0_bytes, node1_bytes = followed.payload("client"), followed.payload("server")
        server_bytes, client_bytes = (node0_bytes, node1_bytes) if server_is_node0 else (node1_bytes, node0_bytes)
        if not server_bytes.startswith(b"RFB "):
            continue
        server_end, client_end = (followed.node0, followed.node1) if server_is_node0 else (followed.node1, followed.node0)
        replay = parse_rfb(client_bytes, server_bytes)
        sessions.append(VncSession(number, server_end, client_end, replay))
    return sessions


def _port(endpoint: str) -> int:
    tail = endpoint.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else -1
