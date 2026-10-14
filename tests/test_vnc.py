"""VNC (RFB) screen, keystroke and clipboard reconstruction (issue #217)."""

from __future__ import annotations

import stat
import struct
import zlib

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.vnc import keysym_text, parse_rfb

PIXFMT = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)


def _server(width: int, height: int, *messages: bytes) -> bytes:
    init = struct.pack(">HH", width, height) + PIXFMT + struct.pack(">I", 2) + b"vn"
    return b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 0) + init + b"".join(messages)


def _client(*messages: bytes) -> bytes:
    return b"RFB 003.008\n" + bytes([1]) + b"\x01" + b"".join(messages)


def _key(down: bool, keysym: int) -> bytes:
    return b"\x04" + bytes([int(down), 0, 0]) + struct.pack(">I", keysym)


def _raw_update(x: int, y: int, w: int, h: int, pixels: bytes) -> bytes:
    return b"\x00\x00\x00\x01" + struct.pack(">HHHHi", x, y, w, h, 0) + pixels


def test_keysym_text_names_printable_and_modifier_keys() -> None:
    assert [keysym_text(k) for k in (0x61, 0x41, 0xFF0D, 0xFF08, 0xFFE1, 0x00E9, 0x01000414)] == [
        "a", "A", "<RET>", "<BS>", "", "é", "Д",
    ]
    assert keysym_text(0x12345) == "<0x12345>"


def test_keystrokes_and_clipboard_come_from_the_client_stream() -> None:
    client = _client(_key(True, 0x68), _key(False, 0x68), _key(True, 0x69), _key(True, 0xFF0D),
                     b"\x06\x00\x00\x00" + struct.pack(">I", 3) + b"ab\xe9")
    rep = parse_rfb(client, _server(1, 1))
    assert rep.version == "3.8" and rep.security == 1 and rep.name == "vn"
    assert rep.keystrokes == "hi<RET>"
    assert rep.clipboard == ["abé"]


def test_raw_and_copyrect_build_the_screen_and_png() -> None:
    red, green = bytes([0, 0, 255, 0]), bytes([0, 255, 0, 0])  # little-endian XRGB
    raw = struct.pack(">HHHHi", 0, 0, 2, 2, 0) + red * 2 + green * 2
    copy = struct.pack(">HHHHi", 0, 1, 2, 1, 1) + struct.pack(">HH", 0, 0)  # row 0 onto row 1
    rep = parse_rfb(_client(), _server(2, 2, b"\x00\x00" + struct.pack(">H", 2) + raw + copy))
    assert rep.rects == 2 and not rep.notes
    png = rep.png()
    assert png is not None and png[:8] == b"\x89PNG\r\n\x1a\n"
    i = png.index(b"IDAT")
    n = struct.unpack(">I", png[i - 4 : i])[0]
    red_row = b"\x00" + bytes([255, 0, 0]) * 2
    assert zlib.decompress(png[i + 4 : i + 4 + n]) == red_row + red_row  # row 1 is the copy of row 0


def test_unsupported_encoding_keeps_the_partial_screen_and_the_keys() -> None:
    server = _server(2, 2, b"\x00\x00" + struct.pack(">H", 1) + struct.pack(">HHHHi", 0, 0, 2, 2, 16))
    client = _client(_key(True, 0x41))
    rep = parse_rfb(client, server)
    assert rep.keystrokes == "A"
    assert rep.png() is not None  # the frame so far is kept; the note says where it stops
    assert any("encoding 16 not decoded" in note for note in rep.notes)


def test_huge_framebuffer_is_not_allocated() -> None:
    rep = parse_rfb(_client(), _server(65535, 65535))
    assert rep.png() is None
    assert any("too large" in note for note in rep.notes)


def test_no_banner_is_a_note_not_a_crash() -> None:
    rep = parse_rfb(b"", b"HTTP/1.1 200 OK\r\n")
    assert rep.version == "" and rep.notes == ["server stream has no RFB banner"]


@requires_tshark
def test_vnc_command_writes_screen_and_keys(cli_runner, tmp_path) -> None:
    out = cli_runner.invoke(app, ["vnc", str(fixture("vnc_session.pcap")), "--out", str(tmp_path)]).output
    assert "hiA<RET>" in out and "4x3" in out
    dest = tmp_path / "stream-0.png"
    assert dest.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@requires_tshark
def test_vnc_command_on_a_capture_without_vnc(cli_runner) -> None:
    out = cli_runner.invoke(app, ["vnc", str(fixture("http_basic.pcap"))]).output
    assert "no VNC (RFB) sessions in this capture" in out
