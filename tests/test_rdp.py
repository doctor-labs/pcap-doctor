from __future__ import annotations

import stat
import struct
import zlib

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.follow import follow
from pcap_doctor.rdp import RdpReplay, _Keys, parse_rdp


def _tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def _x224(code: int, var: bytes) -> bytes:
    body = bytes([code]) + b"\x00" * 5 + var
    return _tpkt(bytes([len(body)]) + body)


def _neg(kind: int, value: int) -> bytes:
    return struct.pack("<BBHI", kind, 0, 8, value)


def _pdu(head: int, body: bytes) -> bytes:
    if len(body) + 2 < 0x80:
        return bytes([head, len(body) + 2]) + body
    return bytes([head, 0x80 | ((len(body) + 3) >> 8), (len(body) + 3) & 0xFF]) + body


def _bitmap_update(flags: int, bpp: int, data: bytes) -> bytes:
    rect = struct.pack("<9H", 0, 0, 0, 0, 1, 1, bpp, flags, len(data)) + data
    upd = struct.pack("<H", 1) + rect
    return b"\x01" + struct.pack("<H", len(upd)) + upd


def test_keys_follow_the_us_layout_and_shift() -> None:
    keys = _Keys()
    keys.press(0x23, False, False)  # h
    keys.press(0x23, False, True)  # release: no text
    keys.press(0x2A, False, False)  # shift down
    keys.press(0x1E, False, False)  # A
    keys.press(0x2A, False, True)  # shift up
    keys.press(0x02, False, False)  # 1
    keys.press(0x53, True, False)  # extended Delete
    keys.press(0x1D, False, False)  # Ctrl: no text
    assert keys.typed == ["h", "A", "1", "<DEL>"]


def test_tls_session_is_reported_not_rebuilt() -> None:
    rep = parse_rdp(_x224(0xE0, _neg(1, 3)), _x224(0xD0, _neg(2, 1)))
    assert rep.negotiated == "TLS" and rep.keystrokes == "" and rep.png() is None
    assert any("encrypted" in note for note in rep.notes)


def test_compressed_bitmap_is_a_note_not_a_picture() -> None:
    server = _x224(0xD0, _neg(2, 0)) + _pdu(0x00, _bitmap_update(0x0001, 32, b"\x00" * 4))
    rep = parse_rdp(_x224(0xE0, _neg(1, 0)), server)
    assert rep.negotiated == "Standard RDP security" and rep.rects == 0 and rep.png() is None
    assert any("compressed" in note for note in rep.notes)


@requires_tshark
def test_plain_session_draws_both_bitmap_updates() -> None:
    followed = follow(fixture("rdp_session.pcap"), "tcp", 0)
    rep = parse_rdp(followed.payload("client"), followed.payload("server"))
    assert (rep.width, rep.height, rep.rects) == (2, 3, 2) and rep.keystrokes == "hiA<RET>"
    picture = rep.png()
    assert picture is not None
    i = picture.index(b"IDAT")
    n = struct.unpack(">I", picture[i - 4 : i])[0]
    red, green, blue = b"\x00" + b"\xff\x00\x00" * 2, b"\x00" + b"\x00\xff\x00" * 2, b"\x00" + b"\x00\x00\xff" * 2
    assert zlib.decompress(picture[i + 4 : i + 4 + n]) == red + green + blue


@requires_tshark
def test_rdp_command_writes_screen_and_keys(cli_runner, tmp_path) -> None:
    out = cli_runner.invoke(app, ["rdp", str(fixture("rdp_session.pcap")), "--out", str(tmp_path)]).output
    assert "hiA<RET>" in out and "2x3" in out
    dest = tmp_path / "stream-0.png"
    assert dest.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@requires_tshark
def test_rdp_command_on_a_capture_without_rdp(cli_runner) -> None:
    out = cli_runner.invoke(app, ["rdp", str(fixture("http_basic.pcap"))]).output
    assert "no RDP sessions in this capture" in out


@requires_tshark
def test_parse_rdp_survives_every_truncation_of_the_fixture() -> None:
    followed = follow(fixture("rdp_session.pcap"), "tcp", 0)
    client, server = followed.payload("client"), followed.payload("server")
    full = parse_rdp(client, server)
    assert full.keystrokes == "hiA<RET>"
    for i in range(len(server) + 1):
        assert isinstance(parse_rdp(client, server[:i]), RdpReplay)
    for j in range(len(client) + 1):
        assert full.keystrokes.startswith(parse_rdp(client[:j], server).keystrokes)
