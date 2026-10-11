"""Byte-built fixtures and packet helpers for the parity features (issues #199 onward).

Everything here is deterministic and carries valid IP/TCP/UDP checksums (so checksum validation, #209, stays
quiet on them) unless a builder asks for a bad one. ``make_fixtures.py`` merges ``FIXTURES`` into its table.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from pathlib import Path

FIXTURES: dict[str, Callable[[], bytes]] = {}


def fixture(name: str) -> Callable[[Callable[[], bytes]], Callable[[], bytes]]:
    def register(fn: Callable[[], bytes]) -> Callable[[], bytes]:
        FIXTURES[name] = fn
        return fn

    return register


def mac(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(":"))


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def ip_packet(
    src: str, dst: str, proto: int, l4: bytes, *, ttl: int = 64, ident: int = 0, flags_frag: int = 0x4000,
    bad_ip_checksum: bool = False,
) -> bytes:
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ident, flags_frag, ttl, proto, 0, _ip4(src), _ip4(dst))
    c = csum(head) ^ (0x1234 if bad_ip_checksum else 0)
    return head[:10] + struct.pack("!H", c) + head[12:] + l4


def ether(src_mac: str, dst_mac: str, payload: bytes, ethertype: int = 0x0800) -> bytes:
    return mac(dst_mac) + mac(src_mac) + struct.pack("!H", ethertype) + payload


def tcp_segment(
    src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", *,
    window: int = 65535, options: bytes = b"", bad_checksum: bool = False,
) -> bytes:
    off = (20 + len(options)) // 4
    head = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, window, 0, 0) + options
    pseudo = _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, 6, len(head) + len(payload))
    c = csum(pseudo + head + payload) ^ (0x4321 if bad_checksum else 0)
    return head[:16] + struct.pack("!H", c) + head[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes, *, bad_checksum: bool = False) -> bytes:
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, 17, length)
    c = (csum(pseudo + head + payload) or 0xFFFF) ^ (0x4321 if bad_checksum else 0)
    return head[:6] + struct.pack("!H", c) + payload


MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


class Wire:
    """Collects frames with a clock; ``write()`` returns the pcap bytes."""

    def __init__(self, start: float = 1_700_100_000.0, step: float = 0.01) -> None:
        self.t, self.step = start, step
        self.frames: list[tuple[float, bytes]] = []

    def add(self, frame: bytes, dt: float | None = None) -> None:
        self.t += self.step if dt is None else dt
        self.frames.append((self.t, frame))

    def write(self) -> bytes:
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for ts, frame in self.frames:
            sec = int(ts)
            out += struct.pack("<IIII", sec, round((ts - sec) * 1_000_000), len(frame), len(frame)) + frame
        return out


class Tcp:
    """One TCP connection with consistent sequence numbers; every method also emits into ``wire``."""

    def __init__(self, wire: Wire, client: str, server: str, sport: int, dport: int, *,
                 cmac: str = MAC_A, smac: str = MAC_B, isn_c: int = 1000, isn_s: int = 5000) -> None:
        self.w, self.c, self.s, self.sp, self.dp = wire, client, server, sport, dport
        self.cmac, self.smac = cmac, smac
        self.seq_c, self.seq_s = isn_c, isn_s

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"", **kw: object) -> None:
        if from_client:
            ack = 0 if flags == 0x02 else self.seq_s
            seg = tcp_segment(self.c, self.s, self.sp, self.dp, self.seq_c, ack, flags, payload, **kw)  # type: ignore[arg-type]
            frame = ether(self.cmac, self.smac, ip_packet(self.c, self.s, 6, seg))
        else:
            seg = tcp_segment(self.s, self.c, self.dp, self.sp, self.seq_s, self.seq_c, flags, payload, **kw)  # type: ignore[arg-type]
            frame = ether(self.smac, self.cmac, ip_packet(self.s, self.c, 6, seg))
        self.w.add(frame)

    def open(self) -> Tcp:
        self._emit(True, 0x02)
        self.seq_c += 1
        self._emit(False, 0x12)
        self.seq_s += 1
        self._emit(True, 0x10)
        return self

    def send(self, from_client: bool, payload: bytes, ack: bool = True) -> Tcp:
        self._emit(from_client, 0x18, payload)
        if from_client:
            self.seq_c += len(payload)
        else:
            self.seq_s += len(payload)
        if ack:
            self._emit(not from_client, 0x10)
        return self

    def close(self) -> Tcp:
        self._emit(True, 0x11)
        self.seq_c += 1
        self._emit(False, 0x11)
        self.seq_s += 1
        self._emit(True, 0x10)
        return self


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, *, smac: str = MAC_A, dmac: str = MAC_B,
              **kw: object) -> bytes:
    return ether(smac, dmac, ip_packet(src, dst, 17, udp_datagram(src, dst, sport, dport, payload, **kw)))  # type: ignore[arg-type]


# -- NTLM / SMB2 builders (also used by the Kerberos and NTLM fixtures) -------------------------------
def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _secbuf(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def ntlm_negotiate() -> bytes:
    return b"NTLMSSP\x00" + struct.pack("<II", 1, 0xE2088297) + _secbuf(0, 32) + _secbuf(0, 32)


def ntlm_challenge(challenge: bytes, target: str = "CORP") -> bytes:
    tname = utf16(target)
    info = struct.pack("<HH", 2, len(tname)) + tname + struct.pack("<HH", 0, 0)  # MsvAvNbDomainName, MsvAvEOL
    head = b"NTLMSSP\x00" + struct.pack("<I", 2) + _secbuf(len(tname), 56) + struct.pack("<I", 0xE2898215)
    head += challenge + bytes(8) + _secbuf(len(info), 56 + len(tname)) + bytes(8)
    return head + tname + info


def ntlm_authenticate(user: str, domain: str, workstation: str, nt_response: bytes, lm_response: bytes = b"\x00" * 24) -> bytes:
    parts = [lm_response, nt_response, utf16(domain), utf16(user), utf16(workstation), b""]
    offset = 64 + 8
    fields = b""
    for p in parts:
        fields += _secbuf(len(p), offset)
        offset += len(p)
    head = b"NTLMSSP\x00" + struct.pack("<I", 3) + fields + struct.pack("<I", 0xE2888215) + bytes(8)
    return head + b"".join(parts)


def smb2_message(command: int, body: bytes, *, response: bool = False, msg_id: int = 0, tree: int = 0,
                 session: int = 0, status: int = 0, credits: int = 1) -> bytes:
    flags = 1 if response else 0
    head = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, status, command, credits, flags, 0, msg_id, 0, tree, session)
            + bytes(16))
    pdu = head + body
    return b"\x00" + struct.pack(">I", len(pdu))[1:] + pdu  # NetBIOS session header


def smb2_negotiate_request(dialects: tuple[int, ...] = (0x0202, 0x0210, 0x0300)) -> bytes:
    body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0x7F, bytes(range(16)), 0)
    body += b"".join(struct.pack("<H", d) for d in dialects)
    return smb2_message(0, body)


def smb2_negotiate_response(dialect: int = 0x0210) -> bytes:
    body = struct.pack("<HHHH16sIIIIQQHHI", 65, 1, dialect, 0, bytes(16)[::-1] or bytes(16), 0x7, 65536, 65536, 65536,
                       132_000_000_000_000_000, 132_000_000_000_000_000, 128, 0, 0) + b"\x00"
    return smb2_message(0, body, response=True, credits=1)


def smb2_session_setup(blob: bytes, *, response: bool = False, msg_id: int = 1, session: int = 0,
                       status: int = 0) -> bytes:
    if response:
        body = struct.pack("<HHHH", 9, 0, 72, len(blob)) + blob
    else:
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(blob), 0) + blob
    return smb2_message(1, body, response=response, msg_id=msg_id, session=session, status=status)


def smb2_tree_connect(path: str, *, tree: int = 0, msg_id: int = 3, session: int = 0x100) -> bytes:
    raw = utf16(path)
    return smb2_message(3, struct.pack("<HHHH", 9, 0, 72, len(raw)) + raw, msg_id=msg_id, session=session)


def smb2_tree_connect_response(*, tree: int = 1, msg_id: int = 3, session: int = 0x100) -> bytes:
    return smb2_message(3, struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x1F01FF), response=True, msg_id=msg_id,
                        tree=tree, session=session)


def smb2_create(name: str, *, tree: int = 1, msg_id: int = 4, session: int = 0x100) -> bytes:
    raw = utf16(name)
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x120089, 0x80, 7, 1, 0x40, 120, len(raw), 0, 0) + raw
    return smb2_message(5, body, msg_id=msg_id, tree=tree, session=session)


def smb2_create_response(*, tree: int = 1, msg_id: int = 4, session: int = 0x100, size: int = 0,
                         fid: bytes = b"\x01" * 16) -> bytes:
    body = struct.pack("<HBBIQQQQQQII", 89, 0, 0, 1, 0, 0, 0, 0, size, size, 0x80, 0) + fid + struct.pack("<II", 0, 0)
    return smb2_message(5, body, response=True, msg_id=msg_id, tree=tree, session=session)


def dns_wire(name: str, qid: int, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def dhcp_message(op: int, xid: int, client_mac: str, msg_type: int, *, ciaddr: str = "0.0.0.0", yiaddr: str = "0.0.0.0",
                 options: bytes = b"") -> bytes:
    head = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000, _ip4(ciaddr), _ip4(yiaddr), bytes(4), bytes(4))
    head += mac(client_mac) + bytes(10) + bytes(64) + bytes(128) + b"\x63\x82\x53\x63"
    return head + bytes([53, 1, msg_type]) + options + b"\xff"


@fixture("logs_mix.pcap")
def fixture_logs_mix() -> bytes:
    """DHCP, an SMTP mail, an SMB2 session (NTLM) and a malformed DNS packet: the protocols the Zeek-style logs add (#199)."""
    w = Wire()
    cl_mac = "02:aa:bb:cc:dd:01"
    # DHCP
    w.add(udp_frame("0.0.0.0", "255.255.255.255", 68, 67, dhcp_message(1, 0x1234, cl_mac, 1, options=bytes([12, 9]) + b"pf-laptop"),
                    smac=cl_mac, dmac="ff:ff:ff:ff:ff:ff"))
    srv = "10.0.0.1"
    offer = dhcp_message(2, 0x1234, cl_mac, 2, yiaddr="10.0.0.50", options=bytes([54, 4]) + _ip4(srv) + bytes([51, 4]) + struct.pack("!I", 3600))
    w.add(udp_frame(srv, "255.255.255.255", 67, 68, offer, smac=MAC_B, dmac="ff:ff:ff:ff:ff:ff"))
    w.add(udp_frame("0.0.0.0", "255.255.255.255", 68, 67,
                    dhcp_message(1, 0x1234, cl_mac, 3, options=bytes([12, 9]) + b"pf-laptop" + bytes([50, 4]) + _ip4("10.0.0.50")),
                    smac=cl_mac, dmac="ff:ff:ff:ff:ff:ff"))
    w.add(udp_frame(srv, "255.255.255.255", 67, 68, dhcp_message(2, 0x1234, cl_mac, 5, yiaddr="10.0.0.50", options=bytes([54, 4]) + _ip4(srv) + bytes([51, 4]) + struct.pack("!I", 3600)),
                    smac=MAC_B, dmac="ff:ff:ff:ff:ff:ff"))
    # SMTP
    c, s = "10.0.0.50", "10.0.0.25"
    t = Tcp(w, c, s, 44000, 25, cmac=cl_mac).open()
    t.send(False, b"220 mail.example ESMTP\r\n")
    t.send(True, b"EHLO pf-laptop\r\n")
    t.send(False, b"250 mail.example\r\n")
    t.send(True, b"MAIL FROM:<alice@example.com>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"RCPT TO:<bob@example.org>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"DATA\r\n")
    t.send(False, b"354 go ahead\r\n")
    t.send(True, b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: quarterly numbers\r\n"
                 b"Date: Tue, 14 Nov 2023 22:16:40 +0000\r\nMessage-ID: <pf-1@example.com>\r\n\r\nsee attached\r\n.\r\n")
    t.send(False, b"250 queued\r\n")
    t.send(True, b"QUIT\r\n")
    t.send(False, b"221 bye\r\n")
    t.close()
    # SMB2 with NTLM
    chal = bytes.fromhex("0123456789abcdef")
    t = Tcp(w, c, "10.0.0.30", 44100, 445, cmac=cl_mac).open()
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    t.send(True, smb2_session_setup(ntlm_negotiate(), msg_id=1))
    t.send(False, smb2_session_setup(ntlm_challenge(chal), response=True, msg_id=1, session=0x100, status=0xC0000016))
    t.send(True, smb2_session_setup(ntlm_authenticate("alice", "CORP", "PF-LAPTOP", bytes(range(16)) + b"\x01\x01" + bytes(30)), msg_id=2, session=0x100))
    t.send(False, smb2_session_setup(b"", response=True, msg_id=2, session=0x100))
    t.send(True, smb2_tree_connect("\\\\10.0.0.30\\ADMIN$"))
    t.send(False, smb2_tree_connect_response())
    t.send(True, smb2_create("windows\\temp\\payload.exe"))
    t.send(False, smb2_create_response())
    t.close()
    # malformed DNS: the question runs past the end of the packet
    w.add(udp_frame(c, "10.0.0.1", 40404, 53, dns_wire("bad.example", 7)[:-6]))
    return w.write()


def write_all(out: Path) -> None:  # pragma: no cover - used by make_fixtures
    for name, builder in FIXTURES.items():
        (out / name).write_bytes(builder())


# -- files_mix.pcap: one file delivered over every protocol the extractor understands (#202, #203) ------------------
FILE_PAYLOADS = {
    "http": b"MZ\x90\x00" + b"PF-HTTP-PAYLOAD-" * 8,
    "ftp": b"%PDF-1.4\n" + b"PF-FTP-PAYLOAD-" * 8,
    "tftp": b"\x7fELF" + b"PF-TFTP-PAYLOAD-" * 4,
    "smb": b"PK\x03\x04" + b"PF-SMB-PAYLOAD-" * 8,
    "mail": b"\x89PNG\r\n\x1a\n" + b"PF-MAIL-PAYLOAD-" * 8,
}


def _mime_mail() -> bytes:
    import base64

    body = base64.encodebytes(FILE_PAYLOADS["mail"])
    return (b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: logo\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="PFBOUND"\r\n\r\n--PFBOUND\r\nContent-Type: text/plain\r\n\r\n'
            b"see logo\r\n--PFBOUND\r\nContent-Type: image/png; name=\"logo.png\"\r\n"
            b'Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="logo.png"\r\n\r\n'
            + body.replace(b"\n", b"\r\n") + b"--PFBOUND--\r\n")


@fixture("files_mix.pcap")
def fixture_files_mix() -> bytes:
    w = Wire(start=1_700_200_000.0)
    c = "10.1.0.5"
    # HTTP download
    t = Tcp(w, c, "10.1.0.80", 45000, 80).open()
    t.send(True, b"GET /dl/tool.exe HTTP/1.1\r\nHost: files.example\r\n\r\n")
    body = FILE_PAYLOADS["http"]
    t.send(False, b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    t.close()
    # FTP passive RETR: control on 21, data on 51210
    t = Tcp(w, c, "10.1.0.21", 45100, 21).open()
    t.send(False, b"220 ftp ready\r\n")
    t.send(True, b"USER anon\r\n")
    t.send(False, b"331 pw\r\n")
    t.send(True, b"PASS x\r\n")
    t.send(False, b"230 ok\r\n")
    t.send(True, b"PASV\r\n")
    t.send(False, b"227 Entering Passive Mode (10,1,0,21,200,10).\r\n")
    t.send(True, b"RETR report.pdf\r\n")
    d = Tcp(w, c, "10.1.0.21", 45101, 51210, isn_c=7000, isn_s=9000).open()
    t.send(False, b"150 Opening data connection\r\n")
    d.send(False, FILE_PAYLOADS["ftp"])
    d.close()
    t.send(False, b"226 done\r\n")
    t.close()
    # TFTP read
    srv = "10.1.0.69"
    w.add(udp_frame(c, srv, 50000, 69, b"\x00\x01fw.bin\x00octet\x00"))
    data = FILE_PAYLOADS["tftp"]
    w.add(udp_frame(srv, c, 40001, 50000, b"\x00\x03\x00\x01" + data))
    w.add(udp_frame(c, srv, 50000, 40001, b"\x00\x04\x00\x01"))
    # SMB2 write of a file
    t = Tcp(w, c, "10.1.0.30", 45200, 445).open()
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    t.send(True, smb2_session_setup(ntlm_negotiate(), msg_id=1))
    t.send(False, smb2_session_setup(ntlm_challenge(bytes(8)), response=True, msg_id=1, session=0x100, status=0xC0000016))
    t.send(True, smb2_session_setup(ntlm_authenticate("bob", "CORP", "PF", bytes(range(16)) + b"\x01\x01" + bytes(30)), msg_id=2, session=0x100))
    t.send(False, smb2_session_setup(b"", response=True, msg_id=2, session=0x100))
    t.send(True, smb2_tree_connect("\\\\10.1.0.30\\share"))
    t.send(False, smb2_tree_connect_response())
    t.send(True, smb2_create("docs\\archive.zip"))
    t.send(False, smb2_create_response())
    t.send(True, smb2_write(FILE_PAYLOADS["smb"]))
    t.send(False, smb2_write_response(len(FILE_PAYLOADS["smb"])))
    t.send(True, smb2_close())
    t.send(False, smb2_close_response())
    t.close()
    # SMTP with a MIME attachment
    t = Tcp(w, c, "10.1.0.25", 45300, 25).open()
    t.send(False, b"220 mx ESMTP\r\n")
    t.send(True, b"EHLO pf\r\n")
    t.send(False, b"250 mx\r\n")
    t.send(True, b"MAIL FROM:<alice@example.com>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"RCPT TO:<bob@example.org>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"DATA\r\n")
    t.send(False, b"354 go\r\n")
    t.send(True, _mime_mail() + b".\r\n")
    t.send(False, b"250 queued\r\n")
    t.send(True, b"QUIT\r\n")
    t.close()
    # POP3 RETR of the same mail
    t = Tcp(w, c, "10.1.0.110", 45400, 110).open()
    t.send(False, b"+OK POP3 ready\r\n")
    t.send(True, b"USER bob\r\n")
    t.send(False, b"+OK\r\n")
    t.send(True, b"PASS secret\r\n")
    t.send(False, b"+OK logged in\r\n")
    t.send(True, b"RETR 1\r\n")
    t.send(False, b"+OK message follows\r\n" + _mime_mail().replace(b"logo.png", b"pop-logo.png") + b".\r\n")
    t.send(True, b"QUIT\r\n")
    t.close()
    # IMAP FETCH of the mail with a literal
    t = Tcp(w, c, "10.1.0.143", 45500, 143).open()
    msg = _mime_mail().replace(b"logo.png", b"imap-logo.png")
    t.send(False, b"* OK IMAP ready\r\n")
    t.send(True, b"a1 LOGIN bob secret\r\n")
    t.send(False, b"a1 OK logged in\r\n")
    t.send(True, b"a2 FETCH 1 BODY[]\r\n")
    t.send(False, b"* 1 FETCH (BODY[] {" + str(len(msg)).encode() + b"}\r\n" + msg + b")\r\na2 OK done\r\n")
    t.send(True, b"a3 LOGOUT\r\n")
    t.close()
    return w.write()


def smb2_write(data: bytes, *, tree: int = 1, msg_id: int = 5, session: int = 0x100, fid: bytes = b"\x01" * 16) -> bytes:
    body = struct.pack("<HHIQ16sIIHHI", 49, 112, len(data), 0, fid, 0, 0, 0, 0, 0) + data
    return smb2_message(9, body, msg_id=msg_id, tree=tree, session=session)


def smb2_write_response(count: int, *, tree: int = 1, msg_id: int = 5, session: int = 0x100) -> bytes:
    return smb2_message(9, struct.pack("<HHIIHH", 17, 0, count, 0, 0, 0) + b"\x00", response=True, msg_id=msg_id,
                        tree=tree, session=session)


def smb2_close(*, tree: int = 1, msg_id: int = 6, session: int = 0x100, fid: bytes = b"\x01" * 16) -> bytes:
    return smb2_message(6, struct.pack("<HHI16s", 24, 0, 0, fid), msg_id=msg_id, tree=tree, session=session)


def smb2_close_response(*, tree: int = 1, msg_id: int = 6, session: int = 0x100) -> bytes:
    return smb2_message(6, struct.pack("<HHIQQQQQQI", 60, 0, 0, 0, 0, 0, 0, 0, 0, 0x80), response=True, msg_id=msg_id,
                        tree=tree, session=session)


def smb1_negotiate_request() -> bytes:
    header = b"\xffSMB" + bytes([0x72]) + struct.pack("<IBHH", 0, 0x18, 0xC853, 0) + bytes(8) + struct.pack("<HHHHH", 0, 0, 1, 0, 1)
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    pdu = header + body
    return b"\x00" + struct.pack(">I", len(pdu))[1:] + pdu


@fixture("smb_attack.pcap")
def fixture_smb_attack() -> bytes:
    """SMBv1 negotiation, then an anonymous SMB2 session that reaches ADMIN$ and writes a service binary (#204)."""
    w = Wire(start=1_700_300_000.0)
    c, s = "10.2.0.9", "10.2.0.40"
    Tcp(w, c, s, 46000, 445).open().send(True, smb1_negotiate_request()).close()
    t = Tcp(w, c, s, 46100, 445).open()
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    t.send(True, smb2_session_setup(ntlm_negotiate(), msg_id=1))
    t.send(False, smb2_session_setup(ntlm_challenge(bytes(8)), response=True, msg_id=1, session=0x100, status=0xC0000016))
    t.send(True, smb2_session_setup(ntlm_authenticate("", "", "", b"", lm_response=b"\x00"), msg_id=2, session=0x100))
    t.send(False, smb2_session_setup(b"", response=True, msg_id=2, session=0x100))
    t.send(True, smb2_tree_connect("\\\\10.2.0.40\\ADMIN$"))
    t.send(False, smb2_tree_connect_response())
    t.send(True, smb2_create("PSEXESVC.exe"))
    t.send(False, smb2_create_response())
    t.send(True, smb2_tree_connect("\\\\10.2.0.40\\IPC$", msg_id=7))
    t.send(False, smb2_tree_connect_response(tree=2, msg_id=7))
    t.send(True, smb2_create("svcctl", tree=2, msg_id=8))
    t.send(False, smb2_create_response(tree=2, msg_id=8))
    t.close()
    return w.write()


def _krb(root: object) -> bytes:
    """DER bytes of one Kerberos message, built with scapy (a dev dependency) and fixed timestamps."""
    from scapy.layers.kerberos import Kerberos

    return bytes(Kerberos(root=root))


@fixture("kerberos.pcap")
def fixture_kerberos() -> bytes:
    """AS exchange that needs pre-authentication, then a TGS request for cifs/fs1 (#205). Names only, no keys."""
    from scapy.asn1.asn1 import ASN1_GENERAL_STRING, ASN1_GENERALIZED_TIME
    from scapy.layers.kerberos import (
        KRB_AS_REP,
        KRB_AS_REQ,
        KRB_ERROR,
        KRB_KDC_REQ_BODY,
        KRB_TGS_REP,
        KRB_TGS_REQ,
        EncryptedData,
        KRB_Ticket,
        PrincipalName,
    )

    realm, when = "CORP.EXAMPLE", ASN1_GENERALIZED_TIME("20231115000000Z")

    def name(kind: int, *parts: str) -> PrincipalName:
        return PrincipalName(nameType=kind, nameString=[ASN1_GENERAL_STRING(p) for p in parts])

    def req(cname: str | None, sname: PrincipalName) -> KRB_KDC_REQ_BODY:
        return KRB_KDC_REQ_BODY(cname=name(1, cname) if cname else None, realm=realm, sname=sname, etype=[18, 23],
                                nonce=1, till=when, rtime=when)

    def enc() -> EncryptedData:
        return EncryptedData(etype=18, cipher=bytes(16))

    krbtgt, cifs = name(2, "krbtgt", realm), name(2, "cifs", "fs1.corp.example")
    w = Wire(start=1_700_400_000.0)
    c, k = "10.3.0.10", "10.3.0.2"
    w.add(udp_frame(c, k, 50001, 88, _krb(KRB_AS_REQ(reqBody=req("alice", krbtgt)))))
    w.add(udp_frame(k, c, 88, 50001, _krb(KRB_ERROR(errorCode=25, stime=when, susec=0, realm=realm, sname=krbtgt,
                                                    cname=name(1, "alice"), crealm=realm))))
    w.add(udp_frame(c, k, 50002, 88, _krb(KRB_AS_REQ(reqBody=req("alice", krbtgt)))))
    w.add(udp_frame(k, c, 88, 50002, _krb(KRB_AS_REP(crealm=realm, cname=name(1, "alice"),
                                                     ticket=KRB_Ticket(realm=realm, sname=krbtgt, encPart=enc()),
                                                     encPart=enc()))))
    w.add(udp_frame(c, k, 50003, 88, _krb(KRB_TGS_REQ(reqBody=req(None, cifs)))))
    w.add(udp_frame(k, c, 88, 50003, _krb(KRB_TGS_REP(msgType=13, crealm=realm, cname=name(1, "alice"),
                                                      ticket=KRB_Ticket(realm=realm, sname=cifs, encPart=enc()),
                                                      encPart=enc()))))
    return w.write()


@fixture("tcp_health.pcap")
def fixture_tcp_health() -> bytes:
    """One TCP stream with a retransmission, a content gap, a zero window and a bad checksum, plus a UDP datagram
    with a bad checksum (#208, #209)."""
    w = Wire(start=1_700_500_000.0)
    c, s = "10.4.0.10", "10.4.0.20"
    t = Tcp(w, c, s, 47000, 8080).open()
    t.send(True, b"GET / HTTP/1.1\r\n\r\n")
    t._emit(True, 0x18, b"PF-RETRANSMIT-01")  # first copy is lost on the wire
    t._emit(True, 0x18, b"PF-RETRANSMIT-01")  # same sequence number again: a retransmission
    t.seq_c += 16
    t.seq_c += 100  # 100 client bytes never captured: a content gap before the next segment
    t.send(True, b"PF-AFTER-THE-GAP")
    t._emit(False, 0x10)  # the server repeats that ACK: a duplicate ACK
    t._emit(False, 0x10, window=0)  # server advertises a zero window
    t.send(False, b"HTTP/1.1 200 OK\r\n\r\n")
    t._emit(True, 0x18, b"PF-BAD-CHECKSUM", bad_checksum=True)
    t.seq_c += 15
    t.close()
    w.add(udp_frame(c, s, 47001, 9999, b"PF-UDP-BAD-SUM", bad_checksum=True))
    return w.write()


@fixture("brute_force.pcap")
def fixture_brute_force() -> bytes:
    """Password guessing on three services, and one client that stays under the limits (#207)."""
    w = Wire(start=1_700_600_000.0)
    attacker, victim, quiet = "10.5.0.66", "10.5.0.20", "10.5.0.11"
    for i in range(20):  # FTP: 20 connections, each a USER/PASS that the server rejects with 530
        t = Tcp(w, attacker, victim, 48000 + i, 21).open()
        t.send(False, b"220 ftp ready\r\n")
        t.send(True, b"USER admin\r\n")
        t.send(False, b"331 Password required\r\n")
        t.send(True, b"PASS guess%02d\r\n" % i)
        t.send(False, b"530 Login incorrect.\r\n")
        t.close()
    for i in range(12):  # HTTP: 12 Basic-auth requests answered 401
        t = Tcp(w, attacker, victim, 49000 + i, 80).open()
        t.send(True, b"GET /admin HTTP/1.1\r\nHost: victim\r\nAuthorization: Basic YWRtaW46Z3Vlc3M=\r\n\r\n")
        t.send(False, b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n")
        t.close()
    t = Tcp(w, attacker, victim, 49500, 445).open()  # SMB: 10 NTLM logons refused on one connection
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    for i in range(10):
        t.send(True, smb2_session_setup(ntlm_authenticate("admin", "CORP", "KALI", bytes(24)), msg_id=2 + i))
        t.send(False, smb2_session_setup(b"", response=True, msg_id=2 + i, status=0xC000006D))
    t.close()
    for i in range(3):  # a user mistyping a password three times stays below every limit
        t = Tcp(w, quiet, victim, 50000 + i, 21).open()
        t.send(True, b"USER alice\r\n")
        t.send(False, b"331 Password required\r\n")
        t.send(True, b"PASS typo\r\n")
        t.send(False, b"530 Login incorrect.\r\n")
        t.close()
    return w.write()


@fixture("weird_mix.pcap")
def fixture_weird_mix() -> bytes:
    """Protocol events with exact Zeek weird names: a UDP length that lies, a window-scale shift over 14, an HTTP
    request with both Content-Length and Transfer-Encoding (#210)."""
    w = Wire(start=1_700_700_000.0)
    c, s = "10.6.0.10", "10.6.0.20"
    payload = b"PF-UDP-LENGTH-LIES"
    head = struct.pack("!HHHH", 47100, 9998, 8 + len(payload) + 40, 0)  # length field 40 bytes longer than the datagram
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 17, head + payload)))
    t = Tcp(w, c, s, 47200, 80)
    t._emit(True, 0x02, options=b"\x03\x03\x0f\x00")  # SYN with window scale shift 15 (the maximum is 14)
    t.seq_c += 1
    t._emit(False, 0x12)
    t.seq_s += 1
    t._emit(True, 0x10)
    t.send(True, b"POST /up HTTP/1.1\r\nHost: s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nPFPF\r\n0\r\n\r\n")
    t.send(False, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    t.close()
    return w.write()


@fixture("dns_records.pcap")
def fixture_dns_records() -> bytes:
    """One answer of each record type beyond A/AAAA/CNAME, plus an EDNS OPT record (#229)."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRMX, DNSRROPT, DNSRRSOA, DNSRRSRV

    w = Wire(start=1_700_800_000.0)
    c, r = "10.7.0.10", "10.7.0.53"
    answers = [
        ("example.org", "TXT", DNSRR(rrname="example.org", type="TXT", ttl=60, rdata=[b"v=spf1 -all"])),
        ("example.org", "MX", DNSRRMX(rrname="example.org", ttl=60, preference=10, exchange="mail.example.org")),
        ("example.org", "NS", DNSRR(rrname="example.org", type="NS", ttl=60, rdata="ns1.example.org")),
        ("10.0.7.10.in-addr.arpa", "PTR", DNSRR(rrname="10.0.7.10.in-addr.arpa", type="PTR", ttl=60, rdata="host.example.org")),
        ("_sip._tcp.example.org", "SRV", DNSRRSRV(rrname="_sip._tcp.example.org", ttl=60, priority=1, weight=5, port=5060,
                                                  target="sip.example.org")),
        ("example.org", "SOA", DNSRRSOA(rrname="example.org", ttl=60, mname="ns1.example.org", rname="admin.example.org",
                                        serial=1, refresh=2, retry=3, expire=4, minimum=5)),
    ]
    for i, (name, qtype, rr) in enumerate(answers):
        query = DNS(id=0x100 + i, rd=1, qd=DNSQR(qname=name, qtype=qtype), ar=DNSRROPT(rclass=1232))
        reply = DNS(id=0x100 + i, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype=qtype), an=rr)
        w.add(udp_frame(c, r, 41000 + i, 53, bytes(query)))
        w.add(udp_frame(r, c, 53, 41000 + i, bytes(reply), smac=MAC_B, dmac=MAC_A))
    caa = DNSRR(rrname="example.org", type="CAA", ttl=60, rdata=b"\x00\x05issueletsencrypt.org")
    w.add(udp_frame(c, r, 41010, 53, bytes(DNS(id=0x200, rd=1, qd=DNSQR(qname="example.org", qtype="CAA")))))
    w.add(udp_frame(r, c, 53, 41010, bytes(DNS(id=0x200, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.org", qtype="CAA"),
                                                an=caa)), smac=MAC_B, dmac=MAC_A))
    return w.write()


def dnp3_crc(data: bytes) -> bytes:
    """CRC-16/DNP (reflected 0x3D65, init 0, xor out 0xFFFF), little-endian, as DNP3 link frames carry it."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", crc ^ 0xFFFF)


def dnp3_frame(app: bytes, *, dst: int, src: int, primary: bool) -> bytes:
    """One DNP3 link frame carrying a single-fragment transport segment and the application bytes ``app``."""
    user = bytes([0xC0]) + app  # transport: FIR | FIN, sequence 0
    ctrl = 0xC4 if primary else 0x44  # DIR | PRM, unconfirmed user data (or the reply direction)
    head = b"\x05\x64" + bytes([5 + len(user), ctrl]) + struct.pack("<HH", dst, src)
    body = b"".join(user[i:i + 16] + dnp3_crc(user[i:i + 16]) for i in range(0, len(user), 16))
    return head + dnp3_crc(head) + body


def modbus_adu(trans: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack("!HHHB", trans, 0, len(pdu) + 1, unit) + pdu


@fixture("ics_mix.pcap")
def fixture_ics_mix() -> bytes:
    """Modbus/TCP reads, a register write and an exception reply; DNP3 a read with its response and a cold restart (#206)."""
    w = Wire(start=1_700_900_000.0)
    hmi, plc, rtu = "10.8.0.10", "10.8.0.20", "10.8.0.30"
    t = Tcp(w, hmi, plc, 49100, 502).open()
    t.send(True, modbus_adu(1, 1, bytes([3]) + struct.pack("!HH", 0, 2)))  # read holding registers 0-1
    t.send(False, modbus_adu(1, 1, bytes([3, 4]) + struct.pack("!HH", 7, 9)))
    t.send(True, modbus_adu(2, 1, bytes([6]) + struct.pack("!HH", 1, 1234)))  # write single register 1
    t.send(False, modbus_adu(2, 1, bytes([6]) + struct.pack("!HH", 1, 1234)))
    t.send(True, modbus_adu(3, 1, bytes([3]) + struct.pack("!HH", 900, 1)))  # read past the end
    t.send(False, modbus_adu(3, 1, bytes([0x83, 2])))  # exception 2: illegal data address
    t.close()
    d = Tcp(w, hmi, rtu, 49200, 20000).open()
    d.send(True, dnp3_frame(bytes([0xC0, 0x01, 60, 1, 6]), dst=10, src=1, primary=True))  # READ class 0
    d.send(False, dnp3_frame(bytes([0xC0, 0x81, 0x00, 0x00]), dst=1, src=10, primary=False))  # RESPONSE, IIN 0
    d.send(True, dnp3_frame(bytes([0xC1, 0x0D]), dst=10, src=1, primary=True))  # COLD_RESTART
    d.send(False, dnp3_frame(bytes([0xC1, 0x81, 0x80, 0x00]), dst=1, src=10, primary=False))  # RESPONSE, IIN device restart
    d.close()
    return w.write()


@fixture("heartbleed.pcap")
def fixture_heartbleed() -> bytes:
    """A TLS heartbeat request that claims 16384 payload bytes but carries 3 (the Heartbleed probe), and an honest one (#234, #264)."""
    w = Wire(start=1_701_000_000.0)
    c, s = "10.9.0.66", "10.9.0.20"
    t = Tcp(w, c, s, 49300, 443).open()
    t.send(True, bytes.fromhex("1803020008") + bytes([1]) + struct.pack("!H", 0x4000) + b"PFX" + bytes(2))  # claims 16384
    t.close()
    h = Tcp(w, c, s, 49301, 443).open()
    beat = bytes([1]) + struct.pack("!H", 4) + b"PING" + bytes(16)  # type, payload_length 4, payload, 16 bytes padding
    h.send(True, bytes.fromhex("180303") + struct.pack("!H", len(beat)) + beat)
    h.close()
    return w.write()


@fixture("tunnels.pcap")
def fixture_tunnels() -> bytes:
    """An inner TCP/UDP exchange carried in GRE and in VXLAN, and one 802.1Q-tagged frame (#227)."""
    w = Wire(start=1_701_100_000.0)
    inner = ip_packet("192.168.50.10", "192.168.50.20", 17, udp_datagram("192.168.50.10", "192.168.50.20", 40001, 9999, b"PF-INNER"))
    gre = struct.pack("!HH", 0x0000, 0x0800) + inner  # GRE, no options, carrying IPv4
    w.add(ether(MAC_A, MAC_B, ip_packet("10.10.0.1", "10.10.0.2", 47, gre)))
    vx_inner = ether("02:00:00:00:00:aa", "02:00:00:00:00:bb", inner)
    vxlan = struct.pack("!II", 0x08000000, 4242 << 8) + vx_inner  # VNI 4242
    w.add(udp_frame("10.20.0.1", "10.20.0.2", 49999, 4789, vxlan))
    tagged = mac(MAC_B) + mac(MAC_A) + struct.pack("!HHH", 0x8100, 100, 0x0800) + ip_packet(
        "10.30.0.1", "10.30.0.2", 17, udp_datagram("10.30.0.1", "10.30.0.2", 40000, 53, b"\x00" * 12))
    w.add(tagged)
    return w.write()


def _arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(sender_mac) + _ip4(sender_ip) + mac(target_mac) + _ip4(target_ip)
    return ether(sender_mac, target_mac, body, ethertype=0x0806)


@fixture("arp_icmp.pcap")
def fixture_arp_icmp() -> bytes:
    """The gateway 10.0.0.1 claimed by two MACs (ARP spoofing) and an ICMP redirect from 10.0.0.254 (#280)."""
    w = Wire(start=1_701_200_000.0)
    w.add(_arp_reply("02:00:00:00:00:01", "10.0.0.1", MAC_A, "10.0.0.20"))
    w.add(_arp_reply("02:00:00:00:00:66", "10.0.0.1", MAC_A, "10.0.0.20"))
    w.add(_arp_reply("02:00:00:00:00:66", "10.0.0.1", MAC_A, "10.0.0.20"))  # repeated claim, one finding
    w.add(_arp_reply(MAC_B, "10.0.0.30", MAC_A, "10.0.0.20"))  # an ordinary, consistent reply
    original = ip_packet("10.0.0.20", "8.8.8.8", 17, udp_datagram("10.0.0.20", "8.8.8.8", 40000, 53, b"\x00" * 12))[:28]
    icmp = struct.pack("!BBH4s", 5, 1, 0, _ip4("10.0.0.66")) + original
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    w.add(ether("02:00:00:00:00:fe", MAC_A, ip_packet("10.0.0.254", "10.0.0.20", 1, icmp)))
    return w.write()


@fixture("devices.pcap")
def fixture_devices() -> bytes:
    """Three senders: a Google OUI, a Raspberry Pi OUI and a locally administered MAC with no vendor (#274)."""
    w = Wire(start=1_701_300_000.0)
    for src_mac, ip in (("00:1a:11:aa:bb:01", "10.40.0.1"), ("b8:27:eb:12:34:56", "10.40.0.2"), ("02:00:00:00:00:0c", "10.40.0.3")):
        for _ in range(2):  # repeated traffic, one row per MAC
            w.add(ether(src_mac, "ff:ff:ff:ff:ff:ff", ip_packet(ip, "10.40.0.255", 17, udp_datagram(ip, "10.40.0.255", 40002, 9999, b"PF-DEV"))))
    return w.write()


@fixture("capture_loss.pcap")
def fixture_capture_loss() -> bytes:
    """One TCP flow whose middle data segment was never captured, then ACKed by the receiver (#240)."""
    w = Wire(start=1_701_400_000.0)
    c, s = "10.50.0.1", "10.50.0.2"
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 40000, 8080, 1000, 0, 0x02))))
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 8080, 40000, 5000, 1001, 0x12))))
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 40000, 8080, 1001, 5001, 0x10))))
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 40000, 8080, 1001, 5001, 0x18, b"A" * 100))))
    # seq 1101..1200 is missing from the capture
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 40000, 8080, 1201, 5001, 0x18, b"C" * 100))))
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 8080, 40000, 5001, 1301, 0x10))))
    return w.write()


@fixture("ftp_odd_port.pcap")
def fixture_ftp_odd_port() -> bytes:
    """An FTP login on TCP 2121, a port tshark does not dissect as FTP unless told to (#254, decode-as)."""
    w = Wire(start=1_701_500_000.0)
    c, s = "10.60.0.1", "10.60.0.2"
    seq = {"c": 1001, "s": 7001}

    def send(from_client: bool, payload: bytes) -> None:
        src, dst, sp, dp = (c, s, 41000, 2121) if from_client else (s, c, 2121, 41000)
        side, other = ("c", "s") if from_client else ("s", "c")
        w.add(ether(MAC_A if from_client else MAC_B, MAC_B if from_client else MAC_A,
                    ip_packet(src, dst, 6, tcp_segment(src, dst, sp, dp, seq[side], seq[other], 0x18, payload))))
        seq[side] += len(payload)

    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 41000, 2121, 1000, 0, 0x02))))
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 2121, 41000, 7000, 1001, 0x12))))
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 41000, 2121, 1001, 7001, 0x10))))
    send(False, b"220 ready\r\n")
    send(True, b"USER admin\r\n")
    send(False, b"331 password please\r\n")
    send(True, b"PASS hunter2\r\n")
    send(False, b"230 logged in\r\n")
    return w.write()


@fixture("http_versions.pcap")
def fixture_http_versions() -> bytes:
    """An HTTP exchange whose client and server announce versioned software (#247)."""
    w = Wire(start=1_701_600_000.0)
    c, s = "10.70.0.1", "10.70.0.2"
    req = b"GET / HTTP/1.1\r\nHost: 10.70.0.2\r\nUser-Agent: curl/7.58.0\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\nContent-Length: 2\r\n\r\nok"
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 42000, 80, 1000, 0, 0x02))))
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 80, 42000, 9000, 1001, 0x12))))
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 42000, 80, 1001, 9001, 0x10))))
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 42000, 80, 1001, 9001, 0x18, req))))
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 80, 42000, 9001, 1001 + len(req), 0x18, resp))))
    return w.write()


@fixture("mail_logins.pcap")
def fixture_mail_logins() -> bytes:
    """Cleartext POP3 USER/PASS, IMAP LOGIN and SMTP AUTH PLAIN logins (#230)."""
    w = Wire(start=1_701_700_000.0)
    c, s = "10.80.0.1", "10.80.0.2"
    exchanges = (
        (41100, 110, [(False, b"+OK POP3 ready\r\n"), (True, b"USER alice\r\n"), (False, b"+OK\r\n"), (True, b"PASS secret1\r\n"), (False, b"+OK logged in\r\n")]),
        (41200, 143, [(False, b"* OK IMAP ready\r\n"), (True, b"a1 LOGIN bob secret2\r\n"), (False, b"a1 OK LOGIN completed\r\n")]),
        (41300, 25, [(False, b"220 mail ESMTP\r\n"), (True, b"EHLO c\r\n"), (False, b"250-mail\r\n250 AUTH PLAIN\r\n"),
                     (True, b"AUTH PLAIN AGNhcm9sAHNlY3JldDM=\r\n"), (False, b"235 2.7.0 Authentication successful\r\n")]),
    )
    for sport, dport, msgs in exchanges:
        seq = {"c": 1001, "s": 5001}
        w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, sport, dport, 1000, 0, 0x02))))
        w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, dport, sport, 5000, 1001, 0x12))))
        w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, sport, dport, 1001, 5001, 0x10))))
        for from_client, payload in msgs:
            src, dst, sp, dp = (c, s, sport, dport) if from_client else (s, c, dport, sport)
            side, other = ("c", "s") if from_client else ("s", "c")
            w.add(ether(MAC_A if from_client else MAC_B, MAC_B if from_client else MAC_A,
                        ip_packet(src, dst, 6, tcp_segment(src, dst, sp, dp, seq[side], seq[other], 0x18, payload))))
            seq[side] += len(payload)
    return w.write()
