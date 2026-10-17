"""Byte-built fixtures and packet helpers for the parity features (issues #199 onward).

Everything here is deterministic and carries valid IP/TCP/UDP checksums (so checksum validation, #209, stays
quiet on them) unless a builder asks for a bad one. ``make_fixtures.py`` merges ``FIXTURES`` into its table.
"""

from __future__ import annotations

import hashlib
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


def _ip6(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def ipv6_packet(src: str, dst: str, payload: bytes, *, next_header: int = 17, hop_limit: int = 64) -> bytes:
    header = struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, hop_limit, _ip6(src), _ip6(dst))
    return header + payload


def udp6_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = _ip6(src) + _ip6(dst) + struct.pack("!II", 17, length)
    c = csum(pseudo + head + payload) or 0xFFFF
    return head[:6] + struct.pack("!H", c) + payload


def udp6_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, *, smac: str = MAC_A,
               dmac: str = MAC_B) -> bytes:
    return ether(smac, dmac, ipv6_packet(src, dst, udp6_datagram(src, dst, sport, dport, payload)), ethertype=0x86dd)


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


# -- DHCPv6 builders (issue #220) ---------------------------------------------------------------

def dhcpv6_opt(opt_type: int, data: bytes) -> bytes:
    """A DHCPv6 option: 2-byte type + 2-byte length + data."""
    return struct.pack("!HH", opt_type, len(data)) + data


def duid_ll(mac_str: str) -> bytes:
    """DUID-LL (type 3, hardware type 1 = Ethernet) carrying a MAC address (RFC 8415 §11.4)."""
    return struct.pack("!HH", 3, 1) + mac(mac_str)


def dns_encode(name: str) -> bytes:
    """DNS label-encoded domain name (RFC 1035), null-terminated."""
    out = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return out + b"\x00"


def dhcpv6_message(msg_type: int, xid: int, *, options: bytes = b"") -> bytes:
    """A minimal DHCPv6 message: 1-byte type + 3-byte XID + options."""
    return struct.pack("!B", msg_type) + struct.pack("!I", xid)[1:] + options


def dhcpv6_ia_na(iaid: int, addr: str, pref_life: int, valid_life: int) -> bytes:
    """An IA_NA option (code 3) containing one IAADDR sub-option (code 5)."""
    ia = struct.pack("!III", iaid, 0, 0)
    iaaddr = _ip6(addr) + struct.pack("!II", pref_life, valid_life)
    ia += dhcpv6_opt(5, iaaddr)
    return dhcpv6_opt(3, ia)


@fixture("dhcpv6.pcap")
def fixture_dhcpv6() -> bytes:
    """A DHCPv6 Solicit/Advertise/Request/Reply exchange with hostname (option 39), vendor class (option 16),
    DNS server (option 23), and a delegated address (option 5 IAADDR), for host inventory (#220)."""
    w = Wire(start=1_700_100_000.0)
    cl_mac = "02:aa:bb:cc:dd:03"
    srv_mac = "02:00:00:00:00:01"
    cl_addr = "fe80::2aa:bbff:fecc:dd03"
    srv_addr = "fe80::1"
    xid = 0x42ab
    client_iaid = 0x42424242
    # SOLICIT (type 1): client -> ff02::1:2 (all DHCP servers/mcast)
    solicit_opts = dhcpv6_opt(1, duid_ll(cl_mac))  # OPTION_CLIENTID (1) wrapping DUID
    solicit_opts += dhcpv6_opt(6, struct.pack("!HH", 23, 24))  # ORO: request DNS_SERVERS(23) and DOMAIN_LIST(24)
    solicit_opts += dhcpv6_opt(39, bytes([0x01]) + dns_encode("pf-v6-laptop.example"))  # CLIENT_FQDN
    solicit_opts += dhcpv6_opt(16, struct.pack("!I", 9) + b"\x00\x00DHCPv6 client\x00")  # VENDOR_CLASS (16): ent + sub-option-len + data
    w.add(udp6_frame(cl_addr, "ff02::1:2", 546, 547, dhcpv6_message(1, xid, options=solicit_opts),
                     smac=cl_mac, dmac="33:33:ff:00:00:02"))
    # ADVERTISE (type 2): server -> client
    advertise_opts = dhcpv6_opt(2, duid_ll(srv_mac))  # OPTION_SERVERID (2)
    advertise_opts += dhcpv6_opt(1, duid_ll(cl_mac))  # OPTION_CLIENTID (1)
    advertise_opts += dhcpv6_ia_na(client_iaid, "2001:db8::100", 0, 3600)
    advertise_opts += dhcpv6_opt(23, _ip6("2001:4860:4860::8888") + _ip6("2001:4860:4860::8844"))  # DNS_SERVERS
    w.add(udp6_frame(srv_addr, cl_addr, 547, 546, dhcpv6_message(2, xid, options=advertise_opts),
                     smac=srv_mac, dmac=cl_mac))
    # REQUEST (type 3): client -> server
    request_opts = dhcpv6_opt(1, duid_ll(cl_mac))
    request_opts += dhcpv6_opt(2, duid_ll(srv_mac))
    request_opts += dhcpv6_ia_na(client_iaid, "2001:db8::100", 0, 3600)
    w.add(udp6_frame(cl_addr, srv_addr, 546, 547, dhcpv6_message(3, xid, options=request_opts),
                     smac=cl_mac, dmac=srv_mac))
    # REPLY (type 7): server -> client
    reply_opts = dhcpv6_opt(2, duid_ll(srv_mac))
    reply_opts += dhcpv6_opt(1, duid_ll(cl_mac))
    reply_opts += dhcpv6_ia_na(client_iaid, "2001:db8::100", 0, 3600)
    reply_opts += dhcpv6_opt(23, _ip6("2001:4860:4860::8888") + _ip6("2001:4860:4860::8844"))
    w.add(udp6_frame(srv_addr, cl_addr, 547, 546, dhcpv6_message(7, xid, options=reply_opts),
                     smac=srv_mac, dmac=cl_mac))
    return w.write()


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


@fixture("dns_dnssec.pcap")
def fixture_dns_dnssec() -> bytes:
    """SVCB, HTTPS, RRSIG, DNSKEY, DS, NSEC and NSEC3 answers (#229)."""

    from scapy.layers.dns import (
        DNS,
        DNSQR,
        DNSRRDNSKEY,
        DNSRRDS,
        DNSRRHTTPS,
        DNSRRNSEC,
        DNSRRNSEC3,
        DNSRROPT,
        DNSRRRSIG,
        DNSRRSVCB,
    )

    w = Wire(start=1_700_800_000.0)
    c, r = "10.7.0.10", "10.7.0.53"
    # (qtype, record, extra tshark fields to check)
    records = [
        ("SVCB", DNSRRSVCB(rrname="example.org", ttl=300, svc_priority=1, target_name="svc.example.org")),
        ("HTTPS", DNSRRHTTPS(rrname="example.org", ttl=300, svc_priority=1, target_name="cdn.example.org")),
        ("DNSKEY", DNSRRDNSKEY(rrname="example.org", ttl=300, flags=257, protocol=3, algorithm=13, publickey=b"\x01\x02")),
        ("DS", DNSRRDS(rrname="example.org", ttl=300, keytag=12345, algorithm=13, digesttype=2, digest=b"\xab\xcd")),
        ("NSEC", DNSRRNSEC(rrname="example.org", ttl=300, nextname="www.example.org", typebitmaps=[1])),
        ("NSEC3", DNSRRNSEC3(rrname="example.org", ttl=300, hashalg=1, flags=0, iterations=0, salt=b"",
                              hashlength=20, nexthashedownername=bytes(range(20)))),
        ("RRSIG", DNSRRRSIG(rrname="example.org", ttl=300, typecovered=1, algorithm=13, labels=3, originalttl=300,
                            expiration=1234567890, inception=1234500000, keytag=12345, signersname="example.org",
                            signature=b"\xab\xcd\xef")),
    ]
    for i, (qtype, rr) in enumerate(records):
        query = DNS(id=0x300 + i, rd=1, qd=DNSQR(qname="example.org", qtype=qtype), ar=DNSRROPT(rclass=1232))
        reply = DNS(id=0x300 + i, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname="example.org", qtype=qtype), an=rr)
        w.add(udp_frame(c, r, 42000 + i, 53, bytes(query)))
        w.add(udp_frame(r, c, 53, 42000 + i, bytes(reply), smac=MAC_B, dmac=MAC_A))
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


@fixture("rtp_quality.pcap")
def fixture_rtp_quality() -> bytes:
    """RTP media with measurable packet loss and interarrival jitter (#253).

    A minimal SIP/SDP exchange (INVITE + 200 OK advertising ``m=audio 20000
    RTP/AVP 8``) lets the index apply its UDP port 20000 -> RTP decode-as, so
    tshark actually dissects the media. Six PCMA packets (clock 8000 Hz,
    payload type 8) then flow on 10.0.0.20:20000 -> 10.0.0.10:20002 with SSRC
    0xAABBCCDD. Sequence numbers 0,1,2,5,6,7 -- packets 3 and 4 are dropped, so
    two holes out of eight expected -> 25.0% loss (matches
    ``tshark -z rtp,streams``). Timestamps advance 160 per packet (20 ms audio
    frames) but arrivals are irregular (12, 7, 9, 11, 11 ms apart), giving an
    RFC 3550 A.8 jitter of ~4.947 ms (tshark reports the same value as its
    *max* jitter; its *mean* jitter is the per-packet average instead).
    """
    w = Wire(start=1_700_100_000.0, step=0.0)
    # A tiny SIP call that advertises the RTP media port so the index can
    # decode the media as RTP.
    sdp = (
        b"v=0\r\no=alice 1 1 IN IP4 10.0.0.10\r\ns=rtp-quality\r\nt=0 0\r\n"
        b"m=audio 20000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
    )
    invite = (
        b"INVITE sip:bob@10.0.0.20 SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1\r\n"
        b"From: <sip:alice@10.0.0.10>;tag=1\r\nTo: <sip:bob@10.0.0.20>\r\n"
        b"Call-ID: rtp-quality-call@10.0.0.10\r\nCSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n" % len(sdp) + sdp
    )
    ok = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1\r\n"
        b"From: <sip:alice@10.0.0.10>;tag=1\r\nTo: <sip:bob@10.0.0.20>;tag=2\r\n"
        b"Call-ID: rtp-quality-call@10.0.0.10\r\nCSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n" % len(sdp) + sdp
    )
    w.add(udp_frame("10.0.0.10", "10.0.0.20", 5060, 5060, invite, smac=MAC_A, dmac=MAC_B), dt=0.0)
    w.add(udp_frame("10.0.0.20", "10.0.0.10", 5060, 5060, ok, smac=MAC_B, dmac=MAC_A), dt=0.05)
    seqs = [0, 1, 2, 5, 6, 7]
    tsvals = [0, 160, 320, 800, 960, 1120]
    arrivals = [0.100, 0.112, 0.119, 0.128, 0.139, 0.150]
    ssrc = 0xAABBCCDD
    for i in range(len(seqs)):
        rtp = struct.pack("!BBHII", 0x80, 8, seqs[i], tsvals[i], ssrc) + b"\x00" * 160
        frame = udp_frame("10.0.0.20", "10.0.0.10", 20000, 20002, rtp, smac=MAC_B, dmac=MAC_A)
        w.add(frame, dt=arrivals[i] if i == 0 else arrivals[i] - arrivals[i - 1])
    return w.write()


@fixture("connect_scans.pcap")
def fixture_connect_scans() -> bytes:
    """Connect scans that complete every handshake: 20 ports on one host, and port 445 on 20 hosts (#242)."""
    w = Wire(start=1_701_800_000.0)
    scanner = "10.90.0.66"

    def connect(dst: str, sport: int, dport: int) -> None:
        w.add(ether(MAC_A, MAC_B, ip_packet(scanner, dst, 6, tcp_segment(scanner, dst, sport, dport, 100, 0, 0x02))))
        w.add(ether(MAC_B, MAC_A, ip_packet(dst, scanner, 6, tcp_segment(dst, scanner, dport, sport, 900, 101, 0x12))))
        w.add(ether(MAC_A, MAC_B, ip_packet(scanner, dst, 6, tcp_segment(scanner, dst, sport, dport, 101, 901, 0x10))))
        w.add(ether(MAC_A, MAC_B, ip_packet(scanner, dst, 6, tcp_segment(scanner, dst, sport, dport, 101, 901, 0x14))))

    for i, port in enumerate(range(20, 40)):  # vertical: 20 ports on one host
        connect("10.90.0.10", 50000 + i, port)
    for i in range(20):  # horizontal: port 445 on 20 hosts
        connect(f"10.90.1.{i + 1}", 51000 + i, 445)
    return w.write()
    return w.write()


@fixture("os_ttls.pcap")
def fixture_os_ttls() -> bytes:
    """SYNs from three hosts a few hops away: initial TTL 128 (Windows), 64 (Linux/Unix) and 255 (network device) (#244)."""
    w = Wire(start=1_701_900_000.0)
    server = "10.95.0.1"
    for i, (host, ttl) in enumerate((("10.95.0.10", 125), ("10.95.0.20", 61), ("10.95.0.30", 252))):
        for n in range(2):  # two SYNs each: one row per host
            w.add(ether(MAC_A, MAC_B, ip_packet(host, server, 6, tcp_segment(host, server, 52000 + i * 10 + n, 443, 7000, 0, 0x02), ttl=ttl)))
    return w.write()


@fixture("dns_plus_tls.pcap")
def fixture_dns_plus_tls() -> bytes:
    """A capture with only DNS and TLS traffic, used to prove protocol-based skip of absent-protocol passes (#328).

    Three DNS queries over UDP and one TLS ClientHello over TCP. No SIP, SMB, SSH, QUIC, RTP, Telnet, NTP, etc.
    """
    w = Wire(start=1_701_950_000.0)
    c, r = "10.99.0.10", "10.99.0.53"
    for i, name in enumerate(("host1.example", "host2.example", "host3.example")):
        w.add(udp_frame(c, r, 44000 + i, 53, dns_wire(name, 0x3000 + i)))
        w.add(udp_frame(r, c, 53, 44000 + i, b"\x00" * 12, smac=MAC_B, dmac=MAC_A))
    t = Tcp(w, c, "10.99.0.20", 45000, 443).open()
    # A TLS 1.3 ClientHello record (content type 0x16, version 0x0303, then the hello).
    hello = bytes.fromhex(
        "010001880303" + "00" * 32 +  # handshake type 1, length, version, random
        "00"  # session id length
        + "0010"  # cipher suites length
        + "1301130213031304c02f"  # a few cipher suites
        + "01"  # extensions length
        + "0000"  # server_name extension (empty for this test)
    )
    record = bytes([0x16, 0x03, 0x03]) + struct.pack("!H", len(hello)) + hello
    t.send(True, record)
    t.close()
    return w.write()


def tls_clienthello(sni: str) -> bytes:
    """A minimal TLS 1.2 ClientHello carrying one cipher and an SNI extension (#239)."""
    # Record: content-type 0x16 (handshake), version 0x0301, length, body.
    # Handshake body: type(1) + length(3) + ClientHello(version(2) + random(32) + session + ciphers + comps + extensions).
    rand = b"\x5a" * 32  # 32-byte TLS random (GMT unix time + 28 random bytes)
    session_id = b"\x00"  # empty session id
    ciphers = struct.pack("!H", 0x1301)  # TLS_AES_128_GCM_SHA256
    comps = b"\x01\x00"  # one compression method: null
    name_bytes = sni.encode()
    sni_ext = (
        struct.pack("!HH", 0x0000, 5 + len(name_bytes))  # extension type=0 (SNI), length
        + struct.pack("!H", len(name_bytes) + 3)  # server_name list length
        + b"\x00"  # name_type=0 (host_name)
        + struct.pack("!H", len(name_bytes)) + name_bytes
    )
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext
    hs_payload = (
        struct.pack("!H", 0x0303)  # ClientHello version TLS 1.2
        + rand
        + session_id
        + struct.pack("!H", 0x0002) + ciphers  # cipher_suites
        + comps
        + ext_block
    )
    hs_body = b"\x01" + struct.pack("!I", len(hs_payload))[1:] + hs_payload  # type + 3-byte length + payload
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs_body)) + hs_body
    return record


@fixture("hostnames.pcap")
def fixture_hostnames() -> bytes:
    """Interesting hostnames in DNS, TLS SNI and HTTP Host that Zeek would call Interesting_Hostname_Login (#239).

    Carries three hostnames whose first label is login/admin/signin-style (must be flagged), and one
    that is not (www.example.com, must stay silent), across all three surfaces.
    """
    w = Wire(start=1_701_950_000.0)
    c, r = "10.7.0.10", "10.7.0.53"  # client and DNS resolver
    # DNS queries (cleartext): login, www (boring), admin-panel, signin
    for i, name in enumerate(("login.example.com", "www.example.com", "admin-panel.example.com", "signin.internal.corp")):
        q = dns_wire(name, 0x4000 + i, 1)
        w.add(udp_frame(c, r, 42000 + i, 53, q))
        labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        question = labels + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + _ip4("93.184.216.34")
        reply = struct.pack("!HHHHHH", 0x4000 + i, 0x8180, 1, 1, 0, 0) + question + answer
        w.add(udp_frame(r, c, 53, 42000 + i, reply, smac=MAC_B, dmac=MAC_A))
    # TLS ClientHello with SNI admin-panel.example.com
    srv = "10.7.0.20"
    t = Tcp(w, c, srv, 49000, 443).open()
    t.send(True, tls_clienthello("admin-panel.example.com"))
    t.close()
    # HTTP request with Host: signin.internal.corp
    h = Tcp(w, c, srv, 49001, 80).open()
    h.send(True, b"GET / HTTP/1.1\r\nHost: signin.internal.corp\r\n\r\n")
    h.close()
    return w.write()


def _nbns_name(name: str) -> bytes:
    """RFC 1002 first-level NetBIOS name: a 0x20 (32) length byte + 32 encoded bytes.

    The 16-byte NetBIOS name (15 space-padded bytes plus a trailing 0x00) becomes two
    ASCII characters ``0x41 + nibble`` per byte. The trailing 0x00 byte is what makes
    tshark print the suffix as ``<00>`` (a workstation/redirector name) rather than ``<20>``.
    """
    padded = name.encode().ljust(15)[:15] + b"\x00"
    out = bytearray(b"\x20")
    for b in padded:
        out += bytes((0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return bytes(out)


def _nbns_query(tid: int, name: str) -> bytes:
    """NB name query (opcode 0): broadcast desired/available flags set."""
    header = struct.pack("!HHHHHH", tid, 0x0300, 1, 0, 0, 0)
    return header + _nbns_name(name) + b"\x00" + struct.pack("!HH", 0x0020, 0x0001)


def _nbns_response(tid: int, name: str, addr: str, *, nb_flags: int) -> bytes:
    """NB name query response carrying one NB (type 0x20) answer: name-type flags + 4-byte address."""
    rdata = struct.pack("!H", nb_flags) + _ip4(addr)
    header = struct.pack("!HHHHHH", tid, 0x8380, 0, 1, 0, 0)
    answer = _nbns_name(name) + b"\x00" + struct.pack("!HH", 0x0020, 0x0001) + struct.pack("!IH", 300, len(rdata)) + rdata
    return header + answer


@fixture("netbios_names.pcap")
def fixture_netbios_names() -> bytes:
    """NBNS name resolution: two answered names (one group, one B-node server) and one unanswered query (#221).

    Verified against tshark 4.6.6: frames 1-5 decode as NBNS with no malformed packets.
    """
    w = Wire(start=1_702_000_000.0)
    client, server = "192.168.56.10", "192.168.56.1"
    w.add(udp_frame(client, server, 137, 137, _nbns_query(0x1111, "WORKGROUP")))
    w.add(udp_frame(server, client, 137, 137, _nbns_response(0x1111, "WORKGROUP", server, nb_flags=0x8400),
                     smac=MAC_B, dmac=MAC_A))
    w.add(udp_frame(client, server, 137, 137, _nbns_query(0x2222, "PF-FILESRV"), dmac="ff:ff:ff:ff:ff:ff"))
    w.add(udp_frame(server, client, 137, 137, _nbns_response(0x2222, "PF-FILESRV", "192.168.56.20", nb_flags=0x0400),
                     smac=MAC_B, dmac=MAC_A))
    w.add(udp_frame(client, server, 137, 137, _nbns_query(0x3333, "GHOSTBOX"), dmac="ff:ff:ff:ff:ff:ff"))
    return w.write()


@fixture("slice_hosts.pcap")
def fixture_slice_hosts() -> bytes:
    """Seven frames over three distinct conversations, for the slicer (#256).

    Frame numbering is 1-based, matching every other tool's packet list:
      1,2,3  TCP 10.96.0.1:40000 -> 10.96.0.2:80   (SYN, SYN-ACK, ACK)
      4,5,6  TCP 10.96.0.1:40001 -> 10.96.0.3:80   (SYN, SYN-ACK, ACK)
      7      UDP 10.96.0.4:53000 -> 10.96.0.9:53    (one DNS query)
    So a host slice on 10.96.0.2 yields frames 1-3, a slice on 10.96.0.9 yields only
    frame 7, and the two TCP flows are told apart by the client port alone.
    """
    w = Wire(start=1_702_000_000.0)
    c = "10.96.0.1"
    Tcp(w, c, "10.96.0.2", 40000, 80, isn_c=1000, isn_s=5000).open()
    Tcp(w, c, "10.96.0.3", 40001, 80, isn_c=2000, isn_s=6000).open()
    w.add(udp_frame("10.96.0.4", "10.96.0.9", 53000, 53, b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))
    return w.write()


@fixture("http_headers.pcap")
def fixture_http_headers() -> bytes:
    """Two HTTP responses: one with no security headers, one with the full set (#271)."""
    w = Wire(start=1_702_000_000.0)
    s = "10.97.0.2"

    def exchange(client: str, sport: int, resp_headers: bytes) -> None:
        req = b"GET / HTTP/1.1\r\nHost: " + s.encode() + b"\r\n\r\n"
        resp = b"HTTP/1.1 200 OK\r\n" + resp_headers + b"Content-Length: 2\r\n\r\nok"
        w.add(ether(MAC_A, MAC_B, ip_packet(client, s, 6, tcp_segment(client, s, sport, 80, 1000, 0, 0x02))))
        w.add(ether(MAC_B, MAC_A, ip_packet(s, client, 6, tcp_segment(s, client, 80, sport, 9000, 1001, 0x12))))
        w.add(ether(MAC_A, MAC_B, ip_packet(client, s, 6, tcp_segment(client, s, sport, 80, 1001, 9001, 0x10))))
        w.add(ether(MAC_A, MAC_B, ip_packet(client, s, 6, tcp_segment(client, s, sport, 80, 1001, 9001, 0x18, req))))
        w.add(ether(MAC_B, MAC_A, ip_packet(s, client, 6, tcp_segment(s, client, 80, sport, 9001, 1001 + len(req), 0x18, resp))))

    exchange("10.97.0.10", 42000, b"Server: nginx\r\n")
    exchange("10.97.0.11", 42001,
             b"Strict-Transport-Security: max-age=31536000\r\n"
             b"Content-Security-Policy: default-src 'self'\r\n"
             b"X-Content-Type-Options: nosniff\r\n"
             b"X-Frame-Options: DENY\r\n")
    return w.write()


def _http_get(w, client: str, server: str, sport: int, uri: str, host: str = "shop.example") -> None:
    """One full HTTP/1.1 GET on a fresh connection, reusing the module's Tcp helper."""
    tcp = Tcp(w, client, server, sport, 80).open()
    req = f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.58.0\r\n\r\n".encode()
    resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nok"
    tcp.send(True, req)
    tcp.send(False, resp)
    tcp.close()


@fixture("web_attack.pcap")
def fixture_web_attack() -> bytes:
    """HTTP requests carrying SQLi, XSS, LFI, path traversal and command-injection URIs (#233).

    Each request goes to its own client IP so a finding can be attributed to exactly one
    payload. The last request (client 10.61.0.9) is the benign control.
    """
    w = Wire(start=1_701_900_000.0)
    server = "10.61.0.1"
    payloads = [
        # SQL injection: tautology with a comment terminator, in the query string.
        ("10.61.0.2", "/items.php?id=1%27%20OR%20%271%27%3D%271%27--%20"),
        # XSS: script tag with an onerror handler, reflected in the path.
        ("10.61.0.3", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        # Local file inclusion: a /etc/passwd read through a PHP filter chain.
        ("10.61.0.4", "/index.php?page=php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-decoded%7Bresource%3D/etc/passwd%7D"),
        # Path traversal: ../ repeated to escape the web root.
        ("10.61.0.5", "/static/../../../../etc/shadow"),
        # OS command injection: a pipe to /bin/sh inside a parameter.
        ("10.61.0.6", "/cgi-bin/luci?cmd=%3Bcat+/etc/passwd%7Csh"),
        # Benign control: an ordinary path, must never match a signature.
        ("10.61.0.9", "/products/list?page=2&sort=name"),
    ]
    for i, (client, uri) in enumerate(payloads):
        _http_get(w, client, server, 41000 + i, uri)
    return w.write()


def _tls_ext(etype: int, value: bytes = b"") -> bytes:
    """One TLS extension: type (2 bytes) + length (2 bytes) + value."""
    return struct.pack("!HH", etype, len(value)) + value


def _tls_record(content_type: int, payload: bytes) -> bytes:
    """One TLS record: content_type + version(0x0303) + length + payload."""
    return struct.pack("!BHH", content_type, 0x0303, len(payload)) + payload


@fixture("ech_0rtt_handshake.pcap")
def fixture_ech_0rtt_handshake() -> bytes:
    """A TLS 1.3 ClientHello offering Encrypted Client Hello (extension 0xfe0d, RFC 9849)
    and early_data (extension 42, RFC 8446), followed by the ServerHello. A passive
    check reports both extensions as offered, since tshark does not decrypt them (#270)."""
    w = Wire(start=1_701_950_000.0)
    c, s = "10.99.0.10", "10.99.0.20"
    t = Tcp(w, c, s, 51000, 443).open()
    # ClientHello: SNI + early_data(42) + supported_versions(43) + key_share(51) + ECH(0xfe0d=65037)
    sni_name = b"shop.example"
    sni_entry = b"\x00" + struct.pack("!H", len(sni_name)) + sni_name
    sni = _tls_ext(0, struct.pack("!H", len(sni_entry)) + sni_entry)
    early_data = _tls_ext(42, b"")
    sup_versions = _tls_ext(43, struct.pack("!B", 2) + struct.pack("!HH", 0x0304, 0x0303))
    key_share = _tls_ext(51, struct.pack("!HH", 0x001d, 32) + b"\x00" * 32)  # x25519, 32-byte key
    ech = _tls_ext(65037, b"\x00" * 8)
    extensions = sni + early_data + sup_versions + key_share + ech
    ch_body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    handshake = struct.pack("B", 1) + struct.pack("!I", len(ch_body))[1:] + ch_body
    t.send(True, _tls_record(22, handshake))
    t.close()
    return w.write()



# -- RADIUS (#222) ---------------------------------------------------------------------------
NAS, AAA = "10.90.0.1", "10.90.0.2"


def radius(code: int, ident: int, attrs: bytes, authenticator: bytes) -> bytes:
    return struct.pack("!BBH", code, ident, 20 + len(attrs)) + authenticator + attrs


def attr(t: int, v: bytes) -> bytes:
    return struct.pack("!BB", t, len(v) + 2) + v


def radius_password(secret: bytes, request_authenticator: bytes, password: bytes) -> bytes:
    """RFC 2865 s5.2 User-Password: the padded secret XORed with MD5(secret + Request Authenticator)."""
    padded = secret + b"\x00" * ((16 - len(secret) % 16) % 16)
    digest = hashlib.md5(secret + request_authenticator).digest()
    stream = (digest * (len(padded) // 16 + 1))[: len(padded)]
    return bytes(a ^ b for a, b in zip(padded, stream, strict=True))


@fixture("radius_logins.pcap")
def fixture_radius_logins() -> bytes:
    """Two RADIUS Access-Requests and an Access-Reject (#222)."""
    w = Wire(start=1_701_800_000.0)
    secret = b"s3cr3t-radius"
    req_auth = bytes(range(16))

    # Verified with tshark: username=alice, Calling-Station-Id=00-11-22-33-44-55, id=7.
    req = radius(1, 7, attr(1, b"alice")
                 + attr(2, radius_password(secret, req_auth, b""))
                 + attr(31, b"00-11-22-33-44-55")
                 + attr(40, b"tunnel-secret"), req_auth)
    # Verified with tshark: username=bob, id=9, Framed-IP-Address carried in the reply.
    second = radius(1, 9, attr(1, b"bob")
                    + attr(2, radius_password(secret, req_auth, b""))
                    + attr(31, b"00-11-22-33-44-66"), req_auth)
    # Verified with tshark: code 3 Access-Reject, id 7, matching the first request.
    reject = radius(3, 7, b"", req_auth)

    w.add(udp_frame(NAS, AAA, 51234, 1812, req, smac=MAC_A, dmac=MAC_B))
    w.add(udp_frame(NAS, AAA, 51234, 1812, second, smac=MAC_A, dmac=MAC_B))
    w.add(udp_frame(AAA, NAS, 1812, 51234, reject, smac=MAC_B, dmac=MAC_A))
    return w.write()


# --------------------------------------------------------------------------
# VPN handshakes (#223)
# --------------------------------------------------------------------------
@fixture("vpn_handshakes.pcap")
def fixture_vpn_handshakes() -> bytes:
    """IKE/IPsec (ISAKMP IKE_SA_INIT on UDP 500), WireGuard (handshake initiation on UDP 51820) and
    OpenVPN (P_CONTROL_HARD_RESET_CLIENT_V1 on UDP 1194): the three VPN handshakes the issue asks for.
    Each protocol gets its own flow so the detector attributes findings per flow."""
    import struct as _s

    w = Wire(start=1_702_000_000.0)
    c, s = "10.0.0.10", "10.0.0.20"

    # -- IKE/IPsec: ISAKMP IKE_SA_INIT on UDP 500 --
    # ISAKMP header (RFC 2408, 28 bytes): SPIi(8) SPIr(8) next_payload(1) version(1)
    #   exchange_type(1) flags(1) message_id(4) length(4)
    # IKE_SA_INIT exchange type = 34 (verified from tshark -G values).
    # A bare ISAKMP header is not dissected by tshark; it needs a trailing SA payload.
    sa_payload = _s.pack("!BBHI", 13, 0, 20, 1) + _s.pack("!I", 1)  # next=13(last), len=20, DOI=1(ipsec), situation
    isakmp = _s.pack("!QQ", 0x1122334455667788, 0)  # SPIi, SPIr
    isakmp += _s.pack("!BBBI", 1, 0x10, 34, 0)  # next=SA(1), ver 1.0, IKE_SA_INIT(34), flags=0
    isakmp += _s.pack("!I", 28 + len(sa_payload))
    isakmp += sa_payload
    w.add(udp_frame(c, s, 500, 500, isakmp))
    w.add(udp_frame(s, c, 500, 500, isakmp))  # responder reply

    # -- WireGuard: handshake initiation (message type 1) on UDP 51820 --
    # Message type is a little-endian uint32 at offset 0; 1 = Handshake Initiation.
    wg = _s.pack("<I", 1) + b"\x00" * 3 + _s.pack("<I", 0xAABBCCDD)
    wg += b"\x00" * 32 + b"\x00" * 48 + b"\x00" * 36 + b"\x00" * 16 + b"\x00" * 16
    w.add(udp_frame(c, s, 51820, 51820, wg))
    wg_resp = _s.pack("<I", 2) + b"\x00" * 3 + _s.pack("<I", 0xAABBCCDD)
    wg_resp += b"\x00" * 32 + b"\x00" * 48 + b"\x00" * 16 + b"\x00" * 16
    w.add(udp_frame(s, c, 51820, 51820, wg_resp))

    # -- OpenVPN: P_CONTROL_HARD_RESET_CLIENT_V1 (opcode=1, first byte 0x08) on UDP 1194 --
    # OpenVPN opcode is the top 5 bits of the first payload byte.
    # 0x08 >> 3 = 1 = P_CONTROL_HARD_RESET_CLIENT_V1.
    ovpn = bytes([0x08]) + b"\x00" * 8 + b"\x01" + b"\x00" * 3 + b"\x00" * 32
    w.add(udp_frame(c, s, 1194, 1194, ovpn))
    ovpn_ack = bytes([0x08]) + b"\x00" * 8 + b"\x01" + b"\x00" * 3 + b"\x00" * 32
    w.add(udp_frame(s, c, 1194, 1194, ovpn_ack))
    return w.write()


def _rdp_coap(data: bytes, *, src: str, dst: str, sport: int, dport: int, seq: int = 0, ack: int = 0, flags: int = 0) -> bytes:
    """Build an RDP/COTP encapsulated TPKT packet."""
    # COTP header (ISO 9548)
    cotp = struct.pack(">BBH", 0xD0, 0x00, len(data)) + data  # COTP TPDU with Length Indicator
    # TPKT header (ISO 10035) - for RDP
    tpkt = struct.pack(">BBH", 0x03, 0x00, len(cotp) + 4)[:2] + struct.pack(">H", len(cotp) + 4) + cotp
    return tcp_segment(src, dst, sport, dport, seq, ack, flags, tpkt)


@fixture("rdp_nat.pcap")
def fixture_rdp_nat() -> bytes:
    """RDP negotiation request with TLS, cookie and client name (#218).
    
    Simulates a Windows RDP client connecting to an RDP server:
    - Client requests TLS security (requestedProtocols = 0x01)
    - Server responds with selected protocol (0x01 = TLS)
    """
    import struct
    
    w = Wire(start=1_702_000_000.0)
    client, server = "10.100.0.50", "10.100.0.10"
    cl_mac, sv_mac = "02:aa:bb:cc:dd:01", "02:bb:cc:dd:ee:01"
    
    # TCP handshake
    t = Tcp(w, client, server, 49000, 3389, cmac=cl_mac, smac=sv_mac).open()
    
    # Build RDP Negotiation Request packet
    # RDP PDU: Type (1 byte), Flags (1 byte), Length (2 bytes), RequestedProtocols (4 bytes)
    # Type=1 means Negotiation Request
    rdp_req_body = struct.pack("<BBHI", 1, 0, 8, 0x01)  # Type=1, Flags=0, Length=8, RequestedProtocols=0x01 (TLS)
    # COTP header: ConnectorId=0xD0, Length Indicator=5 (includes Length Indicator field)
    cotp_header = struct.pack("<BHB", 0xD0, 5, 0)
    rdp_cotp = cotp_header + rdp_req_body
    # TPKT header: Version=3, Reserved=0, Length (big endian)
    tpkt_len = len(rdp_cotp) + 4
    tpkt_header = struct.pack(">BBH", 3, 0, tpkt_len)
    rdp_packet = tpkt_header + rdp_cotp  # 16 bytes total
    
    t.send(True, rdp_packet)
    
    # RDP Negotiation Response (Type = 2)
    # Server selects TLS (SelectedProtocol = 0x01)
    rdp_resp_body = struct.pack("<BBHI", 2, 0, 8, 0x01)  # Type=2, Flags=0, Length=8, SelectedProtocol=0x01
    cotp_header_resp = struct.pack("<BHB", 0xD0, 5, 0)
    rdp_cotp_resp = cotp_header_resp + rdp_resp_body
    tpkt_len_resp = len(rdp_cotp_resp) + 4
    tpkt_header_resp = struct.pack(">BBH", 3, 0, tpkt_len_resp)
    rdp_packet_resp = tpkt_header_resp + rdp_cotp_resp
    
    t.send(False, rdp_packet_resp)
    
    # Close the TCP connection
    t.close()
    return w.write()


# --------------------------------------------------------------------------
# PostgreSQL (pgsql) and Redis (RESP) dissection (#225)
# --------------------------------------------------------------------------

def _pgsql_startup(user: str, database: str) -> bytes:
    """PostgreSQL StartupMessage: length(4) + protocol_version(4) + key\x00val\x00... + \x00."""
    params = b"user\x00" + user.encode() + b"\x00database\x00" + database.encode() + b"\x00\x00"
    body = struct.pack("!I", 0x00030000) + params  # protocol version 3.0
    return struct.pack("!I", len(body) + 4) + body


def _pgsql_auth_request(authtype: int) -> bytes:
    """Server Authentication request ('R' + length 8 + authtype)."""
    return b"R" + struct.pack("!II", 8, authtype)


def _pgsql_password_message(password: str) -> bytes:
    """Client PasswordMessage ('p' + length + password + \\x00)."""
    body = password.encode() + b"\x00"
    return b"p" + struct.pack("!I", len(body) + 4) + body


def _pgsql_simple_query(query: str) -> bytes:
    """Client Simple Query ('Q' + length + query + \\x00)."""
    body = query.encode() + b"\x00"
    return b"Q" + struct.pack("!I", len(body) + 4) + body


def _pgsql_ready_for_query() -> bytes:
    return b"Z" + struct.pack("!I", 5) + b"I"


def _pgsql_command_complete(tag: str) -> bytes:
    body = tag.encode() + b"\x00"
    return b"C" + struct.pack("!I", len(body) + 4) + body


@fixture("pgsql_redis.pcap")
def fixture_pgsql_redis() -> bytes:
    """A PostgreSQL cleartext-password exchange with a startup (user, database), an auth request, a password,
    and a simple query; plus a Redis AUTH (password never logged) and a GET key (#225)."""
    w = Wire(start=1_702_000_000.0)
    c, s = "10.10.0.10", "10.10.0.20"
    # PostgreSQL on port 5432
    t = Tcp(w, c, s, 51000, 5432).open()
    t.send(True, _pgsql_startup("admin", "appdb"))             # startup: user=admin, database=appdb
    t.send(False, _pgsql_auth_request(1))                       # server: cleartext-password auth (type 1)
    t.send(True, _pgsql_password_message("pf-pgsql-pw"))        # client: password (must never appear)
    t.send(False, _pgsql_auth_request(0))                       # server: AuthenticationOk (type 0)
    t.send(False, _pgsql_ready_for_query())                     # server: ready
    t.send(True, _pgsql_simple_query("SELECT 1 FROM users"))   # client: simple query
    t.send(False, _pgsql_command_complete("SELECT 1"))          # server: command complete
    t.send(False, _pgsql_ready_for_query())                     # server: ready
    t.close()
    # Redis on port 6379
    t = Tcp(w, c, s, 51001, 6379).open()
    t.send(True, b"*2\r\n$4\r\nAUTH\r\n$12\r\npf-redis-pw\r\n")  # AUTH password (must never appear)
    t.send(False, b"+OK\r\n")
    t.send(True, b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n")          # GET mykey
    t.send(False, b"$5\r\nhello\r\n")
    t.send(True, b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$5\r\nvalue\r\n")  # SET mykey value (value never logged)
    t.send(False, b"+OK\r\n")
    t.close()
    return w.write()


@fixture("irc_socks_creds.pcap")
def fixture_irc_socks_creds() -> bytes:
    """IRC PASS, NickServ IDENTIFY, and SOCKS5 username/password credentials in cleartext (#231)."""
    w = Wire(start=1_702_000_000.0)
    irc_client = "10.0.0.10"
    irc_server = "10.0.0.20"
    socks_client = "10.0.0.30"
    socks_server = "10.0.0.40"
    
    # IRC PASS command and NickServ IDENTIFY on port 6667
    # Use a single Twitch-style IRC session
    irc = Tcp(w, irc_client, irc_server, 45000, 6667)
    irc.open()
    irc.send(True, b"PASS my-irc-password-123\r\n")
    irc.send(True, b"NICK testuser\r\n")
    irc.send(True, b"USER testuser 0 * :Test User\r\n")
    irc.send(True, b"PRIVMSG NickServ :IDENTIFY nickserv-secret\r\n")
    
    # SOCKS5 username/password auth (port 1080)
    # SOCKSv5 greeting: version 5, 2 auth methods (0x00 = no auth, 0x02 = user/pass)
    socks_greeting = bytes([0x05, 0x02, 0x00, 0x02])
    # SOCKS5 subnegotiation for username/password (RFC 1929):
    # version 1, username length, username, password length, password
    socks_auth = bytes([0x01, len(b"socksuser"), *b"socksuser", len(b"sockspass"), *b"sockspass123"])
    
    socks = Tcp(w, socks_client, socks_server, 45002, 1080)
    socks.open()
    socks.send(True, socks_greeting)
    socks.send(False, bytes([0x05, 0x02]))  # version 5, user/pass auth selected
    socks.send(True, socks_auth)
    socks.send(False, bytes([0x05, 0x00]))  # version 5, status 0 = succeeded
    return w.write()


@fixture("rfb_vnc.pcap")
def fixture_rfb_vnc() -> bytes:
    """A complete RFB/VNC handshake: version 3.8, server offers None (1) + VNC (2) auth,
    client picks None, auth succeeds, ServerInit carries desktop name 'Test Desktop' (#219).

    Security types: 1 = None, 2 = VNC (challenge/response). The None auth path is used so
    tshark emits a clean 4-byte auth-result field and a full ServerInit with a desktop name.
    """
    w = Wire(start=1_702_000_000.0)
    c, s = "10.100.0.10", "10.100.0.20"
    seq = {"c": 1000, "s": 5000}

    def send(from_client: bool, payload: bytes) -> None:
        sport, dport = (59000, 5900) if from_client else (5900, 59000)
        src, dst = (c, s) if from_client else (s, c)
        side, other = ("c", "s") if from_client else ("s", "c")
        w.add(ether(MAC_A if from_client else MAC_B, MAC_B if from_client else MAC_A,
                    ip_packet(src, dst, 6, tcp_segment(src, dst, sport, dport, seq[side], seq[other], 0x18, payload))))
        seq[side] += len(payload)

    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 59000, 5900, 1000, 0, 0x02))))
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 5900, 59000, 5000, 1001, 0x12))))
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 59000, 5900, 1001, 5001, 0x10))))
    # RFB version string exchange (3.8)
    send(False, b"RFB 003.008\n")
    send(True, b"RFB 003.008\n")
    # Server lists security types: None (1) and VNC (2)
    send(False, struct.pack("B", 2) + bytes([1, 2]))
    # Client selects None auth (1)
    send(True, bytes([1]))
    # Server auth result for None: 4 bytes, 0 = OK
    send(False, struct.pack(">I", 0))
    # ClientInit: shared desktop flag (1 = True)
    send(True, bytes([1]))
    # ServerInit: width(2) + height(2) + pixel_format(16) + name_len(4) + name
    pixel_format = bytes([8, 1, 0, 0, 7, 0, 7, 0, 3, 0, 3, 0, 0, 0, 0, 0])
    name = b"Test Desktop"
    server_init = struct.pack(">HH", 800, 600) + pixel_format + struct.pack(">I", len(name)) + name
    send(False, server_init)
    return w.write()


def stun_msg(msg_type: int, tid: bytes, body: bytes = b"") -> bytes:
    """One RFC 5389 STUN message. ``tid`` is the 12-byte transaction id."""
    return struct.pack("!HHI", msg_type, len(body), 0x2112A442) + tid + body


def stun_xor_mapped_address(port: int, addr: str) -> bytes:
    """XOR-MAPPED-ADDRESS attribute (RFC 5389 §14.2), IPv4 family, port in host order.

    Per RFC 5389 the port is XOR'd with the most significant 16 bits of the magic cookie and the
    address with the whole 32-bit cookie, so tshark decodes both back out again.
    """
    ip = struct.unpack("!I", socket.inet_aton(addr))[0]
    xport = port ^ (0x2112A442 >> 16)
    xaddr = ip ^ 0x2112A442
    return struct.pack("!HH", 0x0020, 8) + struct.pack("!B", 0) + struct.pack("!B", 0x01) + struct.pack("!H", xport) + struct.pack("!I", xaddr)


@fixture("stun_rtsp.pcap")
def fixture_stun_rtsp() -> bytes:
    """One STUN BINDING-REQUEST/RESPONSE pair with an XOR-MAPPED-ADDRESS, and a short RTSP OPTIONS->200 +
    DESCRIBE->404 exchange on TCP/554 (#224)."""
    w = Wire(start=1_702_000_000.0)
    tid = bytes.fromhex("00112233445566778899aabb")
    client, server = "10.10.0.1", "10.10.0.2"
    # STUN: binding request, then a success response carrying XOR-MAPPED-ADDRESS 192.0.2.33:4432.
    w.add(udp_frame(client, server, 49722, 3478, stun_msg(0x0001, tid)))
    w.add(udp_frame(server, client, 3478, 49722, stun_msg(0x0101, tid, stun_xor_mapped_address(4432, "192.0.2.33")),
                    dmac=MAC_A, smac=MAC_B))
    # RTSP over TCP/554: OPTIONS -> 200 OK, then DESCRIBE -> 404.
    t = Tcp(w, client, server, 49300, 554)
    t.open()
    t.send(True, b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: qa\r\n\r\n")
    t.send(False, b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, TEARDOWN\r\n\r\n")
    t.send(True, b"DESCRIBE rtsp://10.10.0.2:554/stream/track1 RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n")
    t.send(False, b"RTSP/1.0 404 Stream Not Found\r\nCSeq: 2\r\n\r\n")
    t.close()
    return w.write()


def _bencode(v: object) -> bytes:
    """Minimal bencode encoder with sorted dict keys (as the bt-dht spec and tshark's dissector demand)."""
    if isinstance(v, bool):
        return b"i%d" % int(v) + b"e"
    if isinstance(v, int):
        return b"i%d" % v + b"e"
    if isinstance(v, bytes):
        return b"%d:" % len(v) + v
    if isinstance(v, str):
        b = v.encode()
        return b"%d:" % len(b) + b
    if isinstance(v, dict):
        out = b"d"
        for k in sorted(v):  # bencode requires sorted keys; tshark's bt-dht heuristic only fires on sorted input
            out += _bencode(k) + _bencode(v[k])
        return out + b"e"
    if isinstance(v, list):
        out = b"l"
        for item in v:
            out += _bencode(item)
        return out + b"e"
    raise TypeError(f"cannot bencode {type(v)!r}")


@fixture("bt_dht.pcap")
def fixture_bt_dht() -> bytes:
    """BitTorrent DHT queries (ping, find_node, get_peers, announce_peer) and one peer-wire handshake (#276)."""
    w = Wire(start=1_702_000_000.0)
    c, s = "10.50.0.2", "10.50.0.3"
    tid = b"\xaa\xbb"
    node_id = b"\xcc" * 20
    info_hash = b"\x11" * 20
    messages = [
        _bencode({"t": tid, "y": "q", "q": "ping", "a": {"id": node_id}}),
        _bencode({"t": tid, "y": "r", "r": {"id": node_id}}),
        _bencode({"t": tid, "y": "q", "q": "find_node", "a": {"id": node_id, "target": b"\xdd" * 20}}),
        _bencode({"t": tid, "y": "q", "q": "get_peers", "a": {"id": node_id, "info_hash": info_hash}}),
        _bencode({"t": tid, "y": "q", "q": "announce_peer", "a": {"id": node_id, "info_hash": info_hash, "port": 6881, "token": b"tokn"}}),
    ]
    for payload in messages:
        w.add(udp_frame(c, s, 6881, 6881, payload))
    # A BitTorrent peer-wire handshake carries the info_hash and a peer-id prefix.
    handshake = bytes([0x13]) + b"BitTorrent protocol" + b"\x00" * 8 + info_hash + b"-AZ1234-1234567890ab"
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 6881, 6889, 1000, 0, 0x02))))  # TCP SYN
    w.add(ether(MAC_B, MAC_A, ip_packet(s, c, 6, tcp_segment(s, c, 6889, 6881, 2000, 1001, 0x12))))  # SYN-ACK
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 6881, 6889, 1001, 2001, 0x10))))  # ACK
    w.add(ether(MAC_A, MAC_B, ip_packet(c, s, 6, tcp_segment(c, s, 6881, 6889, 1001, 2001, 0x18, handshake))))
    return w.write()


# -- HTTP/2 (h2c, prior-knowledge) -------------------------------------------------
def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    """One HTTP/2 frame header (RFC 7540 §4.1): 3-byte length, type, flags, 4-byte stream id, payload."""
    return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload


def h2_literal(name: bytes, value: bytes) -> bytes:
    """A single HPACK header literal using the literal-without-indexing representation (index 0).

    Wire form: 0x10 (pattern 0001xxxx = literal without indexing, name indexed), name-length,
    name, value-length, value. The name is sent literally so the bytes are easy to verify.
    """
    return bytes([0x10, len(name)]) + name + bytes([len(value)]) + value


def h2_headers(stream_id: int, headers: list[tuple[bytes, bytes]], end_headers: bool = True) -> bytes:
    """A HEADERS frame carrying a literal-without-indexing HPACK header block."""
    payload = b"".join(h2_literal(n, v) for n, v in headers)
    return h2_frame(0x01, 0x1 if end_headers else 0x0, stream_id, payload)


@fixture("http2_cleartext.pcap")
def fixture_http2_cleartext() -> bytes:
    """HTTP/2 over cleartext (h2c, prior-knowledge): a GET with an :authority/:path and a 200, plus a POST with
    an Authorization header, both on separate streams (#226). HEADERS frames use literal-without-indexing
    HPACK so the encoded bytes are easy to verify by hand."""
    w = Wire(start=1_701_980_000.0)
    client, server, port = "10.0.0.10", "10.0.0.20", 80
    t = Tcp(w, client, server, 50030, port).open()
    # Connection preface (RFC 7540 §3.4): the client's magic string + an empty SETTINGS frame.
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = h2_frame(0x04, 0x00, 0)  # SETTINGS (type 4), stream 0
    # Stream 1: GET /api/v1/status on api.example -> 200
    req1 = h2_headers(1, [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"api.example"),
        (b":path", b"/api/v1/status"),
    ])
    # Stream 3: POST /api/v1/login on api.example with an Authorization header -> 200
    req2 = h2_headers(3, [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"api.example"),
        (b":path", b"/api/v1/login"),
    ])
    t.send(True, preface + settings + req1 + req2)
    # Server replies with an empty SETTINGS, then a HEADERS frame carrying :status 200 for each stream.
    resp1 = h2_headers(1, [(b":status", b"200")])
    resp2 = h2_headers(3, [(b":status", b"200")])
    t.send(False, settings + resp1 + resp2)
    t.close()
    return w.write()


@fixture("search_bytes.pcap")
def fixture_search_bytes() -> bytes:
    """Two flows carrying a literal keyword in a TCP payload and a hex pattern in a UDP payload (#215).

    TCP: client -> server carries b"SESSION=secret-token" at offset 0; the server replies with b"echo: password".
    UDP: a single datagram carries the 4-byte pattern b"\\xde\\xad\\xbe\\xef" followed by b"keep".
    The keyword "secret-token" appears nowhere in UDP, and "keep" only in UDP, so direction and frame are
    attributable.
    """
    w = Wire(start=1_701_950_000.0)
    # TCP flow with a plaintext keyword.
    t = Tcp(w, "10.20.0.10", "10.20.0.1", 40000, 80).open()
    t.send(True, b"SESSION=secret-token")
    t.send(False, b"echo: password")
    t.close()
    # UDP datagram with a hex byte pattern.
    w.add(udp_frame("10.20.0.10", "10.20.0.1", 53000, 53, b"\xde\xad\xbe\xefkeep"))
    return w.write()


@fixture("irc_chat.pcap")
def fixture_irc_chat() -> bytes:
    """Plain IRC on 6667: channel PRIVMSG, a NOTICE, and a PRIVMSG split over two TCP segments (#213)."""
    w = Wire(start=1_702_000_000.0)
    t = Tcp(w, "10.90.0.1", "10.90.0.2", 42001, 6667).open()
    t.send(True, b"NICK alice\r\nUSER alice 0 * :Alice\r\n")
    t.send(False, b":irc.example 001 alice :Welcome\r\n")
    t.send(True, b"JOIN #ops\r\nPRIVMSG #ops :deploy is done, rollback plan in wiki\r\n")
    t.send(False, b":bob!b@host PRIVMSG #ops :ack, checking the logs\r\n:irc.example NOTICE alice :server notice\r\n")
    t.send(True, b"PRIVMSG #ops :split ")
    t.send(True, b"message\r\n")
    t.close()
    return w.write()
