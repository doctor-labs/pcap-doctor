"""Per-frame magic-byte carving of raw packet payloads (issue #216).

``carve`` scans the raw payload bytes of every packet (not reassembled streams, and including UDP)
for the file signatures in ``pcap_doctor.filetypes.MAGIC`` and reports, per frame, the signature
name and the byte offset where it occurred. Expected offsets below were verified with tshark
against the hand-built capture, not by hand: frame 4's ``tcp.payload`` is
``0001`` + ``%PDF-1.7`` and frame 6's ``udp.payload`` is ``01 02 03`` + ``PK\x03\x04``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from conftest import ROOT, requires_tshark
from pcap_doctor.carving import CarveHit, carve, scan_payload
from pcap_doctor.index import IndexBuilder
from pcap_doctor.tshark import TsharkRunner

sys.path.insert(0, str(ROOT / "scripts"))


def test_scan_payload_reports_the_signature_and_its_offset() -> None:
    assert scan_payload(b"\x00\x01%PDF-1.7") == [("application/pdf", 2)]
    assert scan_payload(b"\x01\x02\x03PK\x03\x04zip") == [("application/zip", 3)]
    assert scan_payload(b"%PDF-1.4") == [("application/pdf", 0)]
    assert scan_payload(b"") == []
    assert scan_payload(b"no magic in here") == []
    # two signatures, each reported at its own offset ("%PDF-1.7\n" is 9 bytes, so PK sits at 9)
    assert scan_payload(b"%PDF-1.7\nPK\x03\x04") == [("application/pdf", 0), ("application/zip", 9)]


def test_scan_payload_is_bounds_safe_on_short_payloads() -> None:
    # the ustar magic sits at offset 257: a payload shorter than that must not match and must not raise
    assert scan_payload(b"ustar") == []
    assert scan_payload(b"x" * 262) == []  # 257..262 is not "ustar"
    assert ("application/x-tar", 257) in scan_payload(b"x" * 257 + b"ustar")
    assert scan_payload(b"BM") == [("image/bmp", 0)]  # the 2-byte BMP magic at offset 0, as in the table


@requires_tshark
def test_carve_finds_the_magics_in_tcp_and_udp_payloads(tmp_path: Path, cache_dir: Path) -> None:
    from parity_fixtures import Tcp, Wire, udp_frame

    w = Wire()
    t = Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open()  # frames 1-3: handshake, no payload
    t.send(True, b"\x00\x01" + b"%PDF-1.7\n%%EOF")  # frame 4: a PDF at payload offset 2
    w.add(udp_frame("10.0.0.5", "10.0.0.6", 5300, 53, b"\x01\x02\x03PK\x03\x04extra"))  # frame 6: a ZIP at payload offset 3
    pcap = tmp_path / "carving.pcap"
    pcap.write_bytes(w.write())

    index = IndexBuilder(TsharkRunner(pcap, use_cache=False)).build()
    hits = carve(index)
    got = {(h.frame, h.signature, h.offset, h.protocol) for h in hits}
    assert got == {(4, "application/pdf", 2, "tcp"), (6, "application/zip", 3, "udp")}
    assert all(isinstance(h, CarveHit) for h in hits)


@requires_tshark
def test_carve_reports_nothing_on_a_capture_without_payloads(tmp_path: Path, cache_dir: Path) -> None:
    from parity_fixtures import Tcp, Wire

    w = Wire()
    t = Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open()
    t.close()  # handshake + teardown only: no payload bytes, so nothing to carve
    pcap = tmp_path / "no_payloads.pcap"
    pcap.write_bytes(w.write())

    index = IndexBuilder(TsharkRunner(pcap, use_cache=False)).build()
    assert carve(index) == []
