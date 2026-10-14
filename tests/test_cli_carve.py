"""``carve``: the CLI surface of packet carving by file signature (issue #216).

The library (``pcap_doctor.carving``) is exercised in ``test_carving.py``; these tests pin that the
command reaches it and prints the same hits, as a table and as ``--json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from conftest import ROOT, requires_tshark
from pcap_doctor.cli import app

sys.path.insert(0, str(ROOT / "scripts"))


@requires_tshark
def test_carve_json_lists_each_hit_with_frame_signature_offset_and_protocol(
    tmp_path: Path, cache_dir: Path, cli_runner
) -> None:
    from parity_fixtures import Tcp, Wire, udp_frame

    w = Wire()
    t = Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open()
    t.send(True, b"\x00\x01" + b"%PDF-1.7\n%%EOF")  # frame 4: PDF at payload offset 2
    w.add(udp_frame("10.0.0.5", "10.0.0.6", 5300, 53, b"\x01\x02\x03PK\x03\x04extra"))  # frame 6: ZIP at offset 3
    pcap = tmp_path / "carving.pcap"
    pcap.write_bytes(w.write())

    result = cli_runner.invoke(app, ["carve", str(pcap), "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert sorted((r["frame"], r["signature"], r["offset"], r["protocol"]) for r in rows) == [
        (4, "application/pdf", 2, "tcp"),
        (6, "application/zip", 3, "udp"),
    ]


@requires_tshark
def test_carve_reports_no_hits_as_an_empty_list(tmp_path: Path, cache_dir: Path, cli_runner) -> None:
    from parity_fixtures import Tcp, Wire

    w = Wire()
    Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open().close()  # handshake and teardown only
    pcap = tmp_path / "no_payloads.pcap"
    pcap.write_bytes(w.write())

    result = cli_runner.invoke(app, ["carve", str(pcap), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == []


def _pdf_and_zip_capture(tmp_path: Path) -> Path:
    from parity_fixtures import Tcp, Wire, udp_frame

    w = Wire()
    t = Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open()
    t.send(True, b"\x00\x01" + b"%PDF-1.7\n%%EOF")  # frame 4: PDF at payload offset 2
    w.add(udp_frame("10.0.0.5", "10.0.0.6", 5300, 53, b"\x01\x02\x03PK\x03\x04extra"))  # frame 6: ZIP at offset 3
    pcap = tmp_path / "carving.pcap"
    pcap.write_bytes(w.write())
    return pcap


@requires_tshark
def test_carve_out_writes_each_hit_from_its_offset_and_nothing_else(tmp_path: Path, cache_dir: Path, cli_runner) -> None:
    pcap = _pdf_and_zip_capture(tmp_path)
    out = tmp_path / "carved"

    result = cli_runner.invoke(app, ["carve", str(pcap), "--out", str(out), "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert sorted(Path(r["path"]).name for r in rows) == ["frame4-2.pdf", "frame6-3.zip"]
    assert (out / "frame4-2.pdf").read_bytes() == b"%PDF-1.7\n%%EOF"  # starts at the magic, runs to payload end
    assert (out / "frame4-2.pdf").read_bytes().startswith(b"%PDF-")
    assert (out / "frame6-3.zip").read_bytes().startswith(b"PK\x03\x04")
    assert {r["bytes"] for r in rows} == {len(b"%PDF-1.7\n%%EOF"), len(b"PK\x03\x04extra")}
    # nothing written outside DIR: the only files under tmp_path are the capture and the two carved files
    files = {p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_file()}
    assert files == {Path("carving.pcap"), Path("carved/frame4-2.pdf"), Path("carved/frame6-3.zip")}


@requires_tshark
def test_carve_streams_finds_a_file_split_across_segments(tmp_path: Path, cache_dir: Path, cli_runner) -> None:
    from parity_fixtures import Tcp, Wire

    w = Wire()
    t = Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open()
    t.send(True, b"%PD")  # the magic itself is split: per packet there is no hit
    t.send(True, b"F-1.7\n%%EOF")
    t.close()
    pcap = tmp_path / "split.pcap"
    pcap.write_bytes(w.write())
    out = tmp_path / "streams"

    per_packet = json.loads(cli_runner.invoke(app, ["carve", str(pcap), "--json"]).output)
    assert per_packet == []

    result = cli_runner.invoke(app, ["carve", str(pcap), "--streams", "--out", str(out), "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert [(r["signature"], r["offset"], r["protocol"], r["stream"]) for r in rows] == [("application/pdf", 0, "tcp", 0)]
    (written,) = list(out.glob("stream0-*-0.pdf"))
    assert written.read_bytes() == b"%PDF-1.7\n%%EOF"


def test_write_hits_sanitizes_names_and_stays_inside_dir(tmp_path: Path) -> None:
    from pcap_doctor.carving import CarveHit, extension_for, write_hits

    hostile = CarveHit(9, "../../escape/x", 0, "tcp", b"MZ-body")
    (dest,) = write_hits([hostile], tmp_path / "out")
    assert dest.parent == (tmp_path / "out").resolve()
    assert dest.name == "frame9-0.bin"  # the odd MIME name has no extension, so it gets the fallback
    assert dest.read_bytes() == b"MZ-body"
    assert extension_for("application/pdf") == ".pdf"
    # a second hit with the same name never overwrites the first
    (again,) = write_hits([hostile], tmp_path / "out")
    assert again != dest and again.exists() and dest.read_bytes() == b"MZ-body"
