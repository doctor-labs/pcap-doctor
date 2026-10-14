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
