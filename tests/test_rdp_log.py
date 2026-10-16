"""RDP negotiation log (issue #218)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app

RDP_FIXTURE = fixture("rdp_nat.pcap")


def _tsv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    header: list[str] = []
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith("#fields"):
            header = line.split("\t")[1:]
        elif not line.startswith("#"):
            rows.append(dict(zip(header, line.split("\t"), strict=True)))
    return header, rows


@pytest.fixture(scope="module")
def rdp_logs_dir(tmp_path_factory, cache_dir):
    from typer.testing import CliRunner

    out = tmp_path_factory.mktemp("rdp_logs")
    result = CliRunner().invoke(app, ["logs", str(RDP_FIXTURE), "-o", str(out), "--format", "both"])
    assert result.exit_code == 0, result.output
    return out


@requires_tshark
def test_rdp_log_is_written(rdp_logs_dir) -> None:
    """RDP log is written with expected columns."""
    rdp_log = rdp_logs_dir / "rdp.log"
    assert rdp_log.exists(), "rdp.log was not created"

    header, _rows = _tsv(rdp_log)
    expected_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "security_protocol", "flags", "cookie", "client_name"]
    assert header == expected_fields, f"Expected {expected_fields}, got {header}"


@requires_tshark
def test_rdp_log_negotiation_request_response(rdp_logs_dir) -> None:
    """RDP negotiation request and response are logged."""
    _, rows = _tsv(rdp_logs_dir / "rdp.log")
    
    # Should have one row from the negotiation response
    assert len(rows) == 1, f"Expected 1 RDP row, got {len(rows)}"
    
    row = rows[0]
    assert row["security_protocol"] == "SSL/TLS", f"Expected SSL/TLS, got {row['security_protocol']}"
    assert row["id.orig_h"] == "10.100.0.50", f"Expected 10.100.0.50, got {row['id.orig_h']}"
    assert row["id.orig_p"] == "49000", f"Expected 49000, got {row['id.orig_p']}"
    assert row["id.resp_h"] == "10.100.0.10", f"Expected 10.100.0.10, got {row['id.resp_h']}"
    assert row["id.resp_p"] == "3389", f"Expected 3389, got {row['id.resp_p']}"
    assert row["flags"] == "0", f"Expected 0, got {row['flags']}"


@requires_tshark
def test_rdp_log_json_format(rdp_logs_dir) -> None:
    """RDP log JSON format is valid."""
    json_log = rdp_logs_dir / "rdp.json.log"
    assert json_log.exists(), "rdp.json.log was not created"
    
    lines = json_log.read_text().splitlines()
    assert len(lines) == 1, f"Expected 1 line, got {len(lines)}"
    
    row = json.loads(lines[0])
    assert row["security_protocol"] == "SSL/TLS"
    assert row["id.orig_h"] == "10.100.0.50"
    assert row["id.resp_p"] == 3389