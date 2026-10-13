"""RFB/VNC dissection and the rfb log (issue #219)."""

from __future__ import annotations

from conftest import codes, fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.logs import LOG_NAMES


@requires_tshark
def test_rfb_log_name_is_registered() -> None:
    assert "rfb" in LOG_NAMES


@requires_tshark
def test_rfb_log_records_version_security_and_desktop(cli_runner, tmp_path, cache_dir) -> None:
    out = tmp_path / "rfb"
    result = cli_runner.invoke(app, ["logs", str(fixture("rfb_vnc.pcap")), "-o", str(out), "--only", "rfb"])
    assert result.exit_code == 0, result.output
    _, rows = _tsv(out / "rfb.log")
    assert len(rows) == 1
    row = rows[0]
    assert row["version"] == "003.008"
    assert row["client_version"] == "003.008"
    assert row["security_types_offered"] == "1,2"
    assert row["security_type_selected"] == "1"
    assert row["auth_result"] == "success"
    assert row["desktop_name"] == "Test Desktop"
    assert row["width"] == "800"
    assert row["height"] == "600"


@requires_tshark
def test_rfb_log_is_a_query_source(cli_runner) -> None:
    import json

    result = json.loads(
        cli_runner.invoke(
            app, ["query", str(fixture("rfb_vnc.pcap")), 'version == "003.008"', "-s", "log:rfb", "--json"]
        ).output
    )
    assert len(result) == 1
    assert result[0]["desktop_name"] == "Test Desktop"


@requires_tshark
def test_rfb_vnc_fixture_produces_no_new_findings(analyze_capture) -> None:
    """The rfb log is dissection, not a detector; no finding codes are expected."""
    result = analyze_capture(fixture("rfb_vnc.pcap"))
    assert codes(result) == set()


def _tsv(path):
    header: list[str] = []
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith("#fields"):
            header = line.split("\t")[1:]
        elif not line.startswith("#"):
            rows.append(dict(zip(header, line.split("\t"), strict=True)))
    return header, rows
