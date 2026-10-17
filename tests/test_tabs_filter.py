"""Display filter over the host, file and credential tab rows (issue #252). Pure: no tshark needed."""

from __future__ import annotations

from pcap_doctor.browse_tabs import FileRow, HostRow, narrow


def _hosts() -> list[HostRow]:
    return [
        HostRow("10.0.0.10", None, None, "web01", "Linux/Unix/Android/macOS", ("server",), 3, 900),
        HostRow("10.0.0.20", None, "Dell", None, None, (), 1, 40),
    ]


def test_empty_filter_keeps_every_row() -> None:
    assert len(narrow(_hosts(), None)) == 2
    assert len(narrow(_hosts(), "")) == 2


def test_filter_matches_any_column_ignoring_case() -> None:
    assert [r.ip for r in narrow(_hosts(), "WEB01")] == ["10.0.0.10"]
    assert [r.ip for r in narrow(_hosts(), "dell")] == ["10.0.0.20"]


def test_filter_keeps_only_matching_rows_and_none_when_nothing_matches() -> None:
    rows = [FileRow(28, "smb", "PSEXESVC.exe", "10.0.0.1:445"), FileRow(9, "http", "a.zip", "10.0.0.2:80")]
    assert [f.frame for f in narrow(rows, "exe")] == [28]
    assert narrow(rows, "nomatch") == []
