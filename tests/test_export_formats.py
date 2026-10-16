"""CSV and CASE (JSON-LD) export of the shown findings (issue #255).

The SARIF and doctor/1 JSON exports already exist; these are the two formats the issue is missing:
a spreadsheet-friendly CSV (NM Professional) and a CASE/JSON-LD document that another tool can ingest.
"""

from __future__ import annotations

import csv
import io
import json

from conftest import fixture, requires_tshark
from pcap_doctor.export import CSV_COLUMNS, to_case, to_csv
from pcap_doctor.models import CaptureInfo, Evidence, Finding, Report, Stats
from pcap_doctor.pipeline import analyze
from pcap_doctor.rules import category_of


def _finding(code: str, severity: str, *, title: str = "t", summary: str = "s") -> Finding:
    return Finding.make(
        detector="d1.tls_cipher",
        code=code,
        title=title,
        severity=severity,
        confidence="high",
        category="crypto",
        summary=summary,
        scope=f"{code}{severity}",
        evidence=[Evidence(frame=7, field="f", value="v")],
        remediation="fix it",
        references=["RFC 8446"],
    )


def _report(findings: list[Finding]) -> Report:
    capture = CaptureInfo(
        path="/abs/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(generated_at="2024-01-01T00:00:00Z", capture=capture, stats=Stats(),
                  flows=[], tls_sessions=[], findings=findings)


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_header_is_exactly_the_declared_columns() -> None:
    header = to_csv(_report([])).splitlines()[0]
    assert header.split(",") == list(CSV_COLUMNS)


def test_csv_has_one_row_per_finding_with_the_contract_values() -> None:
    f = _finding("HTTP_CLEARTEXT", "medium", title="t", summary="s")
    (row,) = _rows(to_csv(_report([f])))
    assert row["code"] == "HTTP_CLEARTEXT"
    assert row["severity"] == "medium"
    assert row["confidence"] == "high"
    assert row["category"] == category_of("HTTP_CLEARTEXT")
    assert row["detector"] == "d1.tls_cipher"
    assert row["id"] == f.id
    assert row["remediation"] == "fix it"
    assert "RFC 8446" in row["references"]
    assert row["frame"] == "7"
    assert row["evidence"]


def test_csv_is_sorted_by_severity_then_code_then_id() -> None:
    report = _report([
        _finding("A_MID", "medium"),
        _finding("B_INFO", "info"),
        _finding("C_CRIT", "critical"),
        _finding("D_MID", "medium"),
    ])
    codes = [row["code"] for row in _rows(to_csv(report))]
    assert codes == ["C_CRIT", "A_MID", "D_MID", "B_INFO"]


def test_csv_uses_rfc4180_quoting_for_embedded_commas_and_quotes() -> None:
    nasty = 'a,b "quoted"\nsecond line'
    f = _finding("CSV_QUOTE", "high", title=nasty, summary=nasty)
    (row,) = _rows(to_csv(_report([f])))
    assert row["title"] == nasty
    assert row["summary"] == nasty


def test_csv_of_an_empty_report_is_a_header_and_nothing_else() -> None:
    text = to_csv(_report([]))
    assert len(text.splitlines()) == 1
    assert text.splitlines()[0].split(",") == list(CSV_COLUMNS)


def test_csv_honours_an_explicit_subset() -> None:
    a = _finding("KEEP_ME", "high")
    b = _finding("DROP_ME", "high")
    (row,) = _rows(to_csv(_report([a, b]), [a]))
    assert row["code"] == "KEEP_ME"


def test_case_document_is_a_json_ld_case_with_one_object_per_finding() -> None:
    report = _report([_finding("HTTP_CLEARTEXT", "critical"), _finding("TLS_WEAK", "low")])
    doc = to_case(report)
    assert doc["@type"] == "case"
    assert doc["@context"], "a JSON-LD document without @context is not JSON-LD"
    assert doc["name"] == "x.pcap"
    assert doc["created"] == report.generated_at
    assert json.loads(json.dumps(doc)) == doc, "must survive a JSON round trip"
    objects = doc["objects"]
    assert len(objects) == 2
    assert {o["@id"] for o in objects} == {f.id for f in report.findings}
    for obj in objects:
        assert obj["@type"] == "case-object"
        assert obj["name"] and obj["description"]
        assert obj["severity"] in ("critical", "high", "medium", "low", "info")
        assert obj["evidence"] == [{"frame": 7, "field": "f", "value": "v"}]


def test_case_objects_carry_the_contract_category_not_the_detector_one() -> None:
    (obj,) = to_case(_report([_finding("HTTP_CLEARTEXT", "medium")]))["objects"]
    assert obj["object_type"] == category_of("HTTP_CLEARTEXT")


def test_case_of_an_empty_report_has_no_objects() -> None:
    assert to_case(_report([]))["objects"] == []


@requires_tshark
def test_csv_of_a_real_capture_lists_exactly_its_finding_codes(tmp_path) -> None:
    result = analyze(fixture("http_basic.pcap"), tmp_path / "out")
    rows = _rows(to_csv(result.report))
    assert {row["code"] for row in rows} == {f.code for f in result.report.findings}
    assert {row["code"] for row in rows} == {
        "HTTP_CLEARTEXT", "HTTP_CLEARTEXT_AUTH", "HTTP_COOKIE_NO_SECURE", "HTTP_MISSING_SECURITY_HEADERS",
    }
    assert all(row["id"] for row in rows)