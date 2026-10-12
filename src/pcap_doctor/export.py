"""CSV and CASE (JSON-LD) export of the shown findings (issue #255).

These formats sit alongside the SARIF and doctor/1 exports that ``output.py`` already
provides. CSV is for a spreadsheet review; CASE is a JSON-LD document that another tool
in the CASE (Cyber-Artifacts, Stix, and Ecosystem) family can ingest.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from .models import SEVERITY_ORDER, Finding, Report
from .rules import category_of

#: Column order for the CSV export; the header line must round-trip to exactly this.
CSV_COLUMNS: tuple[str, ...] = (
    "id",
    "severity",
    "confidence",
    "category",
    "code",
    "detector",
    "title",
    "location",
    "flow_key",
    "frame",
    "evidence",
    "summary",
    "remediation",
    "references",
)


def _sort_key(f: Finding) -> tuple[int, str, str]:
    return (SEVERITY_ORDER.get(f.severity, 99), f.code, f.id)


def _evidence_text(f: Finding) -> str:
    if not f.evidence:
        return ""
    return " | ".join(f"frame {e.frame}: {e.field}={e.value}" for e in f.evidence)


def _references_text(f: Finding) -> str:
    return ", ".join(f.references) if f.references else ""


def _location(f: Finding) -> str:
    if f.flow_key:
        return f.flow_key
    if f.evidence:
        return f"frame {f.evidence[0].frame}"
    return ""


def _row(f: Finding) -> dict[str, str]:
    return {
        "id": f.id,
        "severity": f.severity,
        "confidence": f.confidence,
        "category": category_of(f.code),
        "code": f.code,
        "detector": f.detector,
        "title": f.title,
        "location": _location(f),
        "flow_key": f.flow_key or "",
        "frame": str(f.evidence[0].frame) if f.evidence else "",
        "evidence": _evidence_text(f),
        "summary": f.summary,
        "remediation": f.remediation or "",
        "references": _references_text(f),
    }


def to_csv(report: Report, findings: list[Finding] | None = None) -> str:
    """Render the shown findings as an RFC 4180 CSV string.

    ``findings`` defaults to every finding on the report. When given, it is a filter
    of the *already shown* findings, not a replacement set. Rows are sorted by
    severity (via ``SEVERITY_ORDER``), then code, then id.
    """
    chosen = sorted(findings if findings is not None else report.findings, key=_sort_key)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(CSV_COLUMNS), quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writeheader()
    for f in chosen:
        writer.writerow(_row(f))
    return buf.getvalue()


def _case_object(f: Finding) -> dict[str, Any]:
    ev: list[dict[str, Any]] = [
        {"frame": e.frame, "field": e.field, "value": e.value} for e in f.evidence
    ]
    return {
        "@type": "case-object",
        "@id": f.id,
        "object_type": category_of(f.code),
        "name": f.title,
        "description": f.summary,
        "severity": f.severity,
        "confidence": f.confidence,
        "evidence": ev,
    }


def to_case(report: Report, findings: list[Finding] | None = None) -> dict[str, Any]:
    """Render the shown findings as a CASE (JSON-LD) document.

    ``findings`` defaults to every finding on the report. When given, it is a filter
    of the *already shown* findings, not a replacement set.
    """
    chosen = findings if findings is not None else report.findings
    return {
        "@type": "case",
        "@context": [
            "https://raw.githubusercontent.com/case-foundation/case-json-ld/master/case.jsonld",
        ],
        "name": report.capture.name,
        "created": report.generated_at,
        "objects": [_case_object(f) for f in chosen],
    }
