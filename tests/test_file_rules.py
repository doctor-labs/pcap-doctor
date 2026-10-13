"""Suricata-style file rules: match extracted files by name, size, magic and md5 (issue #275).

These tests build hand-crafted file records (no tshark needed) and assert on the
rule codes and match kinds that come back, never on prose.
"""

from __future__ import annotations

from pathlib import Path

from pcap_doctor.extract import ExtractedFile
from pcap_doctor.file_rules import FileRule, file_rules_match


def _file(name: str, size: int, md5: str, mime: str) -> ExtractedFile:
    from pcap_doctor.filetypes import FileInfo

    return ExtractedFile(protocol="http", name=name, path=Path(f"/fake/{name}"),
                         size=size, info=FileInfo(md5=md5, sha1="s1", sha256="s256", size=size, mime_type=mime))


def _rules() -> list[FileRule]:
    return [
        FileRule(code="NAME_EXE_GLOB", name="*.exe"),
        FileRule(code="SIZE_IN_RANGE", min_size=10, max_size=100),
        FileRule(code="SIZE_TOO_SMALL", max_size=5),
        FileRule(code="MIME_PDF", magic="application/pdf"),
        FileRule(code="MD5_KNOWN_BAD", md5="be1c8df3a8c13a019757b606c8f6102d"),
    ]


def test_name_glob_matches_case_insensitively() -> None:
    rules = [FileRule(code="NAME_EXE_GLOB", name="*.exe")]
    f = _file("tool.EXE", 200, "deadbeef", "application/octet-stream")
    matches = file_rules_match([f], rules)
    assert [m.code for m in matches[f.name]] == ["NAME_EXE_GLOB"]


def test_name_glob_does_not_match_wrong_extension() -> None:
    rules = [FileRule(code="NAME_EXE_GLOB", name="*.exe")]
    f = _file("tool.zip", 200, "deadbeef", "application/zip")
    matches = file_rules_match([f], rules)
    assert matches[f.name] == []


def test_size_range_matches_on_both_bounds() -> None:
    rules = [FileRule(code="SIZE_IN_RANGE", min_size=10, max_size=100)]
    f = _file("a.bin", 100, "deadbeef", "application/octet-stream")
    matches = file_rules_match([f], rules)
    assert [m.code for m in matches[f.name]] == ["SIZE_IN_RANGE"]
    f2 = _file("b.bin", 10, "deadbeef", "application/octet-stream")
    matches2 = file_rules_match([f2], rules)
    assert [m.code for m in matches2[f2.name]] == ["SIZE_IN_RANGE"]


def test_size_range_rejects_below_min() -> None:
    rules = [FileRule(code="SIZE_IN_RANGE", min_size=10, max_size=100)]
    f = _file("small.bin", 5, "deadbeef", "application/octet-stream")
    matches = file_rules_match([f], rules)
    assert matches[f.name] == []


def test_size_max_only_matches_at_and_below() -> None:
    rules = [FileRule(code="SIZE_TOO_SMALL", max_size=5)]
    f_small = _file("tiny.bin", 5, "deadbeef", "application/octet-stream")
    f_big = _file("big.bin", 100, "deadbeef", "application/octet-stream")
    matches = file_rules_match([f_small, f_big], rules)
    assert [m.code for m in matches[f_small.name]] == ["SIZE_TOO_SMALL"]
    assert matches[f_big.name] == []


def test_magic_match() -> None:
    rules = [FileRule(code="MIME_PDF", magic="application/pdf")]
    f = _file("report.pdf", 500, "deadbeef", "application/pdf")
    matches = file_rules_match([f], rules)
    assert [m.code for m in matches[f.name]] == ["MIME_PDF"]


def test_magic_does_not_match_wrong_type() -> None:
    rules = [FileRule(code="MIME_PDF", magic="application/pdf")]
    f = _file("data.zip", 500, "deadbeef", "application/zip")
    matches = file_rules_match([f], rules)
    assert matches[f.name] == []


def test_md5_match() -> None:
    # md5 computed via hashlib.md5 on b'PK\x03\x04' + b'PF-SMB-PAYLOAD-' * 8
    rules = [FileRule(code="MD5_KNOWN_BAD", md5="be1c8df3a8c13a019757b606c8f6102d")]
    f = _file("archive.zip", 124, "be1c8df3a8c13a019757b606c8f6102d", "application/zip")
    matches = file_rules_match([f], rules)
    assert [m.code for m in matches[f.name]] == ["MD5_KNOWN_BAD"]


def test_md5_does_not_match_different_hash() -> None:
    rules = [FileRule(code="MD5_KNOWN_BAD", md5="be1c8df3a8c13a019757b606c8f6102d")]
    f = _file("archive.zip", 124, "00000000000000000000000000000000", "application/zip")
    matches = file_rules_match([f], rules)
    assert matches[f.name] == []


def test_rule_that_must_not_match() -> None:
    """A rule targeting *.exe must not match a .zip file."""
    rules = [FileRule(code="NAME_EXE_GLOB", name="*.exe")]
    f = _file("payload.zip", 124, "be1c8df3a8c13a019757b606c8f6102d", "application/zip")
    matches = file_rules_match([f], rules)
    assert matches[f.name] == []


def test_multiple_rules_match_one_file() -> None:
    rules = _rules()
    f = _file("tool.exe", 50, "be1c8df3a8c13a019757b606c8f6102d", "application/x-msdownload")
    matches = file_rules_match([f], rules)
    codes = [m.code for m in matches[f.name]]
    assert "NAME_EXE_GLOB" in codes
    assert "SIZE_IN_RANGE" in codes
    assert "MD5_KNOWN_BAD" in codes
    assert "MIME_PDF" not in codes
    assert "SIZE_TOO_SMALL" not in codes


def test_multiple_files_all_matched() -> None:
    rules = _rules()
    files = [
        _file("tool.exe", 50, "be1c8df3a8c13a019757b606c8f6102d", "application/x-msdownload"),
        _file("doc.pdf", 50, "deadbeef", "application/pdf"),
        _file("tiny.txt", 3, "deadbeef", "text/plain"),
    ]
    matches = file_rules_match(files, rules)
    assert "NAME_EXE_GLOB" in [m.code for m in matches["tool.exe"]]
    assert "MIME_PDF" in [m.code for m in matches["doc.pdf"]]
    assert "SIZE_TOO_SMALL" in [m.code for m in matches["tiny.txt"]]


def test_empty_rules_match_nothing() -> None:
    f = _file("tool.exe", 50, "deadbeef", "application/octet-stream")
    matches = file_rules_match([f], [])
    assert matches[f.name] == []


def test_empty_files_match_nothing() -> None:
    rules = _rules()
    matches = file_rules_match([], rules)
    assert matches == {}
