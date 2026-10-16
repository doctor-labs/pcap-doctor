"""Local indicator matching: user-supplied IOC files, no network (issue #236)."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.extract import extract
from pcap_doctor.index import IndexBuilder
from pcap_doctor.ioc import load_hash_iocs, load_iocs, match_iocs
from pcap_doctor.tshark import TsharkRunner

IOC_TEXT = """\
# indicators for the hostnames fixture
93.184.216.34  known bad host
10.0.0.0/8
admin-panel.example.com  phishing kit
*.example.com
http://signin.internal.corp/ credential page
d41d8cd98f00b204e9800998ecf8427e
not an indicator!!
"""


def _write(tmp_path: Path, text: str = IOC_TEXT) -> Path:
    path = tmp_path / "iocs.txt"
    path.write_text(text)
    return path


def test_load_iocs_detects_types_and_warns_on_the_rest(tmp_path: Path) -> None:
    indicators, warnings = load_iocs([_write(tmp_path)])
    assert [(i.kind, i.value) for i in indicators] == [
        ("ip", "93.184.216.34"),
        ("ip", "10.0.0.0/8"),
        ("domain", "admin-panel.example.com"),
        ("domain", "example.com"),
        ("url", "http://signin.internal.corp/"),
    ]
    assert indicators[0].label == "known bad host"
    assert len(warnings) == 2  # the md5 (hashes are not matched) and the junk line
    assert any("iocs.txt:7" in w and "hash" in w for w in warnings)
    assert any("iocs.txt:8" in w for w in warnings)


def test_match_iocs_on_the_hostnames_fixture(tmp_path: Path) -> None:
    indicators, _ = load_iocs([_write(tmp_path)])
    index = IndexBuilder(TsharkRunner(fixture("hostnames.pcap"), use_cache=False)).build()
    hits = match_iocs(index, indicators)
    by_kind = {(h.kind, h.indicator, h.subject): h for h in hits}

    ip = by_kind[("ip", "93.184.216.34", "93.184.216.34")]
    assert ip.source == "dns" and ip.frame == 1
    assert by_kind[("domain", "admin-panel.example.com", "admin-panel.example.com")].source == "dns"
    assert by_kind[("domain", "example.com", "login.example.com")].frame == 1  # subdomain of a suffix indicator
    assert by_kind[("url", "http://signin.internal.corp/", "signin.internal.corp/")].frame == 20
    # one hit per (indicator, subject): the same name in several DNS answers is reported once
    assert len([h for h in hits if h.indicator == "admin-panel.example.com"]) == 1


@requires_tshark
def test_ioc_is_opt_in_and_reports_ioc_match(cli_runner, tmp_path: Path, cache_dir) -> None:
    out = tmp_path / "r"
    ioc = _write(tmp_path)
    args = ["analyze", str(fixture("hostnames.pcap")), "-o", str(out), "-q", "--no-handoff", "--ioc", str(ioc)]
    assert cli_runner.invoke(app, args).exit_code == 0
    report = json.loads((out / "report.json").read_text())
    hits = [f for f in report["findings"] if f["code"] == "IOC_MATCH"]
    assert hits and all(f["severity"] == "high" and f["confidence"] == "medium" for f in hits)
    assert any("93.184.216.34" in f["title"] for f in hits)
    assert all(f["evidence"] and f["evidence"][0]["frame"] for f in hits)

    plain = tmp_path / "plain"
    assert cli_runner.invoke(app, ["analyze", str(fixture("hostnames.pcap")), "-o", str(plain), "-q", "--no-handoff"]).exit_code == 0
    assert "IOC_MATCH" not in (plain / "report.json").read_text()



def test_load_hash_iocs_reads_md5_sha1_and_sha256(tmp_path: Path) -> None:
    digests = [
        "D41D8CD98F00B204E9800998ECF8427E",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]
    hashes = load_hash_iocs([_write(tmp_path, chr(10).join(digests) + chr(10))])
    assert [(h.kind, h.value) for h in hashes] == [("hash", d.lower()) for d in digests]


@requires_tshark
def test_hash_ioc_matches_an_object_extracted_from_the_capture(cli_runner, tmp_path: Path) -> None:
    capture = fixture("http_basic.pcap")
    objects = [f for f in extract(capture, tmp_path / "extracted", ("http",)) if f.info is not None]
    assert objects, "http_basic.pcap has no HTTP object to hash"
    ioc = tmp_path / "hashes.txt"
    ioc.write_text(f"{objects[0].info.sha256}  known bad payload" + chr(10))
    out = tmp_path / "r"
    args = ["analyze", str(capture), "-o", str(out), "-q", "--no-handoff", "--ioc", str(ioc)]
    assert cli_runner.invoke(app, args).exit_code == 0
    report = json.loads((out / "report.json").read_text())
    hits = [f for f in report["findings"] if f["code"] == "IOC_MATCH" and "ioc:hash" in f["tags"]]
    assert hits and hits[0]["subjects"] == [objects[0].name]
    assert hits[0]["severity"] == "high" and hits[0]["confidence"] == "medium"
