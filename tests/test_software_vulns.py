"""D15 -- vulnerable software versions announced in banners and headers (#235)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.detectors.software_vulns import parse_version, vulnerable_cve


def test_version_parsing_takes_the_numeric_prefix() -> None:
    assert parse_version("7.4p1") == (7, 4)
    assert parse_version("2.4.49") == (2, 4, 49)
    assert parse_version("Go") is None
    assert parse_version(None) is None


def test_known_vulnerable_versions_match_and_neighbours_do_not() -> None:
    assert vulnerable_cve("Apache", "2.4.49") == "CVE-2021-41773"
    assert vulnerable_cve("Apache", "2.4.50") == "CVE-2021-42013"
    assert vulnerable_cve("Apache", "2.4.51") is None
    assert vulnerable_cve("Apache", "2.4.29") is None
    assert vulnerable_cve("OpenSSH", "7.2") == "CVE-2016-10012"
    assert vulnerable_cve("OpenSSH", "7.4") is None
    assert vulnerable_cve("vsftpd", "2.3.4") == "CVE-2011-2523"
    assert vulnerable_cve("Exim", "4.91") == "CVE-2019-10149"
    assert vulnerable_cve("Exim", "4.92") is None
    assert vulnerable_cve("Exim", "4.79") is None


@requires_tshark
def test_vulnerable_server_is_reported_once_with_its_frame(analyze_capture) -> None:
    result = analyze_capture(fixture("vuln_versions.pcap"))
    hits = [f for f in result.findings if f.code == "SERVICE_VULNERABLE_VERSION"]
    assert [f.subjects for f in hits] == [["10.90.0.2"]]
    assert hits[0].evidence[0].frame > 0


@requires_tshark
def test_non_vulnerable_versions_are_silent(analyze_capture) -> None:
    result = analyze_capture(fixture("http_versions.pcap"))
    assert not [f for f in result.findings if f.code == "SERVICE_VULNERABLE_VERSION"]
