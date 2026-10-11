"""Zeek-style software.log: versioned software announced in HTTP headers and SSH banners (issue #247)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


def _rows(analyze_capture, name: str) -> set[tuple[object, ...]]:
    rows = log_rows(analyze_capture(fixture(name)).index, "software")
    return {(r["host"], r["host_p"], r["software_type"], r["name"], r["version"]) for r in rows}


@requires_tshark
def test_http_server_and_browser_versions(analyze_capture) -> None:
    assert _rows(analyze_capture, "http_versions.pcap") == {
        ("10.70.0.2", 80, "HTTP::SERVER", "Apache", "2.4.29"),
        ("10.70.0.1", None, "HTTP::BROWSER", "curl", "7.58.0"),  # like Zeek, a client has no port
    }
    rows = log_rows(analyze_capture(fixture("http_versions.pcap")).index, "software")
    assert any(r["unparsed_version"] == "Apache/2.4.29 (Ubuntu)" for r in rows)


@requires_tshark
def test_ssh_banners_are_deduplicated_per_host_and_role(analyze_capture) -> None:
    assert _rows(analyze_capture, "ssh_weak.pcap") == {
        ("10.0.0.20", 22, "SSH::SERVER", "OpenSSH", "7.4"),
        ("10.0.0.10", None, "SSH::CLIENT", "OpenSSH", "7.4"),
    }


def test_ssh_banner_versions_parse_like_real_banners() -> None:
    from pcap_doctor.logs import _parse_ssh_version as parse

    assert parse("SSH-2.0-OpenSSH_7.4p1 Ubuntu-4ubuntu0.3") == ("OpenSSH", "7.4p1")
    assert parse("SSH-2.0-dropbear_2019.78") == ("dropbear", "2019.78")
    assert parse("SSH-1.99-Cisco-1.25") == ("Cisco", "1.25")
    assert parse("SSH-2.0-Go") == ("Go", None)
