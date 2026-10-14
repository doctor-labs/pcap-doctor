"""Zeek-style known_services: each server host, the ports it serves and the service name (issue #246)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_a_server_lists_its_service_ports(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("mail_logins.pcap")).index, "known_services")
    by_port = {(r["host"], r["port"]): r for r in rows}
    # 10.80.0.2 serves SMTP (25), POP3 (110) and IMAP (143); the clients are not listed
    assert {p for (h, p) in by_port if h == "10.80.0.2"} == {25, 110, 143}, rows
    assert all(r["proto"] == "tcp" for r in rows)
    assert by_port[("10.80.0.2", 143)]["service"] in {"imap", "imaps", "imap-tls"} or "imap" in (by_port[("10.80.0.2", 143)]["service"] or "")
    assert not any(h == "10.80.0.1" for (h, p) in by_port), "the client is not a server"


@requires_tshark
def test_a_tls_server_is_known_on_443(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("weak_tls.pcap")).index, "known_services")
    assert any(r["port"] == 443 for r in rows), rows
