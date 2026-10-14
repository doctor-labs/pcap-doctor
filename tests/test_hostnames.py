"""Interesting hostname detection (#239): login/admin/signin-style names in DNS, TLS SNI and HTTP Host."""

from __future__ import annotations

from conftest import codes, fixture


def test_interesting_hostnames_are_flagged(analyze_capture):
    """DNS 'login', TLS SNI 'admin-panel' and HTTP Host 'signin' are flagged; 'www' is not (#239)."""
    result = analyze_capture(fixture("hostnames.pcap"))
    found = [f for f in result.report.findings if f.code == "INTERESTING_HOSTNAME"]
    # Three distinct hostnames carry an interesting first label.
    subjects = {";".join(f.subjects) for f in found}
    assert "admin-panel.example.com" in subjects, subjects
    assert "signin.internal.corp" in subjects, subjects
    assert "login.example.com" in subjects, subjects
    # The boring www name must not be flagged.
    assert not any("www.example.com" in s for s in subjects), subjects
    # Evidence cites real frame numbers and the right tshark fields.
    fields = {e.field for f in found for e in f.evidence}
    assert {"dns.qry.name", "tls.handshake.extensions_server_name", "http.host"} <= fields, fields


def test_boring_hostnames_are_silent(analyze_capture):
    """A capture with only boring hostnames produces no INTERESTING_HOSTNAME finding (#239)."""
    assert "INTERESTING_HOSTNAME" not in codes(analyze_capture(fixture("dns_external.pcap")))
    assert "INTERESTING_HOSTNAME" not in codes(analyze_capture(fixture("dns_records.pcap")))
