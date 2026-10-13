"""HTTP/2 over cleartext (h2c, prior-knowledge) is reported with its decoded HPACK pseudo-headers (#226)."""

from __future__ import annotations

import pytest

from conftest import codes, fixture, requires_tshark


@requires_tshark
def test_h2c_prior_knowledge_is_reported(analyze_capture) -> None:
    result = analyze_capture(fixture("http2_cleartext.pcap"))
    found = sorted(
        (f for f in result.report.findings if f.code == "HTTP2_CLEARTEXT"), key=lambda f: f.flow_key
    )
    assert len(found) == 1
    finding = found[0]
    assert finding.severity == "high"
    assert finding.confidence == "high"
    # The two request pseudo-headers reached the report per stream, alongside the response status.
    values = {e.value for e in finding.evidence}
    assert "GET api.example/api/v1/status" in values
    assert "POST api.example/api/v1/login" in values
    assert "200" in values
    # The h2c flow must be marked cleartext, not encrypted.
    flow = result.index.flow(finding.flow_key)
    assert flow is not None
    assert flow.encrypted is False
    assert any("http2" in e for e in flow.encryption_evidence)


@requires_tshark
def test_only_cleartext_http2_is_reported(analyze_capture) -> None:
    # A TLS-protected capture must not trigger the h2c detector.
    assert "HTTP2_CLEARTEXT" not in codes(analyze_capture(fixture("strong_tls13.pcap")))
    assert "HTTP2_CLEARTEXT" not in codes(analyze_capture(fixture("weak_tls.pcap")))


@requires_tshark
def test_http2_exchange_records_pseudo_headers(analyze_capture) -> None:
    index = analyze_capture(fixture("http2_cleartext.pcap")).index
    by_path = {e.path: e for e in index.http2}
    get = by_path["/api/v1/status"]
    assert get.method == "GET"
    assert get.authority == "api.example"
    assert get.scheme == "https"
    assert get.status == "200"
    post = by_path["/api/v1/login"]
    assert post.method == "POST"
    assert post.authority == "api.example"
    assert post.status == "200"
    # Every recorded stream is cleartext h2c.
    assert all(not e.is_encrypted for e in index.http2)


@requires_tshark
@pytest.mark.parametrize("name", ["http2_cleartext.pcap"])
def test_expected_codes_entry(analyze_capture, name: str) -> None:
    assert "HTTP2_CLEARTEXT" in codes(analyze_capture(fixture(name)))
