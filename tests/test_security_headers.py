"""Missing HTTP security headers on observed responses (issue #271)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_a_response_missing_security_headers_is_reported(analyze_capture) -> None:
    findings = [f for f in analyze_capture(fixture("http_headers.pcap")).report.findings if f.code == "HTTP_MISSING_SECURITY_HEADERS"]
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.severity == "low"
    # the server missing every header is named; the one with all headers is not
    assert "10.97.0.10" in " ".join(f.subjects) or "10.97.0.10" in f.summary
    for header in ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
        assert header in f.summary, header
    assert "10.97.0.11" not in f.summary, "the response that has all headers is not reported"
