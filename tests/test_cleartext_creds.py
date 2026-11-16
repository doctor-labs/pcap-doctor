"""IRC, SOCKS, TDS and COTP cleartext credential extraction (issue #231)."""

from __future__ import annotations

from conftest import codes, fixture, requires_tshark


@requires_tshark
def test_irc_socks_tds_fixtures_emit_specific_codes(analyze_capture) -> None:
    assert "IRC_CLEARTEXT_CREDENTIAL" in codes(analyze_capture(fixture("irc_socks_creds.pcap")))
    assert "SOCKS_CLEARTEXT_CREDENTIAL" in codes(analyze_capture(fixture("irc_socks_creds.pcap")))
    assert "TDS_CLEARTEXT_CREDENTIAL" in codes(analyze_capture(fixture("mssql_tds.pcap")))


@requires_tshark
def test_detector_findings_redact_secrets_irc_socks(analyze_capture) -> None:
    report = analyze_capture(fixture("irc_socks_creds.pcap")).report
    irc = [f for f in report.findings if f.code == "IRC_CLEARTEXT_CREDENTIAL"]
    socks = [f for f in report.findings if f.code == "SOCKS_CLEARTEXT_CREDENTIAL"]
    assert irc and socks
    for f in irc:
        assert f.evidence and f.evidence[0].frame > 0
        assert "<redacted" in f.evidence[0].value
        assert "my-irc-password-123" not in f.summary
        assert "my-irc-password-123" not in f.evidence[0].value
        assert "IRC" in f.title or "IRC" in f.summary
    for f in socks:
        assert f.evidence and f.evidence[0].frame > 0
        assert "<redacted" in f.evidence[0].value
        assert "sockspass123" not in f.summary
        assert "sockspass123" not in f.evidence[0].value
        assert "SOCKS" in f.title or "SOCKS" in f.summary


@requires_tshark
def test_detector_findings_redact_secrets_tds(analyze_capture) -> None:
    report = analyze_capture(fixture("mssql_tds.pcap")).report
    tds = [f for f in report.findings if f.code == "TDS_CLEARTEXT_CREDENTIAL"]
    assert tds
    for f in tds:
        assert f.evidence and f.evidence[0].frame > 0
        assert "<redacted" in f.evidence[0].value
        assert "Passw0rd!" not in f.summary
        assert "Passw0rd!" not in f.evidence[0].value
        assert "sa" in f.summary or "sa" in f.scope


@requires_tshark
def test_negative_no_false_positive_on_strong_tls(analyze_capture) -> None:
    result = analyze_capture(fixture("strong_tls13.pcap"))
    found = codes(result)
    assert "IRC_CLEARTEXT_CREDENTIAL" not in found
    assert "SOCKS_CLEARTEXT_CREDENTIAL" not in found
    assert "TDS_CLEARTEXT_CREDENTIAL" not in found


@requires_tshark
def test_extra_irc_cases_and_secrets_never_leak(analyze_capture) -> None:
    report = analyze_capture(fixture("cleartext_creds_extra.pcap")).report
    assert "IRC_CLEARTEXT_CREDENTIAL" in codes(analyze_capture(fixture("cleartext_creds_extra.pcap")))
    irc = [f for f in report.findings if f.code == "IRC_CLEARTEXT_CREDENTIAL"]
    assert irc
    secrets = ("server-secret", "oper-secret", "chan-key")
    for f in irc:
        assert f.evidence and f.evidence[0].frame > 0
        assert "<redacted" in f.evidence[0].value
        for s in secrets:
            assert s not in f.summary
            assert s not in f.evidence[0].value
            assert s not in f.title
            assert s not in repr(f.subjects)
            assert s not in repr(f.references)
            assert s not in repr(f.tags)
    # detector must not leak extracted IRC secrets anywhere in its own findings
    blob = " ".join(repr(f) for f in irc)
    for s in secrets:
        assert s not in blob


