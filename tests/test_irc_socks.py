"""Cleartext IRC and SOCKS5 credential extraction (issue #231)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_irc_pass_is_redacted_cleartext_credential(analyze_capture) -> None:
    findings = [f for f in analyze_capture(fixture("irc_socks_creds.pcap")).report.findings if f.code == "CLEARTEXT_CREDENTIAL"]
    
    # IRC PASS command - should be detected with redacted password
    irc_findings = [f for f in findings if "irc.request.command_parameter" in f.evidence[0].field]
    assert irc_findings, "Expected IRC credential finding"
    
    irc_pass = irc_findings[0]
    assert irc_pass.evidence[0].frame == 4
    assert irc_pass.evidence[0].field == "irc.request.command_parameter"
    # Password should be redacted: 19 chars = len('my-irc-password-123')
    assert irc_pass.evidence[0].value == "<redacted 19 chars>"


@requires_tshark
def test_socks5_credentials_are_detected(analyze_capture) -> None:
    findings = [f for f in analyze_capture(fixture("irc_socks_creds.pcap")).report.findings if f.code == "CLEARTEXT_CREDENTIAL"]
    
    # SOCKS5 username and password should be detected
    socks_findings = [f for f in findings if "socks" in f.evidence[0].field]
    assert len(socks_findings) >= 2, f"Expected at least 2 SOCKS5 findings, got {len(socks_findings)}"
    
    # Check that credentials are present (POP3/IMAP/SMTP style - not redacted for service fields)
    socks_username = [f for f in socks_findings if "socks.username" in f.evidence[0].field]
    socks_password = [f for f in socks_findings if "socks.password" in f.evidence[0].field]
    
    assert socks_username, "Expected SOCKS5 username finding"
    assert socks_password, "Expected SOCKS5 password finding"
    assert "socksuser" in socks_username[0].evidence[0].value
    assert "sockspass" in socks_password[0].evidence[0].value