"""Cleartext POP3, IMAP and SMTP AUTH credentials (issue #230)."""

from __future__ import annotations

from conftest import fixture, requires_tshark


@requires_tshark
def test_pop3_imap_and_smtp_logins_are_cleartext_credentials(analyze_capture) -> None:
    findings = [f for f in analyze_capture(fixture("mail_logins.pcap")).report.findings if f.code == "CLEARTEXT_CREDENTIAL"]
    by_label = {f.title.split(" exposed")[0]: f for f in findings}
    assert set(by_label) == {"POP3 password", "IMAP LOGIN password", "SMTP AUTH PLAIN password"}, [f.title for f in findings]
    assert (by_label["POP3 password"].evidence[0].frame, by_label["POP3 password"].evidence[0].value) == (7, "secret1")
    assert (by_label["IMAP LOGIN password"].evidence[0].frame, by_label["IMAP LOGIN password"].evidence[0].value) == (13, "secret2")
    smtp = by_label["SMTP AUTH PLAIN password"]
    assert (smtp.evidence[0].frame, smtp.evidence[0].value) == (21, "secret3")
    assert "carol" in smtp.summary  # the decoded user name is named
