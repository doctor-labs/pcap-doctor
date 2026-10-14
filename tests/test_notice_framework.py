"""Notice framework: per-code action, dedup and rate-limit from `[notice.CODE]` in the project config (issue #273)."""

from __future__ import annotations

import pytest

from pcap_doctor.config import ConfigError, apply, parse
from pcap_doctor.models import Finding


def _finding(code: str, subject: str = "10.0.0.1", flow: str = "tcp:10.0.0.1:1<->9.9.9.9:443", severity: str = "high") -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=code, severity=severity, confidence="high",
        category="crypto", summary="", scope=f"{code}{subject}{flow}{severity}", subjects=[subject], flow_key=flow,
    )


def test_action_log_moves_findings_out_of_the_report_into_notes() -> None:
    config = parse({"notice": {"TLS_CIPHER_WEAK": {"action": "log"}}}, "cfg")
    findings = [_finding("TLS_CIPHER_WEAK"), _finding("DNS_CLEARTEXT")]
    kept, notes = apply(findings, config)
    assert [f.code for f in kept] == ["DNS_CLEARTEXT"]
    assert any("TLS_CIPHER_WEAK" in n and "logged" in n and findings[0].id in n for n in notes)


def test_action_suppress_drops_findings_and_notes_the_count() -> None:
    config = parse({"notice": {"TLS_CIPHER_WEAK": {"action": "suppress"}}}, "cfg")
    kept, notes = apply([_finding("TLS_CIPHER_WEAK"), _finding("TLS_CIPHER_WEAK", "10.0.0.2")], config)
    assert kept == []
    assert any("suppressed 2 finding(s)" in n and "TLS_CIPHER_WEAK" in n for n in notes)


def test_dedup_collapses_same_notice_on_same_flow_and_keeps_the_worst() -> None:
    config = parse({"notice": {"TLS_CIPHER_WEAK": {"dedup": True}}}, "cfg")
    findings = [
        _finding("TLS_CIPHER_WEAK", severity="medium"),
        _finding("TLS_CIPHER_WEAK", severity="high"),
        _finding("TLS_CIPHER_WEAK", "10.0.0.2"),  # other subject: a different notice, kept
    ]
    kept, notes = apply(findings, config)
    assert [(f.subjects[0], f.severity) for f in kept] == [("10.0.0.1", "high"), ("10.0.0.2", "high")]
    assert any("deduplicated 1" in n and "TLS_CIPHER_WEAK" in n for n in notes)


def test_dedup_is_off_by_default() -> None:
    kept, notes = apply([_finding("TLS_CIPHER_WEAK"), _finding("TLS_CIPHER_WEAK", severity="medium")], parse({}, "cfg"))
    assert len(kept) == 2
    assert not any("deduplicated" in n for n in notes)


def test_max_rate_limits_a_code_per_run_and_notes_the_rest() -> None:
    config = parse({"notice": {"TLS_CIPHER_WEAK": {"max": 2}}}, "cfg")
    findings = [_finding("TLS_CIPHER_WEAK", f"10.0.0.{i}") for i in range(1, 6)] + [_finding("DNS_CLEARTEXT")]
    kept, notes = apply(findings, config)
    assert [f.subjects[0] for f in kept if f.code == "TLS_CIPHER_WEAK"] == ["10.0.0.1", "10.0.0.2"]
    assert any("rate-limited 3" in n and "TLS_CIPHER_WEAK" in n for n in notes)
    assert any(f.code == "DNS_CLEARTEXT" for f in kept)


@pytest.mark.parametrize(
    ("notice", "message"),
    [
        ({"NOT_A_CODE": {"action": "log"}}, "unknown code"),
        ({"TLS_CIPHER_WEAK": {"action": "page"}}, "action"),
        ({"TLS_CIPHER_WEAK": {"max": 0}}, "max"),
        ({"TLS_CIPHER_WEAK": {"max": "2"}}, "max"),
        ({"TLS_CIPHER_WEAK": {"max": True}}, "max"),
        ({"TLS_CIPHER_WEAK": {"dedup": "yes"}}, "dedup"),
        ({"TLS_CIPHER_WEAK": {"severity": "low"}}, "unknown key"),
        ({"TLS_CIPHER_WEAK": "log"}, "table"),
        (["TLS_CIPHER_WEAK"], "table"),
    ],
)
def test_invalid_notice_config_is_rejected(notice, message) -> None:
    with pytest.raises(ConfigError, match=message):
        parse({"notice": notice}, "cfg")
