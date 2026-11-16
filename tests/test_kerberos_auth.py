"""Kerberos exchange dissection: principal/realm/service inventory, tickets without an AS exchange,
and replies that name no principal (#205). Codes and metadata only."""

from __future__ import annotations

from conftest import fixture, requires_tshark

MY_CODES = ("KERBEROS_PRINCIPAL_INVENTORY", "KERBEROS_TGS_WITHOUT_AS", "KERBEROS_ANONYMOUS_REPLY")


def _by_code(result) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in result.findings:
        if f.code in MY_CODES:
            out.setdefault(f.code, []).append(f)
    return out


@requires_tshark
def test_the_inventory_names_principal_realm_and_service(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("kerberos.pcap")))
    assert set(found) == {"KERBEROS_PRINCIPAL_INVENTORY"}
    inventory = found["KERBEROS_PRINCIPAL_INVENTORY"]
    # alice authenticates to CORP.EXAMPLE and then asks for a cifs ticket: two inventory rows.
    assert len(inventory) == 2
    text = " ".join(f.summary for f in inventory)
    assert "alice@CORP.EXAMPLE" in text
    assert "CORP.EXAMPLE" in text
    assert "cifs/fs1.corp.example" in text
    assert all(f.severity == "info" for f in inventory)
    assert all(f.evidence and f.evidence[0].frame > 0 for f in inventory)
    assert all(f.evidence[0].value for f in inventory)
    assert all(f.references and f.remediation for f in inventory)


@requires_tshark
def test_a_service_ticket_without_an_as_exchange_is_reported(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("kerberos_tgs_only.pcap")))
    assert "KERBEROS_TGS_WITHOUT_AS" in found
    finding = found["KERBEROS_TGS_WITHOUT_AS"][0]
    assert finding.severity == "medium"
    # The capture may simply start after the AS exchange, so the certainty is low.
    assert finding.confidence == "low"
    assert "alice@CORP.EXAMPLE" in finding.summary
    assert "cifs/fs1.corp.example" in finding.summary
    assert finding.evidence and finding.evidence[0].frame > 0
    assert finding.references and finding.remediation


@requires_tshark
def test_a_complete_exchange_is_not_reported_as_missing_an_as(analyze_capture) -> None:
    # kerberos.pcap holds the whole AS exchange (the client retries from a new source port after the
    # KDC demands pre-authentication), so the service ticket is backed by an AS exchange.
    assert "KERBEROS_TGS_WITHOUT_AS" not in _by_code(analyze_capture(fixture("kerberos.pcap")))


@requires_tshark
def test_a_reply_that_names_no_principal_is_reported(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("kerberos_anonymous.pcap")))
    assert "KERBEROS_ANONYMOUS_REPLY" in found
    finding = found["KERBEROS_ANONYMOUS_REPLY"][0]
    assert finding.severity == "low"
    assert finding.confidence == "high"
    assert "CORP.EXAMPLE" in finding.summary
    assert finding.evidence and finding.evidence[0].frame > 0
    assert finding.references and finding.remediation


@requires_tshark
def test_the_detector_is_quiet_without_kerberos(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("strong_tls13.pcap")))
    assert not found


@requires_tshark
def test_the_codes_are_stable_across_runs(analyze_capture) -> None:
    first = analyze_capture(fixture("kerberos.pcap"))
    second = analyze_capture(fixture("kerberos.pcap"))
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert all(f.id for f in first.findings if f.code in MY_CODES)
