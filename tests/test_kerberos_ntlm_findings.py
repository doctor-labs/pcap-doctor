"""Kerberos and NTLM findings: weak etypes, missing pre-auth, NTLMv1 and unsigned NTLM (#205). Codes and metadata only."""

from __future__ import annotations

from conftest import fixture, requires_tshark


def _by_code(result) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in result.findings:
        if f.code.startswith(("KERBEROS_", "NTLM_")):  # other detectors (SMB, ...) may fire on the same capture
            out.setdefault(f.code, []).append(f)
    return out


@requires_tshark
def test_kerberos_weak_etypes_and_missing_preauth(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("kerberos_weak.pcap")))
    assert set(found) == {"KERBEROS_WEAK_ETYPE", "KERBEROS_NO_PREAUTH"}
    severities = sorted(f.severity for f in found["KERBEROS_WEAK_ETYPE"])
    assert severities == ["high", "medium"]  # DES TGS reply is high, RC4 AS reply is medium
    assert all(f.evidence and f.evidence[0].frame > 0 for f in found["KERBEROS_WEAK_ETYPE"])
    assert all(f.evidence[0].value for f in found["KERBEROS_NO_PREAUTH"])
    assert all(f.references for f in found["KERBEROS_WEAK_ETYPE"] + found["KERBEROS_NO_PREAUTH"])


@requires_tshark
def test_ntlm_v1_and_unsigned_challenge(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("ntlm_v1.pcap")))
    assert set(found) == {"NTLM_V1_AUTH", "NTLM_SIGNING_NOT_NEGOTIATED"}
    assert found["NTLM_V1_AUTH"][0].severity == "high"
    assert found["NTLM_SIGNING_NOT_NEGOTIATED"][0].severity == "medium"
    assert all(f.evidence[0].frame > 0 for f in found["NTLM_V1_AUTH"] + found["NTLM_SIGNING_NOT_NEGOTIATED"])


@requires_tshark
def test_kerberos_preauth_fixture_is_not_flagged_as_no_preauth(analyze_capture) -> None:
    # The KDC demanded pre-authentication (PREAUTH_REQUIRED) on this exchange, so the retry is not a no-preauth request.
    assert "KERBEROS_NO_PREAUTH" not in _by_code(analyze_capture(fixture("kerberos.pcap")))
