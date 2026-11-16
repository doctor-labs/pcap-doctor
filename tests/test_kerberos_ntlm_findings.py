"""Kerberos and NTLM findings: weak etypes, missing pre-auth, NTLMv1 and unsigned NTLM (#205). Codes and metadata only."""

from __future__ import annotations

from conftest import fixture, requires_tshark


def _by_code(result) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in result.findings:
        # Only the codes this file is about; d25.kerberos_auth emits KERBEROS_* codes of its own.
        if f.code in {"KERBEROS_WEAK_ETYPE", "KERBEROS_NO_PREAUTH", "NTLM_V1_AUTH", "NTLM_SIGNING_NOT_NEGOTIATED"}:
            out.setdefault(f.code, []).append(f)
    return out


@requires_tshark
def test_kerberos_weak_etypes_and_missing_preauth(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("kerberos_weak.pcap")))
    assert {"KERBEROS_WEAK_ETYPE", "KERBEROS_NO_PREAUTH"} <= set(found)
    assert "KERBEROS_TICKET_ISSUED" in found  # exposure view: krbtgt vs service tickets, no ticket/key material
    severities = sorted(f.severity for f in found["KERBEROS_WEAK_ETYPE"])
    assert severities == ["high", "medium"]  # DES TGS reply is high, RC4 AS reply is medium
    assert all(f.evidence and f.evidence[0].frame > 0 for f in found["KERBEROS_WEAK_ETYPE"])
    assert all(f.evidence[0].value for f in found["KERBEROS_NO_PREAUTH"])
    assert all(f.references for f in found["KERBEROS_WEAK_ETYPE"] + found["KERBEROS_NO_PREAUTH"])
    for f in found["KERBEROS_TICKET_ISSUED"]:
        assert f.evidence and all(e.frame > 0 for e in f.evidence)
        blob = " ".join([f.summary] + [e.value for e in f.evidence])
        assert "encPart" not in blob and "cipher" not in blob


@requires_tshark
def test_ntlm_v1_and_unsigned_challenge(analyze_capture) -> None:
    found = _by_code(analyze_capture(fixture("ntlm_v1.pcap")))
    assert {"NTLM_V1_AUTH", "NTLM_SIGNING_NOT_NEGOTIATED", "NTLM_HASH_OFFLINE_CRACKABLE", "NTLM_IDENTITY_EXPOSED", "NTLM_NEGOTIATION"} <= set(found)
    assert found["NTLM_V1_AUTH"][0].severity == "high"
    assert found["NTLM_SIGNING_NOT_NEGOTIATED"][0].severity == "medium"
    assert all(f.evidence[0].frame > 0 for f in found["NTLM_V1_AUTH"] + found["NTLM_SIGNING_NOT_NEGOTIATED"])
    for f in found["NTLM_HASH_OFFLINE_CRACKABLE"] + found["NTLM_IDENTITY_EXPOSED"]:
        assert f.evidence and all(e.frame > 0 and e.value for e in f.evidence)
        assert f.remediation and f.references
        # no secret material: lengths, names and outcomes only
        blob = " ".join([f.summary, f.title] + [e.value for e in f.evidence] + (f.subjects or []))
        assert "ntlmssp.auth.ntresponse" not in blob
        assert "ntlmssp.auth.lmresponse" not in blob
        assert "serverchallenge" not in blob.lower()
        assert "\\x" not in blob and " 00 " not in f" {blob} " and "NTLMSSP\x00" not in blob
        assert all(len(e.value) < 120 for e in f.evidence)  # never a response blob


@requires_tshark
def test_kerberos_preauth_fixture_is_not_flagged_as_no_preauth(analyze_capture) -> None:
    # The KDC demanded pre-authentication (PREAUTH_REQUIRED) on this exchange, so the retry is not a no-preauth request.
    found = _by_code(analyze_capture(fixture("kerberos.pcap")))
    assert "KERBEROS_NO_PREAUTH" not in found
    assert "KERBEROS_TICKET_ISSUED" in found  # reports principal/realm/service and krbtgt vs service ticket
    kinds = " ".join(e.value for f in found["KERBEROS_TICKET_ISSUED"] for e in f.evidence)
    assert "krbtgt/" in kinds and "cifs/" in kinds
    assert all(f.evidence and all(e.frame > 0 for e in f.evidence) for f in found["KERBEROS_TICKET_ISSUED"])
    blob = " ".join([f.summary for f in found["KERBEROS_TICKET_ISSUED"]] + [e.value for f in found["KERBEROS_TICKET_ISSUED"] for e in f.evidence])
    assert "encPart" not in blob and "cipher" not in blob
    assert "\\x" not in blob


@requires_tshark
def test_rejected_ntlm_logon_and_delegation_shape(analyze_capture) -> None:
    ntlm = _by_code(analyze_capture(fixture("ntlm_rejected.pcap")))
    assert {"NTLM_HASH_OFFLINE_CRACKABLE", "NTLM_IDENTITY_EXPOSED", "NTLM_CHALLENGE_UNANSWERED"} & set(ntlm) or "NTLM_HASH_OFFLINE_CRACKABLE" in ntlm
    assert "NTLM_HASH_OFFLINE_CRACKABLE" in ntlm and "NTLM_IDENTITY_EXPOSED" in ntlm
    assert "NTLM_V1_AUTH" not in ntlm  # not accepted by the server
    assert any("not accepted" in f.summary for f in ntlm["NTLM_IDENTITY_EXPOSED"])
    krb = _by_code(analyze_capture(fixture("kerberos_delegation.pcap")))
    assert "KERBEROS_TGS_WITHOUT_PRIOR_AUTH" in krb and "KERBEROS_TICKET_ISSUED" in krb


@requires_tshark
def test_kerberos_ntlm_findings_never_expose_secret_material(analyze_capture) -> None:
    banned = ("ntlmssp.auth.ntresponse", "ntlmssp.auth.lmresponse", "ntlmssp.ntlmserverchallenge",
              "kerberos.cipher", "encPart", "NTLMSSP\\x00")
    for name in ("kerberos.pcap", "kerberos_weak.pcap", "kerberos_delegation.pcap", "ntlm_v1.pcap", "ntlm_rejected.pcap"):
        result = analyze_capture(fixture(name))
        for f in result.findings:
            if not f.code.startswith(("KERBEROS_", "NTLM_")):
                continue
            parts = [f.title, f.summary, f.flow_key or "", " ".join(f.subjects or []), f.remediation or ""]
            parts += [e.field for e in f.evidence] + [e.value for e in f.evidence]
            blob = "\n".join(parts)
            for token in banned:
                assert token not in blob, (name, f.code, token)
            assert "\\x" not in blob, (name, f.code)
            assert all(len(e.value) < 200 for e in f.evidence)
            # no raw response-like blobs: evidence stays short metadata
            assert not any(len(v) > 64 and all(c in "0123456789abcdefABCDEF: " for c in v) for v in [e.value for e in f.evidence])
