"""kerberos.log and ntlm.log: identities only, while NTLM response material stays in core for opt-in extraction (#205, #382)."""

from __future__ import annotations

import json

from conftest import fixture, requires_tshark
from pcap_doctor.krb_ntlm import NTLMSSP_AUTHENTICATE, NTLMSSP_CHALLENGE
from pcap_doctor.logs import log_rows
from pcap_doctor.tshark import PASSES

COLS = ("request_type", "client", "service", "success", "error_msg", "cipher")


@requires_tshark
def test_kerberos_log_pairs_requests_with_replies_and_errors(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("kerberos.pcap")).index, "kerberos")
    assert [tuple(r[c] for c in COLS) for r in rows] == [
        ("AS", "alice/CORP.EXAMPLE", "krbtgt/CORP.EXAMPLE", False, "KDC_ERR_PREAUTH_REQUIRED", None),
        ("AS", "alice/CORP.EXAMPLE", "krbtgt/CORP.EXAMPLE", True, None, "aes256-cts-hmac-sha1-96"),
        ("TGS", "alice/CORP.EXAMPLE", "cifs/fs1.corp.example", True, None, "aes256-cts-hmac-sha1-96"),
    ]
    assert all(r["id.resp_p"] == 88 for r in rows)


@requires_tshark
def test_ntlm_log_reports_identities_and_server_names(analyze_capture) -> None:
    (row,) = log_rows(analyze_capture(fixture("logs_mix.pcap")).index, "ntlm")
    assert (row["username"], row["hostname"], row["domainname"], row["server_tree_name"]) == (
        "alice", "PF-LAPTOP", "CORP", "CORP")
    (anon,) = log_rows(analyze_capture(fixture("smb_attack.pcap")).index, "ntlm")
    assert anon["username"] is None and anon["domainname"] is None


def test_ntlm_hash_material_fields_are_requested_but_kerberos_cipher_is_not() -> None:
    fields = set(PASSES["ntlm"].fields)
    assert {"ntlmssp.auth.ntresponse", "ntlmssp.auth.lmresponse", "ntlmssp.ntlmserverchallenge"} <= fields
    assert "kerberos.cipher" not in set(PASSES["kerberos"].fields)


@requires_tshark
def test_ntlm_response_material_is_carried_but_never_leaks_to_default_surfaces(analyze_capture) -> None:
    result = analyze_capture(fixture("ntlm_v1.pcap"))
    index = result.index
    auths = [m for m in index.ntlm if m.message_type == NTLMSSP_AUTHENTICATE]
    assert auths, "fixture must contain an NTLM AUTHENTICATE"
    assert any(m.server_challenge for m in index.ntlm if m.message_type == NTLMSSP_CHALLENGE)
    assert any(m.server_challenge and (m.nt_response or m.lm_response) for m in auths)

    # carried for opt-in extraction, but excluded from serialization/repr
    dumped = [m.model_dump(mode="json") for m in auths]
    assert all("lm_response" not in d and "nt_response" not in d and "server_challenge" not in d for d in dumped)
    assert all("lm_response" not in repr(m) and "nt_response" not in repr(m) and "server_challenge" not in repr(m) for m in auths)

    materials = [b.hex() for m in auths for b in (m.lm_response, m.nt_response, m.server_challenge) if b]
    assert materials
    report_blob = json.dumps(result.report.to_json_dict())
    log_blob = json.dumps(log_rows(index, "ntlm"), default=str)
    for blob in (report_blob, log_blob):
        assert "ntlmssp.auth.ntresponse" not in blob
        assert "ntlmssp.auth.lmresponse" not in blob
        assert "ntlmssp.ntlmserverchallenge" not in blob
        for material in materials:
            assert material not in blob.lower() and material not in blob.upper()
    for row in log_rows(index, "ntlm"):
        assert not {"lm_response", "nt_response", "server_challenge"} & set(row)
