"""kerberos.log and ntlm.log: names, realms, outcomes, and never any crackable material (issue #205)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
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


def test_no_crackable_fields_are_ever_requested() -> None:
    fields = set(PASSES["kerberos"].fields) | set(PASSES["ntlm"].fields)
    assert not fields & {"ntlmssp.auth.ntresponse", "ntlmssp.auth.lmresponse", "ntlmssp.ntlmserverchallenge",
                         "kerberos.cipher"}
