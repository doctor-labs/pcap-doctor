"""DNS answers beyond A/AAAA/CNAME, and the EDNS payload size, in dns.log (issue #229)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_dns_log_answers_cover_txt_mx_ns_ptr_srv_soa_caa(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("dns_records.pcap")).index, "dns")
    got = {(r["query"], r["qtype_name"]): r for r in rows}
    expected = {
        ("example.org", "TXT"): ["TXT 11 v=spf1 -all"],
        ("example.org", "MX"): ["mail.example.org"],
        ("example.org", "NS"): ["ns1.example.org"],
        ("10.0.7.10.in-addr.arpa", "PTR"): ["host.example.org"],
        ("_sip._tcp.example.org", "SRV"): ["sip.example.org"],
        ("example.org", "SOA"): ["ns1.example.org"],
        ("example.org", "CAA"): ["issue letsencrypt.org"],
    }
    assert set(got) == set(expected), sorted(got)
    for key, answers in expected.items():
        assert got[key]["answers"] == answers, (key, got[key]["answers"])
    assert {got[k]["edns_udp_size"] for k in expected if k[1] != "CAA"} == {1232}
    assert got[("example.org", "CAA")]["edns_udp_size"] is None


@requires_tshark
def test_dns_log_answers_cover_svcb_https_dnssec(analyze_capture) -> None:
    """SVCB, HTTPS, RRSIG, DNSKEY, DS, NSEC and NSEC3 answers in dns.answers (#229)."""
    rows = log_rows(analyze_capture(fixture("dns_dnssec.pcap")).index, "dns")
    got = {(r["query"], r["qtype_name"]): r for r in rows}
    expected = {
        ("example.org", "SVCB"): ["svc.example.org"],
        ("example.org", "HTTPS"): ["cdn.example.org"],
        ("example.org", "RRSIG"): ["example.org"],
        ("example.org", "DNSKEY"): ["1296"],
        ("example.org", "DS"): ["0x3039"],
        ("example.org", "NSEC"): ["www.example.org"],
    }
    for key, answers in expected.items():
        assert key in got, (key, sorted(got))
        assert got[key]["answers"] == answers, (key, got[key]["answers"], got[key])
    # NSEC3 answer is a base32 hash whose exact value is non-deterministic across runs
    assert ("example.org", "NSEC3") in got, sorted(got)
    assert got[("example.org", "NSEC3")]["answers"], got[("example.org", "NSEC3")]["answers"]
