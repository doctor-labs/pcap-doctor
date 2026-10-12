"""Web attack detection on HTTP request URIs: SQLi, XSS, LFI, traversal, command injection (#233).

The fixture gives each attack payload its own client IP, so a finding is attributed to
exactly one request. The benign request (client 10.61.0.9) is the negative control.
"""

from __future__ import annotations

from conftest import fixture, requires_tshark

SQLI = "10.61.0.2"
XSS = "10.61.0.3"
LFI = "10.61.0.4"
TRAVERSAL = "10.61.0.5"
CMDI = "10.61.0.6"
BENIGN = "10.61.0.9"


@requires_tshark
def test_each_attack_uri_is_reported_and_the_benign_one_is_not(analyze_capture) -> None:
    result = analyze_capture(fixture("web_attack.pcap"))
    hits = [f for f in result.report.findings if f.code.startswith("HTTP_WEB_ATTACK")]
    subjects = {ip for f in hits for ip in f.subjects}

    for client, label in ((SQLI, "SQL"), (XSS, "XSS"), (LFI, "LFI"), (TRAVERSAL, "traversal"), (CMDI, "command")):
        assert client in subjects, f"no web-attack finding for the {label} request from {client}: {hits}"

    assert BENIGN not in subjects, f"the benign request was reported as a web attack: {hits}"


@requires_tshark
def test_the_five_payloads_map_to_five_distinct_kinds(analyze_capture) -> None:
    result = analyze_capture(fixture("web_attack.pcap"))
    kinds = {
        f.code.removeprefix("HTTP_WEB_ATTACK_")
        for f in result.report.findings
        if f.code.startswith("HTTP_WEB_ATTACK")
    }
    assert kinds == {"SQLI", "XSS", "LFI", "TRAVERSAL", "COMMAND_INJECTION"}, kinds
