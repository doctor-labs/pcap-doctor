"""NBNS/NetBIOS name resolution as a Zeek-style netbios.log (issue #221).

Ground truth captured from tshark 4.6.6 on tests/fixtures/netbios_names.pcap:

    1 192.168.56.10 -> 192.168.56.1  NBNS  92  Name query              NB WORKGROUP<00>
    2 192.168.56.1  -> 192.168.56.10 NBNS 104  Name query response     NB 192.168.56.1
    3 192.168.56.10 -> 192.168.56.1  NBNS  92  Name query              NB PF-FILESRV<00>
    4 192.168.56.1  -> 192.168.56.10 NBNS 104  Name query response     NB 192.168.56.20
    5 192.168.56.10 -> 192.168.56.1  NBNS  92  Name query              NB GHOSTBOX<00>

    $ tshark -r tests/fixtures/netbios_names.pcap -T fields \
        -e nbns.id -e nbns.flags.response -e nbns.name -e nbns.addr
    0x1111|False|WORKGROUP<00>|
    0x1111|True|WORKGROUP<00> (Workstation/Redirector)|192.168.56.1
    0x2222|False|PF-FILESRV<00>|
    0x2222|True|PF-FILESRV<00> (Workstation/Redirector)|192.168.56.20
    0x3333|False|GHOSTBOX<00>|

So: two names are answered, one (GHOSTBOX) never is. The name column carries a
suffix tshark appends (``<00>`` for the query, ``(Workstation/Redirector)`` for the
answer) — the log must strip both to the bare NetBIOS name.
"""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.logs import LOG_NAMES, log_rows


@requires_tshark
def test_netbios_is_an_exported_log_name() -> None:
    assert "netbios" in LOG_NAMES


@requires_tshark
def test_netbios_log_has_one_row_per_queried_name(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("netbios_names.pcap")).index, "netbios")
    # GHOSTBOX is queried but never answered, so it still gets a row with no address.
    assert sorted(r["name"] for r in rows) == ["GHOSTBOX", "PF-FILESRV", "WORKGROUP"], rows


@requires_tshark
def test_netbios_log_carries_the_address_returned_for_each_answered_name(analyze_capture) -> None:
    rows = {r["name"]: r for r in log_rows(analyze_capture(fixture("netbios_names.pcap")).index, "netbios")}
    assert rows["WORKGROUP"]["addresses"] == "192.168.56.1", rows["WORKGROUP"]
    assert rows["PF-FILESRV"]["addresses"] == "192.168.56.20", rows["PF-FILESRV"]
    # The unanswered query must not invent an address.
    assert rows["GHOSTBOX"]["addresses"] in (None, "", []), rows["GHOSTBOX"]


@requires_tshark
def test_netbios_log_strips_the_dissector_suffix_from_the_name(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("netbios_names.pcap")).index, "netbios")
    for row in rows:
        assert "<" not in row["name"] and "(" not in row["name"], row["name"]


@requires_tshark
def test_netbios_log_records_the_querying_and_answering_endpoints(analyze_capture) -> None:
    rows = {r["name"]: r for r in log_rows(analyze_capture(fixture("netbios_names.pcap")).index, "netbios")}
    work = rows["WORKGROUP"]
    # The client broadcast the query, so orig is the client and resp is the responder.
    assert (work["id.orig_h"], work["id.orig_p"]) == ("192.168.56.10", 137), work
    assert (work["id.resp_h"], work["id.resp_p"]) == ("192.168.56.1", 137), work
    assert work["is_group"] is True, work  # WORKGROUP was answered with the group flag set


@requires_tshark
def test_netbios_log_is_queryable_and_typos_exit_2(cli_runner, analyze_capture) -> None:
    pcap = str(fixture("netbios_names.pcap"))
    ok = cli_runner.invoke(app, ["query", pcap, 'name == "PF-FILESRV"', "-s", "log:netbios", "--json"])
    assert ok.exit_code == 0, ok.output
    assert "192.168.56.20" in ok.output
    bad = cli_runner.invoke(app, ["query", pcap, "name == \"x\"", "-s", "log:netbioss", "--json"])
    assert bad.exit_code == 2, bad.output