"""D25 long_tail: Syslog, BitTorrent/DHT, IRC/SOCKS, and port-inventory exposure (#228)."""

from __future__ import annotations

from conftest import codes, fixture, requires_tshark


@requires_tshark
def test_syslog_cleartext_exposure(analyze_capture) -> None:
    result = analyze_capture(fixture("syslog.pcap"))
    assert "CLEARTEXT_SYSLOG" in codes(result)
    found = [f for f in result.report.findings if f.code == "CLEARTEXT_SYSLOG"]
    assert found and found[0].evidence and found[0].evidence[0].frame > 0
    assert "CLEARTEXT_SYSLOG_SECRET" not in codes(result)


@requires_tshark
def test_bittorrent_infohash_and_dht(analyze_capture) -> None:
    result = analyze_capture(fixture("bt_dht.pcap"))
    assert "SERVICE_BITTORRENT_INFOHASH" in codes(result)
    assert "SERVICE_DHT_BOOTSTRAP" in codes(result)


@requires_tshark
def test_irc_socks_cleartext_inventory(analyze_capture) -> None:
    result = analyze_capture(fixture("irc_chat.pcap"))
    assert "CLEARTEXT_IRC" in codes(result)
    result = analyze_capture(fixture("irc_socks_creds.pcap"))
    assert "CLEARTEXT_IRC" in codes(result)
    assert "CLEARTEXT_SOCKS" in codes(result)


@requires_tshark
def test_long_tail_quiet_on_modern_tls(analyze_capture) -> None:
    result = analyze_capture(fixture("strong_tls13.pcap"))
    assert "CLEARTEXT_SYSLOG" not in codes(result)
    assert "SERVICE_BITTORRENT_INFOHASH" not in codes(result)
    assert "CLEARTEXT_IRC" not in codes(result)


@requires_tshark
def test_port_inventory_protocols(analyze_capture) -> None:
    result = analyze_capture(fixture("long_tail_ports.pcap"))
    got = codes(result)
    assert "SERVICE_FINGER_EXPOSED" in got
    assert "SERVICE_IDENT_EXPOSED" in got
    assert "SERVICE_XMPP_CLEARTEXT" in got
    assert "SERVICE_LPR_EXPOSED" in got
    assert "SERVICE_PIA_EXPOSED" in got
    assert "SERVICE_NCP_EXPOSED" in got
