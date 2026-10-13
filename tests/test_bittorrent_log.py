"""Zeek-style bittorrent.log for DHT queries and peer-wire handshakes (issue #276)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_bittorrent_log_records_dht_messages_and_handshake(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("bt_dht.pcap")).index, "bittorrent")
    by_q = {(r["query"], r["txid"]): r for r in rows if r["msg_type"] == "request"}
    assert set(by_q) == {
        ("ping", "aabb"),
        ("find_node", "aabb"),
        ("get_peers", "aabb"),
        ("announce_peer", "aabb"),
    }, sorted((r.get("query") or "", r.get("txid") or "", r["msg_type"]) for r in rows)
    assert by_q[("get_peers", "aabb")]["info_hash"] == "11" * 20
    assert by_q[("announce_peer", "aabb")]["info_hash"] == "11" * 20
    # the ping response and the handshake are not requests
    others = [r for r in rows if r["msg_type"] != "request"]
    assert sorted(r["msg_type"] for r in others) == ["handshake", "response"]
    handshakes = [r for r in others if r["msg_type"] == "handshake"]
    assert len(handshakes) == 1
    hs = handshakes[0]
    assert hs["info_hash"] == "11" * 20
    assert hs["peer_id_prefix"] == "-AZ1234-"


@requires_tshark
def test_bittorrent_log_rows_carry_originator_ids(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("bt_dht.pcap")).index, "bittorrent")
    assert all(r["id.orig_h"] == "10.50.0.2" and r["id.orig_p"] == 6881 for r in rows)
    assert all(r["id.resp_h"] == "10.50.0.3" for r in rows)
