"""Zeek-style tunnel.log: GRE, VXLAN and 802.1Q encapsulations by their outer endpoints (issue #227)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_tunnel_log_lists_each_encapsulation_once_with_its_outer_endpoints(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("tunnels.pcap")).index, "tunnel")
    by_type = {r["tunnel_type"]: r for r in rows}
    assert set(by_type) == {"Tunnel::GRE", "Tunnel::VXLAN", "VLAN"}, rows
    gre = by_type["Tunnel::GRE"]
    assert (gre["id.orig_h"], gre["id.resp_h"], gre["id.resp_p"]) == ("10.10.0.1", "10.10.0.2", 0)
    vx = by_type["Tunnel::VXLAN"]
    assert (vx["id.orig_h"], vx["id.resp_p"], vx["tunnel_id"]) == ("10.20.0.1", 4789, "4242")
    assert by_type["VLAN"]["tunnel_id"] == "100"
    assert all(r["action"] == "Tunnel::DISCOVER" for r in rows)
