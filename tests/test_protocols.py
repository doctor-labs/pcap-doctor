"""Protocol hierarchy breakdown: frames and bytes per protocol layer (issue #279)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_each_layer_is_counted_once_per_frame(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("tunnels.pcap")).index, "protocols")
    frames = {r["protocol"]: r["frames"] for r in rows}
    # tunnels.pcap: GRE-in-IP, VXLAN-in-UDP and an 802.1Q frame
    assert frames["eth"] == 3 and frames["ip"] == 3 and frames["udp"] == 3
    assert frames["gre"] == 1 and frames["vxlan"] == 1 and frames["vlan"] == 1
    assert frames["dns"] == 1 and frames["data"] == 2
    assert "ethertype" not in frames  # a dissector-internal layer, not a protocol
    by_proto = {r["protocol"]: r for r in rows}
    assert by_proto["eth"]["bytes"] >= by_proto["gre"]["bytes"] > 0
    assert by_proto["eth"]["percent_frames"] == 100.0
    # most frames first
    assert [r["frames"] for r in rows] == sorted((r["frames"] for r in rows), reverse=True)
