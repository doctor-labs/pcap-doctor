"""Passive OS guess from the initial TTL of a host's SYNs, p0f-style (issue #244)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_initial_ttl_gives_an_os_family_per_host(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("os_ttls.pcap")).index, "os")
    by_host = {r["host"]: r for r in rows}
    assert set(by_host) == {"10.95.0.10", "10.95.0.20", "10.95.0.30"}, rows  # one row per host
    assert (by_host["10.95.0.10"]["initial_ttl"], by_host["10.95.0.10"]["hops"], by_host["10.95.0.10"]["os_guess"]) == (128, 3, "Windows")
    assert (by_host["10.95.0.20"]["initial_ttl"], by_host["10.95.0.20"]["os_guess"]) == (64, "Linux/Unix/Android/macOS")
    assert (by_host["10.95.0.30"]["initial_ttl"], by_host["10.95.0.30"]["os_guess"]) == (255, "network device")
    assert all(r["syns"] == 2 for r in rows)
