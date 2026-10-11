"""Zeek-style device log: one row per sender MAC with its OUI vendor and IPs (issue #274, MAC part of #245)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_device_log_has_one_row_per_mac_with_vendor_and_ips(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("devices.pcap")).index, "device")
    by_mac = {r["mac"]: r for r in rows}
    assert set(by_mac) == {"00:1a:11:aa:bb:01", "b8:27:eb:12:34:56", "02:00:00:00:00:0c"}, rows
    assert "Google" in (by_mac["00:1a:11:aa:bb:01"]["vendor"] or "")
    assert "Raspberry" in (by_mac["b8:27:eb:12:34:56"]["vendor"] or "")
    assert by_mac["02:00:00:00:00:0c"]["vendor"] is None  # locally administered, no vendor
    assert by_mac["b8:27:eb:12:34:56"]["ips"] == ["10.40.0.2"]
    assert by_mac["00:1a:11:aa:bb:01"]["packets"] == 2
