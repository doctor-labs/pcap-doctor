"""Zeek-style syslog.log: RFC 3164 and RFC 5424 messages over UDP/514 (issue #228)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import _rfc3164_msg, log_rows


@requires_tshark
def test_syslog_log_records_facility_level_version_and_message(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("syslog.pcap")).index, "syslog")
    by_host = {r["hostname"]: r for r in rows}
    assert set(by_host) == {"myhost", "myhost2", "myhost3"}, rows
    r3164 = by_host["myhost"]  # RFC 3164
    assert (r3164["facility"], r3164["level"]) == (4, 2)
    assert r3164["version"] is None  # RFC 3164 has no version field
    assert r3164["timestamp"] == "Oct 11 22:14:15"  # the RFC 3164 timestamp text
    assert r3164["appname"] is None  # tshark leaves appname empty for RFC 3164
    assert r3164["procid"] == "myapp"  # tshark maps the RFC 3164 TAG into procid
    assert r3164["msgid"] is None
    assert r3164["msg"] == "123]: hello world from rfc3164"
    r5424 = by_host["myhost2"]  # RFC 5424
    assert (r5424["facility"], r5424["level"]) == (4, 2)
    assert r5424["version"] == "1"  # RFC 5424 version field
    assert r5424["hostname"] == "myhost2"
    assert r5424["appname"] == "myapp2"
    assert r5424["procid"] == "123"
    assert r5424["msgid"] == "42"
    assert r5424["msg"] == "ID42 [example@12345 key=val] hello from rfc5424"


@requires_tshark
def test_syslog_log_truncates_long_messages(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("syslog.pcap")).index, "syslog")
    long_row = next(r for r in rows if r["hostname"] == "myhost3")
    assert long_row["msg"] == "99]: " + "x" * 195  # tshark keeps the tag prefix, truncated to 200 chars
    assert len(long_row["msg"]) == 200


@requires_tshark
def test_syslog_log_has_connection_endpoints(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("syslog.pcap")).index, "syslog")
    row = next(r for r in rows if r["hostname"] == "myhost")
    assert (row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"]) == (
        "10.0.0.10", 51400, "10.0.0.20", 514)


def test_rfc3164_msg_normalises_both_tshark_shapes() -> None:
    ts = "Oct 11 22:14:15"
    new = ("123]: hi", None)  # tshark 4.4: msg after the TAG, msgid empty
    assert _rfc3164_msg(None, ts, "123]: hi", None) == new
    # tshark 4.2 (CI, Ubuntu 24.04): whole line in msg, text after the TAG in msgid
    assert _rfc3164_msg(None, ts, ts + " myhost myapp[123]: hi", "[123]: hi") == new
    # RFC 5424 is never rewritten
    assert _rfc3164_msg("1", "2024-01-01T00:00:00Z", "ID42 hi", "42") == ("ID42 hi", "42")
