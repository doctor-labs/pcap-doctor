"""Pivot search across the Zeek-style log tables (issue #250)."""

from __future__ import annotations

from pcap_doctor.logs import LogTable, pivot


def _table(name: str, columns: list[tuple[str, str]], rows: list[dict[str, object]]) -> LogTable:
    return LogTable(name, columns, rows)


def test_value_found_across_two_logs_and_two_fields() -> None:
    conn = _table("conn", [("uid", "string"), ("id.orig_h", "addr")],
                  [{"uid": "C1", "id.orig_h": "10.0.0.5"}, {"uid": "C2", "id.orig_h": "10.0.0.9"}])
    dns = _table("dns", [("uid", "string"), ("query", "string")],
                 [{"uid": "C3", "query": "example.com"}, {"uid": "C9", "query": "other.example"}])
    logs = {"conn": conn, "dns": dns}
    assert pivot(logs, "C1") == [("conn", 0, "uid")]
    # the same IP as a hostname field and an address field in two logs
    assert sorted(pivot(logs, "10.0.0.5")) == [("conn", 0, "id.orig_h")]
    assert sorted(pivot(logs, "example.com")) == [("dns", 0, "query")]


def test_value_in_two_fields_of_one_log() -> None:
    ssl = _table("ssl", [("id.orig_h", "addr"), ("server_name", "string")],
                 [{"id.orig_h": "10.0.0.5", "server_name": "10.0.0.5"}])
    assert sorted(pivot({"ssl": ssl}, "10.0.0.5")) == [("ssl", 0, "id.orig_h"), ("ssl", 0, "server_name")]


def test_value_nowhere_is_an_empty_result() -> None:
    conn = _table("conn", [("uid", "string")], [{"uid": "C1"}])
    assert pivot({"conn": conn}, "no-such-value") == []


def test_hostname_match_is_case_insensitive() -> None:
    http = _table("http", [("host", "string")], [{"host": "Example.COM"}])
    assert pivot({"http": http}, "example.com") == [("http", 0, "host")]
    # and the other way round
    assert pivot({"http": http}, "EXAMPLE.com") == [("http", 0, "host")]


def test_ip_text_match_is_case_insensitive_and_none_is_skipped() -> None:
    conn = _table("conn", [("id.orig_h", "addr")], [{"id.orig_h": None}, {"id.orig_h": "10.0.0.5"}])
    assert pivot({"conn": conn}, "10.0.0.5") == [("conn", 1, "id.orig_h")]


def test_row_order_is_table_then_row_then_field() -> None:
    t = _table("t", [("a", "string"), ("b", "string")],
               [{"a": "x", "b": "x"}, {"a": "x", "b": None}])
    assert pivot({"t": t}, "x") == [("t", 0, "a"), ("t", 0, "b"), ("t", 1, "a")]
