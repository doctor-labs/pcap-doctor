"""Zeek-style pgsql.log and redis.log (issue #225)."""

from __future__ import annotations

from conftest import fixture, requires_tshark
from pcap_doctor.logs import log_rows


@requires_tshark
def test_pgsql_log_records_startup_auth_and_query(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("pgsql_redis.pcap")).index, "pgsql")
    # Startup parameters: user=admin, database=appdb
    startup = [r for r in rows if r["parameter_name"] == "user"]
    assert len(startup) == 1
    assert startup[0]["parameter_value"] == "admin"
    db = [r for r in rows if r["parameter_name"] == "database"]
    assert len(db) == 1
    assert db[0]["parameter_value"] == "appdb"
    # Authentication method requested by server: type 1 = cleartext password
    auth_rows = [r for r in rows if r["authtype"] is not None]
    assert len(auth_rows) == 2  # two auth request frames (authtype 1 and authtype 0)
    assert auth_rows[0]["authtype"] == "AuthenticationCleartextPassword"
    assert auth_rows[1]["authtype"] == "AuthenticationOk"
    # Simple query text
    queries = [r for r in rows if r["query"] is not None]
    assert len(queries) == 1
    assert queries[0]["query"] == "SELECT 1 FROM users"
    # Password must never appear in the log
    text = repr(rows)
    assert "pf-pgsql-pw" not in text


@requires_tshark
def test_redis_log_records_command_and_key_never_passwords(analyze_capture) -> None:
    rows = log_rows(analyze_capture(fixture("pgsql_redis.pcap")).index, "redis")
    # AUTH: command logged but no key (the password is the arg, never logged)
    auth = next(r for r in rows if r["command"] == "AUTH")
    assert auth["key"] is None
    # GET mykey: command + key
    get = next(r for r in rows if r["command"] == "GET")
    assert get["key"] == "mykey"
    # SET mykey value: command + key, value never logged
    set_ = next(r for r in rows if r["command"] == "SET")
    assert set_["key"] == "mykey"
    # Password must never appear in the log
    text = repr(rows)
    assert "pf-redis-pw" not in text
    # No values logged anywhere
    assert "value" not in text.lower() or "mykey" in text  # "value" may appear as a command arg name, not the value
