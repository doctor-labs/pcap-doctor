"""SIEM log shipping: JSON-lines, RFC 5424 syslog and HTTP POST of the EVE events (issue #257)."""

from __future__ import annotations

import json
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.ship import format_syslog

SYSLOG_HEADER = re.compile(r"^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) - (.*)$")


def _event() -> dict:
    return {
        "timestamp": "2026-10-15T10:00:00.123456+0000",
        "event_type": "alert",
        "alert": {"signature": "TLS_CIPHER_WEAK", "severity": 2},
    }


def test_syslog_line_is_rfc5424_with_eve_json_as_msg() -> None:
    line = format_syslog(_event())
    match = SYSLOG_HEADER.match(line)
    assert match, line
    pri, stamp, host, app_name, procid, msgid, msg = match.groups()
    assert int(pri) == 16 * 8 + 4  # local0.warning: the alert severity 2 maps to warning
    assert stamp == "2026-10-15T10:00:00.123456+00:00"
    assert (host, app_name, procid, msgid) == ("-", "pcap-doctor", "-", "alert")
    assert json.loads(msg) == _event()
    assert "\n" not in line


def test_syslog_info_events_use_notice_or_info_priority() -> None:
    flow = {"timestamp": "2026-10-15T10:00:00.000000+0000", "event_type": "flow"}
    assert int(SYSLOG_HEADER.match(format_syslog(flow)).group(1)) == 16 * 8 + 6  # local0.info


@requires_tshark
def test_file_jsonl_and_syslog_outputs(cli_runner, tmp_path) -> None:
    pcap = str(fixture("logs_mix.pcap"))
    jsonl = tmp_path / "events.jsonl"
    assert cli_runner.invoke(app, ["ship", pcap, "--out", str(jsonl)]).exit_code == 0
    events = [json.loads(x) for x in jsonl.read_text().splitlines()]
    assert {e["event_type"] for e in events} >= {"flow", "alert"}

    syslog = tmp_path / "events.syslog"
    result = cli_runner.invoke(app, ["ship", pcap, "--format", "syslog", "--out", str(syslog)])
    assert result.exit_code == 0, result.output
    lines = syslog.read_text().splitlines()
    assert len(lines) == len(events) and all(SYSLOG_HEADER.match(x) for x in lines)


@requires_tshark
def test_stdout_is_the_default_destination(cli_runner) -> None:
    result = cli_runner.invoke(app, ["ship", str(fixture("http_basic.pcap")), "--types", "http"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output.splitlines()[0])["event_type"] == "http"


@requires_tshark
def test_two_destinations_exit_2(cli_runner, tmp_path) -> None:
    pcap = str(fixture("http_basic.pcap"))
    result = cli_runner.invoke(app, ["ship", pcap, "--out", str(tmp_path / "x"), "--syslog", "127.0.0.1:9"])
    assert result.exit_code == 2


@requires_tshark
def test_syslog_udp_sends_one_datagram_per_event(cli_runner) -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5)
    port = receiver.getsockname()[1]
    result = cli_runner.invoke(app, ["ship", str(fixture("http_basic.pcap")), "--types", "http",
                                     "--syslog", f"127.0.0.1:{port}", "--proto", "udp"])
    assert result.exit_code == 0, result.output
    datagram, _ = receiver.recvfrom(65535)
    assert SYSLOG_HEADER.match(datagram.decode())
    receiver.close()


@requires_tshark
def test_syslog_tcp_uses_octet_counting(cli_runner) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    # The client connects into the listen backlog and sends a few hundred bytes, which fit the
    # socket buffer, so the CLI finishes before we accept. No helper thread, no ordering race.
    result = cli_runner.invoke(app, ["ship", str(fixture("http_basic.pcap")), "--types", "http",
                                     "--syslog", f"127.0.0.1:{port}", "--proto", "tcp"])
    assert result.exit_code == 0, result.output
    conn, _ = server.accept()
    server.close()
    chunks = []
    with conn:
        conn.settimeout(5)
        while chunk := conn.recv(65536):
            chunks.append(chunk)
    data, frames = b"".join(chunks), []
    while data:  # RFC 6587 octet counting: "<len> <msg>" back to back, no trailing newline
        length, _, data = data.partition(b" ")
        frames.append(data[: int(length)].decode())
        data = data[int(length):]
    assert frames and all(SYSLOG_HEADER.match(f) for f in frames)


class _Collector(BaseHTTPRequestHandler):
    seen: ClassVar[list[dict]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        _Collector.seen.append({"path": self.path, "type": self.headers["Content-Type"],
                                "auth": self.headers.get("Authorization"), "body": body})
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:  # keep test output quiet
        return


@requires_tshark
def test_http_post_sends_jsonl_with_bearer_token_from_env(cli_runner, monkeypatch) -> None:
    _Collector.seen = []
    server = HTTPServer(("127.0.0.1", 0), _Collector)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    monkeypatch.setenv("PCAP_DOCTOR_SHIP_TOKEN", "s3cret-token")
    url = f"http://127.0.0.1:{server.server_address[1]}/ingest"
    result = cli_runner.invoke(app, ["ship", str(fixture("http_basic.pcap")), "--types", "http", "--http", url])
    thread.join(5)
    server.server_close()
    assert result.exit_code == 0, result.output
    got = _Collector.seen[0]
    assert got["path"] == "/ingest" and got["type"] == "application/x-ndjson"
    assert got["auth"] == "Bearer s3cret-token"
    assert json.loads(got["body"].splitlines()[0])["event_type"] == "http"
    assert "s3cret-token" not in result.output


def test_http_destination_must_be_http_or_https(cli_runner) -> None:
    result = cli_runner.invoke(app, ["ship", str(fixture("http_basic.pcap")), "--http", "file:///etc/passwd"])
    assert result.exit_code == 2
