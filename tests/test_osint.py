from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import request

from typer.testing import CliRunner

from pcap_doctor.cli import app
from pcap_doctor.detectors.osint import OsintDetector
from pcap_doctor.index import IndexBuilder
from pcap_doctor.tshark import TsharkRunner

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dns_external.pcap"
runner = CliRunner()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.last_body = body  # type: ignore[attr-defined]
        payload = json.dumps({"status": "ok", "verdict": "benign", "received": json.loads(body.decode())}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


def _start_server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.last_body = b""
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, f"http://127.0.0.1:{httpd.server_port}/lookup"


def test_osint_no_endpoint_makes_no_network_call(monkeypatch):
    called = {"count": 0}

    def boom(*args, **kwargs):
        called["count"] += 1
        raise AssertionError("network contacted without --endpoint")

    monkeypatch.setattr(request, "urlopen", boom)
    # also guard the command's imported name
    import pcap_doctor.cli.osint as osint_mod

    monkeypatch.setattr(osint_mod.request, "urlopen", boom)

    result = runner.invoke(app, ["osint", str(FIXTURE), "--json"])
    assert result.exit_code == 0, result.output
    assert called["count"] == 0
    data = json.loads(result.stdout)
    assert data["schema"] == "doctor/1"
    assert data["data"]["osint"]["endpoint_contacted"] is False
    assert data["data"]["osint"]["endpoint"] is None
    assert data["data"]["osint"]["indicators"]["file_sha256"]
    notes = " ".join(data.get("data", {}).get("notes", [])).lower()
    assert "no network contact without --endpoint" in notes
    assert data["findings"] == []


def test_osint_detector_silent_without_opt_in():
    index = IndexBuilder(TsharkRunner(FIXTURE)).build()
    # Normal analyze path / no opt-in: no lookup data attached, no findings.
    assert OsintDetector().detect(index) == []


def test_osint_with_stub_endpoint_reports_lookup_result(monkeypatch):
    httpd, url = _start_server()
    try:
        result = runner.invoke(app, ["osint", str(FIXTURE), "--endpoint", url, "--json"])
        assert result.exit_code == 0, result.output
        combined = (result.stdout + (result.stderr or "")).lower()
        assert "this query left the machine" in combined
        data = json.loads(result.stdout)
        assert data["schema"] == "doctor/1"
        assert data["data"]["osint"]["endpoint_contacted"] is True
        assert data["data"]["osint"]["endpoint"] == url
        codes = [f["id"] for f in data["findings"]]
        assert "OSINT_LOOKUP_PERFORMED" in codes
        assert all(f["detector"] == "d25.osint" for f in data["findings"])
        assert all("verdict" not in f.get("summary", "").lower() or "benign" in f.get("summary", "").lower() for f in data["findings"])
        # result from stub is carried through
        assert any("benign" in f["summary"] for f in data["findings"])
        assert httpd.last_body  # endpoint was actually contacted
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_osint_detector_reports_only_when_opted_in():
    index = IndexBuilder(TsharkRunner(FIXTURE)).build()
    index.osint_lookups = [{"kind": "hash", "indicator": "abc", "endpoint": "http://example.invalid", "result": '{"ok":true}', "frame": 1}]
    findings = OsintDetector().detect(index)
    assert [f.code for f in findings] == ["OSINT_LOOKUP_PERFORMED"]
    assert findings[0].severity == "info"
    assert findings[0].remediation
