"""SIEM log shipping (issue #257): the EVE events as JSON-lines, RFC 5424 syslog, or HTTP POST.

Stdlib only (``socket``, ``urllib.request``). Nothing is sent unless the caller names a destination; the
default is stdout. The events are the same ``build_eve`` objects that ``pcap-doctor eve`` prints.

Syslog lines use the RFC 5424 header with the EVE event as the MSG, so a receiver can parse the
header and still get the full JSON. The HOSTNAME field is the NILVALUE ``-`` so no capture or host
name leaks into the header.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from typing import Any

APP_NAME = "pcap-doctor"
TOKEN_ENV = "PCAP_DOCTOR_SHIP_TOKEN"
_FACILITY_LOCAL0 = 16
_SYSLOG_SEVERITY = {1: 3, 2: 4, 3: 5}  # EVE alert severity -> err, warning, notice
_INFO = 6


def jsonl_lines(events: list[dict[str, Any]]) -> list[str]:
    return [json.dumps(e, ensure_ascii=False) for e in events]


def format_syslog(event: dict[str, Any]) -> str:
    """One RFC 5424 line: ``<PRI>1 TIMESTAMP - pcap-doctor - EVENT_TYPE - JSON``."""
    severity = _SYSLOG_SEVERITY.get(event["alert"]["severity"], 5) if event["event_type"] == "alert" else _INFO
    stamp = event["timestamp"]
    if stamp.endswith("+0000"):  # RFC 3339 wants a colon in the offset
        stamp = stamp[:-5] + "+00:00"
    msg = json.dumps(event, ensure_ascii=False)
    return f"<{_FACILITY_LOCAL0 * 8 + severity}>1 {stamp} - {APP_NAME} - {event['event_type']} - {msg}"


def send_syslog(lines: list[str], host: str, port: int, proto: str) -> None:
    """UDP: one datagram per line. TCP: RFC 6587 octet-counting frames, no delimiter.

    ponytail: a UDP datagram cannot exceed ~64 KiB, so a larger event raises OSError; the CLI reports it.
    """
    kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    family, _, _, _, addr = socket.getaddrinfo(host, port, type=kind)[0]
    with socket.socket(family, kind) as sock:
        if proto == "udp":
            for line in lines:
                sock.sendto(line.encode("utf-8"), addr)
            return
        sock.settimeout(10)
        sock.connect(addr)
        for line in lines:
            data = line.encode("utf-8")
            sock.sendall(f"{len(data)} ".encode("ascii") + data)


def post_jsonl(lines: list[str], url: str, token: str | None) -> None:
    """POST the lines as ``application/x-ndjson``. The token goes in the Authorization header only."""
    headers = {"Content-Type": "application/x-ndjson"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = ("\n".join(lines) + "\n").encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:
        response.read()
