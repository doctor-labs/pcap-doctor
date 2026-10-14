"""Session search and per-session PCAP retrieval (issue #251, Arkime-style).

A read-only layer over ``CaptureIndex``: the search reads the flows and the TLS SNI / HTTP host
names already in the index, and retrieval asks tshark on demand for one session's packets by its
tcp or udp stream index.
"""

from __future__ import annotations

from pathlib import Path

from .index import CaptureIndex
from .models import Flow
from .ondemand import run_fields, run_text


def _names(index: CaptureIndex, key: str, flow: Flow) -> list[str]:
    names = [key, flow.endpoint_a, str(flow.port_a), flow.endpoint_b, str(flow.port_b), flow.app_proto]
    tls = index.tls.get(key)
    if tls is not None and tls.sni:
        names.append(tls.sni)
    # ponytail: scans the HTTP list once per session (O(sessions x exchanges)); index by key if big captures get slow
    names += [h.host for h in index.http if h.key == key and h.host]
    return names


def search_sessions(index: CaptureIndex, text: str = "") -> list[Flow]:
    """Sessions whose key, endpoints, ports, application protocol, TLS SNI or HTTP host contain ``text``.

    Case-insensitive substring match, in first-seen order. An empty ``text`` lists every session.
    """
    needle = text.casefold().strip()
    hits: list[Flow] = []
    for key, flow in index.flows.items():
        if not needle or any(needle in name.casefold() for name in _names(index, key, flow)):
            hits.append(flow)
    return hits


def session_pcap(pcap: Path, flow: Flow, dst: Path) -> int:
    """Write the packets of one session to ``dst`` (tshark's default output format); returns the frame count.

    Selects by ``tcp.stream`` or ``udp.stream`` (the protocol-specific counters, so a UDP session with the
    same index is not included). Raises ``ValueError`` when the session has no stream index.
    """
    if flow.stream_index is None:
        raise ValueError(f"session {flow.key} has no {flow.proto} stream index, so its packets cannot be selected")
    display = f"{flow.proto}.stream == {flow.stream_index}"
    frames = run_fields(pcap, ["frame.number"], display)
    if not frames:
        raise ValueError(f"no packets for session {flow.key} in {pcap.name}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    run_text(pcap, ["-Y", display, "-w", str(dst)])
    return len(frames)
