"""Local indicator matching: IPs/CIDRs, domains and URLs from a file you supply (``analyze --ioc``, issue #236).

Offline by design: indicator files are read from disk, nothing is fetched. The matcher only looks at what the
index already holds (DNS names and answers, TLS SNI, HTTP Host/URI, observed hosts), so it adds no tshark pass.

File format: one indicator per line, the first whitespace-separated token is the indicator, the rest is a label.
Blank lines and ``#`` comments are skipped. The type is detected from the token:

* ``1.2.3.4`` or ``10.0.0.0/8`` -> IP address / CIDR, matched against DNS answers and observed hosts;
* ``example.com`` -> domain, matches the name and its subdomains; a ``*.`` prefix is accepted and means the same;
* ``http://host/path?query`` -> URL, matched exactly against the HTTP Host and request URI.

Hash indicators are reported as skipped: the index holds no file hashes, so they would never match.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .index import CaptureIndex

_DOMAIN = re.compile(r"(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_HASH = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


@dataclass(frozen=True)
class Indicator:
    kind: str  # "ip" | "domain" | "url"
    value: str
    label: str = ""


@dataclass
class IocHit:
    kind: str
    indicator: str
    subject: str  # the IP, the matched name, or host + URI
    source: str  # "dns" | "tls" | "http" | "ip"
    frame: int
    flow_key: str | None
    label: str = ""


def _parse_token(token: str) -> tuple[str | None, str | None]:
    """Return ``(kind, None)`` for a usable indicator, ``(None, reason)`` otherwise."""
    if "://" in token:
        parts = urlsplit(token)
        if parts.scheme in ("http", "https") and parts.hostname:
            return "url", None
        return None, "URL indicator needs an http(s) scheme and a host"
    try:
        ipaddress.ip_network(token, strict=False)
        return "ip", None
    except ValueError:
        pass
    if _HASH.fullmatch(token):
        return None, "hash indicators are not matched (no file hashes in the index)"
    if _DOMAIN.fullmatch(token.lower()):
        return "domain", None
    return None, f"unrecognised indicator {token[:60]!r}"


def load_iocs(paths: list[Path]) -> tuple[list[Indicator], list[str]]:
    """Read indicator files. Returns the usable indicators and one warning per skipped line."""
    indicators: list[Indicator] = []
    warnings: list[str] = []
    for path in paths:
        for lineno, raw in enumerate(Path(path).read_text(errors="replace").splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            token, *rest = re.split(r"\s+", line, maxsplit=1)
            label = rest[0] if rest else ""
            kind, reason = _parse_token(token)
            if kind is None:
                warnings.append(f"[ioc] {Path(path).name}:{lineno}: {reason}")
                continue
            if kind == "domain":
                token = token.lower().removeprefix("*.")
            indicators.append(Indicator(kind, token, label))
    return indicators, warnings


def _domain_hit(name: str, domains: list[Indicator]) -> Indicator | None:
    name = name.lower().rstrip(".")
    for ind in domains:
        if name == ind.value or name.endswith("." + ind.value):
            return ind
    return None


def _host(value: str | None) -> str:
    # The Host header may carry a port; indicators never do.
    return re.sub(r":\d+$", "", (value or "").lower())


def match_iocs(index: CaptureIndex, indicators: list[Indicator]) -> list[IocHit]:
    """Match indicators against the index. One hit per (indicator, subject); the first frame wins."""
    ips = [(ind, ipaddress.ip_network(ind.value, strict=False)) for ind in indicators if ind.kind == "ip"]
    domains = [ind for ind in indicators if ind.kind == "domain"]
    urls: list[tuple[Indicator, str, str]] = []
    for item in indicators:
        if item.kind == "url":
            parts = urlsplit(item.value)
            urls.append((item, parts.hostname or "", (parts.path or "/") + (f"?{parts.query}" if parts.query else "")))

    out: list[IocHit] = []
    seen: set[tuple[str, str, str]] = set()

    def add(ind: Indicator, subject: str, source: str, frame: int, flow_key: str | None) -> None:
        if not frame or (ind.value, subject, ind.kind) in seen:
            return
        seen.add((ind.value, subject, ind.kind))
        out.append(IocHit(ind.kind, ind.value, subject, source, frame, flow_key, ind.label))

    def match_ip(text: str, source: str, frame: int, flow_key: str | None) -> None:
        try:
            address = ipaddress.ip_address(text.strip())
        except ValueError:
            return
        for ind, net in ips:
            if address in net:
                add(ind, str(address), source, frame, flow_key)

    for dns in index.dns:
        ind = _domain_hit(dns.name, domains)
        if ind:
            add(ind, dns.name.lower().rstrip("."), "dns", dns.frame, dns.key)
        for answer in dns.answers:
            match_ip(answer, "dns", dns.frame, dns.key)

    for tls in index.tls.values():
        if not tls.sni or tls.client_hello is None:
            continue
        ind = _domain_hit(tls.sni, domains)
        if ind:
            add(ind, tls.sni.lower().rstrip("."), "tls", tls.client_hello.frame, tls.key)

    for http in index.http:
        if not http.host or http.uri is None:
            continue
        host = _host(http.host)
        ind = _domain_hit(host, domains)
        if ind:
            add(ind, host, "http", http.frame, http.key)
        for url_ind, url_host, url_path in urls:
            if host == url_host and http.uri == url_path:
                add(url_ind, f"{host}{http.uri}", "http", http.frame, http.key)

    for observed in index.hosts.values():
        flows = index.flows_touching(observed.ip)
        if flows and ips:
            first = min(flows, key=lambda f: f.first_frame or 1 << 62)
            match_ip(observed.ip, "ip", first.first_frame, first.key)
    return out
