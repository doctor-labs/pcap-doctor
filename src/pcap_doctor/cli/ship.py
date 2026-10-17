"""``ship``: send EVE events to a SIEM (file, stdout, syslog host, or HTTP POST). Issue #257."""

from __future__ import annotations

import os
import urllib.parse
from pathlib import Path

import typer

from ..eve import EVENT_TYPES, build_eve
from ..index import IndexBuilder
from ..ship import TOKEN_ENV, format_syslog, jsonl_lines, post_jsonl, send_syslog
from ..tshark import TsharkRunner
from ._console import tshark_errors


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code=2)


def ship(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    out: Path | None = typer.Option(None, "--out", "-o", help="write to this file"),
    fmt: str = typer.Option("jsonl", "--format", help="jsonl or syslog, for --out and stdout"),
    syslog: str | None = typer.Option(None, "--syslog", help="host:port of a syslog receiver (RFC 5424)"),
    proto: str = typer.Option("udp", "--proto", help="udp or tcp, for --syslog"),
    http: str | None = typer.Option(None, "--http", help="http(s) URL to POST JSON-lines to"),
    token_env: str = typer.Option(TOKEN_ENV, "--token-env", help="env var holding a bearer token for --http"),
    types: str = typer.Option("", "--types", help=f"comma-separated subset of: {', '.join(EVENT_TYPES)}"),
) -> None:
    """Ship EVE events for SIEM ingest. Sends nothing unless a destination is named; default is stdout."""
    destinations = [d for d in (out, syslog, http) if d is not None]
    if len(destinations) > 1:
        raise _fail("choose one destination: --out, --syslog or --http")
    if fmt not in ("jsonl", "syslog"):
        raise _fail("--format must be jsonl or syslog")
    if proto not in ("udp", "tcp"):
        raise _fail("--proto must be udp or tcp")

    target: tuple[str, int] | None = None
    if syslog is not None:
        host, sep, port_text = syslog.rpartition(":")
        if not sep or not host or not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise _fail("--syslog must be host:port")
        target = (host, int(port_text))
    shown_url = None
    if http is not None:
        parts = urllib.parse.urlsplit(http)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise _fail("--http must be an http:// or https:// URL")
        # Only scheme and host are shown: the path or query may carry a secret.
        shown_url = f"{parts.scheme}://{parts.netloc}"

    wanted = tuple(x.strip() for x in types.split(",") if x.strip()) or EVENT_TYPES
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
        try:
            events = build_eve(index, wanted)
        except ValueError as exc:
            raise _fail(str(exc)) from exc

    try:
        if http is not None:
            token = os.environ.get(token_env) or None
            post_jsonl(jsonl_lines(events), http, token)
            typer.echo(f"posted {len(events)} events to {shown_url}", err=True)
        elif target is not None:
            lines = [format_syslog(e) for e in events]
            send_syslog(lines, target[0], target[1], proto)
            typer.echo(f"sent {len(events)} syslog events to {target[0]}:{target[1]} ({proto})", err=True)
        else:
            lines = [format_syslog(e) for e in events] if fmt == "syslog" else jsonl_lines(events)
            text = "".join(line + "\n" for line in lines)
            if out is None:
                typer.echo(text, nl=False)
            else:
                out.write_text(text, encoding="utf-8")
                typer.echo(f"wrote {out} ({len(events)} events)", err=True)
    except OSError as exc:
        # Name the error class only: the message can echo the URL or host back.
        typer.echo(f"error: shipping failed ({type(exc).__name__})", err=True)
        raise typer.Exit(code=1) from exc


def register(app: typer.Typer) -> None:
    app.command()(ship)
