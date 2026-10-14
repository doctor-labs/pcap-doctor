"""``search``: keyword / byte-pattern search across packet payloads (issue #215).

Runs one on-demand tshark pass that reassembles TCP payloads and reads UDP data payloads per frame,
then reports every offset where the pattern occurs. The pattern is a literal string by default, or a
hex byte string with --hex (e.g. ``deadbeef``). Capture bytes are shown as hex only -- never
re-interpreted as text or passed through ``clean_capture_text``, because a pattern match is data,
not a value a rich table could render as markup.

A non-zero match count exits 0; zero matches exits 1 (useful for CI gates like ``pcap-doctor search
capture.pcap secret --json | jq``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import typer
from rich.table import Table

from ..search import match_to_dict, search_payloads
from ._console import capture_cell, console, tshark_errors

_CMD = "search"


def _resolve_pattern(pattern: str, as_hex: bool) -> bytes:
    if as_hex:
        if not re.fullmatch(r"[0-9a-fA-F]+", pattern) or len(pattern) % 2:
            console.print("[red]--hex pattern must be an even run of hex digits[/red]")
            raise typer.Exit(code=2)
        return bytes.fromhex(pattern)
    return pattern.encode("utf-8")


def search(
    pcap: Path = typer.Argument(..., exists=True, readable=True, help="pcap or pcapng file"),
    pattern: str = typer.Argument(..., help="byte pattern to search for; default a literal text keyword"),
    as_hex: bool = typer.Option(False, "--hex", help="treat PATTERN as a hex byte string (e.g. deadbeef)"),
    as_json: bool = typer.Option(
        False, "--json", help="print matches as JSON; exits 0 when >=1 match, else 1"
    ),
    limit: int = typer.Option(100, "--limit", "-n", help="max matches to show (0 = all)"),
) -> None:
    """Search packet payloads for a keyword or byte pattern; exit 1 when nothing matches."""
    needle = _resolve_pattern(pattern, as_hex)
    try:
        with tshark_errors():
            matches = search_payloads(pcap, needle)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    if as_json:
        shown = matches[:limit] if limit else matches
        typer.echo(
            json.dumps(
                {
                    "pattern": pattern,
                    "hex": as_hex,
                    "matches": len(matches),
                    "results": [match_to_dict(m) for m in shown],
                },
                indent=2,
            )
        )
        raise typer.Exit(code=0 if matches else 1)
    n = len(matches)
    if not n:
        console.print(f"0 match(es) for {capture_cell(pattern)!r} in {pcap.name}")
        raise typer.Exit(code=1)
    shown = matches[:limit] if limit else matches
    table = Table(
        title=f"{n} match(es) for {capture_cell(pattern)!r} in {pcap.name}"
        + (f" (showing {len(shown)})" if len(shown) < n else "")
    )
    for col in ("frame", "proto", "stream", "offset", "length", "snippet"):
        table.add_column(col, no_wrap=True)
    for m in shown:
        # The endpoint span already says which way the packet went (src:port -> dst:port).
        table.add_row(
            str(m.frame),
            m.proto,
            capture_cell(f"{m.src}:{m.sport} {m.direction} {m.dst}:{m.dport}"),
            str(m.offset),
            str(m.length),
            capture_cell(m.snippet.hex()),
        )
    console.print(table)
    if len(shown) < n:
        console.print(f"[dim]{n - len(shown)} more match(es); raise --limit[/dim]")
    raise typer.Exit(code=0)


def register(app: typer.Typer) -> None:
    app.command(_CMD)(search)
