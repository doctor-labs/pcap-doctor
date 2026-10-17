"""``session``: search sessions by name or endpoint, and write one session's packets to a file. Issue #251."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from ..index import IndexBuilder
from ..prompts import clean_capture_text
from ..sessions import search_sessions, session_pcap
from ..tshark import TsharkRunner
from ._console import capture_cell, console, tshark_errors


def session(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    query: str = typer.Argument("", help="text to find in endpoints, ports, app protocol, TLS SNI or HTTP host; empty lists all"),
    limit: int = typer.Option(50, "--limit", "-n", help="max sessions listed (0 = all)"),
    as_json: bool = typer.Option(False, "--json", help="matching sessions as JSON"),
    key: str = typer.Option("", "--key", help="flow key of one session to extract (from the listing)"),
    out: Path | None = typer.Option(None, "--out", "-o", help="file to write the packets of the session given with --key"),
) -> None:
    """Find sessions, or write one session's packets (--key with --out) to a capture file."""
    if bool(key) != (out is not None):
        console.print("[red]--key and --out go together[/red]")
        raise typer.Exit(code=2)
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
        if out is not None:
            flow = index.flow(key)
            if flow is None:
                console.print(f"[red]no session {capture_cell(key)} in {capture_cell(pcap.name)}[/red]", highlight=False)
                raise typer.Exit(code=2)
            try:
                count = session_pcap(pcap, flow, out)
            except ValueError as exc:
                console.print(f"[red]{capture_cell(str(exc))}[/red]", highlight=False)
                raise typer.Exit(code=2) from exc
            console.print(f"{out}  ({count} packets)", highlight=False, markup=False)
            return
        flows = search_sessions(index, query)
    shown = flows[:limit] if limit else flows
    if as_json:
        keep = ("key", "proto", "endpoint_a", "port_a", "endpoint_b", "port_b", "app_proto", "packets", "bytes", "stream_index")
        rows = [{k: clean_capture_text(v, 1000) if isinstance(v, str) else v for k, v in f.model_dump().items() if k in keep}
                for f in shown]
        typer.echo(json.dumps(rows, indent=2))
        return
    table = Table(title=f"{len(flows)} session(s) in {pcap.name}" + (f" matching {query!r}" if query else ""))
    for name in ("key", "app", "packets", "bytes", "stream"):
        table.add_column(name, no_wrap=name == "stream")
    for f in shown:
        table.add_row(capture_cell(f.key), capture_cell(f.app_proto), str(f.packets), str(f.bytes),
                      "" if f.stream_index is None else str(f.stream_index))
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command()(session)
