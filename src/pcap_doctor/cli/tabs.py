"""``tabs``: hosts, files and credentials seen in a capture, one tab at a time (issue #252)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from ..browse_tabs import TABS, credentials, files, hosts, narrow
from ..index import IndexBuilder
from ..tshark import TsharkRunner
from ._console import capture_cell, console, tshark_errors


def tabs(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    tab: str = typer.Option("hosts", "--tab", "-t", help=f"which tab: {', '.join(TABS)}"),
    filter_text: str | None = typer.Option(
        None, "--filter", "-f", help="only rows with this text in any column (case-insensitive)"
    ),
) -> None:
    """Browse the hosts, files or credentials in a capture (read-only; findings come from `analyze`)."""
    if tab not in TABS:
        typer.echo(f"error: unknown tab {tab!r}; tabs: {', '.join(TABS)}", err=True)
        raise typer.Exit(code=2)
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
    if tab == "hosts":
        rows = narrow(hosts(index), filter_text)
        table = Table(title=f"{len(rows)} hosts in {pcap.name}")
        for col in ("ip", "mac", "vendor", "hostname", "os", "roles", "flows", "bytes"):
            table.add_column(col, no_wrap=True)
        for h in rows:
            table.add_row(*(capture_cell(str(v)) for v in (
                h.ip, h.mac or "", h.vendor or "", h.hostname or "", h.os_guess or "",
                ",".join(h.roles), h.flows, h.bytes,
            )))
    elif tab == "files":
        table = Table(title=f"files in {pcap.name}")
        for col in ("frame", "source", "name", "flow"):
            table.add_column(col, no_wrap=True)
        for f in narrow(files(index), filter_text):
            table.add_row(*(capture_cell(str(v)) for v in (f.frame, f.source, f.name, f.flow)))
    else:
        table = Table(title=f"credentials in {pcap.name} (secrets redacted)")
        for col in ("frame", "source", "user", "secret", "flow"):
            table.add_column(col, no_wrap=True)
        for c in narrow(credentials(index), filter_text):
            table.add_row(*(capture_cell(str(v)) for v in (c.frame, c.source, c.user or "", c.secret, c.flow)))
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command()(tabs)
