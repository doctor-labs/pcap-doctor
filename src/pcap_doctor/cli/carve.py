"""``carve``: file signatures found inside raw packet payloads, per frame (NetworkMiner-style carving). Issue #216."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import typer
from rich.table import Table

from ..carving import carve_runner
from ..tshark import TsharkRunner
from ._console import capture_cell, console, tshark_errors


def carve_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    as_json: bool = typer.Option(False, "--json", help="print the hits as JSON"),
) -> None:
    """List file signatures (magic bytes) found in each packet's TCP/UDP payload, with frame and offset.

    Carves raw packets, not reassembled streams: a file split across segments is not found.
    """
    with tshark_errors():
        hits = carve_runner(TsharkRunner(pcap))
    if as_json:
        typer.echo(json.dumps([asdict(h) for h in hits], indent=2))
        return
    table = Table(title=f"{len(hits)} carved signature(s) in {pcap.name}")
    for name in ("frame", "signature", "offset", "protocol"):
        table.add_column(name, no_wrap=True)
    for h in hits:
        table.add_row(str(h.frame), capture_cell(h.signature), str(h.offset), h.protocol)
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command("carve")(carve_cmd)
