"""``carve``: file signatures found in packet or reassembled stream payloads (NetworkMiner-style carving). Issue #216."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from ..carving import carve_runner, carve_streams, write_hits
from ..prompts import clean_capture_text
from ..tshark import TsharkRunner
from ._console import capture_cell, console, tshark_errors


def carve_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    as_json: bool = typer.Option(False, "--json", help="print the hits as JSON"),
    out: Path | None = typer.Option(
        None, "--out", "-o",
        help="write each carved payload, from its signature to the end of its payload, into DIR as "
             "frame<N>-<offset>.<ext> (or stream<N>-<dir>-<offset>.<ext>). Files are written 0600 and never opened. "
             "Per-packet carving truncates a file that is split across segments.",
    ),
    streams: bool = typer.Option(
        False, "--streams",
        help="carve each reassembled TCP stream and direction instead of single packets, so a file split across "
             "segments is found whole. Runs one tshark follow per TCP stream: slow on large captures.",
    ),
) -> None:
    """List file signatures (magic bytes) found in packet payloads, with frame and offset.

    Default: one packet at a time (TCP and UDP). With --streams: reassembled TCP streams.
    """
    with tshark_errors():
        hits = carve_streams(pcap) if streams else carve_runner(TsharkRunner(pcap))
    paths: list[Path] | None = None
    if out is not None:
        try:
            paths = write_hits(hits, out)
        except (OSError, ValueError) as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    if as_json:
        rows = []
        for i, h in enumerate(hits):
            row: dict[str, object] = {"frame": h.frame or None, "stream": h.stream,
                                      "direction": h.direction or None, "signature": h.signature,
                                      "offset": h.offset, "protocol": h.protocol}
            if paths is not None:
                row["path"] = str(paths[i])
                row["bytes"] = len(h.payload) - h.offset
            rows.append(row)
        typer.echo(json.dumps(rows, indent=2))
        return
    table = Table(title=f"{len(hits)} carved signature(s) in {pcap.name}")
    for name in ("where", "signature", "offset", "protocol", *(("path",) if paths is not None else ())):
        table.add_column(name, no_wrap=name != "path")
    for i, h in enumerate(hits):
        where = f"frame {h.frame}" if h.stream is None else f"tcp stream {h.stream} {h.direction}"
        cells = [capture_cell(where), capture_cell(h.signature), str(h.offset), h.protocol]
        if paths is not None:
            cells.append(capture_cell(clean_capture_text(str(paths[i]), 500)))
        table.add_row(*cells)
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command("carve")(carve_cmd)
