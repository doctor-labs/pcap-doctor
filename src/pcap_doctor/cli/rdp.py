"""``rdp``: typed keys and the screen of RDP sessions, when they are not encrypted. Issue #217."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.table import Table

from ..rdp import reconstruct
from ._console import capture_cell, console, tshark_errors


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def rdp(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    stream: int | None = typer.Option(None, "--stream", help="one TCP stream (see `streams`); default: port 3389"),
    out: Path | None = typer.Option(None, "--out", "-o", help="folder for the screen PNGs (default: CAPTURE.rdp)"),
) -> None:
    """Rebuild RDP sessions: the keys typed and the last screen as PNG. TLS and CredSSP sessions are not decoded."""
    with tshark_errors():
        sessions = reconstruct(pcap, stream)
    if not sessions:
        console.print("no RDP sessions in this capture")
        return
    folder = out or pcap.with_name(pcap.name + ".rdp")
    table = Table(title="RDP sessions")
    for col in ("stream", "server", "security", "size", "keys typed", "bitmaps", "screen"):
        table.add_column(col)
    for session in sessions:
        rep = session.replay
        screen = "not rendered"
        picture = rep.png()
        if picture is not None:
            folder.mkdir(parents=True, exist_ok=True)
            dest = folder / f"stream-{session.stream}.png"
            _write_private(dest, picture)
            screen = str(dest)
        table.add_row(
            str(session.stream),
            capture_cell(session.server),
            capture_cell(rep.negotiated or "-"),
            f"{rep.width}x{rep.height}" if rep.width else "-",
            capture_cell(rep.keystrokes[:200] + ("..." if len(rep.keystrokes) > 200 else "")) or "-",
            str(rep.rects),
            capture_cell(screen),
        )
    console.print(table)
    for session in sessions:
        for note in session.replay.notes:
            console.print(f"stream {session.stream}: {capture_cell(note)}")


def register(app: typer.Typer) -> None:
    app.command()(rdp)
