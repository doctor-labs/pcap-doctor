"""Live scan progress display (issue #332).

Translates structured :class:`~pcap_doctor.pipeline.ProgressEvent` values into
either a ``rich`` live display (when stderr is a terminal and this is not a
machine-readable run) or one plain line per stage on stderr (otherwise).

Nothing is ever written to stdout from this module: the report and the score
stay byte-identical whether progress is on or off.
"""

from __future__ import annotations

import sys
from collections import Counter
from typing import TYPE_CHECKING

from rich.console import Console, RenderableType
from rich.live import Live
from rich.markup import escape
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..pipeline import ProgressEvent


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class _StageTracker:
    """Tracks elapsed time and counts for the currently-active stage."""

    def __init__(self) -> None:
        self.pass_i = 0
        self.pass_total = 0
        self.detector_i = 0
        self.detector_total = 0
        self.pass_elapsed = 0.0
        self.detector_elapsed = 0.0
        self.severity_counts: Counter[str] = Counter()
        self.latest_title: str | None = None
        self.latest_severity: str | None = None


class ProgressDisplay:
    """A progress callback that drives either a rich live display or plain stderr lines.

    Pass ``tty=True`` (the default derived from ``sys.stderr.isatty()``) for the
    full live bar; pass ``tty=False`` (or ``json_mode=True``) for one plain line
    per stage on stderr.
    """

    def __init__(
        self,
        *,
        tty: bool | None = None,
        console: Console | None = None,
    ) -> None:
        self._console = console or Console(file=sys.stderr, stderr=True, highlight=False)
        self._tty = sys.stderr.isatty() if tty is None else tty
        self._tracker = _StageTracker()
        self._live: Live | None = None
        self._progress: Progress | None = None
        self._pass_task: int = 0
        self._detector_task: int = 0

    def is_tty(self) -> bool:
        return self._tty

    @property
    def callback(self) -> Callable[[ProgressEvent], None]:
        return self._on_event

    def start(self) -> None:
        if self._tty:
            self._progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=self._console,
                transient=True,
                disable=not self._tty,
            )
            self._live = Live(
                self._render(),
                console=self._console,
                refresh_per_second=8,
                transient=True,
                screen=False,
            )
            self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None
        if self._progress is not None:
            self._progress.stop()
            self._progress = None

    def _on_event(self, event: ProgressEvent) -> None:
        t = self._tracker
        if event.kind == "pass":
            if event.phase == "started":
                t.pass_i = event.index
                t.pass_total = event.total
                t.pass_elapsed = 0.0
            elif event.phase == "finished":
                t.pass_elapsed = event.elapsed or 0.0
        elif event.kind == "detector":
            if event.phase == "started":
                t.detector_i = event.index
                t.detector_total = event.total
                t.detector_elapsed = 0.0
            elif event.phase == "finished":
                t.detector_elapsed = event.elapsed or 0.0
        elif event.kind == "finding":
            if event.severity:
                t.severity_counts[str(event.severity)] += 1
            t.latest_title = event.title or event.name
            t.latest_severity = event.severity

        if self._tty and self._live is not None:
            self._live.update(self._render())
        else:
            # Non-TTY / machine mode: one plain line per stage event.
            self._plain_line(event)

    def _render(self) -> RenderableType:
        from rich.text import Text as _Text

        t = self._tracker

        pass_desc = f"pass {t.pass_i}/{t.pass_total}"
        det_desc = f"detector {t.detector_i}/{t.detector_total}"
        sev_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = t.severity_counts.get(sev, 0)
            if count:
                sev_parts.append(f"{sev}: {count}")
        sev_str = " · ".join(sev_parts) if sev_parts else "findings: 0"
        latest = escape(t.latest_title or "") if t.latest_title else ""
        latest_tag = f" [{t.latest_severity}]" if t.latest_severity else ""

        lines = [
            f"[bold]{pass_desc}[/bold]  {sev_str}",
            f"[dim]{det_desc} · {t.detector_elapsed:.1f}s elapsed[/dim]{latest_tag} {latest}",
        ]
        return _Text("\n".join(lines))

    def _plain_line(self, event: ProgressEvent) -> None:
        """One plain stderr line per stage in non-TTY / machine mode."""
        if event.kind == "pass" and event.phase == "started":
            self._console.print(f"pass {event.index}/{event.total} {event.name} …", highlight=False)
        elif event.kind == "pass" and event.phase == "finished":
            self._console.print(
                f"pass {event.index}/{event.total} {event.name} done in {event.elapsed:.1f}s",
                highlight=False,
            )
        elif event.kind == "detector" and event.phase == "started":
            self._console.print(
                f"detector {event.index}/{event.total} {event.name}",
                highlight=False,
            )
        elif event.kind == "finding":
            self._console.print(
                f"  finding {event.severity} {event.code or ''} {event.title or ''}",
                highlight=False,
            )
