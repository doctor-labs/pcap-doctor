"""TTY live-display rendering of structured progress events (issue #332)."""

from __future__ import annotations

import io

from rich.console import Console

from pcap_doctor.cli._progress import ProgressDisplay
from pcap_doctor.pipeline import ProgressEvent


def _feed_events(display: ProgressDisplay) -> None:
    """Replay the same event sequence the pipeline emits for a small scan."""
    for i, name in enumerate(["base", "tls", "http"], start=1):
        display.callback(ProgressEvent(
            kind="pass", name=name, phase="started", index=i, total=3,
        ))
        display.callback(ProgressEvent(
            kind="pass", name=name, phase="finished", index=i, total=3, elapsed=0.1,
        ))
    total_detectors = 2
    display.callback(ProgressEvent(
        kind="detector", name="d1.tls_cipher", phase="started", index=1, total=total_detectors,
    ))
    display.callback(ProgressEvent(
        kind="finding", name="TLS_CIPHER_WEAK", phase="produced",
        severity="critical", code="TLS_CIPHER_WEAK",
        title="weak cipher on tcp:1.2.3.4:443",
    ))
    display.callback(ProgressEvent(
        kind="finding", name="TLS_NO_FORWARD_SECRECY", phase="produced",
        severity="high", code="TLS_NO_FORWARD_SECRECY",
        title="no forward secrecy on tcp:1.2.3.4:443",
    ))
    display.callback(ProgressEvent(
        kind="detector", name="d1.tls_cipher", phase="finished", index=1, total=total_detectors, elapsed=0.5,
    ))
    display.callback(ProgressEvent(
        kind="detector", name="d2.transport_exposure", phase="started", index=2, total=total_detectors,
    ))
    display.callback(ProgressEvent(
        kind="detector", name="d2.transport_exposure", phase="finished", index=2, total=total_detectors, elapsed=0.2,
    ))


def test_tty_live_display_renders_markup_and_updates_counters() -> None:
    """The live display must render markup (not literal [bold]) and show live counters."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=100, color_system=None)
    display = ProgressDisplay(tty=True, console=console, transient=False)
    display.start()
    _feed_events(display)
    display.stop()

    out = buf.getvalue()
    # counters reflect the third pass, not 0/0
    assert "pass 3/" in out
    assert "detector 2/" in out
    # the latest finding's title and severity counts are rendered
    assert "no forward secrecy" in out
    assert "critical" in out
    assert "high" in out
    # rich markup must be rendered, never leaked as literal tags
    assert "[bold]" not in out
    assert "[/bold]" not in out
    assert "[dim]" not in out
    assert "[/dim]" not in out
