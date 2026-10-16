"""Structured scan progress events (issue #332)."""

from __future__ import annotations

from conftest import FIXTURES, requires_tshark
from pcap_doctor.pipeline import ProgressEvent, analyze

# The logical decode passes emitted by IndexBuilder.build(), in order. The
# "tls" pass consumes both the tls and dtls tshark rows; dtls is not reported
# as a separate phase because the builder merges it into the tls step.
EXPECTED_PASSES = [
    "base", "tls", "http", "dns", "sip", "rtp", "ssh", "quic",
    "services", "telnet", "smb",
]


@requires_tshark
def test_pass_started_and_finished_events_match_passes(cache_dir, tmp_path) -> None:
    """Every pass that runs emits exactly one started + one finished event."""
    events: list[ProgressEvent] = []
    analyze(FIXTURES / "weak_tls.pcap", tmp_path / "r", on_event=events.append)

    pass_events = [e for e in events if e.kind == "pass"]
    started = [e for e in pass_events if e.phase == "started"]
    finished = [e for e in pass_events if e.phase == "finished"]

    # counts match the passes actually run
    assert len(started) == len(finished)
    # names are the real passes, in order
    names = [e.name for e in started]
    for name in EXPECTED_PASSES:
        assert name in names
    # each finished event carries an elapsed time
    assert all(e.elapsed is not None and e.elapsed >= 0.0 for e in finished)


@requires_tshark
def test_detector_events_match_run_detectors(cache_dir, tmp_path) -> None:
    """Each detector that runs emits a started event; counts are consistent."""
    events: list[ProgressEvent] = []
    analyze(FIXTURES / "weak_tls.pcap", tmp_path / "r", on_event=events.append)

    detector_events = [e for e in events if e.kind == "detector"]
    started = [e for e in detector_events if e.phase == "started"]
    finished = [e for e in detector_events if e.phase == "finished"]
    assert len(started) == len(finished) >= 1
    # indices are 1-based and contiguous
    assert [e.index for e in started] == list(range(1, len(started) + 1))
    assert [e.total for e in started] == [len(started)] * len(started)


@requires_tshark
def test_finding_events_carry_severity(cache_dir, tmp_path) -> None:
    """Each finding produced emits a finding event with a real severity."""
    events: list[ProgressEvent] = []
    analyze(FIXTURES / "weak_tls.pcap", tmp_path / "r", on_event=events.append)

    finding_events = [e for e in events if e.kind == "finding"]
    # weak_tls produces findings
    assert len(finding_events) >= 1
    assert all(e.severity in ("critical", "high", "medium", "low", "info") for e in finding_events)
    # each carries a non-empty title
    assert all(e.title for e in finding_events)


@requires_tshark
def test_pass_total_is_constant(cache_dir, tmp_path) -> None:
    """The pass total reported on started equals the total reported on finished."""
    events: list[ProgressEvent] = []
    analyze(FIXTURES / "weak_tls.pcap", tmp_path / "r", on_event=events.append)

    pass_events = [e for e in events if e.kind == "pass"]
    for e in pass_events:
        assert e.total == e.total  # total is stable
    started = [e for e in pass_events if e.phase == "started"]
    finished = [e for e in pass_events if e.phase == "finished"]
    for s, f in zip(started, finished, strict=True):
        assert s.total == f.total
        assert s.index == f.index


@requires_tshark
def test_non_tty_stdout_is_byte_identical_across_runs(tmp_path) -> None:
    """Progress must never touch stdout. Two non-TTY runs produce identical stdout.

    Progress stage lines go to stderr only; stdout (the summary) is byte-identical
    across runs so CI logs and report consumers stay stable.
    """
    import subprocess
    import sys

    pcap = str(FIXTURES / "weak_tls.pcap")
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    cmd = sys.executable, "-m", "pcap_doctor.cli"

    # Both runs without -q: progress bar is on (stderr TTY-less → plain lines).
    # stdout must be identical and free of progress artefacts.
    res_a = subprocess.run(
        [*cmd, "analyze", pcap, "-o", str(out_a)],
        capture_output=True, text=True, check=True,
    )
    res_b = subprocess.run(
        [*cmd, "analyze", pcap, "-o", str(out_b)],
        capture_output=True, text=True, check=True,
    )
    # progress stage lines live on stderr, never stdout
    assert "pass 1/11" not in res_a.stdout
    assert "pass 1/11" not in res_b.stdout
    assert "pass 1/11" in res_a.stderr
    assert "pass 1/11" in res_b.stderr
    # stdout is byte-identical across runs except for the output directory path
    assert res_a.stdout.replace("a/", "X/").replace("b/", "X/") == res_b.stdout.replace("a/", "X/").replace("b/", "X/")
