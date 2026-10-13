#!/usr/bin/env python3
"""Deterministic large-capture benchmark for ``pcap-doctor analyze`` (issue #333).

Why this exists: there was no repeatable way to measure scan performance, so speed-ups
could not be proven or guarded. ``bench_large.py`` builds one large capture by
``mergecap``-ing ``--copies N`` copies of a real fixture (deterministic and
written to a temp dir, never committed), runs the full analyze pipeline against it
with a tshark-launch counter, and prints:

  * wall time,
  * user + sys CPU seconds of the process tree (``resource.getrusage(RUSAGE_CHILDREN)``),
  * peak RSS of child processes (same source),
  * the number of tshark *pass* launches (excludes the ``tshark -G``/``-v`` lookups
    used for capability discovery; see ``scripts/launch_counter.py``).

The launch count is what the regression guard in ``tests/test_launch_budget.py``
locks down; this script is the human-readable measurement it is grounded in.

A small CI mode (``--copies small``) builds a tiny capture just to prove the
harness still wires up end to end; it is not a timing assertion.

Usage:
    .venv/bin/python scripts/bench_large.py                       # default large
    .venv/bin/python scripts/bench_large.py --copies 50 --ci      # CI guard mode
"""

from __future__ import annotations

import argparse
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from launch_counter import count_launches, make_wrapper, with_wrapped_path  # noqa: E402

DEFAULT_COPIES = 2000
SMALL_COPIES = 25
PCAP_DOCTOR = shutil.which("pcap-doctor") or str(ROOT / ".venv" / "bin" / "pcap-doctor")


def _rusage_children() -> tuple[float, float, int]:
    """Return (user_sec, sys_sec, max_rss_kb) for the whole child process tree."""
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ru.ru_utime, ru.ru_stime, ru.ru_maxrss


def build_large(src: Path, copies: int, tmp: Path) -> Path:
    """``mergecap``-replicate ``src`` ``copies`` times into a temp pcap. Deterministic."""
    out = tmp / f"{src.stem}_{copies}x.pcap"
    # mergecap of the same file many times is deterministic: packet bytes are
    # duplicated verbatim, so the capture is reproducible across runs/machines.
    cmd = [shutil.which("mergecap") or "", "-w", str(out), *(str(src) for _ in range(copies))]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 or not out.exists():
        raise RuntimeError(f"mergecap failed: {proc.stderr.strip()[:500]}")
    return out


def analyze(pcap: Path, cache_dir: Path, bin_dir: Path) -> subprocess.CompletedProcess:
    env = with_wrapped_path(bin_dir)
    env["PCAP_DOCTOR_CACHE"] = str(cache_dir)
    env["CI"] = "1"  # keep the analyzer non-interactive in CI
    out = Path(tempfile.mkdtemp(prefix="bench-out-"))
    return subprocess.run(
        [PCAP_DOCTOR, "analyze", str(pcap), "-o", str(out), "-q", "--no-handoff"],
        capture_output=True, text=True, env=env, cwd=str(ROOT), check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark pcap-doctor on a large capture.")
    parser.add_argument("--fixture", default="arp_icmp.pcap", help="fixture to replicate (default: arp_icmp.pcap)")
    parser.add_argument("--copies", type=int, default=DEFAULT_COPIES, help="number of mergecap copies")
    parser.add_argument("--ci", action="store_true", help="CI guard mode: use a small capture; check launch count only")
    args = parser.parse_args()

    if args.ci:
        args.copies = SMALL_COPIES

    if not shutil.which("tshark"):
        print("bench: tshark is missing -- install Wireshark/tshark and rerun")
        return 0
    if not shutil.which("mergecap"):
        print("bench: mergecap is missing -- install Wireshark/tshark and rerun")
        return 0

    src = FIXTURES / args.fixture
    if not src.exists():
        print(f"bench: fixture {src} is missing; run: python scripts/make_fixtures.py")
        return 0

    with tempfile.TemporaryDirectory(prefix="bench-") as tmp:
        tmp_path = Path(tmp)
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        log_path = tmp_path / "launches.log"
        bin_dir = make_wrapper(log_path)

        print(f"bench: building {args.copies}x {src.name} with mergecap ...", file=sys.stderr)
        build_start = time.monotonic()
        large = build_large(src, args.copies, tmp_path)
        build_secs = time.monotonic() - build_start
        size = large.stat().st_size
        print(f"bench: {args.copies}x -> {large} ({size / 1_000_000:.1f} MB) in {build_secs:.2f}s", file=sys.stderr)

        # Warm the capability lookups so they are not charged to the analyze measurement.
        subprocess.run([str(ROOT / ".venv" / "bin" / "python"), "-c",
                        "from pcap_doctor.tshark import tshark_version, valid_fields, protocol_names, default_prefs; "
                        "tshark_version(); valid_fields(); protocol_names(); default_prefs()"],
                       env=with_wrapped_path(bin_dir), capture_output=True, text=True)

        proc_start = time.monotonic()
        before = _rusage_children()
        proc = analyze(large, cache_dir, bin_dir)
        after = _rusage_children()
        wall = time.monotonic() - proc_start

        if proc.returncode not in (0, 1):
            print(f"bench: analyze failed (exit {proc.returncode}): {proc.stderr[-600:]}")
            return proc.returncode

        launches = count_launches(log_path)
        user = after[0] - before[0]
        sys_ = after[1] - before[1]
        # ru_maxrss is the high-water mark of child RSS. Units differ by OS:
        # Linux reports kB, macOS reports bytes, so normalise to MB.
        peak_rss = after[2]
        if sys.platform == "linux":
            peak_rss_mb = peak_rss / 1024
        else:
            peak_rss_mb = peak_rss / (1024 * 1024)

        print(f"bench: {args.copies}x {src.name} ({size / 1_000_000:.1f} MB)")
        print(f"wall          {wall:8.2f} s")
        print(f"cpu user+sys  {user:8.2f} s  (user {user:.2f} + sys {sys_:.2f})")
        print(f"peak child RSS     {peak_rss_mb:.1f} MB")
        print(f"tshark launches      {launches}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
