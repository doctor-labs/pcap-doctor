"""Regression guard for the number of tshark launches per ``analyze`` (issue #333).

Speed-ups for #328 (skip passes for unused protocols) and #330 (merge passes into
one process) will lower this count. When that lands, raise ``BUDGET`` to the new
measurement and note the issue that lowered it. There are deliberately **no**
timing assertions: wall time is noisy, launch count is not.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
# The launch counter helper lives with the other bench scripts; reuse it rather
# than copy the wrapper/ counting logic into the test.
sys.path.insert(0, str(ROOT / "scripts"))
from launch_counter import count_launches, make_wrapper, with_wrapped_path  # noqa: E402

#: Maximum number of tshark pass launches a single ``analyze`` may make on a
#: small fixture with a cold cache. Measured today (tshark 4.x) as 15: 11
#: prefetched passes + rtp + arp_icmp + capture_loss + the conn log pass that
#: the transport-exposure detector reads. Later speed-up issues MUST lower it:
#:  - #328: skip passes for protocols absent from the capture (landed via #338)
#:  - #330: merge several passes into one tshark invocation
#: Do not raise this without first measuring the new count.
#: PR #338 lowered the count on this fixture from 15 to 4 (base + 3 present-protocol
#: passes; arp_icmp.pcap carries only ARP and ICMP on well-known ports).
BUDGET = 5

PCAP = FIXTURES / "arp_icmp.pcap"


@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark is not installed")
def test_analyze_launch_budget(tmp_path: Path) -> None:
    """One ``analyze`` on a small fixture must not launch more than ``BUDGET`` passes."""
    if not PCAP.exists():
        pytest.skip(f"fixture {PCAP.name} is missing; run: python scripts/make_fixtures.py")
    log_path = tmp_path / "launches.log"
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    bin_dir = make_wrapper(log_path)
    env = with_wrapped_path(bin_dir)
    env["PCAP_DOCTOR_CACHE"] = str(cache_dir)
    out = tmp_path / "report"
    proc = subprocess.run(
        [
            shutil.which("pcap-doctor") or str(ROOT / ".venv" / "bin" / "pcap-doctor"),
            "analyze",
            str(PCAP),
            "-o",
            str(out),
            "-q",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
    )
    assert proc.returncode in (0, 1), f"analyze failed (exit {proc.returncode}):\n{proc.stderr[-600:]}"
    launches = count_launches(log_path)
    # A lower bound keeps the guard from passing vacuously if the counter is broken
    # (e.g. the tokenizer misclassifying every pass as a lookup): a real analyze
    # launches several passes, so fewer than 2 means the counter is not
    # recording passes. See issue #333.
    assert launches >= 2, (
        f"analyze launched only {launches} pass(es) on {PCAP.name}; the counter may be misclassifying "
        "passes as lookups (see scripts/launch_counter.py classify)."
    )
    assert launches <= BUDGET, (
        f"analyze launched {launches} tshark pass(es) on {PCAP.name}, over the budget of {BUDGET}; "
        "see #333 and the BUDGET comment in this test."
    )
