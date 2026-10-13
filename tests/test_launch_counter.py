"""Unit tests for the tshark launch counter (issue #333).

The classifier must not mistake a capture path that *contains* ``-v`` or
``-G`` (e.g. ``.../pytest-of-vaibhav/-Users-vaibhav/Desktop/...``) for a
lookup. It must also not mistake the ``-G`` inside a field filter name. Classification
is done on argv **tokens**, and a real analysis pass is the one that reads a capture
(``-r``). These tests pin that behaviour before fixing it.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from launch_counter import classify  # noqa: E402


def test_classify_a_pass_even_when_the_path_contains_v_or_G() -> None:
    # A pytest temp path /private/var/folders/xx/pytest-of-vaibhav/... is a real capture path
    # and must NOT be classified as a lookup.
    line = "-r /private/var/folders/ab/pytest-of-vaibhav/Desktop/x.pcap -n -l -Y dns -T fields -e frame.number"
    assert classify(line) == "pass"


def test_classify_a_pass_without_a_display_filter() -> None:
    line = "-r /private/tmp/claude-501/-Users-vaibhavtomar-Desktop/x/bench.pcap -n -l"
    assert classify(line) == "pass"


def test_classify_lookups() -> None:
    assert classify("-G fields") == "lookup"
    assert classify("-G protocols") == "lookup"
    assert classify("-G defaultprefs") == "lookup"
    assert classify("-v") == "lookup"
