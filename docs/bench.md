# Benchmarking and the tshark launch budget

Issue #333 — there was no repeatable way to measure scan performance, so speed-ups
could not be proven or guarded. This page records how to run the benchmark and
what the current baseline is.

## The counter

The analysis pipeline counts its work in **tshark launches**: one `tshark -r ...
-T fields` process per protocol pass (see `src/pcap_doctor/tshark.py`,
`TsharkRunner`). The cheap wrapper in `scripts/launch_counter.py` installs a
`~/tshark` shim ahead of the real binary that appends each invocation's argv to
a log file; a pass launch is any line that is not a capability lookup (`-G ...` or
`-v`).

## Running the benchmark

```
.venv/bin/python scripts/bench_large.py                       # default: 2000x arp_icmp.pcap
.venv/bin/python scripts/bench_large.py --copies 200          # larger capture
.venv/bin/python scripts/bench_large.py --ci                  # CI mode: 25 copies, checks only
```

The large capture is built with `mergecap` of N copies of a real fixture into a
temp directory; it is never committed. Missing `tshark`/`mergecap` print a clear
message and exit 0. Output:

```
wall          <seconds> s
cpu user+sys  <seconds> s
peak child RSS     <MB> MB
tshark launches      15
```

## Baseline (measured 2026-10-13 class machine)

- 15 tshark pass launches per `analyze` with a cold cache on a small fixture
  (11 prefetched passes + `rtp` + the on-demand `arp_icmp`, `capture_loss` and
  the `conn` log pass read by the transport-exposure detector).
- This count is deterministic across fixtures and tshark builds: pass *count*
  depends only on `PASSES` and which detectors are enabled, not on which fields
  a build knows.

## The regression guard

`tests/test_launch_budget.py` runs `analyze` on `tests/fixtures/arp_icmp.pcap`
through the launch counter and asserts the pass-launch count is `<= BUDGET`
(`BUDGET = 15` today). It has **no timing assertions** — wall time is noisy, launch
count is not. When a speed-up lands, the relevant issue must raise `BUDGET` to
the new measurement:

- #328 skip passes for protocols absent from the capture,
- #330 merge several passes into one tshark invocation.
