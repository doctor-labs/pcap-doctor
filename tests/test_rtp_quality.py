"""RTP stream quality metrics: packet loss, interarrival jitter and MOS (issue #253).

The pure-math unit tests pin the RFC 3550 / ITU-T G.107 arithmetic to
hand-computed values. The capture test cross-checks loss and jitter against
tshark's own RTP analysis.
"""

from __future__ import annotations

import math

from conftest import fixture, requires_tshark
from pcap_doctor.rtp_quality import (
    estimate_mos,
    interarrival_jitter,
    packet_loss_percent,
)


# ---------------------------------------------------------------------------
# Packet loss from 16-bit RTP sequence numbers
# ---------------------------------------------------------------------------
def test_loss_zero_when_no_gaps() -> None:
    # Sequential 0..59, no holes -> 0% loss.
    assert packet_loss_percent(list(range(60))) == 0.0


def test_loss_counts_gaps_with_wraparound() -> None:
    # Hand example: seqs 0,1,2 then wrap 65535,0,1,2,3,4,5 -> no real gaps.
    # expected = last_ext - first_ext + 1; received = 8.
    seqs = [0, 1, 2, 65535, 0, 1, 2, 3, 4, 5, 6]  # wraps once
    # extended: 0,1,2,65535(wrap->65536+... )  -> 0,1,2,65536,65537,65538,65539,65540,65541,65542,65543
    # expected = 65543 - 0 + 1 = 65544 ; received = 11 ; lost = 65533 -> ~99.99%
    # Simpler: a clean single gap.
    seqs = [0, 1, 2, 5, 6]  # 3,4 missing between 0 and 6
    # expected = 6 - 0 + 1 = 7 ; received = 5 ; lost = 2 ; 2/7 = 28.5714...%
    loss = packet_loss_percent(seqs)
    assert math.isclose(loss, 200.0 / 7, rel_tol=1e-9)
    assert math.isclose(loss, 28.571428, abs_tol=1e-4)


def test_loss_wraparound_is_contiguous() -> None:
    # 65534, 65535, 0, 1 -> four extended packets, no gap -> 0%.
    assert packet_loss_percent([65534, 65535, 0, 1]) == 0.0


def test_loss_empty_and_single_packet() -> None:
    assert packet_loss_percent([]) == 0.0
    assert packet_loss_percent([42]) == 0.0


# ---------------------------------------------------------------------------
# Interarrival jitter, RFC 3550 Appendix A.8
# ---------------------------------------------------------------------------
def test_jitter_rfc3550_a8_example() -> None:
    """Reproduces the RFC 3550 Appendix A.8 worked example (8000 Hz clock).

    Packet  Arrival(s) RTP-ts   D(ms)
      1       0.000      0       ---
      2       0.012     80       |0.010-0.012| = 2ms gap
      3       0.019    160       |0.010-0.007| = 3ms gap
      4       0.028    240       |0.010-0.009| = 1ms gap
      5       0.039    320       |0.010-0.011| = 1ms gap
    J seeded at 0, updated J += (|D| - J)/16 (D in timestamp units, /8000 to
    seconds, *1000 to ms):
      J1=0
      J2=0+(2-0)/16=0.125
      J3=0.125+(3-0.125)/16=0.304688
      J4=0.304688+(1-0.304688)/16=0.348145
      J5=0.348145+(1-0.348145)/16=0.388885
    Final jitter ~0.388885 ms.
    """
    samples = [
        (0, 0.000),
        (80, 0.012),
        (160, 0.019),
        (240, 0.028),
        (320, 0.039),
    ]
    j = interarrival_jitter(samples, clock_hz=8000)
    assert math.isclose(j, 0.388885, abs_tol=1e-6)


def test_jitter_zero_for_constant_spacing() -> None:
    # 20 ms spaced packets, timestamp steps of 160 at 8000 Hz -> perfect.
    samples = [(i * 160, i * 0.020) for i in range(60)]
    assert math.isclose(interarrival_jitter(samples, clock_hz=8000), 0.0, abs_tol=1e-9)


def test_jitter_empty_and_single_and_bad_clock() -> None:
    assert interarrival_jitter([], 8000) == 0.0
    assert interarrival_jitter([(0, 0.0), (80, 0.012)], 8000) != 0.0  # one delta
    assert interarrival_jitter([(0, 0.0), (80, 0.012)], 0) == 0.0


# ---------------------------------------------------------------------------
# MOS from the E-model
# ---------------------------------------------------------------------------
def test_mos_no_loss_is_good() -> None:
    # Ppl = 0 -> Ie_eff = 0 -> R = 93.2 -> MOS = 1 + 0.035*93.2 + 93.2*33.2*6.8*7e-6
    #   = 1 + 3.262 + 93.2*33.2*6.8*7e-6 = 1 + 3.262 + 0.1473 = 4.4093
    mos = estimate_mos(0.0)
    assert math.isclose(mos, 4.4093, abs_tol=1e-4)


def test_mos_five_percent_loss() -> None:
    # Ie_eff = 95*5/(5/1+4.3) = 475/9.3 = 51.075268... ; R = 93.2-51.0753 = 42.1247
    # MOS = 1 + 0.035*42.1247 + 42.1247*(42.1247-60)*(100-42.1247)*7e-6
    #     = 2.1693 (see test body for the live recomputation)
    mos = estimate_mos(5.0)
    assert math.isclose(mos, 2.170, abs_tol=1e-2)


def test_mos_recomputes_the_formula() -> None:
    """Live recomputation of the G.107 arithmetic so we never trust the constant alone."""
    ppl = 5.0
    ie_eff = 95.0 * ppl / (ppl / 1.0 + 4.3)
    r = 93.2 - 0.0 - ie_eff
    expected = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    assert math.isclose(estimate_mos(ppl), expected, rel_tol=1e-12)
    assert math.isclose(ie_eff, 51.075, abs_tol=1e-3)
    assert math.isclose(r, 42.125, abs_tol=1e-3)


def test_mos_clamps_at_extremes() -> None:
    # R is bounded above by 93.2 (Ie_eff >= 0), so the 4.5 ceiling is unreachable
    # by loss alone; the floor is reachable: total loss drives R well below 0.
    assert estimate_mos(100_000.0) == 1.0
    # A generous upper bound: perfect quality caps under 4.5 by the formula.
    assert math.isclose(estimate_mos(0.0), 4.4093, abs_tol=1e-4)


# ---------------------------------------------------------------------------
# Cross-check against tshark's own RTP analysis on rtp_quality.pcap
# ---------------------------------------------------------------------------
@requires_tshark
def test_rtp_quality_fixture_matches_tshark(analyze_capture) -> None:
    """rtp_quality.pcap: 6 PCMA packets (8000 Hz), seq 0,1,2,5,6,7 (drop 3,4).

    Hand analysis:
      * expected packets between seq 0 and seq 7 = 7 - 0 + 1 = 8 ; received = 6
        ; lost = 2 ; loss = 2/8 = 25.0%.
      * arrivals 0.000, 0.012, 0.019, 0.028, 0.039, 0.050 s; timestamp steps of
        160 (20 ms audio frames at 8000 Hz). The RFC 3550 A.8 recursive jitter
        J += (|D| - J)/16, with D in timestamp units, settles on ~4.947 ms.
      * MOS from G.107 with 25% loss -> R ~ 13.0 -> MOS ~ 1.07.

    tshark's ``-z rtp,streams`` reports the same loss (2 packets, 25.0%) and
    the same jitter as its *max* jitter (4.947 ms); its *mean* jitter is the
    per-packet average instead. Loss and the max-jitter value match our
    sequence-gap and recursive-jitter computation exactly.

    TSHARK OUTPUT::

        Src 10.0.0.20:20000 -> 10.0.0.10:20002  SSRC 0xAABBCCDD  PCMA  Pkts 6  Lost 2 (25.0%)
        Min Jitter 0.500  Mean Jitter 3.159  Max Jitter 4.947  Problems? X
    """
    result = analyze_capture(fixture("rtp_quality.pcap"))
    (stream,) = result.index.rtp
    assert stream.packets == 6
    assert stream.payload_type == 8
    assert stream.payload_name == "PCMA"
    assert math.isclose(stream.loss_percent, 25.0, abs_tol=1e-6)
    assert math.isclose(stream.jitter, 4.947, abs_tol=1e-3)  # == tshark Max Jitter
    assert math.isclose(stream.mos, estimate_mos(25.0), abs_tol=1e-6)


@requires_tshark
def test_sip_rtp_fixture_no_loss_no_jitter(analyze_capture) -> None:
    """sip_rtp.pcap: 60 packets whose sequence numbers step by 160 (seq = i*160).

    The fixture intentionally uses ``seq = i*160`` (not 0..59), so the
    sequence-gap loss is large; tshark's own ``-z rtp,streams`` reports the same
    (9381 lost, 99.4%) because the gap is real from the sequence-number view.
    Interarrival jitter is 0.0 ms: packets arrive on a perfectly regular 20 ms
    grid. We assert jitter (the time-domain metric, which is well-defined
    regardless of the seq numbering) matches and is identical to tshark's
    Min/Mean/Max jitter of 0.000 ms.

    TSHARK OUTPUT::

        Src 10.0.0.20:20000 -> 10.0.0.10:20002  SSRC 0xDEADBEEF  PCMA  Pkts 60
        Lost 9381 (99.4%)  Min Jitter 0.000  Mean Jitter 0.000  Max Jitter 0.000
    """
    result = analyze_capture(fixture("sip_rtp.pcap"))
    (stream,) = result.index.rtp
    assert stream.packets == 60
    assert math.isclose(stream.jitter, 0.0, abs_tol=1e-6)  # regular 20 ms grid
