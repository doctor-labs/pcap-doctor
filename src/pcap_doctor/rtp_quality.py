"""RTP stream quality metrics (issue #253).

Pure, side-effect-free helpers for the three numbers a manual RTP inspection
needs:

* ``packet_loss_percent`` -- fraction of holes in the 16-bit RTP sequence-number
  stream, per RFC 3550 section 6.4.1 / Appendix A.6.
* ``interarrival_jitter`` -- the RFC 3550 section 6.4.1 / Appendix A.8 estimate,
  reported in milliseconds.
* ``estimated_mos`` -- a single-number voice quality from the ITU-T G.107
  E-model ``R = 93.2 - Id - Ie_eff`` simplified form (G.711, packet-loss
  concealment).

Nothing here touches the filesystem or tshark: every function is a pure function
of its arguments so the unit tests can pin the arithmetic to hand-computed
values.
"""

from __future__ import annotations

#: RTP sequence numbers are 16-bit and wrap from 65535 to 0.
_SEQ_MOD = 1 << 16


def _extended_seqs(seqs: list[int]) -> list[int]:
    """Lift 16-bit RTP sequence numbers to a monotonic 32-bit count, RFC 3550 A.1.

    Each observed 16-bit sequence number is interpreted relative to the previous
    one: a forward delta of up to half the 16-bit range is taken as-is, anything
    larger is a wrap to the next (or previous) cycle. This is the
    ``seq < base_seq + 32768`` rule from RFC 3550 Appendix A.1, which keeps loss
    measurement correct across the 65535 -> 0 rollover.
    """
    if not seqs:
        return []
    out: list[int] = [int(seqs[0]) % _SEQ_MOD]
    for seq in seqs[1:]:
        prev = out[-1]
        raw = int(seq) % _SEQ_MOD
        delta = raw - (prev % _SEQ_MOD)
        if delta < 0:
            delta += _SEQ_MOD
        # delta in [0, 65535]: a jump of more than half the range is a wrap.
        if delta >= _SEQ_MOD // 2:
            delta -= _SEQ_MOD
        out.append(prev + delta)
    return out


def packet_loss_percent(seqs: list[int]) -> float:
    """Packet loss as a percentage (0..100), from RTP sequence-number gaps.

    RFC 3550 section 6.4.1: lost = (highest_expected - received) + 1, where
    highest_expected is the maximum extended sequence number and received is
    the count of packets actually seen. Zero gaps -> 0.0; a single packet ->
    0.0 (no loss detectable from one sample).
    """
    if not seqs:
        return 0.0
    ext = _extended_seqs(seqs)
    expected = ext[-1] - ext[0] + 1
    received = len(ext)
    if expected <= 0:
        return 0.0
    lost = max(0, expected - received)
    return 100.0 * lost / expected


def interarrival_jitter(samples: list[tuple[int, float]], clock_hz: int) -> float:
    """RFC 3550 section 6.4.1 / Appendix A.8 interarrival jitter, in milliseconds.

    ``samples`` is ordered (as captured) ``(rtp_timestamp, arrival_seconds)``
    pairs; ``clock_hz`` is the RTP payload clock rate that turns a timestamp
    delta into seconds (e.g. 8000 for PCMU/PCMA, 16000 for linear PCM).

    Algorithm (Appendix A.8):
        transit = rtp_timestamp - arrival_seconds * clock_hz   # in timestamp units
        for each packet after the first:
            d = transit(i) - transit(i-1)
            j = j + (|d| - j) / 16
    The result is converted from timestamp units to milliseconds via the clock
    rate. Bounds-checked: a zero/negative/None clock rate yields 0.0 jitter.
    """
    if clock_hz <= 0 or len(samples) < 2:
        return 0.0
    jitter_ts = 0.0
    transit_prev: float | None = None
    for rtp_ts, arrival in samples:
        transit = rtp_ts - arrival * clock_hz
        if transit_prev is not None:
            d = transit - transit_prev
            jitter_ts += (abs(d) - jitter_ts) / 16.0
        transit_prev = transit
    # timestamp units -> ms: (jitter_ts / clock_hz) * 1000
    return jitter_ts / clock_hz * 1000.0


# ITU-T G.107 E-model (G.711 with packet-loss concealment), simplified form.
#
#   Ie_eff = 95 * Ppl / (Ppl / BurstR + Bpl)
#       with BurstR = 1.0 (random/lossy-burst ratio; 1.0 == purely random loss)
#       and   Bpl   = 4.3 (PLC impairment for G.711)
#   Id  = 0  (no one-way-delay information is recoverable from a capture)
#   R   = 93.2 - Id - Ie_eff, clamped to 0..100
#   MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6   for 0 < R < 100
#         = 1                                     for R <= 0
#         = 4.5                                   for R >= 100
#
# Reference: ITU-T G.107 (08/2016) and G.113, section on the E-model.
_IE_BASE = 95.0
_BURST_R = 1.0
_BPL = 4.3


def estimate_mos(packet_loss_percent: float) -> float:
    """Estimated MOS (1.0..4.5) from packet loss percentage, G.107 E-model.

    ``packet_loss_percent`` is the loss fraction in percent (0..100). Loss
    below a tiny epsilon counts as no loss (PLC hides it).
    """
    ppl = max(0.0, packet_loss_percent)
    ie_eff = 0.0 if ppl <= 0.0 else _IE_BASE * ppl / (ppl / _BURST_R + _BPL)
    r = 93.2 - 0.0 - ie_eff  # Id = 0 (no delay info from a capture)
    if r <= 0:
        return 1.0
    if r >= 100:
        return 4.5
    return 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
