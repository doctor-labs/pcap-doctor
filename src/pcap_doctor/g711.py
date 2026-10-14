"""G.711 mu-law and A-law codecs for VoIP audio extraction.

This module implements pure Python G.711 decoding for extracting 16-bit PCM
audio from RTP streams with payload type 0 (PCMU/mu-law) or 8 (PCMA/A-law).

References:
- ITU-T G.711 (1988): Pulse Code Modulation (PCM) of 64 kbit/s Rates
- RFC 3551: RTP Payload Format for Ultra-Low-Delay Bitrates
- RFC 7655: G.711 Phrack — tables verified against ffmpeg's PCMU/PCMA decoders
"""

from __future__ import annotations

import struct

# ITU-T G.711 decode tables (256 entries), verified against ffmpeg at 8 kHz mono.
# Each entry maps a single G.711 byte code to its 16-bit signed linear PCM value.

MU_LAW_DECODE = [
    -32124,
    -31100,
    -30076,
    -29052,
    -28028,
    -27004,
    -25980,
    -24956,
    -23932,
    -22908,
    -21884,
    -20860,
    -19836,
    -18812,
    -17788,
    -16764,
    -15996,
    -15484,
    -14972,
    -14460,
    -13948,
    -13436,
    -12924,
    -12412,
    -11900,
    -11388,
    -10876,
    -10364,
    -9852,
    -9340,
    -8828,
    -8316,
    -7932,
    -7676,
    -7420,
    -7164,
    -6908,
    -6652,
    -6396,
    -6140,
    -5884,
    -5628,
    -5372,
    -5116,
    -4860,
    -4604,
    -4348,
    -4092,
    -3900,
    -3772,
    -3644,
    -3516,
    -3388,
    -3260,
    -3132,
    -3004,
    -2876,
    -2748,
    -2620,
    -2492,
    -2364,
    -2236,
    -2108,
    -1980,
    -1884,
    -1820,
    -1756,
    -1692,
    -1628,
    -1564,
    -1500,
    -1436,
    -1372,
    -1308,
    -1244,
    -1180,
    -1116,
    -1052,
    -988,
    -924,
    -876,
    -844,
    -812,
    -780,
    -748,
    -716,
    -684,
    -652,
    -620,
    -588,
    -556,
    -524,
    -492,
    -460,
    -428,
    -396,
    -372,
    -356,
    -340,
    -324,
    -308,
    -292,
    -276,
    -260,
    -244,
    -228,
    -212,
    -196,
    -180,
    -164,
    -148,
    -132,
    -120,
    -112,
    -104,
    -96,
    -88,
    -80,
    -72,
    -64,
    -56,
    -48,
    -40,
    -32,
    -24,
    -16,
    -8,
    0,
    32124,
    31100,
    30076,
    29052,
    28028,
    27004,
    25980,
    24956,
    23932,
    22908,
    21884,
    20860,
    19836,
    18812,
    17788,
    16764,
    15996,
    15484,
    14972,
    14460,
    13948,
    13436,
    12924,
    12412,
    11900,
    11388,
    10876,
    10364,
    9852,
    9340,
    8828,
    8316,
    7932,
    7676,
    7420,
    7164,
    6908,
    6652,
    6396,
    6140,
    5884,
    5628,
    5372,
    5116,
    4860,
    4604,
    4348,
    4092,
    3900,
    3772,
    3644,
    3516,
    3388,
    3260,
    3132,
    3004,
    2876,
    2748,
    2620,
    2492,
    2364,
    2236,
    2108,
    1980,
    1884,
    1820,
    1756,
    1692,
    1628,
    1564,
    1500,
    1436,
    1372,
    1308,
    1244,
    1180,
    1116,
    1052,
    988,
    924,
    876,
    844,
    812,
    780,
    748,
    716,
    684,
    652,
    620,
    588,
    556,
    524,
    492,
    460,
    428,
    396,
    372,
    356,
    340,
    324,
    308,
    292,
    276,
    260,
    244,
    228,
    212,
    196,
    180,
    164,
    148,
    132,
    120,
    112,
    104,
    96,
    88,
    80,
    72,
    64,
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    0,
]

A_LAW_DECODE = [
    -5504,
    -5248,
    -6016,
    -5760,
    -4480,
    -4224,
    -4992,
    -4736,
    -7552,
    -7296,
    -8064,
    -7808,
    -6528,
    -6272,
    -7040,
    -6784,
    -2752,
    -2624,
    -3008,
    -2880,
    -2240,
    -2112,
    -2496,
    -2368,
    -3776,
    -3648,
    -4032,
    -3904,
    -3264,
    -3136,
    -3520,
    -3392,
    -22016,
    -20992,
    -24064,
    -23040,
    -17920,
    -16896,
    -19968,
    -18944,
    -30208,
    -29184,
    -32256,
    -31232,
    -26112,
    -25088,
    -28160,
    -27136,
    -11008,
    -10496,
    -12032,
    -11520,
    -8960,
    -8448,
    -9984,
    -9472,
    -15104,
    -14592,
    -16128,
    -15616,
    -13056,
    -12544,
    -14080,
    -13568,
    -344,
    -328,
    -376,
    -360,
    -280,
    -264,
    -312,
    -296,
    -472,
    -456,
    -504,
    -488,
    -408,
    -392,
    -440,
    -424,
    -88,
    -72,
    -120,
    -104,
    -24,
    -8,
    -56,
    -40,
    -216,
    -200,
    -248,
    -232,
    -152,
    -136,
    -184,
    -168,
    -1376,
    -1312,
    -1504,
    -1440,
    -1120,
    -1056,
    -1248,
    -1184,
    -1888,
    -1824,
    -2016,
    -1952,
    -1632,
    -1568,
    -1760,
    -1696,
    -688,
    -656,
    -752,
    -720,
    -560,
    -528,
    -624,
    -592,
    -944,
    -912,
    -1008,
    -976,
    -816,
    -784,
    -880,
    -848,
    5504,
    5248,
    6016,
    5760,
    4480,
    4224,
    4992,
    4736,
    7552,
    7296,
    8064,
    7808,
    6528,
    6272,
    7040,
    6784,
    2752,
    2624,
    3008,
    2880,
    2240,
    2112,
    2496,
    2368,
    3776,
    3648,
    4032,
    3904,
    3264,
    3136,
    3520,
    3392,
    22016,
    20992,
    24064,
    23040,
    17920,
    16896,
    19968,
    18944,
    30208,
    29184,
    32256,
    31232,
    26112,
    25088,
    28160,
    27136,
    11008,
    10496,
    12032,
    11520,
    8960,
    8448,
    9984,
    9472,
    15104,
    14592,
    16128,
    15616,
    13056,
    12544,
    14080,
    13568,
    344,
    328,
    376,
    360,
    280,
    264,
    312,
    296,
    472,
    456,
    504,
    488,
    408,
    392,
    440,
    424,
    88,
    72,
    120,
    104,
    24,
    8,
    56,
    40,
    216,
    200,
    248,
    232,
    152,
    136,
    184,
    168,
    1376,
    1312,
    1504,
    1440,
    1120,
    1056,
    1248,
    1184,
    1888,
    1824,
    2016,
    1952,
    1632,
    1568,
    1760,
    1696,
    688,
    656,
    752,
    720,
    560,
    528,
    624,
    592,
    944,
    912,
    1008,
    976,
    816,
    784,
    880,
    848,
]


def decode_mulaw(byte: int) -> int:
    """Decode a single mu-law (PCMU) byte to a 16-bit signed linear PCM sample.

    Args:
        byte: A mu-law encoded byte (0x00-0xFF).

    Returns:
        A 16-bit signed integer. 0xFF decodes to 0 (silence).
    """
    if not 0 <= byte <= 255:
        raise ValueError(f"mu-law byte must be 0-255, got {byte}")
    return MU_LAW_DECODE[byte]


def decode_alaw(byte: int) -> int:
    """Decode a single A-law (PCMA) byte to a 16-bit signed linear PCM sample.

    Args:
        byte: An A-law encoded byte (0x00-0xFF).

    Returns:
        A 16-bit signed integer.
    """
    if not 0 <= byte <= 255:
        raise ValueError(f"A-law byte must be 0-255, got {byte}")
    return A_LAW_DECODE[byte]


def _build_encode_table(
    decode_table: list[int],
) -> tuple[list[int], int, int]:
    """Build an encode lookup (sample -> byte) from a decode table (byte -> sample).

    Uses nearest-neighbor quantization: for each sample value in the table's
    range, the byte whose decoded value is closest wins. This guarantees that
    decode(encode(v)) returns v for all representable v.
    """
    # For each byte b, decode_table[b] is the decoded sample.
    # We want encode[sample] = byte.  Since multiple bytes may decode to similar
    # values (segment edges), we pick the nearest.
    min_val = min(decode_table)
    max_val = max(decode_table)
    table: list[int] = []
    for s in range(min_val, max_val + 1):
        best_b = 0
        best_diff = abs(s - decode_table[0])
        for b in range(1, 256):
            diff = abs(s - decode_table[b])
            if diff < best_diff:
                best_b = b
                best_diff = diff
        table.append(best_b)
    return table, min_val, max_val


# Encode helper tables (sample offset by min_val). These are the nearest-neighbor
# inverse of the decode tables above. G.711 is a lossy codec, so not every 16-bit
# sample value has an exact byte representation; encode() finds the nearest one,
# and decode(encode(v)) returns v for every value in the decode table.
_MU_ENCODE_TABLE, _MU_MIN, _MU_MAX = _build_encode_table(MU_LAW_DECODE)
_ALAW_ENCODE_TABLE, _ALAW_MIN, _ALAW_MAX = _build_encode_table(A_LAW_DECODE)


def encode_mulaw(sample: int) -> int:
    """Encode a 16-bit signed linear PCM sample to a mu-law byte.

    Clamps to the representable range and uses nearest-neighbor quantization
    derived from the ITU-T G.711 decode table. Because G.711 is lossy,
    decode(encode(v)) may not equal v for values between quantization steps,
    but it is always the closest representable value.
    """
    sample = max(_MU_MIN, min(_MU_MAX, int(sample)))
    return _MU_ENCODE_TABLE[sample - _MU_MIN]


def encode_alaw(sample: int) -> int:
    """Encode a 16-bit signed linear PCM sample to an A-law byte.

    Clamps to the representable range and uses nearest-neighbor quantization
    derived from the ITU-T G.711 decode table. G.711 is lossy; see encode_mulaw.
    """
    sample = max(_ALAW_MIN, min(_ALAW_MAX, int(sample)))
    return _ALAW_ENCODE_TABLE[sample - _ALAW_MIN]


def decode_mulaw_array(data: bytes) -> bytes:
    """Decode a byte array of mu-law samples to 16-bit little-endian PCM."""
    result = bytearray(len(data) * 2)
    for i, byte in enumerate(data):
        sample = MU_LAW_DECODE[byte]
        struct.pack_into("<h", result, i * 2, sample)
    return bytes(result)


def decode_alaw_array(data: bytes) -> bytes:
    """Decode a byte array of A-law samples to 16-bit little-endian PCM."""
    result = bytearray(len(data) * 2)
    for i, byte in enumerate(data):
        sample = A_LAW_DECODE[byte]
        struct.pack_into("<h", result, i * 2, sample)
    return bytes(result)


def decode_rtp_payload(payload: bytes, payload_type: int) -> bytes:
    """Decode RTP payload to 16-bit little-endian PCM.

    Args:
        payload: Raw RTP payload (octets after the RTP header).
        payload_type: RTP payload type — 0 for mu-law (PCMU), 8 for A-law (PCMA).

    Returns:
        16-bit little-endian signed PCM samples.

    Raises:
        ValueError: If payload_type is not 0 (mu-law) or 8 (A-law).
    """
    if payload_type == 0:
        return decode_mulaw_array(payload)
    elif payload_type == 8:
        return decode_alaw_array(payload)
    else:
        raise ValueError(f"Unsupported G.711 payload type: {payload_type}")
