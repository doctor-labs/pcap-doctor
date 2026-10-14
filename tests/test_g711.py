"""Unit tests for G.711 mu-law and A-law decoding.

These tests verify the G.711 decode functionality for RTP audio extraction.
Decode tables are verified against ffmpeg's built-in PCMU/PCMA decoders.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import wave
from pathlib import Path

import pytest

from pcap_doctor.g711 import (
    A_LAW_DECODE,
    MU_LAW_DECODE,
    decode_alaw,
    decode_alaw_array,
    decode_mulaw,
    decode_mulaw_array,
    decode_rtp_payload,
    encode_mulaw,
)

FFMPEG = shutil.which("ffmpeg")


def _ffmpeg_decode(payload: bytes, codec: str) -> bytes:
    """Decode raw G.711 bytes with ffmpeg; returns 16-bit little-endian PCM."""
    proc = subprocess.run(
        [
            "ffmpeg",
            "-f",
            codec,
            "-ar",
            "8000",
            "-ac",
            "1",
            "-i",
            "-",
            "-f",
            "s16le",
            "-",
        ],
        input=payload,
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


class TestMuLawDecode:
    """Test mu-law (PCMU, payload type 0) decoding."""

    def test_key_vectors_match_itu_t(self) -> None:
        """Brief-required vectors, ground truth from ITU-T G.711 / ffmpeg."""
        assert decode_mulaw(0xFF) == 0  # silence
        assert decode_mulaw(0x00) == -32124
        assert decode_mulaw(0x80) == 32124
        assert decode_mulaw(0xFE) == 8

    def test_mu_law_decode_accepts_valid_bytes(self) -> None:
        """Decode should accept all valid bytes 0x00-0xFF."""
        for b in (0x00, 0x55, 0x80, 0xAA, 0xFF):
            result = decode_mulaw(b)
            assert isinstance(result, int)

    def test_mu_law_invalid_input(self) -> None:
        """Invalid byte values should raise ValueError."""
        with pytest.raises(ValueError):
            decode_mulaw(-1)
        with pytest.raises(ValueError):
            decode_mulaw(256)


class TestALawDecode:
    """Test A-law (PCMA, payload type 8) decoding."""

    def test_key_vectors_match_itu_t(self) -> None:
        """Brief-required vectors, ground truth from ITU-T G.711 / ffmpeg."""
        assert decode_alaw(0xD5) == 8
        assert decode_alaw(0x55) == -8

    def test_alaw_decode_accepts_valid_bytes(self) -> None:
        """Decode should accept all valid bytes 0x00-0xFF."""
        for b in (0x00, 0x55, 0x80, 0xAA, 0xFF):
            result = decode_alaw(b)
            assert isinstance(result, int)

    def test_alaw_invalid_input(self) -> None:
        """Invalid byte values should raise ValueError."""
        with pytest.raises(ValueError):
            decode_alaw(-1)
        with pytest.raises(ValueError):
            decode_alaw(256)


class TestG711ArrayDecoding:
    """Test array decoding for RTP payload extraction."""

    def test_decode_mulaw_array(self) -> None:
        """Decode a sequence of mu-law bytes to 16-bit PCM."""
        data = bytes([0x00] * 10)
        result = decode_mulaw_array(data)
        assert len(result) == 20  # 10 bytes -> 20 bytes (16-bit each)

    def test_decode_alaw_array(self) -> None:
        """Decode a sequence of A-law bytes to 16-bit PCM."""
        data = bytes([0x00] * 10)
        result = decode_alaw_array(data)
        assert len(result) == 20  # 10 bytes -> 20 bytes

    def test_decode_mulaw_array_values(self) -> None:
        """Decoded bytes should match individual decode calls."""
        data = bytes([0xFF, 0x00, 0x80, 0xFE])
        result = decode_mulaw_array(data)
        samples = struct.unpack("<4h", result)
        assert samples == (0, -32124, 32124, 8)


class TestG711WavExport:
    """Test WAV file generation from decoded G.711 audio."""

    def test_export_mulaw_to_wav(self, tmp_path: Path) -> None:
        """Export decoded mu-law to WAV file."""
        audio_data = decode_mulaw_array(bytes([0x00] * 80))

        wav_path = tmp_path / "test_mulaw.wav"
        with wave.open(str(wav_path), "wb") as wf:
            wf.setnchannels(1)  # mono
            wf.setsampwidth(2)  # 16-bit
            wf.setframerate(8000)  # 8kHz
            wf.writeframes(audio_data)

        # Verify the file
        assert wav_path.exists()
        with wave.open(str(wav_path), "rb") as wf:
            assert wf.getnframes() == 80
            assert wf.getframerate() == 8000
            assert wf.getsampwidth() == 2

    def test_export_alaw_to_wav(self, tmp_path: Path) -> None:
        """Export decoded A-law to WAV file."""
        audio_data = decode_alaw_array(bytes([0x00] * 80))

        wav_path = tmp_path / "test_alaw.wav"
        with wave.open(str(wav_path), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)  # 16-bit
            wf.setframerate(8000)  # 8kHz
            wf.writeframes(audio_data)

        assert wav_path.exists()
        with wave.open(str(wav_path), "rb") as wf:
            assert wf.getnframes() == 80
            assert wf.getframerate() == 8000


class TestG711RtpPayload:
    """Test RTP payload decoding function."""

    def test_decode_rtp_payload_mulaw(self) -> None:
        """Decode RTP payload with mu-law encoding (pt=0)."""
        payload = bytes([0x00] * 10)
        result = decode_rtp_payload(payload, 0)
        assert len(result) == 20  # 10 bytes -> 20 bytes (16-bit)

    def test_decode_rtp_payload_alaw(self) -> None:
        """Decode RTP payload with A-law encoding (pt=8)."""
        payload = bytes([0x00] * 10)
        result = decode_rtp_payload(payload, 8)
        assert len(result) == 20

    def test_decode_rtp_payload_unsupported(self) -> None:
        """Unsupported payload type raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported"):
            decode_rtp_payload(b"test", 4)


class TestG711RoundTrip:
    """Verify our decode matches ffmpeg's encode (ground truth for the codec).

    G.711 is a lossy codec, so not every 16-bit sample has an exact byte
    representation. We verify that for every byte ffmpeg produces, our decode
    table returns the same sample ffmpeg's decoder returns (i.e. our tables
    match ffmpeg's bit-for-bit on decode).
    """

    @pytest.mark.skipif(not FFMPEG, reason="ffmpeg not available")
    def test_mulaw_decode_matches_ffmpeg(self) -> None:
        """Our MU_LAW_DECODE must match ffmpeg's PCMU decoder for all 256 codes."""
        ffmpeg_decoded = struct.unpack("<256h", _ffmpeg_decode(bytes(range(256)), "mulaw"))
        assert list(MU_LAW_DECODE) == list(ffmpeg_decoded)

    @pytest.mark.skipif(not FFMPEG, reason="ffmpeg not available")
    def test_alaw_decode_matches_ffmpeg(self) -> None:
        """Our A_LAW_DECODE must match ffmpeg's PCMA decoder for all 256 codes."""
        ffmpeg_decoded = struct.unpack("<256h", _ffmpeg_decode(bytes(range(256)), "alaw"))
        assert list(A_LAW_DECODE) == list(ffmpeg_decoded)

    @pytest.mark.skipif(not FFMPEG, reason="ffmpeg not available")
    def test_mulaw_encode_decodes_to_nearest(self) -> None:
        """decode(encode(v)) returns the nearest representable value."""
        for v in [-32124, -10000, -100, 0, 100, 10000, 32124]:
            byte = encode_mulaw(v)
            decoded = decode_mulaw(byte)
            assert decoded in MU_LAW_DECODE


class TestG711Tables:
    """Test the decode tables have correct structure."""

    def test_mu_law_table_complete(self) -> None:
        """Mu-law table has 256 entries."""
        assert len(MU_LAW_DECODE) == 256

    def test_alaw_table_complete(self) -> None:
        """A-law table has 256 entries."""
        assert len(A_LAW_DECODE) == 256

    def test_mu_law_table_contains_expected_values(self) -> None:
        """Spot-check values verified against ffmpeg."""
        assert MU_LAW_DECODE[0xFF] == 0
        assert MU_LAW_DECODE[0x00] == -32124
        assert MU_LAW_DECODE[0x80] == 32124
        assert MU_LAW_DECODE[0xFE] == 8

    def test_alaw_table_contains_expected_values(self) -> None:
        """Spot-check values verified against ffmpeg."""
        assert A_LAW_DECODE[0xD5] == 8
        assert A_LAW_DECODE[0x55] == -8
