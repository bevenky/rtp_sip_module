"""Tests for audio types."""

import pytest


def test_import():
    """Test that the module can be imported."""
    try:
        from rtp_sip import AudioFrame, Codec
    except ImportError:
        pytest.skip("rtp_sip not built - run 'maturin develop' first")


def test_codec_enum():
    """Test codec enumeration."""
    try:
        from rtp_sip import Codec

        assert Codec.PCMU.payload_type == 0
        assert Codec.PCMA.payload_type == 8
    except ImportError:
        pytest.skip("rtp_sip not built")


def test_audio_frame_creation():
    """Test creating an audio frame."""
    try:
        from rtp_sip import AudioFrame

        # Create a frame with 20ms of silence at 16kHz
        # 320 samples * 2 bytes = 640 bytes
        samples = bytes(640)
        frame = AudioFrame(samples, 16000)

        assert frame.sample_rate == 16000
        assert frame.channels == 1
        assert frame.duration_ms == 20
        assert frame.num_samples() == 320
        assert not frame.is_empty()
    except ImportError:
        pytest.skip("rtp_sip not built")


def test_audio_frame_silence():
    """Test creating a silence frame."""
    try:
        from rtp_sip import AudioFrame

        frame = AudioFrame.silence_20ms()

        assert frame.sample_rate == 16000
        assert frame.duration_ms == 20
        assert len(frame.samples) == 640
    except ImportError:
        pytest.skip("rtp_sip not built")
