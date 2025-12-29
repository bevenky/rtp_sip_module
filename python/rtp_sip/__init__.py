"""
rtp_sip - Python bindings for libfs telephony (SIP/RTP)

This module provides async Python bindings for SIP/RTP telephony
using embedded libfs (FreeSWITCH) as the underlying engine.

Modes:
- Mode 3 (RTP-Only): Use RtpSession when SIP is handled externally
- Mode 1 (Outbound): Use SIP.dial() to place calls
- Mode 2 (Inbound): Use SIP with set_inbound_handler

Example:
    import asyncio
    from rtp_sip import RtpSession, RtpConfig, AudioFrame

    async def main():
        config = RtpConfig("0.0.0.0", 5004, "192.168.1.100", 5006)
        session = RtpSession(config)

        await session.start()

        # Receive audio (L16 PCM, 16kHz, mono)
        frame = await session.recv_audio(100)
        if frame:
            # Process with STT...
            samples = frame.samples

        # Send audio
        response = AudioFrame(audio_bytes, 16000)
        await session.send_audio(response)

        await session.stop()

    asyncio.run(main())
"""

# Import from Rust extension
try:
    from .rtp_sip import (
        # Config
        Config,
        # RTP (Mode 3)
        RtpConfig,
        RtpSession,
        RtpStats,
        # SIP (Mode 1 & 2)
        PyswitchConfig,
        SipConfig,
        TrunkConfig,
        SIP,
        Call,
        CallDirection,
        # Audio
        AudioFrame,
        Codec,
        # Functions
        shutdown,
        is_running,
        _shutdown_sync,
        # Version
        __version__,
    )
except ImportError as e:
    raise ImportError(
        "Failed to import rtp_sip native module. "
        "Make sure you've built it with 'maturin develop' or 'maturin build'. "
        f"Original error: {e}"
    ) from e

__all__ = [
    # Config
    "Config",
    # RTP (Mode 3)
    "RtpConfig",
    "RtpSession",
    "RtpStats",
    # SIP (Mode 1 & 2)
    "PyswitchConfig",
    "SipConfig",
    "TrunkConfig",
    "SIP",
    "Call",
    "CallDirection",
    # Audio
    "AudioFrame",
    "Codec",
    # Functions
    "shutdown",
    "is_running",
    # Version
    "__version__",
]
