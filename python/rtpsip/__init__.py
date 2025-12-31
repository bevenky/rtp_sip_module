"""
rtpsip - High-performance SIP/RTP library for Voice AI

A Rust library for SIP signaling and RTP media handling,
exposed to Python via PyO3.

Example (Decorator-based interface):
    from rtpsip import Client, Call

    client = Client("sip", config="config.toml")

    @client.on_incoming
    def handle_incoming(call: Call):
        print(f"Incoming call from {call.from_uri}")
        call.answer()

    @client.on_audio
    def handle_audio(call: Call, samples: list[int]):
        response = ai.process(samples)
        call.send_audio(response)

    @client.on_dtmf
    def handle_dtmf(call: Call, digit: str):
        print(f"DTMF: {digit}")

    @client.on_hangup
    def handle_hangup(call: Call, reason: str):
        print(f"Call ended: {reason}")

    # Make outbound call
    call = client.dial(to="+14155551234", from_="+14155550000")

    client.run()

Two modes:
    - "sip": Full SIP + RTP (signaling + media)
    - "rtp": RTP-only (media only, external signaling via WebSocket)

Config auto-detection:
    1. Explicit config parameter
    2. config.toml in current directory
    3. Environment variables (RTPSIP_PROVIDER, RTPSIP_AUTH_USERNAME, etc.)
"""

# New decorator-based interface
from rtpsip.client import Client, Call

# Low-level Rust bindings (for advanced usage)
from rtpsip._rtpsip import (
    SipRunner,
    CallEvent,
    CallState,
    DtmfMode,
    RtpSession,
    JitterStats,
    __version__,
)

# Configuration classes
from rtpsip.config import (
    Config,
    SipConfig,
    RtpConfig,
    ProviderConfig,
    RtpSessionConfig,
    create_single_provider_config,
    create_multi_provider_config,
)

__all__ = [
    # New interface
    "Client",
    "Call",
    # Low-level (advanced)
    "SipRunner",
    "CallEvent",
    "CallState",
    "DtmfMode",
    "RtpSession",
    "JitterStats",
    # Configuration
    "Config",
    "SipConfig",
    "RtpConfig",
    "ProviderConfig",
    "RtpSessionConfig",
    "create_single_provider_config",
    "create_multi_provider_config",
    # Version
    "__version__",
]
