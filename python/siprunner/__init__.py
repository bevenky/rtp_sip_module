"""
siprunner - High-performance SIP/RTP library for Voice AI

A Rust library for SIP signaling and RTP media handling,
exposed to Python via PyO3.

Two Operating Modes:

Mode A: Full SIP + RTP (Python config)
    from siprunner import SipRunner
    from siprunner.config import Config, ProviderConfig

    config = Config(
        providers=[
            ProviderConfig(
                name="twilio",
                server="sip.twilio.com",
                username="ACCOUNT_SID",
                password="AUTH_TOKEN",
                prefixes=["+1"],
                default=True,
            )
        ]
    )
    config.to_toml("config.toml")

    runner = SipRunner.from_config("config.toml")
    runner.start()
    call_id = runner.call(to="+14155551234", from_="+14155550000")
    # ...

Mode A: Full SIP + RTP (programmatic single provider)
    from siprunner import SipRunner

    runner = SipRunner(
        provider_name="plivo",
        provider_server="sip.plivo.com",
        username="AUTH_ID",
        password="AUTH_TOKEN",
    )
    runner.start()
    # ...

Mode B: RTP-Only (External Signaling)
    from siprunner import RtpSession
    from siprunner.config import RtpSessionConfig

    config = RtpSessionConfig(
        local_ip="0.0.0.0",
        local_port=0,  # Dynamic
        codec="PCMU",
    )

    session = RtpSession(**config.to_dict())
    session.start()
    session.send_audio(samples)
    audio = session.recv_audio(100)
    session.stop()
"""

from siprunner._siprunner import (
    # Mode A: Full SIP + RTP
    SipRunner,
    CallEvent,
    CallState,
    DtmfMode,
    # Mode B: RTP-only
    RtpSession,
    JitterStats,
    # Version
    __version__,
)

# Configuration classes
from siprunner.config import (
    Config,
    SipConfig,
    RtpConfig,
    ProviderConfig,
    RtpSessionConfig,
    create_single_provider_config,
    create_multi_provider_config,
)

__all__ = [
    # Mode A - Core
    "SipRunner",
    "CallEvent",
    "CallState",
    "DtmfMode",
    # Mode B - Core
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
