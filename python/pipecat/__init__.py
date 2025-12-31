"""
Pipecat integration for siprunner

Provides serializers and transports for using siprunner with Pipecat pipelines.

Two transport types:

1. SipRtpTransport (Mode A - Full SIP + RTP):
   - Works with any SIP trunking provider (Twilio, Telnyx, Plivo SIP, etc.)
   - Handles SIP signaling + RTP media
   - Full call control: call, hangup, hold, transfer, DTMF

2. PlivoRtpTransport (Mode B - Plivo WebSocket + RTP):
   - Works with Plivo's WebSocket-based streaming
   - Two audio modes: "websocket" (default) or "rtp" (lower latency)
   - RTP mode uses siprunner's RtpSession for direct UDP audio

Example - SIP Trunking (any provider):
    from siprunner.pipecat import SipRtpTransport

    transport = SipRtpTransport(
        provider_name="twilio",
        server="sip.twilio.com",
        username="ACCOUNT_SID",
        password="AUTH_TOKEN",
    )

    await transport.start()
    call_id = await transport.call(to="+14155551234", from_="+14155550000")

Example - Plivo with RTP mode:
    from siprunner.pipecat import PlivoRtpTransport

    transport = PlivoRtpTransport(
        websocket=websocket,
        audio_mode="rtp",  # Use direct RTP instead of WebSocket audio
    )

    await transport.start()
    transport.set_rtp_remote(remote_ip, remote_port)
"""

# SIP RTP Transport (Mode A - any SIP provider)
from siprunner.pipecat.sip_rtp_serializer import (
    SipRtpTransport,
    SipInputTransport,
    SipOutputTransport,
    SipTransportParams,
    CallEventFrame,
    DtmfFrame,
)

# Plivo Transport with RTP mode (Mode B)
from siprunner.pipecat.plivo_serializer import (
    PlivoRtpTransport,
    PlivoInputTransport,
    PlivoOutputTransport,
    PlivoTransportParams,
    PlivoFrameSerializer,
    PlivoEventFrame,
    AudioMode,
)

__all__ = [
    # SIP+RTP (Mode A) - any SIP provider
    "SipRtpTransport",
    "SipInputTransport",
    "SipOutputTransport",
    "SipTransportParams",
    "CallEventFrame",
    "DtmfFrame",
    # Plivo with RTP mode (Mode B)
    "PlivoRtpTransport",
    "PlivoInputTransport",
    "PlivoOutputTransport",
    "PlivoTransportParams",
    "PlivoFrameSerializer",
    "PlivoEventFrame",
    "AudioMode",
]
