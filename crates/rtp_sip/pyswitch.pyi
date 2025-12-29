"""Type stubs for pyswitch native module.

Thin wrappers around FreeSWITCH for SIP/RTP telephony.

Modes:
- Mode 3 (RTP-only): External SIP handling, pyswitch handles RTP
- Mode 1 (Outbound): Python initiates calls via SipStack.dial()
- Mode 2 (Inbound): Python receives calls via set_inbound_handler()
"""

from typing import Awaitable, Callable, Optional

__version__: str

class Codec:
    """Audio codec enumeration."""

    PCMU: Codec
    """G.711 u-law"""

    PCMA: Codec
    """G.711 A-law"""

    L16: Codec
    """Linear 16-bit PCM"""

    @property
    def payload_type(self) -> int:
        """RTP payload type number."""
        ...

class AudioFrame:
    """Audio frame containing PCM samples."""

    def __init__(self, samples: bytes, sample_rate: int = 16000) -> None:
        """Create a new audio frame.

        Args:
            samples: L16 PCM bytes (little-endian)
            sample_rate: Sample rate in Hz (default: 16000)
        """
        ...

    @property
    def samples(self) -> bytes:
        """Raw PCM samples as bytes (L16, little-endian)."""
        ...

    @property
    def sample_rate(self) -> int:
        """Sample rate in Hz."""
        ...

    @property
    def channels(self) -> int:
        """Number of channels (always 1 = mono)."""
        ...

    @property
    def timestamp(self) -> int:
        """RTP timestamp."""
        ...

    @property
    def duration_ms(self) -> int:
        """Frame duration in milliseconds."""
        ...

    def num_samples(self) -> int:
        """Number of samples in the frame."""
        ...

    def is_empty(self) -> bool:
        """Check if frame is empty."""
        ...

    @staticmethod
    def from_bytes(data: bytes, sample_rate: int = 16000) -> "AudioFrame":
        """Create a frame from raw bytes."""
        ...

    @staticmethod
    def silence_20ms() -> "AudioFrame":
        """Create a 20ms frame of silence at 16kHz."""
        ...

class RtpConfig:
    """RTP session configuration."""

    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
    ) -> None:
        """Create a new RTP configuration.

        Args:
            local_ip: Local IP to bind for receiving (e.g., "0.0.0.0")
            local_port: Local port to bind
            remote_ip: Remote IP to send to
            remote_port: Remote port to send to
        """
        ...

    def with_codec(self, codec: Codec) -> "RtpConfig":
        """Set the codec (default: PCMU)."""
        ...

    def with_sample_rate(self, sample_rate: int) -> "RtpConfig":
        """Set the sample rate (default: 8000)."""
        ...

    def with_ptime(self, ptime_ms: int) -> "RtpConfig":
        """Set packet time in milliseconds (default: 20)."""
        ...

    @property
    def local_ip(self) -> str: ...
    @property
    def local_port(self) -> int: ...
    @property
    def remote_ip(self) -> str: ...
    @property
    def remote_port(self) -> int: ...

class RtpStats:
    """RTP session statistics."""

    @property
    def packets_sent(self) -> int: ...
    @property
    def packets_received(self) -> int: ...
    @property
    def packets_lost(self) -> int: ...
    @property
    def jitter_ms(self) -> float: ...
    @property
    def rtt_ms(self) -> float: ...

class RtpSession:
    """RTP session for audio transport (Mode 3: RTP-only).

    Use when SIP signaling is handled externally (e.g., via WebSocket).
    Audio is received/sent via RTP based on negotiated parameters.
    """

    def __init__(self, config: RtpConfig) -> None:
        """Create a new RTP session.

        Args:
            config: RTP configuration
        """
        ...

    async def start(self) -> None:
        """Start the RTP session.

        Binds to local port and begins receiving/sending RTP.
        """
        ...

    async def stop(self) -> None:
        """Stop the RTP session."""
        ...

    async def recv_audio(self, timeout_ms: int = 100) -> Optional[AudioFrame]:
        """Receive next audio frame from remote.

        Returns L16 PCM at 16kHz mono (suitable for STT).
        Returns None on timeout.

        Args:
            timeout_ms: Timeout in milliseconds (default: 100)
        """
        ...

    async def send_audio(self, frame: AudioFrame) -> None:
        """Send audio frame to remote.

        Frame should be L16 PCM at 16kHz mono.
        Automatically resampled to 8kHz and encoded to G.711.
        """
        ...

    async def send_audio_bytes(self, data: bytes) -> None:
        """Send raw audio bytes (L16 PCM, 16kHz, mono)."""
        ...

    def update_remote(self, ip: str, port: int) -> None:
        """Update remote RTP endpoint.

        Use when remote party's address changes.
        """
        ...

    @property
    def local_port(self) -> int:
        """Get local port."""
        ...

    @property
    def is_running(self) -> bool:
        """Check if session is running."""
        ...

    @property
    def stats(self) -> RtpStats:
        """Get RTP statistics."""
        ...


# =============================================================================
# SIP Classes (Mode 1 & 2)
# =============================================================================


class CallDirection:
    """Call direction enumeration."""

    INBOUND: "CallDirection"
    """Inbound call (caller -> us)."""

    OUTBOUND: "CallDirection"
    """Outbound call (us -> callee)."""


class Call:
    """Active call session.

    Uses media bugs for audio capture/injection,
    which works correctly with mod_sofia's internal RTP management.
    """

    @property
    def uuid(self) -> str:
        """Get call UUID."""
        ...

    @property
    def direction(self) -> CallDirection:
        """Get call direction."""
        ...

    @property
    def caller_id(self) -> Optional[str]:
        """Get caller ID (for inbound calls)."""
        ...

    @property
    def destination(self) -> Optional[str]:
        """Get destination number."""
        ...

    @property
    def is_active(self) -> bool:
        """Check if call is active."""
        ...

    async def answer(self) -> None:
        """Answer the call (for inbound calls)."""
        ...

    async def hangup(self, reason: Optional[str] = None) -> None:
        """Hangup the call.

        Args:
            reason: Hangup reason (optional):
                - "normal_clearing" (default)
                - "user_busy"
                - "no_answer"
                - "call_rejected"
        """
        ...

    async def recv_audio(self, timeout_ms: int = 100) -> Optional[AudioFrame]:
        """Receive audio frame from remote.

        Returns L16 PCM at 16kHz mono (upsampled from 8kHz).
        Returns None on timeout.

        Args:
            timeout_ms: Timeout in milliseconds (default: 100)
        """
        ...

    async def send_audio(self, frame: AudioFrame) -> None:
        """Send audio frame to remote.

        Frame should be L16 PCM at 16kHz mono.
        """
        ...

    async def send_dtmf(self, digits: str) -> None:
        """Send DTMF digits.

        Args:
            digits: DTMF digits to send (0-9, *, #, A-D)
        """
        ...

    def get_variable(self, name: str) -> Optional[str]:
        """Get a channel variable."""
        ...


class SipConfig:
    """SIP stack configuration."""

    def __init__(
        self,
        local_ip: str = "0.0.0.0",
        local_port: int = 5060,
        user_agent: str = "plivo-sip-agent",
        debug: bool = False,
    ) -> None:
        """Create a new SIP configuration.

        Args:
            local_ip: Local IP address (default: "0.0.0.0")
            local_port: Local SIP port (default: 5060)
            user_agent: User agent string (default: "plivo-sip-agent")
            debug: Enable debug logging (default: False)
        """
        ...

    @property
    def local_ip(self) -> str: ...
    @property
    def local_port(self) -> int: ...
    @property
    def user_agent(self) -> str: ...
    @property
    def debug(self) -> bool: ...


class TrunkConfig:
    """SIP trunk configuration for connecting to carriers/providers."""

    def __init__(
        self,
        name: str,
        host: str,
        port: int = 5060,
        username: Optional[str] = None,
        password: Optional[str] = None,
        register: bool = False,
        caller_id_name: Optional[str] = None,
        caller_id_number: Optional[str] = None,
    ) -> None:
        """Create a new trunk configuration.

        Args:
            name: Trunk name (used in dial strings)
            host: Gateway host (IP or hostname)
            port: Gateway port (default: 5060)
            username: Auth username (optional)
            password: Auth password (optional)
            register: Register with gateway (default: False)
            caller_id_name: Caller ID name (optional)
            caller_id_number: Caller ID number (optional)
        """
        ...

    @property
    def name(self) -> str: ...
    @property
    def host(self) -> str: ...
    @property
    def port(self) -> int: ...
    @property
    def username(self) -> Optional[str]: ...
    @property
    def register(self) -> bool: ...
    @property
    def caller_id_name(self) -> Optional[str]: ...
    @property
    def caller_id_number(self) -> Optional[str]: ...


class SIP:
    """SIP transport for managing trunks and calls.

    Uses embedded FreeSWITCH with mod_sofia and media bugs
    for audio capture/injection.

    Example:
        >>> sip = SIP(SipConfig())
        >>> await sip.start()
        >>> await sip.add_trunk(TrunkConfig("mytrunk", "sip.provider.com"))
        >>> call = await sip.dial("18005551234", "mytrunk")
        >>> while call.is_active:
        ...     frame = await call.recv_audio(100)
        >>> await call.hangup()
        >>> await sip.stop()
    """

    def __init__(self, config: SipConfig) -> None:
        """Create a new SIP transport.

        Args:
            config: SIP transport configuration
        """
        ...

    @staticmethod
    async def from_config_file(path: str) -> "SIP":
        """Create a SIP transport from a TOML config file."""
        ...

    async def start(self) -> None:
        """Start the SIP transport."""
        ...

    async def stop(self) -> None:
        """Stop the SIP transport."""
        ...

    async def add_trunk(self, trunk: TrunkConfig) -> None:
        """Add a SIP trunk."""
        ...

    async def remove_trunk(self, name: str) -> None:
        """Remove a SIP trunk."""
        ...

    async def dial(
        self,
        destination: str,
        trunk: str,
        timeout_sec: Optional[int] = None,
        caller_id_name: Optional[str] = None,
        caller_id_number: Optional[str] = None,
    ) -> Call:
        """Dial an outbound call.

        Args:
            destination: Phone number or SIP URI
            trunk: Trunk name to use
            timeout_sec: Call timeout in seconds (default: 60)
            caller_id_name: Override caller ID name (optional)
            caller_id_number: Override caller ID number (optional)

        Returns:
            Call object representing the active call
        """
        ...

    async def handle_inbound(self, uuid: str) -> Call:
        """Handle an inbound call by UUID.

        Returns a Call object for the session.
        """
        ...

    async def get_session(self, uuid: str) -> Optional[Call]:
        """Get a session by UUID."""
        ...

    async def list_sessions(self) -> list[str]:
        """List active session UUIDs."""
        ...

    def set_inbound_handler(
        self, handler: Callable[[Call], Awaitable[None]]
    ) -> None:
        """Set handler for inbound calls.

        The handler is called for each incoming call with a Call object.

        Note: Automatic dispatch not yet implemented. Use handle_inbound()
        to manually handle inbound calls by UUID.

        Example:
            >>> async def on_call(call: Call) -> None:
            ...     await call.answer()
            ...     while call.is_active:
            ...         frame = await call.recv_audio()
            ...         # process audio...
            ...     await call.hangup()
            >>>
            >>> sip.set_inbound_handler(on_call)
        """
        ...

    @property
    def is_running(self) -> bool:
        """Check if transport is running."""
        ...


# Alias for backwards compatibility
SipStack = SIP
