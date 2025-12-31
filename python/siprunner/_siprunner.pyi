"""Type stubs for siprunner._siprunner"""

from typing import Optional, List
from enum import IntEnum

__version__: str


# =============================================================================
# Mode A: Full SIP + RTP
# =============================================================================

class Transport(IntEnum):
    """Transport protocol enum"""
    Udp = 0
    Tcp = 1
    Tls = 2
    WebSocket = 3


class CallState(IntEnum):
    """Call state enum"""
    Initializing = 0
    Ringing = 1
    Answered = 2
    Active = 3
    Terminating = 4
    Terminated = 5


class DtmfMode(IntEnum):
    """
    DTMF transmission mode.

    Auto: Auto-detect from remote SDP (recommended)
    Rfc2833: Force RFC 2833 in RTP (telephone-event)
    Info: Force SIP INFO
    """
    Auto = 0
    Rfc2833 = 1
    Info = 2


class ProviderConfig:
    """
    SIP provider configuration.

    Args:
        id: Unique provider identifier
        sip_server: SIP server hostname
        username: Authentication username
        password: Authentication password
        name: Human-readable name (defaults to id)
        sip_port: SIP server port (default: 5060)
        transport: Transport protocol (default: UDP)
        realm: Authentication realm (optional)
        from_domain: From header domain (optional)
        prefixes: List of phone number prefixes this provider handles
        priority: Routing priority (lower = higher priority)
        max_concurrent: Maximum concurrent calls (None = unlimited)
        register: Whether to register with the provider
        register_interval: Registration interval in seconds
    """

    id: str
    name: str
    sip_server: str
    sip_port: int
    transport: Transport
    username: str
    password: str
    realm: Optional[str]
    from_domain: Optional[str]
    prefixes: List[str]
    priority: int
    max_concurrent: Optional[int]
    register: bool
    register_interval: int

    def __init__(
        self,
        id: str,
        sip_server: str,
        username: str,
        password: str,
        name: Optional[str] = None,
        sip_port: int = 5060,
        transport: Transport = Transport.Udp,
        realm: Optional[str] = None,
        from_domain: Optional[str] = None,
        prefixes: Optional[List[str]] = None,
        priority: int = 1,
        max_concurrent: Optional[int] = None,
        register: bool = False,
        register_interval: int = 300,
    ) -> None: ...


class CallEvent:
    """
    Call event received from SipRunner.

    Attributes:
        event_type: Event type ("incoming", "ringing", "early_media", "answered",
                    "audio_ready", "dtmf_received", "reinvite", "hangup", "error")
        call_id: Call ID this event relates to
        from_uri: From URI (for incoming calls)
        to_uri: To URI (for incoming calls)
        reason: Reason string (for hangup events)
        error: Error message (for error events)
        sdp: SDP body (for early_media and reinvite events)
        digit: DTMF digit (for dtmf_received events)
        duration: DTMF duration in ms (for dtmf_received events)
    """

    event_type: str
    call_id: str
    from_uri: Optional[str]
    to_uri: Optional[str]
    reason: Optional[str]
    error: Optional[str]
    sdp: Optional[str]
    digit: Optional[str]
    duration: Optional[int]

    def is_incoming(self) -> bool:
        """Check if this is an incoming call event"""
        ...

    def is_ringing(self) -> bool:
        """Check if this is a ringing event (180 Ringing)"""
        ...

    def is_early_media(self) -> bool:
        """Check if this is an early media event (183 Session Progress)"""
        ...

    def is_answered(self) -> bool:
        """Check if this is an answered event (200 OK)"""
        ...

    def is_audio_ready(self) -> bool:
        """Check if this is an audio ready event"""
        ...

    def is_dtmf(self) -> bool:
        """Check if this is a DTMF received event"""
        ...

    def is_reinvite(self) -> bool:
        """Check if this is a re-INVITE event"""
        ...

    def is_hangup(self) -> bool:
        """Check if this is a hangup event"""
        ...

    def is_error(self) -> bool:
        """Check if this is an error event"""
        ...


class CallSession:
    """
    Handle to an active call session.

    Provides convenient methods for interacting with a specific call.
    """

    @property
    def call_id(self) -> str:
        """Get the call ID"""
        ...

    def send_audio(self, samples: List[int]) -> None:
        """
        Send audio samples to this call.

        Args:
            samples: PCM i16 samples, 8kHz mono
        """
        ...

    def recv_audio(self, timeout_ms: int) -> List[int]:
        """
        Receive audio samples from this call.

        Args:
            timeout_ms: Timeout in milliseconds

        Returns:
            PCM i16 samples, 8kHz mono
        """
        ...

    def hangup(self) -> None:
        """Hangup this call"""
        ...

    def state(self) -> Optional[CallState]:
        """Get the current call state"""
        ...


class SipRunner:
    """
    Main Python interface for SIP + RTP operations.

    Provides a high-level API for making and receiving SIP calls
    with integrated RTP audio handling.

    Example:
        from siprunner import SipRunner, ProviderConfig

        runner = SipRunner()
        runner.add_provider(ProviderConfig(
            id="plivo",
            sip_server="sip.plivo.com",
            username="AUTH_ID",
            password="AUTH_TOKEN",
            prefixes=["+1"],
        ))
        runner.start()

        call_id = runner.call(
            to="sip:+14155551234@sip.plivo.com",
            from_="sip:+14155550000@sip.plivo.com"
        )
        runner.send_audio(call_id, samples)
        audio = runner.recv_audio(call_id, timeout_ms=100)
        runner.hangup(call_id)

        runner.stop()
    """

    def __init__(
        self,
        local_addr: str = "0.0.0.0:5060",
        rtp_port_start: int = 10000,
        rtp_port_end: int = 20000,
    ) -> None:
        """
        Create a new SipRunner instance.

        Args:
            local_addr: Local address to bind to (default: "0.0.0.0:5060")
            rtp_port_start: Start of RTP port range (default: 10000)
            rtp_port_end: End of RTP port range (default: 20000)
        """
        ...

    def add_provider(self, config: ProviderConfig) -> None:
        """
        Add a SIP provider configuration.

        Args:
            config: ProviderConfig instance
        """
        ...

    def remove_provider(self, provider_id: str) -> None:
        """
        Remove a provider.

        Args:
            provider_id: ID of the provider to remove
        """
        ...

    def start(self) -> None:
        """
        Start the SIP engine.

        Initializes the SIP engine and registers with configured providers.
        """
        ...

    def stop(self) -> None:
        """Stop the SIP engine"""
        ...

    def is_running(self) -> bool:
        """Check if the engine is running"""
        ...

    def call(
        self,
        to: str,
        from_: str,
        provider_id: Optional[str] = None,
    ) -> str:
        """
        Make an outbound call.

        Args:
            to: Destination SIP URI (e.g., "sip:+14155551234@sip.provider.com")
            from_: Caller SIP URI
            provider_id: Optional provider ID (if not specified, auto-routes based on prefixes)

        Returns:
            Call ID string
        """
        ...

    def hangup(self, call_id: str) -> None:
        """
        Hangup a call.

        Args:
            call_id: Call ID to hangup
        """
        ...

    def send_audio(self, call_id: str, samples: List[int]) -> None:
        """
        Send audio samples to a call.

        Args:
            call_id: Call ID
            samples: List of PCM i16 samples (8kHz mono)
        """
        ...

    def recv_audio(self, call_id: str, timeout_ms: int) -> List[int]:
        """
        Receive audio samples from a call.

        Args:
            call_id: Call ID
            timeout_ms: Timeout in milliseconds

        Returns:
            List of PCM i16 samples (8kHz mono)
        """
        ...

    def answer(self, call_id: str) -> None:
        """
        Answer an incoming call.

        Args:
            call_id: Call ID to answer
        """
        ...

    def reject(self, call_id: str, status_code: int = 486) -> None:
        """
        Reject an incoming call.

        Args:
            call_id: Call ID to reject
            status_code: SIP status code (486=Busy, 603=Decline)
        """
        ...

    def send_dtmf(
        self,
        call_id: str,
        digits: str,
        duration_ms: int = 100,
        inter_digit_ms: int = 100,
    ) -> None:
        """
        Send DTMF digits (auto-selects RFC 2833 or SIP INFO).

        Uses RFC 2833 if remote supports telephone-event in SDP,
        otherwise falls back to SIP INFO.

        Args:
            call_id: Call ID
            digits: DTMF digits to send (0-9, *, #, A-D, w=500ms pause, W=1s pause)
            duration_ms: Duration per digit in milliseconds (default: 100)
            inter_digit_ms: Delay between digits in milliseconds (default: 100)
        """
        ...

    def recv_dtmf(self, call_id: str) -> Optional[tuple[str, int]]:
        """
        Non-blocking receive of RFC 2833 DTMF from RTP stream.

        Args:
            call_id: Call ID

        Returns:
            Tuple of (digit, duration_ms) or None if no DTMF available
        """
        ...

    def recv_dtmf_blocking(self, call_id: str, timeout_ms: int) -> Optional[tuple[str, int]]:
        """
        Blocking receive of RFC 2833 DTMF from RTP stream.

        Args:
            call_id: Call ID
            timeout_ms: Timeout in milliseconds

        Returns:
            Tuple of (digit, duration_ms) or None on timeout
        """
        ...

    def get_dtmf_mode(self, call_id: str) -> DtmfMode:
        """
        Get the DTMF mode for a call.

        Args:
            call_id: Call ID

        Returns:
            DtmfMode.Rfc2833 if remote supports telephone-event, else DtmfMode.Info
        """
        ...

    def set_dtmf_mode(self, call_id: str, mode: DtmfMode) -> None:
        """
        Override the DTMF mode for a call.

        Args:
            call_id: Call ID
            mode: DtmfMode.Auto, DtmfMode.Rfc2833, or DtmfMode.Info
        """
        ...

    def transfer(self, call_id: str, target: str) -> None:
        """
        Blind transfer a call (REFER).

        Args:
            call_id: Call ID to transfer
            target: Target SIP URI (e.g., "sip:+14155559999@sip.provider.com")
        """
        ...

    def hold(self, call_id: str) -> None:
        """
        Put call on hold.

        Sends a re-INVITE with sendonly SDP to put the call on hold.

        Args:
            call_id: Call ID to hold
        """
        ...

    def unhold(self, call_id: str) -> None:
        """
        Resume call from hold.

        Sends a re-INVITE with sendrecv SDP to resume the call.

        Args:
            call_id: Call ID to resume
        """
        ...

    def reinvite(self, call_id: str, sdp: Optional[str] = None) -> None:
        """
        Send re-INVITE with custom SDP.

        Uses rsipstack's dialog.reinvite() for session modification.

        Args:
            call_id: Call ID
            sdp: New SDP offer (optional, uses current if None)
        """
        ...

    def next_event(self, timeout_ms: int) -> Optional[CallEvent]:
        """
        Get the next event (blocking).

        Args:
            timeout_ms: Timeout in milliseconds

        Returns:
            CallEvent or None if timeout
        """
        ...

    def active_calls(self) -> List[str]:
        """Get all active call IDs"""
        ...

    def get_call_state(self, call_id: str) -> Optional[CallState]:
        """Get the state of a call"""
        ...


# =============================================================================
# Mode B: RTP-only
# =============================================================================

class JitterStats:
    """Jitter buffer statistics"""

    @property
    def packets_received(self) -> int:
        """Number of packets received"""
        ...

    @property
    def packets_lost(self) -> int:
        """Number of packets lost"""
        ...

    @property
    def packets_dropped(self) -> int:
        """Number of packets dropped (late arrivals)"""
        ...

    @property
    def packets_reordered(self) -> int:
        """Number of packets reordered"""
        ...

    @property
    def jitter_ms(self) -> float:
        """Current jitter in milliseconds"""
        ...

    @property
    def buffer_delay_ms(self) -> int:
        """Current buffer delay in milliseconds"""
        ...

    @property
    def buffer_size(self) -> int:
        """Current buffer size (number of packets)"""
        ...


class RtpSession:
    """
    RTP-only session for use with external signaling.

    Example:
        session = RtpSession(
            local_addr="0.0.0.0:0",
            remote_addr="1.2.3.4:5678",
            codec="PCMU",
        )
        session.start()

        # Send audio (PCM i16 samples, 8kHz mono)
        session.send_audio(samples)

        # Receive audio
        audio = session.recv_audio(100)  # 100ms timeout

        session.stop()

    Args:
        local_addr: Local address to bind to (default: "0.0.0.0:0" for ephemeral port)
        remote_addr: Remote RTP endpoint address (can be set later with set_remote)
        codec: Codec to use ("PCMU" or "PCMA", default: "PCMU")
        ssrc: SSRC identifier (auto-generated if not provided)
    """

    def __init__(
        self,
        local_addr: str = "0.0.0.0:0",
        remote_addr: Optional[str] = None,
        codec: str = "PCMU",
        ssrc: Optional[int] = None,
    ) -> None: ...

    @property
    def local_addr(self) -> str:
        """Get the local address (available after start)"""
        ...

    @property
    def remote_addr(self) -> Optional[str]:
        """Get the remote address"""
        ...

    @property
    def ssrc(self) -> int:
        """Get the SSRC"""
        ...

    @property
    def codec(self) -> str:
        """Get the codec type"""
        ...

    @property
    def is_running(self) -> bool:
        """Check if the session is running"""
        ...

    def set_remote(self, addr: str) -> None:
        """
        Set the remote RTP endpoint address.

        Args:
            addr: Remote address in "host:port" format
        """
        ...

    def start(self) -> None:
        """Start the RTP session"""
        ...

    def stop(self) -> None:
        """Stop the RTP session"""
        ...

    def send_audio(self, samples: List[int]) -> None:
        """
        Send audio samples.

        Args:
            samples: PCM i16 samples, 8kHz mono (typically 160 samples = 20ms)
        """
        ...

    def recv_audio(self, timeout_ms: int) -> Optional[List[int]]:
        """
        Receive audio samples with timeout.

        Args:
            timeout_ms: Timeout in milliseconds

        Returns:
            PCM i16 samples, 8kHz mono, or None if timeout
        """
        ...

    def get_stats(self) -> JitterStats:
        """Get jitter buffer statistics"""
        ...

    def reset_jitter_buffer(self) -> None:
        """Reset the jitter buffer"""
        ...
