"""
Pipecat Transport for rtp_sip

Provides BaseTransport implementations for integrating rtp_sip with Pipecat
voice AI pipelines.

Two transport options:
1. RtpTransport - For RTP-only mode (external SIP signaling via WebSocket)
2. SipTransport - For full SIP mode (limited - mod_sofia unavailable)

Example with RTP-only mode (recommended):
    from rtp_sip.pipecat_transport import RtpTransport

    transport = RtpTransport(
        remote_ip="10.0.0.1",
        remote_port=20000,
        local_port=10000,  # optional
    )

    pipeline = Pipeline([
        transport.input(),
        stt,
        llm,
        tts,
        transport.output(),
    ])

    await pipeline.run()
"""

import asyncio
import logging
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass

from rtp_sip import (
    RtpSession,
    AudioFrame,
    SIP,
    SipConfig,
    TrunkConfig,
    Call,
)

logger = logging.getLogger(__name__)


# =============================================================================
# RTP-Only Transport (Mode 3) - RECOMMENDED
# =============================================================================

@dataclass
class RtpParams:
    """RTP parameters, typically received from external SIP signaling."""
    remote_ip: str
    remote_port: int
    local_port: int = 0  # 0 = auto-assign


class RtpTransport:
    """
    Pipecat-compatible transport using rtp_sip RTP-only mode.

    Use this when SIP signaling is handled externally (e.g., via WebSocket
    from FreeSWITCH, Odinweb, or another SIP proxy).

    Audio format:
        - Input: L16 PCM, 16kHz, mono (from remote, decoded from G.711)
        - Output: L16 PCM, 16kHz, mono (to remote, encoded to G.711)

    Example:
        async def handle_websocket(ws):
            # Get RTP params from WebSocket message
            msg = await ws.recv()
            params = json.loads(msg)

            transport = RtpTransport(
                remote_ip=params["remote_ip"],
                remote_port=params["remote_port"],
                local_port=params.get("local_port", 0),
            )

            await transport.start()

            # Audio loop
            while True:
                frame = await transport.recv_audio()
                if frame:
                    # Process with STT/LLM/TTS
                    response = await process(frame)
                    await transport.send_audio(response)
    """

    def __init__(
        self,
        remote_ip: str,
        remote_port: int,
        local_port: int = 0,
        sample_rate: int = 16000,
    ):
        """
        Create RTP transport.

        Args:
            remote_ip: Remote RTP endpoint IP
            remote_port: Remote RTP endpoint port
            local_port: Local port to bind (0 = auto-assign)
            sample_rate: Audio sample rate (default: 16000 for AI models)
        """
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self._local_port = local_port
        self.sample_rate = sample_rate
        self._session: Optional[RtpSession] = None
        self._running = False

    @classmethod
    def from_params(cls, params: RtpParams, sample_rate: int = 16000) -> "RtpTransport":
        """Create transport from RtpParams dataclass."""
        return cls(
            remote_ip=params.remote_ip,
            remote_port=params.remote_port,
            local_port=params.local_port,
            sample_rate=sample_rate,
        )

    async def start(self) -> None:
        """Start the RTP transport."""
        self._session = RtpSession(self.remote_ip, self.remote_port)
        if self._local_port:
            self._session.with_local_port(self._local_port)

        await self._session.start()
        self._running = True
        logger.info(
            f"RtpTransport started: local={self.local_port} -> "
            f"remote={self.remote_ip}:{self.remote_port}"
        )

    async def stop(self) -> None:
        """Stop the RTP transport."""
        self._running = False
        if self._session:
            await self._session.stop()
            self._session = None
        logger.info("RtpTransport stopped")

    async def recv_audio(self, timeout_ms: int = 100) -> Optional[AudioFrame]:
        """
        Receive audio frame from remote.

        Returns L16 PCM at 16kHz mono (decoded from G.711 8kHz, upsampled).
        Returns None on timeout.

        Args:
            timeout_ms: Timeout in milliseconds
        """
        if not self._session:
            return None
        return await self._session.recv_audio(timeout_ms)

    async def send_audio(self, frame: AudioFrame) -> None:
        """
        Send audio frame to remote.

        Accepts L16 PCM at 16kHz mono (downsampled to 8kHz, encoded to G.711).

        Args:
            frame: AudioFrame with L16 PCM data
        """
        if self._session:
            await self._session.send_audio(frame)

    async def send_audio_bytes(self, data: bytes, sample_rate: int = 16000) -> None:
        """
        Send raw audio bytes to remote.

        Args:
            data: L16 PCM bytes (little-endian, mono)
            sample_rate: Sample rate of the data
        """
        frame = AudioFrame(data, sample_rate)
        await self.send_audio(frame)

    def update_remote(self, ip: str, port: int) -> None:
        """Update remote endpoint (e.g., for odinweb re-INVITE)."""
        if self._session:
            self._session.update_remote(ip, port)

    @property
    def local_port(self) -> int:
        """Get the local port (after start)."""
        if self._session:
            return self._session.local_port
        return self._local_port

    @property
    def is_running(self) -> bool:
        """Check if transport is running."""
        return self._running and self._session is not None

    @property
    def stats(self):
        """Get RTP statistics."""
        if self._session:
            return self._session.stats
        return None


# =============================================================================
# SIP Transport (Mode 1/2) - LIMITED (mod_sofia unavailable in embedded mode)
# =============================================================================

@dataclass
class SipTrunkParams:
    """SIP trunk configuration parameters."""
    name: str
    host: str
    port: int = 5060
    username: Optional[str] = None
    password: Optional[str] = None
    register: bool = False
    caller_id_name: Optional[str] = None
    caller_id_number: Optional[str] = None


class SipTransport:
    """
    Pipecat-compatible transport using rtp_sip SIP mode.

    WARNING: SIP mode is limited because mod_sofia doesn't load in embedded
    mode. The SIP stack initializes but cannot make/receive calls.

    For production use, prefer RtpTransport with external SIP signaling.

    Example (conceptual - doesn't fully work yet):
        transport = SipTransport(
            trunk_params=SipTrunkParams(
                name="carrier",
                host="sip.provider.com",
                username="user",
                password="pass",
            ),
            local_port=5060,
        )

        # For inbound calls
        transport.set_inbound_handler(handle_call)
        await transport.start()

        # For outbound calls
        call = await transport.dial("+18005551234")
        while call.is_active:
            frame = await call.recv_audio()
            await call.send_audio(response)
    """

    def __init__(
        self,
        trunk_params: SipTrunkParams,
        local_ip: str = "0.0.0.0",
        local_port: int = 5060,
    ):
        """
        Create SIP transport.

        Args:
            trunk_params: SIP trunk configuration
            local_ip: Local IP to bind
            local_port: Local SIP port
        """
        self.trunk_params = trunk_params
        self.local_ip = local_ip
        self.local_port = local_port
        self._sip: Optional[SIP] = None
        self._inbound_handler: Optional[Callable[[Call], Awaitable[None]]] = None
        self._running = False

    def set_inbound_handler(
        self,
        handler: Callable[[Call], Awaitable[None]]
    ) -> None:
        """
        Set handler for inbound calls.

        Args:
            handler: Async function called with Call object for each inbound call
        """
        self._inbound_handler = handler
        if self._sip:
            self._sip.set_inbound_handler(handler)

    async def start(self) -> None:
        """Start the SIP transport and register with trunk."""
        config = SipConfig(
            local_ip=self.local_ip,
            local_port=self.local_port,
        )
        self._sip = SIP(config)

        if self._inbound_handler:
            self._sip.set_inbound_handler(self._inbound_handler)

        await self._sip.start()

        # Add trunk
        trunk = TrunkConfig(
            name=self.trunk_params.name,
            host=self.trunk_params.host,
            port=self.trunk_params.port,
            username=self.trunk_params.username,
            password=self.trunk_params.password,
            register=self.trunk_params.register,
            caller_id_name=self.trunk_params.caller_id_name,
            caller_id_number=self.trunk_params.caller_id_number,
        )
        await self._sip.add_trunk(trunk)

        self._running = True
        logger.info(f"SipTransport started on {self.local_ip}:{self.local_port}")

    async def stop(self) -> None:
        """Stop the SIP transport."""
        self._running = False
        if self._sip:
            await self._sip.stop()
            self._sip = None
        logger.info("SipTransport stopped")

    async def dial(
        self,
        destination: str,
        timeout_sec: int = 60,
        caller_id_name: Optional[str] = None,
        caller_id_number: Optional[str] = None,
    ) -> Call:
        """
        Dial an outbound call.

        Args:
            destination: Phone number or SIP URI
            timeout_sec: Ring timeout in seconds
            caller_id_name: Override caller ID name
            caller_id_number: Override caller ID number

        Returns:
            Call object for the active call
        """
        if not self._sip:
            raise RuntimeError("SipTransport not started")

        return await self._sip.dial(
            destination=destination,
            trunk=self.trunk_params.name,
            timeout_sec=timeout_sec,
            caller_id_name=caller_id_name,
            caller_id_number=caller_id_number,
        )

    @property
    def is_running(self) -> bool:
        """Check if transport is running."""
        return self._running


# =============================================================================
# Pipecat Frame Helpers
# =============================================================================

def audio_frame_to_pipecat(frame: AudioFrame) -> dict:
    """
    Convert rtp_sip AudioFrame to Pipecat AudioRawFrame format.

    Returns dict compatible with Pipecat's AudioRawFrame constructor.
    """
    return {
        "audio": frame.samples,
        "sample_rate": frame.sample_rate,
        "num_channels": frame.channels,
    }


def pipecat_to_audio_frame(
    audio: bytes,
    sample_rate: int = 16000,
) -> AudioFrame:
    """
    Convert Pipecat audio data to rtp_sip AudioFrame.

    Args:
        audio: L16 PCM bytes from Pipecat
        sample_rate: Sample rate (default: 16000)
    """
    return AudioFrame(audio, sample_rate)


# =============================================================================
# Pipecat BaseTransport Integration (when pipecat is installed)
# =============================================================================

try:
    from pipecat.transports.base_transport import BaseTransport
    from pipecat.frames.frames import AudioRawFrame, Frame

    class PipecatRtpTransport(BaseTransport):
        """
        Full Pipecat BaseTransport implementation using rtp_sip.

        Example:
            from rtp_sip.pipecat_transport import PipecatRtpTransport
            from pipecat.pipeline import Pipeline

            transport = PipecatRtpTransport(
                remote_ip="10.0.0.1",
                remote_port=20000,
            )

            pipeline = Pipeline([
                transport.input(),
                deepgram_stt,
                openai_llm,
                elevenlabs_tts,
                transport.output(),
            ])

            await pipeline.run()
        """

        def __init__(
            self,
            remote_ip: str,
            remote_port: int,
            local_port: int = 0,
            **kwargs
        ):
            super().__init__(**kwargs)
            self._rtp = RtpTransport(
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=local_port,
            )
            self._recv_task: Optional[asyncio.Task] = None

        async def start(self, frame_processor) -> None:
            """Start transport and begin receiving audio."""
            await self._rtp.start()
            self._recv_task = asyncio.create_task(self._recv_loop())

        async def stop(self) -> None:
            """Stop transport."""
            if self._recv_task:
                self._recv_task.cancel()
                try:
                    await self._recv_task
                except asyncio.CancelledError:
                    pass
            await self._rtp.stop()

        async def _recv_loop(self) -> None:
            """Receive audio and push to pipeline."""
            while self._rtp.is_running:
                frame = await self._rtp.recv_audio(100)
                if frame:
                    pipecat_frame = AudioRawFrame(
                        audio=frame.samples,
                        sample_rate=frame.sample_rate,
                        num_channels=frame.channels,
                    )
                    await self.push_frame(pipecat_frame)

        async def write_frame(self, frame: Frame) -> None:
            """Send audio frame to remote."""
            if isinstance(frame, AudioRawFrame):
                audio_frame = AudioFrame(frame.audio, frame.sample_rate)
                await self._rtp.send_audio(audio_frame)

        @property
        def local_port(self) -> int:
            return self._rtp.local_port

except ImportError:
    # Pipecat not installed - PipecatRtpTransport not available
    PipecatRtpTransport = None


__all__ = [
    "RtpParams",
    "RtpTransport",
    "SipTrunkParams",
    "SipTransport",
    "audio_frame_to_pipecat",
    "pipecat_to_audio_frame",
    "PipecatRtpTransport",
]
