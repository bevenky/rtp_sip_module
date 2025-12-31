"""
Plivo Serializer with RTP Mode Support for Pipecat

Extends Plivo's WebSocket-based transport to support rtpsip's RtpSession
for media handling (Mode B - RTP only, signaling via WebSocket).

Two audio modes:
- "websocket" (default): Audio via Plivo's WebSocket (base64 encoded)
- "rtp": Audio via rtpsip's RtpSession (direct RTP/UDP)

RTP mode advantages:
- Lower latency (direct UDP vs WebSocket)
- Better jitter handling (adaptive jitter buffer)
- Standard RTP compliance (RFC 3550)

Example:
    from pipecat.pipeline.pipeline import Pipeline
    from rtpsip.pipecat.plivo_serializer import PlivoRtpTransport

    # RTP mode - audio via direct RTP
    transport = PlivoRtpTransport(
        websocket=websocket,
        audio_mode="rtp",
        rtp_local_ip="0.0.0.0",
        rtp_local_port=0,  # Dynamic port allocation
    )

    # After WebSocket signaling provides remote RTP info:
    transport.set_rtp_remote(remote_ip, remote_port)

    pipeline = Pipeline([
        transport.input(),
        stt,
        llm,
        tts,
        transport.output(),
    ])
"""

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any, Union
from enum import Enum

try:
    from pipecat.frames.frames import (
        Frame,
        AudioRawFrame,
        StartFrame,
        EndFrame,
        CancelFrame,
        TextFrame,
    )
    from pipecat.processors.frame_processor import FrameDirection, FrameProcessor
    from pipecat.transports.base_input import BaseInputTransport
    from pipecat.transports.base_output import BaseOutputTransport
    from pipecat.transports.base_transport import BaseTransport, TransportParams
    from pipecat.serializers.base_serializer import FrameSerializer

    PIPECAT_AVAILABLE = True
except ImportError:
    PIPECAT_AVAILABLE = False
    Frame = object
    FrameProcessor = object
    BaseInputTransport = object
    BaseOutputTransport = object
    BaseTransport = object
    FrameSerializer = object

from rtpsip import RtpSession
from rtpsip.config import RtpSessionConfig

logger = logging.getLogger(__name__)

# Audio constants (Plivo uses 8kHz PCMU/PCMA)
SAMPLE_RATE = 8000
FRAME_SIZE_MS = 20
SAMPLES_PER_FRAME = int(SAMPLE_RATE * FRAME_SIZE_MS / 1000)  # 160


class AudioMode(Enum):
    """Audio transport mode"""

    WEBSOCKET = "websocket"  # Audio via WebSocket (base64)
    RTP = "rtp"  # Audio via direct RTP/UDP


@dataclass
class PlivoTransportParams:
    """Configuration for Plivo transport"""

    # Audio mode
    audio_mode: str = "websocket"  # "websocket" or "rtp"

    # RTP settings (only used if audio_mode="rtp")
    rtp_local_ip: str = "0.0.0.0"
    rtp_local_port: int = 0  # 0 = dynamic allocation
    rtp_codec: str = "PCMU"

    # Audio settings
    audio_sample_rate: int = SAMPLE_RATE
    audio_frame_size_ms: int = FRAME_SIZE_MS

    # Plivo-specific settings
    stream_id: Optional[str] = None
    call_uuid: Optional[str] = None


@dataclass
class PlivoEventFrame(Frame if PIPECAT_AVAILABLE else object):
    """Plivo WebSocket event frame"""

    event_type: str  # start, media, dtmf, stop
    stream_id: Optional[str] = None
    call_uuid: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


@dataclass
class DtmfFrame(Frame if PIPECAT_AVAILABLE else object):
    """DTMF digit frame"""

    digit: str
    duration_ms: int = 250


class PlivoFrameSerializer(FrameSerializer if PIPECAT_AVAILABLE else object):
    """
    Plivo WebSocket frame serializer.

    Handles Plivo's WebSocket protocol:
    - Incoming: JSON messages with base64 audio or events
    - Outgoing: JSON messages with base64 audio

    Use with audio_mode="websocket" for standard Plivo audio handling.
    """

    def __init__(self, stream_id: Optional[str] = None):
        self._stream_id = stream_id

    def serialize(self, frame: Frame) -> bytes:
        """Serialize frame to Plivo WebSocket format"""
        if PIPECAT_AVAILABLE and isinstance(frame, AudioRawFrame):
            # Encode audio as base64
            audio_b64 = base64.b64encode(frame.audio).decode("utf-8")
            msg = {
                "event": "media",
                "streamId": self._stream_id,
                "media": {"payload": audio_b64},
            }
            return json.dumps(msg).encode("utf-8")
        return b""

    def deserialize(self, data: bytes) -> Optional[Frame]:
        """Deserialize Plivo WebSocket message to frame"""
        try:
            msg = json.loads(data.decode("utf-8"))
            event = msg.get("event", "")

            if event == "media":
                # Decode base64 audio
                payload = msg.get("media", {}).get("payload", "")
                if payload:
                    audio_bytes = base64.b64decode(payload)
                    if PIPECAT_AVAILABLE:
                        return AudioRawFrame(
                            audio=audio_bytes,
                            sample_rate=SAMPLE_RATE,
                            num_channels=1,
                        )

            elif event == "start":
                return PlivoEventFrame(
                    event_type="start",
                    stream_id=msg.get("streamId"),
                    call_uuid=msg.get("start", {}).get("callUUID"),
                    data=msg.get("start"),
                )

            elif event == "dtmf":
                digit = msg.get("dtmf", {}).get("digit", "")
                if digit:
                    return DtmfFrame(digit=digit)

            elif event == "stop":
                return PlivoEventFrame(
                    event_type="stop",
                    stream_id=msg.get("streamId"),
                    data=msg.get("stop"),
                )

        except Exception as e:
            logger.error(f"Error deserializing Plivo message: {e}")

        return None


class PlivoInputTransport(BaseInputTransport if PIPECAT_AVAILABLE else object):
    """
    Plivo input transport with RTP mode support.

    Receives audio from either:
    - WebSocket (audio_mode="websocket")
    - RTP session (audio_mode="rtp")
    """

    def __init__(
        self,
        params: PlivoTransportParams,
        websocket: Any,
        rtp_session: Optional[RtpSession] = None,
    ):
        if PIPECAT_AVAILABLE:
            super().__init__(TransportParams(audio_in_enabled=True))

        self._params = params
        self._websocket = websocket
        self._rtp_session = rtp_session
        self._running = False
        self._receive_task: Optional[asyncio.Task] = None
        self._serializer = PlivoFrameSerializer(params.stream_id)

    @property
    def rtp_local_addr(self) -> Optional[str]:
        """Get RTP local address (for signaling exchange)"""
        if self._rtp_session:
            return self._rtp_session.local_addr
        return None

    @property
    def rtp_local_port(self) -> Optional[int]:
        """Get RTP local port"""
        if self._rtp_session:
            addr = self._rtp_session.local_addr
            if addr:
                return int(addr.split(":")[1])
        return None

    def set_rtp_remote(self, ip: str, port: int):
        """Set RTP remote endpoint after signaling exchange"""
        if self._rtp_session:
            self._rtp_session.set_remote(f"{ip}:{port}")
            logger.info(f"RTP remote set to {ip}:{port}")

    async def start(self, frame: StartFrame = None):
        if PIPECAT_AVAILABLE and frame:
            await super().start(frame)
        self._running = True

        # Start appropriate receive task based on mode
        if self._params.audio_mode == "rtp" and self._rtp_session:
            self._receive_task = asyncio.create_task(self._receive_rtp())
        else:
            self._receive_task = asyncio.create_task(self._receive_websocket())

        logger.info(f"Plivo input started (mode: {self._params.audio_mode})")

    async def stop(self, frame: EndFrame = None):
        self._running = False

        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        if PIPECAT_AVAILABLE and frame:
            await super().stop(frame)
        logger.info("Plivo input stopped")

    async def _receive_websocket(self):
        """Receive audio from WebSocket"""
        while self._running:
            try:
                data = await self._websocket.recv()
                if isinstance(data, str):
                    data = data.encode("utf-8")

                frame = self._serializer.deserialize(data)

                if frame:
                    if isinstance(frame, PlivoEventFrame):
                        # Handle start event - extract stream info
                        if frame.event_type == "start":
                            self._params.stream_id = frame.stream_id
                            self._params.call_uuid = frame.call_uuid
                            self._serializer._stream_id = frame.stream_id

                    if PIPECAT_AVAILABLE:
                        await self.push_frame(frame)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error receiving from WebSocket: {e}")
                await asyncio.sleep(0.01)

    async def _receive_rtp(self):
        """Receive audio from RTP session"""
        while self._running:
            try:
                loop = asyncio.get_event_loop()
                samples = await loop.run_in_executor(
                    None, lambda: self._rtp_session.recv_audio(100)
                )

                if samples and PIPECAT_AVAILABLE:
                    # Convert samples to bytes (L16 PCM)
                    audio_bytes = b"".join(
                        s.to_bytes(2, byteorder="little", signed=True) for s in samples
                    )
                    frame = AudioRawFrame(
                        audio=audio_bytes,
                        sample_rate=self._params.audio_sample_rate,
                        num_channels=1,
                    )
                    await self.push_frame(frame)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error receiving from RTP: {e}")
                await asyncio.sleep(0.01)


class PlivoOutputTransport(BaseOutputTransport if PIPECAT_AVAILABLE else object):
    """
    Plivo output transport with RTP mode support.

    Sends audio via either:
    - WebSocket (audio_mode="websocket")
    - RTP session (audio_mode="rtp")
    """

    def __init__(
        self,
        params: PlivoTransportParams,
        websocket: Any,
        rtp_session: Optional[RtpSession] = None,
    ):
        if PIPECAT_AVAILABLE:
            super().__init__(TransportParams(audio_out_enabled=True))

        self._params = params
        self._websocket = websocket
        self._rtp_session = rtp_session
        self._running = False
        self._serializer = PlivoFrameSerializer(params.stream_id)

    def set_rtp_remote(self, ip: str, port: int):
        """Set RTP remote endpoint"""
        if self._rtp_session:
            self._rtp_session.set_remote(f"{ip}:{port}")

    async def start(self, frame: StartFrame = None):
        if PIPECAT_AVAILABLE and frame:
            await super().start(frame)
        self._running = True
        logger.info(f"Plivo output started (mode: {self._params.audio_mode})")

    async def stop(self, frame: EndFrame = None):
        self._running = False
        if PIPECAT_AVAILABLE and frame:
            await super().stop(frame)
        logger.info("Plivo output stopped")

    async def process_frame(self, frame: Frame, direction: FrameDirection = None):
        if PIPECAT_AVAILABLE and direction:
            await super().process_frame(frame, direction)

        if not self._running:
            return

        if PIPECAT_AVAILABLE and isinstance(frame, AudioRawFrame):
            await self._send_audio(frame)

    async def _send_audio(self, frame):
        """Send audio via appropriate transport"""
        if self._params.audio_mode == "rtp" and self._rtp_session:
            await self._send_rtp(frame)
        else:
            await self._send_websocket(frame)

    async def _send_websocket(self, frame):
        """Send audio via WebSocket"""
        try:
            data = self._serializer.serialize(frame)
            if data:
                await self._websocket.send(data)
        except Exception as e:
            logger.error(f"Error sending to WebSocket: {e}")

    async def _send_rtp(self, frame):
        """Send audio via RTP"""
        try:
            # Convert bytes to samples
            samples = []
            for i in range(0, len(frame.audio), 2):
                sample = int.from_bytes(
                    frame.audio[i : i + 2], byteorder="little", signed=True
                )
                samples.append(sample)

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: self._rtp_session.send_audio(samples)
            )
        except Exception as e:
            logger.error(f"Error sending to RTP: {e}")

    async def send_dtmf(self, digit: str, duration_ms: int = 250):
        """Send DTMF via WebSocket (signaling)"""
        try:
            msg = {
                "event": "dtmf",
                "streamId": self._params.stream_id,
                "dtmf": {"digit": digit, "duration": duration_ms},
            }
            await self._websocket.send(json.dumps(msg))
        except Exception as e:
            logger.error(f"Error sending DTMF: {e}")


class PlivoRtpTransport(BaseTransport if PIPECAT_AVAILABLE else object):
    """
    Plivo Transport with RTP mode support for Pipecat.

    Combines Plivo's WebSocket signaling with rtpsip's RTP for media.

    Modes:
    - audio_mode="websocket": Standard Plivo (audio via WebSocket)
    - audio_mode="rtp": Audio via direct RTP/UDP (lower latency)

    Example - WebSocket mode (standard Plivo):
        transport = PlivoRtpTransport(
            websocket=websocket,
            audio_mode="websocket",
        )

    Example - RTP mode (lower latency):
        transport = PlivoRtpTransport(
            websocket=websocket,
            audio_mode="rtp",
            rtp_local_ip="0.0.0.0",
            rtp_local_port=0,  # Dynamic
        )

        await transport.start()

        # Get local RTP port for signaling
        local_port = transport.rtp_local_port

        # Send local RTP info to Plivo via WebSocket
        await websocket.send(json.dumps({
            "event": "rtp_info",
            "rtp": {"ip": local_ip, "port": local_port}
        }))

        # When Plivo sends remote RTP info:
        transport.set_rtp_remote(remote_ip, remote_port)

        # Pipeline setup
        pipeline = Pipeline([
            transport.input(),
            stt,
            llm,
            tts,
            transport.output(),
        ])
    """

    def __init__(
        self,
        websocket: Any,
        audio_mode: str = "websocket",
        rtp_local_ip: str = "0.0.0.0",
        rtp_local_port: int = 0,
        rtp_codec: str = "PCMU",
        params: Optional[PlivoTransportParams] = None,
        **kwargs,
    ):
        self._websocket = websocket

        if params:
            self._params = params
        else:
            self._params = PlivoTransportParams(
                audio_mode=audio_mode,
                rtp_local_ip=rtp_local_ip,
                rtp_local_port=rtp_local_port,
                rtp_codec=rtp_codec,
                **kwargs,
            )

        self._rtp_session: Optional[RtpSession] = None
        self._input: Optional[PlivoInputTransport] = None
        self._output: Optional[PlivoOutputTransport] = None

    @property
    def rtp_local_addr(self) -> Optional[str]:
        """Get RTP local address"""
        if self._rtp_session:
            return self._rtp_session.local_addr
        return None

    @property
    def rtp_local_port(self) -> Optional[int]:
        """Get RTP local port"""
        if self._rtp_session:
            addr = self._rtp_session.local_addr
            if addr:
                return int(addr.split(":")[1])
        return None

    def set_rtp_remote(self, ip: str, port: int):
        """Set RTP remote endpoint"""
        if self._input:
            self._input.set_rtp_remote(ip, port)
        if self._output:
            self._output.set_rtp_remote(ip, port)

    async def start(self):
        """Start transport"""
        # Create RTP session if in RTP mode
        if self._params.audio_mode == "rtp":
            config = RtpSessionConfig(
                local_ip=self._params.rtp_local_ip,
                local_port=self._params.rtp_local_port,
                codec=self._params.rtp_codec,
            )
            self._rtp_session = RtpSession(**config.to_dict())
            self._rtp_session.start()
            logger.info(f"RTP session started on {self._rtp_session.local_addr}")

        # Create input/output transports
        self._input = PlivoInputTransport(
            self._params, self._websocket, self._rtp_session
        )
        self._output = PlivoOutputTransport(
            self._params, self._websocket, self._rtp_session
        )

        logger.info(f"Plivo transport started (mode: {self._params.audio_mode})")

    async def stop(self):
        """Stop transport"""
        if self._rtp_session:
            self._rtp_session.stop()
            self._rtp_session = None

        logger.info("Plivo transport stopped")

    def input(self) -> PlivoInputTransport:
        """Get input transport for pipeline"""
        if not self._input:
            raise RuntimeError("Transport not started")
        return self._input

    def output(self) -> PlivoOutputTransport:
        """Get output transport for pipeline"""
        if not self._output:
            raise RuntimeError("Transport not started")
        return self._output

    async def send_dtmf(self, digit: str, duration_ms: int = 250):
        """Send DTMF via WebSocket signaling"""
        if self._output:
            await self._output.send_dtmf(digit, duration_ms)

    def get_stats(self):
        """Get RTP jitter buffer stats (RTP mode only)"""
        if self._rtp_session:
            return self._rtp_session.get_stats()
        return None


# Convenience aliases
PlivoTransport = PlivoRtpTransport
PlivoInputTransport = PlivoInputTransport
PlivoOutputTransport = PlivoOutputTransport
