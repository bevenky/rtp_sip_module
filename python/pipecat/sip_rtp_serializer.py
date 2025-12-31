"""
SIP RTP Serializer for Pipecat

A generic SIP trunking serializer that works with any SIP provider:
- Twilio SIP Trunking
- Telnyx
- Plivo SIP
- Bandwidth
- Vonage
- Any standards-compliant SIP trunk

Uses siprunner's SipRunner (Mode A) for full SIP signaling + RTP media.

Audio format: L16 PCM i16 samples at 8kHz mono (160 samples = 20ms frame)

Example:
    from pipecat.pipeline.pipeline import Pipeline
    from pipecat.transports.base_transport import TransportParams
    from siprunner.pipecat.sip_rtp_serializer import SipRtpTransport

    # Single provider setup
    transport = SipRtpTransport(
        provider_name="twilio",
        server="sip.twilio.com",
        username="ACCOUNT_SID",
        password="AUTH_TOKEN",
    )

    # Or multi-provider from config
    transport = SipRtpTransport(config_path="config.toml")

    pipeline = Pipeline([
        transport.input(),
        stt_processor,
        llm_processor,
        tts_processor,
        transport.output(),
    ])
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any

try:
    from pipecat.frames.frames import (
        Frame,
        AudioRawFrame,
        StartFrame,
        EndFrame,
        CancelFrame,
    )
    from pipecat.processors.frame_processor import FrameDirection, FrameProcessor
    from pipecat.transports.base_input import BaseInputTransport
    from pipecat.transports.base_output import BaseOutputTransport
    from pipecat.transports.base_transport import BaseTransport, TransportParams

    PIPECAT_AVAILABLE = True
except ImportError:
    PIPECAT_AVAILABLE = False
    # Stub classes for standalone usage
    Frame = object
    FrameProcessor = object
    BaseInputTransport = object
    BaseOutputTransport = object
    BaseTransport = object

from siprunner import SipRunner, CallEvent, CallState, DtmfMode

logger = logging.getLogger(__name__)

# Audio constants
SAMPLE_RATE = 8000
FRAME_SIZE_MS = 20
SAMPLES_PER_FRAME = int(SAMPLE_RATE * FRAME_SIZE_MS / 1000)  # 160


@dataclass
class SipTransportParams:
    """Configuration for SIP transport"""

    # Provider settings (for single provider mode)
    provider_name: str = ""
    server: str = ""
    username: str = ""
    password: str = ""
    port: int = 5060

    # Or use config file (for multi-provider)
    config_path: Optional[str] = None

    # Local SIP settings
    local_ip: str = "0.0.0.0"
    local_port: int = 5060
    transport: str = "udp"  # udp or tls

    # TLS settings (if transport="tls")
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None

    # Audio settings
    audio_sample_rate: int = SAMPLE_RATE
    audio_frame_size_ms: int = FRAME_SIZE_MS

    # Call settings
    auto_answer_inbound: bool = False
    dtmf_mode: Optional[str] = None  # "auto", "rfc2833", "info"


@dataclass
class DtmfFrame(Frame if PIPECAT_AVAILABLE else object):
    """DTMF digit frame"""

    digit: str
    duration_ms: int = 250
    call_id: Optional[str] = None


@dataclass
class CallEventFrame(Frame if PIPECAT_AVAILABLE else object):
    """SIP call event frame"""

    event_type: str  # incoming, ringing, early_media, answered, dtmf, hangup
    call_id: str
    from_uri: Optional[str] = None
    to_uri: Optional[str] = None
    digit: Optional[str] = None
    reason: Optional[str] = None


class SipInputTransport(BaseInputTransport if PIPECAT_AVAILABLE else object):
    """
    SIP input transport - receives audio and call events.

    Emits:
    - AudioRawFrame: Incoming audio (L16 PCM)
    - CallEventFrame: Call state changes, DTMF, etc.
    """

    def __init__(self, params: SipTransportParams, runner: SipRunner):
        if PIPECAT_AVAILABLE:
            super().__init__(TransportParams(audio_in_enabled=True))
        self._params = params
        self._runner = runner
        self._running = False
        self._active_calls: Dict[str, bool] = {}
        self._receive_task: Optional[asyncio.Task] = None
        self._event_task: Optional[asyncio.Task] = None

    async def start(self, frame: StartFrame):
        if PIPECAT_AVAILABLE:
            await super().start(frame)
        self._running = True

        # Start event processing task
        self._event_task = asyncio.create_task(self._process_events())
        logger.info("SIP input transport started")

    async def stop(self, frame: EndFrame):
        self._running = False

        if self._event_task:
            self._event_task.cancel()
            try:
                await self._event_task
            except asyncio.CancelledError:
                pass

        if PIPECAT_AVAILABLE:
            await super().stop(frame)
        logger.info("SIP input transport stopped")

    async def _process_events(self):
        """Process SIP events and emit frames"""
        while self._running:
            try:
                loop = asyncio.get_event_loop()
                event = await loop.run_in_executor(
                    None, lambda: self._runner.next_event(100)
                )

                if event:
                    await self._handle_event(event)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing SIP event: {e}")
                await asyncio.sleep(0.1)

    async def _handle_event(self, event: CallEvent):
        """Handle SIP call event"""
        frame = None

        if event.is_incoming():
            frame = CallEventFrame(
                event_type="incoming",
                call_id=event.call_id,
                from_uri=event.from_uri,
                to_uri=event.to_uri,
            )
            if self._params.auto_answer_inbound:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None, lambda: self._runner.answer(event.call_id)
                )

        elif event.is_ringing():
            frame = CallEventFrame(event_type="ringing", call_id=event.call_id)

        elif event.is_early_media():
            frame = CallEventFrame(event_type="early_media", call_id=event.call_id)
            self._active_calls[event.call_id] = True
            # Start receiving audio for this call
            asyncio.create_task(self._receive_audio(event.call_id))

        elif event.is_answered():
            frame = CallEventFrame(event_type="answered", call_id=event.call_id)
            if event.call_id not in self._active_calls:
                self._active_calls[event.call_id] = True
                asyncio.create_task(self._receive_audio(event.call_id))

        elif event.is_dtmf():
            frame = CallEventFrame(
                event_type="dtmf", call_id=event.call_id, digit=event.digit
            )

        elif event.is_hangup():
            frame = CallEventFrame(
                event_type="hangup", call_id=event.call_id, reason=event.reason
            )
            self._active_calls.pop(event.call_id, None)

        if frame and PIPECAT_AVAILABLE:
            await self.push_frame(frame)

    async def _receive_audio(self, call_id: str):
        """Receive audio for a specific call"""
        while self._running and call_id in self._active_calls:
            try:
                loop = asyncio.get_event_loop()
                samples = await loop.run_in_executor(
                    None, lambda: self._runner.recv_audio(call_id, 100)
                )

                if samples and PIPECAT_AVAILABLE:
                    # Convert to bytes (L16 PCM)
                    audio_bytes = b"".join(
                        s.to_bytes(2, byteorder="little", signed=True) for s in samples
                    )
                    frame = AudioRawFrame(
                        audio=audio_bytes,
                        sample_rate=self._params.audio_sample_rate,
                        num_channels=1,
                    )
                    await self.push_frame(frame)

            except Exception as e:
                logger.error(f"Error receiving audio for {call_id}: {e}")
                await asyncio.sleep(0.01)


class SipOutputTransport(BaseOutputTransport if PIPECAT_AVAILABLE else object):
    """
    SIP output transport - sends audio and controls calls.

    Accepts:
    - AudioRawFrame: Outgoing audio (L16 PCM)
    - DtmfFrame: Send DTMF digits
    """

    def __init__(self, params: SipTransportParams, runner: SipRunner):
        if PIPECAT_AVAILABLE:
            super().__init__(TransportParams(audio_out_enabled=True))
        self._params = params
        self._runner = runner
        self._running = False
        self._current_call_id: Optional[str] = None

    async def start(self, frame: StartFrame):
        if PIPECAT_AVAILABLE:
            await super().start(frame)
        self._running = True
        logger.info("SIP output transport started")

    async def stop(self, frame: EndFrame):
        self._running = False
        if PIPECAT_AVAILABLE:
            await super().stop(frame)
        logger.info("SIP output transport stopped")

    def set_call_id(self, call_id: str):
        """Set the active call ID for audio output"""
        self._current_call_id = call_id

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        if PIPECAT_AVAILABLE:
            await super().process_frame(frame, direction)

        if not self._running or not self._current_call_id:
            return

        if PIPECAT_AVAILABLE and isinstance(frame, AudioRawFrame):
            await self._send_audio(frame)
        elif isinstance(frame, DtmfFrame):
            await self._send_dtmf(frame)

    async def _send_audio(self, frame):
        """Send audio frame"""
        if not self._current_call_id:
            return

        # Convert bytes to samples
        samples = []
        for i in range(0, len(frame.audio), 2):
            sample = int.from_bytes(frame.audio[i : i + 2], byteorder="little", signed=True)
            samples.append(sample)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: self._runner.send_audio(self._current_call_id, samples)
        )

    async def _send_dtmf(self, frame: DtmfFrame):
        """Send DTMF digits"""
        call_id = frame.call_id or self._current_call_id
        if not call_id:
            return

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self._runner.send_dtmf(call_id, frame.digit, frame.duration_ms),
        )

    # Call control methods
    async def call(self, to: str, from_: str) -> str:
        """Initiate outbound call"""
        loop = asyncio.get_event_loop()
        call_id = await loop.run_in_executor(
            None, lambda: self._runner.call(to=to, from_=from_)
        )
        self._current_call_id = call_id
        return call_id

    async def answer(self, call_id: str):
        """Answer incoming call"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self._runner.answer(call_id))
        self._current_call_id = call_id

    async def reject(self, call_id: str, status_code: int = 486):
        """Reject incoming call"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: self._runner.reject(call_id, status_code)
        )

    async def hangup(self, call_id: Optional[str] = None):
        """Hang up call"""
        call_id = call_id or self._current_call_id
        if call_id:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self._runner.hangup(call_id))

    async def hold(self, call_id: Optional[str] = None):
        """Put call on hold"""
        call_id = call_id or self._current_call_id
        if call_id:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self._runner.hold(call_id))

    async def unhold(self, call_id: Optional[str] = None):
        """Resume call from hold"""
        call_id = call_id or self._current_call_id
        if call_id:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self._runner.unhold(call_id))

    async def transfer(self, target: str, call_id: Optional[str] = None):
        """Transfer call (REFER)"""
        call_id = call_id or self._current_call_id
        if call_id:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: self._runner.transfer(call_id, target)
            )


class SipRtpTransport(BaseTransport if PIPECAT_AVAILABLE else object):
    """
    SIP RTP Transport for Pipecat.

    Full SIP signaling + RTP media transport for any SIP trunking provider.

    Example:
        # Single provider
        transport = SipRtpTransport(
            provider_name="twilio",
            server="sip.twilio.com",
            username="ACCOUNT_SID",
            password="AUTH_TOKEN",
        )

        # Multi-provider from config
        transport = SipRtpTransport(config_path="config.toml")

        # Use in pipeline
        pipeline = Pipeline([
            transport.input(),
            stt,
            llm,
            tts,
            transport.output(),
        ])

        await transport.start()

        # Make outbound call
        call_id = await transport.call(to="+14155551234", from_="+14155550000")

        # Or handle inbound (auto_answer_inbound=True in params)
    """

    def __init__(
        self,
        provider_name: str = "",
        server: str = "",
        username: str = "",
        password: str = "",
        config_path: Optional[str] = None,
        params: Optional[SipTransportParams] = None,
        **kwargs,
    ):
        if params:
            self._params = params
        else:
            self._params = SipTransportParams(
                provider_name=provider_name,
                server=server,
                username=username,
                password=password,
                config_path=config_path,
                **kwargs,
            )

        self._runner: Optional[SipRunner] = None
        self._input: Optional[SipInputTransport] = None
        self._output: Optional[SipOutputTransport] = None

    async def start(self):
        """Start SIP stack"""
        if self._params.config_path:
            self._runner = SipRunner.from_config(self._params.config_path)
        else:
            self._runner = SipRunner(
                provider_name=self._params.provider_name,
                provider_server=self._params.server,
                username=self._params.username,
                password=self._params.password,
            )

        self._runner.start()

        self._input = SipInputTransport(self._params, self._runner)
        self._output = SipOutputTransport(self._params, self._runner)

        logger.info(f"SIP transport started for {self._params.provider_name}")

    async def stop(self):
        """Stop SIP stack"""
        if self._runner:
            self._runner.stop()
            self._runner = None
        logger.info("SIP transport stopped")

    def input(self) -> SipInputTransport:
        """Get input transport for pipeline"""
        if not self._input:
            raise RuntimeError("Transport not started")
        return self._input

    def output(self) -> SipOutputTransport:
        """Get output transport for pipeline"""
        if not self._output:
            raise RuntimeError("Transport not started")
        return self._output

    # Convenience methods that delegate to output transport
    async def call(self, to: str, from_: str) -> str:
        """Make outbound call"""
        if not self._output:
            raise RuntimeError("Transport not started")
        return await self._output.call(to, from_)

    async def answer(self, call_id: str):
        """Answer incoming call"""
        if self._output:
            await self._output.answer(call_id)

    async def reject(self, call_id: str, status_code: int = 486):
        """Reject incoming call"""
        if self._output:
            await self._output.reject(call_id, status_code)

    async def hangup(self, call_id: Optional[str] = None):
        """Hang up call"""
        if self._output:
            await self._output.hangup(call_id)

    async def hold(self, call_id: Optional[str] = None):
        """Put call on hold"""
        if self._output:
            await self._output.hold(call_id)

    async def unhold(self, call_id: Optional[str] = None):
        """Resume from hold"""
        if self._output:
            await self._output.unhold(call_id)

    async def transfer(self, target: str, call_id: Optional[str] = None):
        """Transfer call"""
        if self._output:
            await self._output.transfer(target, call_id)

    async def send_dtmf(
        self, digits: str, duration_ms: int = 250, call_id: Optional[str] = None
    ):
        """Send DTMF digits"""
        if self._output:
            frame = DtmfFrame(digit=digits, duration_ms=duration_ms, call_id=call_id)
            await self._output._send_dtmf(frame)
