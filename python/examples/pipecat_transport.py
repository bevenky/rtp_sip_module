#!/usr/bin/env python3
"""
Pipecat Transport Integration Example

This example shows how pyswitch can be used as a transport layer
for Pipecat voice AI pipelines.

The pattern:
1. WebSocket connection receives SIP/RTP parameters
2. pyswitch RtpSession handles audio transport
3. Audio flows through Pipecat pipeline

Note: This is a conceptual example. Actual Pipecat integration
requires implementing the Pipecat transport interface.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, AsyncIterator, Any

from pyswitch import RtpSession, RtpConfig, AudioFrame

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RtpParams:
    """RTP parameters received from SIP signaling (via WebSocket)."""

    local_port: int
    remote_ip: str
    remote_port: int
    codec: str = "PCMU"
    sample_rate: int = 8000


class PyswitchTransport:
    """
    Pipecat-compatible transport using pyswitch RTP.

    This class bridges pyswitch's RtpSession with Pipecat's
    transport abstraction.
    """

    def __init__(self, rtp_params: RtpParams):
        self.params = rtp_params
        self.session: Optional[RtpSession] = None
        self._running = False

    async def start(self):
        """Start the transport."""
        config = RtpConfig(
            "0.0.0.0",
            self.params.local_port,
            self.params.remote_ip,
            self.params.remote_port,
        )
        self.session = RtpSession(config)
        await self.session.start()
        self._running = True
        logger.info("PyswitchTransport started")

    async def stop(self):
        """Stop the transport."""
        self._running = False
        if self.session:
            await self.session.stop()
        logger.info("PyswitchTransport stopped")

    async def recv_audio(self) -> AsyncIterator[AudioFrame]:
        """Receive audio frames from remote.

        Yields L16 PCM frames at 16kHz mono.
        """
        while self._running and self.session:
            frame = await self.session.recv_audio(100)
            if frame:
                yield frame

    async def send_audio(self, frame: AudioFrame):
        """Send audio frame to remote.

        Args:
            frame: L16 PCM frame at 16kHz mono
        """
        if self.session:
            await self.session.send_audio(frame)


class MockPipecatPipeline:
    """
    Mock Pipecat pipeline for demonstration.

    In a real implementation, this would be replaced with
    the actual Pipecat pipeline components.
    """

    def __init__(self, transport: PyswitchTransport):
        self.transport = transport

    async def run(self):
        """Run the pipeline."""
        logger.info("Pipeline started")

        try:
            async for frame in self.transport.recv_audio():
                # In a real pipeline:
                # 1. Send to VAD (Voice Activity Detection)
                # 2. Send to STT (Speech-to-Text)
                # 3. Process with LLM
                # 4. Generate TTS response
                # 5. Send back via transport

                # For demo, just log
                logger.debug(
                    f"Received: {frame.num_samples()} samples, "
                    f"{frame.duration_ms}ms"
                )

                # Echo back (placeholder for TTS output)
                await self.transport.send_audio(frame)

        except Exception as e:
            logger.error(f"Pipeline error: {e}")


async def handle_websocket_connection(ws_message: dict):
    """
    Handle incoming WebSocket message with RTP parameters.

    In a real implementation, this would be called when a WebSocket
    message arrives with RTP negotiation results from SIP signaling.

    Args:
        ws_message: Message from WebSocket with RTP params
    """
    # Parse RTP parameters from WebSocket message
    # (In real usage, this comes from mod_audio_stream_rust or similar)
    params = RtpParams(
        local_port=ws_message.get("local_port", 5004),
        remote_ip=ws_message.get("remote_ip", "127.0.0.1"),
        remote_port=ws_message.get("remote_port", 5006),
        codec=ws_message.get("codec", "PCMU"),
    )

    # Create transport
    transport = PyswitchTransport(params)

    # Create pipeline
    pipeline = MockPipecatPipeline(transport)

    try:
        await transport.start()
        await pipeline.run()
    finally:
        await transport.stop()


async def main():
    """Main entry point - simulates WebSocket message arrival."""
    # Simulate receiving RTP params from WebSocket
    ws_message = {
        "local_port": 5004,
        "remote_ip": "127.0.0.1",
        "remote_port": 5006,
        "codec": "PCMU",
    }

    logger.info("Simulating WebSocket connection with RTP params")
    await handle_websocket_connection(ws_message)


if __name__ == "__main__":
    asyncio.run(main())
