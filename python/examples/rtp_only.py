#!/usr/bin/env python3
"""
RTP-Only Mode Example (Mode 3)

This example demonstrates using pyswitch for RTP-only audio transport.
In this mode, SIP signaling is handled externally (e.g., via WebSocket),
and pyswitch only handles the RTP audio stream.

Use case:
- External SIP proxy handles call setup
- Passes RTP parameters to Python via WebSocket
- pyswitch handles audio send/receive

Audio format:
- Input from RTP: G.711 u-law @ 8kHz
- Converted to: L16 PCM @ 16kHz mono (for STT)
- Output to RTP: L16 @ 16kHz -> G.711 @ 8kHz

Requirements:
- pyswitch built with FreeSWITCH libraries
- Network connectivity between endpoints
"""

import asyncio
import logging
from pyswitch import RtpSession, RtpConfig, AudioFrame, Codec

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def echo_server(local_port: int, remote_ip: str, remote_port: int):
    """Simple echo server - receives audio and echoes it back.

    Args:
        local_port: Port to listen on
        remote_ip: Remote IP to send to
        remote_port: Remote port to send to
    """
    # Create RTP configuration
    config = RtpConfig("0.0.0.0", local_port, remote_ip, remote_port)

    # Create session
    session = RtpSession(config)

    logger.info(f"Starting RTP session on port {local_port}")
    logger.info(f"Sending to {remote_ip}:{remote_port}")

    try:
        # Start the session
        await session.start()
        logger.info("RTP session started")

        # Echo loop
        while True:
            # Receive audio frame (100ms timeout)
            frame = await session.recv_audio(100)

            if frame:
                logger.debug(
                    f"Received frame: {frame.num_samples()} samples, "
                    f"{frame.duration_ms}ms"
                )

                # Echo it back
                await session.send_audio(frame)

                # Log stats periodically
                stats = session.stats
                if stats.packets_received % 100 == 0:
                    logger.info(
                        f"Stats: sent={stats.packets_sent}, "
                        f"received={stats.packets_received}"
                    )
            else:
                # Timeout - no audio received
                pass

    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        await session.stop()
        logger.info("RTP session stopped")


async def stt_pipeline(local_port: int, remote_ip: str, remote_port: int):
    """Example with STT processing.

    This demonstrates the typical voice AI pipeline:
    1. Receive audio from RTP
    2. Process with STT (placeholder)
    3. Generate TTS response (placeholder)
    4. Send back via RTP
    """
    config = RtpConfig("0.0.0.0", local_port, remote_ip, remote_port)
    session = RtpSession(config)

    try:
        await session.start()
        logger.info("STT pipeline started")

        audio_buffer = bytearray()

        while True:
            frame = await session.recv_audio(100)

            if frame:
                # Accumulate audio
                audio_buffer.extend(frame.samples)

                # Process when we have enough audio (e.g., 500ms)
                # 16kHz * 0.5s * 2 bytes = 16000 bytes
                if len(audio_buffer) >= 16000:
                    logger.info(f"Processing {len(audio_buffer)} bytes of audio")

                    # TODO: Send to STT service
                    # transcript = await stt_service.transcribe(audio_buffer)

                    # TODO: Process with LLM
                    # response = await llm.generate(transcript)

                    # TODO: Generate TTS audio
                    # tts_audio = await tts_service.synthesize(response)

                    # TODO: Send TTS audio back
                    # for chunk in chunks(tts_audio, 640):  # 20ms frames
                    #     frame = AudioFrame(chunk, 16000)
                    #     await session.send_audio(frame)

                    # Clear buffer
                    audio_buffer.clear()

    except KeyboardInterrupt:
        pass
    finally:
        await session.stop()


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="pyswitch RTP-only example")
    parser.add_argument(
        "--mode",
        choices=["echo", "stt"],
        default="echo",
        help="Mode: echo (default) or stt",
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=5004,
        help="Local RTP port (default: 5004)",
    )
    parser.add_argument(
        "--remote-ip",
        default="127.0.0.1",
        help="Remote IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--remote-port",
        type=int,
        default=5006,
        help="Remote RTP port (default: 5006)",
    )

    args = parser.parse_args()

    if args.mode == "echo":
        await echo_server(args.local_port, args.remote_ip, args.remote_port)
    else:
        await stt_pipeline(args.local_port, args.remote_ip, args.remote_port)


if __name__ == "__main__":
    asyncio.run(main())
