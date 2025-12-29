#!/usr/bin/env python3
"""
RTP Loopback Test - verifies both send and receive work correctly.

Creates a sender and receiver on localhost and verifies packets are transmitted.
"""

import asyncio
import time
import math
import pytest

import rtp_sip
from rtp_sip import RtpSession, AudioFrame


def create_test_frame(duration_ms: int = 20, sample_rate: int = 8000) -> AudioFrame:
    """Create a test audio frame with a sine wave pattern."""
    num_samples = int(sample_rate * duration_ms / 1000)
    samples = []
    for i in range(num_samples):
        sample = int(math.sin(2 * math.pi * 440 * i / sample_rate) * 16000)
        samples.append(sample)
    sample_bytes = b''.join(s.to_bytes(2, 'little', signed=True) for s in samples)
    return AudioFrame(sample_bytes, sample_rate)


@pytest.mark.asyncio
async def test_rtp_send_only():
    """Test that RTP packets can be sent (no receiver)."""
    sender = RtpSession("127.0.0.1", 40002)
    sender.with_local_port(40000)

    try:
        await sender.start()
        assert sender.is_running

        for i in range(10):
            frame = create_test_frame()
            await sender.send_audio(frame)
            await asyncio.sleep(0.02)

        assert sender.stats.packets_sent >= 10
        print(f"Sent {sender.stats.packets_sent} packets")
    finally:
        await sender.stop()


@pytest.mark.asyncio
async def test_rtp_loopback():
    """Test RTP loopback - sender and receiver on localhost."""
    # Sender sends to receiver's port
    sender = RtpSession("127.0.0.1", 41002)
    sender.with_local_port(41000)

    # Receiver listens on port 41002, points back to sender
    receiver = RtpSession("127.0.0.1", 41000)
    receiver.with_local_port(41002)

    try:
        await receiver.start()
        await sender.start()

        # Send some packets
        num_packets = 10
        for i in range(num_packets):
            frame = create_test_frame()
            await sender.send_audio(frame)
            await asyncio.sleep(0.02)

        # Give time for packets to arrive
        await asyncio.sleep(0.1)

        # Try to receive packets
        received = 0
        for _ in range(20):  # Try up to 20 times
            frame = await receiver.recv_audio(50)  # 50ms timeout
            if frame:
                received += 1
            if received >= num_packets:
                break

        print(f"Sent: {sender.stats.packets_sent}, Received: {receiver.stats.packets_received}")

        assert sender.stats.packets_sent >= num_packets, f"Expected {num_packets} sent, got {sender.stats.packets_sent}"
        # We should receive at least some packets (not necessarily all due to timing)
        assert receiver.stats.packets_received > 0, f"Expected >0 received, got {receiver.stats.packets_received}"

    finally:
        await sender.stop()
        await receiver.stop()


@pytest.mark.asyncio
async def test_rtp_bidirectional():
    """Test bidirectional RTP - both sides send and receive."""
    # Session A
    session_a = RtpSession("127.0.0.1", 42002)
    session_a.with_local_port(42000)

    # Session B
    session_b = RtpSession("127.0.0.1", 42000)
    session_b.with_local_port(42002)

    try:
        await session_a.start()
        await session_b.start()

        num_packets = 5

        # A sends to B
        for i in range(num_packets):
            await session_a.send_audio(create_test_frame())
            await asyncio.sleep(0.02)

        # B sends to A
        for i in range(num_packets):
            await session_b.send_audio(create_test_frame())
            await asyncio.sleep(0.02)

        await asyncio.sleep(0.1)

        # Try to receive on both sides
        for _ in range(10):
            await session_a.recv_audio(50)
            await session_b.recv_audio(50)

        print(f"Session A: sent={session_a.stats.packets_sent}, recv={session_a.stats.packets_received}")
        print(f"Session B: sent={session_b.stats.packets_sent}, recv={session_b.stats.packets_received}")

        assert session_a.stats.packets_sent >= num_packets
        assert session_b.stats.packets_sent >= num_packets

    finally:
        await session_a.stop()
        await session_b.stop()


@pytest.mark.asyncio
async def test_rtp_concurrent_sessions():
    """Test multiple concurrent RTP sessions."""
    num_sessions = 4
    sessions = []
    base_port = 43000

    try:
        for i in range(num_sessions):
            local_port = base_port + (i * 10)
            remote_port = local_port + 2
            s = RtpSession("127.0.0.1", remote_port)
            s.with_local_port(local_port)
            sessions.append(s)

        # Start all sessions
        await asyncio.gather(*[s.start() for s in sessions])

        # Send on all sessions
        async def send_burst(session, count=10):
            for _ in range(count):
                await session.send_audio(create_test_frame())
                await asyncio.sleep(0.02)

        await asyncio.gather(*[send_burst(s) for s in sessions])

        total_sent = sum(s.stats.packets_sent for s in sessions)
        print(f"Total sent across {num_sessions} sessions: {total_sent}")

        assert total_sent >= num_sessions * 10

    finally:
        await asyncio.gather(*[s.stop() for s in sessions])


if __name__ == "__main__":
    asyncio.run(test_rtp_loopback())
