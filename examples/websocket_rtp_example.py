#!/usr/bin/env python3
"""
WebSocket + RTP Integration Example (Mode B)

This example demonstrates using rtpsip's RTP-only mode with external
WebSocket signaling for Voice AI applications.

Architecture:
    Python App <--WebSocket--> Signaling Server <--WebSocket--> Remote Client
    Python App <----RTP-----> Remote Client (direct audio)

Flow:
    1. Connect to signaling server via WebSocket
    2. Receive call notification with remote RTP endpoint
    3. Create RtpSession with dynamic port
    4. Send local RTP endpoint back via WebSocket
    5. Audio flows directly via RTP
    6. DTMF is sent/received via WebSocket (not in RTP stream)
"""

import asyncio
import json
import signal
import sys
from dataclasses import dataclass
from typing import Optional, Callable
from rtpsip import RtpSession, JitterStats

# For real usage, install: pip install websockets
try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    print("Note: Install 'websockets' package for real WebSocket support")
    print("      pip install websockets")


@dataclass
class CallSession:
    """Represents an active call session"""
    call_id: str
    rtp_session: RtpSession
    remote_host: str
    remote_port: int
    local_port: int


class VoiceAIClient:
    """
    Voice AI client using WebSocket signaling and RTP audio.

    This is the pattern for integrating with external signaling servers
    (e.g., Twilio MediaStreams, custom WebSocket servers).
    """

    def __init__(
        self,
        signaling_url: str,
        local_ip: str = "0.0.0.0",
        public_ip: Optional[str] = None,
        on_audio: Optional[Callable[[str, list], None]] = None,
        on_dtmf: Optional[Callable[[str, str], None]] = None,
    ):
        """
        Args:
            signaling_url: WebSocket URL for signaling server
            local_ip: Local IP to bind RTP sockets
            public_ip: Public IP to advertise (if behind NAT)
            on_audio: Callback for received audio (call_id, samples)
            on_dtmf: Callback for received DTMF (call_id, digit)
        """
        self.signaling_url = signaling_url
        self.local_ip = local_ip
        self.public_ip = public_ip or local_ip
        self.on_audio = on_audio
        self.on_dtmf = on_dtmf

        self.sessions: dict[str, CallSession] = {}
        self.ws = None
        self.running = False

    async def connect(self):
        """Connect to signaling server"""
        if not HAS_WEBSOCKETS:
            print("WebSocket library not available, running in demo mode")
            return

        self.ws = await websockets.connect(self.signaling_url)
        self.running = True
        print(f"Connected to signaling server: {self.signaling_url}")

    async def disconnect(self):
        """Disconnect and cleanup all sessions"""
        self.running = False

        # Stop all RTP sessions
        for session in self.sessions.values():
            session.rtp_session.stop()
        self.sessions.clear()

        if self.ws:
            await self.ws.close()
            self.ws = None

    async def handle_incoming_call(self, call_id: str, remote_host: str, remote_port: int) -> CallSession:
        """
        Handle incoming call notification from signaling server.

        This is called when the server tells us about a new call and
        provides the remote RTP endpoint.
        """
        print(f"Incoming call: {call_id}")
        print(f"  Remote RTP: {remote_host}:{remote_port}")

        # Create RTP session with dynamic port
        rtp_session = RtpSession(
            local_addr=f"{self.local_ip}:0",  # Dynamic port allocation
            codec="PCMU",
        )

        # Start session - this allocates the port
        rtp_session.start()

        # Get the allocated port
        local_addr = rtp_session.local_addr
        local_port = int(local_addr.split(":")[1])
        print(f"  Local RTP: {self.public_ip}:{local_port}")

        # Set remote endpoint
        rtp_session.set_remote(f"{remote_host}:{remote_port}")

        # Create session object
        session = CallSession(
            call_id=call_id,
            rtp_session=rtp_session,
            remote_host=remote_host,
            remote_port=remote_port,
            local_port=local_port,
        )
        self.sessions[call_id] = session

        # Send our RTP endpoint back to signaling server
        await self.send_message({
            "type": "rtp_ready",
            "call_id": call_id,
            "rtp_host": self.public_ip,
            "rtp_port": local_port,
        })

        return session

    async def handle_call_ended(self, call_id: str):
        """Handle call ended notification"""
        if call_id in self.sessions:
            session = self.sessions.pop(call_id)
            session.rtp_session.stop()
            print(f"Call ended: {call_id}")

    async def send_message(self, message: dict):
        """Send message to signaling server"""
        if self.ws:
            await self.ws.send(json.dumps(message))
        else:
            print(f"[Demo] Would send: {json.dumps(message)}")

    # =========================================================================
    # DTMF Handling (via WebSocket, not RTP)
    # =========================================================================

    async def send_dtmf(self, call_id: str, digits: str):
        """
        Send DTMF digits via WebSocket signaling.

        In RTP-only mode, DTMF is NOT sent via RFC 2833 in the RTP stream.
        Instead, it's sent as a WebSocket message to the signaling server,
        which relays it to the remote party.

        Args:
            call_id: The call to send DTMF on
            digits: DTMF digits to send (0-9, *, #, A-D)
        """
        if call_id not in self.sessions:
            raise ValueError(f"No active call: {call_id}")

        print(f"Sending DTMF via WebSocket: {digits}")

        await self.send_message({
            "type": "dtmf",
            "call_id": call_id,
            "digits": digits,
        })

    def handle_dtmf_received(self, call_id: str, digit: str):
        """
        Handle DTMF received via WebSocket signaling.

        The signaling server sends us DTMF events when the remote party
        presses digits.
        """
        print(f"DTMF received via WebSocket: {digit}")

        if self.on_dtmf:
            self.on_dtmf(call_id, digit)

    # =========================================================================
    # Audio Handling
    # =========================================================================

    def send_audio(self, call_id: str, samples: list[int]):
        """
        Send audio samples to the remote party.

        Args:
            call_id: The call to send audio on
            samples: PCM i16 samples (160 samples = 20ms at 8kHz)
        """
        if call_id not in self.sessions:
            raise ValueError(f"No active call: {call_id}")

        session = self.sessions[call_id]
        session.rtp_session.send_audio(samples)

    def recv_audio(self, call_id: str, timeout_ms: int = 100) -> Optional[list[int]]:
        """
        Receive audio samples from the remote party.

        Args:
            call_id: The call to receive audio from
            timeout_ms: Timeout in milliseconds

        Returns:
            PCM i16 samples (160 samples = 20ms at 8kHz), or None on timeout
        """
        if call_id not in self.sessions:
            raise ValueError(f"No active call: {call_id}")

        session = self.sessions[call_id]
        return session.rtp_session.recv_audio(timeout_ms)

    def get_stats(self, call_id: str) -> JitterStats:
        """Get jitter buffer statistics for a call"""
        if call_id not in self.sessions:
            raise ValueError(f"No active call: {call_id}")

        return self.sessions[call_id].rtp_session.get_stats()

    # =========================================================================
    # Main Event Loop
    # =========================================================================

    async def run(self):
        """Main event loop - process signaling and audio"""
        await self.connect()

        try:
            # Run signaling and audio processing concurrently
            await asyncio.gather(
                self._signaling_loop(),
                self._audio_loop(),
            )
        except asyncio.CancelledError:
            pass
        finally:
            await self.disconnect()

    async def _signaling_loop(self):
        """Process incoming WebSocket messages"""
        if not self.ws:
            # Demo mode - simulate incoming call
            await asyncio.sleep(1)
            print("\n[Demo] Simulating incoming call...")
            await self.handle_incoming_call(
                call_id="demo-call-123",
                remote_host="127.0.0.1",
                remote_port=5004,
            )

            # Simulate DTMF received
            await asyncio.sleep(2)
            print("\n[Demo] Simulating DTMF received...")
            self.handle_dtmf_received("demo-call-123", "1")
            self.handle_dtmf_received("demo-call-123", "2")
            self.handle_dtmf_received("demo-call-123", "3")

            # Simulate sending DTMF
            await asyncio.sleep(1)
            print("\n[Demo] Sending DTMF response...")
            await self.send_dtmf("demo-call-123", "456#")

            await asyncio.sleep(5)
            await self.handle_call_ended("demo-call-123")
            return

        async for message in self.ws:
            if not self.running:
                break

            try:
                data = json.loads(message)
                msg_type = data.get("type")

                if msg_type == "call_start":
                    await self.handle_incoming_call(
                        call_id=data["call_id"],
                        remote_host=data["rtp_host"],
                        remote_port=data["rtp_port"],
                    )

                elif msg_type == "call_end":
                    await self.handle_call_ended(data["call_id"])

                elif msg_type == "dtmf":
                    self.handle_dtmf_received(
                        call_id=data["call_id"],
                        digit=data["digit"],
                    )

            except Exception as e:
                print(f"Error processing message: {e}")

    async def _audio_loop(self):
        """Process audio for all active sessions"""
        while self.running:
            for call_id, session in list(self.sessions.items()):
                try:
                    # Non-blocking audio receive
                    audio = session.rtp_session.try_recv_audio()
                    if audio and self.on_audio:
                        self.on_audio(call_id, audio)
                except Exception as e:
                    print(f"Audio error on {call_id}: {e}")

            # Small sleep to prevent busy loop
            await asyncio.sleep(0.001)


# =============================================================================
# Example Usage
# =============================================================================

def on_audio_received(call_id: str, samples: list[int]):
    """Callback when audio is received"""
    # In a real app, you would:
    # 1. Send to speech-to-text engine
    # 2. Process with your Voice AI
    # 3. Generate response audio and send back
    print(f"Received {len(samples)} audio samples on call {call_id}")


def on_dtmf_received(call_id: str, digit: str):
    """Callback when DTMF is received via WebSocket"""
    print(f"DTMF '{digit}' received on call {call_id}")

    # Example: Handle IVR menu selection
    if digit == "1":
        print("  -> User selected option 1")
    elif digit == "2":
        print("  -> User selected option 2")
    elif digit == "#":
        print("  -> User confirmed selection")


async def main():
    """Main entry point"""
    print("=" * 60)
    print("WebSocket + RTP Integration Demo (Mode B)")
    print("=" * 60)
    print()
    print("This demo shows the RTP-only mode workflow:")
    print("  - Dynamic port allocation")
    print("  - WebSocket signaling for call setup")
    print("  - DTMF via WebSocket (not RTP)")
    print("  - L16 audio via RTP")
    print()

    # Create client
    client = VoiceAIClient(
        signaling_url="wss://your-signaling-server.com/ws",
        local_ip="0.0.0.0",
        public_ip="YOUR_PUBLIC_IP",  # Set this for NAT traversal
        on_audio=on_audio_received,
        on_dtmf=on_dtmf_received,
    )

    # Handle Ctrl+C
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(client.disconnect()))

    # Run client
    await client.run()

    print("\nDemo complete!")


if __name__ == "__main__":
    asyncio.run(main())
