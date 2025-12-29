#!/usr/bin/env python3
"""
Example: Outbound Call (Mode 1)

Demonstrates placing an outbound call via SIP trunk and handling audio.
This example shows integration with a simple echo bot.

Requirements:
    - FreeSWITCH running with mod_sofia loaded
    - SIP trunk configured
    - pyswitch installed: `maturin develop`

Usage:
    python outbound_call.py --destination 18005551234 --trunk mytrunk
"""

import argparse
import asyncio
import signal
import sys
from typing import Optional

# Import pyswitch
try:
    from pyswitch import (
        SipStack,
        SipConfig,
        TrunkConfig,
        Call,
        AudioFrame,
    )
except ImportError:
    print("Error: pyswitch not installed. Run 'maturin develop' first.")
    sys.exit(1)


class OutboundCallHandler:
    """Handles an outbound call with audio processing."""

    def __init__(self, call: Call):
        self.call = call
        self.running = True
        self.frames_received = 0
        self.frames_sent = 0

    async def run(self) -> None:
        """Main call handling loop."""
        print(f"Call connected: {self.call.uuid}")
        print(f"  Direction: {self.call.direction}")
        print(f"  Destination: {self.call.destination}")

        # Wait for media to be ready
        retry = 0
        while not self.call.is_media_ready and retry < 50:
            await asyncio.sleep(0.1)
            retry += 1

        if not self.call.is_media_ready:
            print("Error: Media not ready after 5 seconds")
            return

        print("Media ready, starting audio loop...")

        try:
            await self._audio_loop()
        except Exception as e:
            print(f"Error in audio loop: {e}")
        finally:
            print(f"Call ended. Received: {self.frames_received}, Sent: {self.frames_sent}")

    async def _audio_loop(self) -> None:
        """Process audio frames (simple echo)."""
        while self.running and self.call.is_active:
            # Receive audio with 100ms timeout
            frame = await self.call.recv_audio(100)

            if frame is not None:
                self.frames_received += 1

                # Echo the audio back (simple test)
                await self.call.send_audio(frame)
                self.frames_sent += 1

                # Log every 50 frames (~1 second)
                if self.frames_received % 50 == 0:
                    print(f"  Processed {self.frames_received} frames...")

    def stop(self) -> None:
        """Signal the handler to stop."""
        self.running = False


async def make_call(
    destination: str,
    trunk_name: str,
    trunk_host: str,
    trunk_username: Optional[str] = None,
    trunk_password: Optional[str] = None,
    timeout_sec: int = 60,
    call_duration: int = 30,
) -> None:
    """Make an outbound call."""
    print(f"Initializing SIP stack...")

    # Create SIP stack
    sip_config = SipConfig(
        local_ip="0.0.0.0",
        local_port=5060,
        user_agent="pyswitch-example/0.1.0",
        debug=True,
    )
    sip = SipStack(sip_config)

    try:
        await sip.start()
        print("SIP stack started")

        # Add trunk
        trunk = TrunkConfig(
            name=trunk_name,
            host=trunk_host,
            port=5060,
            username=trunk_username,
            password=trunk_password,
            register=False,  # Don't register for outbound-only
            caller_id_name="PySwitch",
            caller_id_number="5551234567",
        )
        await sip.add_trunk(trunk)
        print(f"Trunk '{trunk_name}' added: {trunk_host}")

        # Place the call
        print(f"Dialing {destination} via {trunk_name}...")
        call = await sip.dial(
            destination=destination,
            trunk=trunk_name,
            timeout_sec=timeout_sec,
        )

        # Handle the call
        handler = OutboundCallHandler(call)

        # Set up call duration timer
        async def call_timer():
            await asyncio.sleep(call_duration)
            print(f"Call duration ({call_duration}s) reached, hanging up...")
            handler.stop()

        timer_task = asyncio.create_task(call_timer())

        try:
            await handler.run()
        finally:
            timer_task.cancel()
            try:
                await timer_task
            except asyncio.CancelledError:
                pass

        # Hangup
        await call.hangup()
        print("Call hung up")

    except Exception as e:
        print(f"Error: {e}")
        raise
    finally:
        await sip.stop()
        print("SIP stack stopped")


def main():
    parser = argparse.ArgumentParser(description="Make an outbound call via pyswitch")
    parser.add_argument(
        "--destination", "-d",
        required=True,
        help="Destination phone number or SIP URI",
    )
    parser.add_argument(
        "--trunk", "-t",
        default="default",
        help="Trunk name (default: 'default')",
    )
    parser.add_argument(
        "--trunk-host",
        default="sip.example.com",
        help="Trunk host (default: sip.example.com)",
    )
    parser.add_argument(
        "--trunk-username",
        help="Trunk authentication username",
    )
    parser.add_argument(
        "--trunk-password",
        help="Trunk authentication password",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Call timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Maximum call duration in seconds (default: 30)",
    )

    args = parser.parse_args()

    # Handle Ctrl+C gracefully
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler():
        print("\nInterrupted, shutting down...")
        for task in asyncio.all_tasks(loop):
            task.cancel()

    loop.add_signal_handler(signal.SIGINT, signal_handler)
    loop.add_signal_handler(signal.SIGTERM, signal_handler)

    try:
        loop.run_until_complete(
            make_call(
                destination=args.destination,
                trunk_name=args.trunk,
                trunk_host=args.trunk_host,
                trunk_username=args.trunk_username,
                trunk_password=args.trunk_password,
                timeout_sec=args.timeout,
                call_duration=args.duration,
            )
        )
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
