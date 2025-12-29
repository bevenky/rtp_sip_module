#!/usr/bin/env python3
"""
Example: Inbound Call Server (Mode 2)

Demonstrates receiving inbound calls via SIP trunk.
Implements a simple IVR that plays a greeting and echoes audio.

Requirements:
    - FreeSWITCH running with mod_sofia loaded
    - SIP trunk configured to route calls to this server
    - pyswitch installed: `maturin develop`

Usage:
    python inbound_server.py --trunk mytrunk --trunk-host sip.provider.com
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
        CallDirection,
        AudioFrame,
    )
except ImportError:
    print("Error: pyswitch not installed. Run 'maturin develop' first.")
    sys.exit(1)


# Global state
active_calls: dict[str, "CallHandler"] = {}
shutdown_event = asyncio.Event()


class CallHandler:
    """Handles an individual inbound call."""

    def __init__(self, call: Call):
        self.call = call
        self.running = True
        self.frames_received = 0
        self.frames_sent = 0

    async def handle(self) -> None:
        """Main call handler - runs as a task."""
        uuid = self.call.uuid
        caller_id = self.call.caller_id or "Unknown"
        destination = self.call.destination or "Unknown"

        print(f"[{uuid[:8]}] Incoming call from {caller_id} to {destination}")

        try:
            # Answer the call
            print(f"[{uuid[:8]}] Answering...")
            await self.call.answer()
            print(f"[{uuid[:8]}] Answered, media ready: {self.call.is_media_ready}")

            # Wait for media
            retry = 0
            while not self.call.is_media_ready and retry < 50:
                await asyncio.sleep(0.1)
                retry += 1

            if not self.call.is_media_ready:
                print(f"[{uuid[:8]}] Media not ready, hanging up")
                await self.call.hangup("no_answer")
                return

            # Process audio (echo bot)
            print(f"[{uuid[:8]}] Starting audio loop...")
            await self._audio_loop()

        except asyncio.CancelledError:
            print(f"[{uuid[:8]}] Call handler cancelled")
        except Exception as e:
            print(f"[{uuid[:8]}] Error: {e}")
        finally:
            # Cleanup
            if self.call.is_active:
                await self.call.hangup()
            print(
                f"[{uuid[:8]}] Call ended. "
                f"Received: {self.frames_received}, Sent: {self.frames_sent}"
            )
            active_calls.pop(uuid, None)

    async def _audio_loop(self) -> None:
        """Process audio frames."""
        uuid = self.call.uuid[:8]

        while self.running and self.call.is_active:
            # Receive audio (100ms timeout)
            frame = await self.call.recv_audio(100)

            if frame is not None:
                self.frames_received += 1

                # Echo the audio back
                await self.call.send_audio(frame)
                self.frames_sent += 1

                # Log progress every second (~50 frames)
                if self.frames_received % 50 == 0:
                    print(f"[{uuid}] {self.frames_received} frames processed")

            # Check for shutdown
            if shutdown_event.is_set():
                print(f"[{uuid}] Shutdown requested")
                break

    def stop(self) -> None:
        """Signal handler to stop."""
        self.running = False


async def on_inbound_call(call: Call) -> None:
    """
    Callback for inbound calls.

    This is called by pyswitch when a new inbound call arrives.
    We spawn a task to handle the call asynchronously.
    """
    handler = CallHandler(call)
    active_calls[call.uuid] = handler

    # Run handler as a background task
    asyncio.create_task(handler.handle())


async def run_server(
    trunk_name: str,
    trunk_host: str,
    trunk_port: int = 5060,
    trunk_username: Optional[str] = None,
    trunk_password: Optional[str] = None,
    local_port: int = 5060,
) -> None:
    """Run the inbound call server."""
    print("Starting inbound call server...")

    # Create SIP stack
    sip_config = SipConfig(
        local_ip="0.0.0.0",
        local_port=local_port,
        user_agent="pyswitch-inbound/0.1.0",
        debug=True,
    )
    sip = SipStack(sip_config)

    try:
        # Register inbound handler BEFORE starting
        sip.set_inbound_handler(on_inbound_call)
        print("Inbound handler registered")

        # Start stack
        await sip.start()
        print(f"SIP stack started on port {local_port}")

        # Add trunk (with registration for inbound)
        trunk = TrunkConfig(
            name=trunk_name,
            host=trunk_host,
            port=trunk_port,
            username=trunk_username,
            password=trunk_password,
            register=True,  # Register to receive inbound calls
        )
        await sip.add_trunk(trunk)
        print(f"Trunk '{trunk_name}' registered with {trunk_host}:{trunk_port}")

        print("\nServer ready. Waiting for calls...")
        print("Press Ctrl+C to stop.\n")

        # Wait for shutdown signal
        await shutdown_event.wait()

        print("\nShutting down...")

        # Stop all active calls
        for uuid, handler in list(active_calls.items()):
            print(f"Stopping call {uuid[:8]}...")
            handler.stop()

        # Wait for calls to end
        await asyncio.sleep(1)

    except Exception as e:
        print(f"Server error: {e}")
        raise
    finally:
        await sip.stop()
        print("SIP stack stopped")


def main():
    parser = argparse.ArgumentParser(
        description="Run an inbound call server with pyswitch"
    )
    parser.add_argument(
        "--trunk", "-t",
        default="inbound",
        help="Trunk name (default: 'inbound')",
    )
    parser.add_argument(
        "--trunk-host",
        required=True,
        help="Trunk host (SIP provider address)",
    )
    parser.add_argument(
        "--trunk-port",
        type=int,
        default=5060,
        help="Trunk port (default: 5060)",
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
        "--local-port",
        type=int,
        default=5060,
        help="Local SIP port to bind (default: 5060)",
    )

    args = parser.parse_args()

    # Setup event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Signal handlers
    def signal_handler():
        print("\nReceived shutdown signal...")
        shutdown_event.set()

    loop.add_signal_handler(signal.SIGINT, signal_handler)
    loop.add_signal_handler(signal.SIGTERM, signal_handler)

    try:
        loop.run_until_complete(
            run_server(
                trunk_name=args.trunk,
                trunk_host=args.trunk_host,
                trunk_port=args.trunk_port,
                trunk_username=args.trunk_username,
                trunk_password=args.trunk_password,
                local_port=args.local_port,
            )
        )
    except asyncio.CancelledError:
        pass
    finally:
        # Cleanup remaining tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    main()
