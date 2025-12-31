#!/usr/bin/env python3
"""
SIP + RTP Integration Example (Mode A)

This example demonstrates using siprunner's full SIP stack for telephony
applications with complete DTMF support.

Features:
    - Multi-provider trunk configuration
    - Outbound and inbound call handling
    - DTMF send (auto RFC 2833 / SIP INFO detection)
    - DTMF receive (both RFC 2833 and SIP INFO)
    - Hold/Resume
    - Call transfer (REFER)
    - Audio streaming (L16)

Architecture:
    Python App <--SIP--> SIP Provider <--PSTN--> Phone
    Python App <--RTP--> SIP Provider (direct audio)
"""

import signal
import sys
import time
import threading
from typing import Optional
from siprunner import SipRunner, CallState, DtmfMode


class TelephonyApp:
    """
    Full-featured telephony application using SIP + RTP.

    This demonstrates the complete Mode A feature set including
    DTMF, hold/resume, and call transfer.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the telephony app.

        Args:
            config_path: Path to config.toml, or None for programmatic config
        """
        if config_path:
            self.runner = SipRunner.from_config(config_path)
        else:
            # Programmatic single-provider setup
            self.runner = SipRunner(
                provider_name="default",
                provider_server="sip.example.com",
                username="your_username",
                password="your_password",
            )

        self.active_calls: dict[str, dict] = {}
        self.running = False

    def start(self):
        """Start the SIP engine"""
        self.runner.start()
        self.running = True
        print("SIP engine started, listening for calls...")

    def stop(self):
        """Stop the SIP engine and hangup all calls"""
        self.running = False
        for call_id in list(self.active_calls.keys()):
            try:
                self.runner.hangup(call_id)
            except Exception:
                pass
        self.runner.stop()
        print("SIP engine stopped")

    # =========================================================================
    # Outbound Calls
    # =========================================================================

    def make_call(self, to_number: str, from_number: str) -> str:
        """
        Make an outbound call.

        The provider is auto-selected based on prefix routing.

        Args:
            to_number: Destination number (e.g., "+14155551234")
            from_number: Caller ID (e.g., "+14155550000")

        Returns:
            call_id for the new call
        """
        call_id = self.runner.call(to=to_number, from_=from_number)
        self.active_calls[call_id] = {
            "direction": "outbound",
            "to": to_number,
            "from": from_number,
            "state": CallState.Ringing,
        }
        print(f"Outbound call started: {call_id}")
        print(f"  To: {to_number}")
        print(f"  From: {from_number}")
        return call_id

    # =========================================================================
    # Inbound Calls
    # =========================================================================

    def answer_call(self, call_id: str):
        """Answer an incoming call"""
        self.runner.answer(call_id)
        print(f"Answered call: {call_id}")

    def reject_call(self, call_id: str, status_code: int = 486):
        """
        Reject an incoming call.

        Args:
            call_id: The call to reject
            status_code: SIP status code (486=Busy, 603=Decline)
        """
        self.runner.reject(call_id, status_code)
        print(f"Rejected call: {call_id} with {status_code}")

    # =========================================================================
    # DTMF - Send
    # =========================================================================

    def send_dtmf(
        self,
        call_id: str,
        digits: str,
        duration_ms: int = 100,
        inter_digit_ms: int = 100,
    ):
        """
        Send DTMF digits on an active call.

        The method is auto-detected based on remote SDP:
        - RFC 2833: If remote supports telephone-event in SDP
        - SIP INFO: Fallback if RFC 2833 not supported

        Args:
            call_id: The call to send DTMF on
            digits: DTMF digits (0-9, *, #, A-D, w=500ms pause, W=1s pause)
            duration_ms: Duration of each digit (100-5000ms)
            inter_digit_ms: Gap between digits

        Example:
            # Send PIN with pauses
            send_dtmf(call_id, "1w2w3w4#")
        """
        # Check call state - DTMF only works on active calls
        call_info = self.active_calls.get(call_id)
        if not call_info or call_info.get("state") != CallState.Active:
            print(f"Warning: Call {call_id} not active, DTMF may fail")

        # Check which DTMF mode is being used
        mode = self.runner.get_dtmf_mode(call_id)
        mode_name = "RFC 2833" if mode == DtmfMode.Rfc2833 else "SIP INFO"
        print(f"Sending DTMF via {mode_name}: {digits}")

        self.runner.send_dtmf(
            call_id,
            digits,
            duration_ms=duration_ms,
            inter_digit_ms=inter_digit_ms,
        )

    def set_dtmf_mode(self, call_id: str, mode: DtmfMode):
        """
        Override the DTMF mode for a call.

        Normally auto-detected, but can be forced if needed.

        Args:
            call_id: The call to configure
            mode: DtmfMode.Auto, DtmfMode.Rfc2833, or DtmfMode.Info
        """
        self.runner.set_dtmf_mode(call_id, mode)
        mode_name = {
            DtmfMode.Auto: "Auto",
            DtmfMode.Rfc2833: "RFC 2833",
            DtmfMode.Info: "SIP INFO",
        }.get(mode, str(mode))
        print(f"DTMF mode set to: {mode_name}")

    # =========================================================================
    # DTMF - Receive
    # =========================================================================

    def recv_dtmf(self, call_id: str) -> Optional[tuple[str, int]]:
        """
        Non-blocking receive of RFC 2833 DTMF from RTP stream.

        Returns:
            Tuple of (digit, duration_ms) or None if no DTMF available
        """
        return self.runner.recv_dtmf(call_id)

    def recv_dtmf_blocking(self, call_id: str, timeout_ms: int = 5000) -> Optional[tuple[str, int]]:
        """
        Blocking receive of RFC 2833 DTMF from RTP stream.

        Args:
            call_id: The call to receive DTMF from
            timeout_ms: Timeout in milliseconds

        Returns:
            Tuple of (digit, duration_ms) or None on timeout
        """
        return self.runner.recv_dtmf_blocking(call_id, timeout_ms)

    # =========================================================================
    # Hold / Resume
    # =========================================================================

    def hold(self, call_id: str):
        """Put a call on hold (sends re-INVITE with sendonly SDP)"""
        self.runner.hold(call_id)
        if call_id in self.active_calls:
            self.active_calls[call_id]["state"] = CallState.Hold
        print(f"Call {call_id} placed on hold")

    def unhold(self, call_id: str):
        """Resume a call from hold (sends re-INVITE with sendrecv SDP)"""
        self.runner.unhold(call_id)
        if call_id in self.active_calls:
            self.active_calls[call_id]["state"] = CallState.Active
        print(f"Call {call_id} resumed")

    # =========================================================================
    # Transfer
    # =========================================================================

    def transfer(self, call_id: str, target: str):
        """
        Blind transfer a call to another number (REFER).

        Args:
            call_id: The call to transfer
            target: Target SIP URI (e.g., "sip:+14155559999@sip.provider.com")
        """
        self.runner.transfer(call_id, target)
        print(f"Call {call_id} transferred to {target}")

    # =========================================================================
    # Audio
    # =========================================================================

    def send_audio(self, call_id: str, samples: list[int]):
        """
        Send audio samples.

        Args:
            call_id: The call to send audio on
            samples: PCM i16 samples (160 samples = 20ms at 8kHz)
        """
        self.runner.send_audio(call_id, samples)

    def recv_audio(self, call_id: str, timeout_ms: int = 100) -> Optional[list[int]]:
        """
        Receive audio samples.

        Args:
            call_id: The call to receive audio from
            timeout_ms: Timeout in milliseconds

        Returns:
            PCM i16 samples (160 samples = 20ms), or None on timeout
        """
        return self.runner.recv_audio(call_id, timeout_ms)

    # =========================================================================
    # Event Loop
    # =========================================================================

    def run_event_loop(self):
        """Main event loop - process SIP events"""
        print("\nWaiting for events (Ctrl+C to exit)...\n")

        while self.running:
            event = self.runner.next_event(timeout_ms=1000)
            if event is None:
                continue

            self._handle_event(event)

    def _handle_event(self, event):
        """Handle a SIP event"""
        call_id = event.call_id

        # =====================================================================
        # Incoming Call
        # =====================================================================
        if event.is_incoming():
            print(f"\n{'='*50}")
            print(f"INCOMING CALL: {call_id}")
            print(f"  From: {event.from_uri}")
            print(f"  To: {event.to_uri}")
            print(f"{'='*50}")

            self.active_calls[call_id] = {
                "direction": "inbound",
                "from": event.from_uri,
                "to": event.to_uri,
                "state": CallState.Ringing,
            }

            # Auto-answer for demo (in real app, you'd prompt user)
            print("Auto-answering call...")
            self.answer_call(call_id)

        # =====================================================================
        # Ringing (180)
        # =====================================================================
        elif event.is_ringing():
            print(f"Call {call_id}: Ringing (180)")
            if call_id in self.active_calls:
                self.active_calls[call_id]["state"] = CallState.Ringing

        # =====================================================================
        # Early Media (183 with SDP)
        # =====================================================================
        elif event.is_early_media():
            print(f"Call {call_id}: Early Media (183)")
            print("  Ringback tone available via RTP")
            if call_id in self.active_calls:
                self.active_calls[call_id]["state"] = CallState.EarlyMedia

        # =====================================================================
        # Answered (200 OK)
        # =====================================================================
        elif event.is_answered():
            print(f"Call {call_id}: ANSWERED!")
            if call_id in self.active_calls:
                self.active_calls[call_id]["state"] = CallState.Active

            # Check DTMF mode
            mode = self.runner.get_dtmf_mode(call_id)
            mode_name = "RFC 2833" if mode == DtmfMode.Rfc2833 else "SIP INFO"
            print(f"  DTMF mode: {mode_name}")

            # Demo: Send DTMF after call is answered
            print("  Sending DTMF: 123#")
            self.send_dtmf(call_id, "123#")

        # =====================================================================
        # DTMF Received (via SIP INFO)
        # =====================================================================
        elif event.is_dtmf():
            print(f"\nDTMF RECEIVED (SIP INFO): {event.digit}")
            self._handle_dtmf_digit(call_id, event.digit)

        # =====================================================================
        # Re-INVITE Received
        # =====================================================================
        elif event.is_reinvite():
            print(f"Call {call_id}: Re-INVITE received")
            if hasattr(event, 'sdp') and event.sdp:
                print(f"  New SDP received")

        # =====================================================================
        # Hangup
        # =====================================================================
        elif event.is_hangup():
            reason = getattr(event, 'reason', 'Unknown')
            print(f"\nCall {call_id}: HANGUP - {reason}")
            if call_id in self.active_calls:
                del self.active_calls[call_id]

    def _handle_dtmf_digit(self, call_id: str, digit: str):
        """Handle received DTMF digit"""
        print(f"  Processing DTMF: {digit}")

        # Example IVR handling
        if digit == "1":
            print("    -> User selected option 1 (Sales)")
        elif digit == "2":
            print("    -> User selected option 2 (Support)")
        elif digit == "0":
            print("    -> User requested operator")
        elif digit == "#":
            print("    -> User confirmed input")
        elif digit == "*":
            print("    -> User cancelled")

    def poll_rfc2833_dtmf(self, call_id: str):
        """
        Poll for RFC 2833 DTMF (comes via RTP, not events).

        Call this in your audio processing loop.
        """
        while True:
            dtmf = self.recv_dtmf(call_id)
            if dtmf is None:
                break
            digit, duration_ms = dtmf
            print(f"DTMF RECEIVED (RFC 2833): {digit} ({duration_ms}ms)")
            self._handle_dtmf_digit(call_id, digit)


# =============================================================================
# Example Config File
# =============================================================================

EXAMPLE_CONFIG = """
# config.toml - Multi-provider SIP configuration

[sip]
local_ip = "0.0.0.0"
local_port = 5060
transport = "udp"

[rtp]
local_ip = "0.0.0.0"
port_start = 10000
port_end = 20000

# US provider (Twilio)
[[providers]]
name = "twilio"
server = "sip.twilio.com"
port = 5060
username = "ACCOUNT_SID"
password = "AUTH_TOKEN"
prefixes = ["+1"]

# UK provider (Telnyx)
[[providers]]
name = "telnyx"
server = "sip.telnyx.com"
port = 5060
username = "USER"
password = "PASS"
prefixes = ["+44"]
default = true  # Fallback for unmatched prefixes

[routing]
blocked_prefixes = ["+1900", "+1976"]  # Premium rate blocking
"""


# =============================================================================
# Demo Functions
# =============================================================================

def demo_outbound_call():
    """Demo: Make an outbound call with DTMF"""
    print("\n" + "=" * 60)
    print("DEMO: Outbound Call with DTMF")
    print("=" * 60)

    app = TelephonyApp()

    try:
        app.start()

        # Make call
        call_id = app.make_call(
            to_number="+14155551234",
            from_number="+14155550000",
        )

        # Wait for answer
        print("\nWaiting for call to be answered...")
        while True:
            event = app.runner.next_event(timeout_ms=1000)
            if event is None:
                continue

            if event.is_answered():
                print("Call answered!")
                break
            elif event.is_hangup():
                print("Call failed or rejected")
                return

        # Send DTMF sequence
        print("\nSending DTMF: 1w2w3w4#")
        app.send_dtmf(call_id, "1w2w3w4#")  # With 500ms pauses

        # Wait for DTMF response
        print("Waiting for DTMF response...")
        dtmf = app.recv_dtmf_blocking(call_id, timeout_ms=10000)
        if dtmf:
            digit, duration = dtmf
            print(f"Received DTMF: {digit} ({duration}ms)")

        # Hangup
        app.runner.hangup(call_id)

    finally:
        app.stop()


def demo_inbound_with_ivr():
    """Demo: Handle inbound calls with IVR DTMF menu"""
    print("\n" + "=" * 60)
    print("DEMO: Inbound Call with IVR DTMF Menu")
    print("=" * 60)

    app = TelephonyApp()

    try:
        app.start()
        print("\nListening for incoming calls...")
        print("Press Ctrl+C to exit\n")

        # Run event loop
        app.run_event_loop()

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        app.stop()


def demo_hold_transfer():
    """Demo: Hold, resume, and transfer"""
    print("\n" + "=" * 60)
    print("DEMO: Hold, Resume, and Transfer")
    print("=" * 60)

    app = TelephonyApp()

    try:
        app.start()

        # Make call
        call_id = app.make_call(
            to_number="+14155551234",
            from_number="+14155550000",
        )

        # Wait for answer
        print("\nWaiting for call to be answered...")
        while True:
            event = app.runner.next_event(timeout_ms=1000)
            if event and event.is_answered():
                break
            elif event and event.is_hangup():
                print("Call failed")
                return

        # Put on hold
        print("\nPutting call on hold...")
        app.hold(call_id)
        time.sleep(2)

        # Resume
        print("Resuming call...")
        app.unhold(call_id)
        time.sleep(2)

        # Transfer
        print("Transferring call...")
        app.transfer(call_id, "sip:+14155559999@sip.provider.com")

    finally:
        app.stop()


# =============================================================================
# Main
# =============================================================================

def main():
    print("=" * 60)
    print("SIP + RTP Integration Demo (Mode A)")
    print("=" * 60)
    print()
    print("This demo shows the full SIP stack with:")
    print("  - Multi-provider trunk routing")
    print("  - DTMF send/receive (RFC 2833 + SIP INFO)")
    print("  - Hold/Resume")
    print("  - Call Transfer (REFER)")
    print()
    print("Example config.toml:")
    print("-" * 40)
    print(EXAMPLE_CONFIG)
    print("-" * 40)
    print()
    print("Available demos:")
    print("  1. Outbound call with DTMF")
    print("  2. Inbound call with IVR menu")
    print("  3. Hold, resume, and transfer")
    print()

    # For actual demo, uncomment one:
    # demo_outbound_call()
    # demo_inbound_with_ivr()
    # demo_hold_transfer()

    print("To run a demo, uncomment the desired function in main()")
    print("or import and call directly:")
    print()
    print("  from sip_example import TelephonyApp, DtmfMode")
    print("  app = TelephonyApp('config.toml')")
    print("  app.start()")
    print("  call_id = app.make_call('+14155551234', '+14155550000')")
    print("  app.send_dtmf(call_id, '123#')")
    print("  dtmf = app.recv_dtmf_blocking(call_id, 5000)")
    print("  app.stop()")


if __name__ == "__main__":
    main()
