#!/usr/bin/env python3
"""
Call Transfer Examples

Demonstrates blind transfer, attended transfer, and handling incoming
REFER requests. Shows NOTIFY subscription tracking for transfer progress.
"""

import sys
import time
from rtpsip import SipRunner


def blind_transfer_example():
    """
    Blind Transfer (REFER)

    Transfers an active call to a third party. The remote end receives
    a REFER and initiates a new INVITE to the transfer target.

    Flow:
        A (us) <--call--> B (remote)
        A sends REFER to B with target C
        B sends INVITE to C
        B sends NOTIFY to A with transfer progress
        A receives TransferProgress events (100 Trying, 180 Ringing, 200 OK)
        Once completed, original call is terminated
    """
    runner = SipRunner.from_config("config.toml")
    runner.start()

    # Make outbound call
    call_id = runner.call(
        to="sip:+14155551234@carrier.com",
        from_="sip:+14155550000@carrier.com",
    )

    while True:
        event = runner.next_event(timeout_ms=30000)
        if event is None:
            continue

        if event.is_answered():
            print(f"Call {event.call_id} answered, initiating transfer...")

            # Wait a moment, then transfer
            time.sleep(2)

            # Blind transfer to target
            runner.transfer(call_id, "sip:+14155559999@carrier.com")
            print("REFER sent, waiting for transfer progress...")

        elif event.is_transfer_initiated():
            print(f"Transfer initiated to {event.target}")

        elif event.is_transfer_progress():
            print(
                f"Transfer progress: {event.status_code} {event.reason} "
                f"(completed={event.completed})"
            )
            if event.completed:
                print("Transfer completed successfully!")
                runner.hangup(call_id)
                break

        elif event.is_transfer_failed():
            print(f"Transfer failed: {event.error}")
            # Call is still active, can retry or continue
            runner.hangup(call_id)
            break

        elif event.is_hangup():
            print(f"Call ended: {event.reason}")
            break

    runner.stop()


def attended_transfer_example():
    """
    Attended Transfer (Consultation Transfer with Replaces)

    Two-step process:
    1. Put original call on hold
    2. Make consultation call to transfer target
    3. Execute attended transfer (original caller gets connected to target)

    Flow:
        A (us) <--call1--> B (original caller)
        A puts B on hold
        A <--call2--> C (consultation call)
        A sends REFER to B with Refer-To containing Replaces header
        B sends INVITE to C with Replaces header
        C replaces call2 with call from B
        A's calls are both terminated
    """
    runner = SipRunner.from_config("config.toml")
    runner.start()

    original_call_id = None
    consultation_call_id = None

    # Wait for incoming call
    while True:
        event = runner.next_event(timeout_ms=30000)
        if event is None:
            continue

        if event.is_incoming():
            print(f"Incoming call from {event.from_uri}")
            runner.answer(event.call_id)
            original_call_id = event.call_id

        elif event.is_answered() and event.call_id == original_call_id:
            print("Original call answered, placing on hold for consultation...")

            # Step 1: Put original caller on hold
            runner.hold(original_call_id)
            time.sleep(1)

            # Step 2: Make consultation call
            consultation_call_id = runner.call(
                to="sip:+14155559999@carrier.com",
                from_="sip:+14155550000@carrier.com",
            )
            print("Consultation call initiated...")

        elif event.is_answered() and event.call_id == consultation_call_id:
            print("Consultation call answered, executing attended transfer...")

            # Step 3: Attended transfer - connect original caller to consultation target
            runner.attended_transfer(original_call_id, consultation_call_id)

        elif event.is_transfer_initiated():
            print(f"Attended transfer initiated to {event.target}")

        elif event.is_transfer_progress():
            print(f"Transfer progress: {event.status_code} {event.reason}")
            if event.completed:
                print("Attended transfer completed!")
                break

        elif event.is_transfer_failed():
            print(f"Transfer failed: {event.error}")
            # Resume original call
            if original_call_id:
                runner.unhold(original_call_id)
            break

        elif event.is_hangup():
            print(f"Call {event.call_id} ended: {event.reason}")
            if event.call_id == original_call_id:
                break

    runner.stop()


def handle_incoming_refer():
    """
    Handle Incoming REFER (Remote-Initiated Transfer)

    When the remote party sends us a REFER, we receive a ReferReceived
    event and can decide whether to follow the transfer.
    """
    runner = SipRunner.from_config("config.toml")
    runner.start()

    while True:
        event = runner.next_event(timeout_ms=30000)
        if event is None:
            continue

        if event.is_incoming():
            runner.answer(event.call_id)

        elif event.is_refer_received():
            print(f"Remote wants to transfer us to: {event.target}")

            # Option 1: Follow the transfer (make new call to target)
            new_call_id = runner.call(
                to=event.target,
                from_="sip:+14155550000@carrier.com",
            )
            # Hang up original call
            runner.hangup(event.call_id)
            print(f"Following transfer, new call: {new_call_id}")

            # Option 2: Reject the transfer (just ignore the REFER)
            # print("Ignoring transfer request")

        elif event.is_hangup():
            print(f"Call ended: {event.reason}")
            break

    runner.stop()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == "blind":
            blind_transfer_example()
        elif mode == "attended":
            attended_transfer_example()
        elif mode == "incoming":
            handle_incoming_refer()
        else:
            print(f"Usage: {sys.argv[0]} [blind|attended|incoming]")
    else:
        print("Transfer Examples:")
        print(f"  {sys.argv[0]} blind     - Blind transfer (REFER)")
        print(f"  {sys.argv[0]} attended  - Attended transfer (Replaces)")
        print(f"  {sys.argv[0]} incoming  - Handle incoming REFER")
