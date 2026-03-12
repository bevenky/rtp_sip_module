#!/usr/bin/env python3
"""
Registration and Gateway Health Monitoring

Demonstrates SIP registration lifecycle, state tracking, and gateway
health monitoring via OPTIONS keepalive.
"""

import time
from rtpsip import SipRunner


def registration_monitoring():
    """
    Monitor registration state and gateway health.

    Events:
        registration_changed - state: "registered", "failed", "expired", "unregistered"
        gateway_health - server: str, healthy: bool
    """
    runner = SipRunner(
        provider_name="primary",
        provider_server="sip.carrier.com",
        port=5060,
        username="myuser",
        password="mypassword",
        local_ip="0.0.0.0",
        local_port=5060,
        register=True,
    )

    runner.start()

    # Check initial registration state
    state = runner.registration_state()
    print(f"Initial registration state: {state}")

    # Monitor events
    while True:
        event = runner.next_event(timeout_ms=60000)
        if event is None:
            # No events for 60s, check state
            state = runner.registration_state()
            print(f"Current registration state: {state}")
            continue

        if event.is_registration_changed():
            print(f"Registration state changed: {event.state}")
            if event.error:
                print(f"  Error: {event.error}")

            # Take action based on state
            if event.state == "failed":
                print("Registration failed! Check credentials or network.")
            elif event.state == "expired":
                print("Registration expired, will auto-refresh.")
            elif event.state == "registered":
                print("Successfully registered, ready to make/receive calls.")

        elif event.is_gateway_health():
            status = "healthy" if event.healthy else "UNHEALTHY"
            print(f"Gateway {event.server}: {status}")

            if not event.healthy:
                print("WARNING: Gateway unreachable, calls may fail!")

        elif event.is_incoming():
            print(f"Incoming call from {event.from_uri}")
            # Only answer if registered
            state = runner.registration_state()
            if state == "registered":
                runner.answer(event.call_id)
            else:
                runner.reject(event.call_id, 503)  # Service Unavailable

        elif event.is_hangup():
            print(f"Call {event.call_id} ended: {event.reason}")

    runner.stop()


def multi_provider_registration():
    """
    Multi-provider setup from config file.

    Uses config.toml with multiple [[providers]] sections.
    Registration state is tracked per provider.
    Calls are routed by longest-prefix match.
    """
    runner = SipRunner.from_config("config.toml")
    runner.start()

    print("Registered with all configured providers")
    print("Calls will be routed by longest-prefix match:")
    print("  +1415... -> primary provider")
    print("  +44...   -> UK provider")
    print("  other    -> default provider")

    # Make calls - routing is automatic
    us_call = runner.call(
        to="sip:+14155551234@carrier.com",
        from_="sip:+14155550000@carrier.com",
    )
    print(f"US call routed via primary: {us_call}")

    while True:
        event = runner.next_event(timeout_ms=30000)
        if event is None:
            continue

        if event.is_registration_changed():
            print(f"Registration: {event.state}")

        elif event.is_gateway_health():
            status = "UP" if event.healthy else "DOWN"
            print(f"Gateway {event.server}: {status}")

        elif event.is_answered():
            print(f"Call {event.call_id} answered")
            time.sleep(5)
            runner.hangup(event.call_id)

        elif event.is_hangup():
            break

    runner.stop()


if __name__ == "__main__":
    registration_monitoring()
