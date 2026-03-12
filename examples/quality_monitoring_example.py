#!/usr/bin/env python3
"""
Quality Monitoring and Diagnostics

Demonstrates RTCP XR VoIP Metrics, Voice Activity Detection,
media timeout handling, and media recording.
"""

import time
from rtpsip import SipRunner


def quality_monitoring():
    """
    Monitor call quality using RTCP and media events.

    RTCP XR VoIP Metrics (RFC 3611) provide:
    - Loss rate, discard rate
    - Burst/gap density and duration
    - Round trip delay, end system delay
    - Signal level, noise level
    - R-factor (voice quality score, 0-100)
    - MOS-LQ (Mean Opinion Score, 1.0-5.0)

    These are generated automatically and included in RTCP reports.
    """
    runner = SipRunner.from_config("config.toml")
    runner.start()

    call_id = runner.call(
        to="sip:+14155551234@carrier.com",
        from_="sip:+14155550000@carrier.com",
    )

    call_start = None

    while True:
        event = runner.next_event(timeout_ms=30000)
        if event is None:
            if call_start and call_id:
                # Periodically check call stats
                elapsed = time.time() - call_start
                print(f"Call duration: {elapsed:.0f}s")
            continue

        if event.is_answered():
            call_start = time.time()
            print(f"Call {event.call_id} answered, monitoring quality...")

        elif event.is_media_timeout():
            print(f"WARNING: Media timeout on call {event.call_id}!")
            print("No RTP packets received within timeout period.")
            print("Possible causes: network failure, NAT timeout, remote crash")
            # Optionally hang up
            runner.hangup(event.call_id)

        elif event.is_hangup():
            if call_start:
                duration = time.time() - call_start
                print(f"Call ended after {duration:.1f}s: {event.reason}")
            break

        elif event.is_error():
            print(f"Error: {event.error}")
            break

    runner.stop()


def media_timeout_config():
    """
    Media Timeout Configuration

    Detects dead RTP streams (no packets received). Configure in config.toml:

        [rtp]
        media_timeout_ms = 30000    # 30 seconds (default)
        # media_timeout_ms = 0     # Disabled

    When timeout triggers, a MediaTimeout event is emitted.
    The call remains active - application decides whether to hang up.

    Common causes of media timeout:
    - Network path failure
    - NAT binding expiry (configure keepalive to prevent)
    - Remote endpoint crash
    - Firewall blocking RTP
    """
    pass


def vad_config():
    """
    Voice Activity Detection (VAD) Configuration

    Energy-based VAD with configurable threshold and hangover.
    Configure in config.toml:

        [rtp]
        enable_vad = true
        vad_threshold = 250.0     # RMS energy threshold (~-30 dBFS)
        vad_hangover_frames = 10  # Frames before silence (200ms at 20ms/frame)

    When VAD is enabled:
    - Speech frames are sent normally
    - Silence frames generate comfort noise (CN)
    - Reduces bandwidth during silence periods

    The hangover mechanism prevents clipping at speech boundaries
    by continuing to send a few frames after energy drops below threshold.
    """
    pass


def srtp_config():
    """
    SRTP Configuration

    Encrypt RTP media with SRTP (RFC 3711). Configure in config.toml:

        [rtp]
        srtp_mode = "optional"   # "disabled" | "optional" | "required"

    Modes:
    - disabled: No SRTP, plain RTP only
    - optional: Offer SRTP in SDP, fall back to RTP if remote doesn't support
    - required: Require SRTP, reject calls without crypto

    Supported cipher suites:
    - AES_CM_128_HMAC_SHA1_80 (default, most compatible)
    - AES_CM_128_HMAC_SHA1_32 (shorter auth tag)

    SRTP parameters are negotiated in SDP via crypto attributes.
    Error recovery automatically re-syncs on decryption failures.
    """
    pass


def rtcp_mux_config():
    """
    RTCP-Mux Configuration

    Multiplex RTP and RTCP on the same port (RFC 5761).
    Reduces NAT traversal complexity by using one port instead of two.

    Configure in config.toml:

        [rtp]
        enable_rtcp_mux = true

    When enabled, SDP includes a=rtcp-mux attribute.
    Both RTP and RTCP packets are sent/received on the RTP port.
    The library automatically demultiplexes based on payload type ranges.
    """
    pass


if __name__ == "__main__":
    print("Quality Monitoring Examples")
    print("==========================")
    print()
    print("Features covered:")
    print("  - RTCP XR VoIP Metrics (RFC 3611)")
    print("  - Media timeout detection")
    print("  - Voice Activity Detection (VAD)")
    print("  - SRTP encryption")
    print("  - RTCP-mux")
    print()
    print("Run quality_monitoring() to see live call quality monitoring.")
    print("See config sections in this file for all configuration options.")
