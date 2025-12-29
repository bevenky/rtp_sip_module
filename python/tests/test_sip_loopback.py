#!/usr/bin/env python3
"""
SIP Mode Tests using FreeSWITCH loopback

Tests Mode 1 (Outbound) and Mode 2 (Inbound) using internal loopback,
no external SIP server required.

NOTE: These tests must run in ISOLATION because SIP mode and RTP-only mode
are mutually exclusive. Run with:
    pytest tests/test_sip_loopback.py  # Run SIP tests alone

Or use pytest-forked to run each test in a separate process:
    pip install pytest-forked
    pytest tests/test_sip_loopback.py --forked
"""

import asyncio
import pytest

# Mark all tests in this module to run in isolation
pytestmark = pytest.mark.sip_mode


def import_rtp_sip():
    """Import rtp_sip or skip if not available."""
    try:
        from rtp_sip import SIP, SipConfig, TrunkConfig, AudioFrame
        return SIP, SipConfig, TrunkConfig, AudioFrame
    except ImportError:
        pytest.skip("rtp_sip not built - run 'maturin develop' first")


@pytest.mark.asyncio
async def test_sip_stack_start_stop():
    """Test that SIP stack can start and stop cleanly."""
    SIP, SipConfig, TrunkConfig, AudioFrame = import_rtp_sip()

    config = SipConfig(
        local_ip="0.0.0.0",
        local_port=15060,
    )
    sip = SIP(config)

    # Start
    await sip.start()
    assert sip.is_running
    print("SIP stack started successfully")

    # Stop
    await sip.stop()
    assert not sip.is_running
    print("SIP stack stopped successfully")


@pytest.mark.asyncio
async def test_sip_add_remove_trunk():
    """Test adding and removing trunks."""
    SIP, SipConfig, TrunkConfig, AudioFrame = import_rtp_sip()

    config = SipConfig(local_port=15061)
    sip = SIP(config)

    try:
        await sip.start()

        # Add trunk
        trunk = TrunkConfig(
            name="test_trunk",
            host="127.0.0.1",
            port=5060,
        )
        await sip.add_trunk(trunk)
        print("Trunk added successfully")

        # Remove trunk
        await sip.remove_trunk("test_trunk")
        print("Trunk removed successfully")

    finally:
        await sip.stop()


@pytest.mark.asyncio
async def test_sip_list_sessions():
    """Test listing active sessions (should be empty initially)."""
    SIP, SipConfig, TrunkConfig, AudioFrame = import_rtp_sip()

    config = SipConfig(local_port=15062)
    sip = SIP(config)

    try:
        await sip.start()

        sessions = await sip.list_sessions()
        assert sessions == [], f"Expected empty sessions, got {sessions}"
        print(f"Sessions list: {sessions}")

    finally:
        await sip.stop()


@pytest.mark.asyncio
async def test_sip_get_nonexistent_session():
    """Test getting a session that doesn't exist."""
    SIP, SipConfig, TrunkConfig, AudioFrame = import_rtp_sip()

    config = SipConfig(local_port=15063)
    sip = SIP(config)

    try:
        await sip.start()

        session = await sip.get_session("nonexistent-uuid")
        assert session is None
        print("Correctly returned None for nonexistent session")

    finally:
        await sip.stop()


@pytest.mark.asyncio
async def test_sip_dial_no_trunk():
    """Test dialing without a trunk configured - should fail gracefully."""
    SIP, SipConfig, TrunkConfig, AudioFrame = import_rtp_sip()

    config = SipConfig(local_port=15064)
    sip = SIP(config)

    try:
        await sip.start()

        # Try to dial without adding trunk first
        with pytest.raises(Exception) as exc_info:
            await sip.dial("1234", "nonexistent_trunk")

        # Should fail with trunk not found error
        assert "not found" in str(exc_info.value).lower() or "trunk" in str(exc_info.value).lower()
        print(f"Correctly failed with: {exc_info.value}")

    finally:
        await sip.stop()


if __name__ == "__main__":
    asyncio.run(test_sip_stack_start_stop())
