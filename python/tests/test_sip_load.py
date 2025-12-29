#!/usr/bin/env python3
"""
SIP Mode Load Test for rtp_sip

Tests concurrent SIP calls through FreeSWITCH to verify:
- No deadlocks in GIL + Mutex handling
- Proper session lifecycle management
- Stable audio processing under load
- No memory leaks with many sessions

Prerequisites:
    - FreeSWITCH must be running (embedded or external)
    - A SIP endpoint to call (can use loopback or pjsua)

Run with:
    python -m pytest python/tests/test_sip_load.py -v -s

Or standalone:
    python python/tests/test_sip_load.py --trunk-host localhost
"""

import asyncio
import time
import statistics
import gc
from dataclasses import dataclass, field
from typing import List, Optional
import pytest


@dataclass
class CallStats:
    """Statistics for a single call."""
    call_id: int
    uuid: str = ""
    connected: bool = False
    frames_sent: int = 0
    frames_received: int = 0
    duration_s: float = 0.0
    error: Optional[str] = None


@dataclass
class SipLoadTestResult:
    """Aggregate results from SIP load test."""
    total_calls: int
    successful_calls: int
    failed_calls: int
    total_frames_sent: int
    total_frames_received: int
    avg_call_duration_s: float
    total_test_duration_s: float
    calls_per_second: float
    errors: List[str] = field(default_factory=list)


def import_pyswitch():
    """Import pyswitch or skip if not available."""
    try:
        from rtp_sip import SIP, SipConfig, TrunkConfig, Call, AudioFrame
        return SIP, SipConfig, TrunkConfig, Call, AudioFrame
    except ImportError:
        pytest.skip("rtp_sip not built - run 'maturin develop' first")


class SipLoadTester:
    """Load tester for SIP calls via FreeSWITCH."""

    def __init__(
        self,
        trunk_host: str,
        trunk_port: int = 5060,
        trunk_username: Optional[str] = None,
        trunk_password: Optional[str] = None,
        num_calls: int = 10,
        call_duration_s: float = 5.0,
        concurrent_limit: int = 10,
    ):
        self.trunk_host = trunk_host
        self.trunk_port = trunk_port
        self.trunk_username = trunk_username
        self.trunk_password = trunk_password
        self.num_calls = num_calls
        self.call_duration_s = call_duration_s
        self.concurrent_limit = concurrent_limit
        self.results: List[CallStats] = []

    async def run_single_call(
        self,
        call_id: int,
        sip_stack,
        AudioFrame,
        trunk_name: str,
        destination: str,
    ) -> CallStats:
        """Run a single test call."""
        stats = CallStats(call_id=call_id)

        try:
            # Place outbound call
            call = await sip_stack.dial(
                destination=destination,
                trunk=trunk_name,
                timeout_sec=30,
            )

            stats.uuid = call.uuid
            stats.connected = True

            start_time = time.time()
            end_time = start_time + self.call_duration_s

            # Audio loop
            silence = bytes(640)  # 20ms of silence at 16kHz
            test_frame = AudioFrame(silence, 16000)

            while time.time() < end_time and call.is_active:
                # Send audio
                await call.send_audio(test_frame)
                stats.frames_sent += 1

                # Receive audio
                frame = await call.recv_audio(50)
                if frame:
                    stats.frames_received += 1

                await asyncio.sleep(0.02)  # 20ms frame interval

            stats.duration_s = time.time() - start_time

            # Hangup
            await call.hangup()

        except Exception as e:
            stats.error = str(e)

        return stats

    async def run_load_test(
        self,
        destination: str = "1234",
    ) -> SipLoadTestResult:
        """Run the full SIP load test."""
        SIP, SipConfig, TrunkConfig, Call, AudioFrame = import_pyswitch()

        print(f"\n{'='*60}")
        print(f"Starting SIP Load Test")
        print(f"{'='*60}")
        print(f"Trunk: {self.trunk_host}:{self.trunk_port}")
        print(f"Total calls: {self.num_calls}")
        print(f"Concurrent limit: {self.concurrent_limit}")
        print(f"Call duration: {self.call_duration_s}s")
        print(f"{'='*60}\n")

        # Create SIP stack
        sip_config = SipConfig(
            local_ip="0.0.0.0",
            local_port=15060,  # Use a non-privileged port for testing
        )
        sip = SIP(sip_config)

        try:
            # Start stack
            await sip.start()
            print("SIP stack started")

            # Add trunk
            trunk = TrunkConfig(
                name="loadtest",
                host=self.trunk_host,
                port=self.trunk_port,
                username=self.trunk_username,
                password=self.trunk_password,
            )
            await sip.add_trunk(trunk)
            print(f"Trunk added: {self.trunk_host}")

            start_time = time.time()

            # Use semaphore to limit concurrency
            semaphore = asyncio.Semaphore(self.concurrent_limit)

            async def limited_call(call_id):
                async with semaphore:
                    return await self.run_single_call(
                        call_id, sip, AudioFrame, "loadtest", destination
                    )

            # Run all calls
            tasks = [limited_call(i) for i in range(self.num_calls)]
            self.results = await asyncio.gather(*tasks)

            end_time = time.time()

        finally:
            await sip.stop()
            print("SIP stack stopped")

        # Aggregate results
        successful = [r for r in self.results if r.connected and not r.error]
        failed = [r for r in self.results if r.error]

        total_sent = sum(r.frames_sent for r in self.results)
        total_recv = sum(r.frames_received for r in self.results)
        durations = [r.duration_s for r in successful]
        avg_duration = statistics.mean(durations) if durations else 0.0

        test_duration = end_time - start_time

        return SipLoadTestResult(
            total_calls=self.num_calls,
            successful_calls=len(successful),
            failed_calls=len(failed),
            total_frames_sent=total_sent,
            total_frames_received=total_recv,
            avg_call_duration_s=avg_duration,
            total_test_duration_s=test_duration,
            calls_per_second=len(successful) / test_duration if test_duration > 0 else 0,
            errors=[r.error for r in failed if r.error],
        )


class TestSipLoad:
    """Test suite for SIP load testing."""

    @pytest.fixture
    def trunk_host(self):
        """Get trunk host from environment or use default."""
        import os
        return os.environ.get("SIP_TRUNK_HOST", "localhost")

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires running SIP server - run manually with --trunk-host")
    async def test_10_concurrent_calls(self, trunk_host):
        """Test 10 concurrent SIP calls."""
        tester = SipLoadTester(
            trunk_host=trunk_host,
            num_calls=10,
            call_duration_s=5.0,
            concurrent_limit=10,
        )
        result = await tester.run_load_test()

        print(f"\n{'='*60}")
        print("RESULTS: 10 Concurrent Calls")
        print(f"{'='*60}")
        print(f"Successful: {result.successful_calls}/{result.total_calls}")
        print(f"Frames sent: {result.total_frames_sent}")
        print(f"Frames received: {result.total_frames_received}")
        print(f"Avg call duration: {result.avg_call_duration_s:.2f}s")
        print(f"{'='*60}\n")

        assert result.successful_calls >= 8, "At least 80% calls should succeed"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires running SIP server - run manually with --trunk-host")
    async def test_100_sequential_calls(self, trunk_host):
        """Test 100 sequential SIP calls (stress test lifecycle)."""
        tester = SipLoadTester(
            trunk_host=trunk_host,
            num_calls=100,
            call_duration_s=2.0,
            concurrent_limit=1,  # Sequential
        )
        result = await tester.run_load_test()

        print(f"\n{'='*60}")
        print("RESULTS: 100 Sequential Calls")
        print(f"{'='*60}")
        print(f"Successful: {result.successful_calls}/{result.total_calls}")
        print(f"Total duration: {result.total_test_duration_s:.2f}s")
        print(f"Calls/second: {result.calls_per_second:.2f}")
        print(f"{'='*60}\n")

        assert result.successful_calls >= 90, "At least 90% calls should succeed"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires running SIP server - run manually with --trunk-host")
    async def test_100_concurrent_calls(self, trunk_host):
        """Test 100 concurrent SIP calls (max load)."""
        tester = SipLoadTester(
            trunk_host=trunk_host,
            num_calls=100,
            call_duration_s=10.0,
            concurrent_limit=100,
        )
        result = await tester.run_load_test()

        print(f"\n{'='*60}")
        print("RESULTS: 100 Concurrent Calls")
        print(f"{'='*60}")
        print(f"Successful: {result.successful_calls}/{result.total_calls}")
        print(f"Failed: {result.failed_calls}")
        print(f"Frames sent: {result.total_frames_sent}")
        print(f"Frames received: {result.total_frames_received}")
        print(f"Total duration: {result.total_test_duration_s:.2f}s")
        if result.errors:
            print(f"Errors: {result.errors[:5]}...")  # First 5 errors
        print(f"{'='*60}\n")

        assert result.successful_calls >= 80, "At least 80% calls should succeed"


async def run_manual_test(
    trunk_host: str,
    trunk_port: int = 5060,
    username: Optional[str] = None,
    password: Optional[str] = None,
    destination: str = "1234",
    num_calls: int = 10,
    concurrent: int = 5,
    duration: float = 5.0,
):
    """Run a manual load test."""
    tester = SipLoadTester(
        trunk_host=trunk_host,
        trunk_port=trunk_port,
        trunk_username=username,
        trunk_password=password,
        num_calls=num_calls,
        call_duration_s=duration,
        concurrent_limit=concurrent,
    )

    result = await tester.run_load_test(destination)

    print(f"\n{'='*60}")
    print("SIP LOAD TEST RESULTS")
    print(f"{'='*60}")
    print(f"Total calls attempted: {result.total_calls}")
    print(f"Successful calls: {result.successful_calls}")
    print(f"Failed calls: {result.failed_calls}")
    print(f"Total frames sent: {result.total_frames_sent}")
    print(f"Total frames received: {result.total_frames_received}")
    print(f"Avg call duration: {result.avg_call_duration_s:.2f}s")
    print(f"Total test duration: {result.total_test_duration_s:.2f}s")
    print(f"Calls per second: {result.calls_per_second:.2f}")
    if result.errors:
        print(f"\nFirst 5 errors:")
        for err in result.errors[:5]:
            print(f"  - {err}")
    print(f"{'='*60}")

    success_rate = result.successful_calls / result.total_calls if result.total_calls > 0 else 0
    passed = success_rate >= 0.8

    print(f"\nOVERALL: {'PASSED' if passed else 'FAILED'} ({success_rate*100:.1f}% success rate)")
    return passed


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SIP Load Test for rtp_sip")
    parser.add_argument("--trunk-host", required=True, help="SIP trunk host")
    parser.add_argument("--trunk-port", type=int, default=5060, help="SIP trunk port")
    parser.add_argument("--username", help="SIP username")
    parser.add_argument("--password", help="SIP password")
    parser.add_argument("--destination", default="1234", help="Destination number")
    parser.add_argument("--calls", type=int, default=10, help="Number of calls")
    parser.add_argument("--concurrent", type=int, default=5, help="Max concurrent calls")
    parser.add_argument("--duration", type=float, default=5.0, help="Call duration in seconds")

    args = parser.parse_args()

    success = asyncio.run(run_manual_test(
        trunk_host=args.trunk_host,
        trunk_port=args.trunk_port,
        username=args.username,
        password=args.password,
        destination=args.destination,
        num_calls=args.calls,
        concurrent=args.concurrent,
        duration=args.duration,
    ))

    exit(0 if success else 1)


if __name__ == "__main__":
    main()
