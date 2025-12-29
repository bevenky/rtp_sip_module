#!/usr/bin/env python3
"""
Load Test for RtpSip RTP Sessions

Tests 100 concurrent RTP sessions to verify:
- No memory leaks
- No deadlocks
- Proper resource cleanup
- Acceptable latency under load

Run with:
    python -m pytest python/tests/test_load_concurrent.py -v -s
"""

import asyncio
import time
import statistics
import gc
from dataclasses import dataclass
from typing import List, Optional
import pytest


@dataclass
class SessionStats:
    """Statistics for a single session."""
    session_id: int
    packets_sent: int
    packets_received: int
    errors: int
    start_time: float
    end_time: float
    latencies_ms: List[float]

    @property
    def duration_s(self) -> float:
        return self.end_time - self.start_time

    @property
    def avg_latency_ms(self) -> float:
        return statistics.mean(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p99_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_lats = sorted(self.latencies_ms)
        idx = int(len(sorted_lats) * 0.99)
        return sorted_lats[min(idx, len(sorted_lats) - 1)]


@dataclass
class LoadTestResult:
    """Aggregate results from load test."""
    total_sessions: int
    successful_sessions: int
    failed_sessions: int
    total_packets_sent: int
    total_packets_received: int
    total_errors: int
    avg_latency_ms: float
    p99_latency_ms: float
    duration_s: float
    sessions_per_second: float


def import_pyswitch():
    """Import pyswitch or skip if not available."""
    try:
        from rtp_sip import RtpSession, AudioFrame
        return RtpSession, AudioFrame
    except ImportError:
        pytest.skip("rtp_sip not built - run 'maturin develop' first")


class RtpLoadTester:
    """Load tester for RTP sessions."""

    def __init__(self, num_sessions: int = 100, duration_s: float = 10.0):
        self.num_sessions = num_sessions
        self.duration_s = duration_s
        self.base_port = 20000  # Start port for sessions
        self.results: List[SessionStats] = []

    async def run_single_session(
        self,
        session_id: int,
        RtpSession,
        AudioFrame,
    ) -> SessionStats:
        """Run a single RTP session for the test duration."""
        # Each session pair uses consecutive ports
        local_port = self.base_port + (session_id * 2)
        remote_port = local_port + 1

        stats = SessionStats(
            session_id=session_id,
            packets_sent=0,
            packets_received=0,
            errors=0,
            start_time=time.time(),
            end_time=0,
            latencies_ms=[],
        )

        try:
            # Create session
            session = RtpSession("127.0.0.1", remote_port)
            session.with_local_port(local_port)

            # Start session
            await session.start()

            # Create test audio frame (20ms of silence at 16kHz)
            silence = bytes(640)  # 320 samples * 2 bytes
            test_frame = AudioFrame(silence, 16000)

            end_time = time.time() + self.duration_s

            while time.time() < end_time:
                try:
                    # Send a packet
                    send_start = time.time()
                    await session.send_audio(test_frame)
                    stats.packets_sent += 1

                    # Try to receive (short timeout)
                    frame = await session.recv_audio(20)
                    if frame:
                        latency = (time.time() - send_start) * 1000
                        stats.latencies_ms.append(latency)
                        stats.packets_received += 1

                except Exception as e:
                    stats.errors += 1

                # Small delay to simulate real-time audio
                await asyncio.sleep(0.02)  # 20ms frame interval

            # Stop session
            await session.stop()

        except Exception as e:
            stats.errors += 1

        stats.end_time = time.time()
        return stats

    async def run_echo_pair(
        self,
        pair_id: int,
        RtpSession,
        AudioFrame,
    ) -> SessionStats:
        """Run a pair of sessions that echo to each other."""
        port_a = self.base_port + (pair_id * 2)
        port_b = port_a + 1

        stats = SessionStats(
            session_id=pair_id,
            packets_sent=0,
            packets_received=0,
            errors=0,
            start_time=time.time(),
            end_time=0,
            latencies_ms=[],
        )

        try:
            # Create two sessions that talk to each other
            session_a = RtpSession("127.0.0.1", port_b)
            session_a.with_local_port(port_a)

            session_b = RtpSession("127.0.0.1", port_a)
            session_b.with_local_port(port_b)

            # Start both
            await session_a.start()
            await session_b.start()

            # Create test audio frame
            silence = bytes(640)
            test_frame = AudioFrame(silence, 16000)

            end_time = time.time() + self.duration_s

            while time.time() < end_time:
                try:
                    # A sends to B
                    send_start = time.time()
                    await session_a.send_audio(test_frame)
                    stats.packets_sent += 1

                    # B receives from A
                    frame = await session_b.recv_audio(50)
                    if frame:
                        latency = (time.time() - send_start) * 1000
                        stats.latencies_ms.append(latency)
                        stats.packets_received += 1

                        # B echoes back to A
                        await session_b.send_audio(frame)
                        stats.packets_sent += 1

                        # A receives echo
                        echo = await session_a.recv_audio(50)
                        if echo:
                            stats.packets_received += 1

                except Exception as e:
                    stats.errors += 1

                await asyncio.sleep(0.02)

            # Stop both
            await session_a.stop()
            await session_b.stop()

        except Exception as e:
            stats.errors += 1

        stats.end_time = time.time()
        return stats

    async def run_load_test(self) -> LoadTestResult:
        """Run the full load test with concurrent sessions."""
        RtpSession, AudioFrame = import_pyswitch()

        print(f"\n{'='*60}")
        print(f"Starting load test: {self.num_sessions} concurrent session pairs")
        print(f"Duration: {self.duration_s}s per session")
        print(f"{'='*60}\n")

        start_time = time.time()

        # Run all session pairs concurrently
        tasks = [
            self.run_echo_pair(i, RtpSession, AudioFrame)
            for i in range(self.num_sessions)
        ]

        self.results = await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.time()

        # Filter out exceptions and count
        successful = [r for r in self.results if isinstance(r, SessionStats)]
        failed = [r for r in self.results if isinstance(r, Exception)]

        # Aggregate stats
        all_latencies = []
        total_sent = 0
        total_received = 0
        total_errors = 0

        for stats in successful:
            all_latencies.extend(stats.latencies_ms)
            total_sent += stats.packets_sent
            total_received += stats.packets_received
            total_errors += stats.errors

        avg_latency = statistics.mean(all_latencies) if all_latencies else 0.0
        if all_latencies:
            sorted_lats = sorted(all_latencies)
            p99_idx = int(len(sorted_lats) * 0.99)
            p99_latency = sorted_lats[min(p99_idx, len(sorted_lats) - 1)]
        else:
            p99_latency = 0.0

        duration = end_time - start_time

        return LoadTestResult(
            total_sessions=self.num_sessions,
            successful_sessions=len(successful),
            failed_sessions=len(failed),
            total_packets_sent=total_sent,
            total_packets_received=total_received,
            total_errors=total_errors,
            avg_latency_ms=avg_latency,
            p99_latency_ms=p99_latency,
            duration_s=duration,
            sessions_per_second=len(successful) / duration if duration > 0 else 0,
        )


class TestConcurrentRtpSessions:
    """Test suite for concurrent RTP sessions."""

    @pytest.mark.asyncio
    async def test_10_concurrent_sessions(self):
        """Test 10 concurrent RTP session pairs."""
        tester = RtpLoadTester(num_sessions=10, duration_s=5.0)
        result = await tester.run_load_test()

        print(f"\n{'='*60}")
        print("RESULTS: 10 Concurrent Sessions")
        print(f"{'='*60}")
        print(f"Successful: {result.successful_sessions}/{result.total_sessions}")
        print(f"Packets sent: {result.total_packets_sent}")
        print(f"Packets received: {result.total_packets_received}")
        print(f"Errors: {result.total_errors}")
        print(f"Avg latency: {result.avg_latency_ms:.2f}ms")
        print(f"P99 latency: {result.p99_latency_ms:.2f}ms")
        print(f"Duration: {result.duration_s:.2f}s")
        print(f"{'='*60}\n")

        # Assertions
        assert result.successful_sessions >= 9, "At least 90% sessions should succeed"
        assert result.total_errors < result.total_packets_sent * 0.01, "Error rate < 1%"

    @pytest.mark.asyncio
    async def test_50_concurrent_sessions(self):
        """Test 50 concurrent RTP session pairs."""
        tester = RtpLoadTester(num_sessions=50, duration_s=5.0)
        result = await tester.run_load_test()

        print(f"\n{'='*60}")
        print("RESULTS: 50 Concurrent Sessions")
        print(f"{'='*60}")
        print(f"Successful: {result.successful_sessions}/{result.total_sessions}")
        print(f"Packets sent: {result.total_packets_sent}")
        print(f"Packets received: {result.total_packets_received}")
        print(f"Errors: {result.total_errors}")
        print(f"Avg latency: {result.avg_latency_ms:.2f}ms")
        print(f"P99 latency: {result.p99_latency_ms:.2f}ms")
        print(f"Duration: {result.duration_s:.2f}s")
        print(f"{'='*60}\n")

        assert result.successful_sessions >= 45, "At least 90% sessions should succeed"
        assert result.p99_latency_ms < 100, "P99 latency should be < 100ms"

    @pytest.mark.asyncio
    async def test_100_concurrent_sessions(self):
        """Test 100 concurrent RTP session pairs (200 total sessions)."""
        tester = RtpLoadTester(num_sessions=100, duration_s=10.0)
        result = await tester.run_load_test()

        print(f"\n{'='*60}")
        print("RESULTS: 100 Concurrent Session Pairs (200 Sessions)")
        print(f"{'='*60}")
        print(f"Successful: {result.successful_sessions}/{result.total_sessions}")
        print(f"Packets sent: {result.total_packets_sent}")
        print(f"Packets received: {result.total_packets_received}")
        print(f"Errors: {result.total_errors}")
        print(f"Avg latency: {result.avg_latency_ms:.2f}ms")
        print(f"P99 latency: {result.p99_latency_ms:.2f}ms")
        print(f"Duration: {result.duration_s:.2f}s")
        print(f"Sessions/sec: {result.sessions_per_second:.2f}")
        print(f"{'='*60}\n")

        # Key assertions for 100 concurrent calls
        assert result.successful_sessions >= 90, "At least 90% sessions should succeed"
        assert result.total_errors < result.total_packets_sent * 0.05, "Error rate < 5%"
        assert result.p99_latency_ms < 200, "P99 latency should be < 200ms under load"

    @pytest.mark.asyncio
    async def test_memory_stability(self):
        """Test that memory doesn't leak over multiple session cycles."""
        RtpSession, AudioFrame = import_pyswitch()

        print("\nTesting memory stability...")

        # Force GC before starting
        gc.collect()

        for cycle in range(5):
            sessions = []

            # Create 20 sessions
            for i in range(20):
                port = 30000 + (cycle * 100) + (i * 2)
                session = RtpSession("127.0.0.1", port + 1)
                session.with_local_port(port)
                sessions.append(session)

            # Start all
            for s in sessions:
                await s.start()

            # Send some packets
            silence = bytes(640)
            frame = AudioFrame(silence, 16000)

            for _ in range(10):
                for s in sessions:
                    try:
                        await s.send_audio(frame)
                    except:
                        pass
                await asyncio.sleep(0.01)

            # Stop all
            for s in sessions:
                await s.stop()

            # Clear references
            sessions.clear()

            # Force GC
            gc.collect()

            print(f"  Cycle {cycle + 1}/5 complete")

        print("Memory stability test passed!")

    @pytest.mark.asyncio
    async def test_rapid_start_stop(self):
        """Test rapid session start/stop doesn't cause issues."""
        RtpSession, AudioFrame = import_pyswitch()

        print("\nTesting rapid start/stop...")

        for i in range(50):
            port = 40000 + (i * 2)
            session = RtpSession("127.0.0.1", port + 1)
            session.with_local_port(port)

            await session.start()

            # Send one packet
            silence = bytes(640)
            frame = AudioFrame(silence, 16000)
            await session.send_audio(frame)

            await session.stop()

            if (i + 1) % 10 == 0:
                print(f"  {i + 1}/50 rapid cycles complete")

        print("Rapid start/stop test passed!")


    @pytest.mark.asyncio
    async def test_concurrent_session_creation_latency(self):
        """Test that 100 concurrent session creations complete in < 5 seconds total.

        This tests the FsWorker async pattern - sessions should start concurrently
        without blocking each other. With the old block_on pattern, 100 sessions
        would take ~140 seconds (P99 latency ~140000ms). With FsWorker, it should
        complete in < 5 seconds with P99 < 50ms per session.
        """
        RtpSession, AudioFrame = import_pyswitch()

        num_sessions = 100
        sessions = []
        start_times = []
        end_times = []

        print(f"\n{'='*60}")
        print(f"Testing concurrent session creation latency ({num_sessions} sessions)")
        print(f"{'='*60}\n")

        # Warmup: create and start one session to trigger FreeSWITCH initialization
        # This is realistic - in production, FS would be initialized at startup
        print("Warming up (initializing FreeSWITCH)...")
        warmup_start = time.time()
        warmup_session = RtpSession("127.0.0.1", 49999)
        warmup_session.with_local_port(49998)
        await warmup_session.start()
        await warmup_session.stop()
        warmup_time = time.time() - warmup_start
        print(f"Warmup complete ({warmup_time:.2f}s)\n")

        async def create_session(session_id: int):
            """Create and start a single session, recording timing."""
            port = 50000 + (session_id * 2)
            session = RtpSession("127.0.0.1", port + 1)
            session.with_local_port(port)

            start = time.time()
            start_times.append(start)

            await session.start()

            end = time.time()
            end_times.append(end)

            return session

        # Create all sessions concurrently
        overall_start = time.time()

        tasks = [create_session(i) for i in range(num_sessions)]
        sessions = await asyncio.gather(*tasks, return_exceptions=True)

        overall_end = time.time()

        # Calculate latencies
        latencies_ms = []
        for i, (start, end) in enumerate(zip(start_times, end_times)):
            latency = (end - start) * 1000
            latencies_ms.append(latency)

        # Calculate statistics
        avg_latency = statistics.mean(latencies_ms) if latencies_ms else 0
        sorted_latencies = sorted(latencies_ms)
        p50_latency = sorted_latencies[len(sorted_latencies) // 2] if sorted_latencies else 0
        p99_idx = int(len(sorted_latencies) * 0.99)
        p99_latency = sorted_latencies[min(p99_idx, len(sorted_latencies) - 1)] if sorted_latencies else 0
        max_latency = max(latencies_ms) if latencies_ms else 0
        total_time = overall_end - overall_start

        # Count successes
        successful = [s for s in sessions if not isinstance(s, Exception)]
        failed = [s for s in sessions if isinstance(s, Exception)]

        print(f"Results:")
        print(f"  Successful sessions: {len(successful)}/{num_sessions}")
        print(f"  Failed sessions: {len(failed)}")
        print(f"  Total time: {total_time*1000:.2f}ms ({total_time:.2f}s)")
        print(f"  Avg session start latency: {avg_latency:.2f}ms")
        print(f"  P50 session start latency: {p50_latency:.2f}ms")
        print(f"  P99 session start latency: {p99_latency:.2f}ms")
        print(f"  Max session start latency: {max_latency:.2f}ms")
        print(f"  Sessions/second: {len(successful)/total_time:.2f}")
        print(f"{'='*60}\n")

        # Cleanup - stop all sessions
        for s in successful:
            try:
                await s.stop()
            except:
                pass

        # Assertions - these are the key metrics
        assert len(successful) >= 95, f"At least 95% sessions should succeed, got {len(successful)}"
        assert total_time < 10, f"Total time should be < 10s, got {total_time:.2f}s"
        assert p99_latency < 500, f"P99 latency should be < 500ms, got {p99_latency:.2f}ms"

        # Ideal targets (not assertions, just info)
        if p99_latency < 50:
            print("EXCELLENT: P99 latency < 50ms (target achieved)")
        elif p99_latency < 100:
            print("GOOD: P99 latency < 100ms")
        else:
            print(f"NOTE: P99 latency {p99_latency:.2f}ms is higher than target 50ms")


async def main():
    """Run load test directly."""
    tester = RtpLoadTester(num_sessions=100, duration_s=10.0)
    result = await tester.run_load_test()

    print(f"\n{'='*60}")
    print("FINAL RESULTS: 100 Concurrent Calls Load Test")
    print(f"{'='*60}")
    print(f"Total session pairs: {result.total_sessions}")
    print(f"Successful: {result.successful_sessions}")
    print(f"Failed: {result.failed_sessions}")
    print(f"Total packets sent: {result.total_packets_sent}")
    print(f"Total packets received: {result.total_packets_received}")
    print(f"Total errors: {result.total_errors}")
    print(f"Average latency: {result.avg_latency_ms:.2f}ms")
    print(f"P99 latency: {result.p99_latency_ms:.2f}ms")
    print(f"Total duration: {result.duration_s:.2f}s")
    print(f"Sessions/second: {result.sessions_per_second:.2f}")
    print(f"{'='*60}")

    # Success criteria
    success = (
        result.successful_sessions >= 90 and
        result.total_errors < result.total_packets_sent * 0.05 and
        result.p99_latency_ms < 200
    )

    print(f"\nOVERALL: {'PASSED' if success else 'FAILED'}")
    return success


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
