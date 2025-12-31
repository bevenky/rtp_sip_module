#!/usr/bin/env python3
"""
GIL Release Benchmark for siprunner

Tests that blocking operations properly release the GIL by running
concurrent Python threads during Rust blocking calls.

Expected behavior with GIL release:
- Multiple threads can run concurrently
- Counter increments happen during blocking waits
- Total operations >> single-threaded baseline

Without GIL release:
- Threads would be serialized
- Counter would barely increment during waits
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from siprunner import RtpSession


class GILBenchmark:
    """Benchmark GIL release in siprunner operations"""

    def __init__(self):
        self.counter = 0
        self.lock = threading.Lock()
        self.running = True

    def increment_counter(self):
        """Background thread that increments counter while GIL should be released"""
        while self.running:
            with self.lock:
                self.counter += 1
            # Small sleep to avoid busy-wait
            time.sleep(0.0001)  # 0.1ms

    def get_counter(self):
        with self.lock:
            return self.counter

    def reset(self):
        with self.lock:
            self.counter = 0
        self.running = True


def benchmark_recv_audio_gil_release():
    """
    Benchmark: recv_audio() should release GIL during timeout wait

    If GIL is properly released, background counter thread will increment
    many times during the blocking recv_audio() call.
    """
    print("\n=== Benchmark: recv_audio() GIL Release ===")

    bench = GILBenchmark()

    # Create RTP session
    session = RtpSession(local_addr="0.0.0.0:0", codec="PCMU")
    session.start()

    # Start background counter thread
    counter_thread = threading.Thread(target=bench.increment_counter)
    counter_thread.daemon = True
    counter_thread.start()

    # Reset counter
    bench.reset()
    start_time = time.perf_counter()

    # Call blocking recv_audio with timeout (should release GIL)
    timeout_ms = 100  # 100ms timeout
    num_calls = 10

    for _ in range(num_calls):
        # This should block for ~timeout_ms but release GIL
        result = session.recv_audio(timeout_ms)
        # Result should be None (no data available)

    elapsed = time.perf_counter() - start_time
    bench.running = False
    counter_thread.join(timeout=1.0)

    final_count = bench.get_counter()

    session.stop()

    # Analysis
    expected_wait_time = (timeout_ms * num_calls) / 1000.0  # in seconds
    increments_per_second = final_count / elapsed if elapsed > 0 else 0

    print(f"  Blocking time: {elapsed*1000:.1f}ms (expected ~{expected_wait_time*1000:.0f}ms)")
    print(f"  Counter increments: {final_count:,}")
    print(f"  Increments/second: {increments_per_second:,.0f}")

    # With GIL release, we expect many increments (thousands)
    # Without GIL release, counter would be near zero during waits
    gil_released = final_count > 100  # Conservative threshold

    if gil_released:
        print(f"  Result: PASS - GIL properly released ({final_count:,} increments)")
    else:
        print(f"  Result: FAIL - GIL may not be released ({final_count} increments)")

    return gil_released, final_count, elapsed


def benchmark_concurrent_sessions():
    """
    Benchmark: Multiple RTP sessions should work concurrently

    If GIL is properly released, multiple sessions can recv_audio
    simultaneously without blocking each other.
    """
    print("\n=== Benchmark: Concurrent Sessions ===")

    num_sessions = 4
    timeout_ms = 50
    calls_per_session = 5

    sessions = []
    for i in range(num_sessions):
        session = RtpSession(local_addr="0.0.0.0:0", codec="PCMU")
        session.start()
        sessions.append(session)

    def session_worker(session_id, session):
        """Worker that calls recv_audio multiple times"""
        start = time.perf_counter()
        for _ in range(calls_per_session):
            session.recv_audio(timeout_ms)
        elapsed = time.perf_counter() - start
        return session_id, elapsed

    # Run all sessions concurrently
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=num_sessions) as executor:
        futures = [
            executor.submit(session_worker, i, sessions[i])
            for i in range(num_sessions)
        ]
        results = [f.result() for f in as_completed(futures)]

    total_elapsed = time.perf_counter() - start_time

    # Cleanup
    for session in sessions:
        session.stop()

    # Analysis
    sequential_time = (timeout_ms * calls_per_session * num_sessions) / 1000.0
    parallel_time = (timeout_ms * calls_per_session) / 1000.0

    print(f"  Sessions: {num_sessions}")
    print(f"  Calls per session: {calls_per_session}")
    print(f"  Timeout per call: {timeout_ms}ms")
    print(f"  Total elapsed: {total_elapsed*1000:.1f}ms")
    print(f"  Sequential would be: ~{sequential_time*1000:.0f}ms")
    print(f"  Parallel ideal: ~{parallel_time*1000:.0f}ms")

    # Speedup calculation
    speedup = sequential_time / total_elapsed if total_elapsed > 0 else 0
    efficiency = speedup / num_sessions * 100

    print(f"  Speedup: {speedup:.2f}x")
    print(f"  Parallel efficiency: {efficiency:.1f}%")

    # With GIL release, speedup should be close to num_sessions
    # Without GIL release, speedup would be ~1x (serialized)
    gil_released = speedup > 1.5  # At least 1.5x speedup expected

    if gil_released:
        print(f"  Result: PASS - Concurrent execution ({speedup:.2f}x speedup)")
    else:
        print(f"  Result: FAIL - Appears serialized ({speedup:.2f}x speedup)")

    return gil_released, speedup, total_elapsed


def benchmark_event_loop_responsiveness():
    """
    Benchmark: Background work during event wait simulation

    Simulates a real-world scenario where Python code needs to
    do work while waiting for SIP events.
    """
    print("\n=== Benchmark: Event Loop Responsiveness ===")

    bench = GILBenchmark()

    # Create session to simulate event waiting
    session = RtpSession(local_addr="0.0.0.0:0", codec="PCMU")
    session.start()

    results = {
        'background_work': 0,
        'blocking_calls': 0,
    }

    def background_worker():
        """Simulates background processing (e.g., audio processing)"""
        work_done = 0
        while bench.running:
            # Simulate some CPU work
            _ = sum(range(100))
            work_done += 1
            time.sleep(0.0001)
        return work_done

    def blocking_worker():
        """Makes blocking calls that should release GIL"""
        calls = 0
        while bench.running:
            session.recv_audio(10)  # 10ms timeout
            calls += 1
        return calls

    # Run both workers concurrently
    duration = 0.5  # 500ms test

    with ThreadPoolExecutor(max_workers=2) as executor:
        bg_future = executor.submit(background_worker)
        block_future = executor.submit(blocking_worker)

        time.sleep(duration)
        bench.running = False

        results['background_work'] = bg_future.result()
        results['blocking_calls'] = block_future.result()

    session.stop()

    print(f"  Test duration: {duration*1000:.0f}ms")
    print(f"  Background work units: {results['background_work']:,}")
    print(f"  Blocking calls made: {results['blocking_calls']}")

    # With GIL release, both should have significant activity
    bg_rate = results['background_work'] / duration
    block_rate = results['blocking_calls'] / duration

    print(f"  Background rate: {bg_rate:,.0f}/sec")
    print(f"  Blocking call rate: {block_rate:.0f}/sec")

    # Success if background work is substantial during blocking
    gil_released = results['background_work'] > 100 and results['blocking_calls'] > 10

    if gil_released:
        print(f"  Result: PASS - Both workers ran concurrently")
    else:
        print(f"  Result: FAIL - Workers may be serialized")

    return gil_released, results


def run_all_benchmarks():
    """Run all GIL benchmarks and summarize results"""
    print("=" * 60)
    print("siprunner GIL Release Benchmarks")
    print("=" * 60)

    results = {}

    # Benchmark 1: recv_audio GIL release
    passed, count, elapsed = benchmark_recv_audio_gil_release()
    results['recv_audio'] = {'passed': passed, 'count': count, 'elapsed': elapsed}

    # Benchmark 2: Concurrent sessions
    passed, speedup, elapsed = benchmark_concurrent_sessions()
    results['concurrent'] = {'passed': passed, 'speedup': speedup, 'elapsed': elapsed}

    # Benchmark 3: Event loop responsiveness
    passed, work_results = benchmark_event_loop_responsiveness()
    results['responsiveness'] = {'passed': passed, 'results': work_results}

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    all_passed = all(r.get('passed', False) for r in results.values())

    for name, result in results.items():
        status = "PASS" if result.get('passed') else "FAIL"
        print(f"  {name}: {status}")

    print()
    if all_passed:
        print("All GIL benchmarks PASSED")
        print("Python threads can run during Rust blocking operations")
    else:
        print("Some benchmarks FAILED")
        print("GIL may not be properly released in some operations")

    return all_passed, results


if __name__ == "__main__":
    success, _ = run_all_benchmarks()
    exit(0 if success else 1)
