# Gaps Round 9: Ninth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-8 (327 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/5389/5766/4733/3389/4566

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P2 | 4 | Minor correctness and robustness issues |
| Total | 4 | |

---

## P2 — Minor (4 bugs)

### Bug 1: Jitter estimate contaminated by late/rejected packets
- **File**: `src/rtp/jitter.rs:143-178`
- **Issue**: The jitter calculation (lines 149-163) and `last_arrival`/`last_timestamp` updates (lines 167-168) run BEFORE the old-packet rejection check (lines 174-178). When a late or retransmitted packet arrives and gets rejected, its arrival time and timestamp have already corrupted the jitter estimate and timing state. Subsequent packets compute jitter against the wrong baseline, causing inflated jitter estimates. FreeSWITCH's STFU buffer rejects stale packets before any statistics update.
- **Fix**: Move the old-packet rejection check before the jitter calculation and timestamp updates.
- **Status**: [x] Fixed — rejection check moved before jitter calculation

### Bug 2: DTMF duration wraparound detection off-by-one at 0x8000
- **File**: `src/rtp/dtmf.rs:1209`
- **Issue**: `last_dur > 0x8000` uses strict greater-than, failing when `last_dur` is exactly `0x8000` (4.096 seconds at 8kHz). A DTMF digit that runs for exactly this duration won't trigger wraparound detection, causing the reported duration to be truncated. Should be `>= 0x8000`.
- **Fix**: Change `last_dur > 0x8000` to `last_dur >= 0x8000`.
- **Status**: [x] Fixed — changed to `>= 0x8000`

### Bug 3: DTMF send loop hardcodes 20ms inter-packet sleep
- **File**: `src/rtp/engine.rs:1208`
- **Issue**: `tokio::time::sleep(Duration::from_millis(20))` is hardcoded instead of using the configured `ptime_ms`. When ptime is 10ms or 30ms, DTMF packets are sent at the wrong rate, causing timing mismatches. The `generate_digit()` call already uses the correct ptime for duration calculations.
- **Fix**: Use `self.ptime_ms.load(Ordering::Relaxed)` instead of hardcoded `20`.
- **Status**: [x] Fixed — uses `ptime_ms.load()` instead of hardcoded 20

### Bug 4: PySipRunner.start() blocks without releasing GIL
- **File**: `src/python/client.rs:271-297`
- **Issue**: `fn start(&self)` calls `runtime.block_on(SipEngine::new(...))` without releasing the GIL. All other blocking methods in the same file (`call()`, `hangup()`, `send_audio()`, etc.) correctly use `py.allow_threads()`. `PyRtpSession.start()` in `session.rs` was fixed in Round 6 but `PySipRunner.start()` was missed. The GIL held during network I/O blocks all Python threads.
- **Fix**: Add `py: Python<'_>` parameter and wrap `block_on` in `py.allow_threads()`.
- **Status**: [x] Fixed — added py parameter, wrapped block_on in py.allow_threads()

---

## False Positives Rejected

1. **VAD DC offset scaling** — Intentional ×256 fixed-point representation. `dc_estimate / 256` at line 363 extracts the actual DC value. The EMA converges correctly to `256 * actual_dc`.
2. **NAT MESSAGE-INTEGRITY hardcoded 20** — The value 20 equals HEADER_SIZE (correct). The calculation produces correct results.
3. **SRTP ROC overflow at 32-bit boundary** — Requires ~2539 years of continuous operation at 20ms ptime. Not a practical concern.
4. **SIP engine** — No new bugs found. All prior fixes verified.

---

## Fix Status

| Phase | Bugs | Fixed | Remaining |
|-------|------|-------|-----------|
| P2 | 4 | 4 | 0 |
| **Total** | **4** | **4** | **0** |
