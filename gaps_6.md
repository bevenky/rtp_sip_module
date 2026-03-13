# Gaps Round 6: Sixth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-5 (311 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/5389/5766/4733/3389/4566

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P1 | 4 | Significant bugs affecting functionality |
| P2 | 4 | Minor issues, edge cases, robustness |
| Total | 8 | |

---

## P1 — Significant (4 bugs)

### Bug 1: REFER blocked in Hold state — violates RFC 3261
- **File**: `src/sip/engine.rs:3124`
- **Issue**: `send_refer()` checks `if sess.state != CallState::Active` and rejects the request. RFC 3261 allows REFER in any established dialog, including when on hold. FreeSWITCH allows REFER during hold — transferring a held call is a standard PBX operation (park-and-transfer, consultative transfer). The check should allow both `Active` and `Hold` states.
- **Fix**: Change condition to `if sess.state != CallState::Active && sess.state != CallState::Hold`.
- **Status**: [x] Fixed — condition allows Active or Hold states

### Bug 2: Failed/timed-out REFER sets refer_pending=true and emits TransferInitiated
- **File**: `src/sip/engine.rs:3266-3279`
- **Issue**: When the REFER transaction gets no final response (`Ok(None)`) or times out (`Err(_)`), the code logs a warning but falls through to lines 3275-3279 which unconditionally set `refer_pending = true`, `refer_target = Some(target)`, and emit `CallEvent::TransferInitiated`. The application sees a successful transfer initiation when the REFER actually failed. This can cause incorrect transfer tracking and NOTIFY confusion.
- **Fix**: Return `Err(...)` in both the `Ok(None)` and `Err(_)` branches instead of falling through to the success path.
- **Status**: [x] Fixed — Ok(None) and Err branches now return Err

### Bug 3: PyRtpSession.start() blocks Python GIL during async operation
- **File**: `src/python/session.rs:162-184`
- **Issue**: `start()` is defined as `fn start(&mut self) -> PyResult<()>` without a `py: Python<'_>` parameter. Line 182 calls `self.runtime.block_on(async { RtpEngine::new(...).await })` which blocks the current thread without releasing the Python GIL. Other blocking methods in the codebase (client.rs lines 402, 519, 557) correctly use `py.allow_threads(|| ...)` to release the GIL. While `RtpEngine::new()` is typically fast (UDP socket bind), it can block if the OS is under load or if address resolution is needed.
- **Fix**: Add `py: Python<'_>` parameter and wrap: `py.allow_threads(|| self.runtime.block_on(async { ... }))`.
- **Status**: [x] Fixed — py.allow_threads() wraps block_on

### Bug 4: DTMF detector silently loses digits when new digit arrives before timeout
- **File**: `src/rtp/dtmf.rs:1139-1143`
- **Issue**: When a new digit arrives (different RTP timestamp) while a previous digit is still in progress (no END packet received), `current_digit` is overwritten without first detecting the previous digit. The 5-second timeout only fires if enough RTP timestamp or wall-clock time has elapsed — but if a new digit arrives quickly (e.g., 200ms later), the timeout hasn't fired yet and the previous digit is silently dropped. FreeSWITCH always force-completes the previous digit when detecting a timestamp change.
- **Fix**: Before overwriting `current_digit`, check if it's `Some` and force-complete it by pushing a `DetectedDtmf` to the `detected_queue` with `is_end: false`.
- **Status**: [x] Fixed — force-completes previous digit before starting new one

---

## P2 — Minor (4 bugs)

### Bug 5: DTMF event code not validated in serialize()
- **File**: `src/rtp/dtmf.rs:286-293`
- **Issue**: `serialize()` writes `self.event` directly to the output byte without validating it is in the valid range 0-15. While `DtmfEvent::code()` always produces valid codes, any code that directly constructs a `DtmfPayload` with an invalid event value will silently emit an RFC 4733-violating packet. Other fields (volume, duration) are already masked/bounded.
- **Fix**: Add `debug_assert!(self.event <= 15, "Invalid DTMF event code")` at the start of `serialize()`.
- **Status**: [x] Fixed — debug_assert added

### Bug 6: recv_dtmf() holds parking_lot lock without releasing GIL
- **File**: `src/python/client.rs:633-641`
- **Issue**: `recv_dtmf()` has no `py: Python<'_>` parameter. It acquires `self.engine.lock()` (parking_lot::Mutex) while holding the GIL. While parking_lot locks are typically microsecond-fast, lock contention from other threads could cause the GIL to be held unnecessarily. The blocking variant `recv_dtmf_blocking()` at line 656 correctly takes a `py` parameter and releases the GIL.
- **Fix**: Add `py: Python<'_>` parameter and wrap in `py.allow_threads(|| ...)`.
- **Status**: [x] Fixed — py.allow_threads() wraps engine.recv_dtmf()

### Bug 7: DTMF sender hardcodes initial_duration to 160 (20ms) regardless of ptime
- **File**: `src/rtp/dtmf.rs:601`, `src/rtp/engine.rs:1187`
- **Issue**: `let initial_duration = 160u16;` was hardcoded for 20ms at 8kHz. For systems using 10ms or 30ms ptime, the first DTMF packet's duration didn't match the actual interval, causing asymmetric timing. FreeSWITCH derives initial duration from the configured `samples_per_interval`.
- **Fix**: Added `interval_ms` parameter to `start_digit()`. Initial duration is now computed as `DtmfPayload::ms_to_timestamp(interval_ms)`. Engine passes actual ptime from `ptime_ms` config instead of hardcoded 20.
- **Status**: [x] Fixed — start_digit() takes interval_ms; engine uses configured ptime

### Bug 8: Sonus mode END packets share same timestamp instead of incrementing
- **File**: `src/rtp/dtmf.rs:667-676`
- **Issue**: In Sonus mode (where timestamps increment per-packet), `end_digit()` called `build_packet()` once and cloned the result 2 more times. Only the first END packet got the timestamp increment; the clones shared the same timestamp. FreeSWITCH calls `rtp_common_write()` for each END packet in Sonus mode, giving each its own incrementing timestamp.
- **Fix**: In Sonus mode, call `build_packet()` 3 times (each gets incrementing timestamp + sequence). In normal mode, keep RFC 4733 §2.5.1.3 behavior (identical seq/timestamp for all 3 END packets).
- **Status**: [x] Fixed — Sonus mode builds each END packet individually

---

## Fix Status

| Phase | Bugs | Fixed | Remaining |
|-------|------|-------|-----------|
| P1 | 4 | 4 | 0 |
| P2 | 4 | 4 | 0 |
| **Total** | **8** | **8** | **0** |
