# Gaps Round 10: Tenth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-9 (331 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/5389/5766/4733/3389/4566

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P2 | 3 | Minor correctness and robustness issues |
| Total | 3 | |

---

## P2 — Minor (3 bugs)

### Bug 1: PySipRunner.stop() blocks without releasing GIL
- **File**: `src/python/client.rs:332-354`
- **Issue**: `fn stop(&self)` calls `self.runtime.block_on(engine.hangup(&call_id))` without releasing the GIL. All other blocking methods in the same file (`call()`, `hangup()`, `send_audio()`, `recv_audio()`, etc.) correctly use `py.allow_threads()`. `PySipRunner.start()` was fixed in Round 9 (Bug 4) but `stop()` was missed. The GIL held during network I/O blocks all Python threads, potentially causing deadlock if another thread needs the GIL to complete an async callback.
- **Fix**: Add `py: Python<'_>` parameter, clone the `Arc<SipEngine>` out of the mutex, wrap the blocking loop in `py.allow_threads()`. Add separate `stop_inner()` method (without GIL release) for the `Drop` impl where no Python token is available.
- **Status**: [x] Fixed — added py parameter, wrapped block_on in py.allow_threads(), added stop_inner() for Drop

### Bug 2: next_sequence not updated when packet equals expected sequence
- **File**: `src/rtp/jitter.rs:222`
- **Issue**: The condition `Self::sequence_after(seq, self.next_sequence.unwrap())` only updates `next_sequence` when the incoming sequence is STRICTLY AFTER the current value. When packets arrive in order (100, 101, 102...), pushing seq=101 when `next_sequence=101` doesn't update to 102 because `sequence_after(101, 101)` returns FALSE. This leaves `next_sequence` stale, causing the NACK gap detector to generate spurious NACKs for already-received packets. FreeSWITCH's STFU buffer correctly tracks the highest received sequence.
- **Fix**: Change `Self::sequence_after(seq, ...)` to `!Self::sequence_before(seq, ...)` which is true when `seq >= next_sequence` in wraparound-aware comparison.
- **Status**: [x] Fixed — changed to !sequence_before for >= semantics

### Bug 3: Test assertion contradicts Bug #R8-2 fix for all-zero DTMF payload
- **File**: `src/rtp/dtmf.rs:1489-1493`
- **Issue**: `test_dtmf_payload_all_zero_rejected()` asserts that `DtmfPayload::parse(&[0,0,0,0]).is_none()`, but Bug #R8-2 (Round 8) removed the all-zero rejection code because `[0,0,0,0]` is a valid Digit '0' per RFC 4733 (event=0, is_end=false, volume=0, duration=0). The test was not updated to match the fix, so it will fail when executed.
- **Fix**: Update test to verify that `[0,0,0,0]` correctly parses as Digit '0' with expected field values.
- **Status**: [x] Fixed — test now asserts correct parse result for Digit '0'

---

## False Positives Rejected

1. **SIP Via hardcoded UDP in REFER** — Already documented as Bug #22 and fixed in prior rounds.
2. **TURN concurrent socket race** — Already documented as an architectural limitation. Would require redesign to fix.
3. **SRTP IV construction** — Verified correct per RFC 3711 §4.1.1. Confirmed by test_aes_cm_iv_salt_xor_at_offset_0.
4. **SRTP ROC estimation** — Verified correct per RFC 3711 §3.3.1. Half-sequence-space rule implemented correctly.
5. **Audio/VAD processing** — DC offset ×256 fixed-point confirmed intentional. All thresholds verified.
6. **RTCP 24-bit signed parsing** — Verified correct sign extension.

---

## Fix Status

| Phase | Bugs | Fixed | Remaining |
|-------|------|-------|-----------|
| P2 | 3 | 3 | 0 |
| **Total** | **3** | **3** | **0** |

---

## Cumulative Audit Summary (Rounds 1-10)

| Round | Found | P0 | Fixed |
|-------|-------|----|-------|
| 1 | 67 | 7 | 67 |
| 2 | 109 | 3 | 109 |
| 3 | 65 | 7 | 63 |
| 4 | 42 | 2 | 41 |
| 5 | 30 | 1 | 29 |
| 6 | 8 | 0 | 8 |
| 7 | 4 | 0 | 4 |
| 8 | 6 | 0 | 6 |
| 9 | 4 | 0 | 4 |
| 10 | 3 | 0 | 3 |
| **Total** | **338** | **20** | **334** |

Note: 4 bugs from earlier rounds were deferred as architectural limitations (not counted as fixed).
