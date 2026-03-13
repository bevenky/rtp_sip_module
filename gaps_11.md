# Gaps Round 11: Eleventh Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-10 (334 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/3515/5389/5766/4733/3389/4566/3611

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P2 | 8 | Minor correctness and robustness issues |
| Total | 8 | |

---

## P2 — Minor (8 bugs)

### Bug 1: Port allocation range_size formula off-by-one
- **File**: `src/rtp/engine.rs:65`
- **Issue**: Formula `((end - start) + 1) / 2` undercounts even ports when both start and end are even. For start=10000, end=10002: computes range_size=1, but there are 2 even ports (10000, 10002). Port 10002 is never tried. The Bug #38 comment claims this was fixed but the formula is still wrong.
- **Fix**: Changed to `((end - start) / 2) + 1` which correctly counts even ports in inclusive ranges.
- **Status**: [x] Fixed

### Bug 2: `is_media_timed_out()` ignores hold state
- **File**: `src/rtp/engine.rs:522-528`
- **Issue**: Uses raw `self.media_timeout_ms` (30s) instead of `effective_media_timeout()` which returns the hold timeout (30min) when on hold. During hold, callers polling this method get false timeout reports even though the background task correctly uses the hold timeout. Inconsistency between public API and internal behavior.
- **Fix**: Changed to use `self.effective_media_timeout()` and `Duration` comparison.
- **Status**: [x] Fixed

### Bug 3: REFER From/To tags swapped for inbound (server dialog) calls
- **File**: `src/sip/engine.rs:3244-3248`
- **Issue**: For server dialogs, rsipstack's `dialog_id.from_tag` is the remote caller's tag, but it's placed in the REFER's From header. RFC 3261 §12.2.1.1 requires From tag = local tag, To tag = remote tag. Works for outbound calls (client dialog) but wrong for inbound calls.
- **Fix**: Determine `local_tag`/`remote_tag` based on `is_client_dialog` flag and use them correctly.
- **Status**: [x] Fixed

### Bug 4: REFER missing Route headers for proxied dialogs
- **File**: `src/sip/engine.rs:3239-3268`
- **Issue**: The manually-constructed REFER request contains no Route headers. RFC 3261 §12.2.1.1 mandates all in-dialog requests include the dialog's route set from Record-Route. Without Route headers, REFERs bypass proxy chains, failing in production SIP deployments with proxies. Requires adding a `route_set` field to `CallSession` populated from Record-Route headers.
- **Fix**: Added `route_set: Vec<String>` to `CallSession`. Extract Record-Route from INVITE (UAS, same order) and from 200 OK (UAC, reversed). Include as Route headers in REFER request.
- **Status**: [x] Fixed

### Bug 5: RTCP XR VoIP Metrics block_length wrong (7 instead of 8)
- **File**: `src/rtp/rtcp.rs:662`
- **Issue**: RFC 3611 §3 defines block_length as "including the header, in 32-bit words minus one". The VoIP Metrics block is 36 bytes (4 header + 4 SSRC + 28 metrics) = 9 words, so block_length should be 9-1=8. Code writes 7 (body only, excluding header and SSRC). Standards-compliant receivers will miscalculate the next XR block offset.
- **Fix**: Changed from 7 to 8.
- **Status**: [x] Fixed

### Bug 6: PySipRunner.start() calls engine.start() without tokio runtime context
- **File**: `src/python/client.rs:317`
- **Issue**: `SipEngine::start()` calls `tokio::spawn` which requires an active tokio runtime context. The runtime guard from `py.allow_threads` was dropped when that closure returned (line 300), leaving no context at line 317. This causes a runtime panic. `PyRtpSession::start()` in session.rs correctly handles this with `let _guard = self.runtime.enter()` at line 201.
- **Fix**: Added `let _guard = self.runtime.enter()` before calling `engine.start()`.
- **Status**: [x] Fixed

### Bug 7: PyRtpSession.set_remote() silently drops address when called before start()
- **File**: `src/python/session.rs:150-159`
- **Issue**: When `self.engine` is `None` (before `start()`), the parsed address is silently discarded and `Ok(())` is returned. The method takes `&self` so it cannot update `self.remote_addr`. The user gets no indication the operation failed.
- **Fix**: Return `PyRuntimeError` when engine is None with guidance to call `start()` first or pass `remote_addr` to constructor.
- **Status**: [x] Fixed

### Bug 8: TURN test missing `mut` on client variable
- **File**: `src/nat/turn/client.rs:1953`
- **Issue**: `test_refresh_with_mock_server` declares `let client` but `refresh()` takes `&mut self`. This is a compilation error in test code.
- **Fix**: Changed to `let mut client`.
- **Status**: [x] Fixed

---

## False Positives Rejected

1. **SRTP module** — All paths verified correct (IV construction, PRF derivation, ROC estimation, replay window, auth tags, MKI handling). 0 bugs.
2. **DTMF module** — All paths verified correct (state machine, wraparound, Sonus compat, reordering guards, payload parsing). 0 bugs.
3. **VAD module** — DC offset ×256 fixed-point confirmed intentional. All thresholds verified. 0 bugs.
4. **SDP parsing** — Codec negotiation, attribute handling, connection line parsing all correct. 0 bugs.

---

## Fix Status

| Phase | Bugs | Fixed | Deferred |
|-------|------|-------|----------|
| P2 | 8 | 8 | 0 |
| **Total** | **8** | **8** | **0** |

---

## Cumulative Audit Summary (Rounds 1-11)

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
| 11 | 8 | 0 | 8 |
| **Total** | **346** | **20** | **342** |

Note: 4 bugs across all rounds deferred as architectural limitations or requiring structural changes.
