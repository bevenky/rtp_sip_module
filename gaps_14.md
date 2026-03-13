# Gaps Round 14: Fourteenth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-13 (350 bugs fixed, including 4 deferred TODOs)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/3515/5389/5766/4733/3389/4566/3611/3264/4028

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P2 | 3 | Minor correctness and robustness issues |
| Total | 3 | |

---

## P2 — Minor (3 bugs)

### Bug 1: Session timer for inbound calls starts at INVITE time, not answer time
- **File**: `src/sip/engine.rs:1173` and `src/sip/engine.rs:1454`
- **Issue**: When an inbound INVITE arrives with a `Session-Expires` header, `process_response()` is called at line 1173. This internally calls `start()` (session_timer.rs:302), which sets `last_refresh = Instant::now()` and `active = true`. The call may ring for an extended period before the user calls `answer()`. When `answer()` runs (line 1454), it checks `is_active()` and spawns the monitoring task, but never calls `timer.refresh()` to reset `last_refresh`. This means the session timer has been counting since INVITE arrival, not since the call was answered. If the phone rings for more than half the Session-Expires interval, a refresh re-INVITE fires immediately after answer. If it rings for the full interval + 32s grace period, the call is immediately terminated.
- **FreeSWITCH comparison**: FreeSWITCH's `switch_core_session_enable_heartbeat()` only activates session timers on call answer, not on receiving the INVITE.
- **Fix**: Call `timer.refresh()` in `answer()` after sending 200 OK, before spawning the monitoring task.
- **Status**: [x] Fixed

### Bug 2: No registration refresh task spawned after 423 retry
- **File**: `src/sip/engine.rs:1641-1661`
- **Issue**: When the initial REGISTER gets a 423 (Interval Too Brief) response, the code retries with the server's Min-Expires value (lines 1640-1661). On success, it correctly updates state to Registered, stores the registration, and emits the event. However, it returns `Ok(())` at line 1661, which exits the function BEFORE reaching the refresh task spawn code at lines 1726-1744. The normal 200 OK path (line 1705) falls through to the refresh task spawn, but the 423 retry path does not. This means registrations established via 423 retry will never be refreshed and will expire silently.
- **FreeSWITCH comparison**: FreeSWITCH's `sofia_reg_handle_register_token()` always schedules a refresh timer regardless of whether the registration required a retry.
- **Fix**: Extracted `spawn_registration_refresh_task()` helper method and called it from both the normal and 423-retry registration paths.
- **Status**: [x] Fixed

### Bug 3: Concurrent next_event() calls get spurious "Runner not started" error
- **File**: `src/python/client.rs:826-843`
- **Issue**: The `next_event()` method uses a take/put-back pattern on the broadcast receiver: `.take()` at line 826, use during `py.allow_threads()`, then `= Some(rx)` at line 843. Between `.take()` and `= Some(rx)`, any concurrent Python thread calling `next_event()` finds the receiver as `None` and gets an error: "Runner not started". This is a race condition introduced by the Bug #40 fix. The error message is misleading — the runner IS started, the receiver is just temporarily borrowed by another thread.
- **FreeSWITCH comparison**: N/A (Python bindings are specific to this crate).
- **Fix**: Check `self.running` flag when receiver is `None`. If running, return `Ok(None)` with debug log (receiver temporarily borrowed). If not running, return the original error.
- **Status**: [x] Fixed

---

## False Positives Rejected (21 items)

### SRTP Module (0 bugs)
1-3. All paths verified correct — ROC underflow, MKI handling, KDR scope unchanged from R13.

### RTP/Jitter Module (0 bugs)
4. **DC offset EMA overflow** — Already verified in R12. Fixed-point ×256 scaling with /256 on use is correct.

### DTMF Module (0 bugs)
5-6. All paths verified correct — duration clamping, END packet sequences unchanged.

### Audio Processing Module (0 bugs)
7-8. All paths verified correct — RMS calculation (fixed in R12), CN generation, VAD thresholds.

### NAT/STUN/TURN Module (0 bugs)
9. **STUN RTO doubling without cap** — RFC 5389 §7.2.1 specifies doubling RTO after each retransmission. The Rm×RTO cap only applies to the final wait after the last retransmission, not to intermediate doublings. Current behavior is correct.
10. **TURN refresh timing jitter** — 80% threshold with 30s check interval provides sufficient margin. Not a bug.

### SIP Module (0 bugs, beyond confirmed items above)
11-18. Cancel/BYE race, Route set, SDP direction, Re-INVITE state, Digest auth, BYE before ACK, CSeq overflow, ReinviteGuard — all verified correct or already fixed in prior rounds.

### Python/SDP Module (0 bugs, beyond confirmed item above)
19-21. recv_audio runtime guard, SDP empty payload types, event serialization — all verified correct.

---

## Fix Status

| Phase | Bugs | Fixed | Deferred |
|-------|------|-------|----------|
| P2 | 3 | 3 | 0 |
| **Total** | **3** | **3** | **0** |

---

## Cumulative Audit Summary (Rounds 1-14)

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
| 12 | 4 | 0 | 4 |
| 13 | 0 | 0 | 0 |
| 14 | 3 | 0 | 3 |
| **Total** | **353** | **20** | **353** |

---

## Convergence Analysis

```
Round:  1    2    3    4    5    6    7    8    9   10   11   12   13   14
Bugs:  67  109   65   42   30    8    4    6    4    3    8    4    0    3
```

Round 13 was zero, Round 14 found 3 new bugs from the recently-implemented deferred TODO fixes (Bug #27 session timers, Bug #40 event resubscribe) and a pre-existing 423 retry path issue. The audit continues to converge.
