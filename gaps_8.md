# Gaps Round 8: Eighth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-7 (321 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/5389/5766/4733/3389/4566

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P2 | 6 | Minor correctness and robustness issues |
| Total | 6 | |

---

## P2 — Minor (5 bugs)

### Bug 1: Jitter buffer allows duplicate packets with seq == last_played_sequence
- **File**: `src/rtp/jitter.rs:171-176`
- **Issue**: `sequence_before(seq, last_played)` returns `false` when `seq == last_played` (delta=0, `0 > 0` is false). A retransmitted packet with the same sequence number as the last played packet passes the "too old" check and is re-inserted into the buffer. FreeSWITCH's STFU buffer rejects packets with `seq <= last_played`.
- **Fix**: Add `|| seq == last_played` to the drop condition.
- **Status**: [x] Fixed — added `|| seq == last_played` to drop condition

### Bug 2: DTMF all-zero payload check is dead code (never fires)
- **File**: `src/rtp/dtmf.rs:264-273`
- **Issue**: Line 264 returns `None` for `event > 15`. Line 271 checks `data[0] > 15 && ...` which can never be true since `data[0]` is guaranteed `<= 15` by line 264. The all-zero rejection check is dead code. The behavior is actually correct (accepting `[0,0,0,0]` as valid Digit '0' per RFC 4733), but the dead code is misleading. Remove the dead check and its comment.
- **Fix**: Remove lines 268-273 (dead code).
- **Status**: [x] Fixed — removed dead code, added explanatory comment

### Bug 3: CN pacing timestamp updated before packet send
- **File**: `src/rtp/engine.rs:1082`
- **Issue**: `last_cn_timestamp` is updated at line 1082 *before* `socket.send_to()` at line 1111. If the send fails (network error), the timestamp is already set, suppressing retries for the entire pacing interval (~1200ms at 20ms ptime). Compare with `send_audio()` (line 1018) which correctly updates `last_audio_sent` *after* successful send.
- **Fix**: Move `*last_cn = Some(Instant::now())` to after line 1111 (after successful send).
- **Status**: [x] Fixed — timestamp update moved after successful send_to()

### Bug 4: Contact URI header parameters not stripped (no angle brackets)
- **File**: `src/sip/engine.rs:1989-1990`
- **Issue**: When Contact header has no angle brackets (e.g., `Contact: sip:alice@host;q=0.7`), the else branch stores the entire string including header parameters in `remote_contact`. Per RFC 3261 Section 20.10, parameters after a URI without angle brackets are header parameters, not URI parameters. The stored value is later used as Request-URI in REFER (line 3182), making the Request-URI invalid. Same pattern at line 2225.
- **Fix**: Strip parameters: `trimmed.split(';').next().unwrap_or(trimmed).to_string()`.
- **Status**: [x] Fixed — both 200 OK and 180/183 handlers strip header params

### Bug 5: REFER Via header gets 0.0.0.0 when local_addr is unspecified
- **File**: `src/sip/engine.rs:3192-3216`
- **Issue**: When `local_addr` is `0.0.0.0`, the code tries to parse a SIP URI (`sip:user@host`) as a `SocketAddr` (line 3195), which always fails. The fallback `format!("{}:{}", request_uri_str, 5060)` creates `sip:user@host:5060` — also not a valid SocketAddr. All paths fail, falling through to `self.config.local_addr` (0.0.0.0). The Via header gets `0.0.0.0`, violating RFC 3261 Section 8.1.1.2.
- **Fix**: Extract host from SIP URI before parsing: strip `sip:`/`sips:` prefix, `user@` part, and URI parameters.
- **Status**: [x] Fixed — SIP URI host extraction added before SocketAddr parsing

### Bug 6: SRTP ROC estimation off-by-one at sequence diff boundary (0x8000)
- **File**: `src/rtp/srtp.rs:786`
- **Issue**: In `estimate_roc()`, the forward case uses `diff < 0x8000` while the backward case (line 796) uses `diff > 0x8000`. When `diff == 0x8000` exactly, the forward case returns `ROC-1` (late packet) while the backward case returns current `ROC` (reorder). RFC 3711 Section 3.3.1 uses strict `>` for both directions, so the boundary should use current ROC in both cases. The asymmetry causes authentication failure when a packet arrives with seq exactly 32768 higher than `s_l`.
- **Fix**: Changed forward case to `if diff > 0x8000 { roc.wrapping_sub(1) } else { roc }` to match backward case symmetry.
- **Status**: [x] Fixed — forward case now uses `diff > 0x8000` matching RFC 3711

---

## False Positives Rejected

1. **Sonus END packets with different sequence numbers** — By design. Sonus compatibility mode intentionally gives each packet unique seq+timestamp, matching FreeSWITCH's `rtp_common_write()` behavior.
2. **SRTP ROC estimation edge cases** — Verified correct implementation matching RFC 3711 Appendix A.
3. **NAT/STUN/TURN code** — No bugs found, all RFC compliance verified.
4. **Python bindings GIL safety** — All blocking operations properly wrapped in `py.allow_threads()`.
5. **SDP handling** — Parsing and generation verified correct.

---

## Fix Status

| Phase | Bugs | Fixed | Remaining |
|-------|------|-------|-----------|
| P2 | 6 | 6 | 0 |
| **Total** | **6** | **6** | **0** |
