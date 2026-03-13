# Gaps Round 12: Twelfth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-11 (342 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/3515/5389/5766/4733/3389/4566/3611/3264

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P2 | 4 | Minor correctness and robustness issues |
| Total | 4 | |

---

## P2 — Minor (4 bugs)

### Bug 1: VAD RMS calculation uses integer division before sqrt
- **File**: `src/rtp/vad.rs:419`
- **Issue**: `(sum_sq / n as u64) as f64).sqrt()` performs integer division before converting to float for sqrt. This truncates the fractional part, causing RMS to be slightly underestimated. For sum_sq=999, n=160: integer gives sqrt(6)=2.45, float gives sqrt(6.24)=2.50. Compounds over many frames and can affect WebRTC VAD sensitivity at thresholds.
- **Fix**: Cast to f64 before division: `(sum_sq as f64 / n as f64).sqrt()`.
- **Status**: [x] Fixed

### Bug 2: VAD DC offset estimate comment wrong about scaling factor
- **File**: `src/rtp/vad.rs:177`
- **Issue**: Comment says "exponential moving average, scaled by 16" but actual formula at line 354 uses α=255/256, making dc_estimate a ×256-scaled value (divided by 256 at line 363). Comment is misleading for maintainers.
- **Fix**: Change comment to "scaled by 256".
- **Status**: [x] Fixed

### Bug 3: Inbound SDP answer missing direction negotiation
- **File**: `src/sip/engine.rs:1107`
- **Issue**: When building SDP answer for inbound calls, `SdpBuilder::new().codecs().build()` produces SDP with implicit `sendrecv` direction regardless of what the remote offered. RFC 3264 §6 requires the answer direction to be the inverse of the offer: `sendonly` offer → `recvonly` answer, `recvonly` → `sendonly`, `inactive` → `inactive`. If the remote INVITE offers `sendonly` (call-on-hold from start), we incorrectly answer `sendrecv`.
- **Fix**: Parse remote SDP direction and pass `answer_direction()` to `SdpBuilder.direction()`.
- **Status**: [x] Fixed

### Bug 4: SDP parser accepts unknown address types instead of rejecting
- **File**: `src/sip/sdp.rs:446`
- **Issue**: When the connection line has an address type other than "IP4" or "IP6" (e.g., "IP8"), the parser logs a warning but continues, returning the parsed address. RFC 4566 only defines IP4 and IP6 as valid address types. Accepting unknown types could mask malformed SDP from broken endpoints.
- **Fix**: Return error instead of warning for unknown address types.
- **Status**: [x] Fixed

---

## False Positives Rejected

1. **SRTP module** — All paths verified correct. 0 bugs.
2. **DTMF module** — Sonus END packet seq numbers are intentional FreeSWITCH compat; min duration (50ms) matches FreeSWITCH; u16 clamping required for 16-bit field; wraparound threshold at 0x8000 is balanced. 0 bugs.
3. **NAT/STUN/TURN module** — All paths verified correct. 0 bugs.
4. **RTP/jitter** — NTP timestamp truncation to u32 is correct (NTP wraps at 2036 by design); initial buffering `.min()` is intentionally conservative. 0 bugs.
5. **SIP Contact URI extraction** — `trimmed[1..end+1]` is correct; `end` is position in stripped string so arithmetic accounts for the offset. 0 bugs.
6. **DC offset EMA** — Formula `dc_estimate * 255/256 + frame_avg` converges to `frame_avg * 256`, correctly divided by 256 on use (line 363). NOT accumulating — it's fixed-point scaling. 0 bugs.
7. **CN amplitude** — Simple linear mapping (0-254) is intentional for low-level comfort noise. Not a dBov conversion bug.
8. **Via transport hardcoded UDP** — Already tracked as known TODO (Bug #22). Not new.
9. **Re-INVITE Route headers** — rsipstack's `dialog.reinvite()` handles routing internally at the dialog layer. Not needed.
10. **Session timers** — Known TODO (Bug #27). Not new.
11. **DTMF missing END timeout when RTP stops** — Wall-clock timeout fires on next audio packet; media timeout handles complete stream loss. Acceptable design.

---

## Fix Status

| Phase | Bugs | Fixed | Deferred |
|-------|------|-------|----------|
| P2 | 4 | 4 | 0 |
| **Total** | **4** | **4** | **0** |

---

## Cumulative Audit Summary (Rounds 1-12)

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
| **Total** | **350** | **20** | **346** |

Note: 4 bugs across all rounds deferred as architectural limitations or requiring structural changes.
