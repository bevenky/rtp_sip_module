# Gaps Round 7: Seventh Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-6 (319 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/5389/5766/4733/3389/4566

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| P1 | 1 | Arithmetic underflow in jitter buffer |
| P2 | 3 | Minor correctness and robustness issues |
| Total | 4 | |

---

## P1 — Significant (1 bug)

### Bug 1: Jitter buffer adapt_delay() can underflow u32 on subtraction
- **File**: `src/rtp/jitter.rs:489`
- **Issue**: `self.current_delay_ms = (self.current_delay_ms - 10).max(self.config.min_delay_ms)` — if `current_delay_ms` is less than 10 (possible when `min_delay_ms < 10`), the subtraction wraps to near `u32::MAX`. The subsequent `.max(min_delay_ms)` then selects `u32::MAX` instead of `min_delay_ms`, causing the delay to spike to ~49 days and the jitter buffer to never release packets. FreeSWITCH uses saturating arithmetic in its jitter buffer delay adaptation.
- **Fix**: Use `self.current_delay_ms.saturating_sub(10).max(self.config.min_delay_ms)`.
- **Status**: [x] Fixed — uses saturating_sub(10)

---

## P2 — Minor (3 bugs)

### Bug 2: DTMF all-zero payload rejection blocks valid Digit0
- **File**: `src/rtp/dtmf.rs:268-271`
- **Issue**: `if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 { return None; }` rejects a payload where event=0 (Digit '0'), end=false, volume=0, duration=0. This is a technically valid initial packet for Digit '0' per RFC 4733 (event code 0 is valid). The check was added to handle malformed equipment that sends all-zero payloads, but it also rejects this edge case. In practice, senders always start with duration > 0 (at least one ptime interval), so this rarely triggers.
- **Fix**: Changed condition to only reject when event > 15 (invalid event code) AND other bytes are zero. Valid Digit0 (event=0) is now accepted.
- **Status**: [x] Fixed — only rejects invalid event codes with zero payload

### Bug 3: Contact header not extracted from 180/183 early responses
- **File**: `src/sip/engine.rs:2173-2258`
- **Issue**: The `DialogState::Early` handler processes SDP and User-Agent from 180/183 responses but does not extract or store the Contact header. Per RFC 3261 §12.1.2, provisional responses that establish a dialog contain a Contact header that defines the remote target for subsequent in-dialog requests. Currently, Contact is only extracted from `DialogState::Confirmed` (200 OK, line 1981). If in-dialog requests (INFO, UPDATE) are sent during early media, they may use the wrong target.
- **Fix**: Added Contact extraction in Early handler using same logic as 200 OK handler.
- **Status**: [x] Fixed — Contact extracted from 180/183 responses

### Bug 4: TURN verify_response_integrity trusts msg_len without buffer bounds check
- **File**: `src/nat/turn/client.rs:868-887`
- **Issue**: The `verify_response_integrity()` function reads `msg_len` from the STUN header bytes [2:3] and computes `end = HEADER_SIZE + msg_len`. The attribute walk loop checks `offset + 4 <= end` but does not verify `end <= raw_bytes.len()`. If a maliciously crafted STUN response declares a large `msg_len` that exceeds the actual buffer, the loop will read past the buffer boundary, causing a panic.
- **Fix**: Added `if end > raw_bytes.len() { return Err(...); }` after computing `end`.
- **Status**: [x] Fixed — bounds check added before attribute walk

---

## Fix Status

| Phase | Bugs | Fixed | Remaining |
|-------|------|-------|-----------|
| P1 | 1 | 1 | 0 |
| P2 | 3 | 3 | 0 |
| **Total** | **4** | **4** | **0** |
