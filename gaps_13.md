# Gaps Round 13: Thirteenth Comprehensive FreeSWITCH Audit

**Date**: 2026-03-13
**Scope**: Line-by-line audit of entire codebase post-rounds 1-12 (346 bugs fixed)
**Method**: 7 parallel audit agents (SRTP, RTP/jitter, SIP, DTMF, NAT/STUN/TURN, audio processing, Python/SDP), comparing against FreeSWITCH, libsrtp2, RFC 3711/3550/3261/3515/5389/5766/4733/3389/4566/3611/3264

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Total | 0 | No new bugs found |

**First round with zero confirmed bugs.** All 24 raw audit findings were verified against actual code and rejected as false positives or already-tracked known TODOs.

### Previously-Deferred TODOs Resolved

In addition to the Round 13 audit, the 4 remaining deferred TODOs from prior rounds were implemented:

| Bug | Description | Status |
|-----|-------------|--------|
| Bug #19 | Registration refresh interval not updated from server response | Fixed |
| Bug #27 | SIP session timers (RFC 4028) not integrated into call lifecycle | Fixed |
| Bug #33 | TURN permission/channel binding refresh not automatic | Fixed |
| Bug #40 | Event loss from broadcast receiver resubscribe on every poll | Fixed |

---

## False Positives Rejected (24 items)

### SRTP Module (0 bugs)
1. **ROC underflow** (srtp.rs:791) — Harmless: value rejected by replay window before any damage.
2. **MKI not zeroed in Drop** (srtp.rs:329) — MKI is a public identifier, not secret key material. Key material IS zeroed.
3. **KDR (Key Derivation Rate) not supported** — Missing feature, not a bug. Out of scope ("without adding new functionality").

### RTP/Jitter Module (0 bugs)
4. **Jitter next_sequence reverse-order** (jitter.rs:226) — Correctly tracks highest+1. Out-of-order packets are in the buffer and `pop()` returns them in order.
5. **Jitter calculation skips reordered packets** (jitter.rs:154) — Already handles both forward and backward timestamp differences.
6. **Adaptive delay oscillation** (jitter.rs:476) — ±10ms steps is a design choice matching FreeSWITCH STFU buffer behavior.
7. **RTP padding validation** (engine.rs:774) — RFC 3550 §5.1 only requires last byte for pad length. Current validation (pad_len==0 or >payload) is correct.
8. **RTP header extensions** (packet.rs) — `rtp` crate's `Packet::unmarshal` handles extensions. Builder defaults (empty) are correct for outbound.
9. **RTCP loss calculation duplicates** — SRTP replay protection deduplicates upstream; jitter buffer tracks by sequence number.

### SIP Module (0 bugs)
10. **Cancel/BYE race** (engine.rs:2079-2118) — Already correctly handled: BYE sent when cancel_pending + 200 OK, RTP stopped, state=Ended.
11. **Registration expiry from server response** — `registration.expires()` reads server's Expires. Known TODO (Bug #19) tracks refresh interval not updating.
12. **Route set from 180 early responses** — Route set from 200 OK sufficient for confirmed dialog. rsipstack handles early dialog routing internally.
13. **SDP direction negotiation** — Already fixed in Round 12 (Bug #R12-3).
14. **Re-INVITE state race** — Dialog stored as `Arc<>`, cloned before await. Arc keeps dialog alive during concurrent modifications.
15. **Digest auth nonce-count race** — `authorize()` takes `&mut self`; Rust borrow checker prevents unsynchronized concurrent access.
16. **BYE before ACK** — rsipstack's dialog layer manages ACK state machine internally.
17. **Session timers** — Known TODO (Bug #27). Not new.
18. **Hangup during reinvite** — BYE takes priority per RFC 3261. `ReinviteGuard` Drop impl ensures `reinvite_pending` cleared.
19. **CSeq overflow** — u32 wraps after 4B requests (~136 years at 1/sec). Unrealistic.

### DTMF Module (0 bugs)
20. **Duration saturating_add** (dtmf.rs:1219) — u16+u32 overflow requires ~16 years continuous DTMF. 30-second `DTMF_MAX_DURATION` guard (line 1222) catches realistic cases.

### NAT/STUN/TURN Module (0 bugs)
21. **TURN concurrent operations race** — `parking_lot::Mutex` serializes all shared state access.

### Python/SDP Module (0 bugs)
22. **recv_audio runtime guard** — `recv_audio_blocking` is pure sync (`try_recv()` + `thread::sleep()`). No tokio runtime needed.
23. **Event loss on resubscribe** — Known TODO (Bug #40). Not new.
24. **SDP empty payload types** — `has_media()` correctly returns false when `payload_types` is empty.

---

## Fix Status

| Phase | Bugs | Fixed | Deferred |
|-------|------|-------|----------|
| **Total** | **0** | **0** | **0** |

---

## Cumulative Audit Summary (Rounds 1-13)

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
| **Total** | **350** | **20** | **350** |

All 350 bugs across 13 rounds have been fixed. The 4 previously-deferred TODOs (Bug #19, #27, #33, #40) were resolved in this round.

---

## Convergence Analysis

```
Round:  1    2    3    4    5    6    7    8    9   10   11   12   13
Bugs:  67  109   65   42   30    8    4    6    4    3    8    4    0
```

The audit has converged to zero new findings. All 350 bugs identified across 13 rounds have been fixed, including the 4 previously-deferred TODOs. The codebase has reached a high level of correctness relative to FreeSWITCH and the relevant RFCs.
