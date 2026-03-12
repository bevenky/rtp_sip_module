# Production Readiness TODO — rtp_sip_module

## CRITICAL (must fix before production)

- [x] **C1: Session Timers (RFC 4028)** — Session-Expires/Min-SE headers + auto re-INVITE to prevent zombie calls ✓ `src/sip/session_timer.rs`
- [x] **C2: RTP timeout detection** — Track `last_packet_time`, emit callback/event if no RTP for N seconds ✓ `src/rtp/engine.rs`
- [x] **C3: Registration auth challenge (401/407)** — Parse WWW-Authenticate, compute Digest response, retry REGISTER ✓ `src/sip/digest_auth.rs`
- [x] **C4: RTP bind to effective local IP** — Bind to `effective_local_addr` not `0.0.0.0` ✓ `src/sip/engine.rs`
- [x] **C5: SRTP via SDES** — Encrypt/decrypt RTP, parse/generate `a=crypto:` in SDP, AES_CM_128_HMAC_SHA1_80 ✓ `src/rtp/srtp.rs` + `src/sip/sdp.rs`
- [x] **C6: RTCP integration into RTP engine** — Periodic RTCP send loop + incoming RTCP parsing in receive path ✓ `src/rtp/engine.rs`

## HIGH (important for quality and interop)

- [x] **H1: Symmetric RTP auto-adjust in engine** — Wire SymmetricRtp into receive loop, update send target on address learn ✓ `src/rtp/engine.rs`
- [x] **H2: SSRC collision detection** — RFC 3550 Section 8.2, detect + re-init on collision ✓ `src/rtp/engine.rs`
- [x] **H3: DTMF clamping** — Mute audio during DTMF send/receive to prevent bleed-through ✓ `src/rtp/engine.rs`
- [x] **H4: Session reaping** — Timeout-based cleanup of terminated sessions in SessionManager ✓ `src/session/manager.rs`
- [x] **H5: Per-dialog CSeq tracking** — HashMap<DialogId, u32> instead of global counter ✓ `src/sip/engine.rs`
- [x] **H6: CN payload (PT 13) send/receive** — Auto-CNG during silence, incoming CN handling ✓ `src/rtp/engine.rs`
- [x] **H7: MOS/R-factor calculation** — ITU-T G.107 from loss/jitter/RTT stats ✓ `src/rtp/rtcp.rs`
- [x] **H8: Media hooks/tapping** — Fork audio to external consumer (recording, ASR) ✓ `src/rtp/media_tap.rs`
- [x] **H9: Additional RTP_BUG flags** — IGNORE_MARK_BIT, SEND_LINEAR_TIMESTAMPS, FLUSH_JB_ON_DTMF, START_SEQ_AT_ZERO, ACCEPT_ANY_PAYLOAD ✓ `src/rtp/dtmf.rs`
- [x] **H10: G.711 Appendix I PLC** — Pitch-based concealment with autocorrelation, OLA crossfade, gain decay ✓ `src/rtp/plc.rs`
- [x] **H11: Contact header rport/received** — NAT-aware SIP contact rewriting ✓ (RTP IP fix + Via rport via rsipstack)

## MEDIUM (for enterprise robustness)

- [x] **M1: Timer-driven RTP playout** — 20ms interval timer decoupled from packet arrival ✓ `src/rtp/engine.rs`
- [x] **M2: RTP flush mode** — Drain without processing during hold/resume/transfer ✓ `src/sip/engine.rs` + `src/rtp/engine.rs`
- [x] **M3: SSRC change handling in RTP receive** — Detect and re-sync (not just RTCP tracking) ✓ `src/rtp/engine.rs`
- [x] **M4: Session heartbeat** — Periodic callback for billing/health monitoring ✓ `src/sip/engine.rs` + `src/python/events.rs`
- [x] **M5: SDP re-negotiation for codec switching** — Full re-INVITE codec change flow ✓ `src/sip/engine.rs` + `src/rtp/engine.rs`
- [x] **M6: Silence detection (VAD)** — For auto-CNG triggering ✓ `src/rtp/vad.rs`
- [x] **M7: Dynamic payload type renegotiation** — Mid-call PT map updates via switch_codec() ✓ `src/rtp/engine.rs` + `src/rtp/packet.rs`
- [x] **M8: Multiple STUN server failover** — Failback with health tracking ✓ `src/nat/stun/pool.rs`
- [x] **M9: OPTIONS keepalive** — Periodic SIP OPTIONS ping ✓ `src/sip/engine.rs`
- [x] **M10: Advanced jitter adaptation** — History-based, trend-aware algorithm ✓ `src/rtp/jitter.rs`
- [x] **M11: RTP payload switching** — Codec change mid-call via switch_codec() ✓ `src/rtp/engine.rs`
- [x] **M12: TURN client lifecycle** — Full Allocate → CreatePermission → ChannelBind → Refresh ✓ `src/nat/turn/client.rs`

## SKIPPED (not needed for SIP trunk Voice AI)

- ICE-lite (WebRTC only)
- STUN over TCP (WebRTC/enterprise — not SIP trunk)
- UPnP/NAT-PMP (office/home PBX deployments)
- Media proxy/passthrough (B2BUA mode)
- STUN MESSAGE-INTEGRITY (not needed for basic SIP trunk STUN)
- Channel variable system (use Rust config structs)
- Application hooks framework (Python layer handles)
