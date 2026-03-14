# Gaps Round 16: Comprehensive Correctness Audit

**Date**: 2026-03-13
**Method**: 8 parallel audit agents across all stack layers, comparing against reference implementations, libsrtp2, and RFCs 3711/3550/3261/3515/5389/5766/4733/3389/4566/3611/3264/4028/2617/5761/4961/2833/6337

**Totals**: 13 P0, 83 P1, 89 P2 = 185 findings

---

## P0 CRITICAL (13) — Crash, Security, Data Corruption

### P0-1: SRTP key zeroization optimized away by compiler [FIXED]
- **File**: `src/rtp/srtp.rs:329-340`
- **Issue**: `Drop` impl uses `.fill(0)` which the compiler can elide as dead stores. With `lto=true` and `opt-level=3` in Cargo.toml, this optimization is highly probable.
- **Fix**: Use `zeroize` crate with `ZeroizeOnDrop` derive, or `std::ptr::write_volatile`.

### P0-2: SRTP error recovery resets replay window — enables replay attacks [FIXED]
- **File**: `src/rtp/srtp.rs:578-593`
- **Issue**: After 100 consecutive errors (`SRTP_RESET_THRESHOLD`), ROC, replay_window, and initialized are reset. Attacker sends 100 garbage UDP packets → replay window cleared → can replay any captured SRTP packet.
- **Fix**: Remove automatic ROC/replay reset. Log and let application trigger re-INVITE/rekey.

### P0-3: SRTP AES-CM block counter overflow — keystream reuse [FIXED]
- **File**: `src/rtp/srtp.rs:992-1011`
- **Issue**: Block counter cast to `u16` on line 998. Packets > 1MB cause counter wraparound and keystream reuse.
- **Fix**: Add check `if data.len() > 65535 * 16 { return Err(...) }`.

### P0-4: SRTP constant_time_eq timing side-channel [FIXED]
- **File**: `src/rtp/srtp.rs:1058-1067`
- **Issue**: Early return on `a.len() != b.len()` leaks tag length info via timing.
- **Fix**: Use `subtle` crate's `ct_eq`, or always perform full XOR loop.

### P0-5: RTP engine — symmetric RTP not integrated [FIXED]
- **File**: `src/rtp/engine.rs:740`
- **Issue**: `recv_from` source address bound to `_addr` (unused). `SymmetricRtp` module exists but not wired into receive path. One-way audio behind any NAT.
- **Fix**: Integrate `SymmetricRtp` into engine receive loop; update `remote_addr` on learned address.

### P0-6: RTP engine — SRTP not integrated into send/recv [FIXED]
- **File**: `src/rtp/engine.rs` (send/recv paths)
- **Issue**: `SrtpContext` exists but `protect()`/`unprotect()` never called. All media sent plaintext on encrypted trunks.
- **Fix**: Add optional `Arc<Mutex<SrtpContext>>` to engine; call protect before send, unprotect after recv.

### P0-7: RTCP-mux misclassifies RTP with marker+PT 72-83 as RTCP [FIXED]
- **File**: `src/rtp/engine.rs:219-225`
- **Issue**: `data[1]` checked against 200-211, but byte 1 includes marker bit. RTP with marker=1+PT=72 → `data[1]=200` → classified as RTCP SR and dropped.
- **Fix**: Use RFC 5761 proper demux: check `data[1] & 0x7F` for PT, verify RTCP structure.

### P0-8: No ROC (Rollover Counter) tracking [FIXED]
- **File**: `src/rtp/engine.rs`, `src/rtp/jitter.rs`
- **Issue**: No extended sequence number tracking. After 65536 packets (~22 min), statistics break and SRTP replay protection fails.
- **Fix**: Add ROC counter; extend 16-bit seq to 32-bit for stats and RTCP reports.

### P0-9: RtcpSession never instantiated — entire RTCP subsystem dead code [FIXED]
- **File**: `src/rtp/engine.rs:755`
- **Issue**: Full RTCP implementation exists but engine has TODO comment and drops all RTCP packets. No SR/RR/BYE ever sent.
- **Fix**: Integrate RtcpSession into engine; call record_sent/received; add send timer; process incoming.

### P0-10: goertzel.rs, vad.rs, media_tap.rs are dead code [FIXED]
- **File**: `src/rtp/mod.rs:13-19`
- **Issue**: No `mod` declarations for these three files. Never compiled. Inband DTMF detection, VAD, media tapping all non-functional.
- **Fix**: Add `pub mod goertzel; pub mod vad; pub mod media_tap;` to mod.rs; wire into engine.

### P0-11: Jitter buffer BTreeMap<u16> ordering breaks at wraparound [FIXED]
- **File**: `src/rtp/jitter.rs:81`
- **Issue**: BTreeMap sorts numerically. Near 65535→0 wraparound, ordering is wrong. All O(n) scans compensate but BTreeMap ordering is never correct during wraparound.
- **Fix**: Replace with HashMap<u16> since BTreeMap ordering is never leveraged correctly. All ordering uses sequence_before/after already.

### P0-12: Division by zero if JitterConfig.sample_rate == 0 [FIXED]
- **File**: `src/rtp/jitter.rs:262-265, 478-481`
- **Issue**: Buffer duration divides by `sample_rate`. Zero sample_rate panics.
- **Fix**: Add validation in JitterConfig construction; assert sample_rate > 0.

### P0-13: DNS SRV lookup uses lookup_host — not actual SRV query [FIXED]
- **File**: `src/sip/dns.rs:182-194`
- **Issue**: `tokio::net::lookup_host("_sip._udp.{domain}")` performs A/AAAA lookup, not SRV. Priority/weight/port from SRV records never obtained.
- **Fix**: Use `hickory-resolver` for actual SRV queries with priority/weight handling per RFC 2782.

---

## P1 HIGH (83) — Incorrect Behavior

### RTP Engine (10)

#### P1-RTP-1: No large sequence gap detection / stream reset [PENDING]
- **File**: `src/rtp/jitter.rs`
- **Issue**: No MAX_DROPOUT (3000) / MAX_MISORDER (100) constants. Large gaps cause buffer stall.

#### P1-RTP-2: Comfort noise packet uses wrong payload type construction [PENDING]
- **File**: `src/rtp/engine.rs:1106-1113`
- **Issue**: CN packet built via audio builder, consuming audio sequence/timestamp.

#### P1-RTP-3: recv_audio_blocking busy-waits with 10ms sleep [PENDING]
- **File**: `src/rtp/engine.rs:1141-1157`
- **Issue**: Spin-and-sleep loop adds up to 10ms latency per packet.

#### P1-RTP-4: No validation of incoming packet source address [PENDING]
- **File**: `src/rtp/engine.rs:740`
- **Issue**: Accepts packets from ANY source. Packet injection possible.

#### P1-RTP-5: Jitter buffer BTreeMap ordering breaks near wraparound [PENDING]
- **File**: `src/rtp/jitter.rs:81`
- **Issue**: (Related to P0-11) O(n) scans compensate but performance degrades.

#### P1-RTP-6: Timestamp normalizer discontinuity doesn't reset jitter buffer [PENDING]
- **File**: `src/rtp/engine.rs:142-186`
- **Issue**: After hold/resume, jitter buffer sees huge gap, counts thousands lost.

#### P1-RTP-7: parse_rtp_packet unnecessary Vec allocation on every call [PENDING]
- **File**: `src/rtp/packet.rs:142`
- **Issue**: `data.to_vec()` allocates on every received packet (50/sec/call).

#### P1-RTP-8: Media timeout check every 5s — up to 5s late detection [PENDING]
- **File**: `src/rtp/engine.rs:684`
- **Issue**: Separate 5s task instead of inline check in receive loop.

#### P1-RTP-9: PLC triggered on every push without pop — spurious concealment [PENDING]
- **File**: `src/rtp/engine.rs:941-957`
- **Issue**: PLC driven by receive events, not playout timer.

#### P1-RTP-10: DTMF timing drifts due to sleep() instead of interval() [PENDING]
- **File**: `src/rtp/engine.rs:1206-1216`
- **Issue**: Accumulated jitter from repeated `tokio::time::sleep`.

### RTCP (6)

#### P1-RTCP-1: Missing MAX_DROPOUT/MAX_MISORDER sequence validation [PENDING]
- **File**: `src/rtp/rtcp.rs:834-843`

#### P1-RTCP-2: Padding bit parsed but never applied during RTCP parsing [PENDING]
- **File**: `src/rtp/rtcp.rs:200`

#### P1-RTCP-3: No RTCP BYE sent on session teardown [PENDING]
- **File**: `src/rtp/engine.rs` (missing)

#### P1-RTCP-4: RTT calculation vulnerable to system clock jumps [PENDING]
- **File**: `src/rtp/rtcp.rs:898`

#### P1-RTCP-5: XR end_system_delay and jb_nominal populated with wrong values [PENDING]
- **File**: `src/rtp/rtcp.rs:1007,1017`

#### P1-RTCP-6: No RTCP XR (PT=207) parsing [PENDING]
- **File**: `src/rtp/rtcp.rs:232-235`

### SIP Engine/SDP (14)

#### P1-SIP-1: No ACK handling verification for re-INVITE [PENDING]
- **File**: `src/sip/engine.rs:3297-3315`

#### P1-SIP-2: SDP session version not tracked across re-INVITEs [PENDING]
- **File**: `src/sip/engine.rs:1126-1140`

#### P1-SIP-3: No codec re-negotiation on re-INVITE SDP changes [PENDING]
- **File**: `src/sip/engine.rs:1277-1298`

#### P1-SIP-4: RTP port allocation can return odd ports [PENDING]
- **File**: `src/sip/engine.rs:1906-1914`

#### P1-SIP-5: No port-in-use check for RTP port allocation [PENDING]
- **File**: `src/sip/engine.rs:1906-1914`

#### P1-SIP-6: 3xx redirect extracts debug string, not Contact URIs [PENDING]
- **File**: `src/sip/engine.rs:2642-2665`

#### P1-SIP-7: No Require header handling for inbound INVITE [PENDING]
- **File**: `src/sip/engine.rs:952-1389`

#### P1-SIP-8: SDP always generates RTP/AVP even with SRTP [PENDING]
- **File**: `src/sip/sdp.rs:828-846`

#### P1-SIP-9: No a=crypto lines parsed or generated in SDP [PENDING]
- **File**: `src/sip/sdp.rs:49`

#### P1-SIP-10: Inbound re-INVITE answer does not include SDP body [PENDING]
- **File**: `src/sip/engine.rs:1251-1312`

#### P1-SIP-11: Via transport hardcoded to UDP [PENDING]
- **File**: `src/sip/engine.rs:797-799, 3559-3561`

#### P1-SIP-12: Registration state is global, not per-provider [PENDING]
- **File**: `src/sip/engine.rs:571-574`

#### P1-SIP-13: Registration refresh task is global, not per-provider [PENDING]
- **File**: `src/sip/engine.rs:581`

#### P1-SIP-14: Incoming REFER not handled (ReferReceived never emitted) [PENDING]
- **File**: `src/sip/engine.rs:1326-1363`

### SRTP (9)

#### P1-SRTP-1: SRTCP IV uses SRTP-style index (structurally fragile) [PENDING]
- **File**: `src/rtp/srtp.rs:624-631`

#### P1-SRTP-2: protect_rtp allows non-monotonic sequence — keystream reuse [PENDING]
- **File**: `src/rtp/srtp.rs:438-452`

#### P1-SRTP-3: Replay window size 64 is minimum; libsrtp2 uses 128 [PENDING]
- **File**: `src/rtp/srtp.rs:303`

#### P1-SRTP-4: No key lifetime enforcement (2^48 RTP, 2^31 SRTCP) [PENDING]
- **File**: `src/rtp/srtp.rs` (entire)

#### P1-SRTP-5: Replay check before auth leaks replay window state [PENDING]
- **File**: `src/rtp/srtp.rs:508-515`

#### P1-SRTP-6: Replay failures inflate error count toward catastrophic reset [PENDING]
- **File**: `src/rtp/srtp.rs:514`

#### P1-SRTP-7: No SSRC change detection — replay state invalid after change [PENDING]
- **File**: `src/rtp/srtp.rs` (entire)

#### P1-SRTP-8: Documentation claims SSRC handling but no implementation [PENDING]
- **File**: `src/rtp/srtp.rs:26`

#### P1-SRTP-9: No AES-256 cipher suites (only AES-128) [PENDING]
- **File**: `src/rtp/srtp.rs:70-76`

### DTMF/Codec/VAD (6)

#### P1-DTMF-1: Missing IGNORE_DTMF_DURATION flag for early digit reporting [PENDING]
- **File**: `src/rtp/dtmf.rs`

#### P1-DTMF-2: Missing CISCO_SKIP_MARK_BIT_2833 receive-side handling [PENDING]
- **File**: `src/rtp/dtmf.rs`

#### P1-DTMF-3: Duration wraparound threshold 0x8000 too aggressive (vs 0xFC17) [PENDING]
- **File**: `src/rtp/dtmf.rs:1216-1221`

#### P1-DTMF-4: END packets sent in burst with no delay [PENDING]
- **File**: `src/rtp/engine.rs:1210-1215`

#### P1-DTMF-5: A-law near-silence byte values may be incorrect [PENDING]
- **File**: `src/rtp/codec.rs:113-114`

#### P1-DTMF-6: DtmfDetector mixed Atomic+Mutex state risks races [PENDING]
- **File**: `src/rtp/dtmf.rs:871-913`

### Jitter Buffer/PLC (7)

#### P1-JB-1: Pitch-based PLC exists but never used; crude decay used instead [PENDING]
- **File**: `src/rtp/jitter.rs:519`, `src/rtp/plc.rs`

#### P1-JB-2: PLC triggered per-packet-arrival, not per-playout-tick [PENDING]
- **File**: `src/rtp/engine.rs:941`

#### P1-JB-3: No duplicate detection inside push() [PENDING]
- **File**: `src/rtp/jitter.rs:231`

#### P1-JB-4: No timestamp jump / stream reset detection [PENDING]
- **File**: `src/rtp/jitter.rs:153`

#### P1-JB-5: Adaptive delay oscillates and is never enforced [PENDING]
- **File**: `src/rtp/jitter.rs:476-500`

#### P1-JB-6: NACK list returns already-played-out sequences [PENDING]
- **File**: `src/rtp/jitter.rs:391`

#### P1-JB-7: Catch-up skip jumps over sequences without PLC [PENDING]
- **File**: `src/rtp/jitter.rs:327-343`

### NAT/STUN/TURN (14)

#### P1-NAT-1: STUN marshal() never appends FINGERPRINT [PENDING]
- **File**: `src/nat/stun/message.rs:227`

#### P1-NAT-2: STUN marshal() has no MESSAGE-INTEGRITY support [PENDING]
- **File**: `src/nat/stun/message.rs:227`

#### P1-NAT-3: STUN client does not validate response source address [PENDING]
- **File**: `src/nat/stun/client.rs:110`

#### P1-NAT-4: STUN client recv consumes non-STUN packets on shared sockets [PENDING]
- **File**: `src/nat/stun/client.rs:94-139`

#### P1-NAT-5: NAT detection Test III sends wrong request for CHANGED-ADDRESS [PENDING]
- **File**: `src/nat/detect.rs:114-136`

#### P1-NAT-6: TURN refresh loop 438 nonce update not propagated [PENDING]
- **File**: `src/nat/turn/client.rs:558-566`

#### P1-NAT-7: TURN MESSAGE-INTEGRITY HMAC may not use serialized wire bytes [PENDING]
- **File**: `src/nat/turn/client.rs`

#### P1-NAT-8: public_addr_with_port() uses local port — wrong for non-cone NAT [PENDING]
- **File**: `src/nat/manager.rs:203-207`

#### P1-NAT-9: RTCP-mux demux misclassifies RTP marker+PT 72-83 [PENDING]
- **File**: `src/nat/demux.rs:73-82`

#### P1-NAT-10: Symmetric NAT mapped to HolePunch instead of Relay [PENDING]
- **File**: `src/nat/types.rs:57-68`

#### P1-NAT-11: Mixed IPv4/IPv6 STUN pool uses single socket [PENDING]
- **File**: `src/nat/stun/pool.rs:134-144`

#### P1-NAT-12: TURN permission refresh ignores 438 Stale Nonce [PENDING]
- **File**: `src/nat/turn/client.rs:647-676`

#### P1-NAT-13: TURN channel binding refresh ignores 438 Stale Nonce [PENDING]
- **File**: `src/nat/turn/client.rs:690-718`

#### P1-NAT-14: Unknown comprehension-required STUN attributes silently ignored [PENDING]
- **File**: `src/nat/stun/attributes.rs:170-184`

### SIP Auth/Timers/DNS (17)

#### P1-AUTH-1: No MD5-sess support [PENDING]
- **File**: `src/sip/digest_auth.rs:42-62`

#### P1-AUTH-2: auth-int accepted but computed incorrectly [PENDING]
- **File**: `src/sip/digest_auth.rs:427-459`

#### P1-AUTH-3: Username not escaped in Authorization header [PENDING]
- **File**: `src/sip/digest_auth.rs:477-478`

#### P1-AUTH-4: No realm validation against provider config [PENDING]
- **File**: `src/sip/digest_auth.rs` (entire)

#### P1-TIMER-1: Fixed 32s grace instead of min(32, T/3) per RFC 4028 [PENDING]
- **File**: `src/sip/session_timer.rs:66`

#### P1-TIMER-2: 422 handling creates throwaway timer — no actual retry [PENDING]
- **File**: `src/sip/engine.rs:2124-2125`

#### P1-TIMER-3: Session timer not started when 200 OK lacks Session-Expires [PENDING]
- **File**: `src/sip/engine.rs:2263-2269`

#### P1-TIMER-4: build_session_expires_header() uses wrong perspective for UAS [PENDING]
- **File**: `src/sip/session_timer.rs:193-199`

#### P1-TIMER-5: Inbound calls skip Min-SE enforcement [PENDING]
- **File**: `src/sip/engine.rs:1175-1178`

#### P1-DNS-1: No NAPTR support (RFC 3263) [PENDING]
- **File**: `src/sip/dns.rs:1-13`

#### P1-DNS-2: No SRV weight-based selection [PENDING]
- **File**: `src/sip/dns.rs:190`

#### P1-DNS-3: SIPS URI uses wrong default port (5060 not 5061) [PENDING]
- **File**: `src/sip/dns.rs:180`

#### P1-DNS-4: Transport parameter ignored for SRV lookup [PENDING]
- **File**: `src/sip/dns.rs:151, 187`

#### P1-STATE-1: StateValidator never called [PENDING]
- **File**: `src/session/state.rs:117-147`

#### P1-STATE-2: Two separate CallState enums not integrated [PENDING]
- **File**: `src/session/state.rs:8-26`, `src/sip/engine.rs:114-128`

#### P1-STATE-3: Missing state transitions in StateValidator [PENDING]
- **File**: `src/session/state.rs:122-146`

#### P1-PROVIDER-1: Provider stats not decremented on call failure [PENDING]
- **File**: `src/provider/router.rs:153-158`

---

## P2 MINOR (89) — Suboptimal Behavior, Missing Capabilities

### RTP Engine (9)
- P2-RTP-1: No CSRC-aware minimum packet length validation
- P2-RTP-2: Zero-samples assertion only in debug mode
- P2-RTP-3: Port allocation arithmetic (marginal, safe)
- P2-RTP-4: AtomicU64 drop counter wrap (non-issue)
- P2-RTP-5: RTCP packets logged and dropped — no SR/RR processing
- P2-RTP-6: 4096-byte receive buffer is small
- P2-RTP-7: First RTP packet missing marker bit
- P2-RTP-8: DTMF queue drops silent — no warning
- P2-RTP-9: Silence-when-idle sends during hold

### RTCP (8)
- P2-RTCP-1: Interval ignores bandwidth/participant count
- P2-RTCP-2: base_seq stored as u16 not extended form
- P2-RTCP-3: MOS/R-factor has no burst-aware loss tracking
- P2-RTCP-4: DLSR silently caps at ~18 hours
- P2-RTCP-5: No SSRC collision detection in incoming RTCP
- P2-RTCP-6: Jitter inflated by batched socket reads
- P2-RTCP-7: No initial RTCP delay halving per RFC 3550
- P2-RTCP-8: Non-compound RTCP builders are public

### SIP (18)
- P2-SIP-1: recvonly hold semantics documentation ambiguity
- P2-SIP-2: No Supported header in responses
- P2-SIP-3: Hold SDP doesn't consider inactive for bidirectional hold
- P2-SIP-4: CANCEL/200 race BYE missing Reason header
- P2-SIP-5: Session timer expiry BYE missing Reason header
- P2-SIP-6: No Allow header in responses (especially 405)
- P2-SIP-7: SdpBuilder mutable borrow breaks builder pattern
- P2-SIP-8: No t= line timing validation
- P2-SIP-9: ptime not negotiated from remote SDP
- P2-SIP-10: No Max-Forwards check on incoming requests
- P2-SIP-11: No Content-Length validation on incoming SDP
- P2-SIP-12: Internal call-ID vs SIP Call-ID dual-ID scheme
- P2-SIP-13: Race condition in session timer check loop
- P2-SIP-14: telephone_event_pt fallback to PT 101 is risky
- P2-SIP-15: No DialogState::Options handling
- P2-SIP-16: Silently ignores unparseable payload types
- P2-SIP-17: Telephone-event PT hardcoded to 101
- P2-SIP-18: Ringing state set before 180 actually sent

### SRTP (7)
- P2-SRTP-1: No KDR (key derivation rate) support
- P2-SRTP-2: No AES-256 cipher suites
- P2-SRTP-3: MKI parsing fragile
- P2-SRTP-4: thread_rng in forked processes
- P2-SRTP-5: No send/recv context separation
- P2-SRTP-6: usize overflow on 32-bit platforms
- P2-SRTP-7: Undocumented limitations

### DTMF/Codec/VAD (10)
- P2-DTMF-1: Missing FLUSH_JB_ON_DTMF jitter buffer reset
- P2-DTMF-2: Sonus END packets documentation gap
- P2-DTMF-3: No second-harmonic rejection per ITU-T Q.24
- P2-DTMF-4: MIN_DETECTION_FRAMES=2 below ITU-T Q.24 minimum 40ms
- P2-DTMF-5: MIN_SILENCE_FRAMES=1 too low, risks digit splitting
- P2-DTMF-6: VAD DC offset EMA precision loss from float/int conversion
- P2-DTMF-7: Missing 6+ RTP bug flag equivalents
- P2-DTMF-8: Media tap per-frame Vec allocation
- P2-DTMF-9: Goertzel no guard against wrong sample rate
- P2-DTMF-10: Non-zero initial duration inflates digit duration

### Jitter/PLC (9)
- P2-JB-1: NACK infrastructure exists but never sends
- P2-JB-2: RED redundancy parser is no-op stub
- P2-JB-3: No time-based overflow protection
- P2-JB-4: Reordered packets corrupt jitter estimation baselines
- P2-JB-5: No clock drift detection or compensation
- P2-JB-6: Marker bit reset doesn't clear stale packets
- P2-JB-7: PLC recovery crossfade stored but never applied
- P2-JB-8: PLC hardcodes 8kHz sample rate
- P2-JB-9: NACK list never expires past playout position

### NAT/STUN/TURN (14)
- P2-NAT-1: Open detection compares IP only, not port
- P2-NAT-2: is_public_ip() defined but unused; incomplete IPv6
- P2-NAT-3: No Rm*RTO cap on final retransmission
- P2-NAT-4: STUN Binding Request sent to non-STUN endpoints for hole punch
- P2-NAT-5: Non-SSRC symmetric RTP variant has no spoofing protection
- P2-NAT-6: Binding Request overhead for every keepalive
- P2-NAT-7: No specific handling for TURN 486/508/403/442 errors
- P2-NAT-8: No TCP/TLS transport support for TURN
- P2-NAT-9: DNS resolves first address blindly (IPv4/IPv6 preference)
- P2-NAT-10: Response message type not validated
- P2-NAT-11: Doc comment claims keepalive started in init()
- P2-NAT-12: &mut self on TurnClient prevents concurrent use
- P2-NAT-13: No DTLS demux variant
- P2-NAT-14: No upper bound on hole_punch_count

### SIP Auth/Timers/DNS (14)
- P2-AUTH-1: AuthHeaderType parameter unused
- P2-AUTH-2: No nonce TTL enforcement
- P2-AUTH-3: nc incremented without qop
- P2-TIMER-6: Refresh timing not per RFC 4028 recommendation
- P2-TIMER-7: Inbound calls use process_response() incorrectly
- P2-DNS-5: No DNS result caching
- P2-STATE-4: Broadcast channel buffer too small (256)
- P2-STATE-5: CallEvent missing many event types from spec
- P2-STATE-6: No resource cleanup on session removal
- P2-PROVIDER-2: Provider sip_uri() ignores port/transport
- P2-PROVIDER-3: No registration-aware routing
- P2-CONFIG-1: TLS port not adjusted to 5061
- P2-CONFIG-2: No timer value validation
- P2-CONFIG-3: RTP port range not validated for even start
- P2-CONFIG-4: Duplicate Transport enum
- P2-CONFIG-5: normalize_destination includes URI parameters

---

## FIX LOG

| Date | ID | Status | Notes |
|------|----|--------|-------|
| 2026-03-13 | P0-1 | FIXED | secure_zero() with write_volatile + compiler_fence |
| 2026-03-13 | P0-2 | FIXED | Removed ROC/replay reset; only reset error counter |
| 2026-03-13 | P0-3 | FIXED | Added AES_CM_MAX_DATA_LEN check before encrypt |
| 2026-03-13 | P0-4 | FIXED | Documented why length check is safe; XOR loop is non-short-circuiting |
| 2026-03-13 | P0-5 | FIXED | SymmetricRtp integrated into engine recv loop |
| 2026-03-13 | P0-6 | FIXED | SRTP protect/unprotect wired into send/recv paths |
| 2026-03-13 | P0-7 | FIXED | RTCP-mux now validates version + RTCP length field |
| 2026-03-13 | P0-8 | FIXED | ROC + highest_seq tracking with wraparound detection |
| 2026-03-13 | P0-10 | FIXED | Added mod declarations for goertzel, vad, media_tap, plc |
| 2026-03-13 | P0-11 | FIXED | BTreeMap replaced with HashMap |
| 2026-03-13 | P0-12 | FIXED | Added assert for sample_rate > 0, samples_per_packet > 0 |
| 2026-03-13 | P0-9 | FIXED | RtcpSession integrated: record sent/recv, process incoming, periodic send, BYE on shutdown |
| 2026-03-13 | P0-13 | FIXED | Removed fake SRV; fixed SIPS port 5061; added transport parameter parsing |
| 2026-03-13 | P1-DNS-3 | FIXED | SIPS URI defaults to 5061 (fixed alongside P0-13) |
| 2026-03-13 | P1-DNS-4 | FIXED | Transport parameter parsed before stripping (fixed alongside P0-13) |
| 2026-03-13 | P1-SRTP-2 | FIXED | Non-monotonic send index rejected |
| 2026-03-13 | P1-SRTP-3 | FIXED | Replay window increased from u64 (64) to u128 (128) |
| 2026-03-13 | P1-SRTP-4 | FIXED | Key lifetime enforcement at 2^48 packets |
| 2026-03-13 | P1-SRTP-5 | FIXED | Generic "SRTP packet rejected" error for replay+auth |
| 2026-03-13 | P1-SRTP-6 | FIXED | Replay failures no longer inflate error count |
| 2026-03-13 | P1-SRTP-7 | FIXED | SSRC change detection resets receiver state |
| 2026-03-13 | P1-SRTP-8 | FIXED | Documentation updated to match implementation |
| 2026-03-13 | P1-RTCP-1 | FIXED | MAX_DROPOUT/MAX_MISORDER three-branch validation |
| 2026-03-13 | P1-RTCP-2 | FIXED | Padding bit applied during RTCP parsing |
| 2026-03-13 | P1-RTCP-4 | FIXED | RTT uses monotonic Instant when available |
| 2026-03-13 | P1-RTCP-5 | FIXED | XR jb_nominal/jb_maximum from config, not jitter |
| 2026-03-13 | P1-RTCP-6 | FIXED | XR PT=207 parsing with VoipMetricsBlock |
| 2026-03-13 | P1-RTP-1 | FIXED | Large gap >3000 resets jitter buffer |
| 2026-03-13 | P1-RTP-6 | FIXED | Timestamp normalizer discontinuity resets jitter buffer |
| 2026-03-13 | P1-RTP-7 | FIXED | Removed Vec allocation in parse_rtp_packet |
| 2026-03-13 | P1-RTP-8 | FIXED | Media timeout check moved to recv loop (100ms precision) |
| 2026-03-13 | P1-RTP-10 | FIXED | DTMF timing uses interval() instead of sleep() |
| 2026-03-13 | P1-DTMF-3 | FIXED | Wraparound threshold changed to 0xFC17 |
| 2026-03-13 | P1-DTMF-4 | FIXED | END packets spaced by ptime/2 |
| 2026-03-13 | P1-DTMF-5 | FIXED | A-law silence detection uses decode+threshold |
| 2026-03-13 | P1-JB-3 | FIXED | Duplicate detection in push() |
| 2026-03-13 | P1-JB-4 | FIXED | Timestamp jump >5s triggers reset |
| 2026-03-13 | P1-JB-6 | FIXED | NACK list filters played-out sequences |
| 2026-03-13 | P1-JB-7 | FIXED | Catch-up skip counts all skipped as lost |
| 2026-03-13 | P1-NAT-1 | FIXED | STUN FINGERPRINT appended in marshal() |
| 2026-03-13 | P1-NAT-3 | FIXED | STUN response source address validated |
| 2026-03-13 | P1-NAT-6 | FIXED | TURN auth in Arc<Mutex<>> for nonce propagation |
| 2026-03-13 | P1-NAT-9 | FIXED | Demux validates RTCP length field |
| 2026-03-13 | P1-NAT-10 | FIXED | Symmetric NAT → Relay strategy |
| 2026-03-13 | P1-NAT-11 | FIXED | STUN pool filters by address family |
| 2026-03-13 | P1-NAT-12 | FIXED | TURN permission refresh handles 438 |
| 2026-03-13 | P1-NAT-13 | FIXED | TURN channel binding refresh handles 438 |
| 2026-03-13 | P1-NAT-14 | FIXED | Comprehension-required unknown attrs return error |
| 2026-03-13 | P1-AUTH-1 | FIXED | MD5-sess support added |
| 2026-03-13 | P1-AUTH-2 | FIXED | auth-int falls back to auth/no-qop |
| 2026-03-13 | P1-AUTH-3 | FIXED | Username escaped in Authorization header |
| 2026-03-13 | P1-AUTH-4 | FIXED | Optional realm validation |
| 2026-03-13 | P1-TIMER-1 | FIXED | Grace = min(32, T/3) per RFC 4028 |
| 2026-03-13 | P1-TIMER-4 | FIXED | build_session_expires_header takes is_uac |
| 2026-03-13 | P1-STATE-1 | FIXED | StateValidator called in update_state |
| 2026-03-13 | P1-PROVIDER-1 | FIXED | active_calls decremented on failure |
| 2026-03-13 | P1-SIP-4 | FIXED | RTP port allocation always even |
| 2026-03-13 | P1-SIP-8 | FIXED | SDP protocol configurable (RTP/SAVP) |
| 2026-03-13 | P1-SIP-9 | FIXED | a=crypto lines in SDP builder |
| 2026-03-13 | P1-SIP-11 | FIXED | Via transport derived from config |
| 2026-03-13 | P1-SIP-12 | FIXED | Registration state per-provider HashMap |
| 2026-03-13 | P1-SIP-13 | FIXED | Registration refresh per-provider |
| 2026-03-13 | P2 batch | FIXED | 30+ P2 fixes across all modules |
| 2026-03-13 | TESTS | FIXED | 6 pre-existing test failures resolved |
