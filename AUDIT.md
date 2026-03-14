# Comprehensive Audit Report: rtp_sip_module

**Date:** 2026-03-11
**Sources:** Internal codebase, plivo-mediaserver (reference implementation), agent-stack (plivo-voice-core), 8 open-source Rust repos, viska/rvoip issue trackers

---

## Table of Contents

1. [Critical Bugs](#1-critical-bugs)
2. [RTP Packet Implementation Gaps](#2-rtp-packet-implementation-gaps)
3. [Jitter Buffer: Ours vs Production-Grade](#3-jitter-buffer-ours-vs-production-grade)
4. [G.711 Codec Assessment](#4-g711-codec-assessment)
5. [REFER / NOTIFY / Transfer Gaps](#5-refer--notify--transfer-gaps)
6. [RTCP: What We Need and How to Add It](#6-rtcp-what-we-need-and-how-to-add-it)
7. [Issues from viska/rvoip That Affect Us](#7-issues-from-viskarvoip-that-affect-us)
8. [Patterns to Borrow from Open-Source](#8-patterns-to-borrow-from-open-source)
9. [Sans-IO Architecture Path](#9-sans-io-architecture-path)
10. [Prioritized Action Plan](#10-prioritized-action-plan)

---

## 1. Critical Bugs

### BUG-1: RTP Padding Not Stripped from Payload (packet.rs)

**Severity: HIGH** — silent data corruption

Our `unmarshal()` parses the padding bit but never removes padding bytes from the payload. RFC 3550 Section 5.1: "The last octet of the padding contains a count of how many padding octets should be ignored, including itself."

```
Current: payload = &data[offset..]  // includes padding bytes
Should:  payload = &data[offset..data.len() - pad_count]
```

If a remote endpoint sends padded packets (common with SRTP), we feed garbage bytes to the G.711 decoder, producing audio artifacts.

**Comparison:** rtp-rs, rtp-types, discortp, rvoip, and agent-stack ALL handle this correctly. Our agent-stack's `rtp.rs` explicitly subtracts `data[data.len()-1]` from the payload slice when padding bit is set.

### BUG-2: Blocking Sleep in Async Context (rtp/engine.rs)

**Severity: HIGH** — potential deadlock

`recv_audio_blocking()` uses `std::thread::sleep()` inside what may be called from a tokio async context. This blocks the entire tokio runtime thread, starving other tasks.

**Fix:** Use `tokio::time::sleep()` in async context, or document that this must only be called from a sync context (which the PyO3 `py.allow_threads()` pattern actually provides — verify call sites).

### BUG-3: Extension Header Bounds Not Validated (packet.rs)

**Severity: MEDIUM** — crash on malformed packets

After reading extension length, we don't validate `offset + 4 + ext_len * 4 <= data.len()` before advancing the offset. A malformed packet with extension length larger than actual data causes silent truncation or panic.

**Comparison:** rtp-types validates each variable-length section sequentially and fails fast. rtp-rs does the same.

### BUG-4: No RTP Version Validation (packet.rs)

**Severity: MEDIUM** — accepts garbage

We never check `version == 2`. Non-RTP packets on the same port (STUN, DTLS) would be parsed as RTP, producing garbage.

**Comparison:** Every reference implementation (rtp-rs, rtp-types, rvoip, agent-stack) rejects version != 2.

---

## 2. RTP Packet Implementation Gaps

### What We Have vs What We Should Have

| Feature | Ours | rtp-rs | rtp-types | rvoip | agent-stack |
|---------|------|--------|-----------|-------|-------------|
| Basic header parse | Yes | Yes | Yes | Yes | Yes |
| Version validation | **No** | Yes | Yes | Yes | Yes |
| Padding removal | **No** | Yes | Yes | Yes | Yes |
| CSRC bounds check | Partial | Yes | Yes | Yes | Yes |
| Extension parsing | Skip only | Full | Full | Full | Skip |
| Extension data access | **No** | Yes | Yes | Yes | No |
| Zero-copy parsing | **No** (copies to Bytes) | Yes | Yes | Partial | No |
| Mutable packet view | **No** | No | Yes | No | No |
| Builder validation | Partial | Yes | Yes | Yes | N/A |
| RTP/RTCP demux (RFC 5761) | **No** | No | No | Yes | No |
| Dedicated Seq type | **No** | Yes | No | Yes | No |

### Recommendations

1. **Immediate:** Fix padding, version validation, extension bounds
2. **Short-term:** Add RFC 5761 demux function (needed for RTCP-MUX)
3. **Medium-term:** Consider zero-copy `RtpReader<'a>` wrapper (borrow `&[u8]`, compute fields on demand) for the hot receive path, keeping the owned `RtpPacket` for the send path. This is the pattern used by rtp-rs and rtp-types.
4. **Nice-to-have:** Dedicated `RtpSeq(u16)` type wrapping sequence arithmetic (rtp-rs pattern)

---

## 3. Jitter Buffer: Ours vs Production-Grade

### Comparison Matrix

| Feature | Ours (jitter.rs) | agent-stack (adaptive_jitter_buffer.rs) | plivo-mediaserver (reference implementation) | rvoip |
|---------|-------------------|----------------------------------------|-------------------------------|-------|
| **Lines of code** | 295 | 935 | 2,632 | ~500 |
| **Data structure** | BTreeMap<u16, Packet> | Circular buffer (Vec) | Linked list + hashtable | BTreeMap<u32, Packet> |
| **Adaptive algorithm** | Linear +-10ms | RFC 3550 EMA jitter + multiplier | Time-skew detection + min/max stats | 4x jitter with hysteresis |
| **Jitter estimation** | RFC 3550 (correct) | RFC 3550 EMA gain=1/16 | Exponential averaging over 50 samples | RFC 3550 gain=1/16 |
| **Initial buffering** | Wait for target_delay | Wait for min_delay_frames | Configurable initial delay | Wait for adaptive delay |
| **Initial buffer timeout** | **None (can hang!)** | Implicit (frame-based) | Configurable | Implicit |
| **PLC** | Decay 0.9x per loss | ITU-T G.711 Appendix I (pitch-based) | External (FEC/NACK) | None built-in |
| **Clock drift** | **Not handled** | Resync on far-ahead | Time-skew detection + offset adjustment | Cycle counter |
| **Silence suppression** | **No** | Via VAD (Silero) | Via VAD (libfvad) | No |
| **Comfort noise** | **No** | LCG-based generator | Via codec | No |
| **Presets** | Single default | plivo/customer_ws/rtp | Configurable | Single |
| **Sequence width** | u16 (wraps at 65535) | u64 (never wraps) | u32 + cycle counter | u32 + cycle |
| **Capacity** | max_packets (50) | 4x max_delay_frames | Dynamic | Dynamic |
| **Stats tracking** | Basic (6 fields) | Comprehensive (10+ fields) | Extensive | Moderate |

### Critical Gaps in Our Jitter Buffer

1. **No initial buffering timeout:** If packets arrive slowly, `initial_buffering_done` never becomes true. Playout never starts. Agent-stack handles this implicitly via frame counting. We need a wall-clock timeout (e.g., 1 second).

2. **Naive adaptive algorithm:** Our `+-10ms` linear adjustment is too slow for real networks. Agent-stack uses `target_delay = jitter_us * multiplier` (configurable, default 3.0) which reacts instantly to jitter spikes. Plivo-mediaserver uses 50-sample statistical windowing.

3. **No clock drift handling:** If sender and receiver clocks drift (common with cheap hardware), our buffer slowly fills or empties. Agent-stack handles this with resync-on-gap. Plivo-mediaserver has explicit time-skew detection with write offset adjustment.

4. **Toy PLC:** Our `attenuation *= 0.9` decay is far from production quality. Agent-stack implements full ITU-T G.711 Appendix I with pitch detection via normalized autocorrelation, overlap-add blending, and progressive attenuation. This is 783 lines vs our 43 lines.

5. **u16 sequence numbers:** We use raw `u16` for sequence tracking. After 65535 packets (~22 minutes at 50pps), sequences wrap. Our `BTreeMap<u16>` cannot distinguish wrap generations. Both agent-stack (u64) and rvoip (u32 + cycle counter) solve this.

### Recommendation

Port the adaptive jitter buffer from agent-stack (`plivo-voice-core/crates/transport/src/adaptive_jitter_buffer.rs`). It's the same org's code, production-tested, and architecturally compatible. Key components to port:

- `AdaptiveJitterBuffer` with circular buffer and EMA jitter estimation
- `PacketLossConcealer` from `plc.rs` (ITU-T G.711 Appendix I)
- `ComfortNoiseGenerator` from `comfort_noise.rs`
- Presets system (plivo, customer_ws, rtp)

---

## 4. G.711 Codec Assessment

### Our Implementation: CORRECT

We delegate to `audio-codec-algorithms` (karip's crate), which is ITU G.191 reference-verified with bit-exact compliance. This is the best available Rust G.711 implementation. The `restsend/audio-codec` alternative uses compile-time lookup tables but lacks ITU verification.

### What's Missing

| Feature | Ours | agent-stack | plivo-mediaserver |
|---------|------|-------------|-------------------|
| G.711 mu-law (PCMU) | Yes (via crate) | Yes (LUT-based) | Yes (LUT-based) |
| G.711 A-law (PCMA) | Yes (via crate) | Yes (LUT-based) | Yes (LUT-based) |
| Linear PCM (L16) | **No** | Yes | Yes |
| Silence detection / VAD | **No** | Yes (Silero ONNX) | Yes (libfvad) |
| Comfort noise generation | **No** | Yes (LCG-based) | Yes |
| A-law <-> mu-law transcoding | **No** | No | Yes (direct table) |
| Resampling (8k/16k/48k) | **No** | Yes (rubato FFT sinc) | Yes |
| Sample rate validation | **No** | Yes | Yes |

### Recommendations

1. **Silence detection:** Not critical for our use case (Voice AI always has audio flowing), but useful for bandwidth optimization. Consider Silero VAD (ONNX model, 512-sample windows) from agent-stack.

2. **Comfort noise:** Important for telephony. When we detect silence, sending CN frames (RFC 3389) prevents the remote thinking the line dropped. Port `comfort_noise.rs` from agent-stack (30 lines, LCG-based).

3. **L16 codec:** Easy addition — just big-endian i16 packing. Useful for high-quality internal pipelines.

4. **Resampling:** If we ever support Opus or wideband, we'll need 8k<->16k<->48k resampling. Agent-stack uses `rubato` crate.

---

## 5. REFER / NOTIFY / Transfer Gaps

### Comparison with plivo-mediaserver

| Feature | Ours | plivo-mediaserver (reference implementation) |
|---------|------|-------------------------------|
| Basic REFER | Yes (dialog.refer()) | Yes (nua_refer) |
| Referred-By header | **No** | Yes (SIPTAG_REFERRED_BY_STR) |
| NOTIFY subscription tracking | Yes (basic) | Yes (full lifecycle) |
| NOTIFY timeout | **No** | Implicit (NUA handles) |
| Transfer progress events | Yes (3 events) | Yes (rich state machine) |
| Attended transfer (Replaces) | Yes (URI encoding) | Yes (sofia-sip built-in) |
| REFER-continuation (keep original call) | **No** | Yes (sip_refer_continue_after_reply) |
| Proxy REFER | **No** | Yes (proxy_refer_uuid) |
| REFER rate limiting | **No** | No |
| Multiple simultaneous transfers | **No** | Yes |

### Specific Gaps

1. **No REFER subscription timeout:** If the remote never sends NOTIFY after accepting REFER, `refer_pending` stays true forever. We need a 30-second timeout (RFC 3515 Section 2.4.7 recommends the subscription duration from Expires header, defaulting to implicit dialog lifetime).

2. **No Referred-By header (RFC 3892):** Some PBXes (Asterisk, reference implementation) use this to identify who initiated the transfer. We should include it in REFER requests.

3. **Consultation call validation:** `attended_transfer()` doesn't verify the consultation call is still active before sending REFER. If it hung up, we'll send a REFER with a dead Replaces header, causing a 481.

4. **No REFER-continuation:** After blind transfer, we always hang up the original call. Some scenarios need to keep it alive until transfer completes (e.g., fall-back if transfer fails).

5. **Re-INVITE glare detection fragile:** We check for "491" in the error message string rather than parsing the SIP status code. rsipstack may not format errors that way.

---

## 6. RTCP: What We Need and How to Add It

### Current State: ZERO RTCP support

RFC 3550 Section 6 makes RTCP **mandatory**. Without it:
- Remote can't measure packet loss or jitter
- No round-trip time estimation
- No way to detect one-way audio
- No congestion feedback
- Some endpoints may drop calls without RTCP

### What plivo-mediaserver Has (reference implementation)

Full RTCP stack: SR, RR, SDES, BYE, APP, XR, feedback (PLI, FIR, NACK, TWCC), FEC/RED, RTT calculation, loss reporting, jitter statistics, event-driven stats exposure.

### What rvoip Has

SR, RR, SDES, BYE, APP, feedback (PLI, FIR, NACK, REMB, TWCC), NTP timestamps, report blocks, congestion detection (5-level state machine), MediaSync for cross-stream synchronization.

### What rtcp-types Provides (ystreet/rtcp-types)

Complete zero-copy parsing and building for all RTCP types including XR and all feedback types. Uses builder + `calculate_size()` + `write_into()` pattern. Compound packet support with iterator. This is the best RTCP library available in Rust.

### Minimum Viable RTCP for Our Use Case

For telephony (G.711 voice), we need:

1. **Receiver Reports (RR)** — report packet loss and jitter to remote
2. **Sender Reports (SR)** — NTP/RTP timestamp mapping for synchronization
3. **SDES with CNAME** — source identification (required by RFC 3550)
4. **BYE** — clean session teardown

We do NOT need (for now): PLI, FIR, NACK, TWCC, REMB, XR, APP (these are for video and WebRTC congestion control).

### Implementation Plan

**Option A: Use `rtcp-types` crate (recommended)**

Add `rtcp-types = "0.2"` to Cargo.toml. It provides zero-copy parsing and building for all types. Then add:

```rust
// New file: src/rtp/rtcp.rs (~300 lines)

struct RtcpSession {
    // Sender state
    packets_sent: u32,
    octets_sent: u32,
    // Receiver state (per remote SSRC)
    packets_received: u32,
    packets_expected: u32,
    packets_lost: u32,
    jitter: f64,
    last_sr_ntp: u64,
    last_sr_received_at: Instant,
    // Timing
    rtcp_interval: Duration,  // 5s default, randomized per RFC 3550
    last_rtcp_sent: Instant,
}

impl RtcpSession {
    fn build_sr(&self) -> Vec<u8> { /* use rtcp_types::SenderReport::builder() */ }
    fn build_rr(&self) -> Vec<u8> { /* use rtcp_types::ReceiverReport::builder() */ }
    fn build_sdes(&self) -> Vec<u8> { /* CNAME item */ }
    fn build_bye(&self) -> Vec<u8> { /* BYE with reason */ }
    fn process_incoming(&mut self, data: &[u8]) { /* parse SR/RR, extract RTT */ }
    fn calculate_rtt(&self) -> Option<Duration> { /* (now - LSR) - DLSR */ }
}
```

Integrate with RtpEngine:
- Send compound RTCP (SR + SDES) every 5s (randomized per RFC 3550 Section 6.2)
- Parse incoming RTCP, update stats
- Send BYE on hangup
- Expose stats to Python via new `get_rtcp_stats(call_id)` method

**Option B: Build from scratch (~500 lines)**

If we want zero dependencies, RTCP packets are simple enough to serialize manually. SR is 28 bytes + 24 per report block. RR is 8 bytes + 24 per block. SDES is variable. This is what rvoip does.

### RTCP-MUX (RFC 5761)

For simplicity, we should support RTCP-MUX (send RTCP on the same port as RTP). This requires:
- Demuxing incoming packets: check byte[1] — payload types 72-76 (PT 200-204) = RTCP, else RTP
- SDP negotiation: `a=rtcp-mux` attribute
- discortp has a clean `demux()` function we can reference

---

## 7. Issues from viska/rvoip That Affect Us

### HIGH Priority

**rvoip #7: Missing Contact Header / 0.0.0.0 in SDP**
- rvoip's INVITE was missing Contact header and had `0.0.0.0` in Via/SDP
- Asterisk rejected with 400
- **Our risk:** We use rsipstack which likely handles Contact automatically, but we MUST verify:
  - Our INVITE includes Contact header with real local IP
  - SDP `o=` and `c=` lines use real IP, not 0.0.0.0
  - Via sent-by uses real IP
  - **Action:** Add integration test that validates outbound INVITE structure

### MEDIUM Priority

**rvoip #9: Config Inheritance for SIP Auth**
- Credentials only configurable at one abstraction level
- **Our status:** We handle this via `Config` with per-provider credentials. Looks OK.

**rvoip #11: Windows Build Failures**
- Raw socket handle type mismatches on Windows
- **Our risk:** We don't target Windows currently, but if we do, our UDP socket code in `rtp/engine.rs` needs platform guards.

**rvoip #5: G.729/Opus Demand**
- Real telecom operators need G.729 and Opus
- **Our plan:** G.711 is sufficient for Voice AI (most providers transcode anyway), but Opus support would be valuable for WebRTC paths.

### LOW Priority

**viska #44: Synchronous Request-Response API**
- Users want `response = sip.request(invite)` style API
- **Our status:** Our Python API is already synchronous (GIL-released blocking calls). This is fine.

**viska #36: SIP Client + Media Library Demand**
- Validates our approach of combining SIP signaling with RTP media

---

## 8. Patterns to Borrow from Open-Source

### From rtp-types: Zero-Copy Packet Parsing

```rust
// Their pattern: #[repr(transparent)] wrapper over &[u8]
// Validate once in parse(), then all accessors are pure bitwise ops
// No allocation on the receive hot path

// We could add this as an alternative to our owned RtpPacket:
pub struct RtpView<'a>(&'a [u8]);  // zero-copy view for receive path
pub struct RtpPacket { ... }        // owned packet for send path
```

### From rtcp-types: Builder + calculate_size + write_into

```rust
// Their pattern for building RTCP:
let size = SenderReport::builder(ssrc)
    .ntp_timestamp(ntp)
    .add_report_block(block)
    .calculate_size()?;
let mut buf = vec![0u8; size];
builder.write_into(&mut buf)?;
// No guessing buffer sizes, no reallocation
```

### From agent-stack: Production Jitter Buffer

The `AdaptiveJitterBuffer` from `plivo-voice-core/crates/transport/` is the most directly applicable. Same organization, production-tested at scale. Key innovations:
- Circular buffer (not BTreeMap) for O(1) insert/remove
- Presets for different transport types
- u64 sequence numbers (never wrap)
- Resync on far-ahead gaps
- Configurable jitter multiplier

### From agent-stack: ITU-T G.711 Appendix I PLC

The `plc.rs` (783 lines) implements proper pitch-based packet loss concealment:
- Normalized autocorrelation for pitch detection
- Overlap-add blending at boundaries
- Progressive attenuation on consecutive losses
- Crossfade recovery when good audio returns

Our 43-line decay-based PLC sounds terrible in comparison.

### From rvoip: Congestion Detection State Machine

```rust
// 5-level congestion detection from weighted loss/RTT/jitter:
enum CongestionLevel { None, Light, Moderate, Severe, Critical }
// Could inform bitrate adaptation, codec switching, or RTCP feedback
```

### From rvoip: RtpTransport Trait

```rust
// Pluggable transport abstraction:
trait RtpTransport: Send + Sync {
    async fn send_rtp(&self, packet: &RtpPacket) -> Result<()>;
    async fn send_rtcp(&self, packet: &[u8]) -> Result<()>;
    async fn subscribe(&self) -> broadcast::Receiver<RtpEvent>;
    fn local_rtp_addr(&self) -> SocketAddr;
    fn local_rtcp_addr(&self) -> SocketAddr;
}
// Enables: UDP, TCP, SRTP, mock (testing) implementations
```

### From siphon-rs: Crate Granularity

Their 15-crate separation (sip-core, sip-parse, sip-transport, sip-transaction, sip-dialog, sip-sdp, etc.) is excellent for maintainability. We could benefit from splitting our monolith into:
- `rtpsip-rtp` (packet, jitter, codec, RTCP)
- `rtpsip-sip` (engine, SDP, transactions)
- `rtpsip-python` (PyO3 bindings)

### From discortp: RTP/RTCP Demux

```rust
// RFC 5761 multiplexed RTP/RTCP demux:
fn demux(data: &[u8]) -> Demuxed {
    if data.len() < 2 { return Demuxed::TooSmall; }
    let pt = data[1] & 0x7F;
    match pt {
        72..=76 => Demuxed::Rtcp(data),  // SR=200-72=128... wait, it's PT 200-204
        _ => Demuxed::Rtp(data),
    }
}
// Actually: RTCP PT 200-204 map to byte[1] values 200-204 (not 72-76)
// The RFC 5761 rule: if PT in {72..79} OR {200..204..211}, it's RTCP
```

---

## 9. Sans-IO Architecture Path

### What is Sans-IO?

Sans-IO means protocol logic has NO direct I/O. Instead of:
```rust
// Current (IO-coupled):
async fn send_rtp(&self, samples: &[i16]) {
    let packet = self.build_packet(samples);
    self.socket.send_to(&packet, self.remote_addr).await?;  // I/O inside protocol
}
```

You do:
```rust
// Sans-IO:
fn encode_rtp(&mut self, samples: &[i16]) -> Vec<u8> {
    self.build_packet(samples)  // Returns bytes, caller does I/O
}

fn handle_incoming(&mut self, data: &[u8]) -> Vec<Action> {
    // Parse, update state, return actions (SendPacket, EmitEvent, SetTimer)
    // NO socket calls, NO async, NO tokio
}
```

### Current Architecture

```
Python (PyO3) --> SipEngine (owns tokio runtime, UDP sockets, timers)
                     |
                     +-> rsipstack (async, owns transport)
                     +-> RtpEngine (async, owns UdpSocket)
                     +-> Jitter buffer, codec, DTMF
```

Everything is tightly coupled to tokio and UDP sockets. The protocol logic (SIP state machine, RTP sequencing, DTMF detection, jitter buffering) is mixed with I/O.

### Target Architecture

```
                    Sans-IO Core (no async, no tokio, no sockets)
                    +------------------------------------------+
                    | RtpCodec: encode/decode packets          |
                    | JitterBuffer: push/pop with timestamps   |
                    | DtmfDetector: feed bytes, get digits     |
                    | RtcpSession: build/parse RTCP            |
                    | SipSession: state machine, emit actions  |
                    +------------------------------------------+
                              |              |
                    +---------+    +---------+
                    | Actions |    | Events  |
                    +---------+    +---------+
                         |              ^
                    +----v--------------+----+
                    |    I/O Integration     |
                    | tokio + UdpSocket      |
                    | (thin async wrapper)   |
                    +------------------------+
                              |
                    +---------v---------+
                    | Python bindings   |
                    | (PyO3)            |
                    +-------------------+
```

### What's Already Sans-IO (or Close)

- **Jitter buffer** (`jitter.rs`): Already sans-IO. Push/pop with no I/O. Just needs better algorithm.
- **Codec** (`codec.rs`): Already sans-IO. Pure encode/decode functions.
- **DTMF detector** (`dtmf.rs`): Already sans-IO. Feed bytes, get digits.
- **Packet parsing** (`packet.rs`): Already sans-IO. Pure serialization/deserialization.
- **PLC** (`jitter.rs`): Already sans-IO.

### What Needs Refactoring

- **RTP engine** (`rtp/engine.rs`): Owns `UdpSocket`, has async send/recv loops. Needs to be split into:
  - `RtpSession` (sans-IO): manages sequence numbers, timestamps, SSRC, codec selection
  - `RtpTransport` (I/O): UDP send/recv, calls into RtpSession for encode/decode

- **SIP engine** (`sip/engine.rs`): Deeply coupled to rsipstack (which is itself async/tokio). This is the hardest part. Options:
  - Keep rsipstack as the I/O layer, extract our state machines (call session, transfer tracking) into sans-IO structs
  - Replace rsipstack with a sans-IO SIP parser (like siphon-rs's `sip-core` + `sip-parse`) and manage transactions ourselves

### Migration Strategy (Incremental)

**Phase 1: Extract RTP sans-IO core (low risk)**
```
src/rtp/
  session.rs      NEW - sans-IO RTP session (seq, ts, SSRC management)
  transport.rs    NEW - async UDP I/O wrapper
  rtcp.rs         NEW - sans-IO RTCP building/parsing
  packet.rs       KEEP (already sans-IO)
  jitter.rs       KEEP (already sans-IO, improve algorithm)
  codec.rs        KEEP (already sans-IO)
  dtmf.rs         KEEP (already sans-IO)
  engine.rs       REFACTOR - thin wrapper calling session + transport
```

**Phase 2: Extract SIP state machines (medium risk)**
```
src/sip/
  call_session.rs   NEW - sans-IO call state machine
  transfer.rs       NEW - sans-IO REFER/NOTIFY state tracking
  engine.rs         REFACTOR - I/O orchestrator only
```

**Phase 3: Trait-based transport (future)**
```
// Enable pluggable transports:
trait RtpTransport: Send + Sync {
    async fn send(&self, data: &[u8], addr: SocketAddr) -> Result<()>;
    async fn recv(&self) -> Result<(Vec<u8>, SocketAddr)>;
}
// Implementations: UdpTransport, MockTransport (testing), WebRtcTransport (future)
```

### Benefits of Sans-IO

1. **Testability:** Protocol logic can be tested with no network, no async runtime. Feed bytes in, assert actions out.
2. **Portability:** Same protocol logic works with tokio, async-std, or sync I/O.
3. **Debugging:** State machines are inspectable. Every state transition is explicit.
4. **Performance:** No async overhead in the hot path (packet processing).
5. **Composability:** Sans-IO components can be reused in different contexts (CLI, server, embedded).

---

## 10. Prioritized Action Plan

### P0: Critical Bugs (fix immediately)

| # | Issue | File | Effort |
|---|-------|------|--------|
| 1 | Fix padding not stripped from payload | packet.rs | 5 lines |
| 2 | Add version == 2 validation | packet.rs | 3 lines |
| 3 | Add extension header bounds check | packet.rs | 5 lines |
| 4 | Add CSRC count bounds check | packet.rs | 3 lines |
| 5 | Verify recv_audio_blocking not called from async | rtp/engine.rs | Audit |

### P1: RTCP Support (required by RFC 3550)

| # | Task | Effort |
|---|------|--------|
| 1 | Add `rtcp-types` dependency | Cargo.toml |
| 2 | Create `src/rtp/rtcp.rs` with RR/SR/SDES/BYE | ~300 lines |
| 3 | Add RTCP send timer (5s interval) to RTP engine | ~50 lines |
| 4 | Parse incoming RTCP, track RTT and remote loss | ~100 lines |
| 5 | Send BYE on call hangup | ~20 lines |
| 6 | Add RFC 5761 RTP/RTCP demux | ~20 lines |
| 7 | Expose stats to Python: `get_rtcp_stats(call_id)` | ~40 lines |

### P2: Jitter Buffer Upgrade

| # | Task | Effort |
|---|------|--------|
| 1 | Port `AdaptiveJitterBuffer` from agent-stack | ~400 lines |
| 2 | Port `PacketLossConcealer` (ITU-T G.711 App I) from agent-stack | ~300 lines |
| 3 | Add comfort noise generator | ~30 lines |
| 4 | Add initial buffering timeout | 5 lines |
| 5 | Switch to u64 sequence numbers | ~20 lines |

### P3: Transfer Improvements

| # | Task | Effort |
|---|------|--------|
| 1 | Add REFER subscription timeout (30s) | ~20 lines |
| 2 | Add Referred-By header to REFER requests | ~10 lines |
| 3 | Validate consultation call active before attended transfer | ~10 lines |
| 4 | Fix re-INVITE glare detection (parse status code, not string) | ~10 lines |

### P4: Architectural Improvements

| # | Task | Effort |
|---|------|--------|
| 1 | Extract sans-IO `RtpSession` from `RtpEngine` | ~200 lines |
| 2 | Add `RtpTransport` trait for pluggable transport | ~50 lines |
| 3 | Add zero-copy `RtpView<'a>` for receive path | ~100 lines |
| 4 | Extract sans-IO call state machine from SIP engine | ~300 lines |

### P5: Nice-to-Have

| # | Task | Effort |
|---|------|--------|
| 1 | L16 codec support | ~30 lines |
| 2 | Dedicated `RtpSeq` type | ~50 lines |
| 3 | Silence detection / VAD | ~100 lines (or integrate Silero) |
| 4 | Resampling support (rubato) | ~100 lines |
| 5 | Crate splitting (rtp, sip, python) | Refactor |

---

## Appendix: Reference Repositories Summary

| Repo | Focus | Key Takeaway |
|------|-------|--------------|
| **rtp-rs** | RTP parsing | Zero-copy reader, Seq type, validate-once pattern |
| **rtp-types** | RTP types | `#[repr(transparent)]` zero-copy, mutable view, multiple writer backends |
| **rtcp-types** | RTCP types | Comprehensive RTCP builder/parser, compound iterator, XR + feedback |
| **discortp** | RTP/RTCP | RFC 5761 demux, `#[non_exhaustive]` payload types, pnet macros |
| **viska** | SIP server | Trait-based TU layer, layered SIP architecture |
| **siphon-rs** | SIP stack | 15-crate separation, nom parser, transaction state machines |
| **rvoip** | Full SIP/RTP | Adaptive jitter, RTCP, SRTP, MediaSync, congestion detection, RtpTransport trait |
| **agent-stack** | Production voice | Best jitter buffer, ITU PLC, comfort noise, codecs, VAD, resampler |
| **plivo-mediaserver** | reference implementation | Industrial RTCP, FEC/RED, NACK, time-skew detection, full transfer support |
