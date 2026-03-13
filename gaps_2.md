# Gaps Round 2: Comprehensive FreeSWITCH Audit

**Status: 109 of 109 fixed (483 tests passing, 0 failures)**

This audit covers bugs, correctness issues, and gaps found via line-by-line review of every module against FreeSWITCH's implementation (switch_rtp.c, mod_sofia, STFU jitter buffer, switch_stun.c, libsrtp patterns).

---

## P0 — Crash / Security / Call-Breaking

### 1. RTCP-mux demux mask prevents RTCP identification (engine.rs:683-691)
- `data[1] & 0x7F` masks off the high bit. RTCP PT 200 (0xC8) becomes 72 after masking, never matching `RTCP_PT_MIN (200)`. **All RTCP packets are misidentified as RTP** when RTCP-mux is enabled.
- **FreeSWITCH**: Checks full `data[1]` byte for RTCP discrimination.
- **Fix**: Remove `& 0x7F` mask: `let pt_byte = data[1];`

### 2. SRTP IV construction offset error in AES-CM (srtp.rs:905-907)
- Salt XORed at offset 2 instead of offset 0. RFC 3711 §4.1.1: the 14-byte salt is XORed directly against the 16-byte IV block starting at position 0. Every encrypted packet uses wrong IV, **breaking interop with all RFC-compliant SRTP implementations**.
- **Fix**: Change `iv[2 + i]` to `iv[i]`.

### 3. SRTP key derivation (PRF) IV construction incorrect (srtp.rs:845-854)
- Label XORed at position 7 instead of position 2 per RFC 3711 §4.3.1. **All derived session keys are wrong**, breaking encryption/decryption entirely.
- **Fix**: XOR label at correct position per RFC 3711 §4.3.1.

### 4. REFER sent via raw UDP bypassing SIP transaction layer (sip/engine.rs:2481-2489)
- Raw `UdpSocket::bind("0.0.0.0:0")` sends REFER outside the SIP stack. No transaction retransmission, no auth challenge handling, response arrives on ephemeral port nothing reads. NATs block the response. **Transfer is fire-and-forget and will fail in most deployments**.
- **FreeSWITCH**: Uses dialog layer (`nua_refer()`).
- **Fix**: Send REFER through the dialog layer or SIP endpoint.

### 5. OPTIONS keepalive sent via raw UDP (sip/engine.rs:767-792)
- Same raw socket issue as REFER. Response parsed as raw string prefix match. Buffer may truncate large responses.
- **Fix**: Send OPTIONS through the SIP endpoint's transaction layer.

### 6. CANCEL/200 OK race: call removed from map, orphaned dialog (sip/engine.rs:1857-1867)
- `cancel()` removes call from `self.calls` before dialog teardown completes. If 200 OK races the CANCEL (RFC 3261 §9.2), the spawned task finds `None` in calls map, **drops the answered call with no BYE sent** — leaked dialog, zombie media.
- **FreeSWITCH**: Marks cancel_pending, sends BYE if 200 OK arrives after CANCEL.
- **Fix**: Set `cancel_pending` flag instead of removing. Send BYE in `do_invite` Ok branch if cancel requested.

### 7. No state validation before re-INVITE (sip/engine.rs:2231-2287)
- `send_reinvite_internal()` doesn't check call state. Can send re-INVITE in Trying/Ringing (violates RFC 3261 §14), EarlyMedia, or Terminated state (may crash if dialog deallocated).
- **Fix**: Return error if `sess.state != CallState::Active && sess.state != CallState::Hold`.

### 8. TURN response MESSAGE-INTEGRITY never verified (turn/client.rs:622)
- Incoming TURN responses are accepted based only on transaction ID match. Attacker on network path can inject forged Allocate Success with spoofed relay address, **redirecting all TURN traffic**.
- **FreeSWITCH**: Verifies HMAC-SHA1 on all authenticated responses.
- **Fix**: Verify MESSAGE-INTEGRITY on authenticated responses before trusting contents.

### 9. No STUN FINGERPRINT validation on received messages (stun/message.rs:87)
- FINGERPRINT attribute (CRC-32) never checked. Corrupted or spoofed STUN messages accepted silently.
- **Fix**: After parsing, if FINGERPRINT present, validate CRC-32 XOR 0x5354554E.

### 10. DTMF out_digit_sofar unbounded increment (dtmf.rs:581)
- `continue_digit` increments `out_digit_sofar` unconditionally, even after digit completes. After u32 wrap (~26M calls), digit re-enters intermediate state producing garbage.
- **Fix**: Check `sofar >= total` BEFORE `fetch_add`. Return None if already complete.

### 11a. SRTP SSRC extracted from wrong RTP header offset (srtp.rs:391, 461)
- `u32::from_be_bytes([packet[4..8]])` reads timestamp, not SSRC. SSRC is at bytes 8-11 per RFC 3550 §5.1. Used in AES-CM IV. **Every encrypted RTP packet uses wrong SSRC in IV**, breaking interop.
- **Fix**: Use `[packet[8], packet[9], packet[10], packet[11]]` for RTP. RTCP lines (552, 597) are correct.

### 11b. SRTP RTP auth tag computed over MKI bytes (srtp.rs:428-437, 476-478)
- MKI appended before auth tag computed. RFC 3711 §4.2: authenticated portion excludes MKI. Breaks interop when MKI used.
- **Fix**: Compute auth tag before appending MKI.

### 11c. SRTCP auth tag computed over MKI bytes (srtp.rs:575-583, 600-608)
- Same as 11b for SRTCP. **Fix**: Exclude MKI from auth input.

### 11d. SRTCP index overflow not guarded (srtp.rs:553-554)
- SRTCP index is 31-bit max. No bounds check. At overflow, keystream reuse — complete security loss.
- **Fix**: Return error if `srtcp_index >= 0x80000000`.

---

## P1 — Correctness / Interop

### 11. No symmetric RTP / source address learning (engine.rs:677)
- `_addr` from `recv_from` is completely discarded. No address learning from incoming packets. **One-way audio in NAT scenarios** where remote sends from different port than SDP.
- **FreeSWITCH**: Implements auto-adjust symmetric RTP.
- **Fix**: Learn remote address from first valid received packet. Update send target.

### 12. No RTP version check on received packets (engine.rs:694)
- After `parse_rtp_packet` succeeds, version field never verified. Non-RTP traffic accepted.
- **Fix**: `if packet.header.version != 2 { continue; }`

### 13. Receive loop pops at most one packet per push (engine.rs:787-801)
- Each push attempts exactly one pop. After burst arrival, jitter buffer accumulates until `max_packets` hit, dropping oldest.
- **FreeSWITCH**: Timer-driven playout decoupled from arrival.
- **Fix**: Pop in a loop, or use separate timer-driven playout task.

### 14. CN timestamp increment uses wrong value (engine.rs:944-947)
- `send_comfort_noise` uses `samples.len()` for timestamp increment. Should use `samples_per_packet()` (ptime-based).
- **Fix**: Use `self.samples_per_packet()` for CN timestamp increment.

### 15. send_comfort_noise advances audio stream sequence/timestamp (engine.rs:944-948)
- CN packets increment the main audio RTP stream's seq/timestamp. When audio resumes, receiver sees gaps and counts them as packet loss.
- **FreeSWITCH**: Separate seq/timestamp management for CN.
- **Fix**: Use separate counter or don't advance audio stream for CN.

### 16. Port allocation integer division truncation (engine.rs:49-60)
- `(end - start) / 2` truncates, losing ports. No validation that start is even. If `end < start`, u16 underflow.
- **Fix**: `((end - start + 2) / 2)`, validate `start % 2 == 0` and `end > start`.

### 17. Silence-when-idle ptime captured once at start, ignores dynamic changes (engine.rs:641-664)
- `ptime_ms` captured when `start()` is called. After SDP renegotiation changes ptime, silence task uses old interval.
- **Fix**: Read `ptime_ms` inside the loop body.

### 18. No marker bit handling on incoming packets (engine.rs receive loop)
- Incoming marker bit (start of talkspurt) completely ignored. Should reset jitter buffer playout for re-sync.
- **FreeSWITCH**: Resets jitter buffer on incoming marker bit.
- **Fix**: When `packet.header.marker == true`, reset jitter buffer initial buffering.

### 19. No duplicate packet detection (engine.rs receive loop)
- Network duplicates pushed into jitter buffer, overwriting originals via BTreeMap::insert.
- **Fix**: Check if seq already in buffer or already played before pushing.

### 20. SSRC collision detection doesn't check local SSRC (engine.rs:702-722)
- Only detects remote SSRC changes, not true SSRC collision (remote == local SSRC, RFC 3550 §8.2).
- **Fix**: Add check `if pkt_ssrc == engine.ssrc { regenerate local SSRC }`.

### 21. TimestampNormalizer::reset doesn't properly maintain continuity (engine.rs:162-168)
- After SSRC change, `local_base_ts` stays at 0. First normalize after reset produces potentially huge offset.
- **Fix**: Set `local_base_ts` to last normalized timestamp plus one ptime before resetting.

### 22. send_audio force_marker not atomic with concurrent senders (engine.rs:850-851)
- Two separate atomic ops (`force_marker.swap`, `in_cn_silence.swap`). Concurrent senders can both miss the flag.
- **Fix**: Serialize entire send path or document single-sender requirement.

### 23. No padding bit handling in receive loop (engine.rs)
- Padding flag ignored. Padded bytes fed to codec decoder, producing noise at end of frame.
- **Fix**: If `packet.header.padding`, strip padding bytes from payload.

### 24. Media timeout fires repeatedly every 5s (engine.rs:626-637)
- No "already fired" flag. After timeout triggers, broadcast sent every 5 seconds indefinitely.
- **Fix**: Add `AtomicBool` flag, set on first timeout, clear when new RTP arrives.

### 25. Drop for RtpEngine does not set running=false (engine.rs:1106-1113)
- Spawned tasks continue running after engine dropped (hold Arc refs). Engine never fully deallocated.
- **Fix**: `self.running.store(false, SeqCst)` in Drop impl.

### 26. DTMF end packet in Sonus mode gets different timestamps (dtmf.rs:610-613, 644)
- Each of the 3 redundant end packets calls `build_packet` which advances `timestamp_dtmf` in Sonus mode. End retransmissions should share same timestamp.
- **Fix**: Build end packet once, clone for retransmissions with different seq numbers.

### 27. DTMF both continue_digit and end_digit emit end packets (dtmf.rs:577-593, 623-635)
- `continue_digit` returns end packet when `sofar >= total`, then `end_digit` generates 3 more. Result: 4+ end packets with potentially different durations.
- **Fix**: `continue_digit` should not set end bit. Return None when done. Let `end_digit` be sole end generator.

### 28. DTMF first packet sent with duration=0 (dtmf.rs:568)
- First packet has `DtmfPayload::new(event, false, 0)`. Some receivers (including this codebase's own detector) reject/mishandle duration=0.
- **FreeSWITCH**: First packet has `duration = samples_per_ptime` (e.g., 160).
- **Fix**: Use `interval_ts` for initial duration.

### 29. DTMF end_digit uses total requested duration, not actual accumulated (dtmf.rs:607-608)
- End packet claims requested duration, not actual accumulated. If called early or late, duration is wrong.
- **Fix**: Use `out_digit_sofar.load()` for end packet duration.

### 30. DTMF start_digit overwrites in-progress digit without ending it (dtmf.rs:557-571)
- Previous digit silently overwritten: no END sent, no timestamp advance. Receiver never gets END.
- **Fix**: Call `end_digit()` internally if `out_digit.is_some()` before starting new digit.

### 31. DTMF Sonus mode double timestamp advance (dtmf.rs:644, 616)
- Every `build_packet` advances +160 in Sonus mode. Then `end_digit` advances by total. For 100ms digit: 2080 total advance, creating large timestamp gap.
- **Fix**: Skip `fetch_add(total)` in end_digit when Sonus mode is active.

### 32. DTMF detector uses Relaxed atomics across multiple fields (dtmf.rs throughout)
- Multiple fields (`in_digit_ts`, `last_in_digit_ts`, `last_duration`, `current_digit`) use Relaxed ordering. Algorithm correctness depends on consistency across fields.
- **Fix**: Use single `Mutex<DtmfDetectorState>` struct for consistency.

### 33. DTMF timeout check relies on RTP timestamps, not wall-clock (dtmf.rs:955-988)
- Timeout only fires when new packet arrives. If remote stops sending entirely, digit hangs forever.
- **Fix**: Use `Instant::now()` wall-clock timer independent of packet arrival.

### 34. DTMF digits > 8.19 seconds broken due to u16 clamping (dtmf.rs:563-564)
- `ms_to_timestamp` returns u16 (max 65535). Duration stored as u32 but clamped value used. Long DTMF digits truncated.
- **Fix**: Store `ms * 8` directly as u32, clamp to u16 only when building payload.

### 35. Jitter: timestamp_diff wrapping_mul(1000) overflows u32 (jitter.rs:136-139)
- Overflows for timestamp delta > ~4.3M (537s at 8kHz). Jitter estimate corrupted.
- **Fix**: Cast to i64 before multiplying: `(ts_diff as i32 as i64) * 1000 / sample_rate as i64`.

### 36. Jitter: unsigned wrapping_sub gives wrong sign for reordered packets (jitter.rs:140)
- Reordered packet where `timestamp < last_timestamp` produces large positive u32, spiking jitter estimate.
- **Fix**: Cast `wrapping_sub` result to i32 for signed difference per RFC 3550.

### 37. Jitter: reorder counter counts gaps as reorders (jitter.rs:157-159)
- Increments `packets_reordered` when seq is ahead of expected (a gap/loss), not when actually reordered.
- **Fix**: Only count as reordered when packet arrives late (seq < highest seen, within window).

### 38. Jitter: BTreeMap eviction drops new packets after wraparound (jitter.rs:198-203)
- Smallest BTreeMap u16 key is evicted. After wraparound, seq 0/1 (new) have smaller keys than 65534/65535 (old). New packets evicted, old kept.
- **Fix**: Use wraparound-aware `sequence_before` to find truly oldest packet.

### 39. Jitter: first playout picks numerically smallest key, wrong at wraparound (jitter.rs:234)
- `packets.keys().next()` picks smallest u16. Buffer {65534, 65535, 0, 1} starts playout from 0, skipping 65534-65535.
- **Fix**: Track first inserted seq or use wraparound-aware comparison.

### 40. PLC: autocorrelation uses fixed PITCH_MAX-length window for all lags (plc.rs:262)
- G.711 Appendix I correlates over lag-length windows. Fixed PITCH_MAX (160) window means 140/160 samples overlap at short lags, biasing toward short pitch estimates.
- **Fix**: Change correlation loop to `for i in 0..lag`.

### 41. PLC: first-frame crossfade never executes (plc.rs:176)
- `overlap_buf` only populated during recovery from loss. On first concealment after good audio, it's empty. No OLA smoothing at good→concealed boundary, causing click.
- **Fix**: Save tail of last good frame into `overlap_buf` during every `update()`.

### 42. PLC: template tiling has no OLA at period boundaries (plc.rs:325-328)
- Modular wrap at `i % tlen` has no crossfade. Click at every pitch-period boundary during concealment.
- **Fix**: Apply OLA crossfading at each period boundary when tiling.

### 43. VAD: energy normalization inverted — scales UP with sample rate (vad.rs:521-523)
- At 48kHz: energy = 6x the mean (divides by n/6 instead of n). Threshold (100) calibrated for 8kHz is meaningless at higher rates.
- **Fix**: Use `sum / n` (pure mean) or `(sum / n) * divisor`. Current formula is inverted.

### 44. VAD: ZCR denominator should be n-1, not n (vad.rs:400)
- Maximum zero crossings is n-1. Denominator of n means ZCR can never reach 1.0.
- **Fix**: Use `(n - 1) as f64`.

### 45. VAD: integer divisor truncation for non-8kHz-multiple rates (vad.rs:192)
- `11025 / 8000 = 1` (should be ~1.378). Up to 10% energy error for non-standard rates.
- **Fix**: Restrict to standard rates or use floating-point normalization.

### 46. SIP: outbound call emits spurious Ringing event before any SIP response (sip/engine.rs:1778-1781)
- Immediately emits `CallEvent::Ringing` after spawning INVITE task. Duplicate when real 180 arrives.
- **Fix**: Remove premature Ringing emission.

### 47. SIP: CANCEL in Trying state fails silently (sip/engine.rs:1434, 1848-1855)
- `client_dialog` is None until `do_invite()` completes. CANCEL does nothing but returns Ok and emits Cancelled.
- **Fix**: Store cancellation flag, check in do_invite spawn. Send CANCEL after provisional.

### 48. SIP: no 200 OK retransmission / ACK timeout handling for inbound calls (sip/engine.rs:1228-1230)
- After `accept()`, no monitoring for missing ACK. Per RFC 3261 §13.3.1.4, UAS must retransmit 200 OK until ACK received.
- **Fix**: Monitor for `DialogState::Confirmed` or implement ACK timeout.

### 49. SIP: re-INVITE from remote: no 200 OK response sent (sip/engine.rs:1069-1109)
- Updates SDP/state but never responds. Remote re-INVITE times out, may tear down call.
- **Fix**: Send 200 OK with local SDP answer after processing re-INVITE.

### 50. SIP: glare detection swallows re-INVITE silently, no 491 sent (sip/engine.rs:1071-1083)
- `continue` skips re-INVITE entirely. No response at all, violating RFC 3261 §14.2.
- **Fix**: Respond with 491 Request Pending.

### 51. SIP: session timer created but never integrated (sip/engine.rs:1043, 1453)
- `session_timer` always None. RFC 4028 implementation exists but is completely unused.
- **Fix**: Create SessionTimer, add headers, spawn refresh task.

### 52. SIP: no registration refresh mechanism (sip/engine.rs:1296-1357)
- One-shot registration with no refresh. Silently expires.
- **Fix**: Spawn background task at ~50% of expiry to re-register.

### 53. SIP: hangup in Trying/Ringing sends BYE instead of CANCEL (sip/engine.rs:1787-1817)
- BYE only valid after 2xx. Should CANCEL for early dialogs.
- **Fix**: Check state, delegate to `cancel()` for Trying/Ringing/EarlyMedia.

### 54. SIP: send_dtmf_info holds parking_lot Mutex across await (sip/engine.rs:1934, 1959-1968)
- Blocks tokio worker thread if another task tries lock. Potential deadlock.
- **Fix**: Extract dialog ref, drop lock, then await.

### 55. SIP: recv_dtmf_blocking holds Mutex during blocking recv (sip/engine.rs:2129-2135)
- Blocks entire thread for up to timeout duration while holding session lock.
- **Fix**: Extract rtp_engine, drop lock, then call blocking recv.

### 56. SIP: incoming INVITE rate limiting returns without sending 503 (sip/engine.rs:889-903)
- Violates RFC 3261 — every INVITE needs a response. Remote waits for 32s timeout.
- **Fix**: Send 503 Service Unavailable with Retry-After header.

### 57. SIP: RTP engine creation failure doesn't reject call (sip/engine.rs:969-981)
- Call accepted with `rtp_engine: None`, 200 OK sent without SDP body. Violates offer/answer model.
- **Fix**: Send 500 response if RTP engine creation fails.

### 58. SIP: Via header hardcodes UDP transport (sip/engine.rs:728-729, 2450-2452)
- Always uses `SIP/2.0/UDP` even when TCP/TLS configured.
- **Fix**: Use configured transport in Via header.

### 59. SIP: REFER without dialog state check (sip/engine.rs:2417-2436)
- REFER can be sent in Trying/EarlyMedia state. Violates RFC 3515 §1.
- **Fix**: Check `sess.state == CallState::Active`.

### 60. SIP: hold/unhold changes state before re-INVITE confirmed (sip/engine.rs:2302-2373)
- Sets `local_hold = true` and `state = Hold` before re-INVITE response. If rejected, state inconsistent.
- **Fix**: Only update state after re-INVITE succeeds.

### 61. SIP: no handling of incoming BYE — RTP engine not stopped (sip/engine.rs:1162-1170)
- `DialogState::Terminated` emits Hangup but doesn't stop RTP engine. Resources leak.
- **Fix**: Call `rtp.stop()` before removing from calls map.

### 62. SIP: RTP engine not stopped on outbound INVITE failure (sip/engine.rs:1543-1561)
- RTP engine created but never stopped if INVITE fails. Ports leak.
- **Fix**: Call `rtp_engine.stop()` in error handler.

### 63. SIP: no 401/407 auth challenge retry (sip/engine.rs:1484-1561)
- Auth challenges treated as generic error. Calls fail with password-protected gateways.
- **Fix**: Detect 401/407, extract digest challenge, retry with credentials.

### 64. SIP: SDP answer always offers PCMU/PCMA, ignores remote offer (sip/engine.rs:984-992)
- Violates RFC 3264: answer must only include codecs from offer. If remote only offers G.729, no common codec.
- **Fix**: Intersect remote offer codecs with local capabilities.

### 65. RTCP: DLSR calculation overflows after ~18.2 hours (rtcp.rs:1026)
- `elapsed.as_secs() << 16` truncates to u32 after 65535 seconds.
- **Fix**: `elapsed.as_secs().min(65535) << 16`.

### 66. RTCP: jitter calculation hardcodes 8000 Hz clock rate (rtcp.rs:831, 1069)
- `arrival_diff_us * 8 / 1000` assumes 8kHz. Wrong for any other codec clock rate.
- **Fix**: Store clock rate in RtcpSession, use it for conversion.

### 67. RTCP: interval loss calculation can underflow (rtcp.rs:1012-1013)
- `expected - last_rr_expected_packets` is u32 subtraction. Underflows during SSRC change race.
- **Fix**: Use `saturating_sub`.

### 68. RTCP: extended seq number base_seq handling underflows (rtcp.rs:824)
- If `highest_seq < base_seq` with no cycles, unsigned subtraction underflows to u32::MAX.
- **Fix**: Store `base_ext_seq` with cycle count, not bare `base_seq as u32`.

### 69. DNS: SRV lookup uses tokio::net::lookup_host which only does A/AAAA (dns.rs:182-189)
- `lookup_host("_sip._udp.example.com:5060")` does A record lookup on literal string. **SRV resolution completely non-functional**.
- **Fix**: Use `hickory-resolver` or similar library with SRV record support.

### 70. DNS: IPv6 address with port parsing broken (dns.rs:164-173)
- `rfind(':')` on bare IPv6 like `::1` finds address colon, parses `1` as port. Address mangled.
- **Fix**: Skip `rfind(':')` port extraction if string contains multiple colons.

### 71. Session timer: refresher=uac always maps to Local regardless of dialog role (session_timer.rs:347)
- If we're UAS, `refresher=uac` means remote is refresher, but code maps to Local.
- **Fix**: Accept dialog role parameter, invert mapping when UAS.

### 72. Goertzel: DTMF duration includes silence frames (goertzel.rs:263)
- `duration_blocks = detection_count + silence_count`. Should only count active detection frames.
- **Fix**: Use `detection_count` only.

### 73. Goertzel: no energy normalization by block size (goertzel.rs)
- Power threshold (4.0e5) tuned for block_size=102. Different block sizes produce wrong detections.
- **Fix**: Normalize power by `block_size^2` before threshold comparison.

### 74. STUN: ErrorCode encode writes padded_len instead of actual length (stun/attributes.rs:84-88)
- TLV header should contain actual (unpadded) value length per RFC 5389 §15. Extra NUL bytes appended to reason string for non-4-aligned lengths.
- **Fix**: Write `value_len` not `padded_len` in the TLV length field.

### 75. TURN: no permission refresh timer (turn/client.rs)
- Permissions expire after 300s with no refresh. After 5 minutes of a TURN call, peer data silently dropped.
- **Fix**: Refresh permissions at ~240s in the refresh loop.

### 76. TURN: no channel binding refresh timer (turn/client.rs)
- Channel bindings expire after 600s with no refresh. ChannelData silently dropped after 10 minutes.
- **Fix**: Refresh channel bindings at ~480s.

### 77. TURN: stale nonce not handled on retry (turn/client.rs:186)
- 438 Stale Nonce treated as fatal. Server nonce rotation breaks TURN allocation.
- **Fix**: On 438, update nonce and retry.

### 78. STUN: no MESSAGE-INTEGRITY verification on received messages (stun/message.rs:87)
- Tampered STUN/TURN responses accepted as valid.
- **Fix**: Verify HMAC-SHA1 on authenticated responses.

### 79. SDP: session-level direction attributes not propagated to media (sdp.rs)
- `a=sendonly` at session level ignored. All media defaults to SendRecv. Violates RFC 3264 §5.
- **Fix**: Propagate session-level direction to media descriptions unless overridden.

### 80. Resampler: sinc history buffer maintained but never used (resampler.rs:78)
- `self.history` updated after `resample_sinc()` but never passed in. Discontinuity artifacts at buffer boundaries.
- **Fix**: Prepend history buffer to input before sinc filter.

---

## P2 — Robustness / Defensive

### 81. SRTP key material not zeroized on drop (srtp.rs)
- Master keys and session keys never cleared from memory.
- **Fix**: Implement Drop with `zeroize` crate.

### 82. SRTP: simplified ROC estimation heuristic (srtp.rs:694-726)
- Threshold of 0x8000 may fail on extreme reordering. RFC 3711 §3.3.1 specifies full modular arithmetic.
- **Fix**: Implement precise RFC 3711 algorithm.

### 83. SRTP: MKI length validation gap (srtp.rs:188-207)
- `mki_length` can be None even when `mki` bytes present. Auth failure on MKI packets.
- **Fix**: Ensure `mki_length` always set when `mki` is Some.

### 84. DTMF: pop_digit uses Vec::remove(0) — O(n) (dtmf.rs:1083)
- **Fix**: Use VecDeque for O(1) front removal.

### 85. DTMF: reset() clears detected_queue, losing detected digits (dtmf.rs:861)
- **Fix**: Create `reset_state()` that preserves detected queue.

### 86. Jitter: process_redundancy is dead code (jitter.rs:307-374)
- Parses RED headers but never inserts recovered data.
- **Fix**: Implement insertion or remove method.

### 87. Jitter: NACK list grows without bound (jitter.rs:96)
- Never capped or expired. **Fix**: Cap at ~500 entries.

### 88. Jitter: lost counter incremented prematurely (jitter.rs:248-250)
- Missing packet counted as lost immediately, no timeout before declaring loss.
- **Fix**: Wait configurable timeout before declaring gap as lost.

### 89. PLC: pitch correlation threshold 0.3 too low (plc.rs:281)
- G.711 Appendix I uses ~0.6. Low threshold accepts noisy pitch estimates.
- **Fix**: Raise to 0.5-0.6.

### 90. PLC: Hann window denominator off-by-one (plc.rs:382)
- Uses `len` instead of `len-1`. Window doesn't reach 1.0 at last sample (~1% gain error).
- **Fix**: Change to `/ (len - 1) as f32`.

### 91. VAD: WebRTC score threshold+100 can overflow u32 (vad.rs:336/415)
- **Fix**: Use `saturating_add(100)`.

### 92. VAD: no DC offset handling (vad.rs)
- DC bias inflates energy, causing false voice detection on silence.
- **Fix**: Maintain running DC estimate, subtract before computing energy.

### 93. Engine: recv_audio_blocking spin-loops holding Mutex (engine.rs:973-989)
- `std::thread::sleep` blocks tokio worker thread.
- **Fix**: Use async mutex with `.recv().await`, or document sync-only usage.

### 94. Engine: recv_tx.try_send() silently drops audio when channel full (engine.rs:771)
- **Fix**: Log warning (rate-limited) on full channel.

### 95. Engine: std::sync::Mutex for allocated_port/last_cn_level can poison (engine.rs:322, 325)
- **Fix**: Use parking_lot::Mutex consistently.

### 96. SIP: call removal before event broadcast race (sip/engine.rs:1168, 1770)
- Application receives Hangup but get_call() returns None.
- **Fix**: Defer removal until after event broadcast.

### 97. SIP: reject() removes call from map before sending response (sip/engine.rs:1253)
- If reject() fails, call already removed with no recovery.
- **Fix**: Remove only after reject response confirmed.

### 98. SIP: no handling of incoming out-of-dialog requests except INVITE (sip/engine.rs:646-649)
- OPTIONS, MESSAGE, etc. silently dropped. Should send 405 Method Not Allowed.
- **Fix**: Respond 200 OK for OPTIONS, 405 for unsupported methods.

### 99. SIP: broadcast channel capacity 100 may be insufficient (sip/engine.rs:585)
- Events silently dropped on overflow. **Fix**: Increase capacity and/or log overflow.

### 100. SIP: Timer T2 config read but never applied (sip/engine.rs:565-568)
- `timer_t2_ms` is checked but never assigned to endpoint. **Fix**: Apply or remove field.

### 101. STUN: is_stun() doesn't validate message length alignment (stun/message.rs:73)
- RFC 5389 §6: message length must be multiple of 4. Non-aligned packets accepted.
- **Fix**: Check `msg_len % 4 != 0`.

### 102. STUN: marshal() doesn't emit FINGERPRINT attribute (stun/message.rs:153)
- Strict servers may reject messages without FINGERPRINT.
- **Fix**: Append FINGERPRINT after all attributes.

### 103. NAT keepalive: start() task leaks if JoinHandle dropped (keepalive.rs:86)
- No Drop impl. Task runs forever holding Arc refs if stop() never called.
- **Fix**: Store JoinHandle in struct, implement Drop.

### 104. NAT keepalive: dual state — local vars shadow shared fields (keepalive.rs:44-47 vs 98-99)
- External `notify_rebinding()`/`notify_stable()` don't affect background task's local state.
- **Fix**: Task should read from shared state.

### 105. TURN: concurrent recv on same socket (turn/client.rs)
- Refresh loop and permission/channel requests recv on same socket. Responses consumed by wrong handler.
- **Fix**: Multiplex through single recv loop, dispatch by transaction ID.

### 106. SDP: version parsing silently defaults to 0 (sdp.rs:265)
- `unwrap_or(0)` masks malformed SDP. **Fix**: Return error on unparseable version.

### 107. SDP: unknown address types silently accepted (sdp.rs:398)
- **Fix**: Return error for unrecognized address types.

### 108. RTCP: randomized interval upper bound exclusive (rtcp.rs:780)
- Factor in [0.5, 1.5) instead of [0.5, 1.5]. Negligible but noted.

### 109. Codec: is_silence_frame checks exact bytes, missing near-silence (codec.rs)
- Byte-value matching instead of energy-based detection. Near-silence frames not detected.
- **Fix**: Use energy-based silence detection after decoding.
