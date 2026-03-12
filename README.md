# rtpsip

High-performance SIP/RTP library for Voice AI applications, written in Rust with Python bindings via PyO3.

## Operating Modes

| | SIP Mode | RTP-Only Mode |
|---|---|---|
| **Use Case** | Full telephony (signaling + media) | External signaling (WebSocket, custom SIP) |
| **SIP Signaling** | Built-in with rsipstack | Not included |
| **Audio Transport** | RTP with G.711 | RTP with G.711 |
| **Audio Format** | PCM i16, 8kHz mono, 20ms frames | PCM i16, 8kHz mono, 20ms frames |
| **DTMF** | Auto RFC 2833 + SIP INFO | Via external signaling |
| **Hold/Transfer** | Full support | Via external signaling |
| **NAT Traversal** | STUN/TURN/Symmetric RTP | Symmetric RTP |

## Installation

```bash
pip install rtpsip
```

## SIP Signaling

- Multi-provider trunking with longest-prefix routing and default fallback
- Blocked prefix routing for premium rate number protection
- Registration with automatic expiry refresh
- Gateway health monitoring via OPTIONS keepalive
- Inbound call handling: listen, answer, reject with status codes
- Outbound calls: dial, cancel (pre-answer), hangup
- CANCEL support for terminating calls before answer
- 3xx redirect handling with configurable auto-redirect
- Transaction timer configuration (T1, T2, T1x64 per RFC 3261)
- TLS transport with certificate verification
- Contact header NAT rewriting
- Rate limiting: max concurrent calls and requests per second
- 100rel/PRACK provisional reliability (RFC 3262)

## SDP & Media Negotiation

- SDP parsing and generation with telephone-event support
- Greedy codec negotiation with local preference priority
- Codec asymmetry support (different send/receive codecs)
- ptime negotiation (10, 20, 30, 40ms packet sizes)
- Session-level and media-level connection address handling
- Variable telephone-event payload type (96-127)

## Call Control

- 5-state call model: Ringing, EarlyMedia, Active, Hold, Ended
- Early media state machine handling 180/183 ordering from mobile carriers
- Hold/Resume with full RFC 6337 compliance (sendonly, recvonly, inactive, c=0.0.0.0 legacy)
- Re-INVITE send and receive with 491 glare collision handling
- Blind transfer via REFER (RFC 3515)
- Attended transfer with Replaces header for consultation transfer
- REFER NOTIFY subscription tracking with SIP fragment status parsing
- Session timers (RFC 4028) with configurable session-expires and min-SE
- Incoming REFER handling for remote-initiated transfers

## DTMF

- Unified DTMF: auto-detects RFC 2833 vs SIP INFO from remote SDP capabilities
- RFC 2833/4733 telephone-event over RTP with marker bit and end-bit redundancy
- SIP INFO send/receive (application/dtmf-relay, application/dtmf)
- Duration wraparound handling for 16-bit field limits
- Interdigit overlap protection
- Device-specific workarounds (Sonus, Cisco)
- Duration clamping 100-5000ms

## RTP Engine

- G.711 codec: PCMU (μ-law) and PCMA (A-law)
- Adaptive jitter buffer with configurable min/max/target delay
- NACK-based retransmission for packet loss recovery
- FEC support (experimental)
- Packet Loss Concealment via waveform substitution
- Media timeout detection with configurable threshold
- Symmetric RTP: learn remote address from incoming packets (RFC 4961)
- SSRC collision detection and recovery
- Marker bit on stream restart
- Comfort noise generation with VAD

## SRTP

- RFC 3711 SRTP encryption and decryption
- Cipher suites: AES-128-CM with HMAC-SHA1-80 and HMAC-SHA1-32
- Crypto attribute negotiation for SDP
- Error recovery with automatic re-sync on decryption failures

## RTCP

- Sender Reports (SR) and Receiver Reports (RR) per RFC 3550
- Source Description (SDES) with CNAME
- RTCP XR VoIP Metrics (RFC 3611, PT=207): loss rate, discard rate, burst density, gap density, round trip delay, end system delay, signal/noise levels, R-factor, MOS-LQ
- RTCP-mux support (RFC 5761) for RTP/RTCP on same port

## Voice Activity Detection

- Energy-based VAD with configurable RMS threshold
- Hangover mechanism to avoid speech clipping
- Comfort noise insertion during silence periods

## Media Recording

- Media tap for recording call audio (send, receive, or mixed)
- PCM capture to file or buffer
- Runtime start/stop control

## NAT Traversal

- STUN client (RFC 5389) with server pool and automatic failover
- TURN relay (RFC 5766) for symmetric NAT environments
- NAT type detection (RFC 3489/5780): full cone, restricted cone, port restricted, symmetric
- UDP hole punching for NAT pinhole opening
- NAT keepalive with periodic STUN binding requests
- RTP/RTCP/STUN packet demultiplexing on shared sockets

## Authentication

- SIP Digest authentication (RFC 2617)
- MD5 and SHA-256 hash algorithms
- qop=auth support
- Challenge parsing from 401/407 responses

## DNS

- SRV record resolution for SIP server discovery
- A record fallback when SRV is unavailable
- Priority and weight-based server selection

## Device Compatibility

- Automatic device detection from User-Agent header
- Sonus: timestamp-per-packet mode, marker bit disabled
- Cisco: marker bit handling adjustments
- Avaya/legacy Asterisk: c=0.0.0.0 hold method
- Mobile carriers: 180-after-183 early media handling, SDP changes between provisional and final responses

## Python API

- **SipRunner**: Full SIP+RTP client with event loop, GIL released on all blocking operations
- **RtpSession**: RTP-only transport for external signaling
- **CallEvent**: Typed event object with convenience methods (is_incoming, is_answered, is_dtmf, etc.)
- **CallState**: 5-state enum (Ringing, EarlyMedia, Active, Hold, Ended)
- **DtmfMode**: Enum for DTMF method selection (Auto, Rfc2833, Info)
- **Pipecat transports**: SipRtpTransport (any SIP provider) and PlivoRtpTransport (WebSocket+RTP)

## Call Events

| Event | Description |
|-------|-------------|
| incoming | New inbound INVITE with from/to URIs |
| ringing | 180 Ringing received |
| early_media | 183 Session Progress with SDP (remote ringback) |
| answered | 200 OK, call connected |
| audio_ready | Media path established |
| dtmf_received | DTMF digit detected (RFC 2833 or SIP INFO) |
| reinvite | Incoming re-INVITE (hold, codec change, etc.) |
| hangup | Call terminated with reason |
| error | Call error |
| cancelled | CANCEL confirmed for outbound call |
| redirected | 3xx redirect with target URIs |
| media_timeout | No RTP received within timeout |
| transfer_initiated | REFER sent to transfer target |
| transfer_progress | NOTIFY received with transfer status |
| transfer_failed | Transfer failed with error |
| refer_received | Incoming REFER from remote party |
| registration_changed | Registration state changed (registered, failed, expired) |
| gateway_health | OPTIONS keepalive result (server, healthy) |

## Configuration

Configuration via TOML file, environment variables, or programmatic Python API. See `docs.md` for complete parameter reference and `examples/` for usage patterns.

### Environment Variables

```
RTPSIP_PROVIDER     - Provider name
RTPSIP_SERVER       - SIP server address
RTPSIP_AUTH_USERNAME - Authentication username
RTPSIP_AUTH_PASSWORD - Authentication password
```

## Documentation

- `docs.md` — Full configuration reference, all parameters, Python API signatures
- `examples/` — Working usage examples for all features
- `docs/API_REFERENCE.md` — API reference

## License

MIT
