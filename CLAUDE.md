# CLAUDE.md

## Project: rtpsip

A high-performance Rust library for SIP signaling and RTP media handling, exposed to Python via PyO3. Designed for Voice AI applications requiring low-latency telephony integration.

**Status: PRODUCTION READY** - 212 Rust tests passing, 52 Python tests passing.

**Industry Compatibility**: Comprehensive edge case handling for interoperability with major VoIP equipment (Sonus, Cisco, Avaya, mobile carriers).

---

## Build & Test

```bash
# Create virtual env
python3 -m venv .venv
source .venv/bin/activate
pip install maturin pytest

# Development build
maturin develop

# Run all tests
cargo test --lib
pytest python/tests/ -v
```

---

## Project Structure

```
rtp_sip_module/
├── Cargo.toml
├── pyproject.toml
├── config.example.toml
├── README.md               # Feature overview (no code examples)
├── CLAUDE.md               # Developer reference
├── docs.md                 # Full configuration & API reference
├── AUDIT.md                # Code audit document
├── examples/               # Usage examples
│   ├── sip_example.py          # Full SIP+RTP telephony app
│   ├── websocket_rtp_example.py # RTP-only with WebSocket signaling
│   ├── transfer_example.py     # Blind and attended transfer
│   ├── registration_example.py # Registration and gateway health
│   ├── nat_traversal_example.py # NAT/STUN/TURN setup
│   └── quality_monitoring_example.py # RTCP XR, VAD, media tap
├── docs/
│   └── API_REFERENCE.md    # API reference
├── src/                    # Rust source
│   ├── lib.rs              # PyO3 module definition
│   ├── config.rs           # TOML config parsing, Transport enum
│   ├── error.rs            # Error types
│   ├── sip/
│   │   ├── mod.rs          # SIP module exports
│   │   ├── engine.rs       # SIP engine (rsipstack wrapper, call management)
│   │   ├── sdp.rs          # SDP parsing/generation
│   │   ├── digest_auth.rs  # RFC 2617 Digest authentication
│   │   ├── dns.rs          # SRV/A record DNS resolution
│   │   └── session_timer.rs # RFC 4028 session timers
│   ├── rtp/
│   │   ├── mod.rs          # RTP module exports
│   │   ├── engine.rs       # RTP send/receive engine
│   │   ├── packet.rs       # RTP packet parsing/serialization
│   │   ├── jitter.rs       # Adaptive jitter buffer with NACK
│   │   ├── codec.rs        # G.711 PCMU/PCMA codec
│   │   ├── dtmf.rs         # RFC 2833/4733 DTMF
│   │   ├── srtp.rs         # SRTP encryption (RFC 3711) with error recovery
│   │   ├── rtcp.rs         # RTCP (RFC 3550) + XR VoIP Metrics (RFC 3611)
│   │   ├── plc.rs          # Packet Loss Concealment
│   │   ├── vad.rs          # Voice Activity Detection
│   │   └── media_tap.rs    # Media recording/tapping
│   ├── nat/
│   │   ├── mod.rs          # NAT module exports
│   │   ├── config.rs       # NAT configuration
│   │   ├── manager.rs      # NAT traversal coordinator
│   │   ├── detect.rs       # NAT type detection (RFC 3489/5780)
│   │   ├── symmetric_rtp.rs # Symmetric RTP (RFC 4961)
│   │   ├── hole_punch.rs   # UDP hole punching
│   │   ├── keepalive.rs    # NAT binding keepalive
│   │   ├── demux.rs        # RTP/RTCP/STUN packet demultiplexing
│   │   ├── types.rs        # NatType, TraversalStrategy enums
│   │   ├── stun/           # STUN client (RFC 5389)
│   │   └── turn/           # TURN relay (RFC 5766)
│   ├── session/
│   │   ├── manager.rs      # Multi-session management
│   │   ├── state.rs        # Call state machine
│   │   └── events.rs       # Event definitions
│   ├── provider/
│   │   ├── config.rs       # Provider configuration
│   │   └── router.rs       # Longest-prefix routing
│   └── python/
│       ├── session.rs      # PyRtpSession (RTP-only mode)
│       ├── events.rs       # PyCallEvent, PyCallState
│       └── client.rs       # PySipRunner Python bindings
└── python/
    ├── rtpsip/
    │   ├── __init__.py     # Main exports
    │   ├── config.py       # Python config classes
    │   └── _rtpsip.pyi     # Type stubs
    └── tests/
        ├── test_rtp.py     # RTP-only tests
        ├── test_sip.py     # SIP+RTP tests
        ├── test_config.py  # Config tests
        └── benchmark_gil.py # GIL benchmark
```

---

## Implemented Features

### SIP Signaling
- SIP engine with rsipstack (registration, invite, bye, cancel, refer)
- SDP parsing/generation with telephone-event
- Multi-provider support with longest-prefix routing
- Blocked prefix routing and default provider fallback
- Inbound call handling (listen, answer, reject)
- Outbound call management (dial, cancel, hangup)
- CANCEL handling for pre-answer call termination
- 3xx redirect handling with auto-redirect support
- Re-INVITE send/receive with 491 glare handling
- REFER send (RFC 3515 blind transfer via raw rsip)
- Attended transfer (Replaces header)
- REFER NOTIFY subscription tracking with SIP fragment parsing
- Hold/Resume with full state tracking (RFC 6337)
- Session timers (RFC 4028) with configurable refresh roles
- Digest authentication (RFC 2617, MD5/SHA-256, qop=auth)
- DNS SRV/A record resolution
- Registration expiry/refresh with state change events
- Gateway health monitoring (OPTIONS keepalive)
- Transaction timer configuration (T1, T2, T1x64)
- TLS transport support with certificate verification
- Contact header NAT rewriting
- Rate limiting (max calls, max requests/sec)
- 100rel/PRACK support (RFC 3262, configurable)

### RTP Media
- RTP packet handling (parse/serialize)
- G.711 codec (PCMU μ-law, PCMA A-law)
- Adaptive jitter buffer with NACK-based retransmission
- RFC 2833/4733 DTMF over RTP (telephone-event)
- Unified DTMF (auto-detection RFC 2833 vs SIP INFO from remote SDP)
- DTMF duration wraparound handling (16-bit field)
- DTMF interdigit overlap protection
- SRTP encryption/decryption (RFC 3711) with error recovery
- RTCP (RFC 3550) with sender/receiver reports
- RTCP XR VoIP Metrics (RFC 3611, PT=207)
- RTCP-mux support (RFC 5761, RTP/RTCP on same port)
- Packet Loss Concealment (waveform substitution)
- Voice Activity Detection (energy-based with hangover)
- Media recording/tapping (PCM capture)
- Media timeout detection (dead stream, configurable)
- Symmetric RTP (learn remote address from incoming packets, RFC 4961)
- SSRC collision recovery
- Marker bit on stream restart
- Codec asymmetry support
- ptime negotiation (10/20/30/40ms)
- Comfort noise generation

### NAT Traversal
- STUN client (RFC 5389) with server pool and failover
- TURN relay (RFC 5766) for symmetric NAT
- NAT type detection (RFC 3489/5780)
- UDP hole punching
- NAT keepalive with periodic STUN binding requests
- RTP/RTCP/STUN packet demultiplexing

### Python Bindings (PyO3)
- SipRunner with GIL-released blocking operations
- RtpSession for RTP-only mode
- CallEvent with typed convenience methods
- CallState enum (Ringing, EarlyMedia, Active, Hold, Ended)
- DtmfMode enum (Auto, Rfc2833, Info)

### Device Compatibility
- RtpBugFlags auto-detection from User-Agent header
- Sonus: timestamp-per-packet mode, marker bit disabled
- Cisco: marker bit handling adjustments
- Avaya/legacy: c=0.0.0.0 hold method support

---

## Call States

5-state model: Ringing → EarlyMedia → Active → Hold → Ended

---

## Call Events

| Event | Fields | Description |
|-------|--------|-------------|
| Incoming | call_id, from, to | New inbound INVITE |
| Ringing | call_id | 180 Ringing |
| EarlyMedia | call_id, sdp | 183 Session Progress with SDP |
| Answered | call_id | 200 OK |
| AudioReady | call_id | Media path established |
| DtmfReceived | call_id, digit, duration | DTMF digit detected |
| ReInvite | call_id, sdp | Incoming re-INVITE |
| Hangup | call_id, reason | Call terminated (BYE) |
| Error | call_id, error | Call error |
| Cancelled | call_id | Outbound CANCEL confirmed |
| Redirected | call_id, targets | 3xx redirect received |
| MediaTimeout | call_id | No RTP received within timeout |
| TransferInitiated | call_id, target | REFER sent |
| TransferProgress | call_id, status_code, reason, completed | NOTIFY received for REFER |
| TransferFailed | call_id, error | Transfer failed |
| ReferReceived | call_id, refer_to | Incoming REFER from remote |
| RegistrationChanged | state, error | Registration state changed |
| GatewayHealth | server, healthy | OPTIONS keepalive result |

---

## Crate Workarounds

- **rsipstack 0.3.3**: Has `dialog.info()`, `dialog.reinvite()`, but NO native `refer()` method. REFER is implemented using rsip directly (builds RFC 3515 request, sends via UDP). DialogState variants use 2-field patterns: `Updated(DialogId, Request)`, `Info(DialogId, Request)`, `Notify(DialogId, Request)`, `Options(DialogId, Request)`. DialogId uses `from_tag`/`to_tag` (not `local_tag`/`remote_tag`).
- **Registration**: `register()` returns `Result<Response>`, `expires()` returns `u32` (not `Option<u32>`). Stored as `Arc<tokio::sync::Mutex<Registration>>`.

---

## Performance

- `parking_lot::Mutex` for sync state (faster than std)
- `py.allow_threads()` releases GIL on all blocking ops (12 call sites)
- `broadcast::channel` for multi-consumer events
- `mpsc::channel` for audio RX and DTMF RX queues
- Atomic types for counters and flags
- Lock-free DTMF detection with atomic state transitions

---

## Test Results

```
Rust: 212 tests passed
  - Config: 9 tests
  - RTP codec: 4 tests
  - RTP jitter: 4 tests
  - RTP packet: 3 tests
  - RTP engine: 5 tests
  - RTP DTMF: 22 tests
  - RTCP: session tests with XR reports
  - SRTP: encryption/decryption/error recovery
  - PLC: packet loss concealment
  - VAD: voice activity detection
  - SIP SDP: 17 tests
  - SIP engine: 13 tests
  - SIP digest auth: RFC 2617 compliance
  - SIP DNS: SRV/A resolution
  - SIP session timer: RFC 4028
  - NAT: STUN, TURN, detection, hole punching
  - Provider config: 5 tests
  - Provider router: 6 tests
  - Session state: 5 tests
  - Session events: 4 tests
  - Session manager: 5 tests

Python: 52 tests passed
  - RTP-only mode: 9 tests
  - SIP+RTP mode: 9 tests
  - Inbound calls: 7 tests
  - Config: 27 tests
```
