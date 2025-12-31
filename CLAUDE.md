# CLAUDE.md

## Project: rtpsip

A high-performance Rust library for SIP signaling and RTP media handling, exposed to Python via PyO3. Designed for Voice AI applications requiring low-latency telephony integration.

**Status: PRODUCTION READY** - 102 Rust tests passing, 52 Python tests passing.

**Industry Compatibility**: Comprehensive edge case handling for interoperability with major VoIP equipment (Sonus, Cisco, Avaya, mobile carriers).

**Latest Improvements:**
- **Pipecat integration** - SipRtpTransport (any SIP provider) + PlivoRtpTransport (WebSocket+RTP)
- **Python config module** - programmatic configuration for SIP/RTP modes
- **Inbound call handling** - receive, answer, and reject incoming INVITE requests
- Early media state machine (handles 180 after 183)
- Greedy codec negotiation (local preference priority)
- Hold/resume with full state tracking (RFC 6337)
- SDP edge case handling (port 0, c=0.0.0.0, direction attributes)
- **GIL-optimized Python bindings** - releases GIL during all blocking ops

---

## Current Implementation Progress

### Core Features ✅
- [x] RTP Engine (codec, jitter buffer, packet handling)
- [x] SIP Engine (rsipstack wrapper)
- [x] SDP parsing/generation with telephone-event
- [x] Multi-provider support with longest-prefix routing
- [x] Config.toml support (UDP/TLS options)
- [x] Blocked prefix routing
- [x] Default provider fallback
- [x] User agent: `plivo-sip-rtp/{version}`
- [x] DTMF send via SIP INFO (uses rsipstack's `dialog.info()`)
- [x] DTMF receive via SIP INFO (parses incoming INFO with dtmf-relay)
- [x] Re-INVITE send (hold/resume, uses rsipstack's `dialog.reinvite()`)
- [x] Re-INVITE receive (via DialogState::Updated events)
- [x] Early media events (ringing, early_media for 180/183 responses)
- [x] RFC 2833/4733 DTMF module (telephone-event payload)
- [x] RFC 2833 integrated into RtpEngine (send/receive via RTP socket)
- [x] SDP with telephone-event (a=rtpmap:101 telephone-event/8000)
- [x] REFER send (RFC 3515 using rsip directly - bypasses rsipstack)
- [x] **Unified DTMF (auto RFC2833/INFO)** - Auto-detects from remote SDP
- [x] Python DTMF bindings with DtmfMode enum (Auto, Rfc2833, Info)
- [x] **Inbound call handling** - listen for, answer, and reject incoming calls
  - Incoming INVITE listener (via rsipstack endpoint.incoming_transactions())
  - ServerInviteDialog for UAS operations
  - answer(call_id) - accept with 200 OK + SDP
  - reject(call_id, status_code) - reject with error response

### Implemented Features ✅
- [x] **Simplified Call States** - 5 states: Ringing, EarlyMedia, Active, Hold, Ended
- [x] **Early Media State Machine** - Handles 180 after 183 (mobile carrier edge case)
- [x] **Greedy Codec Negotiation** - Local preference priority (always enabled)
- [x] **Hold State Tracking** - Full local/remote hold state with RFC 6337 compliance
- [x] **DTMF State Validation** - send_dtmf requires Active state (call answered)
- [x] **SDP Edge Cases:**
  - Port 0 detection (stream disabled)
  - c=0.0.0.0 legacy hold method
  - Direction attributes (sendrecv/sendonly/recvonly/inactive)

### Call States (Simplified)
```python
class CallState:
    Ringing = 0     # 180 - ringing, no media yet
    EarlyMedia = 1  # 183 with SDP - can hear ringback/IVR
    Active = 2      # 200 OK - call answered (DTMF allowed)
    Hold = 3        # on hold (local or remote)
    Ended = 4       # call ended
```

### RFC 2833 DTMF Implementation
- `DtmfPayload` - 4-byte packet format (event, E|volume, duration)
- `DtmfSender` - Generates packets with marker bit and end-bit redundancy
- `DtmfDetector` - Detects digits with sanity checking and deduplication
- Payload type 101, 8000Hz sample rate
- SDP includes `a=rtpmap:101 telephone-event/8000` and `a=fmtp:101 0-16`

### Pending Features
- [ ] DTMF inband send (tone generation)
- [ ] DTMF inband receive (Goertzel tone detection)
- [ ] REFER NOTIFY subscription handling

### Implementation Notes

**Early Media (180/183 handling):**
- 180 without SDP: Generate local ringback
- 183 with SDP: Open media connection for remote ringback
- 180 after 183: Continue using established media (don't revert to local)

**Codec Negotiation:**
- Uses greedy mode: local codec preference priority
- Iterates through local preferences, selects first match in remote offer

**Hold/Resume (RFC 6337):**
- a=sendonly: Local party initiating hold
- a=inactive: Both parties on hold
- a=recvonly: Remote is sending, we receive only
- c=0.0.0.0: Legacy hold method (deprecated but supported)
- Port 0: Stream disabled/rejected

**Edge Cases Handled (Inbound & Outbound):**

All features work identically for both inbound and outbound calls.

*SDP Edge Cases:*
- Port 0: Stream disabled/rejected (RFC 3264)
- c=0.0.0.0: Legacy hold method (Orc, Avaya, legacy Asterisk)
- Different SDP in 183 vs 200 OK (mobile carriers, load balancers)
- Port/IP changes between provisional and final responses
- Missing rtpmap for static payload types (0=PCMU, 8=PCMA)
- Variable telephone-event PT (96-127, not just 101)
- Session vs media level connection addresses

*Early Media Edge Cases:*
- 180 after 183: Mobile carrier behavior - continue using established media
- 183 without SDP: Treat as 180 (some proxies strip SDP)
- Multiple 183: First one with SDP wins, subsequent may update RTP target

*DTMF Edge Cases (RFC 2833 & SIP INFO):*
- Auto-detection from remote SDP telephone-event capability
- Marker bit on first packet, end-bit 3x redundancy (RFC 4733)
- Stuck stream detection (8000 same-timestamp packets = reset)
- SIP INFO whitespace/case variations (Signal=, signal=, SIGNAL=)
- Duration clamping 100-5000ms, default 250ms
- application/dtmf and application/dtmf-relay content types

*Hold/Resume Edge Cases (RFC 6337):*
- a=sendonly/recvonly/inactive direction semantics
- Legacy c=0.0.0.0 hold (deprecated but common)
- Local vs remote hold tracking (both tracked independently)
- Port 0 as stream disabled/hold indicator

*Re-INVITE Edge Cases:*
- Incoming via DialogState::Updated
- SDP and RTP target update on each re-INVITE
- **491 Glare handling (RFC 3261 Section 14.1)**:
  - Auto-retry on 491 "Request Pending" response
  - Outbound calls (Call-ID owner): wait 2.1-4 seconds, retry
  - Inbound calls: wait 0-2 seconds, retry
  - Up to 3 retry attempts with random backoff

*REFER Edge Cases (RFC 3515):*
- Refer-To header auto-wrapped in angle brackets
- Referred-By header (RFC 3892)
- Works with client_dialog (outbound) or server_dialog (inbound)

### Device Compatibility & Auto-Detection

The library automatically detects remote device types from User-Agent header and applies appropriate workarounds:

**Auto-Detection (from User-Agent):**
- `RtpBugFlags::detect_from_user_agent()` parses User-Agent header
- Sonus devices: enables timestamp-per-packet mode, disables marker bit
- Cisco devices: disables marker bit handling
- **Fully automatic for both inbound and outbound calls:**
  - Inbound: Detected from INVITE User-Agent, applied to RTP engine immediately
  - Outbound: Detected from 180/183/200 OK User-Agent, applied when received
- Bug flags automatically propagated to `DtmfSender` via `RtpEngine::set_rtp_bug_flags()`

**DTMF Edge Cases (RFC 4733 + device workarounds):**
- Duration wraparound ("flip" mechanism) - 16-bit duration field wraps at 0xFFFF
- 4-byte payload offset detection - some devices send zero padding before DTMF
- All-zero payload rejection (certain equipment sends malformed packets)
- 30-second digit timeout (sanity limit for stuck streams)
- Stuck stream detection (1500 same-timestamp packets = reset)
- Marker bit on first packet, end-bit 3x redundancy
- **Sonus device workaround**:
  - Increments timestamp per packet (deviates from RFC 4733, but required for Sonus)
  - Disables marker bit on first packet
  - Auto-enabled when "sonus" detected in User-Agent

**SDP/Hold Edge Cases:**
- c=0.0.0.0 legacy hold (RFC 2543, used by Avaya, legacy Asterisk)
- a=sendonly/recvonly/inactive direction semantics
- Port 0 stream disabled/rejected
- Session vs media level connection addresses
- Variable telephone-event PT (96-127, not just 101)

**Early Media Edge Cases:**
- 180 after 183 handling (mobile carrier behavior - continue using established media)
- 183 without SDP treated as 180
- SDP changes between 183 and 200 OK (load balancers, mobile carriers)

### Known Limitations

Features NOT implemented:
- Session timers (RFC 4028) - for long-duration calls
- T.38 fax detection - fax over IP
- DTMF pass-through mode - forwarding DTMF without processing
- Immediate DTMF digit queueing - report digits before end-bit
- Jitter buffer flush on DTMF start - reduce latency for IVR
- REFER NOTIFY subscription handling - transfer progress tracking
- Attended transfer (Replaces header) - consultation transfer

### Crate Workarounds
- **rsipstack 0.3.3**: Has `dialog.info()`, `dialog.reinvite()`, but NO native `refer()` method
  - REFER is implemented using rsip directly (builds proper RFC 3515 request, sends via UDP)
  - Uses dialog ID (Call-ID, tags) from rsipstack, bypasses dialog layer for REFER only
- **webrtc-rs rtp crate**: No RFC 2833 support - implemented from scratch

---

## Configuration (config.toml)

```toml
[sip]
local_ip = "0.0.0.0"
local_port = 5060
transport = "udp"  # or "tls"
# tls_cert = "/path/to/cert.pem"
# tls_key = "/path/to/key.pem"

[rtp]
local_ip = "0.0.0.0"
port_start = 10000
port_end = 20000

# Multiple providers - uses longest prefix match for routing
[[providers]]
name = "plivo_us"
server = "sip.plivo.com"
port = 5060
auth_username = "AUTH_ID"
auth_password = "AUTH_TOKEN"
prefixes = ["+1", "+1415", "+1650"]  # +1415 matches before +1

[[providers]]
name = "plivo_eu"
server = "sip.plivo.com"
port = 5060
auth_username = "AUTH_ID_EU"
auth_password = "AUTH_TOKEN_EU"
prefixes = ["+44", "+49"]
default = true  # Fallback for unmatched prefixes

[routing]
blocked_prefixes = ["+1900", "+1976"]  # Calls fail immediately
```

### Environment Variables

Config is auto-detected from environment variables if no config file is provided:

```bash
RTPSIP_PROVIDER=plivo
RTPSIP_SERVER=sip.plivo.com
RTPSIP_AUTH_USERNAME=your_auth_id
RTPSIP_AUTH_PASSWORD=your_auth_token
```

---

## Python API

### Decorator-Based Interface (Recommended)

The recommended way to use rtpsip is with the decorator-based Client interface:

```python
from rtpsip import Client, Call

# Create client with mode as first argument
# Config is auto-detected from config.toml or environment variables
client = Client("sip", config="config.toml")

# Or auto-detect config (checks env vars, then config.toml in current dir)
# client = Client("sip")

@client.on_incoming
def handle_incoming(call: Call):
    """Handle incoming calls"""
    print(f"Incoming call from {call.from_uri}")
    call.answer()

@client.on_answered
def handle_answered(call: Call):
    """Called when call is answered"""
    print(f"Call {call.id} answered!")
    call.send_dtmf("1#")

@client.on_audio
def handle_audio(call: Call, samples: list[int]):
    """Handle incoming audio - 160 samples = 20ms at 8kHz"""
    # Process audio (e.g., send to STT)
    response = ai.process(samples)
    call.send_audio(response)

@client.on_dtmf
def handle_dtmf(call: Call, digit: str):
    """Handle DTMF digits"""
    print(f"DTMF received: {digit}")

@client.on_hangup
def handle_hangup(call: Call, reason: str):
    """Handle call hangup"""
    print(f"Call ended: {reason}")

# Make outbound call
call = client.dial(to="+14155551234", from_="+14155550000")

# Run the client (blocking)
client.run()
```

Two modes available:
- `"sip"`: Full SIP + RTP (signaling + media)
- `"rtp"`: RTP-only (media only, external signaling via WebSocket)

### Low-Level API (Advanced Usage)

For more control, use the SipRunner directly:

```python
from rtpsip import SipRunner

# From config file (recommended for multi-provider)
runner = SipRunner.from_config("config.toml")

# Or programmatic (single provider)
runner = SipRunner(
    provider_name="plivo",
    provider_server="sip.plivo.com",
    username="AUTH_ID",
    password="AUTH_TOKEN",
)

runner.start()

# Make call - auto-routes based on prefix
call_id = runner.call(to="+14155551234", from_="+14155550000")

# Event loop
while True:
    event = runner.next_event(timeout_ms=30000)
    if event is None:
        continue

    if event.is_ringing():
        print(f"Call {event.call_id} ringing")
    elif event.is_early_media():
        print(f"Call {event.call_id} early media (183)")
        # RTP may be available for ringback tone
    elif event.is_answered():
        print(f"Call {event.call_id} answered")
        # Audio available
        runner.send_audio(call_id, samples)
        audio = runner.recv_audio(call_id, timeout_ms=100)
    elif event.is_dtmf():
        print(f"DTMF received: {event.digit}")
    elif event.is_reinvite():
        print(f"Re-INVITE received with SDP: {event.sdp}")
    elif event.is_hangup():
        print(f"Call {event.call_id} ended: {event.reason}")
        break

# DTMF (auto-selects RFC2833 or SIP INFO based on remote SDP)
# Note: send_dtmf only works after call is Active (answered)
runner.send_dtmf(call_id, "123#", duration_ms=100, inter_digit_ms=100)

# Check which DTMF mode is being used
mode = runner.get_dtmf_mode(call_id)  # DtmfMode.Rfc2833 or DtmfMode.Info

# Receive DTMF (RFC2833 from RTP stream)
dtmf = runner.recv_dtmf(call_id)  # Returns (digit, duration_ms) or None

# Override DTMF mode if needed
from rtpsip import DtmfMode
runner.set_dtmf_mode(call_id, DtmfMode.Info)  # Force SIP INFO

# Hold/Resume (re-INVITE)
runner.hold(call_id)     # sendonly SDP
runner.unhold(call_id)   # sendrecv SDP

# Call transfer (REFER via INFO workaround)
runner.transfer(call_id, "sip:bob@example.com")

runner.hangup(call_id)
runner.stop()
```

### Inbound Call Handling

```python
from rtpsip import SipRunner

runner = SipRunner.from_config("config.toml")
runner.start()  # Starts listening for incoming calls

while True:
    event = runner.next_event(timeout_ms=30000)
    if event is None:
        continue

    if event.is_incoming():
        print(f"Incoming call from {event.from_uri} to {event.to_uri}")
        # Accept the call
        runner.answer(event.call_id)
        # Or reject with status code (486=Busy, 603=Decline)
        # runner.reject(event.call_id, 486)
    elif event.is_answered():
        # Call is now active, can send/receive audio
        runner.send_audio(event.call_id, samples)
    elif event.is_dtmf():
        print(f"DTMF: {event.digit}")
    elif event.is_hangup():
        print(f"Call ended: {event.reason}")
        break

runner.stop()
```

### Mode B: RTP-Only (External Signaling)

Pure audio transport for use with external signaling (WebSocket, custom SIP).

**Included:** Audio send/receive, adaptive jitter buffer, packet loss concealment, G.711 codec.
**NOT included:** SIP signaling, DTMF, authentication, providers - handle these externally.

```python
from rtpsip import RtpSession

session = RtpSession(
    local_addr="0.0.0.0:0",
    remote_addr="1.2.3.4:5678",
    codec="PCMU",  # or "PCMA"
)
session.start()

# Send audio (PCM i16, 8kHz mono, 160 samples = 20ms)
session.send_audio(samples)  # List[int] - PCM i16 samples

# Receive audio (returns L16 PCM i16 samples)
audio = session.recv_audio(100)  # timeout_ms, returns None on timeout

# Jitter buffer stats
stats = session.get_stats()
print(f"Packets: {stats.packets_received}, Lost: {stats.packets_lost}")
print(f"Jitter: {stats.jitter_ms:.1f}ms, Buffer: {stats.buffer_delay_ms}ms")

session.stop()
```

### Pipecat Integration

Two transport types for Pipecat pipelines:

**SipRtpTransport** - Any SIP trunking provider (Twilio, Telnyx, Plivo SIP, etc.):
```python
from rtpsip.pipecat import SipRtpTransport

transport = SipRtpTransport(
    provider_name="twilio",
    server="sip.twilio.com",
    username="ACCOUNT_SID",
    password="AUTH_TOKEN",
)

await transport.start()
call_id = await transport.call(to="+14155551234", from_="+14155550000")

# Use in pipeline
pipeline = Pipeline([
    transport.input(),
    stt_processor,
    llm_processor,
    tts_processor,
    transport.output(),
])
```

**PlivoRtpTransport** - Plivo WebSocket with optional RTP mode:
```python
from rtpsip.pipecat import PlivoRtpTransport

# RTP mode - lower latency, direct UDP audio
transport = PlivoRtpTransport(
    websocket=websocket,
    audio_mode="rtp",  # "websocket" (default) or "rtp"
    rtp_local_port=0,  # Dynamic allocation
)

await transport.start()

# Get local port for signaling exchange
local_port = transport.rtp_local_port

# After receiving remote RTP info from WebSocket
transport.set_rtp_remote(remote_ip, remote_port)

# Use in pipeline
pipeline = Pipeline([
    transport.input(),
    stt,
    llm,
    tts,
    transport.output(),
])
```

---

## Test Results

```
Rust: 102 tests passed
  - Config: 9 tests (multi-provider, routing, blocked prefixes)
  - RTP codec: 4 tests
  - RTP jitter: 4 tests
  - RTP packet: 3 tests
  - RTP engine: 5 tests (+ RFC 2833 loopback, config)
  - RTP DTMF: 22 tests (RFC 4733, device workarounds, auto-detection, Sonus/Cisco modes)
  - SIP SDP: 17 tests (+ hold detection, codec negotiation, direction)
  - SIP engine: 13 tests (+ DTMF INFO parsing, 491 glare handling)
  - Provider config: 5 tests
  - Provider router: 6 tests
  - Session state: 5 tests
  - Session events: 4 tests
  - Session manager: 5 tests

Python: 52 tests passed
  - Mode B (RTP-only): 9 tests (+ websocket workflow, concurrent sessions)
  - Mode A (SIP+RTP): 9 tests
  - Inbound call handling: 7 tests
  - Config module: 27 tests (providers, routing, TOML, validation)
```

---

## Performance Optimizations

### Python GIL Handling

All blocking operations release the Python GIL using `py.allow_threads()` to enable concurrent Python thread execution:

- `call()`, `hangup()` - SIP signaling operations
- `send_audio()`, `recv_audio()` - RTP audio operations
- `next_event()` - Event loop waiting
- `send_dtmf()`, `recv_dtmf_blocking()` - DTMF operations
- `hold()`, `unhold()`, `reinvite()` - Session modifications

### Channel Architecture

| Channel | Type | Purpose |
|---------|------|---------|
| Events | `broadcast::channel` | Multi-consumer call events |
| Audio RX | `mpsc::channel` | RTP audio receive buffer |
| DTMF RX | `mpsc::channel` | RFC 2833 DTMF detection queue |

### Synchronization

- `parking_lot::Mutex` for all internal state (faster than std::sync::Mutex)
- `AtomicBool`, `AtomicU32`, etc. for counters and flags
- Lock-free DTMF detection with atomic state transitions

### Best Practices Applied

- Clone `Arc` references before releasing GIL (avoid lock contention)
- `resubscribe()` for broadcast receiver (avoid holding lock during wait)
- Separate runtime entry from blocking operations
- Minimize Python object lifetime during Rust operations

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
├── CLAUDE.md                # Project documentation
├── .gitignore
├── Cargo.toml
├── Cargo.lock
├── README.md
├── pyproject.toml
├── config.example.toml
├── examples/
│   ├── websocket_rtp_example.py  # Mode B demo
│   └── sip_example.py            # Mode A demo
├── src/                          # Rust source (pure Rust, no FreeSWITCH)
│   ├── lib.rs               # PyO3 module definition
│   ├── config.rs            # TOML config parsing
│   ├── error.rs             # Error types
│   ├── sip/
│   │   ├── engine.rs        # SIP engine (rsipstack)
│   │   └── sdp.rs           # SDP parsing/generation
│   ├── rtp/
│   │   ├── engine.rs        # RTP send/receive
│   │   ├── packet.rs        # RTP packet handling
│   │   ├── jitter.rs        # Jitter buffer
│   │   ├── codec.rs         # G.711 encode/decode
│   │   └── dtmf.rs          # RFC 2833 DTMF
│   ├── session/
│   │   ├── manager.rs       # Multi-session management
│   │   ├── state.rs         # Call state machine
│   │   └── events.rs        # Event definitions
│   ├── provider/
│   │   ├── config.rs        # Provider configuration
│   │   └── router.rs        # Prefix-based routing
│   └── python/
│       ├── session.rs       # PyRtpSession (Mode B)
│       ├── events.rs        # PyCallEvent, PyCallState
│       └── client.rs        # SipRunner Python bindings (Mode A)
└── python/
    ├── rtpsip/
    │   ├── __init__.py      # Main exports
    │   ├── config.py        # Python config classes
    │   └── _rtpsip.pyi   # Type stubs
    ├── pipecat/             # Pipecat integration
    │   ├── __init__.py
    │   ├── sip_rtp_serializer.py   # SIP trunking transport (any provider)
    │   └── plivo_serializer.py     # Plivo WebSocket + RTP transport
    └── tests/
        ├── test_rtp.py      # Mode B tests (9 tests)
        ├── test_sip.py      # Mode A tests (16 tests)
        ├── test_config.py   # Config tests (27 tests)
        └── benchmark_gil.py # GIL release benchmark
```

---

## RFC 2833 Implementation Details

The DTMF module (`src/rtp/dtmf.rs`) implements RFC 4733 telephone-event:

### Payload Format (4 bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     event     |E|R| volume    |          duration            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **event**: 0-9 = digits, 10 = *, 11 = #, 12-15 = A-D
- **E**: End bit (1 = final packet for this event)
- **R**: Reserved (must be 0)
- **volume**: Power level in dBm0 (0-63, typically 10)
- **duration**: In timestamp units (at 8000Hz, 160 = 20ms)

### Key Components
- `DtmfEvent` - Enum for digits 0-9, *, #, A-D
- `DtmfPayload` - Parse/serialize 4-byte format
- `DtmfSender` - Generate packets with marker/end bits
- `DtmfDetector` - Detect with sanity checking
