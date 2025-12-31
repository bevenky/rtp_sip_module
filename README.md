# rtpsip

High-performance SIP/RTP library for Voice AI applications, written in Rust with Python bindings.

## Two Operating Modes

| Feature | Mode A: SIP+RTP | Mode B: RTP-Only |
|---------|-----------------|------------------|
| **Use Case** | Full telephony | External signaling (WebSocket) |
| **SIP Signaling** | Built-in | Not included |
| **Audio Transport** | RTP with G.711 | RTP with G.711 |
| **Audio I/O** | PCM i16 (L16) | PCM i16 (L16) |
| **Jitter Buffer** | Adaptive | Adaptive |
| **DTMF** | RFC 2833 + SIP INFO | Not included* |
| **Providers/Trunks** | Multi-provider routing | Not applicable |
| **Hold/Transfer** | Full support | Transfer via WebSocket |

*Mode B is pure audio transport - DTMF and signaling handled externally via WebSocket.

## Features (Mode A)

- **Full SIP Stack** - Make and receive calls with multi-provider routing
- **RTP Media** - G.711 (PCMU/PCMA) codec with adaptive jitter buffer
- **DTMF Support** - RFC 2833 (in-band RTP) and SIP INFO (out-of-band)
- **Device Compatibility** - Auto-detection for Sonus, Cisco, and other equipment
- **Hold/Resume** - RFC 6337 compliant with direction attribute handling
- **Call Transfer** - Blind transfer via REFER (RFC 3515)
- **GIL-Optimized** - Releases Python GIL during all blocking operations

## Features (Mode B)

- **Pure Audio Transport** - Send/receive PCM i16 samples at 8kHz
- **Adaptive Jitter Buffer** - RFC 3550 compliant with packet loss concealment
- **G.711 Codec** - PCMU (μ-law) or PCMA (A-law) encoding
- **Zero SIP Overhead** - No signaling, authentication, or DTMF processing
- **GIL-Optimized** - Releases Python GIL during all blocking operations

## Installation

```bash
pip install rtpsip
```

Or build from source:

```bash
git clone https://github.com/your-org/rtpsip
cd rtpsip
python -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop
```

---

## Mode A: Full SIP + RTP

Complete telephony solution with SIP signaling and RTP media.

### Quick Start (Decorator Interface)

The recommended way to use rtpsip:

```python
from rtpsip import Client, Call

# Create client with mode and optional config
client = Client("sip", config="config.toml")

# Or auto-detect config from env vars / config.toml
# client = Client("sip")

@client.on_incoming
def handle_incoming(call: Call):
    print(f"Incoming call from {call.from_uri}")
    call.answer()

@client.on_answered
def handle_answered(call: Call):
    print(f"Call {call.id} answered!")
    call.send_dtmf("1#")

@client.on_audio
def handle_audio(call: Call, samples: list[int]):
    # 160 samples = 20ms at 8kHz
    response = process_audio(samples)
    call.send_audio(response)

@client.on_dtmf
def handle_dtmf(call: Call, digit: str):
    print(f"DTMF received: {digit}")

@client.on_hangup
def handle_hangup(call: Call, reason: str):
    print(f"Call ended: {reason}")

# Make outbound call
call = client.dial(to="+14155551234", from_="+14155550000")

# Run the client (blocking)
client.run()
```

### Environment Variables

Config auto-detected from environment if no config file:

```bash
export RTPSIP_PROVIDER=plivo
export RTPSIP_SERVER=sip.plivo.com
export RTPSIP_AUTH_USERNAME=your_auth_id
export RTPSIP_AUTH_PASSWORD=your_auth_token
```

### Low-Level API

For more control, use SipRunner directly:

```python
from rtpsip import SipRunner, CallState, DtmfMode

# Create runner with single provider
runner = SipRunner(
    provider_name="plivo",
    provider_server="sip.plivo.com",
    username="your_auth_id",
    password="your_auth_token",
)

# Start the engine (begins listening for incoming calls)
runner.start()

# Make an outbound call
call_id = runner.call(to="+14155551234", from_="+14155550000")

# Event loop
while True:
    event = runner.next_event(timeout_ms=30000)
    if event is None:
        continue

    if event.is_ringing():
        print(f"Call {event.call_id} is ringing")

    elif event.is_early_media():
        print(f"Early media available (ringback tone)")
        # Can receive audio here (remote ringback)

    elif event.is_answered():
        print(f"Call answered!")
        # Full duplex audio now available

    elif event.is_dtmf():
        print(f"DTMF received: {event.digit}")

    elif event.is_hangup():
        print(f"Call ended: {event.reason}")
        break

runner.stop()
```

### Multi-Provider Configuration

```python
# Use config file for multiple providers with prefix routing
client = Client("sip", config="config.toml")
# Or: runner = SipRunner.from_config("config.toml")
```

**config.toml:**
```toml
[sip]
local_ip = "0.0.0.0"
local_port = 5060
transport = "udp"

[rtp]
local_ip = "0.0.0.0"
port_start = 10000
port_end = 20000

# Provider for US numbers
[[providers]]
name = "plivo_us"
server = "sip.plivo.com"
auth_username = "AUTH_ID"
auth_password = "AUTH_TOKEN"
prefixes = ["+1", "+1415", "+1650"]

# Provider for EU numbers
[[providers]]
name = "plivo_eu"
server = "sip.plivo.com"
auth_username = "AUTH_ID_EU"
auth_password = "AUTH_TOKEN_EU"
prefixes = ["+44", "+49"]
default = true  # Fallback for unmatched prefixes

[routing]
blocked_prefixes = ["+1900", "+1976"]  # Premium rate blocking
```

### Inbound Call Handling

```python
from rtpsip import SipRunner

runner = SipRunner.from_config("config.toml")
runner.start()

while True:
    event = runner.next_event(timeout_ms=30000)

    if event and event.is_incoming():
        print(f"Incoming call from {event.from_uri}")

        # Accept the call
        runner.answer(event.call_id)

        # Or reject with status code
        # runner.reject(event.call_id, 486)  # 486 = Busy
        # runner.reject(event.call_id, 603)  # 603 = Decline
```

### Audio Streaming

```python
# Send audio (PCM i16 samples, 8kHz mono, 160 samples = 20ms)
samples = [0] * 160  # 20ms of silence
runner.send_audio(call_id, samples)

# Receive audio (returns None on timeout)
audio = runner.recv_audio(call_id, timeout_ms=100)
if audio:
    # Process received audio samples
    process_audio(audio)
```

### DTMF (Dual-Tone Multi-Frequency)

```python
# Send DTMF (auto-selects RFC 2833 or SIP INFO based on remote capability)
runner.send_dtmf(call_id, "1234#", duration_ms=100, inter_digit_ms=100)

# With pauses: w = 500ms, W = 1000ms
runner.send_dtmf(call_id, "1w2w3w4#")

# Check which mode is being used
mode = runner.get_dtmf_mode(call_id)  # DtmfMode.Rfc2833 or DtmfMode.Info

# Receive RFC 2833 DTMF from RTP stream
dtmf = runner.recv_dtmf(call_id)
if dtmf:
    digit, duration_ms = dtmf
    print(f"Received: {digit} ({duration_ms}ms)")

# Note: SIP INFO DTMF arrives via next_event() with is_dtmf() == True
```

### Hold/Resume

```python
# Put call on hold (sends re-INVITE with sendonly SDP)
runner.hold(call_id)

# Resume call (sends re-INVITE with sendrecv SDP)
runner.unhold(call_id)

# Check call state
state = runner.get_call_state(call_id)
if state == CallState.Hold:
    print("Call is on hold")
```

### Call Transfer (REFER)

```python
# Blind transfer to another number
runner.transfer(call_id, "sip:+14155559999@sip.provider.com")
```

---

## Mode B: RTP-Only (External Signaling)

Pure audio transport for use with external signaling (WebSocket, custom SIP, etc.).

**What's included:** Audio send/receive, adaptive jitter buffer, packet loss concealment, G.711 codec.

**What's NOT included:** SIP signaling, DTMF, authentication, providers, hold/transfer - handle these externally.

### Quick Start

```python
from rtpsip import RtpSession

# Create session with local and remote addresses
session = RtpSession(
    local_addr="0.0.0.0:0",      # 0 = auto-assign port
    remote_addr="192.168.1.100:5004",
    codec="PCMU",                 # or "PCMA"
)

# Start RTP processing
session.start()

# Check actual local port
print(f"Listening on: {session.local_addr}")

# Send audio (PCM i16 samples, 8kHz mono)
samples = [0] * 160  # 20ms frame
session.send_audio(samples)

# Receive audio with timeout
audio = session.recv_audio(timeout_ms=100)
if audio:
    process_audio(audio)

# Non-blocking receive
audio = session.try_recv_audio()

# Get jitter buffer statistics
stats = session.get_stats()
print(f"Packets received: {stats.packets_received}")
print(f"Packets lost: {stats.packets_lost}")
print(f"Jitter: {stats.jitter_ms:.1f}ms")

session.stop()
```

### Dynamic Remote Address

```python
session = RtpSession(local_addr="0.0.0.0:5004", codec="PCMU")
session.start()

# Set remote address later (e.g., from SDP)
session.set_remote("192.168.1.100:5006")
```

### Jitter Buffer Control

```python
# Reset jitter buffer (e.g., after call transfer)
session.reset_jitter_buffer()

# Get detailed statistics
stats = session.get_stats()
print(f"Buffer size: {stats.buffer_size}")
print(f"Buffer delay: {stats.buffer_delay_ms}ms")
print(f"Packets reordered: {stats.packets_reordered}")
print(f"Packets dropped: {stats.packets_dropped}")
```

---

## Examples

Complete example applications are available in the `examples/` directory:

### WebSocket + RTP Integration (Mode B)

**File:** `examples/websocket_rtp_example.py`

For Voice AI applications using external WebSocket signaling:

```python
from rtpsip import RtpSession

# Workflow for external signaling (e.g., Plivo XML, custom WebSocket)

# 1. Receive remote RTP endpoint from signaling server via WebSocket
# remote_host, remote_port = websocket.recv()

# 2. Create session with dynamic port allocation
session = RtpSession(local_addr="0.0.0.0:0", codec="PCMU")
session.start()

# 3. Get allocated port to send back via WebSocket
local_port = int(session.local_addr.split(":")[1])
# websocket.send({"rtp_host": my_public_ip, "rtp_port": local_port})

# 4. Set remote endpoint when server confirms
session.set_remote(f"{remote_host}:{remote_port}")

# 5. Audio flows - receive L16 samples for speech-to-text
while True:
    audio = session.recv_audio(100)  # List[int] - PCM i16 @ 8kHz
    if audio:
        text = speech_to_text(audio)
        response = ai_generate(text)
        response_audio = text_to_speech(response)
        session.send_audio(response_audio)

# DTMF in Mode B: handled via WebSocket, not RTP
# websocket.send({"type": "dtmf", "digits": "123#"})
```

### Full SIP Telephony (Mode A)

**File:** `examples/sip_example.py`

For traditional telephony with built-in SIP stack:

```python
from rtpsip import SipRunner, DtmfMode

# Create with multi-provider config
runner = SipRunner.from_config("config.toml")
runner.start()

# Make outbound call (auto-routes based on prefix)
call_id = runner.call(to="+14155551234", from_="+14155550000")

# Handle events
while True:
    event = runner.next_event(timeout_ms=30000)

    if event.is_answered():
        # Send DTMF (auto RFC 2833 or SIP INFO)
        runner.send_dtmf(call_id, "123#")

        # Check DTMF mode
        mode = runner.get_dtmf_mode(call_id)
        print(f"Using: {'RFC 2833' if mode == DtmfMode.Rfc2833 else 'SIP INFO'}")

    elif event.is_dtmf():
        # Receive DTMF (SIP INFO arrives via events)
        print(f"DTMF: {event.digit}")

        # RFC 2833 DTMF from RTP stream
        rfc2833_dtmf = runner.recv_dtmf(call_id)
        if rfc2833_dtmf:
            digit, duration = rfc2833_dtmf
            print(f"RFC 2833 DTMF: {digit}")

    elif event.is_hangup():
        break

# Hold, resume, transfer
runner.hold(call_id)
runner.unhold(call_id)
runner.transfer(call_id, "sip:+14155559999@provider.com")

runner.stop()
```

### Running the Examples

```bash
# WebSocket + RTP demo (runs in demo mode without websockets package)
python examples/websocket_rtp_example.py

# SIP demo (shows config and usage)
python examples/sip_example.py
```

---

## API Reference

### Client (Recommended)

| Method/Decorator | Description |
|------------------|-------------|
| `Client(mode, config=None)` | Create client ("sip" or "rtp" mode) |
| `@client.on_incoming` | Decorator for incoming call handler |
| `@client.on_answered` | Decorator for answered handler |
| `@client.on_audio` | Decorator for audio handler |
| `@client.on_dtmf` | Decorator for DTMF handler |
| `@client.on_hangup` | Decorator for hangup handler |
| `client.dial(to, from_)` | Make outbound call, returns Call |
| `client.run()` | Start event loop (blocking) |

### Call

| Method | Description |
|--------|-------------|
| `call.answer()` | Answer incoming call |
| `call.reject(status_code)` | Reject call (486=Busy, 603=Decline) |
| `call.hangup()` | End the call |
| `call.hold()` | Put call on hold |
| `call.unhold()` | Resume from hold |
| `call.transfer(target)` | Blind transfer |
| `call.send_audio(samples)` | Send PCM i16 audio |
| `call.send_dtmf(digits, duration_ms)` | Send DTMF digits |

### SipRunner (Low-Level)

| Method | Description |
|--------|-------------|
| `SipRunner(provider_name, provider_server, ...)` | Create with single provider |
| `SipRunner.from_config(path)` | Create from TOML config file |
| `start()` | Start SIP engine and listener |
| `stop()` | Stop engine and hangup all calls |
| `call(to, from_)` | Make outbound call, returns call_id |
| `hangup(call_id)` | End a call |
| `answer(call_id)` | Answer incoming call |
| `reject(call_id, status_code)` | Reject incoming call |
| `next_event(timeout_ms)` | Wait for next event |
| `send_audio(call_id, samples)` | Send PCM i16 audio |
| `recv_audio(call_id, timeout_ms)` | Receive audio with timeout |
| `send_dtmf(call_id, digits, ...)` | Send DTMF digits |
| `recv_dtmf(call_id)` | Non-blocking DTMF receive |
| `recv_dtmf_blocking(call_id, timeout_ms)` | Blocking DTMF receive |
| `get_dtmf_mode(call_id)` | Get current DTMF mode |
| `set_dtmf_mode(call_id, mode)` | Override DTMF mode |
| `hold(call_id)` | Put call on hold |
| `unhold(call_id)` | Resume from hold |
| `transfer(call_id, target_uri)` | Blind transfer (REFER) |

### RtpSession

| Method | Description |
|--------|-------------|
| `RtpSession(local_addr, remote_addr, codec, ssrc)` | Create session |
| `start()` | Start RTP processing |
| `stop()` | Stop RTP processing |
| `set_remote(addr)` | Set/change remote address |
| `send_audio(samples)` | Send PCM i16 audio |
| `recv_audio(timeout_ms)` | Receive with timeout |
| `try_recv_audio()` | Non-blocking receive |
| `get_stats()` | Get jitter buffer stats |
| `reset_jitter_buffer()` | Reset jitter buffer |

### CallState Enum

```python
from rtpsip import CallState

CallState.Ringing    # 180 - Ringing, no media
CallState.EarlyMedia # 183 - Early media (ringback)
CallState.Active     # 200 OK - Call answered
CallState.Hold       # On hold
CallState.Ended      # Call terminated
```

### DtmfMode Enum

```python
from rtpsip import DtmfMode

DtmfMode.Auto    # Auto-detect from remote SDP (recommended)
DtmfMode.Rfc2833 # Force RFC 2833 in RTP
DtmfMode.Info    # Force SIP INFO
```

---

## Performance

### GIL Handling

All blocking operations release the Python GIL, enabling true concurrency:

```
Benchmark Results (4 concurrent sessions):
- Sequential time: ~1000ms
- Parallel time: ~303ms
- Speedup: 3.30x
- Efficiency: 82.4%
```

### Architecture

- **Rust core** with zero-copy where possible
- **Tokio async runtime** for SIP/RTP I/O
- **parking_lot::Mutex** for fast synchronization
- **Broadcast channels** for event distribution

---

## Device Compatibility

Automatic workarounds for known device quirks:

| Device | Issue | Workaround |
|--------|-------|------------|
| Sonus | Expects wrong DTMF timestamp | Auto-enabled via User-Agent |
| Cisco | Skips marker bit handling | Auto-enabled via User-Agent |
| Avaya | Legacy c=0.0.0.0 hold | Detected and handled |
| Mobile carriers | 180 after 183 | State machine handles correctly |

---

## License

MIT
