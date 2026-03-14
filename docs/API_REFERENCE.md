# rtpsip API Reference

Complete API documentation for the rtpsip library.

## Table of Contents

- [Client](#client)
- [Call](#call)
- [Enums](#enums)
- [Configuration](#configuration)
- [Low-Level API](#low-level-api)
  - [SipRunner](#siprunner)
  - [RtpSession](#rtpsession)
  - [CallEvent](#callevent)

---

## Client

The main high-level interface for SIP/RTP operations.

```python
from rtpsip import Client
```

### Constructor

```python
Client(mode: str, config: Optional[Union[str, Dict]] = None)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | `str` | `"sip"` for SIP+RTP or `"rtp"` for RTP-only |
| `config` | `str \| Dict \| None` | Path to config.toml, dict, or None for auto-detect |

**Config auto-detection order:**
1. Provided config dict/path
2. `config.toml` in current directory
3. Environment variables

### Decorators

| Decorator | Signature | Description |
|-----------|-----------|-------------|
| `@client.on_incoming` | `(call: Call) -> None` | Incoming call received |
| `@client.on_ringing` | `(call: Call) -> None` | Outbound call ringing |
| `@client.on_answered` | `(call: Call) -> None` | Call answered |
| `@client.on_audio` | `(call: Call, samples: list[int]) -> None` | Audio received (160 samples = 20ms) |
| `@client.on_dtmf` | `(call: Call, digit: str) -> None` | DTMF digit received |
| `@client.on_hangup` | `(call: Call, reason: str) -> None` | Call ended |

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `run()` | `() -> None` | Start client and run event loop (blocking) |
| `dial()` | `(to: str, from_: str) -> Call` | Make outbound call |
| `set_remote()` | `(ip: str, port: int) -> None` | Set remote RTP endpoint (RTP mode) |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `local_port` | `Optional[int]` | Local RTP port (RTP mode only) |
| `local_addr` | `Optional[str]` | Local RTP address (RTP mode only) |

---

## Call

Represents an active call session.

```python
from rtpsip import Call
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique call identifier |
| `from_uri` | `str` | Caller URI |
| `to_uri` | `str` | Callee URI |
| `state` | `str` | Current state: `"ringing"`, `"early_media"`, `"active"`, `"ended"` |
| `direction` | `str` | `"inbound"` or `"outbound"` |

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `answer()` | `() -> None` | Answer incoming call |
| `reject()` | `(status_code: int = 486) -> None` | Reject call (486=Busy, 603=Decline) |
| `hangup()` | `() -> None` | End the call |
| `hold()` | `() -> None` | Put call on hold |
| `unhold()` | `() -> None` | Resume from hold |
| `transfer()` | `(target: str) -> None` | Transfer call to target |
| `send_audio()` | `(samples: list[int]) -> None` | Send audio (PCM i16, 8kHz, 160 samples = 20ms) |
| `send_dtmf()` | `(digits: str, duration_ms: int = 250) -> None` | Send DTMF digits |

---

## Enums

### CallState

```python
from rtpsip import CallState

class CallState(IntEnum):
    Ringing = 0      # 180 - ringing, no media
    EarlyMedia = 1   # 183 with SDP - can hear ringback
    Active = 2       # 200 OK - call answered
    Hold = 3         # On hold
    Ended = 4        # Call terminated
```

### DtmfMode

```python
from rtpsip import DtmfMode

class DtmfMode(IntEnum):
    Auto = 0      # Auto-detect from remote SDP (recommended)
    Rfc2833 = 1   # Force RFC 2833 in RTP (telephone-event)
    Info = 2      # Force SIP INFO
```

### Transport

```python
from rtpsip import Transport

class Transport(IntEnum):
    Udp = 0
    Tcp = 1
    Tls = 2
    WebSocket = 3
```

---

## Configuration

### config.toml Format

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

# Provider configuration
[[providers]]
name = "plivo"
server = "sip.plivo.com"
port = 5060
username = "AUTH_ID"
password = "AUTH_TOKEN"
prefixes = ["+1"]
default = true

# Multiple providers with prefix routing
[[providers]]
name = "plivo_eu"
server = "sip.plivo.com"
port = 5060
username = "AUTH_ID_EU"
password = "AUTH_TOKEN_EU"
prefixes = ["+44", "+49"]

[routing]
blocked_prefixes = ["+1900", "+1976"]
```

### Environment Variables

```bash
RTPSIP_PROVIDER=plivo
RTPSIP_SERVER=sip.plivo.com
RTPSIP_AUTH_USERNAME=your_auth_id
RTPSIP_AUTH_PASSWORD=your_auth_token
RTPSIP_LOCAL_IP=0.0.0.0
RTPSIP_LOCAL_PORT=5060
RTPSIP_TRANSPORT=udp
```

### ProviderConfig Class

```python
from rtpsip import ProviderConfig, Transport

config = ProviderConfig(
    id="plivo",
    sip_server="sip.plivo.com",
    username="AUTH_ID",
    password="AUTH_TOKEN",
    name="Plivo US",           # Optional, defaults to id
    sip_port=5060,             # Default: 5060
    transport=Transport.Udp,   # Default: UDP
    realm=None,                # Optional auth realm
    from_domain=None,          # Optional From header domain
    prefixes=["+1"],           # Phone prefixes for routing
    priority=1,                # Lower = higher priority
    max_concurrent=None,       # Max concurrent calls
    register=False,            # SIP REGISTER
    register_interval=300,     # Registration interval (seconds)
)
```

---

## Low-Level API

For advanced use cases requiring direct control.

### SipRunner

Full SIP + RTP engine with direct control.

```python
from rtpsip import SipRunner, ProviderConfig
```

#### Constructor

```python
SipRunner(
    local_addr: str = "0.0.0.0:5060",
    rtp_port_start: int = 10000,
    rtp_port_end: int = 20000,
)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `add_provider()` | `(config: ProviderConfig) -> None` | Add SIP provider |
| `remove_provider()` | `(provider_id: str) -> None` | Remove provider |
| `start()` | `() -> None` | Start SIP engine |
| `stop()` | `() -> None` | Stop SIP engine |
| `is_running()` | `() -> bool` | Check if running |
| `call()` | `(to: str, from_: str, provider_id: str = None) -> str` | Make call, returns call_id |
| `hangup()` | `(call_id: str) -> None` | End call |
| `answer()` | `(call_id: str) -> None` | Answer incoming call |
| `reject()` | `(call_id: str, status_code: int = 486) -> None` | Reject call |
| `send_audio()` | `(call_id: str, samples: list[int]) -> None` | Send audio |
| `recv_audio()` | `(call_id: str, timeout_ms: int) -> list[int]` | Receive audio |
| `send_dtmf()` | `(call_id: str, digits: str, duration_ms: int = 100, inter_digit_ms: int = 100) -> None` | Send DTMF |
| `recv_dtmf()` | `(call_id: str) -> Optional[tuple[str, int]]` | Non-blocking DTMF receive |
| `recv_dtmf_blocking()` | `(call_id: str, timeout_ms: int) -> Optional[tuple[str, int]]` | Blocking DTMF receive |
| `get_dtmf_mode()` | `(call_id: str) -> DtmfMode` | Get DTMF mode for call |
| `set_dtmf_mode()` | `(call_id: str, mode: DtmfMode) -> None` | Override DTMF mode |
| `hold()` | `(call_id: str) -> None` | Put on hold |
| `unhold()` | `(call_id: str) -> None` | Resume from hold |
| `transfer()` | `(call_id: str, target: str) -> None` | Blind transfer (REFER) |
| `reinvite()` | `(call_id: str, sdp: str = None) -> None` | Send re-INVITE |
| `next_event()` | `(timeout_ms: int) -> Optional[CallEvent]` | Get next event |
| `active_calls()` | `() -> list[str]` | Get active call IDs |
| `get_call_state()` | `(call_id: str) -> Optional[CallState]` | Get call state |

#### Example

```python
from rtpsip import SipRunner, ProviderConfig

runner = SipRunner()
runner.add_provider(ProviderConfig(
    id="plivo",
    sip_server="sip.plivo.com",
    username="AUTH_ID",
    password="AUTH_TOKEN",
    prefixes=["+1"],
))
runner.start()

call_id = runner.call(to="+14155551234", from_="+14155550000")

while True:
    event = runner.next_event(timeout_ms=100)
    if event and event.is_answered():
        runner.send_audio(call_id, samples)
        audio = runner.recv_audio(call_id, timeout_ms=100)
    elif event and event.is_hangup():
        break

runner.stop()
```

---

### RtpSession

RTP-only session for external signaling scenarios.

```python
from rtpsip import RtpSession
```

#### Constructor

```python
RtpSession(
    local_addr: str = "0.0.0.0:0",
    remote_addr: Optional[str] = None,
    codec: str = "PCMU",
    ssrc: Optional[int] = None,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `local_addr` | `str` | Local bind address (`host:port`, port 0 = ephemeral) |
| `remote_addr` | `str \| None` | Remote RTP endpoint (can set later) |
| `codec` | `str` | `"PCMU"` or `"PCMA"` |
| `ssrc` | `int \| None` | SSRC identifier (auto-generated if None) |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `local_addr` | `str` | Local address (available after start) |
| `remote_addr` | `Optional[str]` | Remote address |
| `ssrc` | `int` | SSRC identifier |
| `codec` | `str` | Codec type |
| `is_running` | `bool` | Running status |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `start()` | `() -> None` | Start session |
| `stop()` | `() -> None` | Stop session |
| `set_remote()` | `(addr: str) -> None` | Set remote endpoint |
| `send_audio()` | `(samples: list[int]) -> None` | Send audio (PCM i16, 8kHz) |
| `recv_audio()` | `(timeout_ms: int) -> Optional[list[int]]` | Receive audio |
| `get_stats()` | `() -> JitterStats` | Get jitter buffer stats |
| `reset_jitter_buffer()` | `() -> None` | Reset jitter buffer |

#### JitterStats

```python
stats = session.get_stats()
stats.packets_received   # int
stats.packets_lost       # int
stats.packets_dropped    # int (late arrivals)
stats.packets_reordered  # int
stats.jitter_ms          # float
stats.buffer_delay_ms    # int
stats.buffer_size        # int (packets in buffer)
```

#### Example

```python
from rtpsip import RtpSession

session = RtpSession(
    local_addr="0.0.0.0:0",
    codec="PCMU",
)
session.start()

# Get local port for signaling
print(f"Local RTP port: {session.local_addr}")

# Set remote after receiving from signaling
session.set_remote("192.168.1.100:5004")

# Audio loop
while True:
    samples = session.recv_audio(100)
    if samples:
        response = process(samples)
        session.send_audio(response)

session.stop()
```

---

### CallEvent

Event from the SIP engine.

```python
from rtpsip import CallEvent
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `event_type` | `str` | Event type string |
| `call_id` | `str` | Call ID |
| `from_uri` | `Optional[str]` | From URI (incoming calls) |
| `to_uri` | `Optional[str]` | To URI (incoming calls) |
| `reason` | `Optional[str]` | Hangup reason |
| `error` | `Optional[str]` | Error message |
| `sdp` | `Optional[str]` | SDP body (early_media, reinvite) |
| `digit` | `Optional[str]` | DTMF digit |
| `duration` | `Optional[int]` | DTMF duration (ms) |

#### Event Type Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `is_incoming()` | `bool` | Incoming INVITE received |
| `is_ringing()` | `bool` | 180 Ringing |
| `is_early_media()` | `bool` | 183 Session Progress with SDP |
| `is_answered()` | `bool` | 200 OK |
| `is_audio_ready()` | `bool` | Audio stream ready |
| `is_dtmf()` | `bool` | DTMF digit received |
| `is_reinvite()` | `bool` | Re-INVITE received |
| `is_hangup()` | `bool` | Call ended |
| `is_error()` | `bool` | Error occurred |

---

## Audio Format

All audio in rtpsip uses:
- **Format**: PCM signed 16-bit (i16)
- **Sample rate**: 8000 Hz (8kHz)
- **Channels**: Mono (1 channel)
- **Frame size**: 160 samples = 20ms

```python
# Send 20ms of audio
samples = [0] * 160  # 160 PCM i16 samples
call.send_audio(samples)

# Receive audio
@client.on_audio
def handle_audio(call: Call, samples: list[int]):
    # samples is List[int] with 160 values
    pass
```

---

## Error Handling

All methods may raise `RtpSipError` for SIP/RTP failures:

```python
from rtpsip import RtpSipError

try:
    call = client.dial(to="+14155551234", from_="+14155550000")
except RtpSipError as e:
    print(f"Call failed: {e}")
```

---

## Thread Safety

- `Client.run()` is blocking - use threading for concurrent operations
- All SipRunner methods release the Python GIL during blocking operations
- Multiple calls can be handled concurrently

```python
import threading

client = Client("sip", config="config.toml")

@client.on_incoming
def handle_incoming(call: Call):
    call.answer()

# Run in background thread
thread = threading.Thread(target=client.run, daemon=True)
thread.start()

# Make calls from main thread
call = client.dial(to="+14155551234", from_="+14155550000")
```
