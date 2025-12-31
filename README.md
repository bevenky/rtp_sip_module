# rtpsip

High-performance SIP/RTP library for Voice AI applications, written in Rust with Python bindings.

## Features

| Feature | SIP Mode | RTP Mode |
|---------|----------|----------|
| **Use Case** | Full telephony | External signaling (WebSocket) |
| **SIP Signaling** | Built-in | Not included |
| **Audio Transport** | RTP with G.711 | RTP with G.711 |
| **Audio I/O** | PCM i16 @ 8kHz | PCM i16 @ 8kHz |
| **Jitter Buffer** | Adaptive | Adaptive |
| **DTMF** | RFC 2833 + SIP INFO | Via external signaling |
| **Hold/Transfer** | Full support | Via external signaling |

## Installation

```bash
pip install rtpsip
```

## Quick Start - SIP Mode

### Handle Incoming Calls

```python
from rtpsip import Client, Call

client = Client("sip", config="config.toml")

@client.on_incoming
def handle_incoming(call: Call):
    print(f"Incoming from {call.from_uri}")
    call.answer()

@client.on_hangup
def handle_hangup(call: Call, reason: str):
    print(f"Call ended: {reason}")

client.run()
```

### Make Outbound Calls

```python
from rtpsip import Client, Call
import threading
import time

client = Client("sip", config="config.toml")

@client.on_answered
def handle_answered(call: Call):
    print("Call answered!")
    call.send_dtmf("1#")

@client.on_hangup
def handle_hangup(call: Call, reason: str):
    print(f"Call ended: {reason}")

# Start client in background
thread = threading.Thread(target=client.run, daemon=True)
thread.start()
time.sleep(1)

# Make call
call = client.dial(to="+14155551234", from_="+14155550000")
print(f"Dialing {call.to_uri}...")

thread.join()
```

## Audio Streaming

```python
@client.on_audio
def handle_audio(call: Call, samples: list[int]):
    # samples: 160 PCM i16 values = 20ms @ 8kHz
    response = process_audio(samples)  # Your AI processing
    call.send_audio(response)
```

## DTMF

```python
@client.on_dtmf
def handle_dtmf(call: Call, digit: str):
    print(f"DTMF: {digit}")
    if digit == "1":
        call.send_audio(menu_audio)
    elif digit == "#":
        call.transfer("+14155559999")

@client.on_answered
def handle_answered(call: Call):
    # Send DTMF after call is active
    call.send_dtmf("123#", duration_ms=200)
```

## Call Control

### Hold/Resume

```python
@client.on_answered
def handle_answered(call: Call):
    # Put on hold
    call.hold()

    # Do something...
    time.sleep(5)

    # Resume
    call.unhold()
```

### Transfer

```python
@client.on_dtmf
def handle_dtmf(call: Call, digit: str):
    if digit == "0":
        # Transfer to operator
        call.transfer("+14155550000")
```

## RTP-Only Mode

For external signaling (WebSocket, custom SIP):

```python
from rtpsip import Client, Call

client = Client("rtp")

@client.on_audio
def handle_audio(call: Call, samples: list[int]):
    response = process_audio(samples)
    call.send_audio(response)

# Set remote RTP endpoint (from WebSocket signaling)
client.set_remote("192.168.1.100", 5004)

# Get local port for signaling exchange
print(f"Local RTP port: {client.local_port}")

client.run()
```

## Configuration

### config.toml

```toml
[sip]
local_ip = "0.0.0.0"
local_port = 5060
transport = "udp"

[rtp]
local_ip = "0.0.0.0"
port_start = 10000
port_end = 20000

[[providers]]
name = "plivo"
server = "sip.plivo.com"
auth_username = "AUTH_ID"
auth_password = "AUTH_TOKEN"
prefixes = ["+1"]
default = true

[routing]
blocked_prefixes = ["+1900", "+1976"]
```

### Environment Variables

Config auto-detected from environment if no config file:

```bash
export RTPSIP_PROVIDER=plivo
export RTPSIP_SERVER=sip.plivo.com
export RTPSIP_AUTH_USERNAME=your_auth_id
export RTPSIP_AUTH_PASSWORD=your_auth_token
```

## Call Object Methods

| Method | Description |
|--------|-------------|
| `call.answer()` | Answer incoming call |
| `call.reject(status_code)` | Reject call (486=Busy, 603=Decline) |
| `call.hangup()` | End the call |
| `call.hold()` | Put call on hold |
| `call.unhold()` | Resume from hold |
| `call.transfer(target)` | Blind transfer |
| `call.send_audio(samples)` | Send PCM i16 audio (160 samples = 20ms) |
| `call.send_dtmf(digits, duration_ms)` | Send DTMF digits |

## API Reference

For complete API documentation including low-level interfaces, see [API Reference](docs/API_REFERENCE.md).

## License

MIT
