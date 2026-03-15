# rtpsip

High-performance SIP/RTP library for Voice AI applications, written in Rust with Python bindings via PyO3.

## Overview

rtpsip provides everything needed to build telephony-integrated Voice AI applications:

- **SIP signaling** — registration, call management, transfers, session timers
- **RTP media** — G.711 codec, adaptive jitter buffer, DTMF, PLC, VAD
- **SRTP encryption** — AES-128-CM with HMAC-SHA1, replay protection
- **RTCP quality metrics** — jitter, loss, RTT, MOS score, XR VoIP metrics
- **NAT traversal** — STUN/TURN, symmetric RTP, hole punching, keepalive

Two operating modes:

| | SIP Mode | RTP-Only Mode |
|---|---|---|
| **Use Case** | Full telephony (signaling + media) | External signaling (WebSocket, custom) |
| **SIP Signaling** | Built-in | Not included |
| **Audio** | G.711 PCM i16, 8kHz mono | G.711 PCM i16, 8kHz mono |
| **DTMF** | Auto RFC 2833 + SIP INFO | Via external signaling |
| **NAT** | STUN/TURN/Symmetric RTP | Symmetric RTP |

## Installation

```bash
pip install rtpsip
```

## Quick Start — SIP Mode

```python
from rtpsip import SipRunner

runner = SipRunner(
    server="sip.carrier.com",
    username="user",
    password="secret",
    register=True,
)
runner.start()

# Make a call
call_id = runner.call(to="sip:+14155551234@carrier.com")

# Event loop
while True:
    event = runner.next_event(timeout_ms=30000)
    if event is None:
        continue
    if event.is_answered():
        runner.send_audio(call_id, samples)  # PCM i16, 160 samples = 20ms
    elif event.is_dtmf():
        print(f"DTMF: {event.digit}")
    elif event.is_hangup():
        break

runner.stop()
```

## Quick Start — RTP-Only Mode

```python
from rtpsip import RtpSession

session = RtpSession(
    local_addr="0.0.0.0:0",
    remote_addr="1.2.3.4:5678",
    codec="PCMU",
)
session.start()

session.send_audio(samples)
audio = session.recv_audio(timeout_ms=100)
session.send_dtmf("1", duration_ms=160)

session.stop()
```

## Configuration

Configuration via TOML file, environment variables, or Python API. See [`docs.md`](docs.md) for the complete reference.

```bash
RTPSIP_PROVIDER=mycarrier
RTPSIP_SERVER=sip.carrier.com
RTPSIP_AUTH_USERNAME=user
RTPSIP_AUTH_PASSWORD=secret
```

## Documentation

- **[`docs.md`](docs.md)** — Complete configuration reference, all parameters, Python API
- **[`examples/`](examples/)** — Working examples for all features
- **[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)** — API reference

## Build from Source

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install maturin pytest
maturin develop
cargo test --lib
pytest python/tests/ -v
```

## License

MIT
