# rtp_sip

Python bindings with **embedded libfs (FreeSWITCH)** for SIP/RTP telephony. No external dependencies required.

## Overview

rtp_sip provides async Python bindings to libfs (FreeSWITCH 1.10.12) for SIP signaling and RTP audio transport. libfs is **statically linked** into the Python module - no separate FreeSWITCH installation needed.

**Design Philosophy**: Embedded libfs with thin wrappers. The final `.whl` file (~15-20MB) contains everything needed for telephony.

## Three Modes

| Mode | Description | Status |
|------|-------------|--------|
| **Mode 3: RTP-Only** | External SIP, rtp_sip handles RTP only | **Working** |
| **Mode 1: Outbound** | Python initiates calls via `SIP.dial()` | Limited (mod_sofia unavailable) |
| **Mode 2: Inbound** | Python receives calls via `set_inbound_handler()` | Limited (mod_sofia unavailable) |

**Note:** RTP-only mode is fully functional. SIP modes are limited because mod_sofia doesn't load in embedded mode.

## Installation

### Using Docker (Recommended)

```bash
# Build the builder image (includes libfs)
docker build -t pyswitch-builder -f docker-build/Dockerfile.builder .

# Build the wheel
docker run --rm -v "$(pwd)":/workspace -w /workspace pyswitch-builder \
    maturin build --release

# Install the wheel
pip install target/wheels/rtp_sip-*.whl
```

### From Source (requires pre-built libfs)

```bash
# 1. Build libfs static libraries first
./scripts/build-freeswitch.sh

# 2. Build Python module
maturin build --release
pip install target/wheels/rtp_sip-*.whl
```

### Requirements

- Python 3.9+
- Rust 1.70+
- libfs static libraries (built by `scripts/build-freeswitch.sh`)

The wheel is self-contained - no runtime dependencies on FreeSWITCH.

## Quick Start

### Mode 3: RTP-Only

For external SIP signaling (WebSocket, SIP proxy):

```python
import asyncio
from rtp_sip import RtpSession, AudioFrame

async def main():
    # Create RTP session (remote IP, remote port)
    session = RtpSession("192.168.1.100", 5006)
    session.with_local_port(5004)  # Optional: set local port

    await session.start()
    print(f"RTP session started on port {session.local_port}")

    try:
        while True:
            # Receive audio (L16 PCM, 16kHz, mono)
            frame = await session.recv_audio(100)
            if frame:
                # Process with STT, generate TTS response...
                await session.send_audio(frame)
    finally:
        await session.stop()

asyncio.run(main())
```

### Mode 1: Outbound Calls

Python initiates calls via SIP trunk:

```python
import asyncio
from rtp_sip import SIP, SipConfig, TrunkConfig

async def main():
    # Configure SIP stack
    sip = SIP(SipConfig(local_port=5060))
    await sip.start()

    # Add SIP trunk (carrier/provider)
    await sip.add_trunk(TrunkConfig(
        "mytrunk", "sip.provider.com",
        username="user", password="secret"
    ))

    # Dial outbound call
    call = await sip.dial("+18005551234", "mytrunk")

    print(f"Call connected: {call.id}")

    # Audio loop
    while call.is_active:
        frame = await call.recv_audio(100)  # L16 @ 16kHz
        if frame:
            # Process with STT, generate TTS...
            await call.send_audio(response_frame)

    await call.hangup()
    await sip.stop()

asyncio.run(main())
```

### Mode 2: Inbound Calls

Python receives incoming calls:

```python
import asyncio
from rtp_sip import SIP, SipConfig, TrunkConfig

async def handle_call(call):
    """Handler for incoming calls"""
    print(f"Incoming call: {call.id}")

    # Answer the call
    await call.answer()

    # Audio processing loop
    while call.is_active:
        frame = await call.recv_audio(100)
        if frame:
            # Process audio (STT -> LLM -> TTS)
            await call.send_audio(response_frame)

    print(f"Call {call.id} ended")

async def main():
    sip = SIP(SipConfig(local_port=5060))

    # Register inbound handler
    sip.set_inbound_handler(handle_call)

    await sip.start()

    # Add trunk with registration for inbound
    await sip.add_trunk(TrunkConfig(
        "mytrunk", "sip.provider.com",
        username="user", password="secret"
    ))

    print("Waiting for incoming calls...")

    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass

    await sip.stop()

asyncio.run(main())
```

## Architecture

### Audio Pipeline

```
INBOUND (Caller -> Python):
  RTP UDP (G.711 @ 8kHz) -> FreeSWITCH Decode -> Resample 8k->16k -> Python

OUTBOUND (Python -> Caller):
  Python (L16 @ 16kHz) -> Resample 16k->8k -> FreeSWITCH Encode G.711 -> RTP UDP
```

| Direction | Wire Format | Python Format |
|-----------|-------------|---------------|
| RTP In/Out | G.711 PCMU/PCMA @ 8kHz | L16 PCM @ 16kHz mono |

Conversion is automatic - you always work with 16kHz L16 in Python.

### Threading Model

```
Python Main Thread (asyncio)
         |
         | pyo3-asyncio (GIL released)
         v
Tokio Runtime (multi-threaded)
    +-- RTP Rx Task (recv from UDP, decode, resample, queue)
    +-- RTP Tx Task (dequeue, resample, encode, send UDP)
    +-- SIP Event Loop (FreeSWITCH mod_sofia)
```

Audio frames are passed via bounded crossbeam channels (100 frame capacity = ~2 seconds buffer).

### SIP Stack Integration

The SIP stack is a **thin wrapper** around FreeSWITCH's mod_sofia. FreeSWITCH handles:

- SIP registration with carriers
- INVITE/BYE/CANCEL state machines
- RTP negotiation (SDP)
- Codec selection
- NAT traversal (STUN/TURN)

**For inbound calls to work**, FreeSWITCH must be:
1. Running (embedded mode or standalone)
2. Configured to route incoming calls to the Python handler
3. Registered with the SIP trunk (if `register=True`)

### RTP Session Flow

The RTP session provides audio transport when SIP signaling is handled externally:

1. **Configuration**: Specify local/remote IP:port pairs
2. **Start**: Binds UDP socket, begins RX/TX loops
3. **Receive**: `recv_audio()` returns decoded, resampled frames
4. **Send**: `send_audio()` queues frames for encoding and transmission
5. **Stop**: Closes socket, cleans up

## API Reference

### SipConfig

```python
SipConfig(
    local_ip: str = "0.0.0.0",      # IP to bind for SIP
    local_port: int = 5060,          # SIP port
    user_agent: str = "plivo-sip-agent",  # SIP User-Agent header
    debug: bool = False              # Enable SIP debug logging
)
```

### TrunkConfig

```python
TrunkConfig(
    name: str,                       # Trunk identifier
    host: str,                       # Gateway host (IP or hostname)
    port: int = 5060,                # Gateway port
    username: Optional[str] = None,  # Auth username
    password: Optional[str] = None,  # Auth password
    register: bool = False,          # Register with gateway
    caller_id_name: Optional[str] = None,    # Default caller ID name
    caller_id_number: Optional[str] = None   # Default caller ID number
)
```

### SipStack

```python
sip = SipStack(config: SipConfig)

await sip.start()
await sip.stop()

await sip.add_trunk(trunk: TrunkConfig)
await sip.remove_trunk(name: str)

call = await sip.dial(
    destination: str,           # Phone number or SIP URI
    trunk: str,                 # Trunk name to use
    timeout_sec: int = 60,      # Ring timeout
    caller_id_name: str = None, # Override caller ID
    caller_id_number: str = None
)

sip.set_inbound_handler(handler: Callable[[Call], Awaitable[None]])

sip.is_running  # bool
```

### Call

```python
call.uuid           # str - Unique call identifier
call.direction      # CallDirection.INBOUND or OUTBOUND
call.caller_id      # Optional[str]
call.destination    # Optional[str]
call.is_active      # bool
call.is_media_ready # bool - True after answer

await call.answer()                    # Answer inbound call
await call.hangup(reason="normal_clearing")
await call.recv_audio(timeout_ms=100)  # Returns AudioFrame or None
await call.send_audio(frame)
await call.send_dtmf("1234#")
call.get_variable("channel_name")      # FreeSWITCH channel variable
```

### RtpConfig

```python
config = RtpConfig(
    local_ip: str,      # IP to bind for RTP
    local_port: int,    # Port to bind
    remote_ip: str,     # Remote RTP host
    remote_port: int    # Remote RTP port
)
config = config.with_codec(Codec.PCMU)  # PCMU, PCMA, or L16
config = config.with_ptime(20)          # Packet time in ms
config = config.with_sample_rate(8000)
```

### RtpSession

```python
session = RtpSession(config: RtpConfig)

await session.start()
await session.stop()

frame = await session.recv_audio(timeout_ms=100)  # Returns AudioFrame or None
await session.send_audio(frame)
await session.send_audio_bytes(data: bytes)

session.update_remote(ip: str, port: int)  # Change remote endpoint

session.local_port  # int
session.is_running  # bool
session.stats       # RtpStats
```

### AudioFrame

```python
frame = AudioFrame(samples: bytes, sample_rate: int = 16000)
frame = AudioFrame.from_bytes(data, sample_rate=16000)
frame = AudioFrame.silence_20ms()

frame.samples       # bytes - L16 PCM little-endian
frame.sample_rate   # int
frame.channels      # int (always 1)
frame.timestamp     # int - RTP timestamp
frame.duration_ms   # int
frame.num_samples() # int
frame.is_empty()    # bool
```

### Codec

```python
Codec.PCMU  # G.711 u-law (payload type 0)
Codec.PCMA  # G.711 A-law (payload type 8)
Codec.L16   # Linear 16-bit PCM (payload type 11)

codec.payload_type  # int
```

## Building for Distribution

### Build Wheel

```bash
# Build for current platform
maturin build --release

# Find wheel in target/wheels/
ls target/wheels/pyswitch-*.whl
```

### Build with Docker (cross-platform)

```dockerfile
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y \
    build-essential curl pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install maturin

WORKDIR /app
COPY . .
RUN maturin build --release
```

### Publishing to PyPI

```bash
# Build wheels for multiple Python versions
maturin build --release

# Upload to PyPI
pip install twine
twine upload target/wheels/pyswitch-*.whl
```

## Testing

**Always use Docker for testing:**

```bash
# Build and run all tests
docker run --rm -v "$(pwd)":/workspace -w /workspace pyswitch-builder bash -c '
    maturin build --release
    pip install --force-reinstall target/wheels/*.whl
    pytest python/tests/ -v
'
```

### Test Isolation

SIP tests and RTP tests are mutually exclusive due to mode locking. The default `pytest` run excludes SIP tests:

```bash
# Run RTP tests (default)
pytest python/tests/ -v

# Run SIP tests only (separate process)
pytest python/tests/test_sip_loopback.py -v -m sip_mode
```

### Performance (200 concurrent sessions)

- Session creation: ~400-500ms (after init)
- Audio send: ~8-20ms
- Session stop: ~8-20ms

## Known Limitations

1. **Mode Locking**: Once initialized, the process is locked to either RTP-only or SIP mode. Cannot switch modes without restarting.

2. **SIP Mode Limited**: mod_sofia doesn't load in embedded mode. SIP modes initialize but cannot make/receive calls.

3. **Single Codec**: Currently supports G.711 (PCMU/PCMA) only.

## Project Structure

```
pyswitch/
├── Cargo.toml              # Workspace root
├── pyproject.toml          # Python package config
├── Dockerfile              # Docker build
├── crates/
│   ├── freeswitch-sys/     # FFI bindings (manual)
│   ├── pyswitch-core/      # Core Rust logic
│   │   └── src/
│   │       ├── audio/      # AudioFrame, Codec, Resampler
│   │       ├── call/       # Call session
│   │       ├── rtp/        # RTP session
│   │       ├── sip/        # SIP stack, TrunkConfig
│   │       └── runtime.rs  # Tokio runtime
│   └── pyswitch/           # PyO3 bindings
│       ├── src/lib.rs
│       └── pyswitch.pyi    # Type stubs
└── python/
    ├── pyswitch/           # Python package
    └── examples/           # Usage examples
```

## License

MIT
