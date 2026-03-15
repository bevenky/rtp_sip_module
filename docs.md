# rtpsip — Configuration & API Reference

High-performance SIP/RTP library for Voice AI. Rust core with Python bindings via PyO3.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration (TOML)](#configuration-toml)
- [Python API — Mode A: SIP + RTP](#python-api--mode-a-sip--rtp)
- [Python API — Mode B: RTP-Only](#python-api--mode-b-rtp-only)
- [SIP Features](#sip-features)
- [RTP Features](#rtp-features)
- [NAT Traversal](#nat-traversal)
- [Security](#security)
- [Monitoring & Diagnostics](#monitoring--diagnostics)
- [All Configuration Options](#all-configuration-options)

---

## Quick Start

### Mode A: Full SIP + RTP (telephony)

```python
from rtpsip import SipRunner, CallEvent

# From config file
runner = SipRunner.from_config("config.toml")

# Or programmatic construction
runner = SipRunner(
    server="sip.carrier.com",
    port=5060,
    username="user",
    password="secret",
    local_ip="0.0.0.0",
    local_port=5060,
    register=True,          # Send REGISTER to server
    user_agent="MyVoiceAI/1.0",
)

runner.start()

# Make outbound call
call_id = runner.call(
    to="sip:+14155551234@carrier.com",
    from_="sip:+14155550000@carrier.com",
)

# Event loop
while True:
    event = runner.next_event(timeout_ms=30000)
    if event is None:
        continue

    if event.is_ringing():
        print(f"Call {event.call_id} is ringing")

    elif event.is_early_media():
        print(f"Early media available (remote ringback)")
        # Can receive audio now via recv_audio()

    elif event.is_answered():
        print(f"Call answered!")
        # Send audio (PCM i16, 8kHz mono, 20ms frames = 160 samples)
        runner.send_audio(call_id, samples)

    elif event.is_dtmf():
        print(f"DTMF digit: {event.digit} (duration: {event.duration}ms)")

    elif event.is_hangup():
        print(f"Call ended: {event.reason}")
        break

    elif event.is_error():
        print(f"Error: {event.error}")
        break

# Receive audio (blocks up to timeout_ms, returns PCM i16 list or None)
audio = runner.recv_audio(call_id, timeout_ms=100)

# Hangup
runner.hangup(call_id)
runner.stop()
```

### Mode B: RTP-Only (external signaling)

```python
from rtpsip import RtpSession

session = RtpSession(
    local_addr="0.0.0.0:0",       # Bind to random port
    remote_addr="1.2.3.4:5678",   # Remote RTP endpoint
    codec="PCMU",                  # PCMU or PCMA
    ssrc=None,                     # Auto-generate
)
session.start()

# Send/receive audio
session.send_audio(samples)          # PCM i16 list
audio = session.recv_audio(100)      # timeout_ms

# DTMF
session.send_dtmf("1", duration_ms=160)
dtmf = session.recv_dtmf(timeout_ms=5000)

session.stop()
```

---

## Configuration (TOML)

```toml
[sip]
local_ip = "0.0.0.0"           # Bind address ("0.0.0.0" for all IPv4, "::" for IPv6)
local_port = 5060               # SIP port
transport = "udp"               # "udp" | "tcp" | "tls"
user_agent = "rtpsip/0.1.0"    # User-Agent header value

# TLS settings (when transport = "tls")
tls_cert = "/path/to/cert.pem"
tls_key = "/path/to/key.pem"
tls_ca_cert = "/path/to/ca.pem"
tls_verify = true               # Verify server certificates

# Transaction timers (RFC 3261 §17)
timer_t1_ms = 500               # RTT estimate (default 500ms)
timer_t2_ms = 4000              # Max retransmit interval (default 4000ms)
timer_t1x64_ms = 32000          # Max retransmit time (default 32000ms)

# Session timers (RFC 4028)
session_expires = 1800           # Session timeout in seconds (default 1800 = 30min)
min_se = 90                      # Minimum Session-Expires (default 90s)

# Reliability
enable_100rel = false            # Support 100rel/PRACK (RFC 3262)

# Rate limiting
max_calls = 100                  # Max concurrent calls (None = unlimited)
max_requests_per_second = 1000   # SIP request rate limit (None = unlimited)

# Keepalive
options_keepalive_interval_secs = 30  # Send OPTIONS pings (None = disabled)

[rtp]
local_ip = "0.0.0.0"
port_start = 10000              # RTP port range start (even numbers)
port_end = 20000                # RTP port range end

# Codec
codec = "PCMU"                  # "PCMU" (G.711 μ-law) or "PCMA" (G.711 A-law)
ptime_ms = 20                   # Packet time: 10, 20, 30, or 40ms

# Jitter buffer
jitter_min_delay_ms = 20        # Minimum buffer delay
jitter_max_delay_ms = 200       # Maximum buffer delay
jitter_target_delay_ms = 60     # Target buffer delay

# DTMF
enable_dtmf = true              # Enable RFC 2833 DTMF detection
dtmf_payload_type = 101         # Payload type for telephone-event (96-127)

# VAD & Comfort Noise
enable_vad = false              # Voice Activity Detection
vad_threshold = 250.0           # RMS energy threshold (~-30 dBFS)
vad_hangover_frames = 10        # Frames before silence transition (200ms)

# Media timeout
media_timeout_ms = 30000        # Dead stream detection (default 30s, 0 = disabled)

# Symmetric RTP
enable_symmetric_rtp = true     # Learn remote address from incoming packets (RFC 4961)

# SRTP
srtp_mode = "optional"          # "disabled" | "optional" | "required"

# RTCP
enable_rtcp_mux = false         # RTP/RTCP on same port (RFC 5761)

# FEC/NACK (experimental)
enable_nack = false             # NACK-based retransmission in jitter buffer

# Provider configuration (multiple providers supported)
[[providers]]
name = "primary"
server = "sip.carrier1.com"
port = 5060
username = "myuser"
password = "mypassword"
realm = "carrier1.com"          # Auth realm (defaults to server)
prefixes = ["+1", "+44"]        # Longest-prefix routing
default = true                  # Fallback for unmatched prefixes

[[providers]]
name = "backup"
server = "sip.carrier2.com"
port = 5060
username = "backupuser"
password = "backuppass"
prefixes = ["+91"]

[routing]
blocked_prefixes = ["+1900", "+44900"]  # Premium rate blocking

[nat]
stun_server = "stun.l.google.com:19302"  # STUN server (default)
stun_servers = [                          # Pool with failover
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
]
turn_server = "turn.example.com:3478"     # TURN relay (for symmetric NAT)
turn_username = "user"
turn_password = "pass"
```

---

## Python API — Mode A: SIP + RTP

### SipRunner

```python
class SipRunner:
    def __init__(
        self,
        server: str,
        port: int = 5060,
        username: str = "",
        password: str = "",
        local_ip: str = "0.0.0.0",
        local_port: int = 5060,
        register: bool = True,        # Send REGISTER on start
        user_agent: str = "rtpsip",
    ): ...

    @staticmethod
    def from_config(path: str) -> "SipRunner":
        """Load from TOML config file."""

    def start(self) -> None:
        """Start SIP engine and register with server."""

    def stop(self) -> None:
        """Unregister and stop SIP engine."""
```

#### Call Management

```python
    def call(
        self,
        to: str,              # Target SIP URI or phone number
        from_: str = None,    # Caller ID (uses config default if None)
        headers: dict = None, # Extra SIP headers
    ) -> str:
        """Make outbound call. Returns call_id."""

    def answer(self, call_id: str) -> None:
        """Answer incoming call (sends 200 OK with SDP)."""

    def hangup(self, call_id: str) -> None:
        """End active call (sends BYE)."""

    def cancel(self, call_id: str) -> None:
        """Cancel outbound call before answer (sends CANCEL).
        Use for calls in Ringing/EarlyMedia state only."""

    def hold(self, call_id: str) -> None:
        """Put call on hold (sends re-INVITE with a=sendonly)."""

    def resume(self, call_id: str) -> None:
        """Resume held call (sends re-INVITE with a=sendrecv)."""
```

#### Audio

```python
    def send_audio(self, call_id: str, samples: list[int]) -> None:
        """Send PCM audio. Samples: i16 list, 8kHz mono, 160 samples = 20ms.
        Releases GIL during send."""

    def recv_audio(self, call_id: str, timeout_ms: int = 100) -> list[int] | None:
        """Receive decoded audio. Returns PCM i16 list or None on timeout.
        Releases GIL during wait."""
```

#### DTMF

```python
    def send_dtmf(
        self,
        call_id: str,
        digit: str,          # "0"-"9", "*", "#", "A"-"D"
        duration_ms: int = 160,
    ) -> None:
        """Send DTMF digit. Method auto-selected (RFC 2833 or SIP INFO)."""

    def recv_dtmf(self, call_id: str, timeout_ms: int = 5000) -> dict | None:
        """Receive DTMF. Returns {'digit': '5', 'duration_ms': 160} or None."""
```

#### Transfer

```python
    def blind_transfer(self, call_id: str, target_uri: str) -> None:
        """Blind transfer (REFER). Sends call to target_uri.
        Monitor transfer progress via TransferProgress events."""

    def attended_transfer(
        self,
        call_id_to_transfer: str,
        consultation_call_id: str,
    ) -> None:
        """Attended transfer. Transfers call_id_to_transfer to the party
        on consultation_call_id using Replaces header.

        Flow:
        1. Put original call on hold
        2. Make consultation call to transfer target
        3. Once consultation call is answered, call attended_transfer()
        4. Original caller is connected to transfer target
        """
```

#### NAT Traversal

```python
    def configure_nat(
        self,
        stun_server: str = "stun.l.google.com:19302",
        stun_servers: list[str] | None = None,
    ) -> None:
        """Configure NAT traversal with STUN. Uses Google STUN by default."""

    def nat_type(self) -> str | None:
        """Get detected NAT type: 'FullCone', 'RestrictedCone',
        'PortRestricted', 'Symmetric', 'Open', or None."""

    def public_addr(self) -> str | None:
        """Get public IP:port from STUN. None if not behind NAT."""
```

#### Events

```python
    def next_event(self, timeout_ms: int = 5000) -> CallEvent | None:
        """Wait for next SIP event. Returns None on timeout.
        Releases GIL during wait."""
```

#### Monitoring

```python
    def rtcp_stats(self, call_id: str) -> RtcpStats | None:
        """Get RTCP statistics for a call."""

    def jitter_stats(self, call_id: str) -> JitterStats | None:
        """Get jitter buffer statistics."""

    def mos(self, call_id: str) -> float:
        """Get current MOS score (1.0-5.0) from RTCP metrics."""

    def vad_state(self, call_id: str) -> str:
        """Get VAD state: 'Voice' or 'Silence'."""

    def call_state(self, call_id: str) -> CallState | None:
        """Get current call state."""

    def active_calls(self) -> list[str]:
        """List all active call IDs."""

    def registration_state(self) -> str:
        """Get registration state: 'Unregistered', 'Registering',
        'Registered', 'Failed', 'Unregistering'."""

    def gateway_health(self, server: str) -> bool | None:
        """Get gateway health from OPTIONS keepalive. None if not configured."""
```

### CallEvent

```python
class CallEvent:
    event_type: str        # Event type string
    call_id: str           # Call identifier
    from_uri: str | None   # Caller URI (incoming calls)
    to_uri: str | None     # Callee URI (incoming calls)
    reason: str | None     # Hangup reason
    error: str | None      # Error description
    sdp: str | None        # SDP body (early_media, reinvite)
    digit: str | None      # DTMF digit
    duration: int | None   # DTMF duration in ms
    target: str | None     # Transfer target URI
    status_code: int | None  # Transfer progress status
    completed: bool | None   # Transfer completion flag
    targets: list[str] | None  # Redirect target URIs

    # Convenience methods
    def is_incoming(self) -> bool: ...
    def is_ringing(self) -> bool: ...
    def is_early_media(self) -> bool: ...
    def is_answered(self) -> bool: ...
    def is_audio_ready(self) -> bool: ...
    def is_dtmf(self) -> bool: ...
    def is_reinvite(self) -> bool: ...
    def is_hangup(self) -> bool: ...
    def is_error(self) -> bool: ...
    def is_transfer_initiated(self) -> bool: ...
    def is_transfer_progress(self) -> bool: ...
    def is_transfer_failed(self) -> bool: ...
    def is_refer_received(self) -> bool: ...
    def is_cancelled(self) -> bool: ...
    def is_redirected(self) -> bool: ...
    def is_media_timeout(self) -> bool: ...
    def is_registration_changed(self) -> bool: ...
```

### CallState

```python
class CallState:
    Ringing = 0      # 180 Ringing
    EarlyMedia = 1   # 183 Session Progress with SDP
    Active = 2       # 200 OK — call connected
    Hold = 3         # On hold (local or remote)
    Ended = 4        # Call terminated
```

### RtcpStats

```python
class RtcpStats:
    packets_sent: int
    octets_sent: int
    packets_received: int
    expected_packets: int
    jitter_ms: float
    loss_percent: float
    rtt_ms: float | None
    r_factor: float          # ITU-T G.107 R-factor (0-100)
    mos: float               # Mean Opinion Score (1.0-5.0)
```

### JitterStats

```python
class JitterStats:
    packets_received: int
    packets_lost: int
    packets_dropped: int      # Late arrivals
    packets_reordered: int
    jitter_ms: float
    buffer_delay_ms: int
    buffer_size: int          # Current packet count in buffer
```

---

## Python API — Mode B: RTP-Only

### RtpSession

```python
class RtpSession:
    def __init__(
        self,
        local_addr: str = "0.0.0.0:0",
        remote_addr: str | None = None,
        codec: str = "PCMU",       # "PCMU" or "PCMA"
        ssrc: int | None = None,   # Auto-generated if None
    ): ...

    def start(self) -> None: ...
    def stop(self) -> None: ...

    # Audio
    def send_audio(self, samples: list[int]) -> None: ...
    def recv_audio(self, timeout_ms: int = 100) -> list[int] | None: ...

    # DTMF
    def send_dtmf(self, digit: str, duration_ms: int = 160) -> None: ...
    def recv_dtmf(self, timeout_ms: int = 5000) -> dict | None: ...

    # SRTP
    def enable_srtp(self, crypto_line: str) -> None:
        """Enable SRTP from SDP a=crypto line.
        Example: enable_srtp('1 AES_CM_128_HMAC_SHA1_80 inline:<base64key>')"""

    @property
    def is_srtp_enabled(self) -> bool: ...

    # Symmetric RTP
    def symmetric_rtp_remote(self) -> str | None:
        """Get the learned remote address from symmetric RTP."""

    # VAD
    def vad_state(self) -> str: ...
    def set_vad_threshold(self, threshold: float) -> None: ...

    # Statistics
    def rtcp_stats(self) -> RtcpStats: ...
    def mos(self) -> float: ...
    def rtt_ms(self) -> float | None: ...
    def jitter_stats(self) -> JitterStats: ...

    # Media tapping
    def add_media_tap(self, callback, direction: str = "both") -> int:
        """Add audio tap for recording/ASR. Returns tap_id."""
    def remove_media_tap(self, tap_id: int) -> None: ...

    @property
    def media_tap_count(self) -> int: ...

    # Properties
    @property
    def local_addr(self) -> str: ...
    @property
    def remote_addr(self) -> str | None: ...
    @property
    def codec(self) -> str: ...
    @property
    def ssrc(self) -> int: ...
```

---

## SIP Features

### Registration

```python
# Auto-registration on start (default)
runner = SipRunner(server="sip.example.com", register=True)
runner.start()  # Sends REGISTER automatically

# Check state
print(runner.registration_state())  # "Registered"

# Registration events
event = runner.next_event()
if event.is_registration_changed():
    print(f"Registration: {event.event_type}")  # "registration_changed"

# Graceful unregistration on stop
runner.stop()  # Sends REGISTER with Expires: 0
```

Registration lifecycle:
- On start: REGISTER with configured credentials
- Auto-refresh at `expiry/2` (server provides expiry in response)
- On 401/407: automatic digest auth retry
- On 423 (Interval Too Brief): use Min-Expires from response
- On failure: exponential backoff (1s, 2s, 4s, ..., max 60s)
- On stop: sends Expires: 0 to unregister

### Call Transfer — Blind

```python
# Blind transfer: send caller to another extension
runner.blind_transfer(call_id, "sip:+14155559999@carrier.com")

# Monitor transfer progress via events
while True:
    event = runner.next_event(timeout_ms=10000)
    if event.is_transfer_initiated():
        print(f"Transfer started to {event.target}")
    elif event.is_transfer_progress():
        print(f"Transfer progress: {event.status_code} {event.reason}")
        if event.completed:
            print("Transfer completed successfully!")
            break
    elif event.is_transfer_failed():
        print(f"Transfer failed: {event.error}")
        break
```

### Call Transfer — Attended

```python
# Step 1: Put original call on hold
runner.hold(original_call_id)

# Step 2: Make consultation call to transfer target
consult_call_id = runner.call(to="sip:+14155559999@carrier.com")

# Step 3: Wait for consultation call to be answered
event = runner.next_event(timeout_ms=30000)
if event.is_answered() and event.call_id == consult_call_id:
    # Step 4: Bridge the two calls
    runner.attended_transfer(original_call_id, consult_call_id)
```

### Incoming REFER (Transfer Request)

```python
event = runner.next_event()
if event.is_refer_received():
    print(f"Transfer request received: {event.target}")
    # Application decides whether to follow the transfer
    # Make a new call to the target and bridge
```

### CANCEL (Abort Outbound Call)

```python
call_id = runner.call(to="sip:+14155551234@carrier.com")

# Changed our mind before they answer
event = runner.next_event(timeout_ms=5000)
if event.is_ringing():
    runner.cancel(call_id)  # Sends CANCEL, cleans up
```

### Hold/Resume

```python
# Put call on hold (sends re-INVITE with a=sendonly)
runner.hold(call_id)

# Resume (sends re-INVITE with a=sendrecv)
runner.resume(call_id)

# Detect remote hold via events
event = runner.next_event()
if event.is_reinvite():
    state = runner.call_state(call_id)
    if state == CallState.Hold:
        print("Remote party put us on hold")
```

### DTMF — Auto-Detection

```python
# DTMF mode is auto-detected from SDP:
# - If remote supports telephone-event → RFC 2833 (in-band RTP)
# - Otherwise → SIP INFO (out-of-band)

runner.send_dtmf(call_id, "1")       # Sends via best available method
runner.send_dtmf(call_id, "#", 300)  # Custom duration (ms)

# Receive DTMF
event = runner.next_event()
if event.is_dtmf():
    print(f"Digit: {event.digit}, Duration: {event.duration}ms")
```

### Session Timers (RFC 4028)

Automatic zombie call prevention:
- Sends `Session-Expires` header in INVITE
- Re-INVITEs automatically at half-interval
- Terminates call if remote doesn't respond

```toml
[sip]
session_expires = 1800   # 30 minutes (default)
min_se = 90              # Minimum 90 seconds
```

### Early Media (180/183)

```python
event = runner.next_event()

if event.is_early_media():
    # 183 Session Progress with SDP — remote ringback available
    # Can now recv_audio() to hear remote ringback/IVR
    audio = runner.recv_audio(call_id, timeout_ms=20)

elif event.is_ringing():
    # 180 Ringing without SDP — generate local ringback
    pass

# Edge case: 180 after 183 (mobile carriers)
# Library handles this automatically — keeps media from 183
```

### Media Timeout Detection

```python
# Configure timeout (default 30 seconds)
# Set in config.toml: media_timeout_ms = 30000

event = runner.next_event()
if event.is_media_timeout():
    print(f"No RTP received for 30s on call {event.call_id}")
    runner.hangup(call_id)  # Clean up dead call
```

### Redirect Handling (3xx)

```python
event = runner.next_event()
if event.is_redirected():
    print(f"Call redirected to: {event.targets}")
    # Manually follow redirect
    new_call_id = runner.call(to=event.targets[0])
```

---

## RTP Features

### Codec Support

| Codec | PT | Rate | Config Value |
|-------|-----|------|-------------|
| G.711 μ-law (PCMU) | 0 | 8kHz | `"PCMU"` |
| G.711 A-law (PCMA) | 8 | 8kHz | `"PCMA"` |

### Packet Time (ptime)

```toml
[rtp]
ptime_ms = 20   # 10, 20, 30, or 40ms
```

Parsed from remote SDP `a=ptime:` and adjusted automatically.

### Jitter Buffer

Adaptive jitter buffer with configurable parameters:

```toml
[rtp]
jitter_min_delay_ms = 20    # Floor: never buffer less than this
jitter_max_delay_ms = 200   # Ceiling: never buffer more than this
jitter_target_delay_ms = 60 # Target: buffer aims for this delay
```

Advanced tuning:
```python
session = RtpSession(local_addr="0.0.0.0:0", codec="PCMU")
stats = session.jitter_stats()
print(f"Jitter: {stats.jitter_ms}ms, Buffer: {stats.buffer_size} packets")
print(f"Lost: {stats.packets_lost}, Reordered: {stats.packets_reordered}")
```

### Packet Loss Concealment (PLC)

G.711 Appendix I pitch-based concealment — automatic, no configuration needed:
- Maintains 48.75ms history buffer
- Autocorrelation for pitch detection (50-400Hz)
- Pitch repeat with overlap-add crossfade
- Exponential decay on continuous loss
- Smooth recovery on packet arrival

### Voice Activity Detection (VAD)

```python
# Enable VAD for silence suppression + comfort noise
session = RtpSession(local_addr="0.0.0.0:0", codec="PCMU")
# VAD is configured via the RTP engine config

# Check state
print(session.vad_state())  # "Voice" or "Silence"

# Tune sensitivity
session.set_vad_threshold(500.0)  # Higher = less sensitive
```

Reference threshold values:
| Threshold | Sensitivity | Use Case |
|-----------|------------|----------|
| 50 | Very high | Quiet environments |
| 250 | Default | General telephony |
| 500 | Low | Noisy environments |
| 1000 | Very low | Only loud speech |

### Comfort Noise (RFC 3389)

When VAD is enabled, silence is replaced with comfort noise packets:
- PT 13 (standard comfort noise)
- Includes noise level byte (RFC 3389 §3)
- Paced to 1 packet per second during silence
- Smooth transition between voice and silence

### DTMF (RFC 2833/4733)

Features:
- Auto-detection from SDP telephone-event
- Variable payload type (96-127, default 101)
- Marker bit on first packet per digit
- End-bit redundancy (3x per RFC 4733)
- Duration wraparound handling for long presses
- Interdigit overlap protection
- Device-specific workarounds (Sonus, Cisco)

```python
# Send
runner.send_dtmf(call_id, "5", duration_ms=160)

# Receive (via events)
event = runner.next_event()
if event.is_dtmf():
    print(f"{event.digit} ({event.duration}ms)")
```

### Symmetric RTP (RFC 4961)

Automatic NAT traversal by learning remote address from incoming packets:

```toml
[rtp]
enable_symmetric_rtp = true  # Default: true
```

Behavior:
- Learns remote address from first incoming RTP packet
- Updates send target to match (handles NAT port mapping)
- Standard for SIP trunks where remote may be behind NAT

### Media Tapping

Non-intrusive audio fork for recording, ASR, or transcription:

```python
# Add a tap (Mode B only)
def on_audio(samples, direction):
    # Process audio for ASR/recording
    pass

tap_id = session.add_media_tap(on_audio, direction="both")
session.remove_media_tap(tap_id)
```

Directions: `"inbound"`, `"outbound"`, `"both"`

### Media Timeout

Detect dead streams when remote stops sending RTP:

```toml
[rtp]
media_timeout_ms = 30000  # 30 seconds (default), 0 = disabled
```

```python
event = runner.next_event()
if event.is_media_timeout():
    runner.hangup(event.call_id)
```

### RTCP (RFC 3550)

Automatic RTCP reporting with quality metrics:

```python
stats = runner.rtcp_stats(call_id)
print(f"Packets sent: {stats.packets_sent}")
print(f"Jitter: {stats.jitter_ms}ms")
print(f"Loss: {stats.loss_percent}%")
print(f"RTT: {stats.rtt_ms}ms")
print(f"MOS: {stats.mos}")
print(f"R-factor: {stats.r_factor}")
```

RTCP-mux (RFC 5761) — RTP and RTCP on same port:
```toml
[rtp]
enable_rtcp_mux = false  # Default: false
```

### SRTP (RFC 3711)

Encryption via SDES key exchange:

```python
# Mode A: Automatic from SDP negotiation
# No configuration needed — keys exchanged in SDP a=crypto: lines

# Mode B: Manual
session.enable_srtp("1 AES_CM_128_HMAC_SHA1_80 inline:dGVzdGtleXRlc3RrZXkxMjM0NTY3ODkwMTIzNA==")
```

Supported cipher suites:
- `AES_CM_128_HMAC_SHA1_80` (standard, 80-bit auth tag)
- `AES_CM_128_HMAC_SHA1_32` (reduced overhead, 32-bit auth tag)

Features:
- Replay protection (128-packet sliding window)
- ROC tracking for long calls
- SSRC change detection (resets replay state on authenticated SSRC change)
- Key lifetime enforcement (warns at 2^47, errors at 2^48 packets)
- Non-monotonic send rejection (prevents keystream reuse)
- Secure key zeroization on context drop (write_volatile + compiler_fence)

---

## NAT Traversal

### STUN

```python
# Default: Google STUN server
runner.configure_nat()

# Custom STUN server
runner.configure_nat(stun_server="stun.mycompany.com:3478")

# Multiple servers with failover
runner.configure_nat(stun_servers=[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
])

# Check results
print(runner.nat_type())    # "FullCone", "Symmetric", etc.
print(runner.public_addr()) # "203.0.113.5:12345"
```

### NAT Type Detection (RFC 3489/5780)

| Type | Description | RTP Works? |
|------|-------------|-----------|
| Open | No NAT | Yes |
| Full Cone | Any external host can reach mapped port | Yes |
| Restricted Cone | Only hosts we've sent to | Yes (with hole punch) |
| Port Restricted | IP + port restricted | Yes (with hole punch) |
| Symmetric | Different mapping per destination | Needs TURN relay |

### TURN Relay

For Symmetric NAT where STUN doesn't work:

```toml
[nat]
turn_server = "turn.example.com:3478"
turn_username = "user"
turn_password = "pass"
```

### Hole Punching

Automatic UDP hole punching before media flows:
- Sends STUN binding requests through the RTP socket
- Opens NAT pinholes for the correct source port
- Works with Full Cone, Restricted Cone, and Port Restricted NAT

### Contact Header NAT Rewriting

When behind NAT, the Contact header in SIP messages is automatically rewritten
to use the public IP from STUN discovery. This ensures the remote party can
route responses and new requests back through the NAT.

---

## Security

### SRTP Encryption

```toml
[rtp]
srtp_mode = "optional"   # "disabled" | "optional" | "required"
```

| Mode | Behavior |
|------|----------|
| disabled | Never use SRTP |
| optional | Use SRTP if remote offers it, plain RTP otherwise |
| required | Reject calls without SRTP |

### TLS for SIP Signaling

```toml
[sip]
transport = "tls"
tls_cert = "/path/to/cert.pem"
tls_key = "/path/to/key.pem"
tls_ca_cert = "/path/to/ca.pem"
tls_verify = true
```

### Digest Authentication

Automatic handling of 401/407 challenges:
- Algorithms: MD5 (RFC 2617), SHA-256 (RFC 7616)
- QOP: auth (standard), auth-int (integrity)
- Nonce caching with nc tracking
- Stale nonce re-authentication

---

## Monitoring & Diagnostics

### MOS Score

Real-time call quality estimation (ITU-T G.107):

```python
mos = runner.mos(call_id)
# 4.0+ : Excellent
# 3.5-4.0: Good
# 3.0-3.5: Fair
# 2.5-3.0: Poor
# < 2.5  : Bad
```

### RTCP Statistics

```python
stats = runner.rtcp_stats(call_id)
print(f"Loss: {stats.loss_percent:.1f}%")
print(f"Jitter: {stats.jitter_ms:.1f}ms")
print(f"RTT: {stats.rtt_ms}ms")
print(f"R-factor: {stats.r_factor:.0f}")
```

### Gateway Health

```python
# Enable OPTIONS keepalive
# config.toml: options_keepalive_interval_secs = 30

healthy = runner.gateway_health("sip.carrier.com")
# True = responding to OPTIONS
# False = not responding
# None = not configured
```

### Logging

Environment variable control:

```bash
# Default: info level
RUST_LOG=rtpsip=info python myapp.py

# Debug SIP signaling
RUST_LOG=rtpsip::sip=debug python myapp.py

# Debug RTP
RUST_LOG=rtpsip::rtp=debug python myapp.py

# Debug everything
RUST_LOG=rtpsip=trace python myapp.py
```

---

## All Configuration Options

### SipConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `local_ip` | string | `"0.0.0.0"` | Bind address |
| `local_port` | u16 | `5060` | SIP port |
| `transport` | string | `"udp"` | `"udp"`, `"tcp"`, `"tls"` |
| `tls_cert` | string? | None | TLS certificate path |
| `tls_key` | string? | None | TLS private key path |
| `tls_ca_cert` | string? | None | CA certificate path |
| `tls_verify` | bool | `true` | Verify server certs |
| `timer_t1_ms` | u32? | `500` | RFC 3261 Timer T1 |
| `timer_t2_ms` | u32? | `4000` | RFC 3261 Timer T2 |
| `timer_t1x64_ms` | u32? | `32000` | RFC 3261 Timer T1x64 |
| `session_expires` | u32 | `1800` | Session timer (seconds) |
| `min_se` | u32 | `90` | Minimum Session-Expires |
| `enable_100rel` | bool | `false` | PRACK support |
| `max_calls` | u32? | None | Max concurrent calls |
| `max_requests_per_second` | u32? | None | SIP rate limit |
| `options_keepalive_interval_secs` | u32? | None | OPTIONS ping interval |
| `user_agent` | string | `"rtpsip"` | User-Agent header |

### RtpConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `local_ip` | string | `"0.0.0.0"` | RTP bind address |
| `port_start` | u16 | `10000` | Port range start |
| `port_end` | u16 | `20000` | Port range end |

### RtpEngineConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `codec` | CodecType | `Pcmu` | Audio codec |
| `ptime_ms` | u32 | `20` | Packet time (ms) |
| `ssrc` | u32? | random | SSRC identifier |
| `enable_dtmf` | bool | `true` | RFC 2833 DTMF |
| `dtmf_payload_type` | u8 | `101` | Telephone-event PT |
| `enable_vad` | bool | `false` | Voice activity detection |
| `enable_symmetric_rtp` | bool | `true` | RFC 4961 NAT learning |
| `media_timeout_ms` | u64 | `30000` | Dead stream timeout |
| `enable_rtcp_mux` | bool | `false` | RFC 5761 RTCP-mux |
| `enable_nack` | bool | `false` | NACK retransmission |
| `recv_codec` | CodecType? | None | Receive codec (asymmetric) |
| `send_silence_when_idle` | bool | `false` | Send silence frames when no audio |
| `flush_jb_on_dtmf` | bool | `false` | Reset jitter buffer on DTMF |
| `dtmf_buffer_size` | usize | `32` | Max queued DTMF events |
| `vad_threshold` | f64 | `250.0` | VAD energy threshold |
| `vad_hangover_frames` | u32 | `10` | Frames before silence transition |

### JitterConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_delay_ms` | u32 | `20` | Minimum buffer delay |
| `max_delay_ms` | u32 | `200` | Maximum buffer delay |
| `target_delay_ms` | u32 | `60` | Target buffer delay |
| `max_packets` | usize | `100` | Max buffered packets |
| `sample_rate` | u32 | `8000` | Audio sample rate |
| `samples_per_packet` | u32 | `160` | Samples per RTP packet |

### NatConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `stun_server` | string | `"stun.l.google.com:19302"` | Primary STUN server |
| `stun_servers` | string[]? | None | STUN pool with failover |
| `turn_server` | string? | None | TURN relay server |
| `turn_username` | string? | None | TURN credentials |
| `turn_password` | string? | None | TURN credentials |

### ProviderConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Provider identifier |
| `server` | string | required | SIP server address |
| `port` | u16 | `5060` | SIP server port |
| `username` | string | `""` | Auth username |
| `password` | string | `""` | Auth password |
| `realm` | string? | server | Auth realm |
| `prefixes` | string[] | `[]` | Routing prefixes |
| `default` | bool | `false` | Default provider |

---

## Examples

### Voice AI Agent

```python
from rtpsip import SipRunner
import my_asr, my_tts, my_llm

runner = SipRunner.from_config("config.toml")
runner.configure_nat()
runner.start()

while True:
    event = runner.next_event(timeout_ms=60000)
    if event is None:
        continue

    if event.is_incoming():
        runner.answer(event.call_id)

    elif event.is_answered() or event.is_audio_ready():
        call_id = event.call_id
        # Start bidirectional audio processing
        while True:
            audio = runner.recv_audio(call_id, timeout_ms=20)
            if audio:
                text = my_asr.transcribe(audio)
                if text:
                    response = my_llm.generate(text)
                    tts_audio = my_tts.synthesize(response)
                    runner.send_audio(call_id, tts_audio)

            ev = runner.next_event(timeout_ms=0)
            if ev and ev.is_hangup():
                break

    elif event.is_hangup():
        print(f"Call ended: {event.reason}")
```

### IVR with DTMF Menu

```python
runner = SipRunner.from_config("config.toml")
runner.start()

event = runner.next_event(timeout_ms=60000)
if event.is_incoming():
    runner.answer(event.call_id)

    # Play prompt (pre-rendered PCM)
    runner.send_audio(event.call_id, prompt_audio)

    # Wait for DTMF
    dtmf_event = runner.next_event(timeout_ms=10000)
    if dtmf_event and dtmf_event.is_dtmf():
        if dtmf_event.digit == "1":
            runner.blind_transfer(event.call_id, "sip:sales@company.com")
        elif dtmf_event.digit == "2":
            runner.blind_transfer(event.call_id, "sip:support@company.com")
```

### Call Recording with Media Tap

```python
from rtpsip import RtpSession
import wave

session = RtpSession(local_addr="0.0.0.0:0", remote_addr="1.2.3.4:5678")

# Set up recording
wav_file = wave.open("recording.wav", "wb")
wav_file.setnchannels(1)
wav_file.setsampwidth(2)  # 16-bit
wav_file.setframerate(8000)

def record_audio(samples, direction):
    import struct
    data = struct.pack(f"<{len(samples)}h", *samples)
    wav_file.writeframes(data)

tap_id = session.add_media_tap(record_audio, direction="both")
session.start()

# ... call processing ...

session.stop()
session.remove_media_tap(tap_id)
wav_file.close()
```

### Quality Monitoring

```python
import time

runner = SipRunner.from_config("config.toml")
runner.start()
call_id = runner.call(to="sip:test@carrier.com")

# Wait for answer
# ...

# Monitor quality every 5 seconds
while True:
    time.sleep(5)
    stats = runner.rtcp_stats(call_id)
    if stats:
        print(f"MOS: {stats.mos:.1f} | Loss: {stats.loss_percent:.1f}% | "
              f"Jitter: {stats.jitter_ms:.0f}ms | RTT: {stats.rtt_ms}ms")

        if stats.mos < 3.0:
            print("WARNING: Poor call quality!")
```

### Multi-Provider Setup

```toml
# config.toml
[[providers]]
name = "us_carrier"
server = "sip.us-carrier.com"
username = "user1"
password = "pass1"
prefixes = ["+1"]

[[providers]]
name = "uk_carrier"
server = "sip.uk-carrier.com"
username = "user2"
password = "pass2"
prefixes = ["+44"]

[[providers]]
name = "default_carrier"
server = "sip.global-carrier.com"
username = "user3"
password = "pass3"
default = true

[routing]
blocked_prefixes = ["+1900", "+44900"]  # Block premium rate
```

```python
runner = SipRunner.from_config("config.toml")
runner.start()

# Auto-routes based on longest prefix match:
runner.call(to="+14155551234")  # → us_carrier
runner.call(to="+442071234567") # → uk_carrier
runner.call(to="+61291234567")  # → default_carrier
runner.call(to="+19001234567")  # → BLOCKED (premium rate)
```

### Attended Transfer Flow

```python
runner = SipRunner.from_config("config.toml")
runner.start()

# Receive incoming call
event = runner.next_event()
if event.is_incoming():
    runner.answer(event.call_id)
    original_call = event.call_id

    # Step 1: Hold original caller
    runner.hold(original_call)

    # Step 2: Call transfer target for consultation
    consult_call = runner.call(to="sip:manager@company.com")

    # Wait for consultation call to connect
    while True:
        ev = runner.next_event(timeout_ms=30000)
        if ev and ev.is_answered() and ev.call_id == consult_call:
            break

    # Step 3: Announce transfer, then bridge
    # "I have a customer on the line about X..."
    runner.send_audio(consult_call, announcement_audio)

    # Step 4: Execute attended transfer
    runner.attended_transfer(original_call, consult_call)

    # Monitor transfer completion
    while True:
        ev = runner.next_event(timeout_ms=10000)
        if ev and ev.is_transfer_progress() and ev.completed:
            print("Transfer complete! Customer connected to manager.")
            break
```
