# CLAUDE.md

## Project: rtp_sip

Python bindings with **embedded libfs (FreeSWITCH)** for SIP/RTP telephony. No external dependencies.

### Overview

rtp_sip provides Python async bindings to libfs (FreeSWITCH 1.10.12 from SignalWire) for SIP signaling and RTP audio transport. libfs is **statically linked** into the Python module - no separate installation required.

User agent is hardcoded as `plivo_rtp_sip/{version}` and not configurable.

### Design Philosophy

**Embedded libfs, not external dependency:**
- libfs (FreeSWITCH 1.10.12) compiled from SignalWire source
- Static linking (~15-20MB per platform)
- Minimal modules: mod_sofia (SIP), mod_g711, mod_dptools
- Single `.whl` file with no runtime dependencies

### Two Mutually Exclusive Modes

The module operates in one of two mutually exclusive modes, determined at first initialization:

1. **RTP-Only Mode (Mode 3)** ✅ *Working*
   - Python handles SIP externally (via WebSocket/HTTP)
   - rtp_sip handles RTP audio only using `switch_rtp_*` FFI
   - Initialize with: `RtpSession().start()`
   - **Status:** Fully functional with embedded libfs

2. **SIP Mode (Mode 1/2)** ⚠️ *Limited - mod_sofia unavailable*
   - Python initiates/receives calls via SIP
   - Uses mod_sofia for SIP signaling, media bugs for audio
   - Initialize with: `SIP().start()`
   - **Status:** Core works but mod_sofia doesn't load in embedded mode

**Mode Selection Rules:**
- The first component started (`RtpSession` or `SIP`) locks the mode
- Cannot switch modes without restarting the process
- Attempting to use the other mode raises an error

### Build

#### Embedded libfs (Recommended)

```bash
# 1. Build libfs static libraries
./scripts/build-freeswitch.sh

# 2. Build Python module with static linking
maturin build --release

# Output: target/wheels/rtp_sip-*.whl (~15-20MB)
```

#### Docker Build

```bash
docker build -t rtp_sip .
docker run --rm rtp_sip
```

#### Development (Dynamic Linking)

```bash
# Uses system libfs (requires libfreeswitch.so installed)
LIBFS_DYNAMIC=1 maturin develop
```

### Project Structure

```
rtp_sip_module/
├── vendor/
│   └── freeswitch-1.10.12/      # libfs source (cloned by build script)
│   └── freeswitch-static/       # Built static libraries
│       ├── lib/*.a
│       └── include/
│
├── conf/
│   └── freeswitch.xml           # Single unified config file
│
├── scripts/
│   └── build-freeswitch.sh      # Build libfs static libs
│
├── crates/
│   ├── libfs-sys/               # FFI bindings + static linking
│   │   ├── src/lib.rs           # extern "C" declarations
│   │   └── build.rs             # Static/dynamic link logic
│   │
│   └── rtp_sip/                 # PyO3 Python bindings + core logic
│       ├── src/
│       │   ├── lib.rs           # PyO3 module entry
│       │   ├── audio.rs         # Python audio bindings
│       │   ├── call.rs          # Python call bindings
│       │   ├── config.rs        # Python config bindings
│       │   ├── rtp.rs           # Python RTP bindings
│       │   ├── sip.rs           # Python SIP bindings
│       │   └── core/            # Core Rust telephony logic
│       │       ├── audio/       # AudioFrame, resampler
│       │       ├── call/        # Call session
│       │       ├── rtp/         # RTP session
│       │       ├── sip/         # SIP stack, TrunkConfig
│       │       ├── libfs_worker.rs  # Worker thread for libfs ops
│       │       └── runtime.rs   # libfs + Tokio init
│       └── rtp_sip.pyi
│
├── examples/
│   └── config.toml              # Example configuration
│
└── python/
    └── examples/
```

### libfs Modules (Embedded)

Only minimal modules are included:

| Module | Purpose |
|--------|---------|
| mod_sofia | SIP signaling (sofia-sip) |
| mod_g711 | G.711 codec (PCMU/PCMA) |
| mod_dptools | Dialplan tools (answer, hangup) |

Disabled: mod_conference, mod_voicemail, mod_lua, mod_python, etc. (~100 modules)

### Call Flow

#### Outbound Call
```
Python dial() → switch_ivr_originate() → SIP INVITE → Carrier
                                       ← 200 OK (SDP)
                                       → ACK
Call returned ← RTP Audio ←→
```

#### Inbound Call
```
Carrier → SIP INVITE → sofia callback → inbound_handler(call)
        ← 100 Trying
                      ← await call.answer()
        ← 200 OK (SDP)
        → ACK
        RTP Audio ←→ → frame = await call.recv_audio()
```

### Audio Pipeline

```
INBOUND (Caller → Python):
  RTP (G.711 @ 8kHz) → libfs decode → Resample 8k→16k → Python

OUTBOUND (Python → Caller):
  Python (L16 @ 16kHz) → Resample 16k→8k → libfs encode → RTP
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/build-freeswitch.sh` | Build libfs static libs |
| `crates/libfs-sys/build.rs` | Static/dynamic link configuration |
| `crates/libfs-sys/src/lib.rs` | FFI bindings |
| `crates/rtp_sip/src/core/runtime.rs` | Mode selection & libfs initialization |
| `crates/rtp_sip/src/core/sip/transport.rs` | SIP transport (Mode 1/2) |
| `crates/rtp_sip/src/core/rtp/session.rs` | RTP session (Mode 3) |
| `crates/rtp_sip/src/core/libfs_worker.rs` | Worker thread for libfs ops |
| `crates/rtp_sip/src/lib.rs` | PyO3 module entry |
| `conf/freeswitch.xml` | Single unified config file |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LIBFS_DYNAMIC` | Use dynamic linking | (unset = static) |
| `LIBFS_LIB_DIR` | Path to libfs libraries | `vendor/freeswitch-static/lib` |
| `LIBFS_INCLUDE_DIR` | Path to libfs headers | `vendor/freeswitch-static/include` |

### Configuration

Configuration can be loaded from TOML:

```toml
# Mode: "rtp_only" or "sip"
mode = "rtp_only"

[rtp]
local_ip = "0.0.0.0"
port_start = 16384
port_end = 32768
codec = "PCMU"

[sip]
local_ip = "0.0.0.0"
local_port = 5060

[[trunks]]
name = "provider"
host = "sip.provider.com"
username = "user"
password = "pass"
```

### Python API

```python
# Load config
from rtp_sip import Config
config = Config.from_file("config.toml")

# Or create programmatically
config = Config(mode="rtp_only")
config.rtp_port_start = 16384
```

```python
# Mode 3: RTP-only
from rtp_sip import RtpSession

session = RtpSession(remote_ip, remote_port)
await session.start()
local_port = session.local_port  # Tell WebSocket this

frame = await session.recv_audio(100)
await session.send_audio(response_frame)

await session.stop()
```

```python
# Mode 1: Outbound SIP call
from rtp_sip import SIP, SipConfig, TrunkConfig

sip = SIP(SipConfig(local_port=5060))
await sip.start()
await sip.add_trunk(TrunkConfig("carrier", "sip.provider.com", username="u", password="p"))
call = await sip.dial("+18005551234", "carrier")

while call.is_active:
    frame = await call.recv_audio(100)  # L16 @ 16kHz
    await call.send_audio(response)

await call.hangup()
await sip.stop()
```

```python
# Mode 2: Inbound calls
async def on_call(call):
    await call.answer()
    while call.is_active:
        frame = await call.recv_audio(100)
        await call.send_audio(response)

sip.set_inbound_handler(on_call)
await sip.start()
```

### Shutdown

Automatic cleanup is registered via `atexit`. For explicit shutdown:

```python
import rtp_sip

# ... use rtp_sip ...

# Explicit graceful shutdown
await rtp_sip.shutdown()

# Check if running
if rtp_sip.is_running():
    print("Worker still active")
```

### Platform Support

| Platform | Status |
|----------|--------|
| Linux x86_64 | Primary |
| Linux ARM64 | Supported |
| macOS ARM64 | Supported |
| macOS x86_64 | Supported |

### Size Estimates

- libfreeswitch.a: ~8-12MB
- sofia-sip: ~2MB
- mod_sofia + mod_g711: ~1MB
- **Final wheel: ~15-20MB per platform**

### Known Limitations

#### Mode Locking

Once a mode is initialized, the process is locked to that mode:
- Starting `RtpSession` locks to RTP-only mode
- Starting `SIP` locks to SIP mode
- Cannot switch modes without restarting the process

#### SIP Mode (Mode 1/2) - mod_sofia Unavailable

Loading mod_sofia in embedded mode doesn't work:
- `switch_core_init_and_modload()` crashes/segfaults in embedded mode
- Manual module loading returns "module load file routine returned an error"
- This is a FreeSWITCH limitation in embedded (non-standalone) mode

**Alternative Approaches for SIP Support:**
1. Use FreeSWITCH as a separate process and connect via ESL
2. Use sofia-sip library directly (bypass FreeSWITCH)
3. Implement SIP using a pure-Rust SIP stack
4. Use a different SIP library (e.g., PJSIP)

**Current Status:**
- RTP-only mode (Mode 3) works reliably
- SIP mode initializes the core but cannot make/receive calls without mod_sofia

### Testing

**ALWAYS use Docker for testing.** The Docker image has the pre-built libfs libraries and correct environment:

```bash
# Build and test
docker build -t pyswitch-builder -f docker-build/Dockerfile.builder .
docker run --rm -v "$(pwd)":/workspace -w /workspace pyswitch-builder bash -c '
    maturin build --release
    pip install --force-reinstall target/wheels/*.whl
    pytest python/tests/ -v
'

# Run specific tests
docker run --rm -v "$(pwd)":/workspace -w /workspace pyswitch-builder bash -c '
    pip install --force-reinstall target/wheels/*.whl
    pytest python/tests/test_rtp_loopback.py -v
'
```

#### Test Isolation

SIP tests and RTP tests are **mutually exclusive** due to mode locking:

```bash
# Run RTP tests (default - excludes SIP tests)
pytest python/tests/ -v

# Run SIP tests only (in separate process)
pytest python/tests/test_sip_loopback.py -v -m sip_mode

# The pyproject.toml has: addopts = "-m 'not sip_mode'"
# This excludes SIP tests by default to avoid mode conflicts
```

#### Performance Benchmarks (200 concurrent sessions)

- Session creation: ~400-500ms (after libfs init)
- Audio send (200 sessions): ~8-20ms
- Session stop (200 sessions): ~8-20ms

### Development Guidelines

#### Commit Messages

- Do NOT include "Claude Code" or "Anthropic" in commit messages
- Use clear, descriptive messages focusing on what changed and why
- Format: `<type>: <description>` (e.g., `fix: resolve GIL deadlock during shutdown`)

#### Code Style

- Use `libfs` terminology, not "FreeSWITCH" (we're embedding it)
- Use `SIP` not `Sip` in user-facing messages
- Keep FFI code in `libfs-sys`, business logic in `rtp_sip`
