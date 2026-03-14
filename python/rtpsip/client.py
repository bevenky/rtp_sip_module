"""
rtpsip Client - Decorator-based interface for SIP/RTP

Example:
    from rtpsip import Client, Call

    client = Client("sip", config="config.toml")

    @client.on_incoming
    def handle_incoming(call: Call):
        call.answer()

    @client.on_audio
    def handle_audio(call: Call, samples: list[int]):
        response = process(samples)
        call.send_audio(response)

    client.run()
"""

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, Dict, List, Any, Union

from rtpsip._rtpsip import (
    SipRunner,
    RtpSession,
    CallEvent,
    CallState,
    DtmfMode,
)


@dataclass
class Call:
    """Represents an active call with simplified interface"""

    id: str
    from_uri: str = ""
    to_uri: str = ""
    state: str = "ringing"
    direction: str = "inbound"  # "inbound" or "outbound"

    _runner: Any = field(default=None, repr=False)
    _rtp_session: Any = field(default=None, repr=False)

    def answer(self) -> None:
        """Answer an incoming call"""
        if self._runner:
            self._runner.answer(self.id)

    def reject(self, status_code: int = 486) -> None:
        """Reject an incoming call (486=Busy, 603=Decline)"""
        if self._runner:
            self._runner.reject(self.id, status_code)

    def hangup(self) -> None:
        """Hang up the call"""
        if self._runner:
            self._runner.hangup(self.id)

    def hold(self) -> None:
        """Put call on hold"""
        if self._runner:
            self._runner.hold(self.id)

    def unhold(self) -> None:
        """Resume call from hold"""
        if self._runner:
            self._runner.unhold(self.id)

    def transfer(self, target: str) -> None:
        """Transfer call to another number"""
        if self._runner:
            self._runner.transfer(self.id, target)

    def send_audio(self, samples: List[int]) -> None:
        """Send audio samples (PCM i16, 8kHz mono, 160 samples = 20ms)"""
        if self._runner:
            self._runner.send_audio(self.id, samples)
        elif self._rtp_session:
            self._rtp_session.send_audio(samples)

    def send_dtmf(self, digits: str, duration_ms: int = 250) -> None:
        """Send DTMF digits"""
        if self._runner:
            self._runner.send_dtmf(self.id, digits, duration_ms)


class Client:
    """
    rtpsip Client with decorator-based handlers.

    Args:
        mode: "sip" for SIP+RTP or "rtp" for RTP-only
        config: Path to config.toml or dict with config

    Example:
        client = Client("sip")
        client = Client("sip", config="config.toml")
        client = Client("rtp")

    Environment variables (auto-detected if no config):
        RTPSIP_PROVIDER=plivo
        RTPSIP_SERVER=sip.plivo.com
        RTPSIP_AUTH_USERNAME=your_username
        RTPSIP_AUTH_PASSWORD=your_password
    """

    def __init__(
        self,
        mode: str,
        config: Optional[Union[str, Dict[str, Any]]] = None,
    ):
        if mode not in ("sip", "rtp"):
            raise ValueError(f"Invalid mode: {mode}. Must be 'sip' or 'rtp'")

        self._mode = mode
        self._config = self._load_config(config)
        self._runner: Optional[SipRunner] = None
        self._rtp_session: Optional[RtpSession] = None
        self._running = False
        self._calls: Dict[str, Call] = {}

        # Handler callbacks
        self._on_incoming: Optional[Callable[[Call], None]] = None
        self._on_ringing: Optional[Callable[[Call], None]] = None
        self._on_answered: Optional[Callable[[Call], None]] = None
        self._on_audio: Optional[Callable[[Call, List[int]], None]] = None
        self._on_dtmf: Optional[Callable[[Call, str], None]] = None
        self._on_hangup: Optional[Callable[[Call, str], None]] = None

    def _load_config(
        self, config: Optional[Union[str, Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Load config from file, dict, or environment"""
        if isinstance(config, dict):
            return config

        if isinstance(config, str):
            return self._load_config_file(config)

        # Auto-detect: check for config.toml in current dir
        if Path("config.toml").exists():
            return self._load_config_file("config.toml")

        # Fall back to environment variables
        return self._load_config_from_env()

    def _load_config_file(self, path: str) -> Dict[str, Any]:
        """Load config from TOML file"""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        with open(path, "rb") as f:
            return tomllib.load(f)

    def _load_config_from_env(self) -> Dict[str, Any]:
        """Load config from environment variables"""
        config: Dict[str, Any] = {}

        # Provider settings
        provider = os.environ.get("RTPSIP_PROVIDER")
        if provider:
            config["providers"] = [
                {
                    "name": provider,
                    "server": os.environ.get("RTPSIP_SERVER", f"sip.{provider}.com"),
                    "port": int(os.environ.get("RTPSIP_PORT", "5060")),
                    "username": os.environ.get("RTPSIP_AUTH_USERNAME", ""),
                    "password": os.environ.get("RTPSIP_AUTH_PASSWORD", ""),
                    "default": True,
                }
            ]

        # SIP settings
        config["sip"] = {
            "local_ip": os.environ.get("RTPSIP_LOCAL_IP", "0.0.0.0"),
            "local_port": int(os.environ.get("RTPSIP_LOCAL_PORT", "5060")),
            "transport": os.environ.get("RTPSIP_TRANSPORT", "udp"),
        }

        # RTP settings
        config["rtp"] = {
            "local_ip": os.environ.get("RTPSIP_RTP_IP", "0.0.0.0"),
            "port_start": int(os.environ.get("RTPSIP_RTP_PORT_START", "10000")),
            "port_end": int(os.environ.get("RTPSIP_RTP_PORT_END", "20000")),
        }

        return config

    # ----- Decorator methods -----

    def on_incoming(self, func: Callable[[Call], None]) -> Callable[[Call], None]:
        """Decorator for incoming call handler"""
        self._on_incoming = func
        return func

    def on_ringing(self, func: Callable[[Call], None]) -> Callable[[Call], None]:
        """Decorator for ringing handler (outbound calls)"""
        self._on_ringing = func
        return func

    def on_answered(self, func: Callable[[Call], None]) -> Callable[[Call], None]:
        """Decorator for answered handler"""
        self._on_answered = func
        return func

    def on_audio(
        self, func: Callable[[Call, List[int]], None]
    ) -> Callable[[Call, List[int]], None]:
        """Decorator for audio handler"""
        self._on_audio = func
        return func

    def on_dtmf(
        self, func: Callable[[Call, str], None]
    ) -> Callable[[Call, str], None]:
        """Decorator for DTMF handler"""
        self._on_dtmf = func
        return func

    def on_hangup(
        self, func: Callable[[Call, str], None]
    ) -> Callable[[Call, str], None]:
        """Decorator for hangup handler"""
        self._on_hangup = func
        return func

    # ----- Call control -----

    def dial(self, to: str, from_: str) -> Call:
        """Make an outbound call"""
        if not self._runner:
            raise RuntimeError("Client not started. Call run() first or use dial() after run() in a thread.")

        call_id = self._runner.call(to=to, from_=from_)
        call = Call(
            id=call_id,
            from_uri=from_,
            to_uri=to,
            state="ringing",
            direction="outbound",
            _runner=self._runner,
        )
        self._calls[call_id] = call
        return call

    # ----- Main loop -----

    def run(self) -> None:
        """Start the client and run the event loop (blocking)"""
        self._start()
        self._running = True

        try:
            if self._mode == "sip":
                self._run_sip_loop()
            else:
                self._run_rtp_loop()
        finally:
            self._stop()

    def _start(self) -> None:
        """Initialize the underlying runner/session"""
        if self._mode == "sip":
            self._start_sip()
        else:
            self._start_rtp()

    def _start_sip(self) -> None:
        """Start SIP runner"""
        providers = self._config.get("providers", [])
        if not providers:
            raise ValueError("No providers configured. Set config or RTPSIP_PROVIDER env var.")

        # Use first provider for simple setup, or write config.toml for multi-provider
        provider = providers[0]

        self._runner = SipRunner(
            provider_name=provider.get("name", "default"),
            provider_server=provider.get("server", ""),
            username=provider.get("username", ""),
            password=provider.get("password", ""),
        )
        self._runner.start()

    def _start_rtp(self) -> None:
        """Start RTP-only session"""
        rtp_config = self._config.get("rtp", {})
        local_ip = rtp_config.get("local_ip", "0.0.0.0")
        local_port = rtp_config.get("local_port", 0)
        codec = rtp_config.get("codec", "PCMU")

        self._rtp_session = RtpSession(
            local_addr=f"{local_ip}:{local_port}",
            codec=codec,
        )
        self._rtp_session.start()

    def _stop(self) -> None:
        """Stop the client"""
        self._running = False
        if self._runner:
            self._runner.stop()
            self._runner = None
        if self._rtp_session:
            self._rtp_session.stop()
            self._rtp_session = None

    def _run_sip_loop(self) -> None:
        """Main event loop for SIP mode"""
        while self._running:
            event = self._runner.next_event(timeout_ms=100)
            if event is None:
                # Check for audio on active calls
                self._process_audio()
                continue

            self._handle_event(event)

    def _run_rtp_loop(self) -> None:
        """Main event loop for RTP-only mode"""
        # Create a dummy call for RTP-only mode
        call = Call(
            id="rtp-session",
            state="active",
            direction="inbound",
            _rtp_session=self._rtp_session,
        )
        self._calls["rtp-session"] = call

        while self._running:
            samples = self._rtp_session.recv_audio(100)
            if samples and self._on_audio:
                self._on_audio(call, samples)

    def _handle_event(self, event: CallEvent) -> None:
        """Handle SIP call event"""
        call_id = event.call_id

        if event.is_incoming():
            call = Call(
                id=call_id,
                from_uri=event.from_uri or "",
                to_uri=event.to_uri or "",
                state="ringing",
                direction="inbound",
                _runner=self._runner,
            )
            self._calls[call_id] = call
            if self._on_incoming:
                self._on_incoming(call)

        elif event.is_ringing():
            call = self._calls.get(call_id)
            if call:
                call.state = "ringing"
                if self._on_ringing:
                    self._on_ringing(call)

        elif event.is_early_media():
            call = self._calls.get(call_id)
            if call:
                call.state = "early_media"

        elif event.is_answered():
            call = self._calls.get(call_id)
            if call:
                call.state = "active"
                if self._on_answered:
                    self._on_answered(call)

        elif event.is_dtmf():
            call = self._calls.get(call_id)
            if call and self._on_dtmf:
                self._on_dtmf(call, event.digit or "")

        elif event.is_hangup():
            call = self._calls.get(call_id)
            if call:
                call.state = "ended"
                if self._on_hangup:
                    self._on_hangup(call, event.reason or "")
                self._calls.pop(call_id, None)

    def _process_audio(self) -> None:
        """Process audio for all active calls"""
        if not self._on_audio:
            return

        for call_id, call in list(self._calls.items()):
            if call.state == "active" and self._runner:
                samples = self._runner.recv_audio(call_id, timeout_ms=10)
                if samples:
                    self._on_audio(call, samples)

    # ----- RTP-only helpers -----

    def set_remote(self, ip: str, port: int) -> None:
        """Set remote RTP endpoint (RTP mode only)"""
        if self._rtp_session:
            self._rtp_session.set_remote(f"{ip}:{port}")

    @property
    def local_port(self) -> Optional[int]:
        """Get local RTP port (RTP mode only)"""
        if self._rtp_session:
            addr = self._rtp_session.local_addr
            if addr:
                return int(addr.split(":")[1])
        return None

    @property
    def local_addr(self) -> Optional[str]:
        """Get local RTP address (RTP mode only)"""
        if self._rtp_session:
            return self._rtp_session.local_addr
        return None
