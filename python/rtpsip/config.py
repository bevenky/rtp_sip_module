"""
Configuration module for rtpsip.

Provides Python-native configuration classes for both SIP+RTP (Mode A)
and RTP-only (Mode B) modes.

Example - Mode A (SIP+RTP):
    from rtpsip.config import Config, SipConfig, RtpConfig, ProviderConfig

    config = Config(
        sip=SipConfig(local_port=5060),
        rtp=RtpConfig(port_start=10000, port_end=20000),
        providers=[
            ProviderConfig(
                name="plivo_us",
                server="sip.plivo.com",
                auth_username="AUTH_ID",
                auth_password="AUTH_TOKEN",
                prefixes=["+1", "+1415"],
            ),
            ProviderConfig(
                name="plivo_eu",
                server="sip.plivo.com",
                auth_username="AUTH_ID_EU",
                auth_password="AUTH_TOKEN_EU",
                prefixes=["+44", "+49"],
                default=True,
            ),
        ],
        blocked_prefixes=["+1900", "+1976"],
    )

    # Save to file
    config.to_toml("config.toml")

    # Or use directly
    from rtpsip import SipRunner
    runner = SipRunner.from_config(config)

Example - Mode B (RTP-only):
    from rtpsip.config import RtpSessionConfig

    config = RtpSessionConfig(
        local_ip="0.0.0.0",
        local_port=0,  # Dynamic port
        codec="PCMU",
        jitter_min_ms=20,
        jitter_max_ms=200,
        jitter_target_ms=60,
    )

    from rtpsip import RtpSession
    session = RtpSession(**config.to_dict())
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from pathlib import Path
import json


# =============================================================================
# Mode A: SIP + RTP Configuration
# =============================================================================

@dataclass
class SipConfig:
    """
    SIP signaling configuration.

    Attributes:
        local_ip: Local IP to bind SIP socket (default: "0.0.0.0")
        local_port: Local SIP port (default: 5060)
        transport: Transport protocol - "udp" or "tls" (default: "udp")
        tls_cert: Path to TLS certificate (required if transport="tls")
        tls_key: Path to TLS private key (required if transport="tls")
    """
    local_ip: str = "0.0.0.0"
    local_port: int = 5060
    transport: str = "udp"
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None

    def validate(self) -> None:
        """Validate the configuration."""
        if self.transport not in ("udp", "tls"):
            raise ValueError(f"Invalid transport '{self.transport}'. Must be 'udp' or 'tls'")
        if self.transport == "tls":
            if not self.tls_cert or not self.tls_key:
                raise ValueError("TLS transport requires tls_cert and tls_key")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for TOML serialization."""
        d = {
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "transport": self.transport,
        }
        if self.tls_cert:
            d["tls_cert"] = self.tls_cert
        if self.tls_key:
            d["tls_key"] = self.tls_key
        return d


@dataclass
class RtpConfig:
    """
    RTP media configuration for SIP mode.

    Attributes:
        local_ip: Local IP to bind RTP sockets (default: "0.0.0.0")
        port_start: RTP port range start (default: 10000)
        port_end: RTP port range end (default: 20000)
    """
    local_ip: str = "0.0.0.0"
    port_start: int = 10000
    port_end: int = 20000

    def validate(self) -> None:
        """Validate the configuration."""
        if self.port_start >= self.port_end:
            raise ValueError("RTP port_start must be less than port_end")
        if self.port_start < 1024:
            raise ValueError("RTP port_start should be >= 1024")
        if self.port_end > 65535:
            raise ValueError("RTP port_end must be <= 65535")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for TOML serialization."""
        return {
            "local_ip": self.local_ip,
            "port_start": self.port_start,
            "port_end": self.port_end,
        }


@dataclass
class ProviderConfig:
    """
    SIP trunk provider configuration.

    Attributes:
        name: Provider name for identification and logging
        server: SIP server hostname (e.g., "sip.plivo.com")
        port: SIP server port (default: 5060)
        auth_username: Authentication username (e.g., Plivo AUTH_ID)
        auth_password: Authentication password (e.g., Plivo AUTH_TOKEN)
        realm: Authentication realm (optional, defaults to server)
        prefixes: List of phone number prefixes this provider handles
                  (longest prefix match wins)
        default: If True, use as fallback for unmatched prefixes
    """
    name: str
    server: str
    port: int = 5060
    auth_username: str = ""
    auth_password: str = ""
    realm: Optional[str] = None
    prefixes: List[str] = field(default_factory=list)
    default: bool = False

    def validate(self) -> None:
        """Validate the configuration."""
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.server:
            raise ValueError(f"Provider '{self.name}' has empty server")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for TOML serialization."""
        d = {
            "name": self.name,
            "server": self.server,
            "port": self.port,
        }
        if self.auth_username:
            d["auth_username"] = self.auth_username
        if self.auth_password:
            d["auth_password"] = self.auth_password
        if self.realm:
            d["realm"] = self.realm
        if self.prefixes:
            d["prefixes"] = self.prefixes
        if self.default:
            d["default"] = self.default
        return d


@dataclass
class Config:
    """
    Main configuration for SIP+RTP mode.

    This is the complete configuration for Mode A (full SIP stack).

    Attributes:
        sip: SIP signaling configuration
        rtp: RTP media configuration
        providers: List of SIP trunk providers
        blocked_prefixes: List of phone prefixes to block
    """
    sip: SipConfig = field(default_factory=SipConfig)
    rtp: RtpConfig = field(default_factory=RtpConfig)
    providers: List[ProviderConfig] = field(default_factory=list)
    blocked_prefixes: List[str] = field(default_factory=list)

    def validate(self) -> None:
        """Validate the entire configuration."""
        self.sip.validate()
        self.rtp.validate()

        if not self.providers:
            raise ValueError("At least one provider is required")

        for provider in self.providers:
            provider.validate()

        # Check for duplicate provider names
        names = [p.name for p in self.providers]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate provider names found")

    def add_provider(self, provider: ProviderConfig) -> "Config":
        """Add a provider and return self for chaining."""
        self.providers.append(provider)
        return self

    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        """Get a provider by name."""
        for p in self.providers:
            if p.name == name:
                return p
        return None

    def route(self, destination: str) -> Optional[ProviderConfig]:
        """
        Route a destination to the best provider (longest prefix match).

        Args:
            destination: Phone number or SIP URI to route

        Returns:
            Best matching provider, or None if no match and no default
        """
        # Normalize destination
        dest = destination
        if dest.startswith("sip:"):
            dest = dest[4:]
        if "@" in dest:
            dest = dest.split("@")[0]

        # Find best match
        best_match = None
        best_len = 0

        for provider in self.providers:
            for prefix in provider.prefixes:
                if dest.startswith(prefix) and len(prefix) > best_len:
                    best_match = provider
                    best_len = len(prefix)

        # Return best match or default
        if best_match:
            return best_match

        for provider in self.providers:
            if provider.default:
                return provider

        return None

    def is_blocked(self, destination: str) -> bool:
        """Check if a destination is blocked."""
        dest = destination
        if dest.startswith("sip:"):
            dest = dest[4:]
        if "@" in dest:
            dest = dest.split("@")[0]

        return any(dest.startswith(prefix) for prefix in self.blocked_prefixes)

    def to_toml(self, path: Optional[str] = None) -> str:
        """
        Generate TOML configuration string.

        Args:
            path: If provided, write to file

        Returns:
            TOML configuration string
        """
        lines = []

        # SIP section
        lines.append("[sip]")
        lines.append(f'local_ip = "{self.sip.local_ip}"')
        lines.append(f"local_port = {self.sip.local_port}")
        lines.append(f'transport = "{self.sip.transport}"')
        if self.sip.tls_cert:
            lines.append(f'tls_cert = "{self.sip.tls_cert}"')
        if self.sip.tls_key:
            lines.append(f'tls_key = "{self.sip.tls_key}"')
        lines.append("")

        # RTP section
        lines.append("[rtp]")
        lines.append(f'local_ip = "{self.rtp.local_ip}"')
        lines.append(f"port_start = {self.rtp.port_start}")
        lines.append(f"port_end = {self.rtp.port_end}")
        lines.append("")

        # Providers
        for provider in self.providers:
            lines.append("[[providers]]")
            lines.append(f'name = "{provider.name}"')
            lines.append(f'server = "{provider.server}"')
            lines.append(f"port = {provider.port}")
            if provider.auth_username:
                lines.append(f'auth_username = "{provider.auth_username}"')
            if provider.auth_password:
                lines.append(f'auth_password = "{provider.auth_password}"')
            if provider.realm:
                lines.append(f'realm = "{provider.realm}"')
            if provider.prefixes:
                prefixes_str = ", ".join(f'"{p}"' for p in provider.prefixes)
                lines.append(f"prefixes = [{prefixes_str}]")
            if provider.default:
                lines.append("default = true")
            lines.append("")

        # Routing
        if self.blocked_prefixes:
            lines.append("[routing]")
            blocked_str = ", ".join(f'"{p}"' for p in self.blocked_prefixes)
            lines.append(f"blocked_prefixes = [{blocked_str}]")
            lines.append("")

        toml_str = "\n".join(lines)

        if path:
            Path(path).write_text(toml_str)

        return toml_str

    @classmethod
    def from_toml(cls, path: str) -> "Config":
        """
        Load configuration from a TOML file.

        Args:
            path: Path to TOML file

        Returns:
            Config instance
        """
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # Fallback for older Python

        content = Path(path).read_text()
        data = tomllib.loads(content)

        sip_data = data.get("sip", {})
        rtp_data = data.get("rtp", {})
        providers_data = data.get("providers", [])
        routing_data = data.get("routing", {})

        return cls(
            sip=SipConfig(**sip_data),
            rtp=RtpConfig(**rtp_data),
            providers=[ProviderConfig(**p) for p in providers_data],
            blocked_prefixes=routing_data.get("blocked_prefixes", []),
        )


# =============================================================================
# Mode B: RTP-Only Configuration
# =============================================================================

@dataclass
class RtpSessionConfig:
    """
    Configuration for RTP-only mode (Mode B).

    For use with external signaling (WebSocket, custom SIP, etc.).

    Attributes:
        local_ip: Local IP to bind (default: "0.0.0.0")
        local_port: Local port (0 = dynamic allocation)
        remote_ip: Remote RTP endpoint IP (optional, can set later)
        remote_port: Remote RTP endpoint port (optional, can set later)
        codec: Audio codec - "PCMU" or "PCMA" (default: "PCMU")
        ssrc: RTP SSRC (auto-generated if not provided)
        jitter_min_ms: Minimum jitter buffer delay in ms (default: 20)
        jitter_max_ms: Maximum jitter buffer delay in ms (default: 200)
        jitter_target_ms: Target jitter buffer delay in ms (default: 60)
    """
    local_ip: str = "0.0.0.0"
    local_port: int = 0
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    codec: str = "PCMU"
    ssrc: Optional[int] = None
    jitter_min_ms: int = 20
    jitter_max_ms: int = 200
    jitter_target_ms: int = 60

    def validate(self) -> None:
        """Validate the configuration."""
        if self.codec not in ("PCMU", "PCMA", "pcmu", "pcma", "ULAW", "ALAW", "ulaw", "alaw"):
            raise ValueError(f"Invalid codec '{self.codec}'. Must be 'PCMU' or 'PCMA'")
        if self.jitter_min_ms >= self.jitter_max_ms:
            raise ValueError("jitter_min_ms must be less than jitter_max_ms")
        if not (self.jitter_min_ms <= self.jitter_target_ms <= self.jitter_max_ms):
            raise ValueError("jitter_target_ms must be between min and max")

    @property
    def local_addr(self) -> str:
        """Get local address string for RtpSession."""
        return f"{self.local_ip}:{self.local_port}"

    @property
    def remote_addr(self) -> Optional[str]:
        """Get remote address string for RtpSession."""
        if self.remote_ip and self.remote_port:
            return f"{self.remote_ip}:{self.remote_port}"
        return None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for RtpSession constructor.

        Returns:
            Dictionary with keys matching RtpSession.__init__ parameters
        """
        d = {
            "local_addr": self.local_addr,
            "codec": self.codec.upper(),
        }
        if self.remote_addr:
            d["remote_addr"] = self.remote_addr
        if self.ssrc is not None:
            d["ssrc"] = self.ssrc
        return d

    def to_json(self, path: Optional[str] = None) -> str:
        """
        Generate JSON configuration string.

        Args:
            path: If provided, write to file

        Returns:
            JSON configuration string
        """
        data = asdict(self)
        json_str = json.dumps(data, indent=2)

        if path:
            Path(path).write_text(json_str)

        return json_str

    @classmethod
    def from_json(cls, path: str) -> "RtpSessionConfig":
        """Load configuration from a JSON file."""
        data = json.loads(Path(path).read_text())
        return cls(**data)


# =============================================================================
# Convenience Functions
# =============================================================================

def create_single_provider_config(
    provider_name: str,
    server: str,
    auth_username: str,
    auth_password: str,
    *,
    local_sip_port: int = 5060,
    rtp_port_start: int = 10000,
    rtp_port_end: int = 20000,
) -> Config:
    """
    Create a simple single-provider configuration.

    Args:
        provider_name: Provider name
        server: SIP server hostname
        auth_username: Authentication username
        auth_password: Authentication password
        local_sip_port: Local SIP port (default: 5060)
        rtp_port_start: RTP port range start (default: 10000)
        rtp_port_end: RTP port range end (default: 20000)

    Returns:
        Config instance

    Example:
        config = create_single_provider_config(
            "plivo",
            "sip.plivo.com",
            "AUTH_ID",
            "AUTH_TOKEN",
        )
    """
    return Config(
        sip=SipConfig(local_port=local_sip_port),
        rtp=RtpConfig(port_start=rtp_port_start, port_end=rtp_port_end),
        providers=[
            ProviderConfig(
                name=provider_name,
                server=server,
                auth_username=auth_username,
                auth_password=auth_password,
                default=True,
            )
        ],
    )


def create_multi_provider_config(
    providers: List[Dict[str, Any]],
    blocked_prefixes: Optional[List[str]] = None,
    **kwargs,
) -> Config:
    """
    Create a multi-provider configuration.

    Args:
        providers: List of provider dictionaries with keys:
            - name: Provider name
            - server: SIP server hostname
            - auth_username: Authentication username
            - auth_password: Authentication password
            - prefixes: List of phone prefixes (optional)
            - default: Is default provider (optional)
        blocked_prefixes: List of phone prefixes to block
        **kwargs: Additional arguments for SipConfig/RtpConfig

    Returns:
        Config instance

    Example:
        config = create_multi_provider_config(
            providers=[
                {
                    "name": "plivo_us",
                    "server": "sip.plivo.com",
                    "auth_username": "AUTH_ID",
                    "auth_password": "AUTH_TOKEN",
                    "prefixes": ["+1"],
                },
                {
                    "name": "plivo_eu",
                    "server": "sip.plivo.com",
                    "auth_username": "AUTH_ID_EU",
                    "auth_password": "AUTH_TOKEN_EU",
                    "prefixes": ["+44"],
                    "default": True,
                },
            ],
            blocked_prefixes=["+1900"],
        )
    """
    provider_configs = [ProviderConfig(**p) for p in providers]

    sip_kwargs = {k: v for k, v in kwargs.items() if k in SipConfig.__dataclass_fields__}
    rtp_kwargs = {k: v for k, v in kwargs.items() if k in RtpConfig.__dataclass_fields__}

    return Config(
        sip=SipConfig(**sip_kwargs) if sip_kwargs else SipConfig(),
        rtp=RtpConfig(**rtp_kwargs) if rtp_kwargs else RtpConfig(),
        providers=provider_configs,
        blocked_prefixes=blocked_prefixes or [],
    )
