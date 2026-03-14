"""Tests for rtpsip configuration module"""

import pytest
import tempfile
from pathlib import Path


class TestProviderConfig:
    """Tests for ProviderConfig"""

    def test_create_provider(self):
        """Test creating a provider configuration"""
        from rtpsip.config import ProviderConfig

        provider = ProviderConfig(
            name="plivo",
            server="sip.plivo.com",
            username="AUTH_ID",
            password="AUTH_TOKEN",
            prefixes=["+1"],
        )

        assert provider.name == "plivo"
        assert provider.server == "sip.plivo.com"
        assert provider.port == 5060  # Default
        assert provider.prefixes == ["+1"]
        assert provider.default is False

    def test_provider_defaults(self):
        """Test provider default values"""
        from rtpsip.config import ProviderConfig

        provider = ProviderConfig(name="test", server="sip.test.com")

        assert provider.port == 5060
        assert provider.username == ""
        assert provider.password == ""
        assert provider.prefixes == []
        assert provider.default is False

    def test_provider_validation_empty_name(self):
        """Test provider validation with empty name"""
        from rtpsip.config import ProviderConfig

        provider = ProviderConfig(name="", server="sip.test.com")
        with pytest.raises(ValueError, match="name is required"):
            provider.validate()

    def test_provider_validation_empty_server(self):
        """Test provider validation with empty server"""
        from rtpsip.config import ProviderConfig

        provider = ProviderConfig(name="test", server="")
        with pytest.raises(ValueError, match="empty server"):
            provider.validate()


class TestSipConfig:
    """Tests for SipConfig"""

    def test_sip_config_defaults(self):
        """Test SIP config default values"""
        from rtpsip.config import SipConfig

        config = SipConfig()

        assert config.local_ip == "0.0.0.0"
        assert config.local_port == 5060
        assert config.transport == "udp"
        assert config.tls_cert is None

    def test_sip_config_validation_invalid_transport(self):
        """Test SIP config validation with invalid transport"""
        from rtpsip.config import SipConfig

        config = SipConfig(transport="http")
        with pytest.raises(ValueError, match="Invalid transport"):
            config.validate()

    def test_sip_config_validation_tls_requires_certs(self):
        """Test SIP config validation - TLS requires certs"""
        from rtpsip.config import SipConfig

        config = SipConfig(transport="tls")
        with pytest.raises(ValueError, match="requires tls_cert"):
            config.validate()

    def test_sip_config_validation_tls_with_certs(self):
        """Test SIP config validation - TLS with certs"""
        from rtpsip.config import SipConfig

        config = SipConfig(
            transport="tls",
            tls_cert="/path/to/cert.pem",
            tls_key="/path/to/key.pem",
        )
        config.validate()  # Should not raise


class TestRtpConfig:
    """Tests for RtpConfig"""

    def test_rtp_config_defaults(self):
        """Test RTP config default values"""
        from rtpsip.config import RtpConfig

        config = RtpConfig()

        assert config.local_ip == "0.0.0.0"
        assert config.port_start == 10000
        assert config.port_end == 20000

    def test_rtp_config_validation_invalid_range(self):
        """Test RTP config validation with invalid port range"""
        from rtpsip.config import RtpConfig

        config = RtpConfig(port_start=20000, port_end=10000)
        with pytest.raises(ValueError, match="port_start must be less than port_end"):
            config.validate()


class TestConfig:
    """Tests for main Config class"""

    def test_create_config(self):
        """Test creating a full configuration"""
        from rtpsip.config import Config, SipConfig, RtpConfig, ProviderConfig

        config = Config(
            sip=SipConfig(local_port=5080),
            rtp=RtpConfig(port_start=20000, port_end=30000),
            providers=[
                ProviderConfig(
                    name="plivo",
                    server="sip.plivo.com",
                    username="AUTH_ID",
                    password="AUTH_TOKEN",
                    prefixes=["+1"],
                )
            ],
            blocked_prefixes=["+1900"],
        )

        assert config.sip.local_port == 5080
        assert config.rtp.port_start == 20000
        assert len(config.providers) == 1
        assert config.blocked_prefixes == ["+1900"]

    def test_config_validation_no_providers(self):
        """Test config validation with no providers"""
        from rtpsip.config import Config

        config = Config()
        with pytest.raises(ValueError, match="At least one provider is required"):
            config.validate()

    def test_config_routing_longest_prefix(self):
        """Test config routing with longest prefix match"""
        from rtpsip.config import Config, ProviderConfig

        config = Config(
            providers=[
                ProviderConfig(name="us", server="sip.us.com", prefixes=["+1"]),
                ProviderConfig(name="sf", server="sip.sf.com", prefixes=["+1415"]),
            ]
        )

        # +1415 should match "sf" (longer prefix)
        provider = config.route("+14155551234")
        assert provider is not None
        assert provider.name == "sf"

        # +1212 should match "us"
        provider = config.route("+12125551234")
        assert provider is not None
        assert provider.name == "us"

    def test_config_routing_default_provider(self):
        """Test config routing with default provider"""
        from rtpsip.config import Config, ProviderConfig

        config = Config(
            providers=[
                ProviderConfig(name="us", server="sip.us.com", prefixes=["+1"]),
                ProviderConfig(name="default", server="sip.default.com", default=True),
            ]
        )

        # +44 has no matching prefix, should use default
        provider = config.route("+442071234567")
        assert provider is not None
        assert provider.name == "default"

    def test_config_routing_no_match(self):
        """Test config routing with no match and no default"""
        from rtpsip.config import Config, ProviderConfig

        config = Config(
            providers=[
                ProviderConfig(name="us", server="sip.us.com", prefixes=["+1"]),
            ]
        )

        # +44 has no match
        provider = config.route("+442071234567")
        assert provider is None

    def test_config_is_blocked(self):
        """Test config blocked prefix check"""
        from rtpsip.config import Config, ProviderConfig

        config = Config(
            providers=[ProviderConfig(name="test", server="sip.test.com")],
            blocked_prefixes=["+1900", "+1976"],
        )

        assert config.is_blocked("+19005551234") is True
        assert config.is_blocked("+19765551234") is True
        assert config.is_blocked("+14155551234") is False

    def test_config_to_toml(self):
        """Test config TOML generation"""
        from rtpsip.config import Config, ProviderConfig

        config = Config(
            providers=[
                ProviderConfig(
                    name="plivo",
                    server="sip.plivo.com",
                    username="AUTH_ID",
                    password="AUTH_TOKEN",
                    prefixes=["+1"],
                    default=True,
                )
            ],
            blocked_prefixes=["+1900"],
        )

        toml_str = config.to_toml()

        assert "[sip]" in toml_str
        assert "[rtp]" in toml_str
        assert "[[providers]]" in toml_str
        assert 'name = "plivo"' in toml_str
        assert 'server = "sip.plivo.com"' in toml_str
        assert 'username = "AUTH_ID"' in toml_str
        assert 'password = "AUTH_TOKEN"' in toml_str

        assert "[routing]" in toml_str
        assert '"+1900"' in toml_str

    def test_config_to_toml_file(self):
        """Test config TOML file writing"""
        from rtpsip.config import Config, ProviderConfig

        config = Config(
            providers=[
                ProviderConfig(name="test", server="sip.test.com", default=True)
            ]
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            config.to_toml(f.name)
            content = Path(f.name).read_text()
            assert "[sip]" in content
            assert 'name = "test"' in content


class TestRtpSessionConfig:
    """Tests for RtpSessionConfig (Mode B)"""

    def test_rtp_session_config_defaults(self):
        """Test RTP session config default values"""
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig()

        assert config.local_ip == "0.0.0.0"
        assert config.local_port == 0
        assert config.codec == "PCMU"
        assert config.remote_ip is None
        assert config.remote_port is None

    def test_rtp_session_config_local_addr(self):
        """Test RTP session config local_addr property"""
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig(local_ip="192.168.1.1", local_port=5004)
        assert config.local_addr == "192.168.1.1:5004"

    def test_rtp_session_config_remote_addr(self):
        """Test RTP session config remote_addr property"""
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig(remote_ip="10.0.0.1", remote_port=5006)
        assert config.remote_addr == "10.0.0.1:5006"

        config_no_remote = RtpSessionConfig()
        assert config_no_remote.remote_addr is None

    def test_rtp_session_config_to_dict(self):
        """Test RTP session config to_dict for RtpSession"""
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig(
            local_ip="0.0.0.0",
            local_port=0,
            codec="PCMA",
        )

        d = config.to_dict()
        assert d["local_addr"] == "0.0.0.0:0"
        assert d["codec"] == "PCMA"
        assert "remote_addr" not in d

    def test_rtp_session_config_validation_invalid_codec(self):
        """Test RTP session config validation with invalid codec"""
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig(codec="OPUS")
        with pytest.raises(ValueError, match="Invalid codec"):
            config.validate()

    def test_rtp_session_config_validation_jitter(self):
        """Test RTP session config jitter validation"""
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig(jitter_min_ms=100, jitter_max_ms=50)
        with pytest.raises(ValueError, match="jitter_min_ms must be less than"):
            config.validate()


class TestConvenienceFunctions:
    """Tests for convenience functions"""

    def test_create_single_provider_config(self):
        """Test create_single_provider_config"""
        from rtpsip.config import create_single_provider_config

        config = create_single_provider_config(
            provider_name="plivo",
            server="sip.plivo.com",
            username="AUTH_ID",
            password="AUTH_TOKEN",
        )

        assert len(config.providers) == 1
        assert config.providers[0].name == "plivo"
        assert config.providers[0].username == "AUTH_ID"
        assert config.providers[0].default is True

    def test_create_multi_provider_config(self):
        """Test create_multi_provider_config"""
        from rtpsip.config import create_multi_provider_config

        config = create_multi_provider_config(
            providers=[
                {
                    "name": "plivo_us",
                    "server": "sip.plivo.com",
                    "username": "AUTH_ID",
                    "password": "AUTH_TOKEN",
                    "prefixes": ["+1"],
                },
                {
                    "name": "plivo_eu",
                    "server": "sip.plivo.com",
                    "username": "AUTH_ID_EU",
                    "password": "AUTH_TOKEN_EU",
                    "prefixes": ["+44"],
                    "default": True,
                },
            ],
            blocked_prefixes=["+1900"],
        )

        assert len(config.providers) == 2
        assert config.providers[0].name == "plivo_us"
        assert config.providers[1].default is True
        assert config.blocked_prefixes == ["+1900"]


class TestConfigIntegration:
    """Integration tests with RtpSession"""

    def test_rtp_session_with_config(self):
        """Test using RtpSessionConfig with RtpSession"""
        from rtpsip import RtpSession
        from rtpsip.config import RtpSessionConfig

        config = RtpSessionConfig(
            local_ip="127.0.0.1",
            local_port=0,
            codec="PCMU",
        )

        # Create session using config
        session = RtpSession(**config.to_dict())
        session.start()

        assert session.is_running
        assert session.codec == "PCMU"

        session.stop()
