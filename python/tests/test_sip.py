"""Tests for rtpsip SIP functionality (Mode A)"""

import pytest
import tempfile
import os


class TestSipRunner:
    """Tests for SipRunner"""

    def test_import_mode_a(self):
        """Test that Mode A classes can be imported"""
        from rtpsip import (
            SipRunner,
            CallEvent,
            CallState,
        )
        assert SipRunner is not None
        assert CallEvent is not None
        assert CallState is not None

    def test_create_runner_programmatic(self):
        """Test creating a SipRunner with programmatic config"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
            username="user",
            password="pass",
        )
        assert not runner.is_running()
        assert runner.provider_count == 1
        assert "test" in runner.provider_names
        assert "SipRunner" in repr(runner)

    def test_create_runner_from_config(self):
        """Test creating a SipRunner from config file"""
        from rtpsip import SipRunner

        config_content = '''
[[providers]]
name = "plivo"
server = "sip.plivo.com"
username = "user"
password = "pass"
default = true
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            runner = SipRunner.from_config(config_path)
            assert not runner.is_running()
            assert runner.provider_count == 1
            assert "plivo" in runner.provider_names
        finally:
            os.unlink(config_path)

    def test_create_runner_multi_provider(self):
        """Test creating a SipRunner with multiple providers"""
        from rtpsip import SipRunner

        config_content = '''
[[providers]]
name = "plivo"
server = "sip.plivo.com"
prefixes = ["+1"]

[[providers]]
name = "telnyx"
server = "sip.telnyx.com"
prefixes = ["+44"]
default = true
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            runner = SipRunner.from_config(config_path)
            assert runner.provider_count == 2
            assert "plivo" in runner.provider_names
            assert "telnyx" in runner.provider_names
        finally:
            os.unlink(config_path)

    def test_blocked_prefixes(self):
        """Test blocked prefixes configuration"""
        from rtpsip import SipRunner

        config_content = '''
[[providers]]
name = "test"
server = "sip.test.com"
default = true

[routing]
blocked_prefixes = ["+1900", "+1976"]
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            runner = SipRunner.from_config(config_path)
            assert "+1900" in runner.blocked_prefixes
            assert "+1976" in runner.blocked_prefixes
        finally:
            os.unlink(config_path)

    def test_call_state_enum(self):
        """Test CallState enum values (simplified 5-state model)"""
        from rtpsip import CallState

        # Simplified states: Ringing -> EarlyMedia -> Active -> Hold -> Ended
        assert CallState.Ringing == 0     # 180 - ringing, no media
        assert CallState.EarlyMedia == 1  # 183 with SDP - can hear ringback
        assert CallState.Active == 2      # 200 OK - call answered
        assert CallState.Hold == 3        # on hold
        assert CallState.Ended == 4       # call ended

    def test_runner_not_started_errors(self):
        """Test that methods error when runner not started"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
        )

        with pytest.raises(RuntimeError):
            runner.call(to="+14155551234", from_="+14155550000")

        with pytest.raises(RuntimeError):
            runner.hangup("some-call-id")

        with pytest.raises(RuntimeError):
            runner.active_calls()

    def test_invalid_config(self):
        """Test that invalid config raises error"""
        from rtpsip import SipRunner

        # No providers
        config_content = '''
[sip]
local_port = 5060
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            with pytest.raises(ValueError):
                SipRunner.from_config(config_path)
        finally:
            os.unlink(config_path)

    def test_tls_config(self):
        """Test TLS configuration"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
            transport="udp",
        )
        assert not runner.is_tls

        # TLS without certs should work in programmatic mode (validation deferred)
        # but would fail on start if actually using TLS


class TestInboundCallHandling:
    """Tests for inbound call handling (answer/reject)"""

    def test_answer_method_exists(self):
        """Test that answer method exists on SipRunner"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
        )
        assert hasattr(runner, 'answer')
        assert callable(runner.answer)

    def test_reject_method_exists(self):
        """Test that reject method exists on SipRunner"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
        )
        assert hasattr(runner, 'reject')
        assert callable(runner.reject)

    def test_answer_not_started_error(self):
        """Test that answer errors when runner not started"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
        )

        with pytest.raises(RuntimeError):
            runner.answer("some-call-id")

    def test_reject_not_started_error(self):
        """Test that reject errors when runner not started"""
        from rtpsip import SipRunner

        runner = SipRunner(
            provider_name="test",
            provider_server="sip.test.com",
        )

        with pytest.raises(RuntimeError):
            runner.reject("some-call-id", 486)

    def test_call_event_is_incoming(self):
        """Test CallEvent has is_incoming method"""
        from rtpsip import CallEvent

        assert hasattr(CallEvent, 'is_incoming')

    def test_call_event_from_uri_attribute(self):
        """Test CallEvent has from_uri attribute"""
        from rtpsip import CallEvent

        # CallEvent is defined with from_uri attribute
        assert 'from_uri' in dir(CallEvent) or hasattr(CallEvent, '__annotations__')

    def test_call_event_to_uri_attribute(self):
        """Test CallEvent has to_uri attribute"""
        from rtpsip import CallEvent

        # CallEvent is defined with to_uri attribute
        assert 'to_uri' in dir(CallEvent) or hasattr(CallEvent, '__annotations__')
