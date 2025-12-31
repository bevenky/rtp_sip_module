"""Basic tests for rtpsip RTP functionality"""

import pytest
import time


class TestRtpSession:
    """Tests for RtpSession"""

    def test_import(self):
        """Test that the module can be imported"""
        from rtpsip import RtpSession, JitterStats, __version__
        assert __version__ is not None

    def test_create_session(self):
        """Test creating an RTP session"""
        from rtpsip import RtpSession

        session = RtpSession(
            local_addr="127.0.0.1:0",
            codec="PCMU",
        )
        assert session.codec == "PCMU"

    def test_create_session_pcma(self):
        """Test creating an RTP session with PCMA codec"""
        from rtpsip import RtpSession

        session = RtpSession(
            local_addr="127.0.0.1:0",
            codec="PCMA",
        )
        assert session.codec == "PCMA"

    def test_invalid_codec(self):
        """Test that invalid codec raises error"""
        from rtpsip import RtpSession

        with pytest.raises(ValueError):
            RtpSession(codec="OPUS")

    def test_start_stop(self):
        """Test starting and stopping a session"""
        from rtpsip import RtpSession

        session = RtpSession(local_addr="127.0.0.1:0")
        session.start()

        assert session.is_running
        # Should have bound to a port
        assert ":0" not in session.local_addr

        session.stop()
        assert not session.is_running

    def test_loopback(self):
        """Test sending and receiving audio in loopback"""
        from rtpsip import RtpSession

        # Create two sessions
        session1 = RtpSession(local_addr="127.0.0.1:0")
        session2 = RtpSession(local_addr="127.0.0.1:0")

        session1.start()
        session2.start()

        # Point them at each other
        session1.set_remote(session2.local_addr)
        session2.set_remote(session1.local_addr)

        # Send multiple packets to fill jitter buffer
        samples = list(range(0, 16000, 100))  # 160 samples
        for _ in range(5):
            session1.send_audio(samples)
            time.sleep(0.02)

        # Give time for packets to arrive
        time.sleep(0.1)

        # Receive
        received = session2.recv_audio(500)

        # Should have received something (G.711 is lossy)
        assert received is not None
        assert len(received) == 160

        session1.stop()
        session2.stop()

    def test_jitter_stats(self):
        """Test getting jitter buffer statistics"""
        from rtpsip import RtpSession

        session = RtpSession(local_addr="127.0.0.1:0")
        session.start()

        stats = session.get_stats()
        assert stats.packets_received == 0
        assert stats.packets_lost == 0
        assert stats.buffer_size == 0

        session.stop()

    def test_websocket_workflow(self):
        """
        Test the exact workflow for external signaling (websocket):

        1. Server sends remote RTP host/port over websocket
        2. Python creates session with dynamic port (0.0.0.0:0)
        3. Python starts session, gets allocated port
        4. Python sends local_addr back to server via websocket
        5. Python calls set_remote() with server's RTP endpoint
        6. Audio flows, Python receives L16 frames via recv_audio()
        """
        from rtpsip import RtpSession

        # Simulate: Server tells us its RTP endpoint via websocket
        # (In real app, this comes from websocket message)
        server_rtp_endpoint = None  # We'll set this from session2

        # Step 1-2: Create session with dynamic port (no remote yet)
        client_session = RtpSession(
            local_addr="127.0.0.1:0",  # Dynamic port
            codec="PCMU",
        )

        # Verify remote is not set yet
        assert client_session.remote_addr is None

        # Step 3: Start session - port is now allocated
        client_session.start()
        assert client_session.is_running

        # Step 4: Get the dynamically allocated port
        local_addr = client_session.local_addr
        assert ":0" not in local_addr  # Port was allocated

        # Extract port for verification
        port = int(local_addr.split(":")[1])
        assert port > 0 and port < 65536

        # Simulate: We would send local_addr to server via websocket here
        # websocket.send({"rtp_addr": local_addr})

        # --- Server side simulation ---
        # Server creates its RTP session pointing at our allocated port
        server_session = RtpSession(local_addr="127.0.0.1:0", codec="PCMU")
        server_session.start()
        server_session.set_remote(local_addr)  # Server points to us
        server_rtp_endpoint = server_session.local_addr

        # Step 5: Simulate receiving server's RTP endpoint via websocket
        # server_rtp_endpoint = websocket.recv()["rtp_addr"]
        client_session.set_remote(server_rtp_endpoint)

        # Verify remote is now set
        assert client_session.remote_addr == server_rtp_endpoint

        # Step 6: Audio flows - server sends, client receives L16 frames
        # Server sends multiple packets to fill jitter buffer
        audio_samples = [i * 100 for i in range(160)]  # 160 samples = 20ms @ 8kHz
        for _ in range(5):
            server_session.send_audio(audio_samples)
            time.sleep(0.02)  # 20ms between packets

        # Give time for packets to arrive and jitter buffer to fill
        time.sleep(0.1)

        # Client receives L16 audio frame
        received = client_session.recv_audio(500)  # 500ms timeout

        # Verify L16 samples received
        assert received is not None, "Should have received audio"
        assert isinstance(received, list), "Should be list of samples"
        assert len(received) == 160, "Should be 160 samples (20ms frame)"
        assert all(isinstance(s, int) for s in received), "Should be i16 integers"

        # Verify jitter stats show packets received
        stats = client_session.get_stats()
        assert stats.packets_received > 0, "Should have received packets"

        # Cleanup
        client_session.stop()
        server_session.stop()

    def test_multiple_concurrent_sessions(self):
        """
        Test multiple RTP sessions with different dynamically allocated ports.
        Simulates handling multiple concurrent calls.
        """
        from rtpsip import RtpSession

        sessions = []
        ports = set()

        # Create 5 concurrent sessions with dynamic ports
        for i in range(5):
            session = RtpSession(local_addr="127.0.0.1:0", codec="PCMU")
            session.start()
            sessions.append(session)

            # Extract port
            port = int(session.local_addr.split(":")[1])
            ports.add(port)

        # All ports should be unique
        assert len(ports) == 5, "Each session should have a unique port"

        # All sessions should be running
        for session in sessions:
            assert session.is_running

        # Cleanup
        for session in sessions:
            session.stop()
            assert not session.is_running
