#!/usr/bin/env python3
"""
NAT Traversal Configuration

Demonstrates configuring STUN, TURN, symmetric RTP, and hole punching
for SIP/RTP behind NAT.

NAT traversal is configured in config.toml and handled automatically
by the library. This example shows the configuration options.
"""


def nat_config_toml():
    """
    NAT configuration in config.toml.

    The [nat] section configures NAT traversal behavior.
    Most users only need to set a STUN server.

    config.toml:
    ```toml
    [sip]
    local_ip = "0.0.0.0"
    local_port = 5060

    [rtp]
    local_ip = "0.0.0.0"
    port_start = 10000
    port_end = 20000

    # Symmetric RTP - learn remote address from incoming packets
    # Handles most NAT scenarios automatically
    enable_symmetric_rtp = true

    [nat]
    # STUN server for reflexive address discovery
    # Used to determine public IP for SDP and SIP Contact header
    stun_server = "stun.l.google.com:19302"

    # STUN server pool for failover
    stun_servers = [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
    ]

    # TURN relay for symmetric NAT
    # Only needed when direct UDP is blocked
    turn_server = "turn.example.com:3478"
    turn_username = "user"
    turn_password = "pass"

    [[providers]]
    name = "carrier"
    server = "sip.carrier.com"
    port = 5060
    username = "user"
    password = "pass"
    default = true
    ```
    """
    pass


def symmetric_rtp_explanation():
    """
    Symmetric RTP (RFC 4961)

    When enabled (default), the RTP engine learns the remote party's
    actual address from incoming RTP packets instead of relying solely
    on the SDP address. This handles cases where:

    - Remote is behind NAT (SDP contains private IP)
    - SBC/proxy rewrites media path
    - Port mapping changes during call

    Enable in config:
        [rtp]
        enable_symmetric_rtp = true

    The library automatically:
    1. Opens RTP socket on configured port
    2. Sends initial packets to SDP address
    3. On first incoming packet, updates remote address to actual source
    4. Continues sending to learned address for rest of call
    """
    pass


def nat_type_detection():
    """
    NAT Type Detection

    The library can detect NAT type using RFC 3489/5780 tests:

    - Full Cone: Any external host can send to mapped address
    - Restricted Cone: Only hosts we've sent to can reply
    - Port Restricted Cone: Only hosts+ports we've sent to can reply
    - Symmetric: Different mapping for each destination

    Detection results influence traversal strategy:
    - Full/Restricted/Port Restricted -> STUN sufficient
    - Symmetric -> TURN relay required

    Detection is automatic when nat.stun_server is configured.
    """
    pass


def contact_nat_rewrite():
    """
    Contact Header NAT Rewriting

    When behind NAT, the SIP Contact header needs to contain the
    public (reflexive) address, not the private address. Configure:

        [sip]
        contact_nat_rewrite = true

    This uses the STUN-discovered address for:
    - Contact header in REGISTER requests
    - Contact header in INVITE requests
    - Via header (rport parameter)

    Without this, the remote SIP proxy may not be able to route
    responses back through the NAT.
    """
    pass


def hole_punching():
    """
    UDP Hole Punching

    For NAT types that require it, the library sends dummy UDP packets
    to open NAT pinholes before media flow begins. This ensures:

    1. NAT creates a mapping for the RTP port
    2. Remote packets can reach us through the NAT
    3. Media flows immediately when call connects (no initial silence)

    Hole punching is automatic and triggered during call setup
    after SDP exchange provides the remote address.
    """
    pass


def keepalive():
    """
    NAT Keepalive

    NAT bindings expire after inactivity (typically 30-120 seconds).
    The library sends periodic STUN binding requests to keep
    NAT pinholes open during long calls or idle periods.

    Configure keepalive interval:
        [sip]
        options_keepalive_interval_secs = 30

    This also serves as gateway health monitoring - failed keepalives
    trigger GatewayHealth events with healthy=false.
    """
    pass


if __name__ == "__main__":
    print("NAT Traversal Configuration Examples")
    print("====================================")
    print()
    print("NAT traversal is configured in config.toml.")
    print("See the docstrings in this file for configuration details.")
    print()
    print("Key settings:")
    print("  [rtp] enable_symmetric_rtp = true   # Learn remote from packets")
    print("  [nat] stun_server = '...'            # Public IP discovery")
    print("  [nat] turn_server = '...'            # Relay for symmetric NAT")
    print("  [sip] contact_nat_rewrite = true     # Fix Contact header")
    print("  [sip] options_keepalive_interval_secs = 30  # Keep NAT alive")
