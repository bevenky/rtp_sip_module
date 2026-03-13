//! TURN message types and attribute extensions (RFC 5766)
//!
//! Extends STUN with TURN-specific methods and attributes.

// TURN methods (added to STUN method space)
pub const ALLOCATE_REQUEST: u16 = 0x0003;
pub const ALLOCATE_SUCCESS: u16 = 0x0103;
pub const ALLOCATE_ERROR: u16 = 0x0113;
pub const REFRESH_REQUEST: u16 = 0x0004;
pub const REFRESH_SUCCESS: u16 = 0x0104;
pub const REFRESH_ERROR: u16 = 0x0114;
pub const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
pub const CREATE_PERMISSION_ERROR: u16 = 0x0118;
pub const CHANNEL_BIND_REQUEST: u16 = 0x0009;
pub const CHANNEL_BIND_SUCCESS: u16 = 0x0109;
pub const CHANNEL_BIND_ERROR: u16 = 0x0119;
pub const SEND_INDICATION: u16 = 0x0016;
pub const DATA_INDICATION: u16 = 0x0017;

// TURN attribute types
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

// STUN auth attributes used by TURN
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;

/// TURN ChannelData header size
pub const CHANNEL_DATA_HEADER_SIZE: usize = 4;

/// Valid TURN channel number range (RFC 5766 Section 11)
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x7FFE;

/// Default TURN allocation lifetime in seconds
pub const DEFAULT_LIFETIME: u32 = 600;

/// Default permission lifetime in seconds
pub const PERMISSION_LIFETIME: u32 = 300;

/// Default channel binding lifetime in seconds
pub const CHANNEL_BIND_LIFETIME: u32 = 600;

/// Check if a channel number is valid
pub fn is_valid_channel(channel: u16) -> bool {
    (CHANNEL_MIN..=CHANNEL_MAX).contains(&channel)
}

/// Parse a TURN ChannelData message.
/// Returns (channel_number, data_slice) or None if invalid.
pub fn parse_channel_data(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < CHANNEL_DATA_HEADER_SIZE {
        return None;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    if !is_valid_channel(channel) {
        return None;
    }
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < CHANNEL_DATA_HEADER_SIZE + length {
        return None;
    }
    Some((channel, &data[CHANNEL_DATA_HEADER_SIZE..CHANNEL_DATA_HEADER_SIZE + length]))
}

/// Build a TURN ChannelData message.
///
/// Note (Bug #60): RFC 5766 §11.5 specifies that padding to a 4-byte boundary
/// is only required for connection-oriented transports (TCP/TLS). For UDP
/// transport, the padding bytes are unnecessary and may confuse strict servers.
/// Currently this function always pads; callers using UDP transport should be
/// aware that the extra padding bytes are included but are not required by the
/// RFC for UDP.
pub fn build_channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHANNEL_DATA_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&channel.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    // Pad to 4-byte boundary (required for TCP/TLS per RFC 5766 §11.5,
    // not strictly needed for UDP but kept for consistency)
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_channel_range() {
        assert!(is_valid_channel(0x4000));
        assert!(is_valid_channel(0x7FFE));
        assert!(is_valid_channel(0x5000));
        assert!(!is_valid_channel(0x3FFF));
        assert!(!is_valid_channel(0x7FFF));
        assert!(!is_valid_channel(0x8000));
        assert!(!is_valid_channel(0x0000));
    }

    #[test]
    fn test_channel_data_roundtrip() {
        let payload = b"hello RTP";
        let data = build_channel_data(0x4001, payload);

        assert_eq!(data[0], 0x40);
        assert_eq!(data[1], 0x01);

        let (channel, parsed_payload) = parse_channel_data(&data).unwrap();
        assert_eq!(channel, 0x4001);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_channel_data_too_short() {
        assert!(parse_channel_data(&[0x40, 0x00]).is_none());
        assert!(parse_channel_data(&[]).is_none());
    }

    #[test]
    fn test_channel_data_invalid_channel() {
        let data = [0x00, 0x01, 0x00, 0x01, 0x42]; // channel 0x0001 is not valid TURN
        assert!(parse_channel_data(&data).is_none());
    }

    #[test]
    fn test_channel_data_truncated_payload() {
        // Header says 10 bytes of data but only 4 available
        let data = [0x40, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04];
        assert!(parse_channel_data(&data).is_none());
    }
}
