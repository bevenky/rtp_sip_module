//! STUN message codec (RFC 5389)
//!
//! Sans-IO: pure serialization/deserialization with no network dependencies.
//!
//! STUN message format (20-byte header + attributes):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use super::attributes::StunAttribute;

/// STUN magic cookie (RFC 5389 Section 6)
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN header size
pub const HEADER_SIZE: usize = 20;

// Message types (RFC 5389 Section 6, method = Binding, class encoded in bits)
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_SUCCESS: u16 = 0x0101;
pub const BINDING_ERROR: u16 = 0x0111;
pub const BINDING_INDICATION: u16 = 0x0011;

/// 96-bit transaction ID
pub type TransactionId = [u8; 12];

/// A STUN message
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub msg_type: u16,
    pub transaction_id: TransactionId,
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    /// Create a new Binding Request with a random transaction ID
    pub fn new_binding_request() -> Self {
        let mut txn_id = [0u8; 12];
        for byte in txn_id.iter_mut() {
            *byte = rand::random();
        }
        Self {
            msg_type: BINDING_REQUEST,
            transaction_id: txn_id,
            attributes: Vec::new(),
        }
    }

    /// Create a Binding Indication (for keepalives — no response expected)
    pub fn new_binding_indication() -> Self {
        let mut txn_id = [0u8; 12];
        for byte in txn_id.iter_mut() {
            *byte = rand::random();
        }
        Self {
            msg_type: BINDING_INDICATION,
            transaction_id: txn_id,
            attributes: Vec::new(),
        }
    }

    /// Check if this data starts with a STUN message (magic cookie check)
    pub fn is_stun(data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }
        // Top 2 bits must be 00
        if data[0] & 0xC0 != 0 {
            return false;
        }
        // Magic cookie at bytes 4-7
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        cookie == MAGIC_COOKIE
    }

    /// Parse a STUN message from bytes
    pub fn unmarshal(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < HEADER_SIZE {
            return Err(StunError::TooShort);
        }

        // Check top 2 bits are 00
        if data[0] & 0xC0 != 0 {
            return Err(StunError::InvalidHeader);
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Verify magic cookie
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie);
        }

        // Transaction ID (12 bytes)
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Message length must not exceed available data
        if HEADER_SIZE + msg_len > data.len() {
            return Err(StunError::TooShort);
        }

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = HEADER_SIZE;
        let end = HEADER_SIZE + msg_len;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                break;
            }

            if let Some(attr) =
                StunAttribute::decode(attr_type, &data[offset..offset + attr_len], &transaction_id)
            {
                attributes.push(attr);
            }

            // Advance past attribute value, padded to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
        })
    }

    /// Serialize this message to bytes
    pub fn marshal(&self) -> Vec<u8> {
        // Encode all attributes first to compute total length
        let mut attr_bytes = Vec::new();
        for attr in &self.attributes {
            attr_bytes.extend_from_slice(&attr.encode(&self.transaction_id));
        }

        let mut buf = Vec::with_capacity(HEADER_SIZE + attr_bytes.len());

        // Header
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&self.transaction_id);

        // Attributes
        buf.extend_from_slice(&attr_bytes);

        buf
    }

    /// Add an attribute
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        self.attributes.push(attr);
    }

    /// Get the first XOR-MAPPED-ADDRESS from the response
    pub fn xor_mapped_address(&self) -> Option<std::net::SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::XorMappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the first MAPPED-ADDRESS from the response
    pub fn mapped_address(&self) -> Option<std::net::SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::MappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the reflexive address (prefers XOR-MAPPED-ADDRESS, falls back to MAPPED-ADDRESS)
    pub fn reflexive_address(&self) -> Option<std::net::SocketAddr> {
        self.xor_mapped_address().or_else(|| self.mapped_address())
    }

    /// Get the CHANGED-ADDRESS or OTHER-ADDRESS
    pub fn changed_address(&self) -> Option<std::net::SocketAddr> {
        for attr in &self.attributes {
            match attr {
                StunAttribute::ChangedAddress(addr) | StunAttribute::OtherAddress(addr) => {
                    return Some(*addr);
                }
                _ => {}
            }
        }
        None
    }

    /// Get the ERROR-CODE
    pub fn error_code(&self) -> Option<u16> {
        for attr in &self.attributes {
            if let StunAttribute::ErrorCode { code, .. } = attr {
                return Some(*code);
            }
        }
        None
    }

    /// Check if this is a response to a given transaction ID
    pub fn is_response_to(&self, txn_id: &TransactionId) -> bool {
        self.transaction_id == *txn_id
    }

    /// Check if this is a success response
    pub fn is_success(&self) -> bool {
        // Success responses have class = 0b10 (bits 4,8 of msg_type)
        self.msg_type & 0x0110 == 0x0100
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        self.msg_type & 0x0110 == 0x0110
    }

    /// Check if this is a request
    pub fn is_request(&self) -> bool {
        self.msg_type & 0x0110 == 0x0000
    }

    /// Check if this is an indication
    pub fn is_indication(&self) -> bool {
        self.msg_type & 0x0110 == 0x0010
    }
}

/// STUN-specific errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    TooShort,
    InvalidHeader,
    InvalidMagicCookie,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunError::TooShort => write!(f, "message too short"),
            StunError::InvalidHeader => write!(f, "invalid STUN header (top 2 bits not 00)"),
            StunError::InvalidMagicCookie => write!(f, "invalid magic cookie"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_binding_request_roundtrip() {
        let msg = StunMessage::new_binding_request();
        let data = msg.marshal();

        assert!(StunMessage::is_stun(&data));
        assert_eq!(data.len(), HEADER_SIZE); // no attributes

        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.msg_type, BINDING_REQUEST);
        assert_eq!(parsed.transaction_id, msg.transaction_id);
        assert!(parsed.is_request());
        assert!(!parsed.is_success());
    }

    #[test]
    fn test_binding_request_with_change_request() {
        let mut msg = StunMessage::new_binding_request();
        msg.add_attribute(StunAttribute::ChangeRequest {
            change_ip: true,
            change_port: true,
        });
        let data = msg.marshal();

        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.attributes.len(), 1);
        assert_eq!(
            parsed.attributes[0],
            StunAttribute::ChangeRequest {
                change_ip: true,
                change_port: true,
            }
        );
    }

    #[test]
    fn test_binding_success_with_xor_mapped() {
        let txn_id: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();

        let msg = StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::XorMappedAddress(addr)],
        };
        let data = msg.marshal();

        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert!(parsed.is_success());
        assert_eq!(parsed.xor_mapped_address(), Some(addr));
        assert_eq!(parsed.reflexive_address(), Some(addr));
    }

    #[test]
    fn test_is_stun_detection() {
        // Valid STUN
        let msg = StunMessage::new_binding_request();
        let data = msg.marshal();
        assert!(StunMessage::is_stun(&data));

        // RTP packet (version 2 = top 2 bits are 10)
        let rtp = [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!StunMessage::is_stun(&rtp));

        // Too short
        assert!(!StunMessage::is_stun(&[0, 1, 2]));
    }

    #[test]
    fn test_error_response() {
        let txn_id: TransactionId = [0; 12];
        let msg = StunMessage {
            msg_type: BINDING_ERROR,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::ErrorCode {
                code: 420,
                reason: "Unknown Attribute".to_string(),
            }],
        };
        let data = msg.marshal();

        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert!(parsed.is_error());
        assert_eq!(parsed.error_code(), Some(420));
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut data = StunMessage::new_binding_request().marshal();
        // Corrupt magic cookie
        data[4] = 0xFF;
        assert!(!StunMessage::is_stun(&data));
        assert_eq!(
            StunMessage::unmarshal(&data).unwrap_err(),
            StunError::InvalidMagicCookie
        );
    }

    #[test]
    fn test_message_class_detection() {
        assert!(
            StunMessage {
                msg_type: BINDING_REQUEST,
                transaction_id: [0; 12],
                attributes: vec![],
            }
            .is_request()
        );

        assert!(
            StunMessage {
                msg_type: BINDING_SUCCESS,
                transaction_id: [0; 12],
                attributes: vec![],
            }
            .is_success()
        );

        assert!(
            StunMessage {
                msg_type: BINDING_ERROR,
                transaction_id: [0; 12],
                attributes: vec![],
            }
            .is_error()
        );

        assert!(
            StunMessage {
                msg_type: BINDING_INDICATION,
                transaction_id: [0; 12],
                attributes: vec![],
            }
            .is_indication()
        );
    }

    #[test]
    fn test_multiple_attributes() {
        let addr1: SocketAddr = "192.168.1.1:5060".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        let txn_id: TransactionId = [0xAA; 12];

        let msg = StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![
                StunAttribute::XorMappedAddress(addr1),
                StunAttribute::ChangedAddress(addr2),
                StunAttribute::Software("test-server".to_string()),
            ],
        };
        let data = msg.marshal();

        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.attributes.len(), 3);
        assert_eq!(parsed.xor_mapped_address(), Some(addr1));
        assert_eq!(parsed.changed_address(), Some(addr2));
    }
}
