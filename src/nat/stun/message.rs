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

/// FINGERPRINT attribute type (RFC 5389 Section 15.5)
pub const ATTR_FINGERPRINT: u16 = 0x8028;

/// FINGERPRINT XOR constant (RFC 5389 Section 15.5)
const FINGERPRINT_XOR: u32 = 0x5354_554E;

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
        // Bug #101: STUN message length must be a multiple of 4 bytes
        // (RFC 5389 Section 6: "all STUN attributes are padded to a multiple
        // of 4 bytes"). A non-aligned length indicates this is not a valid
        // STUN message.
        let msg_len = u16::from_be_bytes([data[2], data[3]]);
        if msg_len % 4 != 0 {
            return false;
        }
        // Bug #27: Validate that the buffer is large enough for the claimed message length
        if data.len() < 20 + msg_len as usize {
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

        // Bug #31: Message length must be a multiple of 4 (RFC 5389 Section 6)
        if msg_len % 4 != 0 {
            return Err(StunError::InvalidHeader);
        }

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

        // Parse attributes, tracking FINGERPRINT position if present
        let mut attributes = Vec::new();
        let mut offset = HEADER_SIZE;
        let end = HEADER_SIZE + msg_len;
        let mut fingerprint_value: Option<u32> = None;
        let mut fingerprint_offset: Option<usize> = None;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let attr_start = offset;
            offset += 4;

            // Bug #53: If the attribute's declared length extends beyond the
            // message boundary, return a parse error instead of silently
            // accepting a truncated message.
            if offset + attr_len > end {
                return Err(StunError::TruncatedAttribute);
            }

            // Check for FINGERPRINT attribute (RFC 5389 Section 15.5)
            if attr_type == ATTR_FINGERPRINT {
                if attr_len == 4 {
                    fingerprint_value = Some(u32::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]));
                    fingerprint_offset = Some(attr_start);
                }
                // FINGERPRINT is always last; do not add to parsed attributes
                offset += (attr_len + 3) & !3;
                continue;
            }

            if let Some(attr) = StunAttribute::decode(
                attr_type,
                &data[offset..offset + attr_len],
                &transaction_id,
            ) {
                attributes.push(attr);
            }

            // Advance past attribute value, padded to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }

        // Bug #9: Validate FINGERPRINT if present.
        // Per RFC 5389 Section 15.5, the CRC-32 is computed over the STUN
        // message up to (but not including) the FINGERPRINT attribute, with
        // the message header length field adjusted to point to the end of
        // the FINGERPRINT attribute (i.e. as if FINGERPRINT were the last
        // attribute, and the length includes the FINGERPRINT TLV = 8 bytes).
        if let (Some(fp_val), Some(fp_off)) = (fingerprint_value, fingerprint_offset) {
            // Build a copy of the bytes preceding FINGERPRINT, with the
            // STUN header message-length field adjusted to include the
            // FINGERPRINT attribute (8 bytes: 4 header + 4 value).
            let bytes_before_fp = fp_off; // everything before the FINGERPRINT TLV
            let adjusted_len = (fp_off - HEADER_SIZE + 8) as u16; // attrs before + FP itself
            let mut buf = Vec::with_capacity(bytes_before_fp);
            buf.extend_from_slice(&data[..bytes_before_fp]);
            // Patch the message-length field (bytes 2..4)
            let len_bytes = adjusted_len.to_be_bytes();
            buf[2] = len_bytes[0];
            buf[3] = len_bytes[1];

            let crc = crc32fast::hash(&buf) ^ FINGERPRINT_XOR;
            if crc != fp_val {
                return Err(StunError::FingerprintMismatch);
            }
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
        })
    }

    /// Serialize this message to bytes
    ///
    /// TODO(Bug #102): For strict RFC 5389 compliance, this should append a
    /// FINGERPRINT attribute (CRC-32 XOR'd with 0x5354554E) as the last
    /// attribute. The unmarshal path already validates FINGERPRINT when
    /// present. Omitting it is interoperable with most STUN implementations
    /// since FINGERPRINT is optional, but some strict middleboxes may
    /// require it for reliable STUN-vs-data demultiplexing.
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
                StunAttribute::ChangedAddress(addr)
                | StunAttribute::OtherAddress(addr) => {
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
    /// An attribute's declared length extends beyond the message boundary
    TruncatedAttribute,
    /// FINGERPRINT attribute CRC-32 check failed
    FingerprintMismatch,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunError::TooShort => write!(f, "message too short"),
            StunError::InvalidHeader => {
                write!(f, "invalid STUN header (top 2 bits not 00)")
            }
            StunError::InvalidMagicCookie => write!(f, "invalid magic cookie"),
            StunError::TruncatedAttribute => {
                write!(f, "attribute length extends beyond message boundary")
            }
            StunError::FingerprintMismatch => {
                write!(f, "FINGERPRINT CRC-32 verification failed")
            }
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
        let txn_id: TransactionId =
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
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
        let rtp = [
            0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
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

    // --- Bug #53 tests: truncated attribute must return error ---

    #[test]
    fn test_truncated_attribute_returns_error() {
        // Bug #53: An attribute whose declared length extends beyond the
        // message boundary must produce TruncatedAttribute, not silently
        // succeed with a partial attribute list.
        //
        // Setup: msg_len declares only 12 bytes of attribute payload
        // (must be multiple of 4 per RFC 5389),
        // but the attribute TLV header claims attr_len = 20 (value bytes).
        // After consuming the 4-byte TLV header, offset = 24, attr_len = 20,
        // but end = 20 + 12 = 32, so 24 + 20 = 44 > 32 => truncated.
        let txn_id: TransactionId = [0xDD; 12];
        let attr_type: u16 = 0x8022; // SOFTWARE
        let attr_len: u16 = 20; // claims 20 bytes of value

        // msg_len is smaller than what the attribute needs:
        // 4 (attr header) + 8 (partial value) = 12 (multiple of 4)
        let msg_len: u16 = 12;

        let mut data = Vec::new();
        data.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        data.extend_from_slice(&msg_len.to_be_bytes());
        data.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        data.extend_from_slice(&txn_id);
        // Attribute TLV header
        data.extend_from_slice(&attr_type.to_be_bytes());
        data.extend_from_slice(&attr_len.to_be_bytes());
        // Only 8 bytes of value (partial, not the claimed 20)
        data.extend_from_slice(b"short!XY");

        // Total data: 20 + 12 = 32 bytes (matches HEADER_SIZE + msg_len)
        // so the outer length check passes.
        assert_eq!(data.len(), HEADER_SIZE + msg_len as usize);

        let result = StunMessage::unmarshal(&data);
        assert_eq!(result.unwrap_err(), StunError::TruncatedAttribute);
    }

    #[test]
    fn test_truncated_second_attribute_returns_error() {
        // A valid first attribute followed by a truncated second attribute
        // must return TruncatedAttribute.
        //
        // Setup: msg_len covers the first attribute plus the second
        // attribute's TLV header, but NOT the second attribute's claimed
        // value length.
        let txn_id: TransactionId = [0xEE; 12];

        // First attribute: SOFTWARE "ok" (2 bytes, padded to 4)
        let attr1_type: u16 = 0x8022;
        let attr1_value = b"ok";
        let attr1_padded_total = 4 + 4; // TLV header (4) + padded value (4)

        // Second attribute: SOFTWARE, claims 50 bytes of value
        let attr2_type: u16 = 0x8022;
        let attr2_claimed_len: u16 = 50;

        // msg_len covers first attr (8) + second attr header (4) + only
        // 4 bytes of the second attr's value (not the full 50).
        // Total msg_len = 16, which is a multiple of 4 per RFC 5389.
        let msg_len: u16 = (attr1_padded_total + 4 + 4) as u16; // = 16

        let mut data = Vec::new();
        data.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        data.extend_from_slice(&msg_len.to_be_bytes());
        data.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        data.extend_from_slice(&txn_id);

        // First attribute (valid)
        data.extend_from_slice(&attr1_type.to_be_bytes());
        data.extend_from_slice(&(attr1_value.len() as u16).to_be_bytes());
        data.extend_from_slice(attr1_value);
        data.extend_from_slice(&[0x00, 0x00]); // padding to 4 bytes

        // Second attribute header
        data.extend_from_slice(&attr2_type.to_be_bytes());
        data.extend_from_slice(&attr2_claimed_len.to_be_bytes());
        // Only 4 bytes of value (not the claimed 50)
        data.extend_from_slice(b"hiXY");

        // Total data = HEADER_SIZE + msg_len = 20 + 16 = 36
        assert_eq!(data.len(), HEADER_SIZE + msg_len as usize);

        // After parsing first attr, offset advances to 32 (header 20 +
        // first attr padded 8 + second attr header 4).
        // attr_len = 50, end = 36, so 32 + 50 = 82 > 36 => TruncatedAttribute
        let result = StunMessage::unmarshal(&data);
        assert_eq!(result.unwrap_err(), StunError::TruncatedAttribute);
    }

    #[test]
    fn test_valid_attribute_still_parses() {
        // Ensure the fix doesn't break valid messages.
        let txn_id: TransactionId = [0xFF; 12];
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let msg = StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::XorMappedAddress(addr)],
        };
        let data = msg.marshal();
        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.xor_mapped_address(), Some(addr));
    }

    #[test]
    fn test_truncated_buffer_returns_too_short() {
        // msg_len says 12 bytes of attributes, but buffer only has 6
        let txn_id: TransactionId = [0xCC; 12];
        let attr_type: u16 = 0x8022; // SOFTWARE
        let attr_value = b"hi"; // 2 bytes

        let msg_len: u16 = 12; // claim 12 bytes

        let mut data = Vec::new();
        data.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        data.extend_from_slice(&msg_len.to_be_bytes());
        data.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        data.extend_from_slice(&txn_id);
        data.extend_from_slice(&attr_type.to_be_bytes());
        data.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        data.extend_from_slice(attr_value);
        // Total: 20 + 6 = 26 bytes, but msg_len claims 12 so end = 32

        // HEADER_SIZE + msg_len > data.len() -> TooShort
        let result = StunMessage::unmarshal(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StunError::TooShort);
    }

    // --- Bug #9 tests: FINGERPRINT validation ---

    #[test]
    fn test_fingerprint_valid() {
        // Build a STUN message, then manually append a correct FINGERPRINT.
        let txn_id: TransactionId = [0x11; 12];
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let msg = StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::XorMappedAddress(addr)],
        };
        let mut data = msg.marshal();

        // Compute the FINGERPRINT value.
        // Per RFC 5389: adjust message length to include FINGERPRINT (8 bytes),
        // compute CRC-32 over the adjusted message, XOR with 0x5354554E.
        let current_attr_len = data.len() - HEADER_SIZE;
        let new_attr_len = (current_attr_len + 8) as u16; // +8 for FINGERPRINT TLV
        let len_bytes = new_attr_len.to_be_bytes();
        let mut adjusted = data.clone();
        adjusted[2] = len_bytes[0];
        adjusted[3] = len_bytes[1];
        let crc = crc32fast::hash(&adjusted) ^ FINGERPRINT_XOR;

        // Append FINGERPRINT attribute: type 0x8028, length 4, value = crc
        data.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&crc.to_be_bytes());
        // Also update the message length in the header to include FINGERPRINT
        data[2] = len_bytes[0];
        data[3] = len_bytes[1];

        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert!(parsed.is_success());
        assert_eq!(parsed.xor_mapped_address(), Some(addr));
    }

    #[test]
    fn test_fingerprint_invalid_returns_error() {
        // Build a STUN message with a bogus FINGERPRINT value.
        let txn_id: TransactionId = [0x22; 12];
        let addr: SocketAddr = "192.168.1.1:3478".parse().unwrap();
        let msg = StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::XorMappedAddress(addr)],
        };
        let mut data = msg.marshal();

        let current_attr_len = data.len() - HEADER_SIZE;
        let new_attr_len = (current_attr_len + 8) as u16;
        let len_bytes = new_attr_len.to_be_bytes();

        // Append FINGERPRINT with a deliberately wrong CRC value
        data.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // bogus
        data[2] = len_bytes[0];
        data[3] = len_bytes[1];

        let result = StunMessage::unmarshal(&data);
        assert_eq!(result.unwrap_err(), StunError::FingerprintMismatch);
    }

    #[test]
    fn test_fingerprint_absent_still_parses() {
        // Messages without FINGERPRINT should still parse normally.
        let txn_id: TransactionId = [0x33; 12];
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let msg = StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::XorMappedAddress(addr)],
        };
        let data = msg.marshal();
        let parsed = StunMessage::unmarshal(&data).unwrap();
        assert_eq!(parsed.xor_mapped_address(), Some(addr));
    }
}
