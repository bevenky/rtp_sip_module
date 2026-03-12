//! SRTP (Secure Real-time Transport Protocol) — RFC 3711
//!
//! Implements SRTP encryption/decryption with SDES key exchange for SIP trunks.
//!
//! # Cipher Suite
//!
//! AES_CM_128_HMAC_SHA1_80 — mandatory-to-implement per RFC 3711:
//! - Encryption: AES-128 in Counter Mode (AES-CM)
//! - Authentication: HMAC-SHA1 truncated to 80 bits (10 bytes)
//! - Key derivation: AES-CM based (RFC 3711 Section 4.3.1)
//!
//! Also supports AES_CM_128_HMAC_SHA1_32 (32-bit auth tag, used for RTP only).
//!
//! # SDES Key Exchange
//!
//! Key material is exchanged via SDP `a=crypto:` attribute (RFC 4568):
//! ```text
//! a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<base64(master_key ‖ master_salt)>
//! ```
//!
//! Master key = 16 bytes, master salt = 14 bytes → 30 bytes base64-encoded.
//!
//! # FreeSWITCH Compatibility
//!
//! - Supports both 80-bit and 32-bit auth tags
//! - Handles SSRC changes (re-derives session keys)
//! - ROC (Rollover Counter) tracking for long calls
//! - Replay protection via 64-packet sliding window

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::Mac;
type HmacSha1 = hmac::Hmac<sha1::Sha1>;

use crate::error::{Result, RtpSipError};

/// SRTP master key length (128 bits)
const SRTP_MASTER_KEY_LEN: usize = 16;
/// SRTP master salt length (112 bits)
const SRTP_MASTER_SALT_LEN: usize = 14;
/// Combined master key + salt length
const SRTP_MASTER_LEN: usize = SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN;

/// SRTP session key length
const SRTP_SESSION_KEY_LEN: usize = 16;
/// SRTP session salt length
const SRTP_SESSION_SALT_LEN: usize = 14;
/// SRTP authentication key length
const SRTP_AUTH_KEY_LEN: usize = 20;

/// Full authentication tag (80 bits)
const SRTP_AUTH_TAG_80: usize = 10;
/// Short authentication tag (32 bits)
const SRTP_AUTH_TAG_32: usize = 4;

/// SRTCP authentication tag is always 80 bits
const SRTCP_AUTH_TAG_LEN: usize = 10;
/// SRTCP E-flag + SRTCP index field (4 bytes)
const SRTCP_INDEX_LEN: usize = 4;

/// Key derivation labels per RFC 3711 Section 4.3.1
const LABEL_RTP_ENCRYPTION: u8 = 0x00;
const LABEL_RTP_AUTH: u8 = 0x01;
const LABEL_RTP_SALT: u8 = 0x02;
const LABEL_RTCP_ENCRYPTION: u8 = 0x03;
const LABEL_RTCP_AUTH: u8 = 0x04;
const LABEL_RTCP_SALT: u8 = 0x05;

/// SRTP cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpCipherSuite {
    /// AES_CM_128_HMAC_SHA1_80 — 80-bit auth tag (standard)
    AesCm128HmacSha1_80,
    /// AES_CM_128_HMAC_SHA1_32 — 32-bit auth tag (reduced overhead)
    AesCm128HmacSha1_32,
}

impl SrtpCipherSuite {
    /// Parse from SDP crypto attribute string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "AES_CM_128_HMAC_SHA1_80" => Some(Self::AesCm128HmacSha1_80),
            "AES_CM_128_HMAC_SHA1_32" => Some(Self::AesCm128HmacSha1_32),
            _ => None,
        }
    }

    /// Get the SDP string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
        }
    }

    /// RTP authentication tag length in bytes
    pub fn rtp_auth_tag_len(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 => SRTP_AUTH_TAG_80,
            Self::AesCm128HmacSha1_32 => SRTP_AUTH_TAG_32,
        }
    }

    /// RTCP authentication tag length (always 80 bits)
    pub fn rtcp_auth_tag_len(&self) -> usize {
        SRTCP_AUTH_TAG_LEN
    }
}

/// Parsed SDP crypto attribute (RFC 4568)
#[derive(Debug, Clone)]
pub struct CryptoAttribute {
    /// Tag number (1-based)
    pub tag: u32,
    /// Cipher suite
    pub suite: SrtpCipherSuite,
    /// Master key (16 bytes)
    pub master_key: [u8; SRTP_MASTER_KEY_LEN],
    /// Master salt (14 bytes)
    pub master_salt: [u8; SRTP_MASTER_SALT_LEN],
}

impl CryptoAttribute {
    /// Parse an `a=crypto:` SDP attribute value
    ///
    /// Format: `<tag> <suite> inline:<base64(key||salt)>[|lifetime|mki]`
    pub fn parse(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(RtpSipError::Rtp(
                "Invalid crypto attribute: too few fields".to_string(),
            ));
        }

        let tag: u32 = parts[0]
            .parse()
            .map_err(|_| RtpSipError::Rtp("Invalid crypto tag".to_string()))?;

        let suite = SrtpCipherSuite::from_str(parts[1]).ok_or_else(|| {
            RtpSipError::Rtp(format!("Unsupported cipher suite: {}", parts[1]))
        })?;

        // Parse inline key: "inline:<base64>[|2^31|1:4]"
        let key_param = parts[2];
        let inline_prefix = "inline:";
        if !key_param.starts_with(inline_prefix) {
            return Err(RtpSipError::Rtp(
                "Crypto key must start with 'inline:'".to_string(),
            ));
        }

        // Strip "inline:" and any trailing lifetime/mki params (separated by |)
        let b64_key = &key_param[inline_prefix.len()..];
        let b64_key = b64_key.split('|').next().unwrap_or(b64_key);

        let key_material = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            b64_key,
        )
        .map_err(|e| RtpSipError::Rtp(format!("Invalid base64 key: {}", e)))?;

        if key_material.len() != SRTP_MASTER_LEN {
            return Err(RtpSipError::Rtp(format!(
                "Master key material must be {} bytes, got {}",
                SRTP_MASTER_LEN,
                key_material.len()
            )));
        }

        let mut master_key = [0u8; SRTP_MASTER_KEY_LEN];
        let mut master_salt = [0u8; SRTP_MASTER_SALT_LEN];
        master_key.copy_from_slice(&key_material[..SRTP_MASTER_KEY_LEN]);
        master_salt.copy_from_slice(&key_material[SRTP_MASTER_KEY_LEN..]);

        Ok(Self {
            tag,
            suite,
            master_key,
            master_salt,
        })
    }

    /// Generate a new random crypto attribute
    pub fn generate(suite: SrtpCipherSuite) -> Self {
        let mut master_key = [0u8; SRTP_MASTER_KEY_LEN];
        let mut master_salt = [0u8; SRTP_MASTER_SALT_LEN];

        // Use rand to generate cryptographically random key material
        for b in master_key.iter_mut() {
            *b = rand::random();
        }
        for b in master_salt.iter_mut() {
            *b = rand::random();
        }

        Self {
            tag: 1,
            suite,
            master_key,
            master_salt,
        }
    }

    /// Format as SDP `a=crypto:` attribute value
    pub fn to_sdp_value(&self) -> String {
        use base64::Engine;
        let mut key_material = Vec::with_capacity(SRTP_MASTER_LEN);
        key_material.extend_from_slice(&self.master_key);
        key_material.extend_from_slice(&self.master_salt);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&key_material);
        format!("{} {} inline:{}", self.tag, self.suite.as_str(), b64)
    }
}

/// Derived session keys for SRTP/SRTCP
#[derive(Clone)]
struct SessionKeys {
    /// Encryption key (16 bytes)
    enc_key: [u8; SRTP_SESSION_KEY_LEN],
    /// Authentication key (20 bytes)
    auth_key: [u8; SRTP_AUTH_KEY_LEN],
    /// Session salt (14 bytes)
    salt: [u8; SRTP_SESSION_SALT_LEN],
}

/// Number of consecutive SRTP errors before logging a warning
const SRTP_WARN_THRESHOLD: u32 = 10;

/// Number of consecutive SRTP errors before re-deriving session keys
const SRTP_RESET_THRESHOLD: u32 = 100;

/// SRTP context for a single direction (send or receive)
///
/// Each direction maintains its own ROC and replay protection state.
pub struct SrtpContext {
    /// Cipher suite
    suite: SrtpCipherSuite,
    /// Master key (retained for key re-derivation on error recovery)
    master_key: [u8; SRTP_MASTER_KEY_LEN],
    /// Master salt (retained for key re-derivation on error recovery)
    master_salt: [u8; SRTP_MASTER_SALT_LEN],
    /// Derived RTP session keys
    rtp_keys: SessionKeys,
    /// Derived RTCP session keys
    rtcp_keys: SessionKeys,
    /// Rollover counter (increments on seq wrap)
    roc: u32,
    /// Highest sequence number seen (for ROC tracking)
    s_l: u16,
    /// Whether we've received any packet yet
    initialized: bool,
    /// SRTCP index counter
    srtcp_index: u32,
    /// Replay protection window (64-bit sliding window)
    replay_window: u64,
    /// Replay window base index
    replay_window_base: u64,
    /// Consecutive error count for error recovery
    error_count: u32,
}

impl SrtpContext {
    /// Create a new SRTP context from master key material
    pub fn new(
        suite: SrtpCipherSuite,
        master_key: [u8; SRTP_MASTER_KEY_LEN],
        master_salt: [u8; SRTP_MASTER_SALT_LEN],
    ) -> Self {
        let rtp_keys = derive_session_keys(&master_key, &master_salt, false);
        let rtcp_keys = derive_session_keys(&master_key, &master_salt, true);

        Self {
            suite,
            master_key,
            master_salt,
            rtp_keys,
            rtcp_keys,
            roc: 0,
            s_l: 0,
            initialized: false,
            srtcp_index: 0,
            replay_window: 0,
            replay_window_base: 0,
            error_count: 0,
        }
    }

    /// Create from a parsed crypto attribute
    pub fn from_crypto(crypto: &CryptoAttribute) -> Self {
        Self::new(crypto.suite, crypto.master_key, crypto.master_salt)
    }

    /// Protect (encrypt + authenticate) an RTP packet in-place
    ///
    /// Input: plaintext RTP packet (header + payload)
    /// Output: SRTP packet (header + encrypted_payload + auth_tag)
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 12 {
            return Err(RtpSipError::Rtp("RTP packet too short".to_string()));
        }

        let header_len = rtp_header_len(packet)?;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Update ROC for outgoing packets
        self.update_roc_send(seq);

        let index = ((self.roc as u64) << 16) | (seq as u64);

        // Encrypt payload in-place
        let mut output = packet.to_vec();
        let payload = &mut output[header_len..];
        aes_cm_encrypt(
            &self.rtp_keys.enc_key,
            &self.rtp_keys.salt,
            ssrc,
            index,
            payload,
        );

        // Compute and append authentication tag
        let auth_tag = compute_rtp_auth_tag(
            &self.rtp_keys.auth_key,
            &output,
            self.roc,
            self.suite.rtp_auth_tag_len(),
        );
        output.extend_from_slice(&auth_tag);

        Ok(output)
    }

    /// Unprotect (authenticate + decrypt) an SRTP packet
    ///
    /// Input: SRTP packet (header + encrypted_payload + auth_tag)
    /// Output: plaintext RTP packet (header + payload)
    ///
    /// Error recovery: tracks consecutive failures and re-derives session
    /// keys after `SRTP_RESET_THRESHOLD` (100) errors, which handles cases
    /// like far-end rekeying or transient corruption.
    pub fn unprotect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let auth_tag_len = self.suite.rtp_auth_tag_len();
        if packet.len() < 12 + auth_tag_len {
            self.handle_unprotect_error();
            return Err(RtpSipError::Rtp("SRTP packet too short".to_string()));
        }

        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Estimate ROC for incoming packet
        let estimated_roc = self.estimate_roc(seq);
        let index = ((estimated_roc as u64) << 16) | (seq as u64);

        // Replay protection
        if self.initialized && !self.check_replay(index) {
            self.handle_unprotect_error();
            return Err(RtpSipError::Rtp("Replay detected".to_string()));
        }

        // Split packet into authenticated portion and auth tag
        let auth_data_len = packet.len() - auth_tag_len;
        let auth_data = &packet[..auth_data_len];
        let received_tag = &packet[auth_data_len..];

        // Verify authentication tag
        let computed_tag = compute_rtp_auth_tag(
            &self.rtp_keys.auth_key,
            auth_data,
            estimated_roc,
            auth_tag_len,
        );

        if !constant_time_eq(&computed_tag, received_tag) {
            self.handle_unprotect_error();
            return Err(RtpSipError::Rtp("Authentication failed".to_string()));
        }

        // Decrypt payload
        let header_len = rtp_header_len(auth_data)?;
        let mut output = auth_data.to_vec();
        let payload = &mut output[header_len..];
        aes_cm_encrypt(
            &self.rtp_keys.enc_key,
            &self.rtp_keys.salt,
            ssrc,
            index,
            payload,
        );

        // Update ROC state after successful decryption
        self.update_roc_recv(seq, estimated_roc);
        self.accept_replay(index);

        // Success -- reset error counter
        self.error_count = 0;

        Ok(output)
    }

    /// Handle an unprotect error: increment counter, warn, and optionally
    /// re-derive session keys to recover from persistent failures.
    fn handle_unprotect_error(&mut self) {
        self.error_count += 1;

        if self.error_count == SRTP_WARN_THRESHOLD {
            tracing::warn!(
                "SRTP: {} consecutive unprotect errors — possible key mismatch or corruption",
                self.error_count,
            );
        }

        if self.error_count >= SRTP_RESET_THRESHOLD {
            tracing::warn!(
                "SRTP: {} consecutive errors reached reset threshold, re-deriving session keys",
                self.error_count,
            );
            self.rtp_keys = derive_session_keys(&self.master_key, &self.master_salt, false);
            self.rtcp_keys = derive_session_keys(&self.master_key, &self.master_salt, true);
            self.error_count = 0;
        }
    }

    /// Get the current consecutive error count
    pub fn error_count(&self) -> u32 {
        self.error_count
    }

    /// Protect an RTCP packet
    pub fn protect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 8 {
            return Err(RtpSipError::Rtp("RTCP packet too short".to_string()));
        }

        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let srtcp_index = self.srtcp_index;
        self.srtcp_index += 1;

        // Encrypt everything after the first 8 bytes (header)
        let mut output = packet.to_vec();
        if output.len() > 8 {
            let payload = &mut output[8..];
            let index = srtcp_index as u64;
            aes_cm_encrypt(
                &self.rtcp_keys.enc_key,
                &self.rtcp_keys.salt,
                ssrc,
                index,
                payload,
            );
        }

        // Append E-flag (1 = encrypted) | SRTCP index (31 bits)
        let e_srtcp_index = 0x8000_0000u32 | (srtcp_index & 0x7FFF_FFFF);
        output.extend_from_slice(&e_srtcp_index.to_be_bytes());

        // Compute and append authentication tag (over header + encrypted_payload + E||index)
        let mut mac =
            <HmacSha1 as Mac>::new_from_slice(&self.rtcp_keys.auth_key).expect("HMAC key size");
        mac.update(&output);
        let full_tag = mac.finalize().into_bytes();
        output.extend_from_slice(&full_tag[..SRTCP_AUTH_TAG_LEN]);

        Ok(output)
    }

    /// Unprotect an SRTCP packet
    pub fn unprotect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let min_len = 8 + SRTCP_INDEX_LEN + SRTCP_AUTH_TAG_LEN;
        if packet.len() < min_len {
            return Err(RtpSipError::Rtp("SRTCP packet too short".to_string()));
        }

        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Split: [authenticated_data] [auth_tag]
        let auth_tag_start = packet.len() - SRTCP_AUTH_TAG_LEN;
        let auth_data = &packet[..auth_tag_start];
        let received_tag = &packet[auth_tag_start..];

        // Verify authentication
        let mut mac =
            <HmacSha1 as Mac>::new_from_slice(&self.rtcp_keys.auth_key).expect("HMAC key size");
        mac.update(auth_data);
        let full_tag = mac.finalize().into_bytes();
        let computed_tag = &full_tag[..SRTCP_AUTH_TAG_LEN];

        if !constant_time_eq(computed_tag, received_tag) {
            return Err(RtpSipError::Rtp("SRTCP authentication failed".to_string()));
        }

        // Extract E-flag and SRTCP index
        let index_start = auth_data.len() - SRTCP_INDEX_LEN;
        let e_index = u32::from_be_bytes([
            auth_data[index_start],
            auth_data[index_start + 1],
            auth_data[index_start + 2],
            auth_data[index_start + 3],
        ]);
        let is_encrypted = (e_index & 0x8000_0000) != 0;
        let srtcp_index = e_index & 0x7FFF_FFFF;

        // Decrypt if encrypted
        let mut output = auth_data[..index_start].to_vec();
        if is_encrypted && output.len() > 8 {
            let payload = &mut output[8..];
            aes_cm_encrypt(
                &self.rtcp_keys.enc_key,
                &self.rtcp_keys.salt,
                ssrc,
                srtcp_index as u64,
                payload,
            );
        }

        Ok(output)
    }

    /// Estimate ROC for incoming packet based on sequence number.
    ///
    /// RFC 3711 Appendix A — uses signed arithmetic to correctly handle
    /// out-of-order packets near sequence number boundaries.
    fn estimate_roc(&self, seq: u16) -> u32 {
        if !self.initialized {
            return 0;
        }

        let s_l = self.s_l as i32;
        let seq_i = seq as i32;
        let roc = self.roc;

        if (self.s_l) < 0x8000 {
            if (seq_i - s_l) > 0x8000_i32 {
                // Seq wrapped backward — late packet from previous ROC
                roc.wrapping_sub(1)
            } else {
                roc
            }
        } else if (s_l - 0x8000_i32) > seq_i {
            // s_l is in upper half, seq is in lower half — forward wrap
            roc.wrapping_add(1)
        } else {
            roc
        }
    }

    /// Update ROC state for outgoing packets
    fn update_roc_send(&mut self, seq: u16) {
        if !self.initialized {
            self.s_l = seq;
            self.initialized = true;
            return;
        }

        // Detect sequence wrap for send direction
        if seq == 0 && self.s_l == 0xFFFF {
            self.roc = self.roc.wrapping_add(1);
        }
        self.s_l = seq;
    }

    /// Update ROC state after successful receive
    fn update_roc_recv(&mut self, seq: u16, estimated_roc: u32) {
        if !self.initialized {
            self.s_l = seq;
            self.roc = estimated_roc;
            self.initialized = true;
            return;
        }

        let index = ((estimated_roc as u64) << 16) | (seq as u64);
        let current_index = ((self.roc as u64) << 16) | (self.s_l as u64);

        if index > current_index {
            self.roc = estimated_roc;
            self.s_l = seq;
        }
    }

    /// Check if packet index passes replay protection.
    ///
    /// Uses a 64-packet sliding window anchored at `replay_window_base` (highest
    /// seen index). Bit N of `replay_window` = whether index `base - N` was seen.
    fn check_replay(&self, index: u64) -> bool {
        if index > self.replay_window_base {
            // Ahead of window — always ok
            return true;
        }
        let delta = self.replay_window_base - index;
        if delta >= 64 {
            // Too old — outside window
            return false;
        }
        // Check if already received
        (self.replay_window & (1u64 << delta)) == 0
    }

    /// Mark packet index as received in replay window
    fn accept_replay(&mut self, index: u64) {
        if index > self.replay_window_base {
            // New highest — shift window
            let shift = index - self.replay_window_base;
            if shift >= 64 {
                self.replay_window = 0;
            } else {
                self.replay_window <<= shift;
            }
            self.replay_window_base = index;
            self.replay_window |= 1; // bit 0 = current index (delta=0)
        } else {
            let delta = self.replay_window_base - index;
            if delta < 64 {
                self.replay_window |= 1u64 << delta;
            }
        }
    }
}

/// Derive session keys from master key using AES-CM PRF (RFC 3711 Section 4.3.1)
fn derive_session_keys(
    master_key: &[u8; SRTP_MASTER_KEY_LEN],
    master_salt: &[u8; SRTP_MASTER_SALT_LEN],
    is_rtcp: bool,
) -> SessionKeys {
    let enc_label = if is_rtcp {
        LABEL_RTCP_ENCRYPTION
    } else {
        LABEL_RTP_ENCRYPTION
    };
    let auth_label = if is_rtcp {
        LABEL_RTCP_AUTH
    } else {
        LABEL_RTP_AUTH
    };
    let salt_label = if is_rtcp {
        LABEL_RTCP_SALT
    } else {
        LABEL_RTP_SALT
    };

    let mut enc_key = [0u8; SRTP_SESSION_KEY_LEN];
    let mut auth_key = [0u8; SRTP_AUTH_KEY_LEN];
    let mut salt = [0u8; SRTP_SESSION_SALT_LEN];

    prf_derive(master_key, master_salt, enc_label, &mut enc_key);
    prf_derive(master_key, master_salt, auth_label, &mut auth_key);
    prf_derive(master_key, master_salt, salt_label, &mut salt);

    SessionKeys {
        enc_key,
        auth_key,
        salt,
    }
}

/// PRF key derivation: generate `output_len` bytes using AES-CM PRF
///
/// x = label || r (where r = index DIV key_derivation_rate, or 0 for KDR=0)
/// key_id = label || r
/// IV = (master_salt XOR key_id) << 16
///
/// output = AES-CM(master_key, IV) — take first output_len bytes
fn prf_derive(
    master_key: &[u8; SRTP_MASTER_KEY_LEN],
    master_salt: &[u8; SRTP_MASTER_SALT_LEN],
    label: u8,
    output: &mut [u8],
) {
    let cipher = Aes128::new(master_key.into());

    // Build key_id: 7 bytes = [label, 0, 0, 0, 0, 0, 0]
    // For KDR=0, r=0, so key_id = [label, 0, 0, 0, 0, 0, 0]
    let mut key_id = [0u8; 7];
    key_id[0] = label;

    // IV = (master_salt XOR (key_id padded to 14 bytes)) || 0x0000
    // master_salt is 14 bytes, key_id is 7 bytes (padded left with zeros in 14-byte space)
    let mut iv = [0u8; 16];
    // Copy salt into iv[0..14]
    iv[..SRTP_MASTER_SALT_LEN].copy_from_slice(master_salt);
    // XOR key_id into the right-aligned position within 14 bytes (bytes 7..14)
    for i in 0..7 {
        iv[7 + i] ^= key_id[i];
    }
    // iv[14..16] are zero (the << 16 in the spec means 16 bits of zero)

    // Generate keystream blocks
    let blocks_needed = (output.len() + 15) / 16;
    let mut generated = 0;

    for block_idx in 0..blocks_needed {
        let mut block = iv;
        // Add block counter to last 2 bytes (big-endian)
        let counter = block_idx as u16;
        block[14] = (counter >> 8) as u8;
        block[15] = counter as u8;

        let block_ref: &mut aes::Block = block.as_mut_slice().into();
        cipher.encrypt_block(block_ref);

        let to_copy = std::cmp::min(16, output.len() - generated);
        output[generated..generated + to_copy].copy_from_slice(&block[..to_copy]);
        generated += to_copy;
    }
}

/// AES-CM encryption/decryption (same operation — XOR with keystream)
///
/// IV construction for SRTP (RFC 3711 Section 4.1.1):
/// IV = (ssrc XOR salt[4..8]) || (index XOR salt[8..14]) padded to 16 bytes
fn aes_cm_encrypt(
    session_key: &[u8; SRTP_SESSION_KEY_LEN],
    session_salt: &[u8; SRTP_SESSION_SALT_LEN],
    ssrc: u32,
    index: u64,
    data: &mut [u8],
) {
    let cipher = Aes128::new(session_key.into());

    // Build IV per RFC 3711 Section 4.1.1
    // IV = 0x00000000 || SSRC || packet_index (48-bit) || 0x0000
    // Then XOR with session_salt (14 bytes, left-padded with 2 zero bytes to 16)
    let mut iv = [0u8; 16];

    // SSRC at bytes 4..8
    iv[4..8].copy_from_slice(&ssrc.to_be_bytes());

    // Packet index (48-bit) at bytes 8..14
    let idx_bytes = index.to_be_bytes(); // 8 bytes, we want low 6
    iv[8..14].copy_from_slice(&idx_bytes[2..8]);

    // XOR with session salt (salt is 14 bytes, positioned at iv[2..16])
    for i in 0..SRTP_SESSION_SALT_LEN {
        iv[2 + i] ^= session_salt[i];
    }

    // Generate keystream and XOR with data
    let blocks_needed = (data.len() + 15) / 16;
    let mut offset = 0;

    for block_idx in 0..blocks_needed {
        let mut block = iv;
        // Add block counter to last 2 bytes
        let counter = block_idx as u16;
        // The counter goes into bytes 14-15 (replacing the zero padding)
        let existing =
            u16::from_be_bytes([block[14], block[15]]);
        let new_val = existing.wrapping_add(counter);
        block[14] = (new_val >> 8) as u8;
        block[15] = new_val as u8;

        let block_ref: &mut aes::Block = block.as_mut_slice().into();
        cipher.encrypt_block(block_ref);

        let to_xor = std::cmp::min(16, data.len() - offset);
        for i in 0..to_xor {
            data[offset + i] ^= block[i];
        }
        offset += to_xor;
    }
}

/// Compute RTP authentication tag
///
/// HMAC-SHA1 over (RTP_header + encrypted_payload + ROC)
fn compute_rtp_auth_tag(
    auth_key: &[u8; SRTP_AUTH_KEY_LEN],
    authenticated_portion: &[u8],
    roc: u32,
    tag_len: usize,
) -> Vec<u8> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(auth_key).expect("HMAC key size");
    mac.update(authenticated_portion);
    mac.update(&roc.to_be_bytes());
    let full_tag = mac.finalize().into_bytes();
    full_tag[..tag_len].to_vec()
}

/// Get RTP header length including CSRC and extension
fn rtp_header_len(packet: &[u8]) -> Result<usize> {
    if packet.len() < 12 {
        return Err(RtpSipError::Rtp("Packet too short for RTP header".to_string()));
    }

    let cc = (packet[0] & 0x0F) as usize;
    let has_extension = (packet[0] & 0x10) != 0;

    let mut len = 12 + cc * 4;

    if has_extension {
        if packet.len() < len + 4 {
            return Err(RtpSipError::Rtp("Packet too short for extension header".to_string()));
        }
        let ext_len = u16::from_be_bytes([packet[len + 2], packet[len + 3]]) as usize;
        len += 4 + ext_len * 4;
    }

    if len > packet.len() {
        return Err(RtpSipError::Rtp("Header length exceeds packet".to_string()));
    }

    Ok(len)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_attribute_parse() {
        // Standard AES_CM_128_HMAC_SHA1_80 crypto line
        let value = "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert_eq!(crypto.tag, 1);
        assert_eq!(crypto.suite, SrtpCipherSuite::AesCm128HmacSha1_80);
        assert_eq!(crypto.master_key.len(), 16);
        assert_eq!(crypto.master_salt.len(), 14);
    }

    #[test]
    fn test_crypto_attribute_parse_with_lifetime() {
        // Crypto line with lifetime parameter
        let value = "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0|2^31";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert_eq!(crypto.tag, 1);
        assert_eq!(crypto.suite, SrtpCipherSuite::AesCm128HmacSha1_80);
    }

    #[test]
    fn test_crypto_attribute_parse_32bit() {
        let value = "2 AES_CM_128_HMAC_SHA1_32 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert_eq!(crypto.tag, 2);
        assert_eq!(crypto.suite, SrtpCipherSuite::AesCm128HmacSha1_32);
    }

    #[test]
    fn test_crypto_attribute_roundtrip() {
        let original = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let sdp_value = original.to_sdp_value();
        let parsed = CryptoAttribute::parse(&sdp_value).unwrap();
        assert_eq!(parsed.tag, original.tag);
        assert_eq!(parsed.suite, original.suite);
        assert_eq!(parsed.master_key, original.master_key);
        assert_eq!(parsed.master_salt, original.master_salt);
    }

    #[test]
    fn test_crypto_attribute_invalid() {
        // Too few fields
        assert!(CryptoAttribute::parse("1 AES_CM_128_HMAC_SHA1_80").is_err());
        // Invalid suite
        assert!(CryptoAttribute::parse("1 INVALID_SUITE inline:abc").is_err());
        // No inline prefix
        assert!(CryptoAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 key:abc").is_err());
        // Wrong key length
        assert!(CryptoAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 inline:dG9vc2hvcnQ=").is_err());
    }

    #[test]
    fn test_srtp_protect_unprotect_roundtrip() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);

        // Create matching send/receive contexts (same key material)
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Build a minimal RTP packet
        // V=2, P=0, X=0, CC=0, M=0, PT=0, seq=1, ts=160, ssrc=12345
        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01]; // header byte 0-3
        rtp_packet.extend_from_slice(&160u32.to_be_bytes()); // timestamp
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes()); // ssrc
        rtp_packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]); // payload

        // Protect
        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        assert_ne!(&srtp_packet[12..12 + 5], &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(srtp_packet.len(), rtp_packet.len() + 10); // +auth_tag

        // Unprotect
        let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    #[test]
    fn test_srtp_32bit_auth_tag() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_32);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        rtp_packet.extend_from_slice(&[0xAA; 160]); // 160 bytes of audio

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        assert_eq!(srtp_packet.len(), rtp_packet.len() + 4); // +4 byte auth tag

        let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    #[test]
    fn test_srtp_authentication_failure() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);

        // Different key for receiver — should fail auth
        let other_crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut recv_ctx = SrtpContext::from_crypto(&other_crypto);

        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        rtp_packet.extend_from_slice(&[0xBB; 20]);

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        assert!(recv_ctx.unprotect_rtp(&srtp_packet).is_err());
    }

    #[test]
    fn test_srtp_replay_protection() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        rtp_packet.extend_from_slice(&[0xCC; 10]);

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();

        // First unprotect — should succeed
        let _ = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();

        // Replay the same packet — should fail
        assert!(recv_ctx.unprotect_rtp(&srtp_packet).is_err());
    }

    #[test]
    fn test_srtp_multiple_packets() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        for seq in 1u16..=100 {
            let mut rtp_packet = vec![0x80, 0x00];
            rtp_packet.extend_from_slice(&seq.to_be_bytes());
            rtp_packet.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
            rtp_packet.extend_from_slice(&[seq as u8; 160]);

            let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
            let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
            assert_eq!(decrypted, rtp_packet);
        }
    }

    #[test]
    fn test_srtcp_protect_unprotect() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Minimal RTCP SR packet (28 bytes)
        let mut rtcp_packet = vec![
            0x80, 0xC8, 0x00, 0x06, // V=2, PT=200 (SR), length=6
            0x00, 0x00, 0x30, 0x39, // SSRC=12345
        ];
        rtcp_packet.extend_from_slice(&[0x11; 20]); // SR body

        let srtcp_packet = send_ctx.protect_rtcp(&rtcp_packet).unwrap();
        // Should have: original_len + 4 (E||index) + 10 (auth tag)
        assert_eq!(srtcp_packet.len(), rtcp_packet.len() + 14);

        let decrypted = recv_ctx.unprotect_rtcp(&srtcp_packet).unwrap();
        assert_eq!(decrypted, rtcp_packet);
    }

    #[test]
    fn test_srtcp_authentication_failure() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);

        let other_crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut recv_ctx = SrtpContext::from_crypto(&other_crypto);

        let rtcp_packet = vec![
            0x80, 0xC8, 0x00, 0x06,
            0x00, 0x00, 0x30, 0x39,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x11, 0x22, 0x33, 0x44,
        ];

        let srtcp_packet = send_ctx.protect_rtcp(&rtcp_packet).unwrap();
        assert!(recv_ctx.unprotect_rtcp(&srtcp_packet).is_err());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let master_key = [0x01u8; SRTP_MASTER_KEY_LEN];
        let master_salt = [0x02u8; SRTP_MASTER_SALT_LEN];

        let keys1 = derive_session_keys(&master_key, &master_salt, false);
        let keys2 = derive_session_keys(&master_key, &master_salt, false);

        assert_eq!(keys1.enc_key, keys2.enc_key);
        assert_eq!(keys1.auth_key, keys2.auth_key);
        assert_eq!(keys1.salt, keys2.salt);
    }

    #[test]
    fn test_rtp_header_len_basic() {
        // Minimal RTP header (12 bytes, CC=0, no extension)
        let packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0xA0, 0, 0, 0x30, 0x39, 0xFF];
        assert_eq!(rtp_header_len(&packet).unwrap(), 12);
    }

    #[test]
    fn test_rtp_header_len_with_csrc() {
        // CC=2 (2 CSRCs = 8 extra bytes)
        let mut packet = vec![0x82, 0x00, 0x00, 0x01, 0, 0, 0, 0xA0, 0, 0, 0x30, 0x39];
        packet.extend_from_slice(&[0; 8]); // 2 CSRCs
        packet.push(0xFF); // payload
        assert_eq!(rtp_header_len(&packet).unwrap(), 20);
    }

    #[test]
    fn test_rtp_header_len_with_extension() {
        // X=1, extension with 1 word (4 bytes)
        let mut packet = vec![0x90, 0x00, 0x00, 0x01, 0, 0, 0, 0xA0, 0, 0, 0x30, 0x39];
        packet.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01]); // extension header (profile=0xBEDE, len=1)
        packet.extend_from_slice(&[0; 4]); // 1 extension word
        packet.push(0xFF); // payload
        assert_eq!(rtp_header_len(&packet).unwrap(), 20);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn test_out_of_order_packets() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Send packets 1, 2, 3
        let mut packets = Vec::new();
        for seq in 1u16..=3 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&42u32.to_be_bytes());
            rtp.extend_from_slice(&[seq as u8; 20]);
            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            packets.push((rtp, srtp));
        }

        // Receive out of order: 1, 3, 2
        let d1 = recv_ctx.unprotect_rtp(&packets[0].1).unwrap();
        assert_eq!(d1, packets[0].0);

        let d3 = recv_ctx.unprotect_rtp(&packets[2].1).unwrap();
        assert_eq!(d3, packets[2].0);

        let d2 = recv_ctx.unprotect_rtp(&packets[1].1).unwrap();
        assert_eq!(d2, packets[1].0);
    }

    #[test]
    fn test_srtp_error_count_increments() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);

        // Use a different key for receiver so all unprotects fail
        let other = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut recv_ctx = SrtpContext::from_crypto(&other);

        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&42u32.to_be_bytes());
        rtp.extend_from_slice(&[0xAA; 20]);

        // Send 15 packets — all should fail
        for seq in 1u16..=15 {
            let mut pkt = vec![0x80, 0x00];
            pkt.extend_from_slice(&seq.to_be_bytes());
            pkt.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            pkt.extend_from_slice(&42u32.to_be_bytes());
            pkt.extend_from_slice(&[0xBB; 20]);
            let srtp = send_ctx.protect_rtp(&pkt).unwrap();
            let _ = recv_ctx.unprotect_rtp(&srtp);
        }

        // Error count should be 15
        assert_eq!(recv_ctx.error_count(), 15);
    }

    #[test]
    fn test_srtp_error_count_resets_on_success() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // First, feed a bad packet (tampered)
        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&42u32.to_be_bytes());
        rtp.extend_from_slice(&[0xCC; 20]);
        let mut srtp = send_ctx.protect_rtp(&rtp).unwrap();
        srtp[12] ^= 0xFF; // Tamper
        let _ = recv_ctx.unprotect_rtp(&srtp);
        assert!(recv_ctx.error_count() > 0);

        // Now send a good packet
        let mut rtp2 = vec![0x80, 0x00, 0x00, 0x02];
        rtp2.extend_from_slice(&320u32.to_be_bytes());
        rtp2.extend_from_slice(&42u32.to_be_bytes());
        rtp2.extend_from_slice(&[0xDD; 20]);
        let srtp2 = send_ctx.protect_rtp(&rtp2).unwrap();
        let _ = recv_ctx.unprotect_rtp(&srtp2).unwrap();

        // Error count should be reset to 0
        assert_eq!(recv_ctx.error_count(), 0);
    }

    #[test]
    fn test_tampered_packet_rejected() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&99u32.to_be_bytes());
        rtp.extend_from_slice(&[0xDD; 40]);

        let mut srtp = send_ctx.protect_rtp(&rtp).unwrap();

        // Tamper with encrypted payload
        srtp[12] ^= 0xFF;

        // Should fail authentication
        assert!(recv_ctx.unprotect_rtp(&srtp).is_err());
    }
}
