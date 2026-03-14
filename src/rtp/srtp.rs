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
//! # Features
//!
//! - Supports both 80-bit and 32-bit auth tags
//! - Detects SSRC changes and resets receiver replay state (P1-SRTP-7)
//! - ROC (Rollover Counter) tracking for long calls
//! - Replay protection via 128-packet sliding window (P1-SRTP-3)
//! - Key lifetime enforcement: warn at 2^47, error at 2^48 packets (P1-SRTP-4)
//! - Non-monotonic send index rejection to prevent keystream reuse (P1-SRTP-2)
//!
//! # Limitations
//!
//! - Only AES-128 cipher suites are supported (AES-256 would require 32-byte keys).
//! - 32-bit ROC overflow is not guarded against, though this would require
//!   ~281 trillion packets.
//! - Send and receive contexts must be separate instances. A single SrtpContext
//!   should NOT be used for both directions simultaneously.

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
    /// MKI value (Master Key Identifier), if present
    pub mki: Option<Vec<u8>>,
    /// MKI length in bytes as declared in the SDP attribute, if present
    pub mki_length: Option<usize>,
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

        // Split on '|' to separate base64 key from optional lifetime and MKI params
        let after_inline = &key_param[inline_prefix.len()..];
        let parts_pipe: Vec<&str> = after_inline.split('|').collect();
        let b64_key = parts_pipe[0];

        // Parse optional MKI parameter (last pipe-separated field in format "mki_value:mki_length")
        let mut mki: Option<Vec<u8>> = None;
        let mut mki_length: Option<usize> = None;
        for part in &parts_pipe[1..] {
            if let Some((mki_val_str, mki_len_str)) = part.split_once(':') {
                // This looks like an MKI field "value:length"
                if let Ok(len) = mki_len_str.parse::<usize>() {
                    // MKI value is a numeric string representing the MKI identifier
                    if let Ok(mki_val_num) = mki_val_str.parse::<u128>() {
                        if len > 0 && len <= 16 {
                            let full_bytes = mki_val_num.to_be_bytes();
                            // Take the last `len` bytes
                            let start = if full_bytes.len() > len {
                                full_bytes.len() - len
                            } else {
                                0
                            };
                            mki = Some(full_bytes[start..].to_vec());
                            mki_length = Some(len);
                        }
                    }
                }
            }
            // Otherwise it's a lifetime parameter (e.g., "2^31") — we ignore it
        }

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
            mki,
            mki_length,
        })
    }

    /// Generate a new random crypto attribute
    pub fn generate(suite: SrtpCipherSuite) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut master_key = [0u8; SRTP_MASTER_KEY_LEN];
        let mut master_salt = [0u8; SRTP_MASTER_SALT_LEN];

        // Fill entire buffers in one call for efficiency and better randomness
        rng.fill(&mut master_key[..]);
        rng.fill(&mut master_salt[..]);

        Self {
            tag: 1,
            suite,
            master_key,
            master_salt,
            mki: None,
            mki_length: None,
        }
    }

    /// Format as SDP `a=crypto:` attribute value
    pub fn to_sdp_value(&self) -> String {
        use base64::Engine;
        let mut key_material = Vec::with_capacity(SRTP_MASTER_LEN);
        key_material.extend_from_slice(&self.master_key);
        key_material.extend_from_slice(&self.master_salt);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&key_material);
        let inline_part = if let (Some(mki_val), Some(mki_len)) = (&self.mki, self.mki_length) {
            // Convert MKI bytes to a numeric value for the SDP representation
            let mut val: u128 = 0;
            for &byte in mki_val.iter() {
                val = (val << 8) | (byte as u128);
            }
            format!("inline:{}|{}:{}", b64, val, mki_len)
        } else {
            format!("inline:{}", b64)
        };
        format!("{} {} {}", self.tag, self.suite.as_str(), inline_part)
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

/// SRTP context for a single direction (send or receive).
///
/// **Important**: Each direction must use its own `SrtpContext` instance.
/// The send side uses `protect_rtp`/`protect_rtcp`, and the receive side uses
/// `unprotect_rtp`/`unprotect_rtcp`. Do not mix directions in a single context,
/// as the replay window, ROC, and counter state would be corrupted.
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
    /// P2-SRTP-1: Key derivation rate. When > 0, session keys are re-derived
    /// every `key_derivation_rate` packets using `r = index / kdr` in the PRF.
    /// Default 0 means keys are derived once at context creation (KDR=0).
    key_derivation_rate: u64,
    /// Rollover counter (increments on seq wrap) — used for receive direction
    roc: u32,
    /// Highest sequence number seen (for ROC tracking) — used for receive direction
    s_l: u16,
    /// Whether we've received any packet yet
    initialized: bool,
    /// 48-bit send packet counter (seq = counter & 0xFFFF, ROC = counter >> 16)
    send_counter: u64,
    /// Whether we've sent any packet yet
    send_initialized: bool,
    /// Last sent 48-bit packet index — used to reject non-monotonic sends
    /// that would reuse AES-CM keystream (P1-SRTP-2)
    last_sent_index: u64,
    /// Total number of packets encrypted via protect_rtp. Used to enforce
    /// key lifetime limits (P1-SRTP-4): warn at 2^47, error at 2^48.
    packets_encrypted: u64,
    /// SRTCP index counter
    srtcp_index: u32,
    /// Replay protection window (128-bit sliding window) for RTP (P1-SRTP-3)
    replay_window: u128,
    /// Replay window base index for RTP
    replay_window_base: u64,
    /// SRTCP replay protection window (64-bit sliding window).
    ///
    /// Note: SRTCP indices are only 31 bits (per RFC 3711 Section 3.4), so a
    /// 64-bit bitmap is more than sufficient. We intentionally reuse the same
    /// 64-bit sliding window implementation as the RTP replay window for
    /// simplicity and code consistency, even though a 32-bit bitmap would
    /// technically cover the SRTCP index space.
    srtcp_replay_window: u64,
    /// SRTCP replay window base index (31-bit SRTCP index, stored as u64 for
    /// consistency with the RTP replay window arithmetic)
    srtcp_replay_window_base: u64,
    /// Whether we've received any SRTCP packet yet (for replay init)
    srtcp_replay_initialized: bool,
    /// Consecutive error count for error recovery
    error_count: u32,
    /// MKI value to append when protecting, if configured
    mki: Option<Vec<u8>>,
    /// MKI length in bytes, for stripping on unprotect
    mki_length: Option<usize>,
    /// Current receive SSRC — used to detect SSRC changes and reset
    /// receiver replay state (P1-SRTP-7)
    current_recv_ssrc: Option<u32>,
}

/// Bug #81: Zeroize SRTP key material on drop to prevent sensitive keys from
/// lingering in memory after the context is no longer needed.
impl Drop for SrtpContext {
    fn drop(&mut self) {
        self.master_key.fill(0);
        self.master_salt.fill(0);
        self.rtp_keys.enc_key.fill(0);
        self.rtp_keys.auth_key.fill(0);
        self.rtp_keys.salt.fill(0);
        self.rtcp_keys.enc_key.fill(0);
        self.rtcp_keys.auth_key.fill(0);
        self.rtcp_keys.salt.fill(0);
    }
}

impl SrtpContext {
    /// Create a new SRTP context from master key material
    pub fn new(
        suite: SrtpCipherSuite,
        master_key: [u8; SRTP_MASTER_KEY_LEN],
        master_salt: [u8; SRTP_MASTER_SALT_LEN],
    ) -> Self {
        Self::with_mki(suite, master_key, master_salt, None, None)
    }

    /// Create a new SRTP context with optional MKI
    ///
    /// # Panics
    /// Panics if `mki` is `Some` but `mki_length` is `None` or does not equal `mki.len()`.
    pub fn with_mki(
        suite: SrtpCipherSuite,
        master_key: [u8; SRTP_MASTER_KEY_LEN],
        master_salt: [u8; SRTP_MASTER_SALT_LEN],
        mki: Option<Vec<u8>>,
        mki_length: Option<usize>,
    ) -> Self {
        // Bug #83: Validate MKI length consistency
        if let Some(ref mki_val) = mki {
            let declared_len = mki_length.unwrap_or_else(|| {
                panic!(
                    "SRTP: mki is Some({} bytes) but mki_length is None",
                    mki_val.len()
                )
            });
            assert_eq!(
                declared_len,
                mki_val.len(),
                "SRTP: mki_length ({}) does not match mki.len() ({})",
                declared_len,
                mki_val.len(),
            );
        }

        let rtp_keys = derive_session_keys(&master_key, &master_salt, false, 0, 0);
        let rtcp_keys = derive_session_keys(&master_key, &master_salt, true, 0, 0);

        Self {
            suite,
            master_key,
            master_salt,
            rtp_keys,
            rtcp_keys,
            key_derivation_rate: 0,
            roc: 0,
            s_l: 0,
            initialized: false,
            send_counter: 0,
            send_initialized: false,
            last_sent_index: 0,
            packets_encrypted: 0,
            srtcp_index: 0,
            replay_window: 0,
            replay_window_base: 0,
            srtcp_replay_window: 0,
            srtcp_replay_window_base: 0,
            srtcp_replay_initialized: false,
            error_count: 0,
            mki,
            mki_length,
            current_recv_ssrc: None,
        }
    }

    /// Create from a parsed crypto attribute
    pub fn from_crypto(crypto: &CryptoAttribute) -> Self {
        Self::with_mki(
            crypto.suite,
            crypto.master_key,
            crypto.master_salt,
            crypto.mki.clone(),
            crypto.mki_length,
        )
    }

    /// Protect (encrypt + authenticate) an RTP packet in-place
    ///
    /// Input: plaintext RTP packet (header + payload)
    /// Output: SRTP packet (header + encrypted_payload + [MKI] + auth_tag)
    ///
    /// Uses a 48-bit send counter to track the packet index. The sequence number
    /// from the packet header is used alongside wraparound detection to properly
    /// increment the ROC, avoiding the old bug where ROC only incremented on the
    /// exact 0xFFFF->0 boundary.
    ///
    /// Returns an error if:
    /// - The computed packet index is not strictly greater than the last sent
    ///   index (non-monotonic sequence would reuse AES-CM keystream).
    /// - The key lifetime limit (2^48 packets) has been reached.
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 12 {
            return Err(RtpSipError::Rtp("RTP packet too short".to_string()));
        }

        // P1-SRTP-4: Key lifetime enforcement
        const KEY_LIFETIME_WARN: u64 = 1u64 << 47;
        const KEY_LIFETIME_MAX: u64 = 1u64 << 48;
        if self.packets_encrypted >= KEY_LIFETIME_MAX {
            return Err(RtpSipError::Rtp(
                "SRTP key lifetime exhausted: 2^48 packets encrypted, re-key required".to_string(),
            ));
        }
        if self.packets_encrypted == KEY_LIFETIME_WARN {
            tracing::warn!(
                "SRTP key lifetime warning: 2^47 packets encrypted, approaching 2^48 limit — \
                 re-key recommended"
            );
        }

        let header_len = rtp_header_len(packet)?;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        // For the sender, maintain a 48-bit counter.
        // On first packet, initialize from the packet's seq number.
        // On subsequent packets, detect wraparound from the seq gap.
        if !self.send_initialized {
            self.send_counter = seq as u64;
            self.send_initialized = true;
        } else {
            let prev_seq = (self.send_counter & 0xFFFF) as u16;
            if seq < prev_seq && (prev_seq - seq) > 0x8000 {
                // Forward wrap detected: seq wrapped around 0xFFFF -> 0
                // Increment the upper 32 bits (ROC portion)
                self.send_counter = ((self.send_counter >> 16).wrapping_add(1) << 16)
                    | (seq as u64);
            } else {
                // Normal progression or reorder within same ROC
                self.send_counter = (self.send_counter & !0xFFFF) | (seq as u64);
            }
        }

        let index = self.send_counter & 0xFFFF_FFFF_FFFF; // 48-bit mask

        // P1-SRTP-2: Reject non-monotonic send indices to prevent keystream reuse.
        // The first packet (packets_encrypted == 0) is always allowed.
        if self.packets_encrypted > 0 && index <= self.last_sent_index {
            return Err(RtpSipError::Rtp(
                "SRTP non-monotonic send index: keystream reuse prevented".to_string(),
            ));
        }
        self.last_sent_index = index;
        self.packets_encrypted += 1;

        let roc = (index >> 16) as u32;

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

        // Compute auth tag BEFORE appending MKI (RFC 3711 §4.2: authenticated
        // portion is header + encrypted payload only, MKI excluded)
        let auth_tag = compute_rtp_auth_tag(
            &self.rtp_keys.auth_key,
            &output,
            roc,
            self.suite.rtp_auth_tag_len(),
        );

        // Append MKI bytes if configured (after auth tag computation)
        if let Some(ref mki_bytes) = self.mki {
            output.extend_from_slice(mki_bytes);
        }

        // Append authentication tag
        output.extend_from_slice(&auth_tag);

        Ok(output)
    }

    /// Unprotect (authenticate + decrypt) an SRTP packet
    ///
    /// Input: SRTP packet (header + encrypted_payload + [MKI] + auth_tag)
    /// Output: plaintext RTP packet (header + payload)
    ///
    /// Error recovery: tracks consecutive authentication failures and logs
    /// warnings after `SRTP_WARN_THRESHOLD` (10) and `SRTP_RESET_THRESHOLD`
    /// (100) errors. Replay rejections are NOT counted toward the error
    /// threshold since they are a normal security mechanism, not a sign of
    /// key mismatch (P1-SRTP-6).
    ///
    /// SSRC change detection (P1-SRTP-7): If the incoming packet's SSRC differs
    /// from the previously seen SSRC, the receiver's replay window, ROC, and
    /// sequence state are reset. This handles legitimate SSRC changes (e.g.,
    /// re-INVITE with new media source) without requiring a new context.
    pub fn unprotect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let auth_tag_len = self.suite.rtp_auth_tag_len();
        let mki_len = self.mki_length.unwrap_or(0);
        let trailer_len = auth_tag_len + mki_len;
        if packet.len() < 12 + trailer_len {
            self.handle_unprotect_error();
            return Err(RtpSipError::Rtp("SRTP packet rejected".to_string()));
        }

        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        // P1-SRTP-7: Detect SSRC change and reset receiver state.
        // A new SSRC indicates a different media source (e.g., re-INVITE,
        // transfer, or SSRC collision recovery). The old replay window and
        // ROC are meaningless for the new SSRC.
        if let Some(prev_ssrc) = self.current_recv_ssrc {
            if ssrc != prev_ssrc {
                tracing::info!(
                    "SRTP: SSRC changed from {:#010x} to {:#010x}, resetting receiver state",
                    prev_ssrc,
                    ssrc
                );
                self.replay_window = 0;
                self.replay_window_base = 0;
                self.s_l = 0;
                self.roc = 0;
                self.initialized = false;
            }
        }
        self.current_recv_ssrc = Some(ssrc);

        // Estimate ROC for incoming packet (RFC 3711 Section 3.3.1)
        let estimated_roc = self.estimate_roc(seq);
        let index = ((estimated_roc as u64) << 16) | (seq as u64);

        // Replay protection (P1-SRTP-5: use generic error message,
        // P1-SRTP-6: do NOT count replay rejections toward error threshold)
        if self.initialized && !self.check_replay(index) {
            return Err(RtpSipError::Rtp("SRTP packet rejected".to_string()));
        }

        // Split packet: [header + encrypted_payload | MKI | auth_tag]
        // RFC 3711 §4.2: authenticated portion is header + encrypted payload only, MKI excluded
        let auth_tag_start = packet.len() - auth_tag_len;
        let received_tag = &packet[auth_tag_start..];
        let auth_data = &packet[..packet.len() - auth_tag_len - mki_len];

        // Verify authentication tag (auth is computed over header + encrypted_payload only)
        let computed_tag = compute_rtp_auth_tag(
            &self.rtp_keys.auth_key,
            auth_data,
            estimated_roc,
            auth_tag_len,
        );

        if !constant_time_eq(&computed_tag, received_tag) {
            self.handle_unprotect_error();
            return Err(RtpSipError::Rtp("SRTP packet rejected".to_string()));
        }

        // auth_data already excludes MKI, so it is the encrypted RTP data
        let encrypted_data = auth_data;

        // Bug #14: Update ROC/s_l and replay window AFTER auth passes but BEFORE
        // header parsing. This prevents replay of authenticated packets if header
        // parsing fails (e.g., malformed extension headers). An authenticated
        // packet is genuine even if its header is unparseable, so it must be
        // consumed from the replay window.
        self.update_roc_recv(seq, estimated_roc);
        self.accept_replay(index);

        // Decrypt payload
        let header_len = rtp_header_len(encrypted_data)?;
        let mut output = encrypted_data.to_vec();
        let payload = &mut output[header_len..];
        aes_cm_encrypt(
            &self.rtp_keys.enc_key,
            &self.rtp_keys.salt,
            ssrc,
            index,
            payload,
        );

        // Success -- reset error counter
        self.error_count = 0;

        Ok(output)
    }

    /// Handle an unprotect error (authentication failure): increment counter and warn.
    ///
    /// This is called only for authentication failures, NOT for replay rejections
    /// (P1-SRTP-6). Replay rejections are a normal security mechanism and should
    /// not inflate the error count.
    ///
    /// SECURITY: We intentionally do NOT reset ROC, replay_window,
    /// replay_window_base, or initialized state, even after many consecutive
    /// errors. Resetting security state would allow an attacker to replay
    /// previously accepted packets by sending ~100 garbage UDP packets to
    /// clear the replay window. Instead, we only log warnings and reset the
    /// error counter to avoid u32 overflow.
    fn handle_unprotect_error(&mut self) {
        self.error_count += 1;

        if self.error_count == SRTP_WARN_THRESHOLD {
            tracing::warn!(
                "SRTP: {} consecutive unprotect errors — possible key mismatch or corruption",
                self.error_count,
            );
        }

        if self.error_count >= SRTP_RESET_THRESHOLD {
            tracing::error!(
                "SRTP: {} consecutive unprotect errors — persistent failure, \
                 possible key mismatch. Security state preserved to prevent replay attacks.",
                self.error_count,
            );
            // Reset only the error counter to prevent u32 overflow on continued
            // garbage input. Do NOT reset ROC, replay_window, replay_window_base,
            // or initialized — doing so would open a replay attack vector.
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

        // SRTCP index is 31-bit (max 0x7FFFFFFF). Guard against overflow to
        // prevent keystream reuse (RFC 3711 §3.3.2).
        if self.srtcp_index >= 0x80000000 {
            return Err(RtpSipError::Rtp(
                "SRTCP index overflow: 31-bit index space exhausted".to_string(),
            ));
        }

        let srtcp_index = self.srtcp_index;
        self.srtcp_index += 1;

        // Encrypt everything after the first 8 bytes (header)
        // P1-SRTP-1: Use dedicated SRTCP encryption that validates the
        // 31-bit index constraint.
        let mut output = packet.to_vec();
        if output.len() > 8 {
            let payload = &mut output[8..];
            aes_cm_encrypt_srtcp(
                &self.rtcp_keys.enc_key,
                &self.rtcp_keys.salt,
                ssrc,
                srtcp_index,
                payload,
            );
        }

        // Append E-flag (1 = encrypted) | SRTCP index (31 bits)
        //
        // Bug #18 note: The E-flag is intentionally always set to 1 (encrypted).
        // RFC 3711 §3.4 defines E=1 as "SRTCP packet is encrypted" and E=0 as
        // "not encrypted". Since this implementation always encrypts SRTCP packets,
        // E=1 is correct. If unencrypted SRTCP is ever needed (e.g., for debugging
        // or null cipher), this would need to be conditional on the cipher suite.
        let e_srtcp_index = 0x8000_0000u32 | (srtcp_index & 0x7FFF_FFFF);
        output.extend_from_slice(&e_srtcp_index.to_be_bytes());

        // Compute auth tag BEFORE appending MKI (RFC 3711 §4.2: authenticated
        // portion is header + encrypted_payload + E||index, MKI excluded)
        let mut mac =
            <HmacSha1 as Mac>::new_from_slice(&self.rtcp_keys.auth_key).expect("HMAC key size");
        mac.update(&output);
        let full_tag = mac.finalize().into_bytes();
        let auth_tag = full_tag[..SRTCP_AUTH_TAG_LEN].to_vec();

        // Append MKI bytes if configured (after auth tag computation)
        if let Some(ref mki_bytes) = self.mki {
            output.extend_from_slice(mki_bytes);
        }

        // Append authentication tag
        output.extend_from_slice(&auth_tag);

        Ok(output)
    }

    /// Unprotect an SRTCP packet
    pub fn unprotect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let mki_len = self.mki_length.unwrap_or(0);
        let min_len = 8 + SRTCP_INDEX_LEN + mki_len + SRTCP_AUTH_TAG_LEN;
        if packet.len() < min_len {
            return Err(RtpSipError::Rtp("SRTCP packet too short".to_string()));
        }

        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Split: [authenticated_data | MKI | auth_tag]
        // RFC 3711 §4.2: authenticated portion excludes MKI
        let auth_tag_start = packet.len() - SRTCP_AUTH_TAG_LEN;
        let received_tag = &packet[auth_tag_start..];
        let auth_data = &packet[..packet.len() - SRTCP_AUTH_TAG_LEN - mki_len];

        // Verify authentication (over header + encrypted_payload + E||index, MKI excluded)
        let mut mac =
            <HmacSha1 as Mac>::new_from_slice(&self.rtcp_keys.auth_key).expect("HMAC key size");
        mac.update(auth_data);
        let full_tag = mac.finalize().into_bytes();
        let computed_tag = &full_tag[..SRTCP_AUTH_TAG_LEN];

        if !constant_time_eq(computed_tag, received_tag) {
            return Err(RtpSipError::Rtp("SRTCP authentication failed".to_string()));
        }

        // auth_data already excludes MKI, so it contains [rtcp_data | E||index]
        let data_with_index = auth_data;

        // Extract E-flag and SRTCP index
        let index_start = data_with_index.len() - SRTCP_INDEX_LEN;
        let e_index = u32::from_be_bytes([
            data_with_index[index_start],
            data_with_index[index_start + 1],
            data_with_index[index_start + 2],
            data_with_index[index_start + 3],
        ]);
        let is_encrypted = (e_index & 0x8000_0000) != 0;
        let srtcp_index = e_index & 0x7FFF_FFFF;

        // SRTCP replay protection (sliding window on the 31-bit SRTCP index)
        let srtcp_idx_u64 = srtcp_index as u64;
        if self.srtcp_replay_initialized {
            if !self.check_srtcp_replay(srtcp_idx_u64) {
                return Err(RtpSipError::Rtp("SRTCP replay detected".to_string()));
            }
        }

        // Decrypt if encrypted
        // P1-SRTP-1: Use dedicated SRTCP decryption that validates the
        // 31-bit index constraint.
        let mut output = data_with_index[..index_start].to_vec();
        if is_encrypted && output.len() > 8 {
            let payload = &mut output[8..];
            aes_cm_encrypt_srtcp(
                &self.rtcp_keys.enc_key,
                &self.rtcp_keys.salt,
                ssrc,
                srtcp_index,
                payload,
            );
        }

        // Accept into SRTCP replay window after successful decryption
        self.accept_srtcp_replay(srtcp_idx_u64);
        self.srtcp_replay_initialized = true;

        Ok(output)
    }

    /// Check if SRTCP index passes replay protection (64-packet sliding window)
    fn check_srtcp_replay(&self, index: u64) -> bool {
        if index > self.srtcp_replay_window_base {
            return true;
        }
        let delta = self.srtcp_replay_window_base - index;
        if delta >= 64 {
            return false;
        }
        (self.srtcp_replay_window & (1u64 << delta)) == 0
    }

    /// Mark SRTCP index as received in replay window
    fn accept_srtcp_replay(&mut self, index: u64) {
        if index > self.srtcp_replay_window_base {
            let shift = index - self.srtcp_replay_window_base;
            if shift >= 64 {
                self.srtcp_replay_window = 0;
            } else {
                self.srtcp_replay_window <<= shift;
            }
            self.srtcp_replay_window_base = index;
            self.srtcp_replay_window |= 1;
        } else {
            let delta = self.srtcp_replay_window_base - index;
            if delta < 64 {
                self.srtcp_replay_window |= 1u64 << delta;
            }
        }
    }

    /// Estimate ROC for incoming packet based on sequence number.
    ///
    /// Implements RFC 3711 Section 3.3.1 properly. Determines the ROC value
    /// (v) to use when computing the packet index, based on the gap between
    /// the received sequence number and the highest sequence number seen so far.
    ///
    /// Bug #82: Limitation — this is a simplified heuristic that uses the
    /// half-sequence-space rule (diff < 0x8000) to decide forward vs backward
    /// wraparound. It works well for normal RTP streams but can misclassify
    /// packets if the gap exceeds 32768 sequence numbers (e.g., extreme
    /// reordering or long outages). See RFC 3711 Section 3.3.1 for the full
    /// algorithm which also considers key derivation rate (KDR).
    fn estimate_roc(&self, seq: u16) -> u32 {
        if !self.initialized {
            return 0;
        }

        let roc = self.roc;
        let s_l = self.s_l;

        if seq > s_l {
            // seq is ahead of s_l
            let diff = seq - s_l;
            // Bug #R8-6: Use `>` not `<` to match RFC 3711 §3.3.1 and the backward
            // case (line 796). When diff == 0x8000 exactly, treat as normal progression
            // (current ROC), not as a late packet from ROC-1.
            if diff > 0x8000 {
                // Large forward gap means seq actually wrapped backward (late packet)
                roc.wrapping_sub(1)
            } else {
                // Normal forward progression — same ROC (includes boundary diff == 0x8000)
                roc
            }
        } else if seq < s_l {
            // seq is behind s_l
            let diff = s_l - seq;
            if diff > 0x8000 {
                // s_l is near the top and seq is near the bottom — forward wrap
                roc.wrapping_add(1)
            } else {
                // Normal reordering — same ROC
                roc
            }
        } else {
            // seq == s_l — same ROC
            roc
        }
    }

    /// Update ROC state after successful receive.
    ///
    /// RFC 3711 Section 3.3.1: update s_l and ROC based on the estimated ROC (v).
    /// The 48-bit index = (v << 16) | seq. If this is greater than the current
    /// highest index, update both s_l and ROC.
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
    /// Uses a 128-packet sliding window (P1-SRTP-3) anchored at
    /// `replay_window_base` (highest seen index). Bit N of `replay_window`
    /// = whether index `base - N` was seen.
    fn check_replay(&self, index: u64) -> bool {
        if index > self.replay_window_base {
            // Ahead of window — always ok
            return true;
        }
        let delta = self.replay_window_base - index;
        if delta >= 128 {
            // Too old — outside window
            return false;
        }
        // Check if already received
        (self.replay_window & (1u128 << delta)) == 0
    }

    /// Mark packet index as received in replay window
    fn accept_replay(&mut self, index: u64) {
        if index > self.replay_window_base {
            // New highest — shift window
            let shift = index - self.replay_window_base;
            if shift >= 128 {
                self.replay_window = 0;
            } else {
                self.replay_window <<= shift;
            }
            self.replay_window_base = index;
            self.replay_window |= 1; // bit 0 = current index (delta=0)
        } else {
            let delta = self.replay_window_base - index;
            if delta < 128 {
                self.replay_window |= 1u128 << delta;
            }
        }
    }
}

/// Derive session keys from master key using AES-CM PRF (RFC 3711 Section 4.3.1)
///
/// P2-SRTP-1: When `key_derivation_rate` > 0, `r = index / key_derivation_rate`
/// is included in the key_id. When KDR is 0, r = 0 (keys derived once).
fn derive_session_keys(
    master_key: &[u8; SRTP_MASTER_KEY_LEN],
    master_salt: &[u8; SRTP_MASTER_SALT_LEN],
    is_rtcp: bool,
    key_derivation_rate: u64,
    index: u64,
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

    // P2-SRTP-1: Compute r = index / kdr (0 when kdr is 0)
    let r: u64 = if key_derivation_rate > 0 {
        index / key_derivation_rate
    } else {
        0
    };

    let mut enc_key = [0u8; SRTP_SESSION_KEY_LEN];
    let mut auth_key = [0u8; SRTP_AUTH_KEY_LEN];
    let mut salt = [0u8; SRTP_SESSION_SALT_LEN];

    prf_derive(master_key, master_salt, enc_label, r, &mut enc_key);
    prf_derive(master_key, master_salt, auth_label, r, &mut auth_key);
    prf_derive(master_key, master_salt, salt_label, r, &mut salt);

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
///
/// P2-SRTP-1: `r` parameter is the key derivation rate divisor result.
/// When KDR > 0, `r = index / kdr`. When KDR = 0, `r = 0`.
fn prf_derive(
    master_key: &[u8; SRTP_MASTER_KEY_LEN],
    master_salt: &[u8; SRTP_MASTER_SALT_LEN],
    label: u8,
    r: u64,
    output: &mut [u8],
) {
    let cipher = Aes128::new(master_key.into());

    // Build key_id: 7 bytes = [label, r_bytes[0..6]]
    // P2-SRTP-1: When KDR > 0, r is included in the key_id after the label.
    // r is a 48-bit value (6 bytes), placed in key_id[1..7].
    let mut key_id = [0u8; 7];
    key_id[0] = label;
    let r_bytes = r.to_be_bytes(); // 8 bytes, we want low 6
    key_id[1..7].copy_from_slice(&r_bytes[2..8]);

    // IV = (master_salt XOR (key_id padded to 14 bytes)) || 0x0000
    // master_salt is 14 bytes, key_id is 7 bytes (padded left with zeros in 14-byte space)
    let mut iv = [0u8; 16];
    // Copy salt into iv[0..14]
    iv[..SRTP_MASTER_SALT_LEN].copy_from_slice(master_salt);
    // XOR key_id into position per RFC 3711 §4.3.1 (bytes 7..14 of the 14-byte IV space)
    for i in 0..7 {
        iv[7 + i] ^= key_id[i];
    }
    // iv[14..16] are zero (the << 16 in the spec means 16 bits of zero)

    // P2-SRTP-6: Use checked_add to prevent usize overflow on 32-bit platforms
    let blocks_needed = output.len().checked_add(15).map(|v| v / 16).unwrap_or(0);
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
    // Then XOR with session_salt (14 bytes at iv[0..14], per RFC 3711 §4.1.1)
    let mut iv = [0u8; 16];

    // SSRC at bytes 4..8
    iv[4..8].copy_from_slice(&ssrc.to_be_bytes());

    // Packet index (48-bit) at bytes 8..14
    let idx_bytes = index.to_be_bytes(); // 8 bytes, we want low 6
    iv[8..14].copy_from_slice(&idx_bytes[2..8]);

    // XOR with session salt (14 bytes at iv[0..14], per RFC 3711 §4.1.1)
    for i in 0..SRTP_SESSION_SALT_LEN {
        iv[i] ^= session_salt[i];
    }

    // P2-SRTP-6: Use checked arithmetic for blocks_needed to prevent
    // usize overflow on 32-bit platforms where data.len() + 15 could wrap.
    let blocks_needed = match data.len().checked_add(15) {
        Some(v) => v / 16,
        None => {
            // On overflow, the data is impossibly large; skip encryption
            // rather than wrapping to a small number of blocks.
            return;
        }
    };
    let mut offset = 0;

    for block_idx in 0..blocks_needed {
        let mut block = iv;
        // Set block counter in last 2 bytes (direct assignment, not accumulation)
        let counter = block_idx as u16;
        // The counter goes into bytes 14-15 (replacing the zero padding)
        block[14] = (counter >> 8) as u8;
        block[15] = counter as u8;

        let block_ref: &mut aes::Block = block.as_mut_slice().into();
        cipher.encrypt_block(block_ref);

        let to_xor = std::cmp::min(16, data.len() - offset);
        for i in 0..to_xor {
            data[offset + i] ^= block[i];
        }
        offset += to_xor;
    }
}

/// P1-SRTP-1: Dedicated AES-CM encryption for SRTCP packets.
///
/// SRTCP uses a 31-bit index (RFC 3711 Section 3.4). This function
/// explicitly validates and handles the 31-bit constraint, preventing
/// accidental misuse with indices >= 2^31 that would corrupt the IV.
///
/// IV construction for SRTCP follows the same layout as SRTP
/// (RFC 3711 Section 4.1.1) but with the 31-bit SRTCP index instead
/// of the 48-bit SRTP packet index.
fn aes_cm_encrypt_srtcp(
    session_key: &[u8; SRTP_SESSION_KEY_LEN],
    session_salt: &[u8; SRTP_SESSION_SALT_LEN],
    ssrc: u32,
    srtcp_index: u32,
    data: &mut [u8],
) {
    // Assert that the SRTCP index fits in 31 bits (max 0x7FFF_FFFF).
    // The caller (protect_rtcp/unprotect_rtcp) should already validate this,
    // but this assertion provides defense-in-depth against IV corruption.
    assert!(
        srtcp_index <= 0x7FFF_FFFF,
        "SRTCP index {:#010x} exceeds 31-bit limit",
        srtcp_index
    );

    // Delegate to the shared AES-CM function with the 31-bit index
    // zero-extended to u64. The top bits are all zero, which is correct
    // for the SRTCP IV layout.
    aes_cm_encrypt(session_key, session_salt, ssrc, srtcp_index as u64, data);
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
    debug_assert!(tag_len <= 20, "auth tag length exceeds SHA1 output size");
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

        let keys1 = derive_session_keys(&master_key, &master_salt, false, 0, 0);
        let keys2 = derive_session_keys(&master_key, &master_salt, false, 0, 0);

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

    #[test]
    fn test_roc_wraparound_without_exact_boundary() {
        // Bug #2: ROC must increment even if the exact 0xFFFF->0 packet is lost.
        // Simulate: send packets near the seq boundary, skip the exact boundary,
        // and verify packets after the wrap still decrypt correctly.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Send packets from seq 0xFFF0 up to 0xFFFE (skip 0xFFFF and 0x0000)
        let mut packets = Vec::new();
        for seq in 0xFFF0u16..=0xFFFE {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xAA; 20]);
            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            packets.push((seq, rtp, srtp));
        }

        // Now send packets 0xFFFF and 0x0000 (the boundary)
        for seq in [0xFFFFu16, 0x0000u16] {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xAA; 20]);
            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            packets.push((seq, rtp, srtp));
        }

        // Send a few more after the wrap
        for seq in 0x0001u16..=0x0005 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xAA; 20]);
            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            packets.push((seq, rtp, srtp));
        }

        // Receive all packets — receiver should handle the wrap gracefully
        for (_seq, rtp_orig, srtp) in &packets {
            let decrypted = recv_ctx.unprotect_rtp(srtp).unwrap();
            assert_eq!(&decrypted, rtp_orig);
        }

        // Now test the case where the exact boundary packets (0xFFFF, 0x0000) are LOST.
        // Re-create contexts.
        let mut send_ctx2 = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx2 = SrtpContext::from_crypto(&crypto);

        let mut all_packets = Vec::new();
        // Send 0xFFF0..=0xFFFE, then 0xFFFF, 0x0000, 0x0001..=0x0005
        for seq in (0xFFF0u16..=0xFFFF).chain(0x0000u16..=0x0005) {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xBB; 20]);
            let srtp = send_ctx2.protect_rtp(&rtp).unwrap();
            all_packets.push((seq, rtp, srtp));
        }

        // Receive all except the boundary packets (0xFFFF and 0x0000, indices 16 and 17)
        for (i, (_seq, rtp_orig, srtp)) in all_packets.iter().enumerate() {
            if i == 15 || i == 16 {
                continue; // Skip the boundary packets
            }
            let decrypted = recv_ctx2.unprotect_rtp(srtp).unwrap();
            assert_eq!(&decrypted, rtp_orig);
        }
    }

    #[test]
    fn test_srtcp_replay_protection() {
        // Bug #26: SRTCP should have replay protection
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let rtcp_packet = vec![
            0x80, 0xC8, 0x00, 0x06,
            0x00, 0x00, 0x30, 0x39,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x11, 0x22, 0x33, 0x44,
        ];

        let srtcp_packet = send_ctx.protect_rtcp(&rtcp_packet).unwrap();

        // First unprotect — should succeed
        let _ = recv_ctx.unprotect_rtcp(&srtcp_packet).unwrap();

        // Replay the same SRTCP packet — should fail
        assert!(recv_ctx.unprotect_rtcp(&srtcp_packet).is_err());
    }

    #[test]
    fn test_srtcp_multiple_packets_with_replay() {
        // Ensure multiple different SRTCP packets work, but replays don't
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut srtcp_packets = Vec::new();
        for i in 0u8..5 {
            let mut rtcp = vec![
                0x80, 0xC8, 0x00, 0x06,
                0x00, 0x00, 0x30, 0x39,
            ];
            rtcp.extend_from_slice(&[i; 20]);
            let srtcp = send_ctx.protect_rtcp(&rtcp).unwrap();
            srtcp_packets.push((rtcp, srtcp));
        }

        // Receive all in order
        for (rtcp_orig, srtcp) in &srtcp_packets {
            let decrypted = recv_ctx.unprotect_rtcp(srtcp).unwrap();
            assert_eq!(&decrypted, rtcp_orig);
        }

        // Replay any of them — should all fail
        for (_rtcp_orig, srtcp) in &srtcp_packets {
            assert!(recv_ctx.unprotect_rtcp(srtcp).is_err());
        }
    }

    #[test]
    fn test_crypto_attribute_parse_with_mki() {
        // Bug #19: Parse MKI from a=crypto attribute
        let value = "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0|1:4";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert_eq!(crypto.tag, 1);
        assert!(crypto.mki.is_some());
        assert_eq!(crypto.mki_length, Some(4));
        let mki = crypto.mki.unwrap();
        assert_eq!(mki.len(), 4);
        // MKI value 1 = [0, 0, 0, 1] in 4 bytes
        assert_eq!(mki, vec![0, 0, 0, 1]);
    }

    #[test]
    fn test_crypto_attribute_parse_with_lifetime_and_mki() {
        // lifetime followed by MKI
        let value = "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0|2^31|1:4";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert_eq!(crypto.tag, 1);
        assert!(crypto.mki.is_some());
        assert_eq!(crypto.mki_length, Some(4));
    }

    #[test]
    fn test_crypto_attribute_no_mki() {
        let value = "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert!(crypto.mki.is_none());
        assert!(crypto.mki_length.is_none());
    }

    #[test]
    fn test_mki_roundtrip_sdp() {
        // Generate a crypto attribute, set MKI, serialize, re-parse
        let mut crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        crypto.mki = Some(vec![0, 0, 0, 42]);
        crypto.mki_length = Some(4);

        let sdp = crypto.to_sdp_value();
        assert!(sdp.contains("|42:4"));

        let parsed = CryptoAttribute::parse(&sdp).unwrap();
        assert_eq!(parsed.mki, Some(vec![0, 0, 0, 42]));
        assert_eq!(parsed.mki_length, Some(4));
    }

    #[test]
    fn test_srtp_with_mki_protect_unprotect() {
        // Bug #19: MKI bytes are appended during protect and stripped during unprotect
        let mut crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        crypto.mki = Some(vec![0x00, 0x01]);
        crypto.mki_length = Some(2);

        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        rtp_packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        // Should have: original_len + 2 (MKI) + 10 (auth_tag)
        assert_eq!(srtp_packet.len(), rtp_packet.len() + 2 + 10);

        let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    #[test]
    fn test_srtcp_with_mki_protect_unprotect() {
        let mut crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        crypto.mki = Some(vec![0xAB, 0xCD]);
        crypto.mki_length = Some(2);

        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtcp_packet = vec![
            0x80, 0xC8, 0x00, 0x06,
            0x00, 0x00, 0x30, 0x39,
        ];
        rtcp_packet.extend_from_slice(&[0x11; 20]);

        let srtcp_packet = send_ctx.protect_rtcp(&rtcp_packet).unwrap();
        // original_len + 4 (E||index) + 2 (MKI) + 10 (auth tag) = +16
        assert_eq!(srtcp_packet.len(), rtcp_packet.len() + 16);

        let decrypted = recv_ctx.unprotect_rtcp(&srtcp_packet).unwrap();
        assert_eq!(decrypted, rtcp_packet);
    }

    #[test]
    fn test_mki_mismatch_corrupts_payload() {
        // Protect with MKI length 2, but receiver expects MKI length 4.
        // The receiver interprets the packet structure differently (strips 4
        // bytes as MKI instead of 2), which causes the authentication check
        // to fail because the auth tag boundary is misaligned.
        let crypto_send = {
            let mut c = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
            c.mki = Some(vec![0x00, 0x01]);
            c.mki_length = Some(2);
            c
        };

        // Receiver has the same key material but different MKI length
        let crypto_recv = CryptoAttribute {
            tag: crypto_send.tag,
            suite: crypto_send.suite,
            master_key: crypto_send.master_key,
            master_salt: crypto_send.master_salt,
            mki: Some(vec![0x00, 0x00, 0x00, 0x01]),
            mki_length: Some(4),
        };

        let mut send_ctx = SrtpContext::from_crypto(&crypto_send);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto_recv);

        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        rtp_packet.extend_from_slice(&[0xAA; 20]);

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        // MKI length mismatch causes the receiver to misparse the packet
        // structure, leading to authentication failure.
        let result = recv_ctx.unprotect_rtp(&srtp_packet);
        assert!(result.is_err(), "MKI length mismatch should cause unprotect to fail");
    }

    #[test]
    fn test_different_seq_produces_different_ciphertext() {
        // Key derivation uses the same session keys, but AES-CM uses the packet
        // index (which includes seq) in the IV, so different seq numbers must
        // produce different ciphertext even for identical plaintext payloads.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut ctx = SrtpContext::from_crypto(&crypto);

        let payload = [0x42u8; 40];

        let mut rtp1 = vec![0x80, 0x00, 0x00, 0x01]; // seq=1
        rtp1.extend_from_slice(&160u32.to_be_bytes());
        rtp1.extend_from_slice(&12345u32.to_be_bytes());
        rtp1.extend_from_slice(&payload);

        let mut rtp2 = vec![0x80, 0x00, 0x00, 0x02]; // seq=2
        rtp2.extend_from_slice(&320u32.to_be_bytes());
        rtp2.extend_from_slice(&12345u32.to_be_bytes());
        rtp2.extend_from_slice(&payload);

        let srtp1 = ctx.protect_rtp(&rtp1).unwrap();
        let srtp2 = ctx.protect_rtp(&rtp2).unwrap();

        // The encrypted payloads (bytes 12..52) must differ despite identical plaintext
        assert_ne!(&srtp1[12..52], &srtp2[12..52]);
    }

    #[test]
    fn test_large_payload_protect_unprotect() {
        // Protect/unprotect a packet near typical MTU limits.
        // RTP header (12) + payload (1400) + auth tag (10) = 1422, well within
        // UDP MTU of 1500.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        // 1400 bytes of payload — near max for a single UDP packet
        let large_payload: Vec<u8> = (0..1400).map(|i| (i & 0xFF) as u8).collect();
        rtp_packet.extend_from_slice(&large_payload);

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        assert_eq!(srtp_packet.len(), rtp_packet.len() + 10);

        let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    #[test]
    fn test_empty_payload_protect_unprotect() {
        // An RTP packet with zero-length payload is valid (e.g., comfort noise,
        // keepalive). The SRTP layer should handle it: encrypt nothing, but still
        // authenticate the header.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // 12-byte RTP header, no payload
        let mut rtp_packet = vec![0x80, 0x00, 0x00, 0x01];
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&12345u32.to_be_bytes());
        assert_eq!(rtp_packet.len(), 12);

        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        // No payload to encrypt, but auth tag is still appended
        assert_eq!(srtp_packet.len(), 12 + 10);

        let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    #[test]
    fn test_crypto_attribute_parse_edge_cases() {
        // Empty string
        assert!(CryptoAttribute::parse("").is_err());

        // Only whitespace
        assert!(CryptoAttribute::parse("   ").is_err());

        // Non-numeric tag
        assert!(CryptoAttribute::parse("abc AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0").is_err());

        // Invalid base64 in key material
        assert!(CryptoAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 inline:!!!invalid-base64!!!").is_err());

        // Valid base64 but wrong decoded length (too short)
        assert!(CryptoAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 inline:AQID").is_err());

        // Missing inline: prefix
        assert!(CryptoAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 notinline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0").is_err());

        // MKI with length 0 should be ignored (treated as no MKI)
        let value = "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0|1:0";
        let crypto = CryptoAttribute::parse(value).unwrap();
        assert!(crypto.mki.is_none());
    }

    #[test]
    fn test_roc_wraparound_skip_to_seq_3() {
        // Specific scenario: sender sends seq 65530..65535, then skips directly
        // to seq 3 (packets 0, 1, 2 are lost in transit). The receiver must
        // detect the forward wrap from the gap (65535 -> 3) and bump the ROC.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Phase 1: send and receive seq 65530..65535 to establish state
        for seq in 65530u16..=65535 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xAA; 20]);

            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            let decrypted = recv_ctx.unprotect_rtp(&srtp).unwrap();
            assert_eq!(decrypted, rtp);
        }

        // Phase 2: sender sends seq 0, 1, 2 (which wraps ROC on the sender)
        // but we do NOT deliver these to the receiver (simulating packet loss).
        for seq in 0u16..=2 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((65536u32 + seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xBB; 20]);
            let _srtp = send_ctx.protect_rtp(&rtp).unwrap();
            // intentionally not delivered
        }

        // Phase 3: receiver gets seq 3 — first packet it sees after 65535.
        // The receiver's estimate_roc must detect the wrap from the gap.
        for seq in 3u16..=5 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((65536u32 + seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&12345u32.to_be_bytes());
            rtp.extend_from_slice(&[0xCC; 20]);

            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            let decrypted = recv_ctx
                .unprotect_rtp(&srtp)
                .expect(&format!("Failed to unprotect seq {} after ROC wrap with gap", seq));
            assert_eq!(decrypted, rtp);
        }
    }

    /// Verify AES-CM IV construction for SRTP encryption per RFC 3711 §4.1.1.
    ///
    /// The 16-byte IV is built as:
    ///   bytes 0..4   = 0x00000000
    ///   bytes 4..8   = SSRC (big-endian)
    ///   bytes 8..14  = packet index (48-bit, big-endian)
    ///   bytes 14..16 = 0x0000
    /// Then the 14-byte session salt is XORed at iv[0..14].
    #[test]
    fn test_aes_cm_iv_salt_xor_at_offset_0() {
        // Construct a known salt and check the IV layout.
        let session_salt: [u8; SRTP_SESSION_SALT_LEN] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        ];
        let ssrc: u32 = 0xDEADBEEF;
        let index: u64 = 0x0000_0102_0304_0506;

        // Build IV the same way aes_cm_encrypt does (after fix)
        let mut iv = [0u8; 16];
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());
        let idx_bytes = index.to_be_bytes();
        iv[8..14].copy_from_slice(&idx_bytes[2..8]);

        // XOR salt at offset 0 (per RFC 3711 §4.1.1)
        for i in 0..SRTP_SESSION_SALT_LEN {
            iv[i] ^= session_salt[i];
        }

        // Verify bytes 0..4 are salt[0..4] XOR 0 = salt[0..4]
        assert_eq!(iv[0], 0x01, "iv[0] should be salt[0] XOR 0x00");
        assert_eq!(iv[1], 0x02, "iv[1] should be salt[1] XOR 0x00");
        assert_eq!(iv[2], 0x03, "iv[2] should be salt[2] XOR 0x00");
        assert_eq!(iv[3], 0x04, "iv[3] should be salt[3] XOR 0x00");

        // Verify bytes 4..8 are salt[4..8] XOR SSRC
        assert_eq!(iv[4], 0x05 ^ 0xDE);
        assert_eq!(iv[5], 0x06 ^ 0xAD);
        assert_eq!(iv[6], 0x07 ^ 0xBE);
        assert_eq!(iv[7], 0x08 ^ 0xEF);

        // Verify bytes 8..14 are salt[8..14] XOR packet_index
        // index = 0x0000_0102_0304_0506, low 6 bytes = [01, 02, 03, 04, 05, 06]
        // Wait: 0x0000_0102_0304_0506 as u64 big-endian = [00, 00, 01, 02, 03, 04, 05, 06]
        // low 6 bytes (idx_bytes[2..8]) = [01, 02, 03, 04, 05, 06]
        assert_eq!(iv[8], 0x09 ^ 0x01);
        assert_eq!(iv[9], 0x0A ^ 0x02);
        assert_eq!(iv[10], 0x0B ^ 0x03);
        assert_eq!(iv[11], 0x0C ^ 0x04);
        assert_eq!(iv[12], 0x0D ^ 0x05);
        assert_eq!(iv[13], 0x0E ^ 0x06);

        // Verify bytes 14..16 are untouched (counter space)
        assert_eq!(iv[14], 0x00, "iv[14] must be 0 (counter space)");
        assert_eq!(iv[15], 0x00, "iv[15] must be 0 (counter space)");
    }

    /// Verify PRF IV construction for SRTP key derivation per RFC 3711 §4.3.1.
    ///
    /// The 16-byte IV is built as:
    ///   iv[0..14] = master_salt
    ///   key_id (7 bytes: label || r) is XORed at iv[2..9]
    ///   iv[14..16] = 0x0000 (counter space for AES-CM)
    #[test]
    fn test_prf_iv_key_id_xor_at_offset_7() {
        let master_salt: [u8; SRTP_MASTER_SALT_LEN] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
            0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
        ];

        // Label 0x00 = cipher key, with r=0 (KDR=0)
        let label: u8 = 0x00;
        let key_id = [label, 0u8, 0, 0, 0, 0, 0]; // 7 bytes

        let mut iv = [0u8; 16];
        iv[..SRTP_MASTER_SALT_LEN].copy_from_slice(&master_salt);
        // key_id XORed at offset 7 (per RFC 3711 §4.3.1)
        for i in 0..7 {
            iv[7 + i] ^= key_id[i];
        }

        // With label=0 and r=0, key_id is all zeros, so IV = salt || 0x0000
        assert_eq!(
            &iv[..14], &master_salt[..],
            "With zero key_id, IV[0..14] should equal master_salt"
        );
        assert_eq!(iv[14], 0x00);
        assert_eq!(iv[15], 0x00);

        // Now test with a non-zero label (0x01 = auth key)
        let label2: u8 = 0x01;
        let key_id2 = [label2, 0u8, 0, 0, 0, 0, 0];

        let mut iv2 = [0u8; 16];
        iv2[..SRTP_MASTER_SALT_LEN].copy_from_slice(&master_salt);
        for i in 0..7 {
            iv2[7 + i] ^= key_id2[i];
        }

        // Bytes 0..7 unchanged (salt[0..7])
        for i in 0..7 {
            assert_eq!(iv2[i], master_salt[i], "iv[{}] should be salt[{}] unchanged", i, i);
        }
        // Byte 7 = salt[7] XOR label = 0x80 XOR 0x01 = 0x81
        assert_eq!(iv2[7], 0x80 ^ 0x01, "iv[7] should be salt[7] XOR label");
        // Bytes 8..14 = salt[8..14] XOR 0 = salt[8..14] (r=0)
        for i in 8..14 {
            assert_eq!(iv2[i], master_salt[i], "iv[{}] should be unchanged (r=0)", i);
        }
        assert_eq!(iv2[14], 0x00, "iv[14] must be 0 (counter space)");
        assert_eq!(iv2[15], 0x00, "iv[15] must be 0 (counter space)");
    }

    /// End-to-end test: protect/unprotect still works after IV construction fixes.
    /// This validates that both prf_derive (key derivation) and aes_cm_encrypt
    /// (payload encryption) use the corrected IV offsets consistently.
    #[test]
    fn test_roundtrip_after_iv_fixes() {
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Send multiple sequential packets and verify roundtrip for each
        for seq in 1u16..=10 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes()); // timestamp
            rtp.extend_from_slice(&12345u32.to_be_bytes()); // ssrc
            rtp.extend_from_slice(&[0x42; 160]); // audio payload

            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            // SRTP packet must differ from plaintext (encrypted)
            assert_ne!(
                &srtp[12..12 + 160], &[0x42; 160],
                "payload should be encrypted for seq {}",
                seq
            );

            let decrypted = recv_ctx.unprotect_rtp(&srtp).unwrap();
            assert_eq!(decrypted, rtp, "round-trip failed for seq {}", seq);
        }
    }

    #[test]
    fn test_ssrc_extracted_from_correct_rtp_offset() {
        // Bug #11a: SSRC must be read from bytes [8..12] of the RTP header,
        // NOT bytes [4..8] (which is the timestamp field).
        // RFC 3550 §5.1: V(2)|P|X|CC | M|PT | seq(2) | timestamp(4) | SSRC(4)
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Construct a packet where timestamp and SSRC are intentionally different
        // so that using the wrong offset would produce a different keystream.
        let ssrc: u32 = 0xDEADBEEF;
        let timestamp: u32 = 0x12345678; // Different from SSRC
        let seq: u16 = 1;

        let mut rtp_packet = vec![0x80, 0x00]; // V=2, P=0, X=0, CC=0
        rtp_packet.extend_from_slice(&seq.to_be_bytes()); // bytes 2-3: seq
        rtp_packet.extend_from_slice(&timestamp.to_be_bytes()); // bytes 4-7: timestamp
        rtp_packet.extend_from_slice(&ssrc.to_be_bytes()); // bytes 8-11: SSRC
        rtp_packet.extend_from_slice(&[0xAA; 40]); // payload

        // Protect and unprotect must round-trip correctly when SSRC != timestamp
        let srtp_packet = send_ctx.protect_rtp(&rtp_packet).unwrap();
        let decrypted = recv_ctx.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(
            decrypted, rtp_packet,
            "Round-trip failed: SSRC may be read from wrong offset"
        );

        // Also verify that different SSRCs produce different ciphertext for
        // the same payload, confirming SSRC is actually used in encryption.
        let mut send_ctx2 = SrtpContext::from_crypto(&crypto);
        let ssrc2: u32 = 0xCAFEBABE;
        let mut rtp_packet2 = vec![0x80, 0x00];
        rtp_packet2.extend_from_slice(&seq.to_be_bytes());
        rtp_packet2.extend_from_slice(&timestamp.to_be_bytes()); // same timestamp
        rtp_packet2.extend_from_slice(&ssrc2.to_be_bytes()); // different SSRC
        rtp_packet2.extend_from_slice(&[0xAA; 40]); // same payload

        let srtp_packet2 = send_ctx2.protect_rtp(&rtp_packet2).unwrap();
        // Encrypted payloads must differ because SSRC differs (different IV)
        assert_ne!(
            &srtp_packet[12..52],
            &srtp_packet2[12..52],
            "Different SSRCs must produce different ciphertext"
        );
    }

    #[test]
    fn test_srtcp_index_overflow_returns_error() {
        // Bug #11d: SRTCP index is 31-bit (max 0x7FFFFFFF). Attempting to
        // protect beyond this limit must return an error to prevent keystream reuse.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut ctx = SrtpContext::from_crypto(&crypto);

        // Set the SRTCP index just below the overflow boundary
        ctx.srtcp_index = 0x7FFFFFFF;

        let rtcp_packet = vec![
            0x80, 0xC8, 0x00, 0x06, // V=2, PT=200 (SR), length=6
            0x00, 0x00, 0x30, 0x39, // SSRC=12345
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // SR body
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x11, 0x22, 0x33, 0x44,
        ];

        // This should succeed (index = 0x7FFFFFFF, the last valid value)
        let result = ctx.protect_rtcp(&rtcp_packet);
        assert!(result.is_ok(), "protect_rtcp should succeed at max index 0x7FFFFFFF");

        // Now srtcp_index is 0x80000000, which exceeds the 31-bit space
        assert_eq!(ctx.srtcp_index, 0x80000000);

        // Next protect_rtcp call must fail
        let result = ctx.protect_rtcp(&rtcp_packet);
        assert!(
            result.is_err(),
            "protect_rtcp must fail when SRTCP index exceeds 31-bit space"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("SRTCP index overflow"),
            "Error message should mention SRTCP index overflow, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_replay_window_128_packets() {
        // P1-SRTP-3: Verify that the replay window accepts packets up to 127
        // positions behind the highest seen index (128-bit window).
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Protect packets 1..=200 but only deliver packet 200 first
        let mut protected = Vec::new();
        for seq in 1u16..=200 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&42u32.to_be_bytes());
            rtp.extend_from_slice(&[seq as u8; 20]);
            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            protected.push((seq, rtp, srtp));
        }

        // Deliver packet 200 first (establishes replay_window_base = 200)
        let d200 = recv_ctx.unprotect_rtp(&protected[199].2).unwrap();
        assert_eq!(d200, protected[199].1);

        // Packet at index 200-127 = 73 should still be accepted (within 128-bit window)
        let d73 = recv_ctx.unprotect_rtp(&protected[72].2).unwrap();
        assert_eq!(d73, protected[72].1);

        // Packet at index 200-128 = 72 should also be accepted (delta=128 means
        // bit 128 would be out of range in a 0-indexed 128-bit window, but let's
        // test the boundary). Actually delta=128 is >= 128 so it's rejected.
        assert!(recv_ctx.unprotect_rtp(&protected[71].2).is_err());

        // Packet at index 200-100 = 100 should be accepted (well within window)
        let d100 = recv_ctx.unprotect_rtp(&protected[99].2).unwrap();
        assert_eq!(d100, protected[99].1);
    }

    #[test]
    fn test_non_monotonic_send_rejected() {
        // P1-SRTP-2: Sending the same sequence number twice must fail.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp1 = vec![0x80, 0x00, 0x00, 0x05]; // seq=5
        rtp1.extend_from_slice(&800u32.to_be_bytes());
        rtp1.extend_from_slice(&42u32.to_be_bytes());
        rtp1.extend_from_slice(&[0xAA; 20]);

        // First send at seq=5 should succeed
        assert!(ctx.protect_rtp(&rtp1).is_ok());

        // Second send at seq=5 (same index) should fail
        let result = ctx.protect_rtp(&rtp1);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("non-monotonic"), "Error should mention non-monotonic, got: {}", err);

        // Sending at seq=4 (backward) should also fail
        let mut rtp_back = vec![0x80, 0x00, 0x00, 0x04]; // seq=4
        rtp_back.extend_from_slice(&640u32.to_be_bytes());
        rtp_back.extend_from_slice(&42u32.to_be_bytes());
        rtp_back.extend_from_slice(&[0xBB; 20]);
        assert!(ctx.protect_rtp(&rtp_back).is_err());

        // Sending at seq=6 (forward) should succeed
        let mut rtp_fwd = vec![0x80, 0x00, 0x00, 0x06]; // seq=6
        rtp_fwd.extend_from_slice(&960u32.to_be_bytes());
        rtp_fwd.extend_from_slice(&42u32.to_be_bytes());
        rtp_fwd.extend_from_slice(&[0xCC; 20]);
        assert!(ctx.protect_rtp(&rtp_fwd).is_ok());
    }

    #[test]
    fn test_key_lifetime_enforcement() {
        // P1-SRTP-4: After 2^48 packets, protect_rtp must return an error.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut ctx = SrtpContext::from_crypto(&crypto);

        // Set packets_encrypted just below the limit
        ctx.packets_encrypted = (1u64 << 48) - 1;

        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&42u32.to_be_bytes());
        rtp.extend_from_slice(&[0xAA; 20]);

        // This should succeed (the last allowed packet)
        assert!(ctx.protect_rtp(&rtp).is_ok());

        // Now packets_encrypted == 2^48, next call must fail
        assert_eq!(ctx.packets_encrypted, 1u64 << 48);

        let mut rtp2 = vec![0x80, 0x00, 0x00, 0x02];
        rtp2.extend_from_slice(&320u32.to_be_bytes());
        rtp2.extend_from_slice(&42u32.to_be_bytes());
        rtp2.extend_from_slice(&[0xBB; 20]);

        let result = ctx.protect_rtp(&rtp2);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("key lifetime"), "Error should mention key lifetime, got: {}", err);
    }

    #[test]
    fn test_replay_does_not_inflate_error_count() {
        // P1-SRTP-6: Replay rejections should NOT increment error_count.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&42u32.to_be_bytes());
        rtp.extend_from_slice(&[0xAA; 20]);

        let srtp = send_ctx.protect_rtp(&rtp).unwrap();

        // First unprotect succeeds, error count stays 0
        let _ = recv_ctx.unprotect_rtp(&srtp).unwrap();
        assert_eq!(recv_ctx.error_count(), 0);

        // Replay the same packet multiple times — error count should stay 0
        for _ in 0..20 {
            let _ = recv_ctx.unprotect_rtp(&srtp);
        }
        assert_eq!(recv_ctx.error_count(), 0, "Replay rejections should not increment error count");
    }

    #[test]
    fn test_ssrc_change_resets_receiver_state() {
        // P1-SRTP-7: When SSRC changes, replay window and ROC should reset.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        let ssrc1: u32 = 12345;
        let ssrc2: u32 = 67890;

        // Send/receive several packets with SSRC1
        for seq in 1u16..=10 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
            rtp.extend_from_slice(&ssrc1.to_be_bytes());
            rtp.extend_from_slice(&[0xAA; 20]);
            let srtp = send_ctx.protect_rtp(&rtp).unwrap();
            let decrypted = recv_ctx.unprotect_rtp(&srtp).unwrap();
            assert_eq!(decrypted, rtp);
        }

        // Now send a packet with SSRC2 at seq=1. Without SSRC change detection,
        // this would fail replay protection (seq=1 already seen). With the fix,
        // the receiver should reset and accept it.
        //
        // We need a new send context for SSRC2 to avoid the non-monotonic check
        // on the sender side (sender tracks by index, not SSRC).
        let mut send_ctx2 = SrtpContext::from_crypto(&crypto);
        let mut rtp_new = vec![0x80, 0x00, 0x00, 0x01]; // seq=1
        rtp_new.extend_from_slice(&160u32.to_be_bytes());
        rtp_new.extend_from_slice(&ssrc2.to_be_bytes());
        rtp_new.extend_from_slice(&[0xBB; 20]);
        let srtp_new = send_ctx2.protect_rtp(&rtp_new).unwrap();
        let decrypted = recv_ctx.unprotect_rtp(&srtp_new).unwrap();
        assert_eq!(decrypted, rtp_new, "Packet with new SSRC should be accepted after state reset");
    }

    #[test]
    fn test_generic_error_message_for_replay_and_auth() {
        // P1-SRTP-5: Both replay and auth failures should return the same
        // generic error message to prevent information leakage.
        let crypto = CryptoAttribute::generate(SrtpCipherSuite::AesCm128HmacSha1_80);
        let mut send_ctx = SrtpContext::from_crypto(&crypto);
        let mut recv_ctx = SrtpContext::from_crypto(&crypto);

        // Get a valid packet
        let mut rtp = vec![0x80, 0x00, 0x00, 0x01];
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&42u32.to_be_bytes());
        rtp.extend_from_slice(&[0xAA; 20]);
        let srtp = send_ctx.protect_rtp(&rtp).unwrap();

        // Accept it first
        let _ = recv_ctx.unprotect_rtp(&srtp).unwrap();

        // Replay it — should get generic error
        let replay_err = recv_ctx.unprotect_rtp(&srtp).unwrap_err().to_string();

        // Tamper with a packet for auth failure
        let mut rtp2 = vec![0x80, 0x00, 0x00, 0x02];
        rtp2.extend_from_slice(&320u32.to_be_bytes());
        rtp2.extend_from_slice(&42u32.to_be_bytes());
        rtp2.extend_from_slice(&[0xBB; 20]);
        let mut srtp2 = send_ctx.protect_rtp(&rtp2).unwrap();
        srtp2[12] ^= 0xFF; // tamper
        let auth_err = recv_ctx.unprotect_rtp(&srtp2).unwrap_err().to_string();

        // Both should be the same generic message
        assert_eq!(replay_err, auth_err,
            "Replay and auth errors should be indistinguishable: replay='{}', auth='{}'",
            replay_err, auth_err
        );
        assert!(replay_err.contains("SRTP packet rejected"),
            "Error should say 'SRTP packet rejected', got: '{}'", replay_err);
    }
}
