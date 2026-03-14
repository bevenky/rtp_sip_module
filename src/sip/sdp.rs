//! SDP (Session Description Protocol) parsing and generation
//!
//! Handles SDP for RTP media negotiation in SIP calls.
//!
//! # Edge Cases Handled (Inbound & Outbound)
//!
//! ## Port Handling
//! - **Port 0**: Stream disabled/rejected (RFC 3264 Section 6). Remote explicitly
//!   rejects the media stream. Must not attempt to send media.
//! - **Port range** (`m=audio 10000/2`): Multiple ports for RTP/RTCP. We extract
//!   base port only (common practice).
//!
//! ## Hold Detection (RFC 3264, RFC 6337)
//! - **c=0.0.0.0**: Legacy hold method (RFC 2543). Deprecated but still common
//!   with older equipment (Orc, some Avaya systems). Treat as hold.
//! - **a=sendonly**: Local party initiating hold. Remote should respond recvonly.
//! - **a=recvonly**: Remote is on hold, we receive only.
//! - **a=inactive**: Bidirectional hold (both parties on hold).
//! - **Session vs media level**: c= at session level applies to all media unless
//!   overridden at media level. Direction attributes same logic.
//!
//! ## Codec Negotiation
//! - **Static payload types (0, 8)**: PCMU/PCMA don't require rtpmap per RFC 3551.
//!   We handle missing rtpmap for these.
//! - **Dynamic payload types (96-127)**: Must have rtpmap. Used for telephone-event.
//! - **Greedy mode**: Local preference wins - iterate our codec list, first match
//!   in remote offer is selected. Ensures predictable codec selection.
//!
//! ## Telephone-Event (RFC 2833/4733)
//! - **Variable PT**: Usually 101, but can be any dynamic PT (96-127). We detect
//!   from rtpmap, not hardcoded.
//! - **fmtp line**: `a=fmtp:101 0-15` specifies supported events (16 DTMF digits,
//!   events 0-15). We now parse remote fmtp and generate the correct range.
//!
//! ## SDP Variations Between Responses
//! - **Different SDP in 183 vs 200 OK**: Common with mobile carriers and some
//!   PBX systems. Port, codec, or IP may change. We re-parse and update RTP
//!   session on each SDP received.
//! - **183 without SDP**: Treat as 180 Ringing (no early media).
//!
//! ## IP Address Handling
//! - **IPv4/IPv6**: Both supported in c= line (IN IP4/IN IP6).
//! - **NAT traversal**: We use the IP from SDP as-is. For NAT scenarios, the
//!   endpoint should provide public IP or use STUN/TURN.
//!
//! ## Known Limitations
//! - Only first audio stream processed (multiple m=audio lines ignored).
//! - Video streams ignored.
//! - Encryption (SRTP) attributes not parsed.

use crate::error::{Result, RtpSipError};
use crate::rtp::CodecType;
use std::net::{IpAddr, SocketAddr};

/// Media direction attribute (RFC 3264)
///
/// Used for hold/resume and one-way media scenarios. Works identically for
/// inbound and outbound calls.
///
/// # Perspective (P2-SIP-1)
///
/// Direction attributes describe the media flow from the **sender's perspective**
/// (the party that includes the attribute in their SDP):
///
/// - `sendonly`: The SDP sender will only send media, and expects the remote
///   to not send (i.e., the sender is putting the remote on hold).
/// - `recvonly`: The SDP sender will only receive media, and expects the remote
///   to send. This is typically the **response** to a `sendonly` offer -- the
///   remote acknowledges that it will receive-only.
/// - `inactive`: Neither party sends media.
/// - `sendrecv`: Both parties send and receive (default).
///
/// When **we** see `recvonly` in a **remote** SDP, it means the remote will
/// only receive -- so from our perspective, we should only send. Conversely,
/// when we see `sendonly` in remote SDP, the remote will only send -- so we
/// should only receive.
///
/// # Hold/Resume Semantics (RFC 6337)
///
/// When putting a call on hold:
/// - Local sends re-INVITE with `a=sendonly` (we can send, remote should stop)
/// - Remote responds with `a=recvonly` (they receive, won't send)
///
/// When resuming:
/// - Local sends re-INVITE with `a=sendrecv`
/// - Remote responds with `a=sendrecv`
///
/// # Edge Cases
///
/// - **Both on hold**: Use `a=inactive`. Neither party sends media.
/// - **Music on hold**: Holder uses `a=sendonly` and sends MOH audio.
/// - **Default**: If no direction attribute, `sendrecv` is implied (RFC 3264).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediaDirection {
    /// Bidirectional media (default)
    #[default]
    SendRecv,
    /// Send-only from SDP sender's perspective (sender holds, remote receives)
    SendOnly,
    /// Receive-only from SDP sender's perspective (sender receives, remote sends)
    RecvOnly,
    /// No media in either direction (both on hold)
    Inactive,
}

impl MediaDirection {
    /// Parse from SDP attribute value
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sendrecv" => Some(Self::SendRecv),
            "sendonly" => Some(Self::SendOnly),
            "recvonly" => Some(Self::RecvOnly),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }

    /// Check if this direction indicates a hold state
    pub fn is_held(&self) -> bool {
        matches!(self, Self::SendOnly | Self::Inactive)
    }

    /// Get the expected answer direction per RFC 3264
    ///
    /// sendrecv -> sendrecv
    /// sendonly -> recvonly
    /// recvonly -> sendonly
    /// inactive -> inactive
    pub fn answer_direction(&self) -> Self {
        match self {
            Self::SendRecv => Self::SendRecv,
            Self::SendOnly => Self::RecvOnly,
            Self::RecvOnly => Self::SendOnly,
            Self::Inactive => Self::Inactive,
        }
    }

    /// Convert to SDP attribute string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }
}

/// Media description from SDP
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media type (audio, video, etc.)
    pub media_type: String,
    /// Port number (0 = stream disabled/rejected)
    pub port: u16,
    /// Protocol (RTP/AVP, RTP/SAVP, etc.)
    pub protocol: String,
    /// Payload types
    pub payload_types: Vec<u8>,
    /// Connection address (if different from session-level)
    pub connection: Option<IpAddr>,
    /// RTP map entries (payload_type -> codec info)
    pub rtpmap: Vec<RtpMapEntry>,
    /// fmtp entries (payload_type -> format parameters string)
    /// Bug #57: Parse fmtp lines from remote SDP (e.g., `a=fmtp:101 0-15`)
    pub fmtp: Vec<(u8, String)>,
    /// Attributes
    pub attributes: Vec<String>,
    /// Media direction (sendrecv/sendonly/recvonly/inactive)
    pub direction: MediaDirection,
    /// P2-SIP-9: Parsed ptime value from remote SDP (packetization time in ms)
    pub ptime: Option<u32>,
}

impl MediaDescription {
    /// Check if this media stream is disabled (port 0)
    pub fn is_disabled(&self) -> bool {
        self.port == 0
    }

    /// Check if this stream is on hold (via direction or legacy c=0.0.0.0)
    pub fn is_held(&self, session_connection: Option<IpAddr>) -> bool {
        // Check direction attribute
        if self.direction.is_held() {
            return true;
        }

        // Check legacy hold method: c=0.0.0.0
        let conn = self.connection.or(session_connection);
        if let Some(ip) = conn {
            if ip.is_unspecified() {
                return true;
            }
        }

        false
    }

    /// Check if this stream has media capability
    pub fn has_media(&self) -> bool {
        !self.is_disabled() && !self.payload_types.is_empty()
    }
}

/// RTP map entry (a=rtpmap:)
#[derive(Debug, Clone)]
pub struct RtpMapEntry {
    pub payload_type: u8,
    pub encoding_name: String,
    pub clock_rate: u32,
    pub channels: Option<u8>,
}

/// Parsed SDP
#[derive(Debug, Clone)]
pub struct Sdp {
    /// Session version
    pub version: u8,
    /// Origin line
    pub origin: SdpOrigin,
    /// Session name
    pub session_name: String,
    /// Connection address (session-level)
    pub connection: Option<IpAddr>,
    /// Media descriptions
    pub media: Vec<MediaDescription>,
    /// Session attributes
    pub attributes: Vec<String>,
}

/// SDP origin (o= line)
#[derive(Debug, Clone)]
pub struct SdpOrigin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub net_type: String,
    pub addr_type: String,
    pub address: String,
}

impl Default for SdpOrigin {
    fn default() -> Self {
        Self {
            username: "-".to_string(),
            session_id: rand::random::<u64>() % 10_000_000_000,
            session_version: 1,
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "0.0.0.0".to_string(),
        }
    }
}

impl Sdp {
    /// Parse SDP from string
    pub fn parse(sdp_str: &str) -> Result<Self> {
        let mut version = 0u8;
        let mut origin = SdpOrigin::default();
        let mut session_name = String::new();
        let mut connection: Option<IpAddr> = None;
        let mut media: Vec<MediaDescription> = Vec::new();
        let mut session_attributes: Vec<String> = Vec::new();
        let mut current_media: Option<MediaDescription> = None;
        // Bug #79: Track which media descriptions have explicit direction attributes
        let mut media_has_direction: Vec<bool> = Vec::new();
        let mut current_has_direction = false;
        // Bug #58: Track which mandatory fields are present
        let mut has_version = false;
        let mut has_origin = false;
        let mut has_session_name = false;
        // P2-SIP-8: Track whether t= line is present
        let mut has_timing = false;

        for line in sdp_str.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.len() < 2 || line.chars().nth(1) != Some('=') {
                continue;
            }

            let type_char = line.chars().next().unwrap();
            let value = &line[2..];

            match type_char {
                'v' => {
                    // Bug #106: Warn when version parsing fails instead of
                    // silently defaulting to 0.
                    version = match value.parse() {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::warn!(
                                "SDP version line 'v={}' is not a valid integer, \
                                 defaulting to 0",
                                value
                            );
                            0
                        }
                    };
                    has_version = true;
                }
                'o' => {
                    origin = Self::parse_origin(value)?;
                    has_origin = true;
                }
                's' => {
                    session_name = value.to_string();
                    has_session_name = true;
                }
                'c' => {
                    let addr = Self::parse_connection(value)?;
                    if current_media.is_some() {
                        current_media.as_mut().unwrap().connection = Some(addr);
                    } else {
                        connection = Some(addr);
                    }
                }
                'm' => {
                    // Save previous media if exists
                    if let Some(m) = current_media.take() {
                        media.push(m);
                        media_has_direction.push(current_has_direction);
                    }
                    current_media = Some(Self::parse_media_line(value)?);
                    current_has_direction = false;
                }
                'a' => {
                    if let Some(ref mut m) = current_media {
                        if value.starts_with("rtpmap:") {
                            if let Ok(entry) = Self::parse_rtpmap(&value[7..]) {
                                m.rtpmap.push(entry);
                            }
                        } else if value.starts_with("ptime:") {
                            // R17: Parse ptime attribute (packetization time)
                            m.ptime = value[6..].trim().parse().ok();
                        } else if value.starts_with("fmtp:") {
                            // Bug #57: Parse fmtp lines (e.g., "fmtp:101 0-15")
                            if let Some((pt_str, params)) = value[5..].split_once(' ') {
                                if let Ok(pt) = pt_str.parse::<u8>() {
                                    m.fmtp.push((pt, params.to_string()));
                                }
                            }
                            m.attributes.push(value.to_string());
                        } else if let Some(dir) = MediaDirection::from_str(value) {
                            // Parse direction attribute (sendrecv/sendonly/recvonly/inactive)
                            m.direction = dir;
                            current_has_direction = true;
                        } else {
                            m.attributes.push(value.to_string());
                        }
                    } else {
                        // Session-level attributes (including direction)
                        session_attributes.push(value.to_string());
                    }
                }
                't' => {
                    // P2-SIP-8: Track timing line presence
                    has_timing = true;
                }
                _ => {}
            }
        }

        // P2-SIP-8: Warn if t= line is missing (mandatory per RFC 4566)
        if !has_timing {
            tracing::warn!(
                "SDP missing mandatory t= (timing) line; \
                 RFC 4566 requires at least one t= line"
            );
        }

        // Save last media if exists
        if let Some(m) = current_media {
            media.push(m);
            media_has_direction.push(current_has_direction);
        }

        // Bug #79: Propagate session-level direction to media descriptions
        // that don't have their own direction attribute.
        let session_direction = session_attributes.iter().find_map(|attr| {
            MediaDirection::from_str(attr)
        });
        if let Some(dir) = session_direction {
            for (i, m) in media.iter_mut().enumerate() {
                if !media_has_direction.get(i).copied().unwrap_or(false) {
                    m.direction = dir;
                }
            }
        }

        // Bug #58: Validate mandatory SDP fields (v=, o=, s=) are present
        if !has_version {
            return Err(RtpSipError::Sdp(
                "Missing mandatory SDP field: v= (version)".to_string(),
            ));
        }
        if !has_origin {
            return Err(RtpSipError::Sdp(
                "Missing mandatory SDP field: o= (origin)".to_string(),
            ));
        }
        if !has_session_name {
            return Err(RtpSipError::Sdp(
                "Missing mandatory SDP field: s= (session name)".to_string(),
            ));
        }

        Ok(Self {
            version,
            origin,
            session_name,
            connection,
            media,
            attributes: session_attributes,
        })
    }

    fn parse_origin(value: &str) -> Result<SdpOrigin> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(RtpSipError::Sdp("Invalid origin line".to_string()));
        }

        let session_id = parts[1].parse().unwrap_or_else(|e| {
            // Bug #13 fix: Log a warning instead of silently defaulting
            tracing::warn!(
                "Failed to parse SDP origin session_id '{}': {}, defaulting to 0",
                parts[1], e
            );
            0
        });
        let session_version = parts[2].parse().unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to parse SDP origin session_version '{}': {}, defaulting to 1",
                parts[2], e
            );
            1
        });

        Ok(SdpOrigin {
            username: parts[0].to_string(),
            session_id,
            session_version,
            net_type: parts[3].to_string(),
            addr_type: parts[4].to_string(),
            address: parts[5].to_string(),
        })
    }

    fn parse_connection(value: &str) -> Result<IpAddr> {
        // Format: IN IP4 192.168.1.1 or IN IP6 ::1
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(RtpSipError::Sdp("Invalid connection line".to_string()));
        }

        let addr_type = parts[1];
        let addr: IpAddr = parts[2]
            .parse()
            .map_err(|_| RtpSipError::Sdp(format!("Invalid IP address: {}", parts[2])))?;

        // Bug #59: Validate that address type matches the actual address
        match addr_type {
            "IP4" => {
                if !addr.is_ipv4() {
                    return Err(RtpSipError::Sdp(format!(
                        "Address type is IP4 but address '{}' is not IPv4",
                        parts[2]
                    )));
                }
            }
            "IP6" => {
                if !addr.is_ipv6() {
                    return Err(RtpSipError::Sdp(format!(
                        "Address type is IP6 but address '{}' is not IPv6",
                        parts[2]
                    )));
                }
            }
            _ => {
                // Bug #R12-4: Reject unknown address types per RFC 4566.
                // Only IP4 and IP6 are valid. Accepting unknown types could
                // mask malformed SDP from broken endpoints.
                return Err(RtpSipError::Sdp(format!(
                    "Unknown address type '{}' in SDP connection line (expected IP4 or IP6)",
                    addr_type
                )));
            }
        }

        Ok(addr)
    }

    fn parse_media_line(value: &str) -> Result<MediaDescription> {
        // Format: audio 49170 RTP/AVP 0 8 97
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(RtpSipError::Sdp("Invalid media line".to_string()));
        }

        let media_type = parts[0].to_string();
        // Bug #55: Parse port as u32 first, validate 0-65535 range to avoid silent wrapping
        let port_str = parts[1].split('/').next().unwrap_or("0");
        let port_u32: u32 = port_str
            .parse()
            .map_err(|_| RtpSipError::Sdp(format!("Invalid port number: {}", port_str)))?;
        if port_u32 > 65535 {
            return Err(RtpSipError::Sdp(format!(
                "Port {} out of range (0-65535)",
                port_u32
            )));
        }
        let port = port_u32 as u16;
        let protocol = parts[2].to_string();
        // P2-SIP-16: Log debug when payload type parsing fails instead of silently ignoring
        let payload_types: Vec<u8> = parts[3..]
            .iter()
            .filter_map(|s| match s.parse() {
                Ok(pt) => Some(pt),
                Err(_) => {
                    tracing::debug!(
                        "SDP: ignoring unparseable payload type '{}' in m= line",
                        s
                    );
                    None
                }
            })
            .collect();

        Ok(MediaDescription {
            media_type,
            port,
            protocol,
            payload_types,
            connection: None,
            rtpmap: Vec::new(),
            fmtp: Vec::new(),
            attributes: Vec::new(),
            direction: MediaDirection::SendRecv, // Default per RFC 3264
            ptime: None,
        })
    }

    fn parse_rtpmap(value: &str) -> Result<RtpMapEntry> {
        // Format: 0 PCMU/8000 or 97 opus/48000/2
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(RtpSipError::Sdp("Invalid rtpmap".to_string()));
        }

        let payload_type: u8 = parts[0]
            .parse()
            .map_err(|_| RtpSipError::Sdp("Invalid payload type".to_string()))?;

        let codec_parts: Vec<&str> = parts[1].split('/').collect();
        let encoding_name = codec_parts[0].to_string();
        // Bug #56: For dynamic payload types (96-127), clock rate is mandatory in rtpmap.
        // Only default to 8000 for static payload types where rtpmap is optional per RFC 3551.
        let clock_rate: u32 = match codec_parts.get(1).and_then(|s| s.parse().ok()) {
            Some(rate) => rate,
            None => {
                if payload_type >= 96 && payload_type <= 127 {
                    return Err(RtpSipError::Sdp(format!(
                        "Missing clock rate for dynamic payload type {}",
                        payload_type
                    )));
                }
                8000 // Default for static payload types (PCMU=0, PCMA=8, etc.)
            }
        };
        let channels: Option<u8> = codec_parts.get(2).and_then(|s| s.parse().ok());

        Ok(RtpMapEntry {
            payload_type,
            encoding_name,
            clock_rate,
            channels,
        })
    }

    /// Get first audio media description
    pub fn audio(&self) -> Option<&MediaDescription> {
        self.media.iter().find(|m| m.media_type == "audio")
    }

    /// Get RTP address from SDP
    pub fn rtp_addr(&self) -> Option<SocketAddr> {
        let audio = self.audio()?;
        let ip = audio.connection.or(self.connection)?;
        Some(SocketAddr::new(ip, audio.port))
    }

    /// Find codec by payload type
    pub fn find_codec(&self, payload_type: u8) -> Option<CodecType> {
        match payload_type {
            0 => Some(CodecType::Pcmu),
            8 => Some(CodecType::Pcma),
            _ => None,
        }
    }

    /// Get preferred codec from audio media
    pub fn preferred_codec(&self) -> Option<CodecType> {
        let audio = self.audio()?;
        audio
            .payload_types
            .iter()
            .find_map(|&pt| self.find_codec(pt))
    }

    /// Check if remote SDP supports RFC 2833/4733 telephone-event
    ///
    /// Works for both inbound and outbound calls - we detect from remote SDP.
    ///
    /// # Detection Strategy
    ///
    /// 1. **Check rtpmap entries**: Look for `telephone-event` encoding name.
    ///    This is the definitive method per RFC 4733.
    /// 2. **Check attributes**: Some endpoints put telephone-event in attributes
    ///    without proper rtpmap structure.
    /// 3. **Fallback to PT 101**: If 101 is in payload types and not mapped to
    ///    something else, assume it's telephone-event (common convention).
    ///
    /// # Edge Cases Handled
    ///
    /// - **Variable payload type**: PT can be 96-127. Orc uses 101,
    ///   some systems use 96 or 100. We don't hardcode.
    /// - **Case insensitive**: `telephone-event`, `TELEPHONE-EVENT` both work.
    /// - **Clock rate variations**: Usually 8000Hz, but we don't validate strictly.
    /// - **PT 101 used for other codec**: If rtpmap shows 101 is something else
    ///   (rare but possible), we correctly skip it.
    ///
    /// # Returns
    ///
    /// The telephone-event payload type if supported, None otherwise.
    /// Use this to determine if RFC 2833 DTMF can be used.
    pub fn telephone_event_pt(&self) -> Option<u8> {
        let audio = self.audio()?;

        // Check rtpmap entries for telephone-event
        for entry in &audio.rtpmap {
            if entry.encoding_name.eq_ignore_ascii_case("telephone-event") {
                return Some(entry.payload_type);
            }
        }

        // Also check attributes for telephone-event (some SDPs don't use rtpmap struct)
        for attr in &audio.attributes {
            let lower = attr.to_ascii_lowercase();
            if lower.contains("telephone-event") {
                // Try to extract payload type from attribute
                // Format: "rtpmap:101 telephone-event/8000"
                if let Some(pt_str) = attr.strip_prefix("rtpmap:") {
                    if let Some(pt) = pt_str.split_whitespace().next() {
                        if let Ok(pt) = pt.parse::<u8>() {
                            return Some(pt);
                        }
                    }
                }
            }
        }

        // P2-SIP-14: Removed risky fallback that assumed PT 101 is telephone-event
        // without an rtpmap declaration. Only use rtpmap-declared payload types.
        // The old code assumed PT 101 = telephone-event if it was in payload_types
        // but not mapped to something else, which could misidentify other codecs.

        None
    }

    /// Check if remote supports RFC 2833 DTMF
    pub fn supports_rfc2833(&self) -> bool {
        self.telephone_event_pt().is_some()
    }

    /// Bug #57: Get the telephone-event fmtp parameters string from remote SDP.
    ///
    /// Returns the event range string (e.g., "0-15") if an fmtp line exists for
    /// the telephone-event payload type, None otherwise.
    pub fn telephone_event_fmtp(&self) -> Option<String> {
        let audio = self.audio()?;
        let te_pt = self.telephone_event_pt()?;
        audio
            .fmtp
            .iter()
            .find(|(pt, _)| *pt == te_pt)
            .map(|(_, params)| params.clone())
    }

    /// Get media direction for audio stream
    pub fn audio_direction(&self) -> MediaDirection {
        self.audio().map(|a| a.direction).unwrap_or_default()
    }

    /// Check if the call is on hold (any hold method)
    ///
    /// Works for both inbound and outbound calls - detection is SDP-based.
    ///
    /// # Hold Detection Methods (in priority order)
    ///
    /// 1. **Port 0** (`m=audio 0`): Stream disabled/rejected. Strongest signal.
    /// 2. **Direction attribute** (`a=sendonly`, `a=inactive`): Modern hold method.
    /// 3. **Legacy c=0.0.0.0**: Old RFC 2543 hold. Still common with:
    ///    - Orc Media Servers
    ///    - Avaya systems
    ///    - Some Cisco CallManager versions
    ///    - Legacy Asterisk configurations
    ///
    /// # Edge Cases Handled
    ///
    /// - **Session vs media level c=**: If c= is 0.0.0.0 at session level and
    ///   no media-level c= overrides it, treat as hold.
    /// - **recvonly is NOT hold**: Remote is sending to us, we just can't send.
    ///   This is used in one-way scenarios, not hold.
    /// - **Multiple checks**: We check all methods because different endpoints
    ///   use different mechanisms.
    pub fn is_on_hold(&self) -> bool {
        let Some(audio) = self.audio() else {
            return false;
        };

        // Stream disabled
        if audio.is_disabled() {
            return true;
        }

        // Direction-based hold
        if audio.is_held(self.connection) {
            return true;
        }

        // Legacy c=0.0.0.0 at session level
        if let Some(ip) = self.connection {
            if ip.is_unspecified() && audio.connection.is_none() {
                return true;
            }
        }

        false
    }

    /// Negotiate codec (greedy mode - local preference wins)
    ///
    /// Iterates through local preferences and returns the first codec
    /// that the remote also supports.
    pub fn negotiate_codec(&self, local_prefs: &[CodecType]) -> Option<CodecType> {
        let audio = self.audio()?;

        // Prefer local order: iterate local prefs, find first remote match
        for codec in local_prefs {
            let pt = codec.payload_type();
            if audio.payload_types.contains(&pt) {
                return Some(*codec);
            }
        }
        None
    }

    /// Get all supported codecs from remote SDP (in their preference order)
    pub fn remote_codecs(&self) -> Vec<CodecType> {
        let Some(audio) = self.audio() else {
            return Vec::new();
        };

        audio
            .payload_types
            .iter()
            .filter_map(|&pt| self.find_codec(pt))
            .collect()
    }

    /// Check if a specific codec is offered by remote
    pub fn offers_codec(&self, codec: CodecType) -> bool {
        let Some(audio) = self.audio() else {
            return false;
        };
        audio.payload_types.contains(&codec.payload_type())
    }
}

/// SDP Builder for generating SDP offers/answers
///
/// P2-SIP-7: SdpBuilder uses `&mut self` in `build()` because each call increments
/// the session_version in the origin line (RFC 3264 Section 8 requires increasing
/// o= version on re-INVITEs). This is intentional: the builder is meant to be
/// reused across the lifetime of a call, with each build() producing a new SDP
/// with a higher version number. Callers must declare the builder as `mut`.
#[derive(Debug, Clone)]
pub struct SdpBuilder {
    origin: SdpOrigin,
    session_name: String,
    connection: IpAddr,
    audio_port: u16,
    codecs: Vec<CodecType>,
    /// Media direction: sendrecv, sendonly, recvonly, inactive
    direction: String,
    /// Include telephone-event for RFC 2833 DTMF (payload type 101)
    include_telephone_event: bool,
    /// Dynamically selected payload type for telephone-event
    telephone_event_pt: u8,
    /// SDP protocol (e.g., "RTP/AVP" or "RTP/SAVP")
    protocol: String,
    /// Optional SRTP crypto attribute (suite, base64-encoded key)
    crypto: Option<(String, String)>,
}

impl SdpBuilder {
    /// Create a new SDP builder
    pub fn new(local_addr: SocketAddr) -> Self {
        let mut origin = SdpOrigin::default();
        origin.address = local_addr.ip().to_string();
        origin.addr_type = if local_addr.ip().is_ipv6() {
            "IP6".to_string()
        } else {
            "IP4".to_string()
        };

        Self {
            origin,
            session_name: "rtpsip".to_string(),
            connection: local_addr.ip(),
            audio_port: local_addr.port(),
            codecs: vec![CodecType::Pcmu, CodecType::Pcma],
            direction: "sendrecv".to_string(),
            include_telephone_event: true, // RFC 2833 DTMF by default
            telephone_event_pt: 101,
            protocol: "RTP/AVP".to_string(),
            crypto: None,
        }
    }

    /// Enable/disable telephone-event for RFC 2833 DTMF
    pub fn telephone_event(mut self, enabled: bool) -> Self {
        self.include_telephone_event = enabled;
        self
    }

    /// Set session name
    pub fn session_name(mut self, name: &str) -> Self {
        self.session_name = name.to_string();
        self
    }

    /// Set codecs to offer
    pub fn codecs(mut self, codecs: Vec<CodecType>) -> Self {
        self.codecs = codecs;
        self
    }

    /// Set media direction (sendrecv, sendonly, recvonly, inactive)
    /// Used for hold/resume operations
    pub fn direction(mut self, direction: &str) -> Self {
        self.direction = direction.to_string();
        self
    }

    /// P1-SIP-8: Set media protocol (e.g., "RTP/AVP", "RTP/SAVP", "RTP/SAVPF")
    pub fn with_protocol(mut self, proto: &str) -> Self {
        self.protocol = proto.to_string();
        self
    }

    /// P1-SIP-9: Set SRTP crypto attributes for a=crypto line generation
    ///
    /// Generates `a=crypto:1 {suite} inline:{key_base64}` in the SDP output.
    /// Common suites: "AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"
    pub fn with_crypto(mut self, suite: &str, key_base64: &str) -> Self {
        self.crypto = Some((suite.to_string(), key_base64.to_string()));
        self
    }

    /// P2-SIP-17: Select an available dynamic payload type for telephone-event.
    ///
    /// Finds the first dynamic PT (96-127) not already used by the configured codecs.
    /// Call this after setting codecs if you need a non-default PT.
    pub fn select_telephone_event_pt(mut self) -> Self {
        let used_pts: Vec<u8> = self.codecs.iter().map(|c| c.payload_type()).collect();
        for pt in 96..=127u8 {
            if !used_pts.contains(&pt) {
                self.telephone_event_pt = pt;
                break;
            }
        }
        self
    }

    /// Build the SDP string
    ///
    /// Bug #20 fix: Each call to build() increments session_version so that
    /// re-INVITEs carry a higher o= version than the initial INVITE, as
    /// required by RFC 3264 Section 8.
    pub fn build(&mut self) -> String {
        self.origin.session_version += 1;
        let addr_type = if self.connection.is_ipv6() {
            "IP6"
        } else {
            "IP4"
        };

        // Build payload types list
        let mut payload_types: Vec<String> = self
            .codecs
            .iter()
            .map(|c| c.payload_type().to_string())
            .collect();

        // P2-SIP-17: Use dynamically selected telephone-event payload type
        let te_pt = self.telephone_event_pt;
        if self.include_telephone_event {
            payload_types.push(te_pt.to_string());
        }

        // P1-SIP-8: Use configured protocol instead of hardcoded RTP/AVP
        let mut sdp = format!(
            "v=0\r\n\
             o={} {} {} {} {} {}\r\n\
             s={}\r\n\
             c=IN {} {}\r\n\
             t=0 0\r\n\
             m=audio {} {} {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.net_type,
            self.origin.addr_type,
            self.origin.address,
            self.session_name,
            addr_type,
            self.connection,
            self.audio_port,
            self.protocol,
            payload_types.join(" ")
        );

        // P1-SIP-9: Add a=crypto line for SRTP if configured
        if let Some((ref suite, ref key_base64)) = self.crypto {
            sdp.push_str(&format!(
                "a=crypto:1 {} inline:{}\r\n",
                suite, key_base64
            ));
        }

        // Add rtpmap for each codec
        for codec in &self.codecs {
            let (name, rate) = match codec {
                CodecType::Pcmu => ("PCMU", 8000),
                CodecType::Pcma => ("PCMA", 8000),
            };
            sdp.push_str(&format!(
                "a=rtpmap:{} {}/{}\r\n",
                codec.payload_type(),
                name,
                rate
            ));
        }

        // Add telephone-event for RFC 2833 DTMF
        // Bug #57: Fix event range from 0-16 to 0-15 (16 DTMF digits, events 0-15)
        // P2-SIP-17: Use dynamically selected PT instead of hardcoded 101
        if self.include_telephone_event {
            sdp.push_str(&format!("a=rtpmap:{} telephone-event/8000\r\n", te_pt));
            sdp.push_str(&format!("a=fmtp:{} 0-15\r\n", te_pt));
        }

        // Add ptime (20ms frames)
        sdp.push_str("a=ptime:20\r\n");
        sdp.push_str(&format!("a={}\r\n", self.direction));

        sdp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_sdp() {
        let sdp_str = r#"v=0
o=- 123456 1 IN IP4 192.168.1.100
s=Test Session
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=ptime:20
a=sendrecv
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.session_name, "Test Session");
        assert!(sdp.connection.is_some());

        let audio = sdp.audio().unwrap();
        assert_eq!(audio.port, 49170);
        assert_eq!(audio.payload_types, vec![0, 8]);
        assert_eq!(audio.rtpmap.len(), 2);
    }

    #[test]
    fn test_rtp_addr() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        let addr = sdp.rtp_addr().unwrap();
        assert_eq!(addr.to_string(), "10.0.0.1:5004");
    }

    #[test]
    fn test_preferred_codec() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 8 0
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert_eq!(sdp.preferred_codec(), Some(CodecType::Pcma));
    }

    #[test]
    fn test_sdp_builder() {
        let addr: SocketAddr = "192.168.1.50:5060".parse().unwrap();
        let mut builder = SdpBuilder::new(addr).codecs(vec![CodecType::Pcmu]);

        let sdp_str = builder.build();
        assert!(sdp_str.contains("v=0"));
        assert!(sdp_str.contains("c=IN IP4 192.168.1.50"));
        assert!(sdp_str.contains("m=audio 5060 RTP/AVP 0"));
        assert!(sdp_str.contains("a=rtpmap:0 PCMU/8000"));
    }

    #[test]
    fn test_sdp_roundtrip() {
        let addr: SocketAddr = "10.0.0.5:49170".parse().unwrap();
        let mut builder = SdpBuilder::new(addr);
        let sdp_str = builder.build();

        let parsed = Sdp::parse(&sdp_str).unwrap();
        assert_eq!(parsed.rtp_addr().unwrap().port(), 49170);
        assert!(parsed.preferred_codec().is_some());
    }

    #[test]
    fn test_telephone_event_detection() {
        // SDP with telephone-event (RFC 2833 support)
        let sdp_with_te = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
"#;

        let sdp = Sdp::parse(sdp_with_te).unwrap();
        assert!(sdp.supports_rfc2833());
        assert_eq!(sdp.telephone_event_pt(), Some(101));
    }

    #[test]
    fn test_telephone_event_not_present() {
        // SDP without telephone-event
        let sdp_without_te = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
"#;

        let sdp = Sdp::parse(sdp_without_te).unwrap();
        assert!(!sdp.supports_rfc2833());
        assert_eq!(sdp.telephone_event_pt(), None);
    }

    #[test]
    fn test_telephone_event_different_pt() {
        // SDP with telephone-event at payload type 96
        let sdp_te_96 = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0 96
a=rtpmap:0 PCMU/8000
a=rtpmap:96 telephone-event/8000
"#;

        let sdp = Sdp::parse(sdp_te_96).unwrap();
        assert!(sdp.supports_rfc2833());
        assert_eq!(sdp.telephone_event_pt(), Some(96));
    }

    // === Hold/Resume Tests ===

    #[test]
    fn test_hold_via_sendonly() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendonly
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert!(sdp.is_on_hold());
        assert_eq!(sdp.audio_direction(), MediaDirection::SendOnly);
    }

    #[test]
    fn test_hold_via_inactive() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=inactive
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert!(sdp.is_on_hold());
        assert_eq!(sdp.audio_direction(), MediaDirection::Inactive);
    }

    #[test]
    fn test_hold_via_legacy_connection() {
        // Legacy hold method: c=0.0.0.0
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 0.0.0.0
t=0 0
m=audio 5004 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert!(sdp.is_on_hold());
    }

    #[test]
    fn test_hold_via_port_zero() {
        // Stream disabled (port 0)
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 0 RTP/AVP 0
a=rtpmap:0 PCMU/8000
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert!(sdp.is_on_hold());
        let audio = sdp.audio().unwrap();
        assert!(audio.is_disabled());
    }

    #[test]
    fn test_not_on_hold() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert!(!sdp.is_on_hold());
        assert_eq!(sdp.audio_direction(), MediaDirection::SendRecv);
    }

    #[test]
    fn test_recvonly_not_hold() {
        // recvonly is not hold (remote is sending to us)
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=recvonly
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        assert!(!sdp.is_on_hold());
        assert_eq!(sdp.audio_direction(), MediaDirection::RecvOnly);
    }

    // === Codec Negotiation Tests ===

    #[test]
    fn test_codec_negotiation() {
        // Remote offers: PCMA, PCMU (prefers PCMA)
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 8 0
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();

        // Local prefers PCMU - local preference wins (greedy mode)
        let local_prefs = vec![CodecType::Pcmu, CodecType::Pcma];
        let codec = sdp.negotiate_codec(&local_prefs).unwrap();
        assert_eq!(codec, CodecType::Pcmu); // Local preference wins

        // Local prefers PCMA - still gets local preference
        let local_prefs = vec![CodecType::Pcma, CodecType::Pcmu];
        let codec = sdp.negotiate_codec(&local_prefs).unwrap();
        assert_eq!(codec, CodecType::Pcma);
    }

    #[test]
    fn test_direction_answer_mapping() {
        assert_eq!(
            MediaDirection::SendRecv.answer_direction(),
            MediaDirection::SendRecv
        );
        assert_eq!(
            MediaDirection::SendOnly.answer_direction(),
            MediaDirection::RecvOnly
        );
        assert_eq!(
            MediaDirection::RecvOnly.answer_direction(),
            MediaDirection::SendOnly
        );
        assert_eq!(
            MediaDirection::Inactive.answer_direction(),
            MediaDirection::Inactive
        );
    }

    #[test]
    fn test_remote_codecs() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 8 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
"#;

        let sdp = Sdp::parse(sdp_str).unwrap();
        let codecs = sdp.remote_codecs();
        assert_eq!(codecs.len(), 2); // PCMA, PCMU (101 is not a codec)
        assert_eq!(codecs[0], CodecType::Pcma);
        assert_eq!(codecs[1], CodecType::Pcmu);
    }

    // ===== Bug #55: SDP port range validation tests =====

    #[test]
    fn test_bug55_port_exceeding_u16_rejected() {
        // Port 70000 exceeds u16 max (65535) and should be rejected
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 70000 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err(), "Port 70000 should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("out of range"),
            "Expected 'out of range' error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug55_port_at_boundary_accepted() {
        // Port 65535 is the maximum valid port
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 65535 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok(), "Port 65535 should be valid");
        let sdp = result.unwrap();
        assert_eq!(sdp.audio().unwrap().port, 65535);
    }

    #[test]
    fn test_bug55_port_zero_accepted() {
        // Port 0 means stream disabled - valid per RFC 3264
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok(), "Port 0 should be valid");
        assert!(result.unwrap().audio().unwrap().is_disabled());
    }

    #[test]
    fn test_bug55_port_with_count_validated() {
        // Port range like "70000/2" should still reject the base port
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 70000/2 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err(), "Port 70000/2 should be rejected");
    }

    // ===== Bug #56: Clock rate validation for dynamic PTs =====

    #[test]
    fn test_bug56_dynamic_pt_missing_clock_rate_rejected() {
        // Dynamic payload type 101 without clock rate should fail
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 101\r\na=rtpmap:101 telephone-event\r\n";
        let result = Sdp::parse(sdp_str);
        // The rtpmap parse should fail and the entry won't be added
        // (parse_rtpmap returns Err, which is silently ignored in the if let Ok block)
        assert!(result.is_ok()); // SDP itself parses, but rtpmap entry is skipped
        let sdp = result.unwrap();
        let audio = sdp.audio().unwrap();
        assert!(
            audio.rtpmap.is_empty(),
            "Dynamic PT without clock rate should not produce rtpmap entry"
        );
    }

    #[test]
    fn test_bug56_static_pt_missing_clock_rate_defaults() {
        // Static payload type 0 (PCMU) without clock rate should default to 8000
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok());
        let sdp = result.unwrap();
        let audio = sdp.audio().unwrap();
        assert_eq!(audio.rtpmap.len(), 1);
        assert_eq!(audio.rtpmap[0].clock_rate, 8000);
    }

    #[test]
    fn test_bug56_dynamic_pt_with_clock_rate_accepted() {
        // Dynamic PT 96 with explicit clock rate should work fine
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok());
        let sdp = result.unwrap();
        let audio = sdp.audio().unwrap();
        assert_eq!(audio.rtpmap.len(), 1);
        assert_eq!(audio.rtpmap[0].clock_rate, 48000);
    }

    // ===== Bug #57: fmtp parsing and generation tests =====

    #[test]
    fn test_bug57_fmtp_parsed_from_remote_sdp() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
"#;
        let sdp = Sdp::parse(sdp_str).unwrap();
        assert_eq!(sdp.telephone_event_fmtp(), Some("0-15".to_string()));
    }

    #[test]
    fn test_bug57_fmtp_not_present() {
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
"#;
        let sdp = Sdp::parse(sdp_str).unwrap();
        assert_eq!(sdp.telephone_event_fmtp(), None);
    }

    #[test]
    fn test_bug57_fmtp_with_old_0_16_from_remote() {
        // Remote sends 0-16 (their range) - we should parse it correctly
        let sdp_str = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 5004 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
"#;
        let sdp = Sdp::parse(sdp_str).unwrap();
        assert_eq!(sdp.telephone_event_fmtp(), Some("0-16".to_string()));
    }

    #[test]
    fn test_bug57_sdp_builder_generates_0_15() {
        // Verify that generated SDP uses 0-15, not 0-16
        let addr: SocketAddr = "10.0.0.1:5004".parse().unwrap();
        let mut builder = SdpBuilder::new(addr).telephone_event(true);
        let sdp_str = builder.build();
        assert!(
            sdp_str.contains("a=fmtp:101 0-15"),
            "SDP builder should generate 0-15, got: {}",
            sdp_str
        );
        assert!(
            !sdp_str.contains("0-16"),
            "SDP builder should NOT contain 0-16, got: {}",
            sdp_str
        );
    }

    // ===== Bug #58: Mandatory SDP field validation tests =====

    #[test]
    fn test_bug58_empty_sdp_rejected() {
        let result = Sdp::parse("");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("Missing mandatory SDP field"),
            "Expected mandatory field error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug58_missing_version_rejected() {
        // SDP with o= and s= but no v=
        let sdp_str = "o=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("v="),
            "Expected version field error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug58_missing_origin_rejected() {
        // SDP with v= and s= but no o=
        let sdp_str = "v=0\r\ns=-\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("o="),
            "Expected origin field error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug58_missing_session_name_rejected() {
        // SDP with v= and o= but no s=
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("s="),
            "Expected session name field error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug58_all_mandatory_fields_present() {
        // Minimal valid SDP
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok(), "SDP with all mandatory fields should parse");
    }

    // ===== Bug #59: Connection address type validation tests =====

    #[test]
    fn test_bug59_ip4_with_ipv6_address_rejected() {
        // c=IN IP4 ::1 should fail: address type says IP4 but address is IPv6
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 ::1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err(), "IP4 with IPv6 address should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("IP4") && err_msg.contains("not IPv4"),
            "Expected address type mismatch error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug59_ip6_with_ipv4_address_rejected() {
        // c=IN IP6 10.0.0.1 should fail: address type says IP6 but address is IPv4
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP6 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_err(), "IP6 with IPv4 address should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("IP6") && err_msg.contains("not IPv6"),
            "Expected address type mismatch error: {}",
            err_msg
        );
    }

    #[test]
    fn test_bug59_ip4_with_ipv4_address_accepted() {
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 192.168.1.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok(), "IP4 with IPv4 address should be accepted");
    }

    #[test]
    fn test_bug59_ip6_with_ipv6_address_accepted() {
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP6 ::1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok(), "IP6 with IPv6 address should be accepted");
    }

    #[test]
    fn test_bug59_ip4_with_zero_address_accepted() {
        // c=IN IP4 0.0.0.0 is valid (legacy hold)
        let sdp_str = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let result = Sdp::parse(sdp_str);
        assert!(result.is_ok(), "IP4 with 0.0.0.0 should be accepted");
    }
}
