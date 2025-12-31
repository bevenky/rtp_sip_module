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
//! - **fmtp line**: `a=fmtp:101 0-16` specifies supported events. We advertise 0-16
//!   (digits + ABCD) but currently only use 0-15.
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
    /// Send-only (local on hold, remote can receive)
    SendOnly,
    /// Receive-only (remote on hold, local can receive)
    RecvOnly,
    /// No media (both on hold)
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
    /// Attributes
    pub attributes: Vec<String>,
    /// Media direction (sendrecv/sendonly/recvonly/inactive)
    pub direction: MediaDirection,
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
                    version = value.parse().unwrap_or(0);
                }
                'o' => {
                    origin = Self::parse_origin(value)?;
                }
                's' => {
                    session_name = value.to_string();
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
                    }
                    current_media = Some(Self::parse_media_line(value)?);
                }
                'a' => {
                    if let Some(ref mut m) = current_media {
                        if value.starts_with("rtpmap:") {
                            if let Ok(entry) = Self::parse_rtpmap(&value[7..]) {
                                m.rtpmap.push(entry);
                            }
                        } else if let Some(dir) = MediaDirection::from_str(value) {
                            // Parse direction attribute (sendrecv/sendonly/recvonly/inactive)
                            m.direction = dir;
                        } else {
                            m.attributes.push(value.to_string());
                        }
                    } else {
                        // Session-level attributes (including direction)
                        session_attributes.push(value.to_string());
                    }
                }
                _ => {}
            }
        }

        // Save last media if exists
        if let Some(m) = current_media {
            media.push(m);
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

        Ok(SdpOrigin {
            username: parts[0].to_string(),
            session_id: parts[1].parse().unwrap_or(0),
            session_version: parts[2].parse().unwrap_or(1),
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

        parts[2]
            .parse()
            .map_err(|_| RtpSipError::Sdp(format!("Invalid IP address: {}", parts[2])))
    }

    fn parse_media_line(value: &str) -> Result<MediaDescription> {
        // Format: audio 49170 RTP/AVP 0 8 97
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(RtpSipError::Sdp("Invalid media line".to_string()));
        }

        let media_type = parts[0].to_string();
        let port: u16 = parts[1]
            .split('/')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let protocol = parts[2].to_string();
        let payload_types: Vec<u8> = parts[3..]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Ok(MediaDescription {
            media_type,
            port,
            protocol,
            payload_types,
            connection: None,
            rtpmap: Vec::new(),
            attributes: Vec::new(),
            direction: MediaDirection::SendRecv, // Default per RFC 3264
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
        let clock_rate: u32 = codec_parts
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(8000);
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

        // Check if 101 is in payload types (common default for telephone-event)
        if audio.payload_types.contains(&101) {
            // Verify it's not used for something else by checking rtpmap
            let used_for_other = audio.rtpmap.iter().any(|e| {
                e.payload_type == 101 && !e.encoding_name.eq_ignore_ascii_case("telephone-event")
            });
            if !used_for_other {
                return Some(101);
            }
        }

        None
    }

    /// Check if remote supports RFC 2833 DTMF
    pub fn supports_rfc2833(&self) -> bool {
        self.telephone_event_pt().is_some()
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

    /// Build the SDP string
    pub fn build(&self) -> String {
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

        // Add telephone-event (PT 101) if enabled
        if self.include_telephone_event {
            payload_types.push("101".to_string());
        }

        let mut sdp = format!(
            "v=0\r\n\
             o={} {} {} {} {} {}\r\n\
             s={}\r\n\
             c=IN {} {}\r\n\
             t=0 0\r\n\
             m=audio {} RTP/AVP {}\r\n",
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
            payload_types.join(" ")
        );

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
        if self.include_telephone_event {
            sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
            sdp.push_str("a=fmtp:101 0-16\r\n");
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
        let builder = SdpBuilder::new(addr).codecs(vec![CodecType::Pcmu]);

        let sdp_str = builder.build();
        assert!(sdp_str.contains("v=0"));
        assert!(sdp_str.contains("c=IN IP4 192.168.1.50"));
        assert!(sdp_str.contains("m=audio 5060 RTP/AVP 0"));
        assert!(sdp_str.contains("a=rtpmap:0 PCMU/8000"));
    }

    #[test]
    fn test_sdp_roundtrip() {
        let addr: SocketAddr = "10.0.0.5:49170".parse().unwrap();
        let builder = SdpBuilder::new(addr);
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
}
