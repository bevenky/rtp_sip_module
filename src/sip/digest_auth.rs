//! SIP Digest Authentication (RFC 2617 / RFC 7616)
//!
//! Implements digest authentication for SIP REGISTER and other requests.
//! Handles 401 Unauthorized and 407 Proxy Authentication Required challenges.
//!
//! # Features
//!
//! - Parse `WWW-Authenticate` / `Proxy-Authenticate` challenge headers
//! - Compute digest response with MD5 (RFC 2617) or SHA-256 (RFC 7616)
//! - Build `Authorization` / `Proxy-Authorization` headers
//! - Nonce caching with nonce-count (nc) tracking for `qop=auth`
//! - `stale=true` handling — re-auth with new nonce without re-prompting
//! - Opaque parameter pass-through
//!
//! # Usage
//!
//! ```rust,no_run
//! use rtpsip::sip::digest_auth::{DigestChallenge, DigestCredentials, AuthHeaderType};
//!
//! // Parse a 401 challenge
//! let header = r#"Digest realm="example.com", nonce="abc123", qop="auth", algorithm=MD5"#;
//! let challenge = DigestChallenge::parse(header).unwrap();
//!
//! // Create credentials with nonce cache
//! let mut creds = DigestCredentials::new("alice", "secret");
//!
//! // Build the Authorization header for retry
//! let auth_header = creds.authorize(
//!     &challenge,
//!     "REGISTER",
//!     "sip:example.com",
//!     AuthHeaderType::Authorization,
//! );
//! ```

use crate::error::{Result, RtpSipError};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use std::fmt;

/// Hash algorithm for digest computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 — RFC 2617 default, most common in SIP
    Md5,
    /// SHA-256 — RFC 7616, preferred for new deployments
    Sha256,
}

impl DigestAlgorithm {
    /// Parse algorithm from the WWW-Authenticate header value.
    /// Returns `Md5` if absent or unrecognized (per RFC 2617 Section 3.2.1).
    fn parse(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase();
        // Match common representations
        if lower == "sha-256" || lower == "sha256" {
            DigestAlgorithm::Sha256
        } else {
            // MD5 is the default per RFC 2617
            DigestAlgorithm::Md5
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestAlgorithm::Md5 => write!(f, "MD5"),
            DigestAlgorithm::Sha256 => write!(f, "SHA-256"),
        }
    }
}

/// Quality of Protection directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qop {
    /// Authentication only — most common for SIP
    Auth,
    /// Authentication with integrity protection (rarely used in SIP)
    AuthInt,
}

impl fmt::Display for Qop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Qop::Auth => write!(f, "auth"),
            Qop::AuthInt => write!(f, "auth-int"),
        }
    }
}

/// Whether the challenge came from WWW-Authenticate (401) or Proxy-Authenticate (407).
/// Determines which response header to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHeaderType {
    /// 401 Unauthorized → respond with `Authorization`
    Authorization,
    /// 407 Proxy Authentication Required → respond with `Proxy-Authorization`
    ProxyAuthorization,
}

/// Parsed challenge from a `WWW-Authenticate` or `Proxy-Authenticate` header.
///
/// Extracts the parameters needed to compute a digest response per RFC 2617/7616.
///
/// # Fields
///
/// - `realm` — Authentication realm (identifies the protection space)
/// - `nonce` — Server-generated nonce (unique per challenge)
/// - `opaque` — Opaque value that must be returned unchanged
/// - `qop` — Quality of protection (if present, nc and cnonce are required)
/// - `algorithm` — Hash algorithm (MD5 or SHA-256)
/// - `stale` — If `true`, nonce expired but credentials are still valid
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    /// Authentication realm
    pub realm: String,
    /// Server-provided nonce
    pub nonce: String,
    /// Opaque value to return unchanged (if present)
    pub opaque: Option<String>,
    /// Quality of protection
    pub qop: Option<Qop>,
    /// Hash algorithm (defaults to MD5)
    pub algorithm: DigestAlgorithm,
    /// Whether the nonce is stale (expired but credentials still valid)
    pub stale: bool,
}

impl DigestChallenge {
    /// Parse a `WWW-Authenticate` or `Proxy-Authenticate` header value into a
    /// `DigestChallenge`.
    ///
    /// Expects the value to start with `Digest` (case-insensitive), followed by
    /// comma-separated `key=value` or `key="value"` parameters.
    ///
    /// # Errors
    ///
    /// Returns `RtpSipError::Auth` if the header does not start with "Digest" or
    /// if the required `realm` or `nonce` parameters are missing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use rtpsip::sip::digest_auth::DigestChallenge;
    /// let header = r#"Digest realm="biloxi.com", nonce="dcd98b", qop="auth""#;
    /// let challenge = DigestChallenge::parse(header).unwrap();
    /// assert_eq!(challenge.realm, "biloxi.com");
    /// assert_eq!(challenge.nonce, "dcd98b");
    /// ```
    pub fn parse(header_value: &str) -> Result<Self> {
        parse_challenge(header_value)
    }
}

/// Cached digest credentials with nonce reuse and nonce-count tracking.
///
/// Reuses a cached nonce for subsequent requests (avoids an extra round trip)
/// until the server responds with 401/stale=true, at which point the nonce
/// is replaced and the counter is reset.
///
/// # Nonce Caching (RFC 2617 Section 3.5)
///
/// A client MAY cache the nonce and reuse it for subsequent requests to the
/// same protection space. The nonce-count (nc) must be incremented for each
/// request using the same nonce when `qop` is present.
///
/// # Thread Safety
///
/// Not thread-safe — designed for single-task registration flows. The
/// `register()` method in `SipEngine` uses one `DigestCredentials` per
/// provider, called from a single task.
#[derive(Debug)]
pub struct DigestCredentials {
    /// SIP username
    pub username: String,
    /// SIP password
    pub password: String,
    /// Cached nonce from last successful challenge
    cached_nonce: Option<String>,
    /// Cached realm from last challenge
    cached_realm: Option<String>,
    /// Cached opaque from last challenge (must be returned unchanged)
    cached_opaque: Option<String>,
    /// Cached qop from last challenge
    cached_qop: Option<Qop>,
    /// Cached algorithm from last challenge
    cached_algorithm: DigestAlgorithm,
    /// Nonce-count: number of times this nonce has been used (for qop=auth)
    nc: u32,
}

impl DigestCredentials {
    /// Create new credentials (no cached nonce yet).
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            cached_nonce: None,
            cached_realm: None,
            cached_opaque: None,
            cached_qop: None,
            cached_algorithm: DigestAlgorithm::Md5,
            nc: 0,
        }
    }

    /// Update the cached challenge parameters from a new server challenge.
    ///
    /// - If `stale=true`, only the nonce is refreshed and nc resets — credentials
    ///   are still valid.
    /// - If the nonce is the same as the cached one, nothing is reset (the nc
    ///   continues incrementing for qop=auth).
    /// - Otherwise (new nonce from a fresh 401), all parameters are updated and
    ///   nc resets.
    pub fn update_challenge(&mut self, challenge: &DigestChallenge) {
        if challenge.stale && self.cached_nonce.is_some() {
            // Stale nonce: just replace the nonce, reset nc, keep other params
            tracing::debug!(
                old_nonce = self.cached_nonce.as_deref().unwrap_or("none"),
                new_nonce = %challenge.nonce,
                "nonce expired (stale=true), refreshing"
            );
            self.cached_nonce = Some(challenge.nonce.clone());
            self.nc = 0;
        } else if self.cached_nonce.as_deref() == Some(&challenge.nonce) {
            // Same nonce — reusing cached challenge, don't reset nc.
            // The nc will be incremented in authorize().
        } else {
            // Fresh challenge with a new nonce: cache all parameters
            self.cached_nonce = Some(challenge.nonce.clone());
            self.cached_realm = Some(challenge.realm.clone());
            self.cached_opaque = challenge.opaque.clone();
            self.cached_qop = challenge.qop.clone();
            self.cached_algorithm = challenge.algorithm;
            self.nc = 0;
        }
    }

    /// Check whether we have a cached nonce that can be reused.
    pub fn has_cached_nonce(&self) -> bool {
        self.cached_nonce.is_some()
    }

    /// Clear the cached nonce (e.g., after auth failure without stale=true).
    pub fn clear_cache(&mut self) {
        self.cached_nonce = None;
        self.cached_realm = None;
        self.cached_opaque = None;
        self.cached_qop = None;
        self.nc = 0;
    }

    /// Build an `Authorization` or `Proxy-Authorization` header value using
    /// the given challenge parameters.
    ///
    /// Increments the nonce-count (nc) and generates a fresh cnonce for each call.
    /// Caches the challenge parameters for future reuse.
    ///
    /// # Arguments
    ///
    /// * `challenge` — Parsed challenge from 401/407 response
    /// * `method` — SIP method (e.g., "REGISTER", "INVITE")
    /// * `uri` — Request URI (e.g., "sip:example.com")
    /// * `header_type` — Whether to format as Authorization or Proxy-Authorization
    ///
    /// # Returns
    ///
    /// The full header value string (e.g., `Digest username="alice", ...`)
    pub fn authorize(
        &mut self,
        challenge: &DigestChallenge,
        method: &str,
        uri: &str,
        header_type: AuthHeaderType,
    ) -> String {
        // Update cache with this challenge
        self.update_challenge(challenge);

        // Increment nonce-count
        self.nc += 1;

        // Generate cnonce
        let cnonce = generate_cnonce();

        // Compute the digest response
        let response = compute_response(
            challenge,
            &self.username,
            &self.password,
            method,
            uri,
            self.nc,
            &cnonce,
        );

        // Build the header value
        build_auth_header(
            challenge,
            &self.username,
            uri,
            &response,
            self.nc,
            &cnonce,
            header_type,
        )
    }

    /// Build an auth header using the cached nonce (for pre-emptive auth).
    ///
    /// Returns `None` if no nonce is cached. Use this to avoid the initial
    /// 401 round-trip on subsequent registrations.
    pub fn authorize_cached(
        &mut self,
        method: &str,
        uri: &str,
        header_type: AuthHeaderType,
    ) -> Option<String> {
        let nonce = self.cached_nonce.clone()?;
        let realm = self.cached_realm.clone()?;

        // Reconstruct a challenge from cached values
        let challenge = DigestChallenge {
            realm,
            nonce,
            opaque: self.cached_opaque.clone(),
            qop: self.cached_qop.clone(),
            algorithm: self.cached_algorithm,
            stale: false,
        };

        Some(self.authorize(&challenge, method, uri, header_type))
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Parse a `WWW-Authenticate` or `Proxy-Authenticate` header value.
///
/// # Format
///
/// ```text
/// Digest realm="biloxi.com", nonce="dcd98b...", qop="auth", algorithm=MD5, opaque="5ccc...", stale=false
/// ```
///
/// Parameters may be quoted or unquoted. The `Digest` scheme prefix is required.
pub fn parse_challenge(header_value: &str) -> Result<DigestChallenge> {
    let trimmed = header_value.trim();

    // Must start with "Digest" (case-insensitive)
    if !trimmed
        .get(..6)
        .map(|s| s.eq_ignore_ascii_case("Digest"))
        .unwrap_or(false)
    {
        return Err(RtpSipError::Auth(format!(
            "expected Digest scheme, got: {}",
            trimmed.chars().take(20).collect::<String>()
        )));
    }

    let params_str = trimmed[6..].trim();
    let params = parse_params(params_str);

    let realm = params
        .get("realm")
        .ok_or_else(|| RtpSipError::Auth("missing realm in challenge".to_string()))?
        .clone();

    let nonce = params
        .get("nonce")
        .ok_or_else(|| RtpSipError::Auth("missing nonce in challenge".to_string()))?
        .clone();

    let opaque = params.get("opaque").cloned();

    let qop = params.get("qop").and_then(|q| {
        // qop can be a comma-separated list like "auth,auth-int"
        // We pick the best one we support: prefer auth over auth-int
        let lower = q.to_ascii_lowercase();
        if lower.contains("auth-int") && !lower.contains("auth,") && lower != "auth" {
            Some(Qop::AuthInt)
        } else if lower.contains("auth") {
            Some(Qop::Auth)
        } else {
            None
        }
    });

    let algorithm = params
        .get("algorithm")
        .map(|a| DigestAlgorithm::parse(a))
        .unwrap_or(DigestAlgorithm::Md5);

    let stale = params
        .get("stale")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    Ok(DigestChallenge {
        realm,
        nonce,
        opaque,
        qop,
        algorithm,
        stale,
    })
}

/// Compute the digest response hash per RFC 2617 / RFC 7616.
///
/// # Algorithm
///
/// ```text
/// HA1 = H(username:realm:password)
/// HA2 = H(method:uri)
///
/// If qop=auth:
///   response = H(HA1:nonce:nc:cnonce:qop:HA2)
/// Else:
///   response = H(HA1:nonce:HA2)
/// ```
///
/// Where H is MD5 or SHA-256 depending on the algorithm field.
pub fn compute_response(
    challenge: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    nc: u32,
    cnonce: &str,
) -> String {
    let ha1 = hash(
        challenge.algorithm,
        &format!("{}:{}:{}", username, challenge.realm, password),
    );

    let ha2 = hash(
        challenge.algorithm,
        &format!("{}:{}", method, uri),
    );

    let response_input = match &challenge.qop {
        Some(qop) => {
            format!(
                "{}:{}:{:08x}:{}:{}:{}",
                ha1, challenge.nonce, nc, cnonce, qop, ha2
            )
        }
        None => {
            format!("{}:{}:{}", ha1, challenge.nonce, ha2)
        }
    };

    hash(challenge.algorithm, &response_input)
}

/// Build the `Authorization` or `Proxy-Authorization` header value.
///
/// Assembles the Digest parameters according to RFC 2617 Section 3.2.2.
/// The `opaque` parameter is included only if present in the challenge
/// (must be returned unchanged per spec).
pub fn build_auth_header(
    challenge: &DigestChallenge,
    username: &str,
    uri: &str,
    response: &str,
    nc: u32,
    cnonce: &str,
    header_type: AuthHeaderType,
) -> String {
    let _ = header_type; // Used by callers to decide which SIP header to set

    let mut parts = vec![
        format!("Digest username=\"{}\"", username),
        format!("realm=\"{}\"", challenge.realm),
        format!("nonce=\"{}\"", challenge.nonce),
        format!("uri=\"{}\"", uri),
        format!("response=\"{}\"", response),
        format!("algorithm={}", challenge.algorithm),
    ];

    if let Some(ref qop) = challenge.qop {
        parts.push(format!("qop={}", qop));
        parts.push(format!("nc={:08x}", nc));
        parts.push(format!("cnonce=\"{}\"", cnonce));
    }

    if let Some(ref opaque) = challenge.opaque {
        parts.push(format!("opaque=\"{}\"", opaque));
    }

    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute hex-encoded hash using the specified algorithm.
fn hash(algorithm: DigestAlgorithm, input: &str) -> String {
    match algorithm {
        DigestAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(input.as_bytes());
            hex::encode(hasher.finalize())
        }
        DigestAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            hex::encode(hasher.finalize())
        }
    }
}

/// Generate a random cnonce value (hex-encoded 8 random bytes).
fn generate_cnonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// Parse `key=value` or `key="value"` parameters from a comma-separated string.
///
/// Handles:
/// - Quoted values: `realm="example.com"`
/// - Unquoted values: `algorithm=MD5`, `stale=false`
/// - Values containing commas inside quotes: `qop="auth,auth-int"`
/// - Leading/trailing whitespace around keys and values
fn parse_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Skip whitespace and commas
        while i < len && (bytes[i] == b' ' || bytes[i] == b',' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= len {
            break;
        }

        // Parse key (stop at '=' or ',' — key cannot contain these)
        let key_start = i;
        while i < len && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        let key = s[key_start..i].trim().to_ascii_lowercase();

        if i >= len || bytes[i] != b'=' {
            // No value — skip
            continue;
        }
        i += 1; // skip '='

        // Skip whitespace after '='
        while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }

        // Parse value (quoted or unquoted)
        let value = if i < len && bytes[i] == b'"' {
            // Quoted value — find closing quote
            i += 1; // skip opening quote
            let val_start = i;
            while i < len && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < len {
                    i += 1; // skip escaped char
                }
                i += 1;
            }
            let val = s[val_start..i].to_string();
            if i < len {
                i += 1; // skip closing quote
            }
            val
        } else {
            // Unquoted value — read until comma or whitespace
            let val_start = i;
            while i < len && bytes[i] != b',' && bytes[i] != b' ' && bytes[i] != b'\t' {
                i += 1;
            }
            s[val_start..i].trim().to_string()
        };

        if !key.is_empty() {
            params.insert(key, value);
        }
    }

    params
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_challenge tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_basic_challenge() {
        let header = r#"Digest realm="biloxi.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093""#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "biloxi.com");
        assert_eq!(challenge.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5);
        assert!(challenge.qop.is_none());
        assert!(challenge.opaque.is_none());
        assert!(!challenge.stale);
    }

    #[test]
    fn test_parse_full_challenge() {
        let header = r#"Digest realm="atlanta.com", nonce="84a4cc6f3082121f32b42a2187831a9e", qop="auth", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5, stale=false"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "atlanta.com");
        assert_eq!(challenge.nonce, "84a4cc6f3082121f32b42a2187831a9e");
        assert_eq!(challenge.qop, Some(Qop::Auth));
        assert_eq!(
            challenge.opaque,
            Some("5ccc069c403ebaf9f0171e9517f40e41".to_string())
        );
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5);
        assert!(!challenge.stale);
    }

    #[test]
    fn test_parse_sha256_algorithm() {
        let header = r#"Digest realm="test.com", nonce="abc", algorithm=SHA-256"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.algorithm, DigestAlgorithm::Sha256);
    }

    #[test]
    fn test_parse_stale_true() {
        let header = r#"Digest realm="test.com", nonce="new-nonce", stale=true"#;
        let challenge = parse_challenge(header).unwrap();
        assert!(challenge.stale);
    }

    #[test]
    fn test_parse_stale_true_case_insensitive() {
        let header = r#"Digest realm="test.com", nonce="abc", stale=TRUE"#;
        let challenge = parse_challenge(header).unwrap();
        assert!(challenge.stale);
    }

    #[test]
    fn test_parse_missing_realm() {
        let header = r#"Digest nonce="abc""#;
        let err = parse_challenge(header).unwrap_err();
        assert!(err.to_string().contains("missing realm"));
    }

    #[test]
    fn test_parse_missing_nonce() {
        let header = r#"Digest realm="test.com""#;
        let err = parse_challenge(header).unwrap_err();
        assert!(err.to_string().contains("missing nonce"));
    }

    #[test]
    fn test_parse_not_digest_scheme() {
        let header = r#"Basic realm="test.com""#;
        let err = parse_challenge(header).unwrap_err();
        assert!(err.to_string().contains("Digest scheme"));
    }

    #[test]
    fn test_parse_qop_auth_int() {
        let header = r#"Digest realm="test.com", nonce="abc", qop="auth-int""#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.qop, Some(Qop::AuthInt));
    }

    #[test]
    fn test_parse_qop_list_prefers_auth() {
        let header = r#"Digest realm="test.com", nonce="abc", qop="auth,auth-int""#;
        let challenge = parse_challenge(header).unwrap();
        // When both are offered, we prefer auth (simpler, no body hashing)
        assert_eq!(challenge.qop, Some(Qop::Auth));
    }

    #[test]
    fn test_parse_case_insensitive_digest() {
        let header = r#"digest realm="test.com", nonce="abc""#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "test.com");
    }

    // -----------------------------------------------------------------------
    // compute_response tests — RFC 2617 Section 3.5 example
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_response_without_qop() {
        // RFC 2617 Section 3.5 example (simplified)
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let response = compute_response(
            &challenge,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        );

        // HA1 = MD5("Mufasa:testrealm@host.com:Circle Of Life")
        //      = 939e7578ed9e3c518a452acee763bce9
        let expected_ha1 = hash(
            DigestAlgorithm::Md5,
            "Mufasa:testrealm@host.com:Circle Of Life",
        );
        assert_eq!(expected_ha1, "939e7578ed9e3c518a452acee763bce9");

        // HA2 = MD5("GET:/dir/index.html")
        //      = 39aff3a2bab6126f332b942af96d3366
        let expected_ha2 = hash(DigestAlgorithm::Md5, "GET:/dir/index.html");
        assert_eq!(expected_ha2, "39aff3a2bab6126f332b942af96d3366");

        // response = MD5(HA1:nonce:HA2)
        let expected = hash(
            DigestAlgorithm::Md5,
            &format!(
                "{}:{}:{}",
                expected_ha1, "dcd98b7102dd2f0e8b11d0f600bfb0c093", expected_ha2
            ),
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn test_compute_response_with_qop_auth() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let response = compute_response(
            &challenge,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        );

        // HA1 = MD5("Mufasa:testrealm@host.com:Circle Of Life")
        let ha1 = hash(
            DigestAlgorithm::Md5,
            "Mufasa:testrealm@host.com:Circle Of Life",
        );
        // HA2 = MD5("GET:/dir/index.html")
        let ha2 = hash(DigestAlgorithm::Md5, "GET:/dir/index.html");
        // response = MD5(HA1:nonce:00000001:0a4f113b:auth:HA2)
        let expected = hash(
            DigestAlgorithm::Md5,
            &format!(
                "{}:{}:{:08x}:{}:{}:{}",
                ha1, "dcd98b7102dd2f0e8b11d0f600bfb0c093", 1u32, "0a4f113b", "auth", ha2
            ),
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn test_compute_response_rfc2617_full_example() {
        // RFC 2617 Section 3.5 full worked example with qop=auth
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let response = compute_response(
            &challenge,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        );

        // This is the expected response from RFC 2617 Section 3.5
        assert_eq!(response, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn test_compute_response_sha256() {
        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        };

        let response = compute_response(
            &challenge,
            "user",
            "passwd",
            "REGISTER",
            "sip:example.com",
            1,
            "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
        );

        // Verify it's a 64-char hex string (SHA-256 produces 256 bits = 32 bytes = 64 hex chars)
        assert_eq!(response.len(), 64);
        assert!(response.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_sip_register_md5() {
        // Typical SIP REGISTER scenario
        let challenge = DigestChallenge {
            realm: "asterisk".to_string(),
            nonce: "1234567890abcdef".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let response = compute_response(
            &challenge,
            "100",
            "password123",
            "REGISTER",
            "sip:pbx.example.com",
            1,
            "abcd1234",
        );

        // Manually verify the computation
        let ha1 = hash(DigestAlgorithm::Md5, "100:asterisk:password123");
        let ha2 = hash(DigestAlgorithm::Md5, "REGISTER:sip:pbx.example.com");
        let expected = hash(
            DigestAlgorithm::Md5,
            &format!(
                "{}:1234567890abcdef:00000001:abcd1234:auth:{}",
                ha1, ha2
            ),
        );
        assert_eq!(response, expected);
    }

    // -----------------------------------------------------------------------
    // build_auth_header tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_auth_header_basic() {
        let challenge = DigestChallenge {
            realm: "biloxi.com".to_string(),
            nonce: "dcd98b".to_string(),
            opaque: None,
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let header = build_auth_header(
            &challenge,
            "bob",
            "sip:biloxi.com",
            "response_hash",
            1,
            "cnonce123",
            AuthHeaderType::Authorization,
        );

        assert!(header.starts_with("Digest "));
        assert!(header.contains(r#"username="bob""#));
        assert!(header.contains(r#"realm="biloxi.com""#));
        assert!(header.contains(r#"nonce="dcd98b""#));
        assert!(header.contains(r#"uri="sip:biloxi.com""#));
        assert!(header.contains(r#"response="response_hash""#));
        assert!(header.contains("algorithm=MD5"));
        // No qop/nc/cnonce when qop is None
        assert!(!header.contains("qop="));
        assert!(!header.contains("nc="));
        assert!(!header.contains("cnonce="));
    }

    #[test]
    fn test_build_auth_header_with_qop() {
        let challenge = DigestChallenge {
            realm: "atlanta.com".to_string(),
            nonce: "84a4cc6f".to_string(),
            opaque: Some("5ccc069c".to_string()),
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let header = build_auth_header(
            &challenge,
            "alice",
            "sip:atlanta.com",
            "response_hash",
            1,
            "cnonce_value",
            AuthHeaderType::Authorization,
        );

        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains(r#"cnonce="cnonce_value""#));
        assert!(header.contains(r#"opaque="5ccc069c""#));
    }

    #[test]
    fn test_build_auth_header_sha256() {
        let challenge = DigestChallenge {
            realm: "test.com".to_string(),
            nonce: "abc".to_string(),
            opaque: None,
            qop: None,
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        };

        let header = build_auth_header(
            &challenge,
            "user",
            "sip:test.com",
            "response_hash",
            1,
            "cnonce",
            AuthHeaderType::Authorization,
        );

        assert!(header.contains("algorithm=SHA-256"));
    }

    // -----------------------------------------------------------------------
    // DigestCredentials tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_credentials_new() {
        let creds = DigestCredentials::new("alice", "secret");
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.password, "secret");
        assert!(!creds.has_cached_nonce());
        assert_eq!(creds.nc, 0);
    }

    #[test]
    fn test_credentials_authorize_and_cache() {
        let mut creds = DigestCredentials::new("alice", "secret");

        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "nonce123".to_string(),
            opaque: Some("opaque_val".to_string()),
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        let header = creds.authorize(
            &challenge,
            "REGISTER",
            "sip:example.com",
            AuthHeaderType::Authorization,
        );

        // Should produce a valid header
        assert!(header.starts_with("Digest "));
        assert!(header.contains(r#"username="alice""#));
        assert!(header.contains("nc=00000001"));

        // Cache should be populated
        assert!(creds.has_cached_nonce());
        assert_eq!(creds.nc, 1);

        // Second authorize with same challenge should increment nc
        let header2 = creds.authorize(
            &challenge,
            "REGISTER",
            "sip:example.com",
            AuthHeaderType::Authorization,
        );
        assert!(header2.contains("nc=00000002"));
        assert_eq!(creds.nc, 2);
    }

    #[test]
    fn test_credentials_authorize_cached() {
        let mut creds = DigestCredentials::new("bob", "password");

        // No cache yet — should return None
        assert!(creds.authorize_cached("REGISTER", "sip:test.com", AuthHeaderType::Authorization).is_none());

        // Authorize with a challenge to populate cache
        let challenge = DigestChallenge {
            realm: "test.com".to_string(),
            nonce: "cached_nonce".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        creds.authorize(&challenge, "REGISTER", "sip:test.com", AuthHeaderType::Authorization);

        // Now cached authorize should work
        let header = creds
            .authorize_cached("REGISTER", "sip:test.com", AuthHeaderType::Authorization)
            .unwrap();
        assert!(header.contains(r#"nonce="cached_nonce""#));
        assert!(header.contains("nc=00000002")); // nc incremented
    }

    #[test]
    fn test_credentials_stale_nonce_refresh() {
        let mut creds = DigestCredentials::new("alice", "secret");

        // Initial challenge
        let challenge1 = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "old_nonce".to_string(),
            opaque: Some("opaque1".to_string()),
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        creds.authorize(
            &challenge1,
            "REGISTER",
            "sip:example.com",
            AuthHeaderType::Authorization,
        );
        assert_eq!(creds.nc, 1);

        // Stale challenge — nonce refreshed, nc reset, opaque preserved from original
        let challenge2 = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "new_nonce".to_string(),
            opaque: Some("opaque1".to_string()),
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: true,
        };
        let header = creds.authorize(
            &challenge2,
            "REGISTER",
            "sip:example.com",
            AuthHeaderType::Authorization,
        );

        // nc should be reset to 1 (stale resets to 0, then authorize increments)
        assert!(header.contains("nc=00000001"));
        assert!(header.contains(r#"nonce="new_nonce""#));
    }

    #[test]
    fn test_credentials_clear_cache() {
        let mut creds = DigestCredentials::new("alice", "secret");

        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "nonce123".to_string(),
            opaque: None,
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        creds.authorize(
            &challenge,
            "REGISTER",
            "sip:example.com",
            AuthHeaderType::Authorization,
        );
        assert!(creds.has_cached_nonce());

        creds.clear_cache();
        assert!(!creds.has_cached_nonce());
        assert_eq!(creds.nc, 0);
    }

    #[test]
    fn test_credentials_nc_incrementing_with_qop() {
        let mut creds = DigestCredentials::new("user", "pass");

        let challenge = DigestChallenge {
            realm: "realm".to_string(),
            nonce: "nonce".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };

        for expected_nc in 1..=5u32 {
            let header = creds.authorize(
                &challenge,
                "REGISTER",
                "sip:realm",
                AuthHeaderType::Authorization,
            );
            let expected = format!("nc={:08x}", expected_nc);
            assert!(
                header.contains(&expected),
                "expected {} in header: {}",
                expected,
                header
            );
        }
    }

    // -----------------------------------------------------------------------
    // parse_params edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_params_extra_whitespace() {
        let header = r#"Digest  realm = "test.com" ,  nonce = "abc"  , algorithm = MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "test.com");
        assert_eq!(challenge.nonce, "abc");
    }

    #[test]
    fn test_parse_params_no_spaces() {
        let header = r#"Digest realm="test.com",nonce="abc",algorithm=MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "test.com");
        assert_eq!(challenge.nonce, "abc");
    }

    // -----------------------------------------------------------------------
    // Hash function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_md5_known_value() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let result = hash(DigestAlgorithm::Md5, "");
        assert_eq!(result, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_hash_sha256_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = hash(DigestAlgorithm::Sha256, "");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_md5_abc() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let result = hash(DigestAlgorithm::Md5, "abc");
        assert_eq!(result, "900150983cd24fb0d6963f7d28e17f72");
    }

    // -----------------------------------------------------------------------
    // Algorithm parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_algorithm_parse_md5() {
        assert_eq!(DigestAlgorithm::parse("MD5"), DigestAlgorithm::Md5);
        assert_eq!(DigestAlgorithm::parse("md5"), DigestAlgorithm::Md5);
    }

    #[test]
    fn test_algorithm_parse_sha256() {
        assert_eq!(DigestAlgorithm::parse("SHA-256"), DigestAlgorithm::Sha256);
        assert_eq!(DigestAlgorithm::parse("sha-256"), DigestAlgorithm::Sha256);
        assert_eq!(DigestAlgorithm::parse("sha256"), DigestAlgorithm::Sha256);
    }

    #[test]
    fn test_algorithm_parse_unknown_defaults_md5() {
        assert_eq!(DigestAlgorithm::parse("unknown"), DigestAlgorithm::Md5);
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(DigestAlgorithm::Md5.to_string(), "MD5");
        assert_eq!(DigestAlgorithm::Sha256.to_string(), "SHA-256");
    }

    // -----------------------------------------------------------------------
    // DigestChallenge::parse (via struct method)
    // -----------------------------------------------------------------------

    #[test]
    fn test_challenge_parse_method() {
        let header = r#"Digest realm="test.com", nonce="abc""#;
        let challenge = DigestChallenge::parse(header).unwrap();
        assert_eq!(challenge.realm, "test.com");
    }

    // -----------------------------------------------------------------------
    // AuthHeaderType coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_header_type_debug() {
        // Ensure both variants are usable
        assert_eq!(
            format!("{:?}", AuthHeaderType::Authorization),
            "Authorization"
        );
        assert_eq!(
            format!("{:?}", AuthHeaderType::ProxyAuthorization),
            "ProxyAuthorization"
        );
    }

    // -----------------------------------------------------------------------
    // Integration-style test: full round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_round_trip_401_flow() {
        // Simulate: REGISTER → 401 → parse challenge → compute → build header → verify

        // 1. Server sends 401 with WWW-Authenticate
        let www_authenticate =
            r#"Digest realm="atlanta.com", nonce="84a4cc6f3082121f32b42a2187831a9e", qop="auth", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5"#;

        // 2. Client parses the challenge
        let challenge = parse_challenge(www_authenticate).unwrap();
        assert_eq!(challenge.realm, "atlanta.com");
        assert_eq!(challenge.qop, Some(Qop::Auth));

        // 3. Client computes response
        let mut creds = DigestCredentials::new("alice", "password123");
        let header = creds.authorize(
            &challenge,
            "REGISTER",
            "sip:atlanta.com",
            AuthHeaderType::Authorization,
        );

        // 4. Verify the header is well-formed
        assert!(header.starts_with("Digest "));
        assert!(header.contains(r#"username="alice""#));
        assert!(header.contains(r#"realm="atlanta.com""#));
        assert!(header.contains(r#"nonce="84a4cc6f3082121f32b42a2187831a9e""#));
        assert!(header.contains(r#"uri="sip:atlanta.com""#));
        assert!(header.contains("algorithm=MD5"));
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains(r#"opaque="5ccc069c403ebaf9f0171e9517f40e41""#));

        // 5. The response field should be a 32-char hex string (MD5)
        let response_start = header.find(r#"response=""#).unwrap() + 10;
        let response_end = header[response_start..].find('"').unwrap() + response_start;
        let response_value = &header[response_start..response_end];
        assert_eq!(response_value.len(), 32);
        assert!(response_value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_full_round_trip_407_flow() {
        // Same as 401 but with Proxy-Authorization header type
        let proxy_authenticate =
            r#"Digest realm="proxy.example.com", nonce="aabbccdd", qop="auth""#;
        let challenge = parse_challenge(proxy_authenticate).unwrap();

        let mut creds = DigestCredentials::new("bob", "secret");
        let header = creds.authorize(
            &challenge,
            "REGISTER",
            "sip:proxy.example.com",
            AuthHeaderType::ProxyAuthorization,
        );

        assert!(header.starts_with("Digest "));
        assert!(header.contains(r#"username="bob""#));
        assert!(header.contains(r#"realm="proxy.example.com""#));
    }

    #[test]
    fn test_reregistration_with_cached_nonce() {
        // Simulate re-registration reusing cached nonce

        let mut creds = DigestCredentials::new("user", "pass");

        // First registration: 401 → auth → 200 OK
        let challenge = DigestChallenge {
            realm: "pbx.local".to_string(),
            nonce: "first_nonce_value".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        creds.authorize(
            &challenge,
            "REGISTER",
            "sip:pbx.local",
            AuthHeaderType::Authorization,
        );

        // Re-registration: use cached nonce (no 401 round-trip)
        let header = creds
            .authorize_cached("REGISTER", "sip:pbx.local", AuthHeaderType::Authorization)
            .expect("should have cached nonce");
        assert!(header.contains(r#"nonce="first_nonce_value""#));
        assert!(header.contains("nc=00000002"));

        // Third registration with cache
        let header = creds
            .authorize_cached("REGISTER", "sip:pbx.local", AuthHeaderType::Authorization)
            .expect("should have cached nonce");
        assert!(header.contains("nc=00000003"));

        // Server says stale=true — update nonce
        let stale_challenge = DigestChallenge {
            realm: "pbx.local".to_string(),
            nonce: "second_nonce_value".to_string(),
            opaque: None,
            qop: Some(Qop::Auth),
            algorithm: DigestAlgorithm::Md5,
            stale: true,
        };
        let header = creds.authorize(
            &stale_challenge,
            "REGISTER",
            "sip:pbx.local",
            AuthHeaderType::Authorization,
        );
        assert!(header.contains(r#"nonce="second_nonce_value""#));
        assert!(header.contains("nc=00000001")); // Reset after stale
    }
}
