// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP-ETag and SIP-If-Match headers (RFC 3903) with security hardening.
//!
//! These headers are used with the PUBLISH method for event state publication.
//!
//! - **SIP-ETag**: Server-assigned entity tag identifying a publication
//! - **SIP-If-Match**: Client-provided entity tag for conditional operations
//!
//! # Security
//!
//! Entity-tag values are validated for length and content to prevent:
//! - DoS attacks via unbounded strings
//! - CRLF injection attacks
//! - Control character injection
//!
//! # Format
//!
//! ```text
//! SIP-ETag: entity-tag
//! SIP-If-Match: entity-tag
//! ```
//!
//! # Example
//!
//! ```text
//! SIP-ETag: dx200xyz
//! SIP-If-Match: dx200xyz
//! ```

use smol_str::SmolStr;
use std::fmt;

// Security: Input size limits
const MAX_ENTITY_TAG_LENGTH: usize = 128;

/// Error types for entity-tag operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityTagError {
    /// Entity-tag is empty
    Empty,
    /// Entity-tag too long
    TooLong { max: usize },
    /// Entity-tag contains invalid characters
    InvalidCharacters(String),
}

impl fmt::Display for EntityTagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityTagError::Empty => write!(f, "Entity-tag cannot be empty"),
            EntityTagError::TooLong { max } => {
                write!(f, "Entity-tag too long (max {})", max)
            }
            EntityTagError::InvalidCharacters(msg) => {
                write!(f, "Entity-tag contains invalid characters: {}", msg)
            }
        }
    }
}

impl std::error::Error for EntityTagError {}

/// Validates an entity-tag value.
fn validate_entity_tag(value: &str) -> Result<(), EntityTagError> {
    if value.is_empty() {
        return Err(EntityTagError::Empty);
    }

    if value.len() > MAX_ENTITY_TAG_LENGTH {
        return Err(EntityTagError::TooLong {
            max: MAX_ENTITY_TAG_LENGTH,
        });
    }

    // Entity-tag is a token per RFC 3903/3261.
    if value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
    {
        return Err(EntityTagError::InvalidCharacters(
            "contains control or whitespace characters".to_string(),
        ));
    }

    let invalid = value.chars().any(|c| {
        !(c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
            ))
    });
    if invalid {
        return Err(EntityTagError::InvalidCharacters(
            "contains non-token characters".to_string(),
        ));
    }

    Ok(())
}

/// The SIP-ETag header (RFC 3903).
///
/// The SIP-ETag header is used by the Event State Compositor (ESC) to identify
/// a specific publication. It's returned in 200 OK responses to PUBLISH requests.
///
/// The entity-tag is an opaque string assigned by the server that uniquely
/// identifies a publication. Clients use this value in SIP-If-Match headers
/// for subsequent operations on the same publication.
///
/// # Security
///
/// Entity-tag values are validated for:
/// - Maximum length of 128 characters
/// - No control characters (prevents CRLF injection)
/// - Non-empty after trimming
///
/// # Usage
///
/// ## Server (ESC) Side
///
/// When receiving an initial PUBLISH request (no SIP-If-Match header):
/// 1. Create a new publication
/// 2. Generate a unique entity-tag
/// 3. Return it in the SIP-ETag header of the 200 OK response
///
/// ## Client (EPA) Side
///
/// When receiving a 200 OK response to PUBLISH:
/// 1. Extract the SIP-ETag value
/// 2. Store it for the publication
/// 3. Use it in SIP-If-Match for refresh/modify/remove operations
///
/// # Example
///
/// ```
/// use sip_core::SipETagHeader;
///
/// // Server generates entity-tag
/// let etag = SipETagHeader::new("dx200xyz").unwrap();
///
/// // Format for header
/// let header_value = etag.to_string();
/// assert_eq!(header_value, "dx200xyz");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipETagHeader {
    /// The entity-tag value
    value: SmolStr,
}

impl SipETagHeader {
    /// Creates a new SIP-ETag header with validation.
    ///
    /// # Arguments
    ///
    /// * `value` - The entity-tag value (an opaque string)
    ///
    /// # Errors
    ///
    /// Returns `EntityTagError` if:
    /// - Value is empty or whitespace-only
    /// - Value exceeds 128 characters
    /// - Value contains control characters
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipETagHeader;
    ///
    /// let etag = SipETagHeader::new("dx200xyz").unwrap();
    /// assert_eq!(etag.value(), "dx200xyz");
    /// ```
    pub fn new(value: &str) -> Result<Self, EntityTagError> {
        validate_entity_tag(value)?;
        Ok(Self {
            value: SmolStr::new(value),
        })
    }

    /// Gets the entity-tag value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Parses a SIP-ETag header from a string with validation.
    ///
    /// # Returns
    ///
    /// - `Ok(SipETagHeader)` if parsing and validation succeed
    /// - `Err(EntityTagError)` if validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipETagHeader;
    ///
    /// let etag = SipETagHeader::parse("dx200xyz").unwrap();
    /// assert_eq!(etag.value(), "dx200xyz");
    /// ```
    pub fn parse(input: &str) -> Result<Self, EntityTagError> {
        Self::new(input)
    }

    /// Compares this entity-tag with another in constant time.
    ///
    /// This helps prevent timing attacks when validating entity-tags.
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.value.as_bytes().ct_eq(other.value.as_bytes()).into()
    }
}

impl fmt::Display for SipETagHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// The SIP-If-Match header (RFC 3903).
///
/// The SIP-If-Match header is used by clients (Event Publication Agents) to
/// identify which publication they want to refresh, modify, or remove.
///
/// The value must match a SIP-ETag previously returned by the server. If the
/// entity-tag doesn't match or has expired, the server returns 412 Conditional
/// Request Failed.
///
/// # Security
///
/// Entity-tag values are validated for:
/// - Maximum length of 128 characters
/// - No control characters (prevents CRLF injection)
/// - Non-empty after trimming
///
/// When comparing entity-tags, use `constant_time_eq()` to prevent timing attacks.
///
/// # Operations
///
/// - **Refresh**: No body, SIP-If-Match present → Extends publication lifetime
/// - **Modify**: Body present, SIP-If-Match present → Updates publication content
/// - **Remove**: No body, SIP-If-Match present, Expires=0 → Deletes publication
///
/// # Example
///
/// ```
/// use sip_core::SipIfMatchHeader;
///
/// // Client wants to refresh publication
/// let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();
///
/// // Format for header
/// let header_value = if_match.to_string();
/// assert_eq!(header_value, "dx200xyz");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipIfMatchHeader {
    /// The entity-tag value (must match a previous SIP-ETag)
    value: SmolStr,
}

impl SipIfMatchHeader {
    /// Creates a new SIP-If-Match header with validation.
    ///
    /// # Arguments
    ///
    /// * `value` - The entity-tag value from a previous SIP-ETag
    ///
    /// # Errors
    ///
    /// Returns `EntityTagError` if:
    /// - Value is empty or whitespace-only
    /// - Value exceeds 128 characters
    /// - Value contains control characters
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipIfMatchHeader;
    ///
    /// let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();
    /// assert_eq!(if_match.value(), "dx200xyz");
    /// ```
    pub fn new(value: &str) -> Result<Self, EntityTagError> {
        validate_entity_tag(value)?;
        Ok(Self {
            value: SmolStr::new(value),
        })
    }

    /// Gets the entity-tag value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Parses a SIP-If-Match header from a string with validation.
    ///
    /// # Returns
    ///
    /// - `Ok(SipIfMatchHeader)` if parsing and validation succeed
    /// - `Err(EntityTagError)` if validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipIfMatchHeader;
    ///
    /// let if_match = SipIfMatchHeader::parse("dx200xyz").unwrap();
    /// assert_eq!(if_match.value(), "dx200xyz");
    /// ```
    pub fn parse(input: &str) -> Result<Self, EntityTagError> {
        Self::new(input)
    }

    /// Compares this entity-tag with a SIP-ETag in constant time.
    ///
    /// This helps prevent timing attacks when validating entity-tags.
    pub fn matches_etag(&self, etag: &SipETagHeader) -> bool {
        use subtle::ConstantTimeEq;
        self.value.as_bytes().ct_eq(etag.value.as_bytes()).into()
    }

    /// Compares this entity-tag with another in constant time.
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.value.as_bytes().ct_eq(other.value.as_bytes()).into()
    }
}

impl fmt::Display for SipIfMatchHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_etag_basic() {
        let etag = SipETagHeader::new("dx200xyz").unwrap();
        assert_eq!(etag.value(), "dx200xyz");
    }

    #[test]
    fn sip_etag_format() {
        let etag = SipETagHeader::new("dx200xyz").unwrap();
        assert_eq!(etag.to_string(), "dx200xyz");
    }

    #[test]
    fn sip_etag_parse() {
        let etag = SipETagHeader::parse("dx200xyz").unwrap();
        assert_eq!(etag.value(), "dx200xyz");
    }

    #[test]
    fn sip_etag_parse_with_whitespace() {
        assert!(SipETagHeader::parse("  dx200xyz  ").is_err());
    }

    #[test]
    fn sip_etag_parse_empty() {
        assert!(matches!(
            SipETagHeader::parse(""),
            Err(EntityTagError::Empty)
        ));
        assert!(matches!(
            SipETagHeader::parse("   "),
            Err(EntityTagError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn sip_etag_rejects_too_long() {
        let long_tag = "x".repeat(MAX_ENTITY_TAG_LENGTH + 1);
        assert!(matches!(
            SipETagHeader::new(&long_tag),
            Err(EntityTagError::TooLong { .. })
        ));
    }

    #[test]
    fn sip_etag_rejects_control_chars() {
        assert!(matches!(
            SipETagHeader::new("dx200\nxyz"),
            Err(EntityTagError::InvalidCharacters(_))
        ));
        assert!(matches!(
            SipETagHeader::new("dx200\rxyz"),
            Err(EntityTagError::InvalidCharacters(_))
        ));
        assert!(matches!(
            SipETagHeader::new("dx200\r\nxyz"),
            Err(EntityTagError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn sip_etag_accepts_max_length() {
        let max_tag = "x".repeat(MAX_ENTITY_TAG_LENGTH);
        assert!(SipETagHeader::new(&max_tag).is_ok());
    }

    #[test]
    fn sip_etag_round_trip() {
        let original = SipETagHeader::new("kwj449x").unwrap();
        let formatted = original.to_string();
        let parsed = SipETagHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn sip_if_match_basic() {
        let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();
        assert_eq!(if_match.value(), "dx200xyz");
    }

    #[test]
    fn sip_if_match_format() {
        let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();
        assert_eq!(if_match.to_string(), "dx200xyz");
    }

    #[test]
    fn sip_if_match_parse() {
        let if_match = SipIfMatchHeader::parse("dx200xyz").unwrap();
        assert_eq!(if_match.value(), "dx200xyz");
    }

    #[test]
    fn sip_if_match_parse_with_whitespace() {
        assert!(SipIfMatchHeader::parse("  kwj449x  ").is_err());
    }

    #[test]
    fn sip_if_match_parse_empty() {
        assert!(matches!(
            SipIfMatchHeader::parse(""),
            Err(EntityTagError::Empty)
        ));
        assert!(matches!(
            SipIfMatchHeader::parse("   "),
            Err(EntityTagError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn sip_if_match_rejects_too_long() {
        let long_tag = "x".repeat(MAX_ENTITY_TAG_LENGTH + 1);
        assert!(matches!(
            SipIfMatchHeader::new(&long_tag),
            Err(EntityTagError::TooLong { .. })
        ));
    }

    #[test]
    fn sip_if_match_rejects_control_chars() {
        assert!(matches!(
            SipIfMatchHeader::new("dx200\nxyz"),
            Err(EntityTagError::InvalidCharacters(_))
        ));
        assert!(matches!(
            SipIfMatchHeader::new("dx200\rxyz"),
            Err(EntityTagError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn sip_if_match_accepts_max_length() {
        let max_tag = "x".repeat(MAX_ENTITY_TAG_LENGTH);
        assert!(SipIfMatchHeader::new(&max_tag).is_ok());
    }

    #[test]
    fn sip_if_match_round_trip() {
        let original = SipIfMatchHeader::new("abc123xyz").unwrap();
        let formatted = original.to_string();
        let parsed = SipIfMatchHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn etag_and_if_match_match() {
        let etag = SipETagHeader::new("dx200xyz").unwrap();
        let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();
        assert_eq!(etag.value(), if_match.value());
    }

    #[test]
    fn if_match_matches_etag() {
        let etag = SipETagHeader::new("dx200xyz").unwrap();
        let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();
        assert!(if_match.matches_etag(&etag));

        let other_etag = SipETagHeader::new("abc123").unwrap();
        assert!(!if_match.matches_etag(&other_etag));
    }

    #[test]
    fn constant_time_eq_works() {
        let etag1 = SipETagHeader::new("dx200xyz").unwrap();
        let etag2 = SipETagHeader::new("dx200xyz").unwrap();
        let etag3 = SipETagHeader::new("abc123").unwrap();

        assert!(etag1.constant_time_eq(&etag2));
        assert!(!etag1.constant_time_eq(&etag3));

        let if_match1 = SipIfMatchHeader::new("dx200xyz").unwrap();
        let if_match2 = SipIfMatchHeader::new("dx200xyz").unwrap();
        let if_match3 = SipIfMatchHeader::new("abc123").unwrap();

        assert!(if_match1.constant_time_eq(&if_match2));
        assert!(!if_match1.constant_time_eq(&if_match3));
    }

    #[test]
    fn fields_are_private() {
        let etag = SipETagHeader::new("dx200xyz").unwrap();
        let if_match = SipIfMatchHeader::new("dx200xyz").unwrap();

        // These should compile (read access via getters)
        let _ = etag.value();
        let _ = if_match.value();

        // These should NOT compile:
        // etag.value = SmolStr::new("evil");              // ← Does not compile!
        // if_match.value = SmolStr::new("evil");          // ← Does not compile!
    }

    #[test]
    fn rejects_various_control_characters() {
        // Test various control characters
        assert!(SipETagHeader::new("test\x00value").is_err());
        assert!(SipETagHeader::new("test\x01value").is_err());
        assert!(SipETagHeader::new("test\x1fvalue").is_err());
        assert!(SipETagHeader::new("test\x7fvalue").is_err());
    }

    #[test]
    fn accepts_common_characters() {
        // Should accept alphanumeric and common punctuation
        assert!(SipETagHeader::new("abc123").is_ok());
        assert!(SipETagHeader::new("abc-123").is_ok());
        assert!(SipETagHeader::new("abc_123").is_ok());
        assert!(SipETagHeader::new("abc.123").is_ok());
        assert!(SipETagHeader::new("abc!%*+`'~").is_ok());
    }

    #[test]
    fn rejects_non_ascii_or_whitespace() {
        assert!(SipETagHeader::new("abc xyz").is_err());
        assert!(SipETagHeader::new("naïve").is_err());
        assert!(SipETagHeader::new("标签").is_err());
    }
}
