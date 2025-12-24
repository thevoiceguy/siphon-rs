// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP-ETag and SIP-If-Match headers (RFC 3903).
//!
//! These headers are used with the PUBLISH method for event state publication.
//!
//! - **SIP-ETag**: Server-assigned entity tag identifying a publication
//! - **SIP-If-Match**: Client-provided entity tag for conditional operations
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

use std::fmt;

use smol_str::SmolStr;

/// The SIP-ETag header (RFC 3903).
///
/// The SIP-ETag header is used by the Event State Compositor (ESC) to identify
/// a specific publication. It's returned in 200 OK responses to PUBLISH requests.
///
/// The entity-tag is an opaque string assigned by the server that uniquely
/// identifies a publication. Clients use this value in SIP-If-Match headers
/// for subsequent operations on the same publication.
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
/// ```ignore
/// use sip_core::SipETagHeader;
///
/// // Server generates entity-tag
/// let etag = SipETagHeader::new("dx200xyz");
///
/// // Add to 200 OK response
/// response.headers_mut().set("SIP-ETag", &etag.to_string());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipETagHeader {
    /// The entity-tag value
    pub value: SmolStr,
}

impl SipETagHeader {
    /// Creates a new SIP-ETag header with the given entity-tag.
    ///
    /// # Arguments
    ///
    /// * `value` - The entity-tag value (an opaque string)
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipETagHeader;
    ///
    /// let etag = SipETagHeader::new("dx200xyz");
    /// assert_eq!(etag.value, "dx200xyz");
    /// ```
    pub fn new(value: &str) -> Self {
        Self {
            value: SmolStr::new(value),
        }
    }

    /// Parses a SIP-ETag header from a string.
    ///
    /// # Returns
    ///
    /// - `Some(SipETagHeader)` if parsing succeeds
    /// - `None` if the header is empty or invalid
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipETagHeader;
    ///
    /// let etag = SipETagHeader::parse("dx200xyz").unwrap();
    /// assert_eq!(etag.value, "dx200xyz");
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let value = input.trim();
        if value.is_empty() {
            return None;
        }
        Some(Self {
            value: SmolStr::new(value),
        })
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
/// # Operations
///
/// - **Refresh**: No body, SIP-If-Match present → Extends publication lifetime
/// - **Modify**: Body present, SIP-If-Match present → Updates publication content
/// - **Remove**: No body, SIP-If-Match present, Expires=0 → Deletes publication
///
/// # Example
///
/// ```ignore
/// use sip_core::SipIfMatchHeader;
///
/// // Client wants to refresh publication
/// let if_match = SipIfMatchHeader::new("dx200xyz");
///
/// // Add to PUBLISH request
/// request.headers_mut().set("SIP-If-Match", &if_match.to_string());
/// request.headers_mut().set("Expires", "3600");
/// // No body for refresh
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipIfMatchHeader {
    /// The entity-tag value (must match a previous SIP-ETag)
    pub value: SmolStr,
}

impl SipIfMatchHeader {
    /// Creates a new SIP-If-Match header with the given entity-tag.
    ///
    /// # Arguments
    ///
    /// * `value` - The entity-tag value from a previous SIP-ETag
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipIfMatchHeader;
    ///
    /// let if_match = SipIfMatchHeader::new("dx200xyz");
    /// assert_eq!(if_match.value, "dx200xyz");
    /// ```
    pub fn new(value: &str) -> Self {
        Self {
            value: SmolStr::new(value),
        }
    }

    /// Parses a SIP-If-Match header from a string.
    ///
    /// # Returns
    ///
    /// - `Some(SipIfMatchHeader)` if parsing succeeds
    /// - `None` if the header is empty or invalid
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipIfMatchHeader;
    ///
    /// let if_match = SipIfMatchHeader::parse("dx200xyz").unwrap();
    /// assert_eq!(if_match.value, "dx200xyz");
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let value = input.trim();
        if value.is_empty() {
            return None;
        }
        Some(Self {
            value: SmolStr::new(value),
        })
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
        let etag = SipETagHeader::new("dx200xyz");
        assert_eq!(etag.value, "dx200xyz");
    }

    #[test]
    fn sip_etag_format() {
        let etag = SipETagHeader::new("dx200xyz");
        assert_eq!(etag.to_string(), "dx200xyz");
    }

    #[test]
    fn sip_etag_parse() {
        let etag = SipETagHeader::parse("dx200xyz").unwrap();
        assert_eq!(etag.value, "dx200xyz");
    }

    #[test]
    fn sip_etag_parse_with_whitespace() {
        let etag = SipETagHeader::parse("  dx200xyz  ").unwrap();
        assert_eq!(etag.value, "dx200xyz");
    }

    #[test]
    fn sip_etag_parse_empty() {
        assert!(SipETagHeader::parse("").is_none());
        assert!(SipETagHeader::parse("   ").is_none());
    }

    #[test]
    fn sip_etag_round_trip() {
        let original = SipETagHeader::new("kwj449x");
        let formatted = original.to_string();
        let parsed = SipETagHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn sip_if_match_basic() {
        let if_match = SipIfMatchHeader::new("dx200xyz");
        assert_eq!(if_match.value, "dx200xyz");
    }

    #[test]
    fn sip_if_match_format() {
        let if_match = SipIfMatchHeader::new("dx200xyz");
        assert_eq!(if_match.to_string(), "dx200xyz");
    }

    #[test]
    fn sip_if_match_parse() {
        let if_match = SipIfMatchHeader::parse("dx200xyz").unwrap();
        assert_eq!(if_match.value, "dx200xyz");
    }

    #[test]
    fn sip_if_match_parse_with_whitespace() {
        let if_match = SipIfMatchHeader::parse("  kwj449x  ").unwrap();
        assert_eq!(if_match.value, "kwj449x");
    }

    #[test]
    fn sip_if_match_parse_empty() {
        assert!(SipIfMatchHeader::parse("").is_none());
        assert!(SipIfMatchHeader::parse("   ").is_none());
    }

    #[test]
    fn sip_if_match_round_trip() {
        let original = SipIfMatchHeader::new("abc123xyz");
        let formatted = original.to_string();
        let parsed = SipIfMatchHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn etag_and_if_match_match() {
        let etag = SipETagHeader::new("dx200xyz");
        let if_match = SipIfMatchHeader::new("dx200xyz");
        assert_eq!(etag.value, if_match.value);
    }
}
