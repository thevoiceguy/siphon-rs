// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP Referred-By header (RFC 3892).
//!
//! The Referred-By header provides authenticated identity information about
//! the referrer in SIP call transfer and referral scenarios. It allows the
//! refer target to verify who initiated the transfer.
//!
//! # Format
//!
//! ```text
//! Referred-By: <sip:referrer@example.com>
//! Referred-By: "Alice" <sip:alice@example.com>;cid="12345@example.com"
//! ```
//!
//! # Usage
//!
//! The Referred-By header is used in two places:
//! 1. In REFER requests to identify the referrer
//! 2. In triggered INVITE requests (copied from the REFER)
//!
//! # Security
//!
//! When the `cid` parameter is present, it references a multipart body
//! containing an S/MIME signed identity token (Authenticated Identity Body).
//! This provides cryptographic proof of the referrer's identity.

use std::collections::BTreeMap;
use std::fmt;

use smol_str::SmolStr;

use crate::name_addr::NameAddr;
use crate::{SipUri, Uri};

/// The Referred-By header (RFC 3892).
///
/// The Referred-By header carries authenticated referrer identity information
/// in call transfer and referral scenarios. It appears in REFER requests and
/// is copied into the triggered INVITE.
///
/// # Components
///
/// - **URI**: The referrer's address (typically their address-of-record)
/// - **cid parameter**: Optional Content-ID referencing an S/MIME signature
/// - **Other parameters**: Generic parameter support
///
/// # Usage Scenarios
///
/// ## Call Transfer
///
/// 1. Alice (referrer) sends REFER to Bob (referee) to call Charlie (refer target)
/// 2. REFER includes: `Referred-By: <sip:alice@example.com>`
/// 3. Bob sends INVITE to Charlie, copying the Referred-By header
/// 4. Charlie can see that Alice initiated the transfer
///
/// ## Authenticated Transfer
///
/// 1. Alice sends REFER with signed identity:
///    ```text
///    Referred-By: <sip:alice@example.com>;cid="sig123@example.com"
///    Content-Type: multipart/signed
///    [S/MIME signature body]
///    ```
/// 2. Bob copies both header and signature body to INVITE
/// 3. Charlie verifies the signature to confirm Alice's identity
///
/// # Security Benefits
///
/// - **Authentication**: Cryptographically verify referrer identity
/// - **Integrity**: Detect if referee modified the referral
/// - **Non-repudiation**: Referrer cannot deny initiating the transfer
/// - **Authorization**: Make policy decisions based on verified identity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferredByHeader {
    /// The referrer's address (name-addr format)
    pub name_addr: NameAddr,
    /// Optional Content-ID referencing an S/MIME signature
    pub cid: Option<SmolStr>,
    /// Additional parameters
    pub params: BTreeMap<SmolStr, SmolStr>,
}

impl ReferredByHeader {
    /// Creates a new Referred-By header with the given URI.
    ///
    /// # Arguments
    ///
    /// * `uri` - The referrer's SIP URI
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::new("sip:alice@example.com");
    /// ```
    pub fn new(uri: &str) -> Self {
        let parsed_uri = SipUri::parse(uri).expect("Invalid SIP URI");
        let name_addr = NameAddr::new(None, Uri::from(parsed_uri), BTreeMap::new())
            .expect("valid name-addr");
        Self {
            name_addr,
            cid: None,
            params: BTreeMap::new(),
        }
    }

    /// Creates a new Referred-By header with a display name and URI.
    ///
    /// # Arguments
    ///
    /// * `display_name` - The referrer's display name
    /// * `uri` - The referrer's SIP URI
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::with_name(
    ///     "Alice",
    ///     "sip:alice@example.com"
    /// );
    /// ```
    pub fn with_name(display_name: &str, uri: &str) -> Self {
        let parsed_uri = SipUri::parse(uri).expect("Invalid SIP URI");
        let name_addr = NameAddr::new(
            Some(SmolStr::new(display_name)),
            Uri::from(parsed_uri),
            BTreeMap::new(),
        )
        .expect("valid name-addr");
        Self {
            name_addr,
            cid: None,
            params: BTreeMap::new(),
        }
    }

    /// Sets the Content-ID parameter.
    ///
    /// The cid parameter references a MIME body part containing an S/MIME
    /// signature that authenticates the referrer's identity.
    ///
    /// # Arguments
    ///
    /// * `cid` - The Content-ID value (e.g., "12345@example.com")
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::new("sip:alice@example.com")
    ///     .with_cid("signature123@example.com");
    /// ```
    pub fn with_cid(mut self, cid: &str) -> Self {
        self.cid = Some(SmolStr::new(cid));
        self
    }

    /// Adds a parameter to the header.
    ///
    /// # Arguments
    ///
    /// * `name` - The parameter name
    /// * `value` - The parameter value
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::new("sip:alice@example.com")
    ///     .with_param("tag", "abc123");
    /// ```
    pub fn with_param(mut self, name: &str, value: &str) -> Self {
        self.params.insert(SmolStr::new(name), SmolStr::new(value));
        self
    }

    /// Returns true if the header includes a Content-ID (signature reference).
    pub fn has_signature(&self) -> bool {
        self.cid.is_some()
    }

    /// Gets the Content-ID if present.
    pub fn get_cid(&self) -> Option<&str> {
        self.cid.as_deref()
    }

    /// Gets a parameter value by name.
    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }

    /// Parses a Referred-By header from a string.
    ///
    /// # Format
    ///
    /// ```text
    /// <sip:uri@domain> [;param=value]*
    /// "Display Name" <sip:uri@domain> [;param=value]*
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(ReferredByHeader)` if parsing succeeds
    /// - `None` if the header is malformed
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let header = ReferredByHeader::parse(
    ///     r#""Alice" <sip:alice@example.com>;cid="sig123@example.com""#
    /// ).unwrap();
    ///
    /// assert_eq!(header.name_addr.display_name().map(|s| s.as_str()), Some("Alice"));
    /// assert_eq!(header.cid.as_deref(), Some("sig123@example.com"));
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();

        // Find the end of the name-addr part (before parameters)
        let (name_addr_str, params_str) = if let Some(angle_end) = input.rfind('>') {
            // Has angle brackets: everything up to and including '>' is name-addr
            let na = &input[..=angle_end];
            let rest = input[angle_end + 1..].trim();
            (na, rest)
        } else {
            // No angle brackets: split at first semicolon
            if let Some(semi_pos) = input.find(';') {
                (&input[..semi_pos], input[semi_pos..].trim())
            } else {
                (input, "")
            }
        };

        // Parse the name-addr (display name and URI)
        let (display_name, uri_str) = if name_addr_str.contains('<') && name_addr_str.contains('>')
        {
            // Format: "Display Name" <sip:uri> or <sip:uri>
            let angle_start = name_addr_str.find('<')?;
            let angle_end = name_addr_str.find('>')?;
            let uri_str = &name_addr_str[angle_start + 1..angle_end];

            let display_part = name_addr_str[..angle_start].trim();
            let display_name = if display_part.is_empty() {
                None
            } else {
                // Remove quotes if present
                let display_part = if display_part.starts_with('"') && display_part.ends_with('"') {
                    &display_part[1..display_part.len() - 1]
                } else {
                    display_part
                };
                Some(SmolStr::new(display_part))
            };

            (display_name, uri_str)
        } else {
            // Just a URI without angle brackets
            (None, name_addr_str)
        };

        let uri = Uri::parse(uri_str)?;

        let name_addr = NameAddr::new(display_name, uri, BTreeMap::new()).ok()?;

        let mut cid = None;
        let mut params = BTreeMap::new();

        // Parse parameters
        if !params_str.is_empty() {
            for part in params_str.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }

                if let Some((key, value)) = part.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();

                    // Remove quotes from value if present
                    let value = if value.starts_with('"') && value.ends_with('"') {
                        &value[1..value.len() - 1]
                    } else {
                        value
                    };

                    if key.eq_ignore_ascii_case("cid") {
                        cid = Some(SmolStr::new(value));
                    } else {
                        params.insert(SmolStr::new(key), SmolStr::new(value));
                    }
                }
            }
        }

        Some(Self {
            name_addr,
            cid,
            params,
        })
    }
}

impl fmt::Display for ReferredByHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write the name-addr
        if let Some(display_name) = self.name_addr.display_name() {
            write!(f, "\"{}\" ", display_name)?;
        }
        write!(f, "<{}>", self.name_addr.uri().as_str())?;

        // Write cid parameter if present
        if let Some(ref cid) = self.cid {
            write!(f, ";cid=\"{}\"", cid)?;
        }

        // Write other parameters
        for (name, value) in &self.params {
            write!(f, ";{}={}", name, value)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_referred_by() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com");
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(referred_by.name_addr.uri(), &Uri::Sip(expected_uri));
        assert!(referred_by.name_addr.display_name().is_none());
        assert!(!referred_by.has_signature());
        assert_eq!(referred_by.cid, None);
    }

    #[test]
    fn referred_by_with_display_name() {
        let referred_by = ReferredByHeader::with_name("Alice", "sip:alice@example.com");
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(
            referred_by.name_addr.display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.name_addr.uri(), &Uri::Sip(expected_uri));
    }

    #[test]
    fn referred_by_with_cid() {
        let referred_by =
            ReferredByHeader::new("sip:alice@example.com").with_cid("signature123@example.com");

        assert!(referred_by.has_signature());
        assert_eq!(referred_by.get_cid(), Some("signature123@example.com"));
        assert_eq!(referred_by.cid, Some(SmolStr::new("signature123@example.com")));
    }

    #[test]
    fn referred_by_with_params() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com")
            .with_param("tag", "abc123")
            .with_param("custom", "value");

        assert_eq!(referred_by.get_param("tag"), Some("abc123"));
        assert_eq!(referred_by.get_param("custom"), Some("value"));
        assert_eq!(referred_by.get_param("missing"), None);
    }

    #[test]
    fn format_basic_referred_by() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com");
        let formatted = referred_by.to_string();

        assert_eq!(formatted, "<sip:alice@example.com>");
    }

    #[test]
    fn format_referred_by_with_name() {
        let referred_by = ReferredByHeader::with_name("Alice", "sip:alice@example.com");
        let formatted = referred_by.to_string();

        assert_eq!(formatted, "\"Alice\" <sip:alice@example.com>");
    }

    #[test]
    fn format_referred_by_with_cid() {
        let referred_by =
            ReferredByHeader::new("sip:alice@example.com").with_cid("sig123@example.com");
        let formatted = referred_by.to_string();

        assert_eq!(
            formatted,
            "<sip:alice@example.com>;cid=\"sig123@example.com\""
        );
    }

    #[test]
    fn format_referred_by_with_all() {
        let referred_by = ReferredByHeader::with_name("Alice", "sip:alice@example.com")
            .with_cid("sig123@example.com")
            .with_param("tag", "abc");

        let formatted = referred_by.to_string();

        assert_eq!(
            formatted,
            "\"Alice\" <sip:alice@example.com>;cid=\"sig123@example.com\";tag=abc"
        );
    }

    #[test]
    fn parse_basic_referred_by() {
        let input = "<sip:alice@example.com>";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(referred_by.name_addr.uri(), &Uri::Sip(expected_uri));
        assert!(referred_by.name_addr.display_name().is_none());
        assert!(!referred_by.has_signature());
    }

    #[test]
    fn parse_referred_by_with_name() {
        let input = "\"Alice\" <sip:alice@example.com>";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(
            referred_by.name_addr.display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.name_addr.uri(), &Uri::Sip(expected_uri));
    }

    #[test]
    fn parse_referred_by_with_cid() {
        let input = "<sip:alice@example.com>;cid=\"sig123@example.com\"";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(referred_by.name_addr.uri(), &Uri::Sip(expected_uri));
        assert_eq!(referred_by.get_cid(), Some("sig123@example.com"));
    }

    #[test]
    fn parse_referred_by_with_all() {
        let input = "\"Alice\" <sip:alice@example.com>;cid=\"sig123@example.com\";tag=abc";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(
            referred_by.name_addr.display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.name_addr.uri(), &Uri::Sip(expected_uri));
        assert_eq!(referred_by.get_cid(), Some("sig123@example.com"));
        assert_eq!(referred_by.get_param("tag"), Some("abc"));
    }

    #[test]
    fn parse_referred_by_cid_case_insensitive() {
        let input = "<sip:alice@example.com>;CID=\"sig123@example.com\"";
        let referred_by = ReferredByHeader::parse(input).unwrap();

        assert_eq!(referred_by.get_cid(), Some("sig123@example.com"));
    }

    #[test]
    fn parse_referred_by_with_whitespace() {
        let input = "  \"Alice\"  <sip:alice@example.com>  ;  cid=\"sig123@example.com\"  ";
        let referred_by = ReferredByHeader::parse(input).unwrap();

        assert_eq!(
            referred_by.name_addr.display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.get_cid(), Some("sig123@example.com"));
    }

    #[test]
    fn parse_empty_string() {
        assert!(ReferredByHeader::parse("").is_none());
    }

    #[test]
    fn round_trip_referred_by() {
        let original = ReferredByHeader::with_name("Alice", "sip:alice@example.com")
            .with_cid("sig123@example.com")
            .with_param("tag", "abc");

        let formatted = original.to_string();
        let parsed = ReferredByHeader::parse(&formatted).unwrap();

        assert_eq!(
            parsed.name_addr.display_name().map(|s| s.as_str()),
            original.name_addr.display_name().map(|s| s.as_str())
        );
        assert_eq!(parsed.name_addr.uri(), original.name_addr.uri());
        assert_eq!(parsed.cid, original.cid);
        assert_eq!(parsed.get_param("tag"), original.get_param("tag"));
    }

    #[test]
    fn round_trip_without_cid() {
        let original = ReferredByHeader::new("sip:alice@example.com");

        let formatted = original.to_string();
        let parsed = ReferredByHeader::parse(&formatted).unwrap();

        assert_eq!(parsed.name_addr.uri(), original.name_addr.uri());
        assert_eq!(parsed.cid, None);
    }
}
