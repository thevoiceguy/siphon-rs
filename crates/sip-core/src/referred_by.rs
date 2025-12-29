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

const MAX_CID_LENGTH: usize = 256;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;
const MAX_PARSE_INPUT: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferredByError {
    CidTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    InvalidCid(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    InvalidUri(String),
    DuplicateParam(String),
    ParseError(String),
    InputTooLarge { max: usize, actual: usize },
}

impl std::fmt::Display for ReferredByError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CidTooLong { max, actual } =>
                write!(f, "CID too long (max {}, got {})", max, actual),
            Self::TooManyParams { max, actual } =>
                write!(f, "too many params (max {}, got {})", max, actual),
            Self::InvalidCid(msg) =>
                write!(f, "invalid CID: {}", msg),
            Self::InvalidUri(msg) =>
                write!(f, "invalid URI: {}", msg),
            Self::DuplicateParam(name) =>
                write!(f, "duplicate parameter: {}", name),
            Self::ParseError(msg) =>
                write!(f, "parse error: {}", msg),
            Self::InputTooLarge { max, actual } =>
                write!(f, "input too large (max {}, got {})", max, actual),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for ReferredByError {}

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
///
/// # Security
///
/// ReferredByHeader validates all fields to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferredByHeader {
    name_addr: NameAddr,
    cid: Option<SmolStr>,
    params: BTreeMap<SmolStr, SmolStr>,
}

impl ReferredByHeader {
    /// Creates a new Referred-By header with the given URI.
    ///
    /// # Arguments
    ///
    /// * `uri` - The referrer's SIP URI
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::new("sip:alice@example.com").unwrap();
    /// ```
    pub fn new(uri: impl AsRef<str>) -> Result<Self, ReferredByError> {
        let parsed_uri = SipUri::parse(uri.as_ref())
            .ok_or_else(|| ReferredByError::InvalidUri("failed to parse SIP URI".to_string()))?;
        
        let name_addr = NameAddr::new(None, Uri::from(parsed_uri), BTreeMap::new())
            .map_err(|e| ReferredByError::InvalidUri(e.to_string()))?;
        
        Ok(Self {
            name_addr,
            cid: None,
            params: BTreeMap::new(),
        })
    }

    /// Creates a new Referred-By header with a display name and URI.
    ///
    /// # Arguments
    ///
    /// * `display_name` - The referrer's display name
    /// * `uri` - The referrer's SIP URI
    ///
    /// # Errors
    ///
    /// Returns an error if the URI or display name is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::with_name(
    ///     "Alice",
    ///     "sip:alice@example.com"
    /// ).unwrap();
    /// ```
    pub fn with_name(
        display_name: impl AsRef<str>,
        uri: impl AsRef<str>,
    ) -> Result<Self, ReferredByError> {
        let parsed_uri = SipUri::parse(uri.as_ref())
            .ok_or_else(|| ReferredByError::InvalidUri("failed to parse SIP URI".to_string()))?;
        
        let name_addr = NameAddr::new(
            Some(SmolStr::new(display_name.as_ref())),
            Uri::from(parsed_uri),
            BTreeMap::new(),
        )
        .map_err(|e| ReferredByError::InvalidUri(e.to_string()))?;
        
        Ok(Self {
            name_addr,
            cid: None,
            params: BTreeMap::new(),
        })
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
    /// # Errors
    ///
    /// Returns an error if the CID is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::new("sip:alice@example.com")
    ///     .unwrap()
    ///     .with_cid("signature123@example.com")
    ///     .unwrap();
    /// ```
    pub fn with_cid(mut self, cid: impl AsRef<str>) -> Result<Self, ReferredByError> {
        validate_cid(cid.as_ref())?;
        self.cid = Some(SmolStr::new(cid.as_ref()));
        Ok(self)
    }

    /// Adds a parameter to the header.
    ///
    /// # Arguments
    ///
    /// * `name` - The parameter name
    /// * `value` - The parameter value
    ///
    /// # Errors
    ///
    /// Returns an error if the parameter is invalid or would exceed limits.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReferredByHeader;
    ///
    /// let referred_by = ReferredByHeader::new("sip:alice@example.com")
    ///     .unwrap()
    ///     .with_param("tag", "abc123")
    ///     .unwrap();
    /// ```
    pub fn with_param(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, ReferredByError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), ReferredByError> {
        let name = name.as_ref();
        let value = value.as_ref();

        validate_param_name(name)?;
        validate_param_value(value)?;

        if self.params.len() >= MAX_PARAMS {
            return Err(ReferredByError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(&name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(ReferredByError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, SmolStr::new(value));
        Ok(())
    }

    /// Returns the name-addr.
    pub fn name_addr(&self) -> &NameAddr {
        &self.name_addr
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
        self.params
            .get(&SmolStr::new(&name.to_ascii_lowercase()))
            .map(|s| s.as_str())
    }

    /// Returns an iterator over parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
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
    /// # Errors
    ///
    /// Returns an error if the header is malformed or invalid.
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
    /// assert_eq!(header.name_addr().display_name().map(|s| s.as_str()), Some("Alice"));
    /// assert_eq!(header.get_cid(), Some("sig123@example.com"));
    /// ```
    pub fn parse(input: &str) -> Result<Self, ReferredByError> {
        if input.len() > MAX_PARSE_INPUT {
            return Err(ReferredByError::InputTooLarge {
                max: MAX_PARSE_INPUT,
                actual: input.len(),
            });
        }

        let input = input.trim();

        // Find the end of the name-addr part (before parameters)
        let (name_addr_str, params_str) = if let Some((_, angle_end)) =
            find_unquoted_angle_brackets(input)?
        {
            let na = &input[..=angle_end];
            let rest = input[angle_end + 1..].trim();
            (na, rest)
        } else if let Some(semi_pos) = input.find(';') {
            (&input[..semi_pos], input[semi_pos..].trim())
        } else {
            (input, "")
        };

        // Parse the name-addr
        let (display_name, uri_str) = if let Some((angle_start, angle_end)) =
            find_unquoted_angle_brackets(name_addr_str)?
        {
            let uri_str = &name_addr_str[angle_start + 1..angle_end];

            let display_part = name_addr_str[..angle_start].trim();
            let display_name = if display_part.is_empty() {
                None
            } else {
                let display_part = if display_part.starts_with('"') && display_part.ends_with('"') {
                    &display_part[1..display_part.len() - 1]
                } else {
                    display_part
                };
                Some(SmolStr::new(display_part))
            };

            (display_name, uri_str)
        } else {
            (None, name_addr_str)
        };

        let uri = Uri::parse(uri_str)
            .ok_or_else(|| ReferredByError::InvalidUri("failed to parse URI".to_string()))?;

        let name_addr = NameAddr::new(display_name, uri, BTreeMap::new())
            .map_err(|e| ReferredByError::InvalidUri(e.to_string()))?;

        let mut cid = None;
        let mut params = BTreeMap::new();

        // Parse parameters
        if !params_str.is_empty() {
            for part in params_str.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }

                if params.len() >= MAX_PARAMS {
                    return Err(ReferredByError::TooManyParams {
                        max: MAX_PARAMS,
                        actual: params.len() + 1,
                    });
                }

                if let Some((key, value)) = part.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();

                    let value = if value.starts_with('"') && value.ends_with('"') {
                        &value[1..value.len() - 1]
                    } else {
                        value
                    };

                    if key.eq_ignore_ascii_case("cid") {
                        validate_cid(value)?;
                        if cid.is_some() {
                            return Err(ReferredByError::DuplicateParam("cid".to_string()));
                        }
                        cid = Some(SmolStr::new(value));
                    } else {
                        validate_param_name(key)?;
                        validate_param_value(value)?;

                        let key_lower = SmolStr::new(&key.to_ascii_lowercase());
                        if params.contains_key(&key_lower) {
                            return Err(ReferredByError::DuplicateParam(key.to_string()));
                        }
                        params.insert(key_lower, SmolStr::new(value));
                    }
                } else {
                    return Err(ReferredByError::ParseError(
                        "parameter missing '='".to_string(),
                    ));
                }
            }
        }

        Ok(Self {
            name_addr,
            cid,
            params,
        })
    }
}

impl fmt::Display for ReferredByHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(display_name) = self.name_addr.display_name() {
            write!(f, "\"{}\" ", display_name)?;
        }
        write!(f, "<{}>", self.name_addr.uri().as_str())?;

        if let Some(ref cid) = self.cid {
            write!(f, ";cid=\"{}\"", cid)?;
        }

        for (name, value) in &self.params {
            write!(f, ";{}={}", name, value)?;
        }

        Ok(())
    }
}

// Validation functions

fn validate_cid(cid: &str) -> Result<(), ReferredByError> {
    if cid.is_empty() {
        return Err(ReferredByError::InvalidCid("empty CID".to_string()));
    }
    if cid.len() > MAX_CID_LENGTH {
        return Err(ReferredByError::CidTooLong {
            max: MAX_CID_LENGTH,
            actual: cid.len(),
        });
    }

    if cid.chars().any(|c| c.is_ascii_control()) {
        return Err(ReferredByError::InvalidCid(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn find_unquoted_angle_brackets(input: &str) -> Result<Option<(usize, usize)>, ReferredByError> {
    let mut in_quotes = false;
    let mut start = None;
    for (idx, ch) in input.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => {
                if start.is_some() {
                    return Err(ReferredByError::ParseError(
                        "nested angle brackets".to_string(),
                    ));
                }
                start = Some(idx);
            }
            '>' if !in_quotes => {
                if let Some(s) = start {
                    return Ok(Some((s, idx)));
                }
                return Err(ReferredByError::ParseError(
                    "closing bracket without opening bracket".to_string(),
                ));
            }
            _ => {}
        }
    }
    if start.is_some() {
        return Err(ReferredByError::ParseError(
            "missing closing bracket".to_string(),
        ));
    }
    Ok(None)
}

fn validate_param_name(name: &str) -> Result<(), ReferredByError> {
    if name.is_empty() {
        return Err(ReferredByError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(ReferredByError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(ReferredByError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), ReferredByError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(ReferredByError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(ReferredByError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_referred_by() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com").unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(referred_by.name_addr().uri(), &Uri::Sip(expected_uri));
        assert!(referred_by.name_addr().display_name().is_none());
        assert!(!referred_by.has_signature());
        assert_eq!(referred_by.cid, None);
    }

    #[test]
    fn referred_by_with_display_name() {
        let referred_by = ReferredByHeader::with_name("Alice", "sip:alice@example.com").unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(
            referred_by.name_addr().display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.name_addr().uri(), &Uri::Sip(expected_uri));
    }

    #[test]
    fn referred_by_with_cid() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_cid("signature123@example.com")
            .unwrap();

        assert!(referred_by.has_signature());
        assert_eq!(referred_by.get_cid(), Some("signature123@example.com"));
        assert_eq!(
            referred_by.cid,
            Some(SmolStr::new("signature123@example.com"))
        );
    }

    #[test]
    fn referred_by_with_params() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_param("tag", "abc123")
            .unwrap()
            .with_param("custom", "value")
            .unwrap();

        assert_eq!(referred_by.get_param("tag"), Some("abc123"));
        assert_eq!(referred_by.get_param("custom"), Some("value"));
        assert_eq!(referred_by.get_param("missing"), None);
    }

    #[test]
    fn format_basic_referred_by() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com").unwrap();
        let formatted = referred_by.to_string();

        assert_eq!(formatted, "<sip:alice@example.com>");
    }

    #[test]
    fn format_referred_by_with_name() {
        let referred_by = ReferredByHeader::with_name("Alice", "sip:alice@example.com").unwrap();
        let formatted = referred_by.to_string();

        assert_eq!(formatted, "\"Alice\" <sip:alice@example.com>");
    }

    #[test]
    fn format_referred_by_with_cid() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_cid("sig123@example.com")
            .unwrap();
        let formatted = referred_by.to_string();

        assert_eq!(
            formatted,
            "<sip:alice@example.com>;cid=\"sig123@example.com\""
        );
    }

    #[test]
    fn format_referred_by_with_all() {
        let referred_by = ReferredByHeader::with_name("Alice", "sip:alice@example.com")
            .unwrap()
            .with_cid("sig123@example.com")
            .unwrap()
            .with_param("tag", "abc")
            .unwrap();

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

        assert_eq!(referred_by.name_addr().uri(), &Uri::Sip(expected_uri));
        assert!(referred_by.name_addr().display_name().is_none());
        assert!(!referred_by.has_signature());
    }

    #[test]
    fn parse_referred_by_with_name() {
        let input = "\"Alice\" <sip:alice@example.com>";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(
            referred_by.name_addr().display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.name_addr().uri(), &Uri::Sip(expected_uri));
    }

    #[test]
    fn parse_referred_by_with_cid() {
        let input = "<sip:alice@example.com>;cid=\"sig123@example.com\"";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(referred_by.name_addr().uri(), &Uri::Sip(expected_uri));
        assert_eq!(referred_by.get_cid(), Some("sig123@example.com"));
    }

    #[test]
    fn parse_referred_by_with_angle_in_display() {
        let input = "\"Bob <Ops>\" <sip:bob@example.com>";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        assert_eq!(
            referred_by.name_addr().display_name().map(|s| s.as_str()),
            Some("Bob <Ops>")
        );
        assert_eq!(
            referred_by.name_addr().uri().as_str(),
            "sip:bob@example.com"
        );
    }

    #[test]
    fn parse_referred_by_with_all() {
        let input = "\"Alice\" <sip:alice@example.com>;cid=\"sig123@example.com\";tag=abc";
        let referred_by = ReferredByHeader::parse(input).unwrap();
        let expected_uri = SipUri::parse("sip:alice@example.com").unwrap();

        assert_eq!(
            referred_by.name_addr().display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.name_addr().uri(), &Uri::Sip(expected_uri));
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
            referred_by.name_addr().display_name().map(|s| s.as_str()),
            Some("Alice")
        );
        assert_eq!(referred_by.get_cid(), Some("sig123@example.com"));
    }

    #[test]
    fn parse_empty_string() {
        assert!(ReferredByHeader::parse("").is_err());
    }

    #[test]
    fn round_trip_referred_by() {
        let original = ReferredByHeader::with_name("Alice", "sip:alice@example.com")
            .unwrap()
            .with_cid("sig123@example.com")
            .unwrap()
            .with_param("tag", "abc")
            .unwrap();

        let formatted = original.to_string();
        let parsed = ReferredByHeader::parse(&formatted).unwrap();

        assert_eq!(
            parsed.name_addr().display_name().map(|s| s.as_str()),
            original.name_addr().display_name().map(|s| s.as_str())
        );
        assert_eq!(parsed.name_addr().uri(), original.name_addr().uri());
        assert_eq!(parsed.cid, original.cid);
        assert_eq!(parsed.get_param("tag"), original.get_param("tag"));
    }

    #[test]
    fn round_trip_without_cid() {
        let original = ReferredByHeader::new("sip:alice@example.com").unwrap();

        let formatted = original.to_string();
        let parsed = ReferredByHeader::parse(&formatted).unwrap();

        assert_eq!(parsed.name_addr().uri(), original.name_addr().uri());
        assert_eq!(parsed.cid, None);
    }

    // Security tests

    #[test]
    fn reject_crlf_in_cid() {
        let result = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_cid("sig123\r\ninjected@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_cid() {
        let long_cid = "x".repeat(MAX_CID_LENGTH + 1);
        let result = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_cid(&long_cid);
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_param_value() {
        let result = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_param("tag", "abc\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_params() {
        let mut referred_by = ReferredByHeader::new("sip:alice@example.com").unwrap();
        
        for i in 0..MAX_PARAMS {
            referred_by.add_param(&format!("p{}", i), "value").unwrap();
        }
        
        let result = referred_by.add_param("overflow", "value");
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_params() {
        let result = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_param("tag", "abc")
            .unwrap()
            .with_param("tag", "def");
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_cid_in_parse() {
        let input = "<sip:alice@example.com>;cid=\"one\";cid=\"two\"";
        let result = ReferredByHeader::parse(input);
        assert!(result.is_err());
    }

    #[test]
    fn reject_param_without_value_in_parse() {
        let input = "<sip:alice@example.com>;tag";
        let result = ReferredByHeader::parse(input);
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_cid() {
        let result = ReferredByHeader::new("sip:alice@example.com")
            .unwrap()
            .with_cid("");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_parse_input() {
        let huge = format!("<sip:alice@example.com>{}", ";p=v".repeat(1000));
        let result = ReferredByHeader::parse(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_uri() {
        let result = ReferredByHeader::new("not-a-uri");
        assert!(result.is_err());
    }

    #[test]
    fn fields_are_private() {
        let referred_by = ReferredByHeader::new("sip:alice@example.com").unwrap();
        
        // These should compile
        let _ = referred_by.name_addr();
        let _ = referred_by.get_cid();
        let _ = referred_by.params();
        
        // These should NOT compile:
        // referred_by.name_addr = ...;  // ← Does not compile!
        // referred_by.cid = None;       // ← Does not compile!
        // referred_by.params.clear();   // ← Does not compile!
    }
}
