// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Route and Record-Route header support (RFC 3261).
//!
//! The Route header is used to force routing through specific proxies,
//! while Record-Route is used by proxies to record themselves in the
//! signaling path for future requests within a dialog.
//!
//! # Format
//!
//! ```text
//! Route: <sip:proxy1.example.com;lr>
//! Route: <sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>
//! Record-Route: <sip:proxy.example.com;lr>
//! ```
//!
//! # The 'lr' Parameter
//!
//! The 'lr' (loose routing) parameter is critical for proper routing.
//! Without it, proxies perform strict routing which can cause routing loops
//! and other issues. Modern SIP implementations should always use 'lr'.
//!
//! # Usage
//!
//! ## Route Header (UAC)
//!
//! A UAC uses Route headers to send requests through specific proxies:
//!
//! ```text
//! INVITE sip:bob@example.com SIP/2.0
//! Route: <sip:proxy1.example.com;lr>
//! Route: <sip:proxy2.example.com;lr>
//! ```
//!
//! ## Record-Route Header (Proxy)
//!
//! A proxy adds itself to Record-Route when forwarding requests:
//!
//! ```text
//! INVITE sip:bob@example.com SIP/2.0
//! Record-Route: <sip:proxy.example.com;lr>
//! ```
//!
//! The UAC copies Record-Route headers to Route headers for subsequent
//! requests in the dialog, ensuring they traverse the same proxies.

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

use crate::{name_addr::NameAddr, Uri};

const MAX_PARSE_INPUT: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    InvalidNameAddr(String),
    InputTooLarge { max: usize, actual: usize },
    ParseError(String),
    EmptyInput,
    MissingUri,
    UnbalancedQuotes,
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNameAddr(msg) => write!(f, "invalid name-addr: {}", msg),
            Self::InputTooLarge { max, actual } => {
                write!(f, "input too large (max {}, got {})", max, actual)
            }
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
            Self::EmptyInput => write!(f, "empty input"),
            Self::MissingUri => write!(f, "missing URI"),
            Self::UnbalancedQuotes => write!(f, "unbalanced quotes in display name"),
        }
    }
}

impl std::error::Error for RouteError {}

/// Parsed Route/Record-Route header value (RFC 3261).
///
/// Route and Record-Route headers contain name-addr values with URI parameters.
/// The most important parameter is 'lr' (loose routing) which should be present
/// on all modern SIP implementations.
///
/// # Security
///
/// RouteHeader delegates validation to NameAddr which enforces:
/// - Display name length limit: 256 characters
/// - Parameter count limit: 64 parameters
/// - Parameter name limit: 64 characters
/// - Parameter value limit: 256 characters
/// - Control character rejection in all fields
///
/// Additionally, RouteHeader enforces:
/// - Input size limit: 2048 bytes (DoS prevention)
/// - Private field prevents bypassing validation
/// - All parsing returns Result for proper error handling
///
/// These validations prevent:
/// - CRLF injection in display names
/// - DoS via unbounded parameters
/// - Malformed URI attacks
/// - Control character injection
///
/// # Examples
///
/// ```
/// use sip_core::{RouteHeader, NameAddr, Uri, SipUri};
/// use std::collections::BTreeMap;
///
/// // Create from NameAddr
/// let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
/// let name_addr = NameAddr::new(None, uri, BTreeMap::new()).unwrap();
/// let route = RouteHeader::new(name_addr);
///
/// // Parse from string
/// let route = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();
///
/// // Create with loose routing
/// let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
/// let route = RouteHeader::with_lr(uri).unwrap();
/// assert!(route.has_lr());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeader(NameAddr);

impl RouteHeader {
    /// Creates a new Route header from a NameAddr.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{RouteHeader, NameAddr, Uri, SipUri};
    /// use std::collections::BTreeMap;
    ///
    /// let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
    /// let name_addr = NameAddr::new(None, uri, BTreeMap::new()).unwrap();
    /// let route = RouteHeader::new(name_addr);
    /// ```
    pub fn new(inner: NameAddr) -> Self {
        Self(inner)
    }

    /// Returns the URI.
    pub fn uri(&self) -> &Uri {
        self.0.uri()
    }

    /// Returns an iterator over URI parameters.
    pub fn params(&self) -> impl Iterator<Item = (&SmolStr, &Option<SmolStr>)> {
        self.0.params()
    }

    /// Returns a reference to the inner NameAddr.
    pub fn inner(&self) -> &NameAddr {
        &self.0
    }

    /// Consumes the RouteHeader and returns the inner NameAddr.
    pub fn into_inner(self) -> NameAddr {
        self.0
    }

    /// Returns true if the 'lr' (loose routing) parameter is present.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RouteHeader;
    ///
    /// let route = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();
    /// assert!(route.has_lr());
    ///
    /// let route = RouteHeader::parse("<sip:proxy.example.com>").unwrap();
    /// assert!(!route.has_lr());
    /// ```
    pub fn has_lr(&self) -> bool {
        if self
            .0
            .params()
            .any(|(name, _)| name.eq_ignore_ascii_case("lr"))
        {
            return true;
        }
        self.0
            .uri()
            .as_sip()
            .map(|sip| sip.params().contains_key("lr"))
            .unwrap_or(false)
    }

    /// Creates a RouteHeader with the 'lr' (loose routing) parameter.
    ///
    /// This is a convenience method for creating loose routing headers, which is
    /// the recommended mode for modern SIP implementations.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{RouteHeader, Uri, SipUri};
    ///
    /// let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
    /// let route = RouteHeader::with_lr(uri).unwrap();
    /// assert!(route.has_lr());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the NameAddr creation fails (e.g., invalid URI).
    pub fn with_lr(uri: Uri) -> Result<Self, RouteError> {
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("lr"), None);
        let name_addr = NameAddr::new(None, uri, params)
            .map_err(|e| RouteError::InvalidNameAddr(e.to_string()))?;
        Ok(Self::new(name_addr))
    }

    /// Returns the number of parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RouteHeader;
    ///
    /// let route = RouteHeader::parse("<sip:proxy.example.com>;lr;transport=tcp").unwrap();
    /// assert_eq!(route.param_count(), 2); // lr + transport
    /// ```
    pub fn param_count(&self) -> usize {
        self.0.params().count()
    }

    /// Gets a specific parameter value by name (case-insensitive).
    ///
    /// Returns None if the parameter is not present. Returns Some(None) if the
    /// parameter is present without a value (like 'lr').
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RouteHeader;
    ///
    /// let route = RouteHeader::parse("<sip:proxy.example.com>;lr;transport=tcp").unwrap();
    ///
    /// // Parameter without value
    /// assert_eq!(route.get_param("lr"), Some(&None));
    ///
    /// // Parameter with value
    /// assert_eq!(route.get_param("transport").and_then(|v| v.as_ref()).map(|s| s.as_str()), Some("tcp"));
    ///
    /// // Non-existent parameter
    /// assert_eq!(route.get_param("foo"), None);
    /// ```
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.0
            .params()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Parses a Route/Record-Route header value.
    ///
    /// # Format
    ///
    /// ```text
    /// <sip:uri> [;param[=value]]*
    /// "Display Name" <sip:uri> [;param[=value]]*
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RouteHeader;
    ///
    /// let route = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();
    /// assert!(route.has_lr());
    ///
    /// let route = RouteHeader::parse(
    ///     "\"My Proxy\" <sip:proxy.example.com;lr;transport=tcp>"
    /// ).unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self, RouteError> {
        if input.len() > MAX_PARSE_INPUT {
            return Err(RouteError::InputTooLarge {
                max: MAX_PARSE_INPUT,
                actual: input.len(),
            });
        }

        let name_addr = parse_name_addr(input.trim())?;

        Ok(Self(name_addr))
    }
}

impl fmt::Display for RouteHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(display_name) = self.0.display_name() {
            write!(f, "\"{}\" ", display_name)?;
        }
        write!(f, "<{}>", self.0.uri().as_str())?;
        for (key, value) in self.0.params() {
            if let Some(v) = value {
                write!(f, ";{}={}", key, v)?;
            } else {
                write!(f, ";{}", key)?;
            }
        }
        Ok(())
    }
}

impl From<NameAddr> for RouteHeader {
    fn from(name_addr: NameAddr) -> Self {
        Self::new(name_addr)
    }
}

fn parse_name_addr(input: &str) -> Result<NameAddr, RouteError> {
    if input.is_empty() {
        return Err(RouteError::EmptyInput);
    }
    match find_unquoted_angle_brackets(input)? {
        Some((start, end)) => {
            let display = input[..start].trim();
            let uri = input[start + 1..end].trim();
            let params = parse_params(input[end + 1..].trim());
            let uri =
                Uri::parse(uri).map_err(|_| RouteError::ParseError("invalid uri".to_string()))?;
            NameAddr::new(
                if display.is_empty() {
                    None
                } else {
                    Some(SmolStr::new(display.trim_matches('"')))
                },
                uri,
                params,
            )
            .map_err(|err| RouteError::InvalidNameAddr(err.to_string()))
        }
        None => {
            let (uri_part, param_part) = input.split_once(';').unwrap_or((input, ""));
            let uri = Uri::parse(uri_part.trim()).map_err(|_| RouteError::MissingUri)?;
            NameAddr::new(None, uri, parse_params(param_part))
                .map_err(|err| RouteError::InvalidNameAddr(err.to_string()))
        }
    }
}

fn parse_params(input: &str) -> BTreeMap<SmolStr, Option<SmolStr>> {
    let mut params = BTreeMap::new();
    for raw in input.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Some((name, value)) = raw.split_once('=') {
            params.insert(
                SmolStr::new(name.trim().to_ascii_lowercase()),
                Some(SmolStr::new(value.trim().trim_matches('"'))),
            );
        } else {
            params.insert(SmolStr::new(raw.to_ascii_lowercase()), None);
        }
    }
    params
}

fn find_unquoted_angle_brackets(input: &str) -> Result<Option<(usize, usize)>, RouteError> {
    let mut in_quotes = false;
    let mut escape_next = false;
    let mut start: Option<usize> = None;
    for (idx, ch) in input.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        if ch == '<' {
            start = Some(idx);
            break;
        }
    }
    let start = match start {
        Some(value) => value,
        None => return Ok(None),
    };
    in_quotes = false;
    escape_next = false;
    for (idx, ch) in input[start + 1..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        if ch == '>' {
            return Ok(Some((start, start + 1 + idx)));
        }
    }
    Err(RouteError::ParseError(
        "unbalanced angle brackets".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SipUri;
    use std::collections::BTreeMap;

    #[test]
    fn create_route_header() {
        let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
        let name_addr = NameAddr::new(None, uri, BTreeMap::new()).unwrap();
        let route = RouteHeader::new(name_addr);

        assert_eq!(route.uri().as_str(), "sip:proxy.example.com");
    }

    #[test]
    fn route_inner() {
        let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
        let name_addr = NameAddr::new(None, uri, BTreeMap::new()).unwrap();
        let route = RouteHeader::new(name_addr.clone());

        assert_eq!(route.inner(), &name_addr);
    }

    #[test]
    fn route_into_inner() {
        let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
        let name_addr = NameAddr::new(None, uri, BTreeMap::new()).unwrap();
        let route = RouteHeader::new(name_addr.clone());

        assert_eq!(route.into_inner(), name_addr);
    }

    #[test]
    fn parse_basic_route() {
        let route = RouteHeader::parse("<sip:proxy.example.com>").unwrap();
        assert_eq!(route.uri().as_str(), "sip:proxy.example.com");
    }

    #[test]
    fn parse_route_with_lr() {
        let route = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();
        assert_eq!(route.uri().as_str(), "sip:proxy.example.com;lr");
        assert!(route.has_lr());
    }

    #[test]
    fn parse_route_without_lr() {
        let route = RouteHeader::parse("<sip:proxy.example.com>").unwrap();
        assert!(!route.has_lr());
    }

    #[test]
    fn parse_route_with_display_name() {
        let route = RouteHeader::parse("\"My Proxy\" <sip:proxy.example.com;lr>").unwrap();
        assert_eq!(
            route.inner().display_name().map(|s| s.as_str()),
            Some("My Proxy")
        );
        assert!(route.has_lr());
    }

    #[test]
    fn parse_route_with_multiple_params() {
        let route = RouteHeader::parse("<sip:proxy.example.com;lr;transport=tcp>").unwrap();
        assert!(route.has_lr());

        let sip_params = route.uri().as_sip().unwrap().params();
        assert!(sip_params.contains_key(&SmolStr::new("lr")));
        let transport: Option<&SmolStr> = sip_params
            .get(&SmolStr::new("transport"))
            .and_then(|v| v.as_ref());
        assert_eq!(transport.map(|s| s.as_str()), Some("tcp"));
    }

    #[test]
    fn format_route_basic() {
        let route = RouteHeader::parse("<sip:proxy.example.com>").unwrap();
        let formatted = route.to_string();
        assert!(formatted.contains("sip:proxy.example.com"));
    }

    #[test]
    fn format_route_with_lr() {
        let route = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();
        let formatted = route.to_string();
        assert!(formatted.contains("sip:proxy.example.com"));
        assert!(formatted.contains("lr"));
    }

    #[test]
    fn round_trip_basic() {
        let original = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();
        let formatted = original.to_string();
        let parsed = RouteHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_with_display_name() {
        let original = RouteHeader::parse("\"Proxy\" <sip:proxy.example.com;lr>").unwrap();
        let formatted = original.to_string();
        let parsed = RouteHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn from_name_addr() {
        let uri = Uri::Sip(SipUri::parse("sip:proxy.example.com").unwrap());
        let name_addr = NameAddr::new(None, uri, BTreeMap::new()).unwrap();
        let route: RouteHeader = name_addr.clone().into();
        assert_eq!(route.inner(), &name_addr);
    }

    // Security tests

    #[test]
    fn reject_oversized_input() {
        let huge = format!("<sip:proxy.example.com>{}", ";param=value".repeat(500));
        let result = RouteHeader::parse(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn tuple_field_is_private() {
        let route = RouteHeader::parse("<sip:proxy.example.com;lr>").unwrap();

        // These should compile (read-only access)
        let _ = route.uri();
        let _ = route.params();
        let _ = route.inner();

        // This should NOT compile (no direct field access):
        // route.0 = ...;  // ← Does not compile!
    }

    #[test]
    fn parse_validates_via_name_addr() {
        // NameAddr validation will catch invalid URIs
        let result = RouteHeader::parse("<not-a-valid-uri>");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_display_name() {
        // CRLF injection attempt in display name
        let result = RouteHeader::parse("\"Proxy\r\nInjected\" <sip:proxy.com>");
        assert!(result.is_err()); // NameAddr should catch this
    }

    #[test]
    fn reject_oversized_display_name() {
        // Display name exceeds MAX_DISPLAY_NAME_LEN (256)
        let long_name = "x".repeat(300);
        let input = format!("\"{}\" <sip:proxy.com>", long_name);
        let result = RouteHeader::parse(&input);
        assert!(result.is_err()); // NameAddr should catch this
    }

    #[test]
    fn reject_too_many_params() {
        // Exceed MAX_PARAM_COUNT (64) from NameAddr
        // NameAddr params come AFTER the closing bracket
        let mut params = String::new();
        for i in 0..70 {
            params.push_str(&format!(";p{}=v{}", i, i));
        }
        let input = format!("<sip:proxy.com>{}", params);
        let result = RouteHeader::parse(&input);
        assert!(result.is_err()); // NameAddr should catch this
    }

    #[test]
    fn parse_empty_input() {
        let result = RouteHeader::parse("");
        assert!(result.is_err());
        if let Err(RouteError::EmptyInput) = result {
            // Expected error type
        } else {
            panic!("Expected EmptyInput error");
        }
    }

    #[test]
    fn parse_whitespace_only() {
        let result = RouteHeader::parse("   ");
        assert!(result.is_err());
        // Should fail during URI parsing since whitespace-only has no URI
    }
}
