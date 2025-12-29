// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Via header (RFC 3261 §20.42) with security hardening.
//!
//! The Via header field indicates the transport used for the transaction and
//! identifies the location where the response is to be sent. A Via header field
//! value is added only after the transport that will be used to reach the next
//! hop has been selected.
//!
//! # Security
//!
//! Via headers are validated for:
//! - Maximum length limits on all components
//! - Valid transport protocol names
//! - Valid sent-by format (host or host:port)
//! - Bounded parameter collections
//! - No control characters (prevents CRLF injection)
//!
//! # Format
//!
//! ```text
//! Via: SIP/2.0/UDP host:port;branch=z9hG4bK776asdhds
//! Via: SIP/2.0/TCP [2001:db8::1]:5060;branch=z9hG4bK776asdhds
//! ```

use std::collections::BTreeMap;
use std::fmt;
use smol_str::SmolStr;

// Security: Input size limits
const MAX_TRANSPORT_LENGTH: usize = 32;
const MAX_SENT_BY_LENGTH: usize = 256;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;

/// Error types for Via header operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViaError {
    /// Invalid transport protocol
    InvalidTransport(String),
    /// Invalid sent-by value
    InvalidSentBy(String),
    /// Invalid parameter
    InvalidParameter(String),
    /// Too many parameters
    TooManyParameters { max: usize },
    /// Input too long
    TooLong { field: &'static str, max: usize },
    /// Invalid format
    InvalidFormat(String),
}

impl fmt::Display for ViaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViaError::InvalidTransport(msg) => write!(f, "Invalid transport: {}", msg),
            ViaError::InvalidSentBy(msg) => write!(f, "Invalid sent-by: {}", msg),
            ViaError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            ViaError::TooManyParameters { max } => write!(f, "Too many parameters (max {})", max),
            ViaError::TooLong { field, max } => write!(f, "{} too long (max {})", field, max),
            ViaError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for ViaError {}

/// Validates a transport protocol name.
fn validate_transport(transport: &str) -> Result<(), ViaError> {
    if transport.is_empty() {
        return Err(ViaError::InvalidTransport(
            "transport cannot be empty".to_string(),
        ));
    }

    if transport.len() > MAX_TRANSPORT_LENGTH {
        return Err(ViaError::TooLong {
            field: "transport",
            max: MAX_TRANSPORT_LENGTH,
        });
    }

    // Check for control characters
    if transport.chars().any(|c| c.is_control()) {
        return Err(ViaError::InvalidTransport(
            "contains control characters".to_string(),
        ));
    }

    // RFC 3261: transport must be a token (alphanum and specific symbols)
    // Common: UDP, TCP, TLS, SCTP, WS, WSS
    if !transport.chars().all(is_token_char) {
        return Err(ViaError::InvalidTransport(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a sent-by value (host or host:port).
fn validate_sent_by(sent_by: &str) -> Result<(), ViaError> {
    if sent_by.is_empty() {
        return Err(ViaError::InvalidSentBy(
            "sent-by cannot be empty".to_string(),
        ));
    }

    if sent_by.len() > MAX_SENT_BY_LENGTH {
        return Err(ViaError::TooLong {
            field: "sent-by",
            max: MAX_SENT_BY_LENGTH,
        });
    }

    // Check for control characters
    if sent_by.chars().any(|c| c.is_control()) {
        return Err(ViaError::InvalidSentBy(
            "contains control characters".to_string(),
        ));
    }

    if sent_by.starts_with('[') {
        let end = sent_by.find(']').ok_or_else(|| {
            ViaError::InvalidSentBy("mismatched IPv6 brackets".to_string())
        })?;
        let host = &sent_by[1..end];
        if host.is_empty() {
            return Err(ViaError::InvalidSentBy(
                "sent-by host cannot be empty".to_string(),
            ));
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'))
        {
            return Err(ViaError::InvalidSentBy(
                "invalid IPv6 address".to_string(),
            ));
        }
        let remainder = &sent_by[end + 1..];
        if remainder.is_empty() {
            return Ok(());
        }
        let port_str = remainder
            .strip_prefix(':')
            .ok_or_else(|| ViaError::InvalidSentBy("invalid sent-by format".to_string()))?;
        validate_port(port_str)?;
        return Ok(());
    }

    if sent_by.contains('[') || sent_by.contains(']') {
        return Err(ViaError::InvalidSentBy(
            "mismatched IPv6 brackets".to_string(),
        ));
    }

    if sent_by.matches(':').count() > 1 {
        return Err(ViaError::InvalidSentBy(
            "IPv6 must be enclosed in brackets".to_string(),
        ));
    }

    let (host, port) = match sent_by.rfind(':') {
        Some(idx) => (&sent_by[..idx], Some(&sent_by[idx + 1..])),
        None => (sent_by, None),
    };

    if host.is_empty() {
        return Err(ViaError::InvalidSentBy(
            "sent-by host cannot be empty".to_string(),
        ));
    }

    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(ViaError::InvalidSentBy(
            "contains invalid characters".to_string(),
        ));
    }

    if let Some(port_str) = port {
        validate_port(port_str)?;
    }

    Ok(())
}

/// Validates a parameter name.
fn validate_param_name(name: &str) -> Result<(), ViaError> {
    if name.is_empty() {
        return Err(ViaError::InvalidParameter(
            "parameter name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(ViaError::TooLong {
            field: "parameter name",
            max: MAX_PARAM_NAME_LENGTH,
        });
    }

    if !name.chars().all(is_token_char) {
        return Err(ViaError::InvalidParameter(
            "parameter name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a parameter value.
fn validate_param_value(value: &str) -> Result<(), ViaError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(ViaError::TooLong {
            field: "parameter value",
            max: MAX_PARAM_VALUE_LENGTH,
        });
    }

    // Check for control characters
    if value.chars().any(|c| c.is_control()) {
        return Err(ViaError::InvalidParameter(
            "parameter value contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_port(port: &str) -> Result<(), ViaError> {
    if port.is_empty() {
        return Err(ViaError::InvalidSentBy(
            "port cannot be empty".to_string(),
        ));
    }
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(ViaError::InvalidSentBy(
            "port must be numeric".to_string(),
        ));
    }
    let port_num = port
        .parse::<u32>()
        .map_err(|_| ViaError::InvalidSentBy("invalid port".to_string()))?;
    if !(1..=65535).contains(&port_num) {
        return Err(ViaError::InvalidSentBy(
            "port out of range".to_string(),
        ));
    }
    Ok(())
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

/// Parsed representation of a Via header.
///
/// # Security
///
/// ViaHeader validates all components and enforces bounds to prevent DoS attacks.
///
/// # Examples
///
/// ```
/// use sip_core::ViaHeader;
///
/// // Create a Via header
/// let via = ViaHeader::new("UDP", "host.example.com:5060").unwrap();
/// assert_eq!(via.transport(), "UDP");
/// assert_eq!(via.sent_by(), "host.example.com:5060");
///
/// // Add parameters
/// let via = via.with_param("branch", Some("z9hG4bK776asdhds")).unwrap();
/// assert!(via.param("branch").is_some());
///
/// // Parse from string
/// let via = ViaHeader::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK776").unwrap();
/// assert_eq!(via.transport(), "UDP");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaHeader {
    /// Transport protocol (e.g., UDP, TCP, TLS)
    transport: SmolStr,
    /// Sent-by value (host or host:port)
    sent_by: SmolStr,
    /// Via parameters (e.g., branch, received, rport)
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl ViaHeader {
    /// Creates a new Via header with validation.
    ///
    /// # Arguments
    ///
    /// * `transport` - Transport protocol (e.g., "UDP", "TCP", "TLS")
    /// * `sent_by` - Sent-by value (host or host:port)
    ///
    /// # Errors
    ///
    /// Returns `ViaError` if:
    /// - Transport is invalid or too long
    /// - Sent-by is invalid or too long
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ViaHeader;
    ///
    /// let via = ViaHeader::new("UDP", "host.example.com:5060").unwrap();
    /// assert_eq!(via.transport(), "UDP");
    /// ```
    pub fn new(transport: impl Into<SmolStr>, sent_by: impl Into<SmolStr>) -> Result<Self, ViaError> {
        let transport = transport.into();
        let sent_by = sent_by.into();

        validate_transport(&transport)?;
        validate_sent_by(&sent_by)?;

        Ok(Self {
            transport,
            sent_by,
            params: BTreeMap::new(),
        })
    }

    /// Parses a Via header from a string.
    ///
    /// # Format
    ///
    /// ```text
    /// SIP/2.0/UDP host:port;param1=value1;param2
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ViaHeader;
    ///
    /// let via = ViaHeader::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK776").unwrap();
    /// assert_eq!(via.transport(), "UDP");
    /// assert_eq!(via.sent_by(), "host:5060");
    /// ```
    pub fn parse(input: &str) -> Result<Self, ViaError> {
        if input.chars().any(|c| c.is_control()) {
            return Err(ViaError::InvalidFormat(
                "contains control characters".to_string(),
            ));
        }

        let trimmed = input.trim_matches(|c| c == ' ' || c == '\t');
        if trimmed.is_empty() {
            return Err(ViaError::InvalidFormat("empty Via header".to_string()));
        }

        // Split into value and parameters
        let mut parts = trimmed.split(';');
        let value_part = parts
            .next()
            .ok_or_else(|| ViaError::InvalidFormat("empty Via header".to_string()))?
            .trim();

        // Parse SIP/2.0/TRANSPORT sent-by
        let mut value_parts = value_part.split_whitespace();

        let protocol_part = value_parts
            .next()
            .ok_or_else(|| ViaError::InvalidFormat("missing protocol".to_string()))?;

        // Expect "SIP/2.0/TRANSPORT"
        let protocol_components: Vec<&str> = protocol_part.split('/').collect();
        if protocol_components.len() != 3 {
            return Err(ViaError::InvalidFormat(
                "protocol must be SIP/2.0/TRANSPORT".to_string(),
            ));
        }

        if !protocol_components[0].eq_ignore_ascii_case("SIP") {
            return Err(ViaError::InvalidFormat(
                "protocol must start with SIP".to_string(),
            ));
        }

        if protocol_components[1] != "2.0" {
            return Err(ViaError::InvalidFormat(
                "only SIP/2.0 is supported".to_string(),
            ));
        }

        let transport = protocol_components[2];
        validate_transport(transport)?;

        let sent_by = value_parts
            .next()
            .ok_or_else(|| ViaError::InvalidFormat("missing sent-by".to_string()))?;
        validate_sent_by(sent_by)?;

        // Check for extra tokens
        if value_parts.next().is_some() {
            return Err(ViaError::InvalidFormat(
                "unexpected tokens after sent-by".to_string(),
            ));
        }

        // Parse parameters
        let mut params = BTreeMap::new();
        for param in parts {
            if params.len() >= MAX_PARAMS {
                return Err(ViaError::TooManyParameters { max: MAX_PARAMS });
            }

            let param = param.trim();
            if param.is_empty() {
                continue;
            }

            if let Some((k, v)) = param.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                validate_param_name(k)?;
                validate_param_value(v)?;
                params.insert(SmolStr::new(k.to_ascii_lowercase()), Some(SmolStr::new(v)));
            } else {
                validate_param_name(param)?;
                params.insert(SmolStr::new(param.to_ascii_lowercase()), None);
            }
        }

        Ok(Self {
            transport: SmolStr::new(transport),
            sent_by: SmolStr::new(sent_by),
            params,
        })
    }

    /// Returns the transport protocol.
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Returns the sent-by value.
    pub fn sent_by(&self) -> &str {
        &self.sent_by
    }

    /// Returns the parameters.
    pub fn params(&self) -> &BTreeMap<SmolStr, Option<SmolStr>> {
        &self.params
    }

    /// Looks up a parameter (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ViaHeader;
    ///
    /// let via = ViaHeader::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK776").unwrap();
    /// assert!(via.param("branch").is_some());
    /// assert!(via.param("BRANCH").is_some()); // Case-insensitive
    /// ```
    pub fn param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }

    /// Adds a parameter with validation.
    pub fn with_param(
        mut self,
        name: impl Into<SmolStr>,
        value: Option<impl Into<SmolStr>>,
    ) -> Result<Self, ViaError> {
        if self.params.len() >= MAX_PARAMS {
            return Err(ViaError::TooManyParameters { max: MAX_PARAMS });
        }

        let name = name.into();
        validate_param_name(&name)?;
        let name = SmolStr::new(name.to_ascii_lowercase());

        let value = match value {
            Some(v) => {
                let v = v.into();
                validate_param_value(&v)?;
                Some(v)
            }
            None => None,
        };

        self.params.insert(name, value);
        Ok(self)
    }

    /// Adds a parameter (mutation).
    pub fn add_param(
        &mut self,
        name: impl Into<SmolStr>,
        value: Option<impl Into<SmolStr>>,
    ) -> Result<(), ViaError> {
        if self.params.len() >= MAX_PARAMS {
            return Err(ViaError::TooManyParameters { max: MAX_PARAMS });
        }

        let name = name.into();
        validate_param_name(&name)?;
        let name = SmolStr::new(name.to_ascii_lowercase());

        let value = match value {
            Some(v) => {
                let v = v.into();
                validate_param_value(&v)?;
                Some(v)
            }
            None => None,
        };

        self.params.insert(name, value);
        Ok(())
    }
}

impl fmt::Display for ViaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP/2.0/{} {}", self.transport, self.sent_by)?;

        for (key, value) in &self.params {
            if let Some(v) = value {
                write!(f, ";{}={}", key, v)?;
            } else {
                write!(f, ";{}", key)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn via_basic() {
        let via = ViaHeader::new("UDP", "host.example.com:5060").unwrap();
        assert_eq!(via.transport(), "UDP");
        assert_eq!(via.sent_by(), "host.example.com:5060");
    }

    #[test]
    fn via_parse() {
        let via = ViaHeader::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK776").unwrap();
        assert_eq!(via.transport(), "UDP");
        assert_eq!(via.sent_by(), "host:5060");
        assert!(via.param("branch").is_some());
    }

    #[test]
    fn via_parse_with_ipv6() {
        let via = ViaHeader::parse("SIP/2.0/TCP [2001:db8::1]:5060").unwrap();
        assert_eq!(via.transport(), "TCP");
        assert_eq!(via.sent_by(), "[2001:db8::1]:5060");
    }

    #[test]
    fn via_parse_multiple_params() {
        let via = ViaHeader::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK776;received=192.0.2.1;rport=5061").unwrap();
        assert_eq!(via.params().len(), 3);
        assert!(via.param("branch").is_some());
        assert!(via.param("received").is_some());
        assert!(via.param("rport").is_some());
    }

    #[test]
    fn via_display() {
        let via = ViaHeader::new("UDP", "host:5060")
            .unwrap()
            .with_param("branch", Some("z9hG4bK776"))
            .unwrap();

        let output = via.to_string();
        assert!(output.contains("SIP/2.0/UDP"));
        assert!(output.contains("host:5060"));
        assert!(output.contains("branch=z9hG4bK776"));
    }

    #[test]
    fn via_param_case_insensitive() {
        let via = ViaHeader::parse("SIP/2.0/UDP host:5060;Branch=z9hG4bK776").unwrap();
        assert!(via.param("branch").is_some());
        assert!(via.param("BRANCH").is_some());
        assert!(via.param("Branch").is_some());
    }

    #[test]
    fn via_rejects_empty_transport() {
        assert!(ViaHeader::new("", "host").is_err());
    }

    #[test]
    fn via_rejects_empty_sent_by() {
        assert!(ViaHeader::new("UDP", "").is_err());
    }

    #[test]
    fn via_rejects_too_long_transport() {
        let long_transport = "x".repeat(MAX_TRANSPORT_LENGTH + 1);
        assert!(ViaHeader::new(long_transport, "host").is_err());
    }

    #[test]
    fn via_rejects_too_long_sent_by() {
        let long_sent_by = "x".repeat(MAX_SENT_BY_LENGTH + 1);
        assert!(ViaHeader::new("UDP", long_sent_by).is_err());
    }

    #[test]
    fn via_rejects_control_chars_in_transport() {
        assert!(ViaHeader::new("UDP\r\n", "host").is_err());
        assert!(ViaHeader::new("UDP\x00", "host").is_err());
    }

    #[test]
    fn via_rejects_control_chars_in_sent_by() {
        assert!(ViaHeader::new("UDP", "host\r\n").is_err());
        assert!(ViaHeader::new("UDP", "host\x00").is_err());
    }

    #[test]
    fn via_rejects_invalid_sent_by_port() {
        assert!(ViaHeader::new("UDP", "host:abc").is_err());
        assert!(ViaHeader::new("UDP", "host:0").is_err());
        assert!(ViaHeader::new("UDP", "host:65536").is_err());
    }

    #[test]
    fn via_rejects_invalid_transport_chars() {
        assert!(ViaHeader::new("UDP TCP", "host").is_err());
        assert!(ViaHeader::new("UDP@HOME", "host").is_err());
    }

    #[test]
    fn via_rejects_invalid_sent_by_chars() {
        assert!(ViaHeader::new("UDP", "host@example").is_err());
    }

    #[test]
    fn via_rejects_too_many_params() {
        let mut via = ViaHeader::new("UDP", "host").unwrap();
        for i in 0..MAX_PARAMS {
            via = via.with_param(format!("p{}", i), Some("v")).unwrap();
        }
        assert!(via.with_param("extra", Some("value")).is_err());
    }

    #[test]
    fn via_parse_rejects_invalid_format() {
        assert!(ViaHeader::parse("").is_err());
        assert!(ViaHeader::parse("UDP host:5060").is_err());
        assert!(ViaHeader::parse("SIP/UDP host:5060").is_err());
        assert!(ViaHeader::parse("SIP/2.0 host:5060").is_err());
        assert!(ViaHeader::parse("SIP/2.0/UDP").is_err());
    }

    #[test]
    fn via_parse_rejects_control_chars() {
        assert!(ViaHeader::parse("SIP/2.0/UDP host:5060\r\n").is_err());
        assert!(ViaHeader::parse("SIP/2.0/UDP host:\n5060").is_err());
    }

    #[test]
    fn via_parse_rejects_unsupported_version() {
        assert!(ViaHeader::parse("SIP/1.0/UDP host:5060").is_err());
        assert!(ViaHeader::parse("SIP/3.0/UDP host:5060").is_err());
    }

    #[test]
    fn via_parse_rejects_non_sip() {
        assert!(ViaHeader::parse("HTTP/1.1/TCP host:5060").is_err());
    }

    #[test]
    fn via_accepts_common_transports() {
        assert!(ViaHeader::new("UDP", "host").is_ok());
        assert!(ViaHeader::new("TCP", "host").is_ok());
        assert!(ViaHeader::new("TLS", "host").is_ok());
        assert!(ViaHeader::new("SCTP", "host").is_ok());
        assert!(ViaHeader::new("WS", "host").is_ok());
        assert!(ViaHeader::new("WSS", "host").is_ok());
    }

    #[test]
    fn via_add_param_mutation() {
        let mut via = ViaHeader::new("UDP", "host").unwrap();
        via.add_param("branch", Some("z9hG4bK776")).unwrap();
        via.add_param("received", Some("192.0.2.1")).unwrap();

        assert_eq!(via.params().len(), 2);
    }

    #[test]
    fn via_round_trip() {
        let original = ViaHeader::new("UDP", "host:5060")
            .unwrap()
            .with_param("branch", Some("z9hG4bK776"))
            .unwrap();

        let formatted = original.to_string();
        let parsed = ViaHeader::parse(&formatted).unwrap();

        assert_eq!(parsed.transport(), original.transport());
        assert_eq!(parsed.sent_by(), original.sent_by());
        assert_eq!(parsed.params().len(), original.params().len());
    }

    #[test]
    fn fields_are_private() {
        let via = ViaHeader::new("UDP", "host").unwrap();

        // These should compile (read access via getters)
        let _ = via.transport();
        let _ = via.sent_by();
        let _ = via.params();

        // These should NOT compile:
        // via.transport = SmolStr::new("evil");    // ← Does not compile!
        // via.params.insert(...);                  // ← Does not compile!
    }

    #[test]
    fn error_display() {
        let err1 = ViaError::InvalidTransport("test".to_string());
        assert_eq!(err1.to_string(), "Invalid transport: test");

        let err2 = ViaError::TooManyParameters { max: 20 };
        assert_eq!(err2.to_string(), "Too many parameters (max 20)");
    }

    #[test]
    fn via_sent_by_ipv6_validation() {
        // Valid IPv6
        assert!(ViaHeader::new("UDP", "[2001:db8::1]").is_ok());
        assert!(ViaHeader::new("UDP", "[2001:db8::1]:5060").is_ok());

        // Invalid - mismatched brackets
        assert!(ViaHeader::new("UDP", "[2001:db8::1").is_err());
        assert!(ViaHeader::new("UDP", "2001:db8::1]").is_err());
        assert!(ViaHeader::new("UDP", "2001:db8::1").is_err());
    }
}
