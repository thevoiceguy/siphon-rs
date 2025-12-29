// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! URI parsing for SIP (RFC 3261) and tel (RFC 3966) URIs with security hardening.

use std::collections::BTreeMap;
use std::fmt;

use percent_encoding::percent_decode_str;
use smol_str::SmolStr;

use crate::TelUri;

// Security: Input size limits
const MAX_URI_LENGTH: usize = 2048;
const MAX_USER_LENGTH: usize = 256;
const MAX_HOST_LENGTH: usize = 256;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_HEADER_NAME_LENGTH: usize = 64;
const MAX_HEADER_VALUE_LENGTH: usize = 512;
const MAX_PARAMS: usize = 50;
const MAX_HEADERS: usize = 50;
const MAX_ABSOLUTE_URI_LENGTH: usize = 2048;

/// Error types for URI operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    /// Invalid scheme
    InvalidScheme(String),
    /// Invalid format
    InvalidFormat(String),
    /// Invalid host
    InvalidHost(String),
    /// Invalid port
    InvalidPort(String),
    /// Invalid user
    InvalidUser(String),
    /// Invalid parameter
    InvalidParameter(String),
    /// Invalid header
    InvalidHeader(String),
    /// Too many items
    TooManyItems { field: &'static str, max: usize },
    /// Input too long
    TooLong { field: &'static str, max: usize },
    /// Percent decoding error
    PercentDecodingError(String),
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UriError::InvalidScheme(msg) => write!(f, "Invalid scheme: {}", msg),
            UriError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            UriError::InvalidHost(msg) => write!(f, "Invalid host: {}", msg),
            UriError::InvalidPort(msg) => write!(f, "Invalid port: {}", msg),
            UriError::InvalidUser(msg) => write!(f, "Invalid user: {}", msg),
            UriError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            UriError::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            UriError::TooManyItems { field, max } => {
                write!(f, "Too many {} (max {})", field, max)
            }
            UriError::TooLong { field, max } => {
                write!(f, "{} too long (max {})", field, max)
            }
            UriError::PercentDecodingError(msg) => write!(f, "Percent decoding error: {}", msg),
        }
    }
}

impl std::error::Error for UriError {}

/// Validates a hostname.
fn validate_host(host: &str) -> Result<(), UriError> {
    if host.is_empty() {
        return Err(UriError::InvalidHost("host cannot be empty".to_string()));
    }

    if host.len() > MAX_HOST_LENGTH {
        return Err(UriError::TooLong {
            field: "host",
            max: MAX_HOST_LENGTH,
        });
    }

    // Check for control characters
    if host.chars().any(|c| c.is_control()) {
        return Err(UriError::InvalidHost(
            "contains control characters".to_string(),
        ));
    }

    // Basic hostname validation (simplified - could be more strict)
    // Allow alphanumeric, dots, dashes, brackets for IPv6
    let valid = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '[' | ']' | ':'));

    if !valid {
        return Err(UriError::InvalidHost(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a user part.
fn validate_user(user: &str) -> Result<(), UriError> {
    if user.is_empty() {
        return Err(UriError::InvalidUser("user cannot be empty".to_string()));
    }

    if user.len() > MAX_USER_LENGTH {
        return Err(UriError::TooLong {
            field: "user",
            max: MAX_USER_LENGTH,
        });
    }

    // Check for control characters
    if user.chars().any(|c| c.is_control()) {
        return Err(UriError::InvalidUser(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a port number.
fn validate_port(port: u16) -> Result<(), UriError> {
    if port == 0 {
        return Err(UriError::InvalidPort("port cannot be 0".to_string()));
    }
    Ok(())
}

/// Validates a parameter name.
fn validate_param_name(name: &str) -> Result<(), UriError> {
    if name.is_empty() {
        return Err(UriError::InvalidParameter(
            "parameter name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(UriError::TooLong {
            field: "parameter name",
            max: MAX_PARAM_NAME_LENGTH,
        });
    }

    // Check for control characters, whitespace, and invalid token chars
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || !is_token_char(c))
    {
        return Err(UriError::InvalidParameter(
            "parameter name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a parameter value.
fn validate_param_value(value: &str) -> Result<(), UriError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(UriError::TooLong {
            field: "parameter value",
            max: MAX_PARAM_VALUE_LENGTH,
        });
    }

    // Check for control characters
    if value.chars().any(|c| c.is_control()) {
        return Err(UriError::InvalidParameter(
            "parameter value contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a header name.
fn validate_header_name(name: &str) -> Result<(), UriError> {
    if name.is_empty() {
        return Err(UriError::InvalidHeader(
            "header name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_HEADER_NAME_LENGTH {
        return Err(UriError::TooLong {
            field: "header name",
            max: MAX_HEADER_NAME_LENGTH,
        });
    }

    // Check for control characters, whitespace, and invalid token chars
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || !is_token_char(c))
    {
        return Err(UriError::InvalidHeader(
            "header name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a header value.
fn validate_header_value(value: &str) -> Result<(), UriError> {
    if value.len() > MAX_HEADER_VALUE_LENGTH {
        return Err(UriError::TooLong {
            field: "header value",
            max: MAX_HEADER_VALUE_LENGTH,
        });
    }

    // Check for control characters and whitespace
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(UriError::InvalidHeader(
            "header value contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Parsed representation of a SIP URI (RFC 3261 §19).
///
/// # Security
///
/// SipUri validates all components and enforces bounds to prevent DoS attacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipUri {
    /// Raw URI string
    raw: SmolStr,
    /// True if this is a SIPS URI
    sips: bool,
    /// User part (optional)
    user: Option<SmolStr>,
    /// Host part (required)
    host: SmolStr,
    /// Port (optional)
    port: Option<u16>,
    /// URI parameters
    params: BTreeMap<SmolStr, Option<SmolStr>>,
    /// URI headers
    headers: BTreeMap<SmolStr, SmolStr>,
}

impl SipUri {
    /// Constructs a `sip:` URI with the given host and default settings.
    pub fn new(host: impl Into<SmolStr>) -> Result<Self, UriError> {
        let host = host.into();
        validate_host(&host)?;

        let raw = SmolStr::new(format!("sip:{}", host));

        Ok(Self {
            raw,
            sips: false,
            user: None,
            host,
            port: None,
            params: BTreeMap::new(),
            headers: BTreeMap::new(),
        })
    }

    /// Attempts to parse a SIP or SIPS URI from the provided string.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        if input.chars().any(|c| c.is_control()) {
            return Err(UriError::InvalidFormat(
                "contains control characters".to_string(),
            ));
        }

        if input.len() > MAX_URI_LENGTH {
            return Err(UriError::TooLong {
                field: "URI",
                max: MAX_URI_LENGTH,
            });
        }

        let raw = SmolStr::new(input);
        let (scheme, rest) = input
            .split_once(':')
            .ok_or_else(|| UriError::InvalidFormat("missing scheme separator".to_string()))?;

        let sips = scheme.eq_ignore_ascii_case("sips");
        if !sips && !scheme.eq_ignore_ascii_case("sip") {
            return Err(UriError::InvalidScheme(format!(
                "expected 'sip' or 'sips', got '{}'",
                scheme
            )));
        }

        let (addr_part, headers_part) = match rest.split_once('?') {
            Some((addr, headers)) => (addr, Some(headers)),
            None => (rest, None),
        };

        let mut params = BTreeMap::new();
        let mut addr_iter = addr_part.split(';');
        let base = addr_iter
            .next()
            .ok_or_else(|| UriError::InvalidFormat("missing address part".to_string()))?
            .trim();

        for param in addr_iter {
            if params.len() >= MAX_PARAMS {
                return Err(UriError::TooManyItems {
                    field: "parameters",
                    max: MAX_PARAMS,
                });
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
                params.insert(SmolStr::new(k), Some(SmolStr::new(v)));
            } else {
                validate_param_name(param)?;
                params.insert(SmolStr::new(param), None);
            }
        }

        let (user, host_port) = match base.split_once('@') {
            Some((user_part, host)) => {
                let decoded = percent_decode_str(user_part.trim())
                    .decode_utf8()
                    .map_err(|e| UriError::PercentDecodingError(e.to_string()))?;

                validate_user(&decoded)?;
                (Some(SmolStr::new(&*decoded)), host.trim())
            }
            None => (None, base.trim()),
        };

        if host_port.is_empty() {
            return Err(UriError::InvalidFormat("missing host".to_string()));
        }

        let (host_str, port) = split_host_port(host_port)?;
        let decoded_host = percent_decode_str(host_str)
            .decode_utf8()
            .map_err(|e| UriError::PercentDecodingError(e.to_string()))?
            .to_ascii_lowercase();

        validate_host(&decoded_host)?;

        if let Some(p) = port {
            validate_port(p)?;
        }

        let mut headers = BTreeMap::new();
        if let Some(headers_part) = headers_part {
            for pair in headers_part.split('&') {
                if headers.len() >= MAX_HEADERS {
                    return Err(UriError::TooManyItems {
                        field: "headers",
                        max: MAX_HEADERS,
                    });
                }

                if pair.is_empty() {
                    continue;
                }

                if let Some((k, v)) = pair.split_once('=') {
                    let k = k.trim();
                    let v = v.trim();
                    validate_header_name(k)?;
                    validate_header_value(v)?;
                    headers.insert(SmolStr::new(k), SmolStr::new(v));
                }
            }
        }

        Ok(Self {
            raw,
            sips,
            user,
            host: SmolStr::new(decoded_host),
            port,
            params,
            headers,
        })
    }

    /// Returns the original textual representation of the URI.
    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    /// Returns true if this is a SIPS URI.
    pub fn is_sips(&self) -> bool {
        self.sips
    }

    /// Returns the user part if present.
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Returns the host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port if present.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the parameters.
    pub fn params(&self) -> &BTreeMap<SmolStr, Option<SmolStr>> {
        &self.params
    }

    /// Returns the headers.
    pub fn headers(&self) -> &BTreeMap<SmolStr, SmolStr> {
        &self.headers
    }

    /// Sets the host with validation.
    pub fn with_host(mut self, host: impl Into<SmolStr>) -> Result<Self, UriError> {
        let host = host.into();
        validate_host(&host)?;
        self.host = host;
        self.raw = build_raw_sip_uri(&self);
        Ok(self)
    }

    /// Clears the port.
    pub fn without_port(mut self) -> Self {
        self.port = None;
        self.raw = build_raw_sip_uri(&self);
        self
    }

    /// Sets the user part with validation.
    pub fn with_user(mut self, user: impl Into<SmolStr>) -> Result<Self, UriError> {
        let user = user.into();
        validate_user(&user)?;
        self.user = Some(user);
        self.raw = build_raw_sip_uri(&self);
        Ok(self)
    }

    /// Sets the port with validation.
    pub fn with_port(mut self, port: u16) -> Result<Self, UriError> {
        validate_port(port)?;
        self.port = Some(port);
        self.raw = build_raw_sip_uri(&self);
        Ok(self)
    }

    /// Adds a parameter with validation.
    pub fn with_param(
        mut self,
        name: impl Into<SmolStr>,
        value: Option<impl Into<SmolStr>>,
    ) -> Result<Self, UriError> {
        if self.params.len() >= MAX_PARAMS {
            return Err(UriError::TooManyItems {
                field: "parameters",
                max: MAX_PARAMS,
            });
        }

        let name = name.into();
        validate_param_name(&name)?;

        let value = match value {
            Some(v) => {
                let v = v.into();
                validate_param_value(&v)?;
                Some(v)
            }
            None => None,
        };

        self.params.insert(name, value);
        self.raw = build_raw_sip_uri(&self);
        Ok(self)
    }
}

/// Unified URI type supporting both SIP URIs (RFC 3261) and tel URIs (RFC 3966).
///
/// # Security
///
/// Uri validates all components through the underlying type validators.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Uri {
    /// SIP or SIPS URI (e.g., sip:user@example.com, sips:+15551234567@example.com)
    Sip(SipUri),
    /// Telephone URI (e.g., tel:+1-555-123-4567, tel:5551234;phone-context=example.com)
    Tel(TelUri),
    /// Absolute URI (e.g., http://example.com/info, https://example.com/loc)
    Absolute(SmolStr),
}

impl Uri {
    /// Parses a URI string, automatically detecting whether it's a SIP or tel URI.
    ///
    /// # Examples
    /// ```
    /// use sip_core::Uri;
    ///
    /// // Parse SIP URI
    /// let uri = Uri::parse("sip:alice@example.com").unwrap();
    ///
    /// // Parse tel URI
    /// let uri = Uri::parse("tel:+1-555-123-4567").unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self, UriError> {
        if input.chars().any(|c| c.is_control()) {
            return Err(UriError::InvalidFormat(
                "contains control characters".to_string(),
            ));
        }

        // Try tel URI first (more specific prefix)
        if input.starts_with("tel:") {
            TelUri::parse(input)
                .map(Uri::Tel)
                .map_err(|e| UriError::InvalidFormat(e.to_string()))
        } else if input.starts_with("sip:") || input.starts_with("sips:") {
            SipUri::parse(input).map(Uri::Sip)
        } else {
            parse_absolute_uri(input).map(Uri::Absolute)
        }
    }

    /// Returns the URI as a string.
    pub fn as_str(&self) -> &str {
        match self {
            Uri::Sip(uri) => uri.as_str(),
            Uri::Tel(uri) => uri.as_str(),
            Uri::Absolute(uri) => uri.as_str(),
        }
    }

    /// Returns true if this is a SIP or SIPS URI.
    pub fn is_sip(&self) -> bool {
        matches!(self, Uri::Sip(_))
    }

    /// Returns true if this is a tel URI.
    pub fn is_tel(&self) -> bool {
        matches!(self, Uri::Tel(_))
    }

    /// Returns true if this is an absolute URI (non-sip, non-tel).
    pub fn is_absolute(&self) -> bool {
        matches!(self, Uri::Absolute(_))
    }

    /// Returns the inner SipUri if this is a SIP URI, None otherwise.
    pub fn as_sip(&self) -> Option<&SipUri> {
        match self {
            Uri::Sip(uri) => Some(uri),
            _ => None,
        }
    }

    /// Returns the inner TelUri if this is a tel URI, None otherwise.
    pub fn as_tel(&self) -> Option<&TelUri> {
        match self {
            Uri::Tel(uri) => Some(uri),
            _ => None,
        }
    }

    /// Returns the absolute URI string if present.
    pub fn as_absolute(&self) -> Option<&str> {
        match self {
            Uri::Absolute(uri) => Some(uri.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<SipUri> for Uri {
    fn from(uri: SipUri) -> Self {
        Uri::Sip(uri)
    }
}

impl From<TelUri> for Uri {
    fn from(uri: TelUri) -> Self {
        Uri::Tel(uri)
    }
}

fn parse_absolute_uri(input: &str) -> Result<SmolStr, UriError> {
    if input.len() > MAX_ABSOLUTE_URI_LENGTH {
        return Err(UriError::TooLong {
            field: "absolute URI",
            max: MAX_ABSOLUTE_URI_LENGTH,
        });
    }

    let trimmed = input.trim();
    let mut chars = trimmed.chars();
    let first = chars
        .next()
        .ok_or_else(|| UriError::InvalidFormat("empty URI".to_string()))?;

    if !first.is_ascii_alphabetic() {
        return Err(UriError::InvalidScheme(
            "scheme must start with letter".to_string(),
        ));
    }

    let mut idx = 1;
    for ch in chars {
        if ch == ':' {
            break;
        }
        if !(ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.') {
            return Err(UriError::InvalidScheme(
                "scheme contains invalid characters".to_string(),
            ));
        }
        idx += ch.len_utf8();
    }

    if !trimmed[idx..].starts_with(':') {
        return Err(UriError::InvalidFormat(
            "missing colon after scheme".to_string(),
        ));
    }

    let remainder = &trimmed[idx + 1..];
    if remainder.is_empty() {
        return Err(UriError::InvalidFormat(
            "empty URI after scheme".to_string(),
        ));
    }

    // Check for control characters
    if remainder.chars().any(|c| c.is_control()) {
        return Err(UriError::InvalidFormat(
            "contains control characters".to_string(),
        ));
    }

    Ok(SmolStr::new(trimmed))
}

/// Splits a host[:port] or IPv6 literal "[host]:port" string.
fn split_host_port(input: &str) -> Result<(&str, Option<u16>), UriError> {
    if input.starts_with('[') {
        let end = input
            .find(']')
            .ok_or_else(|| UriError::InvalidHost("unclosed IPv6 bracket".to_string()))?;
        let host = &input[1..end];
        let remainder = &input[end + 1..];

        if let Some(stripped) = remainder.strip_prefix(':') {
            let port = stripped
                .parse()
                .map_err(|_| UriError::InvalidPort("invalid port number".to_string()))?;
            Ok((host, Some(port)))
        } else {
            Ok((host, None))
        }
    } else if let Some(idx) = input.rfind(':') {
        // If multiple colons (unbracketed IPv6), invalid
        if input.matches(':').count() > 1 {
            return Err(UriError::InvalidHost(
                "unbracketed IPv6 address".to_string(),
            ));
        }

        let (host, port_str) = input.split_at(idx);
        if port_str.len() > 1 && port_str[1..].chars().all(|c| c.is_ascii_digit()) {
            let port = port_str[1..]
                .parse()
                .map_err(|_| UriError::InvalidPort("invalid port number".to_string()))?;
            Ok((host, Some(port)))
        } else {
            Ok((input, None))
        }
    } else {
        Ok((input, None))
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

fn build_raw_sip_uri(uri: &SipUri) -> SmolStr {
    let mut out = String::new();
    out.push_str(if uri.sips { "sips:" } else { "sip:" });
    if let Some(user) = &uri.user {
        out.push_str(user.as_str());
        out.push('@');
    }
    if uri.host.contains(':') && !uri.host.starts_with('[') && !uri.host.ends_with(']') {
        out.push('[');
        out.push_str(uri.host.as_str());
        out.push(']');
    } else {
        out.push_str(uri.host.as_str());
    }
    if let Some(port) = uri.port {
        out.push(':');
        out.push_str(&port.to_string());
    }
    for (key, value) in &uri.params {
        out.push(';');
        out.push_str(key.as_str());
        if let Some(val) = value {
            out.push('=');
            out.push_str(val.as_str());
        }
    }
    if !uri.headers.is_empty() {
        out.push('?');
        let mut first = true;
        for (key, value) in &uri.headers {
            if !first {
                out.push('&');
            }
            first = false;
            out.push_str(key.as_str());
            out.push('=');
            out.push_str(value.as_str());
        }
    }
    SmolStr::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sip_uri_via_uri_enum() {
        let uri = Uri::parse("sip:alice@example.com").unwrap();
        assert!(uri.is_sip());
        assert!(!uri.is_tel());

        let sip_uri = uri.as_sip().unwrap();
        assert_eq!(sip_uri.host(), "example.com");
        assert_eq!(sip_uri.user().unwrap(), "alice");
    }

    #[test]
    fn parses_tel_uri_via_uri_enum() {
        let uri = Uri::parse("tel:+1-555-123-4567").unwrap();
        assert!(uri.is_tel());
        assert!(!uri.is_sip());

        let tel_uri = uri.as_tel().unwrap();
        assert!(tel_uri.is_global());
        assert_eq!(tel_uri.number(), "+15551234567");
    }

    #[test]
    fn uri_enum_display() {
        let sip_uri = Uri::parse("sip:alice@example.com").unwrap();
        assert_eq!(sip_uri.to_string(), "sip:alice@example.com");

        let tel_uri = Uri::parse("tel:+15551234567").unwrap();
        assert_eq!(tel_uri.to_string(), "tel:+15551234567");
    }

    #[test]
    fn uri_enum_from_conversions() {
        let sip = SipUri::parse("sip:alice@example.com").unwrap();
        let uri: Uri = sip.into();
        assert!(uri.is_sip());

        let tel = TelUri::parse("tel:+15551234567").unwrap();
        let uri: Uri = tel.into();
        assert!(uri.is_tel());
    }

    #[test]
    fn rejects_unbracketed_ipv6_host() {
        let uri = SipUri::parse("sip:2001:db8::1");
        assert!(uri.is_err());
    }

    #[test]
    fn accepts_bracketed_ipv6() {
        let uri = SipUri::parse("sip:alice@[2001:db8::1]").unwrap();
        assert_eq!(uri.host(), "2001:db8::1");
    }

    #[test]
    fn parses_sip_uri_with_port() {
        let uri = SipUri::parse("sip:alice@example.com:5060").unwrap();
        assert_eq!(uri.host(), "example.com");
        assert_eq!(uri.port(), Some(5060));
    }

    #[test]
    fn parses_sip_uri_with_params() {
        let uri = SipUri::parse("sip:alice@example.com;transport=tcp;lr").unwrap();
        assert!(uri.params().contains_key("transport"));
        assert!(uri.params().contains_key("lr"));
    }

    #[test]
    fn parses_sip_uri_with_headers() {
        let uri = SipUri::parse("sip:alice@example.com?subject=test&priority=urgent").unwrap();
        assert_eq!(uri.headers().get("subject").unwrap().as_str(), "test");
        assert_eq!(uri.headers().get("priority").unwrap().as_str(), "urgent");
    }

    #[test]
    fn rejects_too_long_uri() {
        let long_uri = format!("sip:{}", "x".repeat(MAX_URI_LENGTH));
        assert!(SipUri::parse(&long_uri).is_err());
    }

    #[test]
    fn rejects_too_long_host() {
        let long_host = "x".repeat(MAX_HOST_LENGTH + 1);
        let uri_str = format!("sip:{}", long_host);
        assert!(SipUri::parse(&uri_str).is_err());
    }

    #[test]
    fn rejects_too_many_params() {
        let mut uri_str = "sip:user@host".to_string();
        for i in 0..=MAX_PARAMS {
            uri_str.push_str(&format!(";p{}=v", i));
        }
        assert!(SipUri::parse(&uri_str).is_err());
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut uri_str = "sip:user@host?".to_string();
        for i in 0..=MAX_HEADERS {
            if i > 0 {
                uri_str.push('&');
            }
            uri_str.push_str(&format!("h{}=v", i));
        }
        assert!(SipUri::parse(&uri_str).is_err());
    }

    #[test]
    fn rejects_control_chars_in_user() {
        assert!(SipUri::parse("sip:user\r\n@host").is_err());
        assert!(SipUri::parse("sip:user\x00@host").is_err());
    }

    #[test]
    fn rejects_control_chars_in_host() {
        assert!(SipUri::parse("sip:user@host\r\n").is_err());
    }

    #[test]
    fn rejects_invalid_port() {
        assert!(SipUri::parse("sip:user@host:0").is_err());
        assert!(SipUri::parse("sip:user@host:99999").is_err());
    }

    #[test]
    fn rejects_empty_host() {
        assert!(SipUri::parse("sip:user@").is_err());
    }

    #[test]
    fn new_validates_host() {
        assert!(SipUri::new("example.com").is_ok());
        assert!(SipUri::new("").is_err());
        let long_host = "x".repeat(MAX_HOST_LENGTH + 1);
        assert!(SipUri::new(long_host).is_err());
    }

    #[test]
    fn with_user_validates() {
        let uri = SipUri::new("example.com").unwrap();
        assert!(uri.clone().with_user("alice").is_ok());
        assert!(uri.clone().with_user("").is_err());

        let long_user = "x".repeat(MAX_USER_LENGTH + 1);
        assert!(uri.with_user(long_user).is_err());
    }

    #[test]
    fn with_port_validates() {
        let uri = SipUri::new("example.com").unwrap();
        assert!(uri.clone().with_port(5060).is_ok());
        assert!(uri.with_port(0).is_err());
    }

    #[test]
    fn with_param_validates() {
        let uri = SipUri::new("example.com").unwrap();
        let uri = uri.with_param("transport", Some("tcp")).unwrap();
        assert!(uri.params().contains_key("transport"));

        // Too many params
        let mut uri = SipUri::new("example.com").unwrap();
        for i in 0..MAX_PARAMS {
            uri = uri.with_param(format!("p{}", i), Some("v")).unwrap();
        }
        assert!(uri.with_param("extra", Some("value")).is_err());
    }

    #[test]
    fn fields_are_private() {
        let uri = SipUri::new("example.com").unwrap();

        // These should compile (read access via getters)
        let _ = uri.host();
        let _ = uri.user();
        let _ = uri.port();
        let _ = uri.params();

        // These should NOT compile:
        // uri.host = SmolStr::new("evil");         // ← Does not compile!
        // uri.params.insert(...);                  // ← Does not compile!
    }

    #[test]
    fn parse_absolute_uri() {
        let uri = Uri::parse("http://example.com/path").unwrap();
        assert!(uri.is_absolute());
        assert_eq!(uri.as_absolute().unwrap(), "http://example.com/path");
    }

    #[test]
    fn rejects_absolute_uri_with_control_chars() {
        assert!(Uri::parse("http://example.com/path\r\n").is_err());
    }

    #[test]
    fn error_display() {
        let err1 = UriError::InvalidScheme("test".to_string());
        assert!(err1.to_string().contains("Invalid scheme"));

        let err2 = UriError::TooManyItems {
            field: "parameters",
            max: 50,
        };
        assert_eq!(err2.to_string(), "Too many parameters (max 50)");
    }
}
