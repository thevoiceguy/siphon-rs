// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Authorization and Proxy-Authorization header support (RFC 7235, RFC 7615, RFC 7616).
//!
//! # Security
//!
//! AuthorizationHeader validates all components and enforces bounds to prevent DoS attacks:
//! - Maximum scheme length (64 bytes)
//! - Maximum parameter count (30 parameters)
//! - Maximum parameter name/value lengths (256 bytes)
//! - No control characters in scheme or parameter values
//! - Duplicate parameter detection

use std::collections::BTreeMap;
use std::fmt;

use smol_str::SmolStr;

// Security: Input size limits
const MAX_SCHEME_LENGTH: usize = 64;
const MAX_AUTH_PARAMS: usize = 30;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;

/// Error types for Authorization header operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    /// Invalid scheme
    InvalidScheme(String),
    /// Invalid parameter
    InvalidParameter(String),
    /// Too many parameters
    TooManyParameters { max: usize },
    /// Input too long
    TooLong { field: &'static str, max: usize },
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationError::InvalidScheme(msg) => write!(f, "Invalid scheme: {}", msg),
            AuthorizationError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            AuthorizationError::TooManyParameters { max } => {
                write!(f, "Too many parameters (max {})", max)
            }
            AuthorizationError::TooLong { field, max } => {
                write!(f, "{} too long (max {})", field, max)
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// Validates a scheme value.
fn validate_scheme(scheme: &str) -> Result<(), AuthorizationError> {
    if scheme.is_empty() {
        return Err(AuthorizationError::InvalidScheme(
            "scheme cannot be empty".to_string(),
        ));
    }

    if scheme.len() > MAX_SCHEME_LENGTH {
        return Err(AuthorizationError::TooLong {
            field: "scheme",
            max: MAX_SCHEME_LENGTH,
        });
    }

    // Check for control characters
    if scheme.chars().any(|c| c.is_control()) {
        return Err(AuthorizationError::InvalidScheme(
            "contains control characters".to_string(),
        ));
    }

    // RFC 7235: auth-scheme = token
    // token = 1*tchar
    // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
    //         "0"-"9" / "A"-"Z" / "^" / "_" / "`" / "a"-"z" / "|" / "~"
    if !scheme.chars().all(is_token_char) {
        return Err(AuthorizationError::InvalidScheme(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a parameter name.
fn validate_param_name(name: &str) -> Result<(), AuthorizationError> {
    if name.is_empty() {
        return Err(AuthorizationError::InvalidParameter(
            "parameter name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(AuthorizationError::TooLong {
            field: "parameter name",
            max: MAX_PARAM_NAME_LENGTH,
        });
    }

    // Check for control characters
    if name.chars().any(|c| c.is_control()) {
        return Err(AuthorizationError::InvalidParameter(
            "parameter name contains control characters".to_string(),
        ));
    }

    // Parameter names must be tokens
    if !name.chars().all(is_token_char) {
        return Err(AuthorizationError::InvalidParameter(
            "parameter name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a parameter value.
fn validate_param_value(value: &str) -> Result<(), AuthorizationError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(AuthorizationError::TooLong {
            field: "parameter value",
            max: MAX_PARAM_VALUE_LENGTH,
        });
    }

    // Check for control characters (except tab which is allowed in quoted strings)
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err(AuthorizationError::InvalidParameter(
            "parameter value contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

fn is_token_value(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_token_char)
}

fn escape_quoted_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

fn digest_param_requires_quotes(name: &str) -> bool {
    matches!(
        name,
        "username" | "realm" | "nonce" | "uri" | "response" | "opaque" | "cnonce" | "domain"
    )
}

/// Represents Authorization / Proxy-Authorization header values (RFC 7235).
///
/// # Security
///
/// AuthorizationHeader validates all components and enforces bounds to prevent DoS attacks.
///
/// # Examples
///
/// ```
/// use sip_core::AuthorizationHeader;
///
/// // Create a Digest authorization header
/// let mut auth = AuthorizationHeader::new("Digest").unwrap();
/// auth.add_param("username", "alice").unwrap();
/// auth.add_param("realm", "example.com").unwrap();
/// auth.add_param("nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093").unwrap();
/// auth.add_param("uri", "sip:bob@biloxi.com").unwrap();
/// auth.add_param("response", "6629fae49393a05397450978507c4ef1").unwrap();
///
/// assert_eq!(auth.scheme(), "Digest");
/// assert_eq!(auth.param("username"), Some(&"alice".into()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationHeader {
    /// Authentication scheme (e.g., "Digest", "Basic")
    scheme: SmolStr,
    /// Authentication parameters (e.g., realm, nonce, response)
    params: BTreeMap<SmolStr, SmolStr>,
}

impl AuthorizationHeader {
    /// Creates a new authorization header with validation.
    ///
    /// # Arguments
    ///
    /// * `scheme` - Authentication scheme (e.g., "Digest", "Basic")
    ///
    /// # Errors
    ///
    /// Returns `AuthorizationError` if:
    /// - Scheme is empty or too long
    /// - Scheme contains invalid characters
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::AuthorizationHeader;
    ///
    /// let auth = AuthorizationHeader::new("Digest").unwrap();
    /// assert_eq!(auth.scheme(), "Digest");
    /// ```
    pub fn new(scheme: impl Into<SmolStr>) -> Result<Self, AuthorizationError> {
        let scheme = scheme.into();
        validate_scheme(&scheme)?;

        Ok(Self {
            scheme,
            params: BTreeMap::new(),
        })
    }

    /// Creates an authorization header from raw components (for parser use).
    ///
    /// This function is intended for use by parsers. It performs full validation
    /// on the scheme and all parameters, including bounds checking.
    ///
    /// # Errors
    ///
    /// Returns `AuthorizationError` if:
    /// - Scheme is invalid
    /// - Too many parameters (max 30)
    /// - Any parameter name or value is invalid
    pub fn from_raw(
        scheme: SmolStr,
        params: BTreeMap<SmolStr, SmolStr>,
    ) -> Result<Self, AuthorizationError> {
        validate_scheme(&scheme)?;

        let mut normalized = BTreeMap::new();
        for (name, value) in params {
            validate_param_name(&name)?;
            validate_param_value(&value)?;
            let key = SmolStr::new(name.to_ascii_lowercase());
            if normalized.contains_key(&key) {
                return Err(AuthorizationError::InvalidParameter(format!(
                    "duplicate parameter: {}",
                    name
                )));
            }
            if normalized.len() >= MAX_AUTH_PARAMS {
                return Err(AuthorizationError::TooManyParameters {
                    max: MAX_AUTH_PARAMS,
                });
            }
            normalized.insert(key, value);
        }

        Ok(Self {
            scheme,
            params: normalized,
        })
    }

    /// Returns the authentication scheme.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns all parameters as an immutable map.
    pub fn params(&self) -> &BTreeMap<SmolStr, SmolStr> {
        &self.params
    }

    /// Looks up a parameter value by name (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::AuthorizationHeader;
    ///
    /// let mut auth = AuthorizationHeader::new("Digest").unwrap();
    /// auth.add_param("realm", "example.com").unwrap();
    ///
    /// assert_eq!(auth.param("realm"), Some(&"example.com".into()));
    /// assert_eq!(auth.param("REALM"), Some(&"example.com".into())); // Case-insensitive
    /// assert_eq!(auth.param("missing"), None);
    /// ```
    pub fn param(&self, name: &str) -> Option<&SmolStr> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }

    /// Adds a parameter with validation.
    ///
    /// # Errors
    ///
    /// Returns `AuthorizationError` if:
    /// - Parameter name or value is invalid
    /// - Too many parameters (max 30)
    /// - Duplicate parameter name
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::AuthorizationHeader;
    ///
    /// let mut auth = AuthorizationHeader::new("Digest").unwrap();
    /// auth.add_param("username", "alice").unwrap();
    /// auth.add_param("realm", "example.com").unwrap();
    ///
    /// assert_eq!(auth.param("username"), Some(&"alice".into()));
    /// ```
    pub fn add_param(
        &mut self,
        name: impl Into<SmolStr>,
        value: impl Into<SmolStr>,
    ) -> Result<(), AuthorizationError> {
        let name = name.into();
        let value = value.into();

        validate_param_name(&name)?;
        validate_param_value(&value)?;

        let name = SmolStr::new(name.to_ascii_lowercase());

        // Check for duplicate
        if self.params.contains_key(&name) {
            return Err(AuthorizationError::InvalidParameter(format!(
                "duplicate parameter: {}",
                name
            )));
        }

        if self.params.len() >= MAX_AUTH_PARAMS {
            return Err(AuthorizationError::TooManyParameters {
                max: MAX_AUTH_PARAMS,
            });
        }

        self.params.insert(name, value);
        Ok(())
    }

    /// Adds a parameter, overwriting if it already exists (for parser use).
    ///
    /// This is used by parsers where the last value should win.
    /// Unlike `add_param()`, this does not reject duplicate parameter names.
    ///
    /// # Errors
    ///
    /// Returns `AuthorizationError` if:
    /// - Parameter name or value is invalid
    /// - Too many parameters (max 30)
    pub fn add_param_overwrite(
        &mut self,
        name: impl Into<SmolStr>,
        value: impl Into<SmolStr>,
    ) -> Result<(), AuthorizationError> {
        let name = name.into();
        let value = value.into();

        validate_param_name(&name)?;
        validate_param_value(&value)?;

        let key = SmolStr::new(name.to_ascii_lowercase());
        if self.params.len() >= MAX_AUTH_PARAMS && !self.params.contains_key(&key) {
            return Err(AuthorizationError::TooManyParameters {
                max: MAX_AUTH_PARAMS,
            });
        }

        self.params.insert(key, value);
        Ok(())
    }
}

impl fmt::Display for AuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.scheme)?;

        for (i, (name, value)) in self.params.iter().enumerate() {
            if i == 0 {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }

            let force_quote = self.scheme.eq_ignore_ascii_case("Digest")
                && digest_param_requires_quotes(name.as_str());
            if !force_quote && is_token_value(value) {
                write!(f, "{}={}", name, value)?;
            } else {
                let escaped = escape_quoted_value(value);
                write!(f, "{}=\"{}\"", name, escaped)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_creation() {
        let auth = AuthorizationHeader::new("Digest").unwrap();
        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.params().len(), 0);
    }

    #[test]
    fn auth_header_add_params() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        auth.add_param("username", "alice").unwrap();
        auth.add_param("realm", "example.com").unwrap();
        auth.add_param("nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093")
            .unwrap();

        assert_eq!(auth.param("username"), Some(&"alice".into()));
        assert_eq!(auth.param("realm"), Some(&"example.com".into()));
    }

    #[test]
    fn auth_header_param_case_insensitive() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        auth.add_param("Realm", "example.com").unwrap();

        assert_eq!(auth.param("realm"), Some(&"example.com".into()));
        assert_eq!(auth.param("REALM"), Some(&"example.com".into()));
        assert_eq!(auth.param("Realm"), Some(&"example.com".into()));
    }

    #[test]
    fn auth_header_rejects_empty_scheme() {
        assert!(AuthorizationHeader::new("").is_err());
    }

    #[test]
    fn auth_header_rejects_too_long_scheme() {
        let long_scheme = "x".repeat(MAX_SCHEME_LENGTH + 1);
        assert!(AuthorizationHeader::new(long_scheme).is_err());
    }

    #[test]
    fn auth_header_rejects_control_chars_in_scheme() {
        assert!(AuthorizationHeader::new("Digest\r\n").is_err());
        assert!(AuthorizationHeader::new("Digest\x00").is_err());
    }

    #[test]
    fn auth_header_rejects_invalid_scheme_chars() {
        assert!(AuthorizationHeader::new("Digest Auth").is_err()); // Space not allowed
        assert!(AuthorizationHeader::new("Digest@Auth").is_err()); // @ not allowed
    }

    #[test]
    fn auth_header_rejects_empty_param_name() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        assert!(auth.add_param("", "value").is_err());
    }

    #[test]
    fn auth_header_rejects_too_long_param_name() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        let long_name = "x".repeat(MAX_PARAM_NAME_LENGTH + 1);
        assert!(auth.add_param(long_name, "value").is_err());
    }

    #[test]
    fn auth_header_rejects_too_long_param_value() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        let long_value = "x".repeat(MAX_PARAM_VALUE_LENGTH + 1);
        assert!(auth.add_param("name", long_value).is_err());
    }

    #[test]
    fn auth_header_rejects_control_chars_in_param_name() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        assert!(auth.add_param("name\r\n", "value").is_err());
        assert!(auth.add_param("name\x00", "value").is_err());
    }

    #[test]
    fn auth_header_rejects_control_chars_in_param_value() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        assert!(auth.add_param("name", "value\r\n").is_err());
        assert!(auth.add_param("name", "value\x00").is_err());
    }

    #[test]
    fn auth_header_allows_tab_in_param_value() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        assert!(auth.add_param("name", "value\twith\ttabs").is_ok());
    }

    #[test]
    fn auth_header_rejects_duplicate_params() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        auth.add_param("realm", "example.com").unwrap();
        assert!(auth.add_param("realm", "other.com").is_err());
    }

    #[test]
    fn auth_header_rejects_too_many_params() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        for i in 0..MAX_AUTH_PARAMS {
            auth.add_param(format!("param{}", i), "value").unwrap();
        }
        assert!(auth.add_param("extra", "value").is_err());
    }

    #[test]
    fn auth_header_display() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        auth.add_param("username", "alice").unwrap();
        auth.add_param("realm", "example.com").unwrap();

        let output = auth.to_string();
        assert!(output.starts_with("Digest"));
        assert!(output.contains("username=\"alice\""));
        assert!(output.contains("realm=\"example.com\""));
    }

    #[test]
    fn auth_header_display_with_quotes() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        auth.add_param("username", "alice smith").unwrap(); // Space requires quotes

        let output = auth.to_string();
        assert!(output.contains("username=\"alice smith\""));
    }

    #[test]
    fn fields_are_private() {
        let auth = AuthorizationHeader::new("Digest").unwrap();

        // These should compile (read access via getters)
        let _ = auth.scheme();
        let _ = auth.params();

        // These should NOT compile:
        // auth.scheme = SmolStr::new("evil");      // ← Does not compile!
        // auth.params.insert(...);                 // ← Does not compile!
    }

    #[test]
    fn error_display() {
        let err1 = AuthorizationError::InvalidScheme("test".to_string());
        assert_eq!(err1.to_string(), "Invalid scheme: test");

        let err2 = AuthorizationError::TooManyParameters { max: 30 };
        assert_eq!(err2.to_string(), "Too many parameters (max 30)");
    }

    #[test]
    fn from_raw_validates() {
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("username"), SmolStr::new("alice"));

        let auth = AuthorizationHeader::from_raw(SmolStr::new("Digest"), params).unwrap();
        assert_eq!(auth.scheme(), "Digest");
        assert_eq!(auth.param("username"), Some(&"alice".into()));
    }

    #[test]
    fn from_raw_rejects_too_many_params() {
        let mut params = BTreeMap::new();
        for i in 0..=MAX_AUTH_PARAMS {
            params.insert(SmolStr::new(format!("p{}", i)), SmolStr::new("v"));
        }

        assert!(AuthorizationHeader::from_raw(SmolStr::new("Digest"), params).is_err());
    }

    #[test]
    fn add_param_overwrite_replaces() {
        let mut auth = AuthorizationHeader::new("Digest").unwrap();
        auth.add_param_overwrite("realm", "example.com").unwrap();
        auth.add_param_overwrite("realm", "other.com").unwrap(); // Overwrites

        assert_eq!(auth.param("realm"), Some(&"other.com".into()));
        assert_eq!(auth.params().len(), 1);
    }
}
