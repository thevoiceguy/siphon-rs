// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Tel URI support per RFC 3966 with security hardening.
//!
//! A tel URI represents a telephone number, which can be either:
//! - Global: Uses E.164 format, starts with '+' (e.g., tel:+1-555-123-4567)
//! - Local: Requires phone-context parameter (e.g., tel:555-1234;phone-context=example.com)
//!
//! # Security
//!
//! Tel URIs are validated for:
//! - Maximum length limits on all components
//! - Valid character sets for telephone numbers
//! - Bounded parameter collections
//! - No control characters (prevents CRLF injection)

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

// Security: Input size limits
const MAX_TELEPHONE_NUMBER_LENGTH: usize = 64;  // E.164 allows max ~15 digits, generous buffer
const MAX_PHONE_CONTEXT_LENGTH: usize = 256;
const MAX_PARAMETER_NAME_LENGTH: usize = 32;
const MAX_PARAMETER_VALUE_LENGTH: usize = 128;
const MAX_PARAMETERS: usize = 20;

/// Error types for Tel URI operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelUriError {
    /// Invalid format
    InvalidFormat(String),
    /// Invalid scheme (not "tel:")
    InvalidScheme,
    /// Number validation error
    InvalidNumber(String),
    /// Phone context validation error
    InvalidPhoneContext(String),
    /// Parameter validation error
    InvalidParameter(String),
    /// Too many parameters
    TooManyParameters { max: usize },
    /// Input too long
    TooLong { field: &'static str, max: usize },
}

impl fmt::Display for TelUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelUriError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            TelUriError::InvalidScheme => write!(f, "Invalid scheme (must be 'tel:')"),
            TelUriError::InvalidNumber(msg) => write!(f, "Invalid telephone number: {}", msg),
            TelUriError::InvalidPhoneContext(msg) => write!(f, "Invalid phone-context: {}", msg),
            TelUriError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            TelUriError::TooManyParameters { max } => {
                write!(f, "Too many parameters (max {})", max)
            }
            TelUriError::TooLong { field, max } => {
                write!(f, "{} too long (max {})", field, max)
            }
        }
    }
}

impl std::error::Error for TelUriError {}

/// Validates a telephone number.
fn validate_telephone_number(number: &str) -> Result<(), TelUriError> {
    if number.is_empty() {
        return Err(TelUriError::InvalidNumber("number cannot be empty".to_string()));
    }

    if number.len() > MAX_TELEPHONE_NUMBER_LENGTH {
        return Err(TelUriError::TooLong {
            field: "telephone number",
            max: MAX_TELEPHONE_NUMBER_LENGTH,
        });
    }

    // RFC 3966: telephone-subscriber = global-number / local-number
    // global-number starts with '+', followed by digits
    // local-number is more flexible but must be valid
    
    // Check for control characters
    if number.chars().any(|c| c.is_control()) {
        return Err(TelUriError::InvalidNumber(
            "contains control characters".to_string(),
        ));
    }

    // For global numbers (E.164), validate format
    if number.starts_with('+') {
        // After '+', should only have digits and optional visual separators
        let has_invalid_chars = number.chars().skip(1).any(|c| {
            !c.is_ascii_digit() && !matches!(c, '-' | '.' | ' ' | '(' | ')')
        });

        if has_invalid_chars {
            return Err(TelUriError::InvalidNumber(
                "global number contains invalid characters".to_string(),
            ));
        }

        // Must have at least one digit after '+'
        if !number.chars().skip(1).any(|c| c.is_ascii_digit()) {
            return Err(TelUriError::InvalidNumber(
                "global number must contain digits".to_string(),
            ));
        }
    } else {
        // Local numbers allow phonedigit and visual separators (RFC 3966 §5.1.2)
        let has_invalid_chars = number.chars().any(|c| {
            !(c.is_ascii_digit()
                || matches!(c, '-' | '.' | ' ' | '(' | ')')
                || matches!(c, '*' | '#' | 'A' | 'B' | 'C' | 'D' | 'a' | 'b' | 'c' | 'd'))
        });

        if has_invalid_chars {
            return Err(TelUriError::InvalidNumber(
                "local number contains invalid characters".to_string(),
            ));
        }

        if !number.chars().any(|c| c.is_ascii_digit()) {
            return Err(TelUriError::InvalidNumber(
                "local number must contain digits".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validates a phone-context value.
fn validate_phone_context(context: &str) -> Result<(), TelUriError> {
    if context.is_empty() {
        return Err(TelUriError::InvalidPhoneContext(
            "phone-context cannot be empty".to_string(),
        ));
    }

    if context.len() > MAX_PHONE_CONTEXT_LENGTH {
        return Err(TelUriError::TooLong {
            field: "phone-context",
            max: MAX_PHONE_CONTEXT_LENGTH,
        });
    }

    // Check for control characters
    if context.chars().any(|c| c.is_control()) {
        return Err(TelUriError::InvalidPhoneContext(
            "contains control characters".to_string(),
        ));
    }

    // RFC 3966: phone-context can be a domain name or global number
    // Basic validation: no semicolons (parameter separator)
    if context.contains(';') {
        return Err(TelUriError::InvalidPhoneContext(
            "contains semicolon".to_string(),
        ));
    }

    Ok(())
}

/// Validates a parameter name.
fn validate_parameter_name(name: &str) -> Result<(), TelUriError> {
    if name.is_empty() {
        return Err(TelUriError::InvalidParameter(
            "parameter name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_PARAMETER_NAME_LENGTH {
        return Err(TelUriError::TooLong {
            field: "parameter name",
            max: MAX_PARAMETER_NAME_LENGTH,
        });
    }

    // Check for control characters, whitespace, and special chars
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, ';' | '='))
    {
        return Err(TelUriError::InvalidParameter(
            "parameter name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a parameter value.
fn validate_parameter_value(value: &str) -> Result<(), TelUriError> {
    if value.len() > MAX_PARAMETER_VALUE_LENGTH {
        return Err(TelUriError::TooLong {
            field: "parameter value",
            max: MAX_PARAMETER_VALUE_LENGTH,
        });
    }

    // Check for control characters and whitespace
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(TelUriError::InvalidParameter(
            "parameter value contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Parsed representation of a tel URI (RFC 3966).
///
/// # Security
///
/// TelUri validates all components and enforces bounds to prevent DoS attacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TelUri {
    /// Raw tel URI string (for serialization)
    raw: SmolStr,
    /// The telephone number (normalized for global numbers)
    number: SmolStr,
    /// True if this is a global number (E.164 format starting with '+')
    is_global: bool,
    /// Phone context for local numbers (required for local, invalid for global)
    phone_context: Option<SmolStr>,
    /// URI parameters (e.g., isub, ext, phone-context)
    parameters: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl TelUri {
    /// Creates a new TelUri from components with validation.
    ///
    /// # Errors
    ///
    /// Returns `TelUriError` if:
    /// - Number is invalid or too long
    /// - Number format doesn't match is_global
    pub fn new(number: impl Into<SmolStr>, is_global: bool) -> Result<Self, TelUriError> {
        let number = number.into();
        validate_telephone_number(&number)?;

        // Validate consistency
        if is_global && !number.starts_with('+') {
            return Err(TelUriError::InvalidNumber(
                "global number must start with '+'".to_string(),
            ));
        }

        if !is_global && number.starts_with('+') {
            return Err(TelUriError::InvalidNumber(
                "local number cannot start with '+'".to_string(),
            ));
        }

        let raw = SmolStr::new(format!("tel:{}", number));

        Ok(Self {
            raw,
            number,
            is_global,
            phone_context: None,
            parameters: BTreeMap::new(),
        })
    }

    /// Attempts to parse a tel URI from the provided string.
    ///
    /// # Examples
    /// ```
    /// use sip_core::TelUri;
    ///
    /// // Global number (E.164)
    /// let uri = TelUri::parse("tel:+1-555-123-4567").unwrap();
    /// assert!(uri.is_global());
    /// assert_eq!(uri.number(), "+15551234567");
    ///
    /// // Local number with phone-context
    /// let uri = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
    /// assert!(!uri.is_global());
    /// assert_eq!(uri.phone_context().unwrap(), "example.com");
    /// ```
    pub fn parse(input: &str) -> Result<Self, TelUriError> {
        let raw = SmolStr::new(input);

        // Must start with "tel:"
        let rest = input
            .strip_prefix("tel:")
            .ok_or(TelUriError::InvalidScheme)?;

        // Split into number and parameters
        let mut parts = rest.split(';');
        let number_part = parts
            .next()
            .ok_or_else(|| TelUriError::InvalidFormat("missing number".to_string()))?
            .trim();

        if number_part.is_empty() {
            return Err(TelUriError::InvalidFormat("empty number".to_string()));
        }

        validate_telephone_number(number_part)?;

        // Determine if global (starts with '+') or local
        let is_global = number_part.starts_with('+');

        // For global numbers, remove visual separators (-, ., space, parentheses)
        // RFC 3966 §5.1.1: Visual separators are for human readability only
        let normalized_number = if is_global {
            normalize_global_number(number_part)
        } else {
            SmolStr::new(number_part)
        };

        // Parse parameters
        let mut parameters = BTreeMap::new();
        let mut phone_context = None;

        for param in parts {
            if parameters.len() >= MAX_PARAMETERS {
                return Err(TelUriError::TooManyParameters {
                    max: MAX_PARAMETERS,
                });
            }

            if param.is_empty() {
                continue;
            }
            if param.chars().any(|c| c.is_whitespace()) {
                return Err(TelUriError::InvalidParameter(
                    "parameter contains whitespace".to_string(),
                ));
            }

            if let Some((key, value)) = param.split_once('=') {
                validate_parameter_name(key)?;
                validate_parameter_value(value)?;

                let key_smol = SmolStr::new(key);
                let value_smol = SmolStr::new(value);

                // Special handling for phone-context
                if key.eq_ignore_ascii_case("phone-context") {
                    validate_phone_context(value)?;
                    phone_context = Some(value_smol.clone());
                }

                parameters.insert(key_smol, Some(value_smol));
        } else {
            validate_parameter_name(param)?;
            parameters.insert(SmolStr::new(param), None);
        }
    }

        // Validate: local numbers MUST have phone-context
        if !is_global && phone_context.is_none() {
            // RFC 3966 §5.1.4: Local numbers require phone-context
            return Err(TelUriError::InvalidFormat(
                "local number requires phone-context parameter".to_string(),
            ));
        }

        // Validate: global numbers MUST NOT have phone-context
        if is_global && phone_context.is_some() {
            // RFC 3966 §5.1.4: Global numbers cannot have phone-context
            return Err(TelUriError::InvalidFormat(
                "global number cannot have phone-context parameter".to_string(),
            ));
        }

        Ok(Self {
            raw,
            number: normalized_number,
            is_global,
            phone_context,
            parameters,
        })
    }

    /// Returns the tel URI as a string.
    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    /// Returns the telephone number.
    pub fn number(&self) -> &str {
        self.number.as_str()
    }

    /// Returns true if this is a global number.
    pub fn is_global(&self) -> bool {
        self.is_global
    }

    /// Returns the phone-context if present.
    pub fn phone_context(&self) -> Option<&str> {
        self.phone_context.as_deref()
    }

    /// Returns the parameters.
    pub fn parameters(&self) -> &BTreeMap<SmolStr, Option<SmolStr>> {
        &self.parameters
    }

    /// Adds a parameter to the tel URI with validation.
    pub fn with_parameter(
        mut self,
        key: impl Into<SmolStr>,
        value: Option<impl Into<SmolStr>>,
    ) -> Result<Self, TelUriError> {
        let key = key.into();
        let key_str = key.as_str();
        let exists = self.parameters.contains_key(&key);
        if !exists && self.parameters.len() >= MAX_PARAMETERS {
            return Err(TelUriError::TooManyParameters {
                max: MAX_PARAMETERS,
            });
        }

        validate_parameter_name(key_str)?;

        let value = match value {
            Some(v) => {
                let v = v.into();
                validate_parameter_value(&v)?;
                Some(v)
            }
            None => None,
        };

        if key_str.eq_ignore_ascii_case("phone-context") {
            let value = value.ok_or_else(|| {
                TelUriError::InvalidPhoneContext("phone-context requires a value".to_string())
            })?;
            if self.is_global {
                return Err(TelUriError::InvalidPhoneContext(
                    "global numbers cannot have phone-context".to_string(),
                ));
            }
            validate_phone_context(&value)?;
            self.phone_context = Some(value.clone());
            self.parameters.insert(key, Some(value));
        } else {
            self.parameters.insert(key, value);
        }

        self.raw = build_raw_uri(&self.number, &self.parameters);
        Ok(self)
    }

    /// Sets the phone-context for local numbers with validation.
    pub fn with_phone_context(mut self, context: impl Into<SmolStr>) -> Result<Self, TelUriError> {
        if self.is_global {
            return Err(TelUriError::InvalidPhoneContext(
                "global numbers cannot have phone-context".to_string(),
            ));
        }

        let context = context.into();
        validate_phone_context(&context)?;

        self.phone_context = Some(context.clone());
        self.parameters
            .insert(SmolStr::new("phone-context"), Some(context));
        self.raw = build_raw_uri(&self.number, &self.parameters);
        Ok(self)
    }
}

impl fmt::Display for TelUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Normalizes a global telephone number by removing visual separators.
/// RFC 3966 §5.1.1: Visual separators (-, ., space, parentheses) are for readability.
fn normalize_global_number(number: &str) -> SmolStr {
    let normalized: String = number
        .chars()
        .filter(|c| !matches!(c, '-' | '.' | ' ' | '(' | ')'))
        .collect();
    SmolStr::new(normalized)
}

fn build_raw_uri(
    number: &SmolStr,
    parameters: &BTreeMap<SmolStr, Option<SmolStr>>,
) -> SmolStr {
    let mut out = format!("tel:{}", number);
    for (key, value) in parameters {
        out.push(';');
        out.push_str(key.as_str());
        if let Some(val) = value {
            out.push('=');
            out.push_str(val.as_str());
        }
    }
    SmolStr::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_tel_uri() {
        let uri = TelUri::parse("tel:+1-555-123-4567").unwrap();
        assert!(uri.is_global());
        assert_eq!(uri.number(), "+15551234567");
        assert!(uri.phone_context().is_none());
    }

    #[test]
    fn parses_global_with_visual_separators() {
        let uri = TelUri::parse("tel:+1(555)123.4567").unwrap();
        assert!(uri.is_global());
        assert_eq!(uri.number(), "+15551234567");
    }

    #[test]
    fn parses_local_with_phone_context() {
        let uri = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
        assert!(!uri.is_global());
        assert_eq!(uri.number(), "5551234");
        assert_eq!(uri.phone_context().unwrap(), "example.com");
    }

    #[test]
    fn rejects_local_without_phone_context() {
        let result = TelUri::parse("tel:5551234");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_global_with_phone_context() {
        let result = TelUri::parse("tel:+15551234;phone-context=example.com");
        assert!(result.is_err());
    }

    #[test]
    fn parses_with_extension() {
        let uri = TelUri::parse("tel:+1-555-123-4567;ext=1234").unwrap();
        assert!(uri.is_global());
        assert_eq!(
            uri.parameters()
                .get("ext")
                .unwrap()
                .as_ref()
                .unwrap()
                .as_str(),
            "1234"
        );
    }

    #[test]
    fn rejects_non_tel_scheme() {
        assert!(TelUri::parse("sip:user@example.com").is_err());
    }

    #[test]
    fn creates_tel_uri_programmatically() {
        let uri = TelUri::new("+15551234567", true).unwrap();
        assert!(uri.is_global());
        assert_eq!(uri.as_str(), "tel:+15551234567");
    }

    #[test]
    fn rejects_too_long_number() {
        let long_number = format!("+{}", "1".repeat(MAX_TELEPHONE_NUMBER_LENGTH));
        assert!(TelUri::new(&long_number, true).is_err());
    }

    #[test]
    fn rejects_empty_number() {
        assert!(TelUri::parse("tel:").is_err());
    }

    #[test]
    fn rejects_control_chars_in_number() {
        assert!(TelUri::parse("tel:+1555\r\n1234").is_err());
        assert!(TelUri::parse("tel:+1555\x001234").is_err());
    }

    #[test]
    fn rejects_too_many_parameters() {
        let mut uri_str = "tel:+15551234".to_string();
        for i in 0..=MAX_PARAMETERS {
            uri_str.push_str(&format!(";p{}=v", i));
        }
        assert!(TelUri::parse(&uri_str).is_err());
    }

    #[test]
    fn rejects_too_long_phone_context() {
        let long_context = "x".repeat(MAX_PHONE_CONTEXT_LENGTH + 1);
        let uri_str = format!("tel:5551234;phone-context={}", long_context);
        assert!(TelUri::parse(&uri_str).is_err());
    }

    #[test]
    fn rejects_control_chars_in_phone_context() {
        assert!(TelUri::parse("tel:5551234;phone-context=test\r\n.com").is_err());
    }

    #[test]
    fn rejects_invalid_parameter_name() {
        assert!(TelUri::parse("tel:+15551234;param with spaces=value").is_err());
        assert!(TelUri::parse("tel:+15551234;param\r\n=value").is_err());
    }

    #[test]
    fn rejects_invalid_parameter_value() {
        assert!(TelUri::parse("tel:+15551234;param=val\r\nue").is_err());
    }

    #[test]
    fn new_validates_number_format() {
        // Global number must start with '+'
        assert!(TelUri::new("15551234", true).is_err());
        
        // Local number cannot start with '+'
        assert!(TelUri::new("+15551234", false).is_err());
    }

    #[test]
    fn with_parameter_validates() {
        let uri = TelUri::new("+15551234", true).unwrap();
        
        // Valid parameter
        let uri = uri.with_parameter("ext", Some("1234")).unwrap();
        assert!(uri.parameters().contains_key("ext"));
        
        // Too many parameters
        let mut uri = TelUri::new("+15551234", true).unwrap();
        for i in 0..MAX_PARAMETERS {
            uri = uri.with_parameter(format!("p{}", i), Some("v")).unwrap();
        }
        assert!(uri.with_parameter("extra", Some("value")).is_err());
    }

    #[test]
    fn with_phone_context_validates() {
        let uri = TelUri::new("5551234", false).unwrap();
        
        // Valid phone-context
        let uri = uri.with_phone_context("example.com").unwrap();
        assert_eq!(uri.phone_context().unwrap(), "example.com");
        
        // Global number cannot have phone-context
        let global = TelUri::new("+15551234", true).unwrap();
        assert!(global.with_phone_context("example.com").is_err());
    }

    #[test]
    fn fields_are_private() {
        let uri = TelUri::new("+15551234", true).unwrap();
        
        // These should compile (read access via getters)
        let _ = uri.number();
        let _ = uri.is_global();
        let _ = uri.phone_context();
        let _ = uri.parameters();
        
        // These should NOT compile:
        // uri.number = SmolStr::new("evil");           // ← Does not compile!
        // uri.is_global = false;                       // ← Does not compile!
        // uri.parameters.insert(...);                  // ← Does not compile!
    }

    #[test]
    fn accepts_valid_global_numbers() {
        assert!(TelUri::parse("tel:+1").is_ok());
        assert!(TelUri::parse("tel:+12345").is_ok());
        assert!(TelUri::parse("tel:+1-555-123-4567").is_ok());
        assert!(TelUri::parse("tel:+44.20.1234.5678").is_ok());
    }

    #[test]
    fn rejects_invalid_global_numbers() {
        // No digits after '+'
        assert!(TelUri::parse("tel:+").is_err());
        
        // Invalid characters
        assert!(TelUri::parse("tel:+abc").is_err());
        assert!(TelUri::parse("tel:+1555#1234").is_err());
    }

    #[test]
    fn error_display() {
        let err1 = TelUriError::InvalidScheme;
        assert_eq!(err1.to_string(), "Invalid scheme (must be 'tel:')");
        
        let err2 = TelUriError::TooManyParameters { max: 20 };
        assert_eq!(err2.to_string(), "Too many parameters (max 20)");
    }
}
