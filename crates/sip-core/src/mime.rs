// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use smol_str::SmolStr;

const MAX_TYPE_LENGTH: usize = 64;
const MAX_SUBTYPE_LENGTH: usize = 64;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MimeTypeError {
    TypeTooLong { max: usize, actual: usize },
    SubtypeTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    InvalidType(String),
    InvalidSubtype(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    EmptyType,
    EmptySubtype,
    DuplicateParam(String),
}

impl std::fmt::Display for MimeTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeTooLong { max, actual } =>
                write!(f, "type too long (max {}, got {})", max, actual),
            Self::SubtypeTooLong { max, actual } =>
                write!(f, "subtype too long (max {}, got {})", max, actual),
            Self::ParamNameTooLong { max, actual } =>
                write!(f, "param name too long (max {}, got {})", max, actual),
            Self::ParamValueTooLong { max, actual } =>
                write!(f, "param value too long (max {}, got {})", max, actual),
            Self::TooManyParams { max, actual } =>
                write!(f, "too many params (max {}, got {})", max, actual),
            Self::InvalidType(msg) =>
                write!(f, "invalid type: {}", msg),
            Self::InvalidSubtype(msg) =>
                write!(f, "invalid subtype: {}", msg),
            Self::InvalidParamName(msg) =>
                write!(f, "invalid param name: {}", msg),
            Self::InvalidParamValue(msg) =>
                write!(f, "invalid param value: {}", msg),
            Self::EmptyType =>
                write!(f, "type cannot be empty"),
            Self::EmptySubtype =>
                write!(f, "subtype cannot be empty"),
            Self::DuplicateParam(name) =>
                write!(f, "duplicate parameter: {}", name),
        }
    }
}

impl std::error::Error for MimeTypeError {}

/// Represents a MIME type such as `application/sdp`.
///
/// Per RFC 2045, MIME types have the format:
/// `type/subtype[;param=value]...`
///
/// # Security
///
/// MimeType validates all components to prevent:
/// - CRLF injection in Content-Type headers
/// - Control character injection
/// - Excessive length (DoS)
/// - Unbounded parameter lists
///
/// # Examples
///
/// ```
/// use sip_core::MimeType;
///
/// // Create a simple MIME type
/// let mime = MimeType::new("application", "sdp").unwrap();
/// assert_eq!(mime.as_str(), "application/sdp");
///
/// // Create with parameters
/// let mime = MimeType::new("text", "plain")
///     .unwrap()
///     .with_param("charset", "utf-8")
///     .unwrap();
/// assert_eq!(mime.param("charset"), Some("utf-8"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeType {
    top_level: SmolStr,
    subtype: SmolStr,
    params: BTreeMap<SmolStr, SmolStr>,
}

impl MimeType {
    /// Creates a new MIME type with validation.
    ///
    /// # Security
    ///
    /// Validates both type and subtype to ensure:
    /// - Not empty
    /// - Within length limits
    /// - No control characters (including CRLF)
    /// - Only valid token characters per RFC 2045
    ///
    /// # Errors
    ///
    /// Returns an error if type or subtype is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::MimeType;
    ///
    /// let mime = MimeType::new("application", "sdp").unwrap();
    /// assert_eq!(mime.top_level(), "application");
    /// assert_eq!(mime.subtype(), "sdp");
    /// ```
    pub fn new(
        top_level: impl AsRef<str>,
        subtype: impl AsRef<str>,
    ) -> Result<Self, MimeTypeError> {
        let top_level = top_level.as_ref();
        let subtype = subtype.as_ref();

        validate_type(top_level)?;
        validate_subtype(subtype)?;

        Ok(Self {
            top_level: SmolStr::new(top_level.to_ascii_lowercase()),
            subtype: SmolStr::new(subtype.to_ascii_lowercase()),
            params: BTreeMap::new(),
        })
    }

    /// Adds a parameter with validation (builder pattern).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parameter name or value is invalid
    /// - Adding would exceed MAX_PARAMS
    /// - Parameter name already exists
    pub fn with_param(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, MimeTypeError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parameter name or value is invalid
    /// - Adding would exceed MAX_PARAMS
    /// - Parameter name already exists
    pub fn add_param(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), MimeTypeError> {
        let name = name.as_ref();

        validate_param_name(name)?;

        if self.params.len() >= MAX_PARAMS {
            return Err(MimeTypeError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(MimeTypeError::DuplicateParam(name.to_string()));
        }

        let value_key = normalize_param_value(value.as_ref())?;
        self.params.insert(name_key, value_key);
        Ok(())
    }

    /// Returns the top-level type (e.g., "application").
    pub fn top_level(&self) -> &str {
        &self.top_level
    }

    /// Returns the subtype (e.g., "sdp").
    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    /// Returns the MIME type as a string (without parameters).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::MimeType;
    ///
    /// let mime = MimeType::new("application", "sdp").unwrap();
    /// assert_eq!(mime.as_str(), "application/sdp");
    /// ```
    pub fn as_str(&self) -> String {
        format!("{}/{}", self.top_level, self.subtype)
    }

    /// Returns the full MIME type string including parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::MimeType;
    ///
    /// let mime = MimeType::new("text", "plain")
    ///     .unwrap()
    ///     .with_param("charset", "utf-8")
    ///     .unwrap();
    /// assert_eq!(mime.to_string(), "text/plain;charset=utf-8");
    /// ```
    pub fn to_string_with_params(&self) -> String {
        let mut result = self.as_str();
        for (name, value) in &self.params {
            result.push(';');
            result.push_str(name);
            result.push('=');
            if is_token(value.as_str()) {
                result.push_str(value);
            } else {
                result.push('"');
                for ch in value.chars() {
                    if ch == '\\' || ch == '"' {
                        result.push('\\');
                    }
                    result.push(ch);
                }
                result.push('"');
            }
        }
        result
    }

    /// Gets a parameter value by name (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::MimeType;
    ///
    /// let mime = MimeType::new("text", "plain")
    ///     .unwrap()
    ///     .with_param("charset", "utf-8")
    ///     .unwrap();
    ///
    /// assert_eq!(mime.param("charset"), Some("utf-8"));
    /// assert_eq!(mime.param("CHARSET"), Some("utf-8")); // case-insensitive
    /// assert_eq!(mime.param("unknown"), None);
    /// ```
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .get(&SmolStr::new(name.to_ascii_lowercase()))
            .map(|s| s.as_str())
    }

    /// Returns an iterator over all parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns the number of parameters.
    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Returns true if there are no parameters.
    pub fn has_params(&self) -> bool {
        !self.params.is_empty()
    }
}

impl std::fmt::Display for MimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_params())
    }
}

impl std::str::FromStr for MimeType {
    type Err = MimeTypeError;

    /// Parses a MIME type from a string.
    ///
    /// Format: `type/subtype[;param=value]...`
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::MimeType;
    /// use std::str::FromStr;
    ///
    /// let mime = MimeType::from_str("text/plain;charset=utf-8").unwrap();
    /// assert_eq!(mime.top_level(), "text");
    /// assert_eq!(mime.subtype(), "plain");
    /// assert_eq!(mime.param("charset"), Some("utf-8"));
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_mime_type(s)
    }
}

// Validation functions

fn validate_type(type_str: &str) -> Result<(), MimeTypeError> {
    if type_str.is_empty() {
        return Err(MimeTypeError::EmptyType);
    }

    if type_str.len() > MAX_TYPE_LENGTH {
        return Err(MimeTypeError::TypeTooLong {
            max: MAX_TYPE_LENGTH,
            actual: type_str.len(),
        });
    }

    if type_str.chars().any(|c| c.is_ascii_control()) {
        return Err(MimeTypeError::InvalidType(
            "contains control characters".to_string(),
        ));
    }

    // Type must be a valid token per RFC 2045
    if !type_str.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    }) {
        return Err(MimeTypeError::InvalidType(
            "contains invalid characters for MIME type".to_string(),
        ));
    }

    Ok(())
}

fn validate_subtype(subtype: &str) -> Result<(), MimeTypeError> {
    if subtype.is_empty() {
        return Err(MimeTypeError::EmptySubtype);
    }

    if subtype.len() > MAX_SUBTYPE_LENGTH {
        return Err(MimeTypeError::SubtypeTooLong {
            max: MAX_SUBTYPE_LENGTH,
            actual: subtype.len(),
        });
    }

    if subtype.chars().any(|c| c.is_ascii_control()) {
        return Err(MimeTypeError::InvalidSubtype(
            "contains control characters".to_string(),
        ));
    }

    // Subtype must be a valid token per RFC 2045
    if !subtype.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    }) {
        return Err(MimeTypeError::InvalidSubtype(
            "contains invalid characters for MIME subtype".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), MimeTypeError> {
    if name.is_empty() {
        return Err(MimeTypeError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(MimeTypeError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(MimeTypeError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    // Parameter names must be valid tokens
    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    }) {
        return Err(MimeTypeError::InvalidParamName(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}


fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
        })
}

fn normalize_param_value(value: &str) -> Result<SmolStr, MimeTypeError> {
    if value.is_empty() {
        return Err(MimeTypeError::InvalidParamValue("empty value".to_string()));
    }

    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(MimeTypeError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(MimeTypeError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        let mut unescaped = String::with_capacity(value.len().saturating_sub(2));
        let mut chars = value[1..value.len() - 1].chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let Some(escaped) = chars.next() else {
                    return Err(MimeTypeError::InvalidParamValue(
                        "dangling escape".to_string(),
                    ));
                };
                if escaped.is_ascii_control() {
                    return Err(MimeTypeError::InvalidParamValue(
                        "contains control characters".to_string(),
                    ));
                }
                unescaped.push(escaped);
                continue;
            }
            if ch == '"' {
                return Err(MimeTypeError::InvalidParamValue(
                    "contains unescaped quote".to_string(),
                ));
            }
            unescaped.push(ch);
        }
        return Ok(SmolStr::new(unescaped));
    }

    if is_token(value) {
        return Ok(SmolStr::new(value));
    }

    Err(MimeTypeError::InvalidParamValue(
        "contains invalid characters".to_string(),
    ))
}

/// Parses a MIME type from a string.
///
/// Format: `type/subtype[;param=value]...`
fn parse_mime_type(s: &str) -> Result<MimeType, MimeTypeError> {
    // Split on semicolon to separate type from parameters
    let parts: Vec<&str> = s.split(';').collect();
    
    if parts.is_empty() {
        return Err(MimeTypeError::InvalidType("empty string".to_string()));
    }

    // Parse type/subtype
    let type_parts: Vec<&str> = parts[0].trim().split('/').collect();
    if type_parts.len() != 2 {
        return Err(MimeTypeError::InvalidType(
            "must be in format type/subtype".to_string(),
        ));
    }

    let mut mime = MimeType::new(type_parts[0].trim(), type_parts[1].trim())?;

    // Parse parameters
    for param_str in &parts[1..] {
        let param_str = param_str.trim();
        if param_str.is_empty() {
            continue;
        }

        let param_parts: Vec<&str> = param_str.splitn(2, '=').collect();
        if param_parts.len() != 2 {
            return Err(MimeTypeError::InvalidParamName(
                "parameter must be name=value".to_string(),
            ));
        }

        mime.add_param(param_parts[0].trim(), param_parts[1].trim())?;
    }

    Ok(mime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mime_type() {
        let mime = MimeType::new("application", "sdp").unwrap();
        assert_eq!(mime.top_level(), "application");
        assert_eq!(mime.subtype(), "sdp");
        assert_eq!(mime.as_str(), "application/sdp");
    }

    #[test]
    fn mime_type_case_normalized() {
        let mime = MimeType::new("APPLICATION", "SDP").unwrap();
        assert_eq!(mime.top_level(), "application");
        assert_eq!(mime.subtype(), "sdp");
    }

    #[test]
    fn mime_with_params() {
        let mime = MimeType::new("text", "plain")
            .unwrap()
            .with_param("charset", "utf-8")
            .unwrap()
            .with_param("boundary", "----boundary")
            .unwrap();

        assert_eq!(mime.param("charset"), Some("utf-8"));
        assert_eq!(mime.param("boundary"), Some("----boundary"));
        assert_eq!(mime.param_count(), 2);
    }

    #[test]
    fn params_case_insensitive() {
        let mime = MimeType::new("text", "plain")
            .unwrap()
            .with_param("Charset", "utf-8")
            .unwrap();

        assert_eq!(mime.param("charset"), Some("utf-8"));
        assert_eq!(mime.param("CHARSET"), Some("utf-8"));
        assert_eq!(mime.param("Charset"), Some("utf-8"));
    }

    #[test]
    fn reject_empty_type() {
        let result = MimeType::new("", "sdp");
        assert!(matches!(result, Err(MimeTypeError::EmptyType)));
    }

    #[test]
    fn reject_empty_subtype() {
        let result = MimeType::new("application", "");
        assert!(matches!(result, Err(MimeTypeError::EmptySubtype)));
    }

    #[test]
    fn reject_crlf_in_type() {
        let result = MimeType::new("application\r\ninjected", "sdp");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_subtype() {
        let result = MimeType::new("application", "sdp\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_param_name() {
        let result = MimeType::new("text", "plain")
            .unwrap()
            .with_param("charset\r\ninjected", "utf-8");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_param_value() {
        let result = MimeType::new("text", "plain")
            .unwrap()
            .with_param("charset", "utf-8\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_type() {
        let long_type = "x".repeat(MAX_TYPE_LENGTH + 1);
        let result = MimeType::new(&long_type, "sdp");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_subtype() {
        let long_subtype = "x".repeat(MAX_SUBTYPE_LENGTH + 1);
        let result = MimeType::new("application", &long_subtype);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_params() {
        let mut mime = MimeType::new("text", "plain").unwrap();
        
        for i in 0..MAX_PARAMS {
            mime.add_param(&format!("p{}", i), "value").unwrap();
        }
        
        // Should fail
        let result = mime.add_param("overflow", "value");
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_params() {
        let result = MimeType::new("text", "plain")
            .unwrap()
            .with_param("charset", "utf-8")
            .unwrap()
            .with_param("charset", "iso-8859-1");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_characters() {
        // Slash in type (other than separator)
        let result = MimeType::new("app/lication", "sdp");
        assert!(result.is_err());
        
        // Space in type
        let result = MimeType::new("app lication", "sdp");
        assert!(result.is_err());
    }

    #[test]
    fn to_string_with_params() {
        let mime = MimeType::new("text", "plain")
            .unwrap()
            .with_param("charset", "utf-8")
            .unwrap();
        
        assert_eq!(mime.to_string_with_params(), "text/plain;charset=utf-8");
    }

    #[test]
    fn display_trait() {
        let mime = MimeType::new("application", "sdp").unwrap();
        assert_eq!(mime.to_string(), "application/sdp");
    }

    #[test]
    fn parse_simple() {
        use std::str::FromStr;
        
        let mime = MimeType::from_str("application/sdp").unwrap();
        assert_eq!(mime.top_level(), "application");
        assert_eq!(mime.subtype(), "sdp");
    }

    #[test]
    fn parse_with_params() {
        use std::str::FromStr;
        
        let mime = MimeType::from_str("text/plain;charset=utf-8").unwrap();
        assert_eq!(mime.top_level(), "text");
        assert_eq!(mime.subtype(), "plain");
        assert_eq!(mime.param("charset"), Some("utf-8"));
    }

    #[test]
    fn parse_multiple_params() {
        use std::str::FromStr;
        
        let mime = MimeType::from_str("text/plain;charset=utf-8;boundary=----bound").unwrap();
        assert_eq!(mime.param("charset"), Some("utf-8"));
        assert_eq!(mime.param("boundary"), Some("----bound"));
    }

    #[test]
    fn round_trip() {
        let original = MimeType::new("text", "plain")
            .unwrap()
            .with_param("charset", "utf-8")
            .unwrap();
        
        let serialized = original.to_string_with_params();
        let parsed = parse_mime_type(&serialized).unwrap();
        
        assert_eq!(original, parsed);
    }

    #[test]
    fn common_mime_types() {
        assert!(MimeType::new("application", "sdp").is_ok());
        assert!(MimeType::new("text", "plain").is_ok());
        assert!(MimeType::new("multipart", "mixed").is_ok());
        assert!(MimeType::new("message", "sipfrag").is_ok());
        assert!(MimeType::new("application", "json").is_ok());
    }

    #[test]
    fn fields_are_private() {
        let mime = MimeType::new("application", "sdp").unwrap();
        
        // These should compile (read-only access)
        let _ = mime.top_level();
        let _ = mime.subtype();
        let _ = mime.param("test");
        
        // These should NOT compile (no direct field access):
        // mime.top_level = SmolStr::new("evil");  // ← Does not compile!
        // mime.subtype = SmolStr::new("evil");    // ← Does not compile!
        // mime.params.clear();                     // ← Does not compile!
    }
}
