// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Common Profile for Instant Messaging (CPIM) message format.
//!
//! This module implements RFC 3860 (Common Profile for Instant Messaging) and
//! RFC 3862 (Common Profile for Instant Messaging (CPIM) Message Format).
//!
//! CPIM provides a standard message format for instant messaging that can be used
//! across different IM protocols, enabling interoperability through gateways.
//!
//! # Message Structure
//!
//! A CPIM message consists of three parts:
//! 1. MIME headers (Content-type: Message/CPIM)
//! 2. Message headers (From, To, DateTime, Subject, etc.)
//! 3. Message content (MIME-encapsulated body)
//!
//! # Security Guarantees
//!
//! This implementation provides comprehensive security hardening:
//!
//! ## DoS Protection
//! - **Body size limit**: 10 MB maximum message body
//! - **Parse size limit**: 20 MB maximum input size
//! - **Header count limits**: Maximum 50 message headers, 20 content headers
//! - **Parameter limits**: Maximum 10 parameters per header
//! - **Length limits**: Header names (128), values (1024), params (64/256)
//!
//! ## Input Validation
//! - **Control character blocking**: Headers and values reject ASCII control chars
//! - **CRLF injection prevention**: Content headers block `\r` and `\n`
//! - **Invalid character detection**: Headers reject `:`, `;`, `=`, `\`, `"` in names
//! - **Parameter validation**: Param names/values validated separately
//! - **Content-Type validation**: Enforces non-empty, length-limited MIME types
//!
//! ## Error Handling
//! All operations return `Result<T, CpimError>` with detailed error information:
//! - Size limit violations include actual and maximum values
//! - Validation errors describe which rule was violated
//! - Parse errors provide context about what failed
//!
//! # Performance
//!
//! For trusted internal use where validation overhead is not needed, unchecked
//! variants are available:
//! - [`CpimMessage::new_unchecked`]
//! - [`CpimMessage::set_header_unchecked`]
//! - [`CpimHeader::new_unchecked`]
//!
//! Use these only when inputs are known to be valid (e.g., from trusted databases).
//!
//! # Examples
//!
//! ## Creating a CPIM message
//!
//! ```
//! use sip_core::cpim::CpimMessage;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let msg = CpimMessage::new("text/plain", b"Hello, World!".to_vec())?
//!     .with_from("Alice <im:alice@example.com>")?
//!     .with_to("Bob <im:bob@example.com>")?
//!     .with_datetime("2023-01-15T10:30:00Z")?
//!     .with_subject("Greeting")?;
//!
//! assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
//! # Ok(())
//! # }
//! ```
//!
//! ## Error handling
//!
//! ```
//! use sip_core::cpim::{CpimMessage, CpimError};
//!
//! # fn example() -> Result<(), CpimError> {
//! // Handle validation errors
//! let result = CpimMessage::new("", vec![]);
//! match result {
//!     Err(CpimError::InvalidContentType(msg)) => {
//!         println!("Invalid content type: {}", msg);
//!     }
//!     Err(e) => println!("Other error: {}", e),
//!     Ok(_) => {}
//! }
//!
//! // Handle size limit errors
//! let huge_body = vec![0u8; 20 * 1024 * 1024]; // 20 MB
//! let result = CpimMessage::new("text/plain", huge_body);
//! match result {
//!     Err(CpimError::BodyTooLarge { max, actual }) => {
//!         println!("Body too large: {} bytes (max {})", actual, max);
//!     }
//!     _ => {}
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Parsing CPIM messages
//!
//! ```
//! use sip_core::cpim::parse_cpim;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let input = "Content-type: Message/CPIM\r\n\r\n\
//!              From: Alice <im:alice@example.com>\r\n\
//!              To: Bob <im:bob@example.com>\r\n\
//!              DateTime: 2023-01-15T10:30:00Z\r\n\r\n\
//!              Content-type: text/plain\r\n\r\n\
//!              Hello, Bob!";
//!
//! let msg = parse_cpim(input)?;
//! assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
//! assert_eq!(msg.body_as_str()?, "Hello, Bob!");
//! # Ok(())
//! # }
//! ```
//!
//! ## Using language-tagged subjects (RFC 3862)
//!
//! ```
//! # use sip_core::cpim::CpimMessage;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let msg = CpimMessage::new("text/plain", b"Hello".to_vec())?
//!     .with_subject_lang("Hello", "en")?
//!     .with_subject_lang("Bonjour", "fr")?;
//!
//! // Retrieve all subject values
//! let subjects = msg.get_header_values("Subject");
//! assert_eq!(subjects, vec!["Hello", "Bonjour"]);
//!
//! // Access language parameters
//! let subject_headers = msg.headers().get("Subject").unwrap();
//! assert_eq!(subject_headers[0].params().get("lang").map(|s| s.as_str()), Some("en"));
//! # Ok(())
//! # }
//! ```
//!
//! ## RFC 3862 Format
//!
//! ```text
//! Content-type: Message/CPIM
//!
//! From: Alice <im:alice@example.com>
//! To: Bob <im:bob@example.com>
//! DateTime: 2023-01-15T10:30:00Z
//! Subject:;lang=en Hello
//!
//! Content-type: text/plain
//!
//! Hello, Bob!
//! ```
//!
//! Note the parameter format: `Header-name:;param=value Value` per RFC 3862 ABNF.

use std::collections::BTreeMap;
use std::fmt;

use smol_str::SmolStr;

const MAX_HEADER_NAME_LENGTH: usize = 128;
const MAX_HEADER_VALUE_LENGTH: usize = 1024;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_HEADERS: usize = 50;
const MAX_PARAMS_PER_HEADER: usize = 10;
const MAX_CONTENT_HEADERS: usize = 20;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const MAX_PARSE_SIZE: usize = 20 * 1024 * 1024; // 20 MB
const MAX_CONTENT_TYPE_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpimError {
    HeaderNameTooLong { max: usize, actual: usize },
    HeaderValueTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    ContentTypeTooLong { max: usize, actual: usize },
    TooManyHeaders { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    TooManyContentHeaders { max: usize, actual: usize },
    BodyTooLarge { max: usize, actual: usize },
    InputTooLarge { max: usize, actual: usize },
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    InvalidContentType(String),
    ParseError(String),
}

impl fmt::Display for CpimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderNameTooLong { max, actual } => {
                write!(f, "header name too long (max {}, got {})", max, actual)
            }
            Self::HeaderValueTooLong { max, actual } => {
                write!(f, "header value too long (max {}, got {})", max, actual)
            }
            Self::ParamNameTooLong { max, actual } => {
                write!(f, "param name too long (max {}, got {})", max, actual)
            }
            Self::ParamValueTooLong { max, actual } => {
                write!(f, "param value too long (max {}, got {})", max, actual)
            }
            Self::ContentTypeTooLong { max, actual } => {
                write!(f, "content type too long (max {}, got {})", max, actual)
            }
            Self::TooManyHeaders { max, actual } => {
                write!(f, "too many headers (max {}, got {})", max, actual)
            }
            Self::TooManyParams { max, actual } => {
                write!(f, "too many params (max {}, got {})", max, actual)
            }
            Self::TooManyContentHeaders { max, actual } => {
                write!(f, "too many content headers (max {}, got {})", max, actual)
            }
            Self::BodyTooLarge { max, actual } => {
                write!(f, "body too large (max {}, got {})", max, actual)
            }
            Self::InputTooLarge { max, actual } => {
                write!(f, "input too large (max {}, got {})", max, actual)
            }
            Self::InvalidHeaderName(name) => write!(f, "invalid header name: {}", name),
            Self::InvalidHeaderValue(value) => write!(f, "invalid header value: {}", value),
            Self::InvalidParamName(name) => write!(f, "invalid param name: {}", name),
            Self::InvalidParamValue(value) => write!(f, "invalid param value: {}", value),
            Self::InvalidContentType(value) => write!(f, "invalid content type: {}", value),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for CpimError {}

/// A CPIM message containing headers and content.
///
/// CPIM messages are used for instant messaging interoperability and include
/// end-to-end metadata (From, To, DateTime, Subject, etc.) along with the
/// message content.
#[derive(Debug, Clone, PartialEq)]
pub struct CpimMessage {
    /// Message headers (From, To, DateTime, Subject, NS, Require, etc.)
    headers: BTreeMap<SmolStr, Vec<CpimHeader>>,
    /// Content type of the message body
    content_type: SmolStr,
    /// Additional content headers (Content-ID, Content-Disposition, etc.)
    content_headers: BTreeMap<SmolStr, SmolStr>,
    /// The message body
    body: Vec<u8>,
}

/// A CPIM message header with optional parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct CpimHeader {
    /// Header value
    value: SmolStr,
    /// Header parameters (e.g., lang=en for Subject)
    params: BTreeMap<SmolStr, SmolStr>,
}

impl CpimMessage {
    /// Creates a new CPIM message with the given content type and body.
    pub fn new(content_type: &str, body: Vec<u8>) -> Result<Self, CpimError> {
        validate_content_type(content_type)?;
        if body.len() > MAX_BODY_SIZE {
            return Err(CpimError::BodyTooLarge {
                max: MAX_BODY_SIZE,
                actual: body.len(),
            });
        }

        Ok(Self {
            headers: BTreeMap::new(),
            content_type: SmolStr::new(content_type),
            content_headers: BTreeMap::new(),
            body,
        })
    }

    /// Creates a new CPIM message without validation (for trusted internal use).
    ///
    /// # Safety
    ///
    /// This bypasses all validation checks. Only use this when you are certain
    /// the inputs are valid (e.g., when deserializing from a trusted source).
    /// Invalid inputs may cause incorrect serialization or panics.
    pub fn new_unchecked(content_type: &str, body: Vec<u8>) -> Self {
        Self {
            headers: BTreeMap::new(),
            content_type: SmolStr::new(content_type),
            content_headers: BTreeMap::new(),
            body,
        }
    }

    /// Returns message headers.
    pub fn headers(&self) -> &BTreeMap<SmolStr, Vec<CpimHeader>> {
        &self.headers
    }

    /// Returns the message content type.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Returns content headers.
    pub fn content_headers(&self) -> &BTreeMap<SmolStr, SmolStr> {
        &self.content_headers
    }

    /// Returns the message body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Replaces the message body.
    pub fn set_body(&mut self, body: Vec<u8>) -> Result<(), CpimError> {
        if body.len() > MAX_BODY_SIZE {
            return Err(CpimError::BodyTooLarge {
                max: MAX_BODY_SIZE,
                actual: body.len(),
            });
        }
        self.body = body;
        Ok(())
    }

    /// Sets the From header.
    pub fn with_from(mut self, from: &str) -> Result<Self, CpimError> {
        self.set_header("From", from)?;
        Ok(self)
    }

    /// Sets the To header.
    pub fn with_to(mut self, to: &str) -> Result<Self, CpimError> {
        self.add_header("To", to)?;
        Ok(self)
    }

    /// Sets the DateTime header.
    pub fn with_datetime(mut self, datetime: &str) -> Result<Self, CpimError> {
        self.set_header("DateTime", datetime)?;
        Ok(self)
    }

    /// Sets the Subject header.
    pub fn with_subject(mut self, subject: &str) -> Result<Self, CpimError> {
        self.add_header("Subject", subject)?;
        Ok(self)
    }

    /// Sets the Subject header with a language tag.
    pub fn with_subject_lang(mut self, subject: &str, lang: &str) -> Result<Self, CpimError> {
        let header = CpimHeader::new(subject)?.with_param("lang", lang)?;
        self.add_header_obj("Subject", header)?;
        Ok(self)
    }

    /// Adds a cc (courtesy copy) recipient.
    pub fn with_cc(mut self, cc: &str) -> Result<Self, CpimError> {
        self.add_header("cc", cc)?;
        Ok(self)
    }

    /// Adds a namespace declaration.
    pub fn with_ns(mut self, prefix: &str, uri: &str) -> Result<Self, CpimError> {
        let value = format!("{} <{}>", prefix, uri);
        self.add_header("NS", &value)?;
        Ok(self)
    }

    /// Adds a Require header.
    pub fn with_require(mut self, feature: &str) -> Result<Self, CpimError> {
        self.add_header("Require", feature)?;
        Ok(self)
    }

    /// Adds a content header (e.g., Content-ID, Content-Disposition).
    pub fn with_content_header(mut self, name: &str, value: &str) -> Result<Self, CpimError> {
        self.add_content_header(name, value)?;
        Ok(self)
    }

    /// Adds a content header (e.g., Content-ID, Content-Disposition).
    pub fn add_content_header(&mut self, name: &str, value: &str) -> Result<(), CpimError> {
        validate_header_name(name)?;
        validate_content_header_value(value)?;
        if self.content_headers.len() >= MAX_CONTENT_HEADERS {
            return Err(CpimError::TooManyContentHeaders {
                max: MAX_CONTENT_HEADERS,
                actual: self.content_headers.len() + 1,
            });
        }
        self.content_headers
            .insert(SmolStr::new(name), SmolStr::new(value));
        Ok(())
    }

    /// Sets a header, replacing any existing values.
    pub fn set_header(&mut self, name: &str, value: &str) -> Result<(), CpimError> {
        validate_header_name(name)?;
        let total_headers: usize = self.headers.values().map(|values| values.len()).sum();
        let replacing = self
            .headers
            .get(name)
            .map(|values| values.len())
            .unwrap_or(0);
        if total_headers.saturating_sub(replacing) + 1 > MAX_HEADERS {
            return Err(CpimError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: total_headers.saturating_sub(replacing) + 1,
            });
        }
        let header = CpimHeader::new(value)?;
        self.headers.insert(SmolStr::new(name), vec![header]);
        Ok(())
    }

    /// Sets a header without validation (for trusted internal use).
    ///
    /// # Safety
    ///
    /// This bypasses all validation checks. Only use when inputs are known to be valid.
    pub fn set_header_unchecked(&mut self, name: &str, value: &str) {
        let header = CpimHeader::new_unchecked(value);
        self.headers.insert(SmolStr::new(name), vec![header]);
    }

    /// Adds a header value (allows multiple values for the same header).
    pub fn add_header(&mut self, name: &str, value: &str) -> Result<(), CpimError> {
        let header = CpimHeader::new(value)?;
        self.add_header_obj(name, header)
    }

    /// Adds a header object.
    pub fn add_header_obj(&mut self, name: &str, header: CpimHeader) -> Result<(), CpimError> {
        validate_header_name(name)?;
        let total_headers: usize = self.headers.values().map(|values| values.len()).sum();
        if total_headers >= MAX_HEADERS {
            return Err(CpimError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: total_headers + 1,
            });
        }
        self.headers
            .entry(SmolStr::new(name))
            .or_default()
            .push(header);
        Ok(())
    }

    /// Gets the first value of a header.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|values| values.first())
            .map(|h| h.value.as_str())
    }

    /// Gets all values of a header.
    pub fn get_header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .get(name)
            .map(|values| values.iter().map(|h| h.value.as_str()).collect())
            .unwrap_or_default()
    }

    /// Gets the message body as a UTF-8 string slice, if valid.
    ///
    /// This is the preferred method as it avoids cloning the body.
    pub fn body_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Gets the message body as a UTF-8 String, if valid.
    ///
    /// Note: This clones the body. Prefer `body_as_str()` when possible.
    pub fn body_as_string(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    /// Formats the CPIM message as a string.
    pub fn to_string(&self) -> Result<String, CpimError> {
        let mut result = String::new();

        // MIME header
        result.push_str("Content-type: Message/CPIM\r\n\r\n");

        // Message headers
        for (name, values) in &self.headers {
            validate_header_name(name)?;
            for header in values {
                result.push_str(name);
                result.push(':');

                // Add parameters if present
                if !header.params.is_empty() {
                    for (param_name, param_value) in &header.params {
                        validate_param_name(param_name)?;
                        validate_param_value(param_value)?;
                        result.push(';');
                        result.push_str(param_name);
                        result.push('=');
                        result.push_str(param_value);
                    }
                }

                result.push(' ');
                result.push_str(&escape_header_value(&header.value));
                result.push_str("\r\n");
            }
        }

        // Blank line separating headers from content
        result.push_str("\r\n");

        // Content headers
        validate_content_type(&self.content_type)?;
        result.push_str("Content-type: ");
        result.push_str(&self.content_type);
        result.push_str("\r\n");

        for (name, value) in &self.content_headers {
            validate_header_name(name)?;
            validate_content_header_value(value)?;
            result.push_str(name);
            result.push_str(": ");
            result.push_str(value);
            result.push_str("\r\n");
        }

        // Blank line before body
        result.push_str("\r\n");

        // Body
        let body_str = String::from_utf8_lossy(&self.body);
        result.push_str(&body_str);

        Ok(result)
    }
}

impl CpimHeader {
    /// Creates a new CPIM header with the given value.
    pub fn new(value: &str) -> Result<Self, CpimError> {
        validate_cpim_header_value(value)?;
        Ok(Self {
            value: SmolStr::new(value),
            params: BTreeMap::new(),
        })
    }

    /// Creates a new CPIM header without validation (for trusted internal use).
    ///
    /// # Safety
    ///
    /// This bypasses validation checks. Only use when the value is known to be valid.
    pub fn new_unchecked(value: &str) -> Self {
        Self {
            value: SmolStr::new(value),
            params: BTreeMap::new(),
        }
    }

    /// Adds a parameter to the header.
    pub fn with_param(mut self, name: &str, value: &str) -> Result<Self, CpimError> {
        validate_param_name(name)?;
        validate_param_value(value)?;
        if self.params.len() >= MAX_PARAMS_PER_HEADER {
            return Err(CpimError::TooManyParams {
                max: MAX_PARAMS_PER_HEADER,
                actual: self.params.len() + 1,
            });
        }
        self.params.insert(SmolStr::new(name), SmolStr::new(value));
        Ok(self)
    }

    /// Returns the header value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the header parameters.
    pub fn params(&self) -> &BTreeMap<SmolStr, SmolStr> {
        &self.params
    }
}

impl fmt::Display for CpimMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_string() {
            Ok(serialized) => write!(f, "{}", serialized),
            Err(_) => Err(fmt::Error),
        }
    }
}

fn validate_header_name(name: &str) -> Result<(), CpimError> {
    if name.is_empty() {
        return Err(CpimError::InvalidHeaderName("empty name".to_string()));
    }
    if name.len() > MAX_HEADER_NAME_LENGTH {
        return Err(CpimError::HeaderNameTooLong {
            max: MAX_HEADER_NAME_LENGTH,
            actual: name.len(),
        });
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(CpimError::InvalidHeaderName(
            "contains control characters".to_string(),
        ));
    }
    if name
        .chars()
        .any(|c| matches!(c, ':' | ';' | '=' | '\\' | '"'))
    {
        return Err(CpimError::InvalidHeaderName(
            "contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_cpim_header_value(value: &str) -> Result<(), CpimError> {
    if value.len() > MAX_HEADER_VALUE_LENGTH {
        return Err(CpimError::HeaderValueTooLong {
            max: MAX_HEADER_VALUE_LENGTH,
            actual: value.len(),
        });
    }
    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), CpimError> {
    if name.is_empty() {
        return Err(CpimError::InvalidParamName("empty name".to_string()));
    }
    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(CpimError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }
    if name
        .chars()
        .any(|c| c.is_ascii_control() || matches!(c, ';' | '=' | '\\' | '"'))
    {
        return Err(CpimError::InvalidParamName(
            "contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), CpimError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(CpimError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }
    if value
        .chars()
        .any(|c| c.is_ascii_control() || matches!(c, ';' | '\\' | '"'))
    {
        return Err(CpimError::InvalidParamValue(
            "contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_content_type(value: &str) -> Result<(), CpimError> {
    if value.is_empty() {
        return Err(CpimError::InvalidContentType(
            "empty content type".to_string(),
        ));
    }
    if value.len() > MAX_CONTENT_TYPE_LENGTH {
        return Err(CpimError::ContentTypeTooLong {
            max: MAX_CONTENT_TYPE_LENGTH,
            actual: value.len(),
        });
    }
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(CpimError::InvalidContentType(
            "contains control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_content_header_value(value: &str) -> Result<(), CpimError> {
    if value.len() > MAX_HEADER_VALUE_LENGTH {
        return Err(CpimError::HeaderValueTooLong {
            max: MAX_HEADER_VALUE_LENGTH,
            actual: value.len(),
        });
    }
    // Check for control characters (includes \r, \n, etc.)
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(CpimError::InvalidHeaderValue(
            "contains control characters".to_string(),
        ));
    }
    Ok(())
}

/// Escapes special characters in a header value according to RFC 3862.
///
/// Control characters must be escaped using the following sequences:
/// - `\\` for backslash
/// - `\\"` for quote
/// - `\\b` for backspace
/// - `\\t` for tab
/// - `\\n` for linefeed
/// - `\\r` for carriage return
/// - `\\uxxxx` for Unicode codepoints
fn escape_header_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\x08' => result.push_str("\\b"),
            '\t' => result.push_str("\\t"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result
}

/// Unescapes special characters in a header value according to RFC 3862.
fn unescape_header_value(value: &str) -> Option<String> {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('b') => result.push('\x08'),
                Some('t') => result.push('\t'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('u') => {
                    // Read 4 hex digits
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() == 4 {
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(unicode_char) = char::from_u32(code) {
                                result.push(unicode_char);
                            } else {
                                return None;
                            }
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        } else {
            result.push(ch);
        }
    }

    Some(result)
}

/// Parses a CPIM message from a string.
pub fn parse_cpim(input: &str) -> Result<CpimMessage, CpimError> {
    if input.len() > MAX_PARSE_SIZE {
        return Err(CpimError::InputTooLarge {
            max: MAX_PARSE_SIZE,
            actual: input.len(),
        });
    }

    // Split into sections by blank lines (CRLF CRLF or LF LF)
    let sections: Vec<&str> = if input.contains("\r\n\r\n") {
        input.split("\r\n\r\n").collect()
    } else {
        input.split("\n\n").collect()
    };

    if sections.len() < 4 {
        return Err(CpimError::ParseError(
            "missing required cpim sections".to_string(),
        ));
    }

    // First section: MIME headers (should contain Content-type: Message/CPIM)
    let mime_section = sections[0];
    if !mime_section.to_lowercase().contains("message/cpim") {
        return Err(CpimError::ParseError(
            "missing message/cpim MIME header".to_string(),
        ));
    }

    // Second section: Message headers
    let headers_section = sections[1];
    let headers = parse_headers(headers_section)?;

    // Third section: Content headers
    let content_headers_section = sections[2];

    // Parse content headers
    let mut content_type = SmolStr::new("text/plain");
    let mut content_headers = BTreeMap::new();

    let line_sep = if content_headers_section.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    for line in content_headers_section.split(line_sep) {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("Content-type")
                || name.eq_ignore_ascii_case("Content-Type")
            {
                validate_content_type(value)?;
                content_type = SmolStr::new(value);
            } else {
                validate_header_name(name)?;
                validate_content_header_value(value)?;
                if content_headers.len() >= MAX_CONTENT_HEADERS {
                    return Err(CpimError::TooManyContentHeaders {
                        max: MAX_CONTENT_HEADERS,
                        actual: content_headers.len() + 1,
                    });
                }
                content_headers.insert(SmolStr::new(name), SmolStr::new(value));
            }
        }
    }

    // Fourth section onwards: Body (join remaining sections in case body contains blank lines)
    let body_str = sections[3..].join("\r\n\r\n");
    let body = body_str.as_bytes().to_vec();

    if body.len() > MAX_BODY_SIZE {
        return Err(CpimError::BodyTooLarge {
            max: MAX_BODY_SIZE,
            actual: body.len(),
        });
    }

    Ok(CpimMessage {
        headers,
        content_type,
        content_headers,
        body,
    })
}

/// Parses CPIM headers from a string.
fn parse_headers(input: &str) -> Result<BTreeMap<SmolStr, Vec<CpimHeader>>, CpimError> {
    let mut headers = BTreeMap::new();

    let line_sep = if input.contains("\r\n") { "\r\n" } else { "\n" };

    for line in input.split(line_sep) {
        if line.is_empty() {
            continue;
        }

        // Split into name and value
        let (name_with_params, value) = line
            .split_once(':')
            .ok_or_else(|| CpimError::ParseError("missing ':'".to_string()))?;

        // Parse header name and parameters
        let mut parts = name_with_params.split(';');
        let name = parts
            .next()
            .ok_or_else(|| CpimError::ParseError("missing header name".to_string()))?
            .trim();
        validate_header_name(name)?;

        let mut params = BTreeMap::new();
        for param in parts {
            if let Some((param_name, param_value)) = param.split_once('=') {
                validate_param_name(param_name.trim())?;
                validate_param_value(param_value.trim())?;
                if params.len() >= MAX_PARAMS_PER_HEADER {
                    return Err(CpimError::TooManyParams {
                        max: MAX_PARAMS_PER_HEADER,
                        actual: params.len() + 1,
                    });
                }
                params.insert(
                    SmolStr::new(param_name.trim()),
                    SmolStr::new(param_value.trim()),
                );
            }
        }

        // Unescape the value
        let unescaped_value = unescape_header_value(value.trim())
            .ok_or_else(|| CpimError::ParseError("invalid escape sequence".to_string()))?;
        validate_cpim_header_value(&unescaped_value)?;

        let header = CpimHeader {
            value: SmolStr::new(&unescaped_value),
            params,
        };

        headers
            .entry(SmolStr::new(name))
            .or_insert_with(Vec::new)
            .push(header);

        let total_headers: usize = headers.values().map(|values| values.len()).sum();
        if total_headers > MAX_HEADERS {
            return Err(CpimError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: total_headers,
            });
        }
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_cpim_message() {
        let msg = CpimMessage::new("text/plain", b"Hello, World!".to_vec())
            .unwrap()
            .with_from("Alice <im:alice@example.com>")
            .unwrap()
            .with_to("Bob <im:bob@example.com>")
            .unwrap()
            .with_datetime("2023-01-15T10:30:00Z")
            .unwrap()
            .with_subject("Greeting")
            .unwrap();

        assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
        assert_eq!(msg.get_header("To"), Some("Bob <im:bob@example.com>"));
        assert_eq!(msg.get_header("DateTime"), Some("2023-01-15T10:30:00Z"));
        assert_eq!(msg.get_header("Subject"), Some("Greeting"));
        assert_eq!(msg.content_type(), "text/plain");
        assert_eq!(msg.body_as_string(), Some("Hello, World!".to_string()));
    }

    #[test]
    fn cpim_with_multiple_recipients() {
        let mut msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .unwrap()
            .with_from("Alice <im:alice@example.com>")
            .unwrap();
        msg.add_header("To", "Bob <im:bob@example.com>").unwrap();
        msg.add_header("To", "Charlie <im:charlie@example.com>")
            .unwrap();

        let to_values = msg.get_header_values("To");
        assert_eq!(to_values.len(), 2);
        assert_eq!(to_values[0], "Bob <im:bob@example.com>");
        assert_eq!(to_values[1], "Charlie <im:charlie@example.com>");
    }

    #[test]
    fn cpim_with_language_tagged_subject() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .unwrap()
            .with_subject_lang("Hello", "en")
            .unwrap()
            .with_subject_lang("Bonjour", "fr")
            .unwrap();

        let subjects = msg.get_header_values("Subject");
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0], "Hello");
        assert_eq!(subjects[1], "Bonjour");

        // Check parameters
        let subject_headers = msg.headers().get("Subject").unwrap();
        assert_eq!(
            subject_headers[0].params().get("lang"),
            Some(&SmolStr::new("en"))
        );
        assert_eq!(
            subject_headers[1].params().get("lang"),
            Some(&SmolStr::new("fr"))
        );
    }

    #[test]
    fn cpim_with_namespace() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .unwrap()
            .with_ns("MyFeatures", "mid:MessageFeatures@id.foo.com")
            .unwrap()
            .with_require("MyFeatures.VitalMessageOption")
            .unwrap();

        assert_eq!(
            msg.get_header("NS"),
            Some("MyFeatures <mid:MessageFeatures@id.foo.com>")
        );
        assert_eq!(
            msg.get_header("Require"),
            Some("MyFeatures.VitalMessageOption")
        );
    }

    #[test]
    fn cpim_with_cc() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .unwrap()
            .with_from("Alice <im:alice@example.com>")
            .unwrap()
            .with_to("Bob <im:bob@example.com>")
            .unwrap()
            .with_cc("Charlie <im:charlie@example.com>")
            .unwrap();

        assert_eq!(
            msg.get_header("cc"),
            Some("Charlie <im:charlie@example.com>")
        );
    }

    #[test]
    fn cpim_with_content_headers() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .unwrap()
            .with_from("Alice <im:alice@example.com>")
            .unwrap()
            .with_to("Bob <im:bob@example.com>")
            .unwrap()
            .with_content_header("Content-ID", "<1234567890@example.com>")
            .unwrap()
            .with_content_header("Content-Disposition", "inline")
            .unwrap();

        assert_eq!(
            msg.content_headers().get("Content-ID"),
            Some(&SmolStr::new("<1234567890@example.com>"))
        );
        assert_eq!(
            msg.content_headers().get("Content-Disposition"),
            Some(&SmolStr::new("inline"))
        );
    }

    #[test]
    fn escape_special_characters() {
        let escaped = escape_header_value("Hello\nWorld\r\nTab:\t Quote:\" Backslash:\\");
        assert_eq!(
            escaped,
            "Hello\\nWorld\\r\\nTab:\\t Quote:\\\" Backslash:\\\\"
        );
    }

    #[test]
    fn unescape_special_characters() {
        let unescaped =
            unescape_header_value("Hello\\nWorld\\r\\nTab:\\t Quote:\\\" Backslash:\\\\").unwrap();
        assert_eq!(unescaped, "Hello\nWorld\r\nTab:\t Quote:\" Backslash:\\");
    }

    #[test]
    fn escape_unicode() {
        let escaped = escape_header_value("Hello\x01World");
        assert_eq!(escaped, "Hello\\u0001World");
    }

    #[test]
    fn unescape_unicode() {
        let unescaped = unescape_header_value("Hello\\u0001World").unwrap();
        assert_eq!(unescaped, "Hello\x01World");
    }

    #[test]
    fn format_cpim_message() {
        let msg = CpimMessage::new("text/plain", b"Hello, World!".to_vec())
            .unwrap()
            .with_from("Alice <im:alice@example.com>")
            .unwrap()
            .with_to("Bob <im:bob@example.com>")
            .unwrap()
            .with_datetime("2023-01-15T10:30:00Z")
            .unwrap()
            .with_subject("Greeting")
            .unwrap();

        let formatted = msg.to_string().unwrap();
        assert!(formatted.contains("Content-type: Message/CPIM"));
        assert!(formatted.contains("From: Alice <im:alice@example.com>"));
        assert!(formatted.contains("To: Bob <im:bob@example.com>"));
        assert!(formatted.contains("DateTime: 2023-01-15T10:30:00Z"));
        assert!(formatted.contains("Subject: Greeting"));
        assert!(formatted.contains("Content-type: text/plain"));
        assert!(formatted.contains("Hello, World!"));
    }

    #[test]
    fn parse_simple_cpim_message() {
        let input = "Content-type: Message/CPIM\r\n\r\nFrom: Alice <im:alice@example.com>\r\nTo: Bob <im:bob@example.com>\r\nDateTime: 2023-01-15T10:30:00Z\r\nSubject: Greeting\r\n\r\nContent-type: text/plain\r\n\r\nHello, World!";

        let msg = parse_cpim(input).unwrap();
        assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
        assert_eq!(msg.get_header("To"), Some("Bob <im:bob@example.com>"));
        assert_eq!(msg.get_header("DateTime"), Some("2023-01-15T10:30:00Z"));
        assert_eq!(msg.get_header("Subject"), Some("Greeting"));
        assert_eq!(msg.content_type(), "text/plain");
        assert_eq!(msg.body_as_string(), Some("Hello, World!".to_string()));
    }

    #[test]
    fn parse_cpim_with_multiple_subjects() {
        let input = "Content-type: Message/CPIM\r\n\r\nFrom: Alice <im:alice@example.com>\r\nTo: Bob <im:bob@example.com>\r\nSubject: Hello\r\nSubject;lang=fr: Bonjour\r\n\r\nContent-type: text/plain\r\n\r\nHello";

        let msg = parse_cpim(input).unwrap();
        let subjects = msg.get_header_values("Subject");
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0], "Hello");
        assert_eq!(subjects[1], "Bonjour");

        let subject_headers = msg.headers().get("Subject").unwrap();
        assert_eq!(
            subject_headers[1].params().get("lang"),
            Some(&SmolStr::new("fr"))
        );
    }

    #[test]
    fn round_trip_cpim() {
        let original = CpimMessage::new("text/plain", b"Test message".to_vec())
            .unwrap()
            .with_from("Alice <im:alice@example.com>")
            .unwrap()
            .with_to("Bob <im:bob@example.com>")
            .unwrap()
            .with_datetime("2023-01-15T10:30:00Z")
            .unwrap()
            .with_subject("Test")
            .unwrap();

        let formatted = original.to_string().unwrap();
        let parsed = parse_cpim(&formatted).unwrap();

        assert_eq!(parsed.get_header("From"), original.get_header("From"));
        assert_eq!(parsed.get_header("To"), original.get_header("To"));
        assert_eq!(
            parsed.get_header("DateTime"),
            original.get_header("DateTime")
        );
        assert_eq!(parsed.get_header("Subject"), original.get_header("Subject"));
        assert_eq!(parsed.body_as_string(), original.body_as_string());
    }

    #[test]
    fn cpim_header_with_params() {
        let header = CpimHeader::new("Hello")
            .unwrap()
            .with_param("lang", "en")
            .unwrap()
            .with_param("charset", "utf-8")
            .unwrap();

        assert_eq!(header.value(), "Hello");
        assert_eq!(header.params().get("lang"), Some(&SmolStr::new("en")));
        assert_eq!(header.params().get("charset"), Some(&SmolStr::new("utf-8")));
    }
}
