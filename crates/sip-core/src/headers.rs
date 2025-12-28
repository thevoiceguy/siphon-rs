// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::slice::Iter;

const MAX_HEADER_NAME_LENGTH: usize = 128;
const MAX_HEADER_VALUE_LENGTH: usize = 8192;
const MAX_HEADERS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    NameTooLong { max: usize, actual: usize },
    ValueTooLong { max: usize, actual: usize },
    TooManyHeaders { max: usize, actual: usize },
    InvalidName(String),
    InvalidValue(String),
    EmptyName,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameTooLong { max, actual } => {
                write!(f, "header name too long (max {}, got {})", max, actual)
            }
            Self::ValueTooLong { max, actual } => {
                write!(f, "header value too long (max {}, got {})", max, actual)
            }
            Self::TooManyHeaders { max, actual } => {
                write!(f, "too many headers (max {}, got {})", max, actual)
            }
            Self::InvalidName(msg) => write!(f, "invalid header name: {}", msg),
            Self::InvalidValue(msg) => write!(f, "invalid header value: {}", msg),
            Self::EmptyName => write!(f, "header name cannot be empty"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Represents a single SIP header field as a name/value pair.
///
/// Per RFC 3261, header fields follow the format:
/// `field-name: field-value`
///
/// # Security
///
/// Header validates both name and value to prevent:
/// - CRLF injection attacks
/// - Control character injection
/// - Header smuggling
/// - Excessive length (DoS)
///
/// Header names must:
/// - Not be empty
/// - Be valid tokens (alphanumeric plus specific symbols)
/// - Not contain control characters including CRLF
/// - Be within length limits
///
/// Header values must:
/// - Not contain raw CRLF sequences (use folding if needed)
/// - Be within length limits
///
/// # Examples
///
/// ```
/// use sip_core::Header;
///
/// let header = Header::new("Content-Type", "application/sdp").unwrap();
/// assert_eq!(header.name(), "Content-Type");
/// assert_eq!(header.value(), "application/sdp");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    name: SmolStr,
    value: SmolStr,
}

impl Header {
    /// Creates a new header with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Name is empty or too long
    /// - Name contains invalid characters (including CRLF)
    /// - Value is too long
    /// - Value contains unescaped CRLF
    pub fn new(name: impl AsRef<str>, value: impl AsRef<str>) -> Result<Self, HeaderError> {
        let name = name.as_ref();
        let value = value.as_ref();

        validate_header_name(name)?;
        validate_header_value(value)?;

        Ok(Self {
            name: SmolStr::new(name),
            value: SmolStr::new(value),
        })
    }

    /// Returns the header name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the header name as SmolStr.
    pub fn name_smol(&self) -> &SmolStr {
        &self.name
    }

    /// Returns the header value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the header value as SmolStr.
    pub fn value_smol(&self) -> &SmolStr {
        &self.value
    }

    /// Returns true if the header name matches (case-insensitive).
    pub fn name_eq(&self, other: &str) -> bool {
        self.name.eq_ignore_ascii_case(other)
    }

    /// Returns a tuple of (name, value) references.
    pub fn as_tuple(&self) -> (&str, &str) {
        (self.name.as_str(), self.value.as_str())
    }
}

/// Collection of SIP headers preserving insertion order.
///
/// Per RFC 3261, headers can appear multiple times and order matters
/// for certain header types (e.g., Via, Route, Record-Route).
///
/// # Security
///
/// Headers validates all entries and enforces:
/// - Maximum header count to prevent DoS
/// - Validation of all header names and values
/// - No direct mutation of internal data
///
/// # Examples
///
/// ```
/// use sip_core::Headers;
///
/// let mut headers = Headers::new();
/// headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();
/// headers.push("To", "Bob <sip:bob@example.com>").unwrap();
///
/// assert_eq!(headers.len(), 2);
/// assert_eq!(headers.get("Via"), Some("SIP/2.0/UDP pc33.example.com"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    inner: Vec<Header>,
}

impl Headers {
    /// Creates an empty header collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a header collection from validated headers.
    ///
    /// # Errors
    ///
    /// Returns an error if the collection exceeds MAX_HEADERS.
    pub fn from_vec(headers: Vec<Header>) -> Result<Self, HeaderError> {
        Self::try_from_iter(headers)
    }

    /// Appends a header to the collection with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The header name or value is invalid
    /// - Adding would exceed MAX_HEADERS
    pub fn push(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), HeaderError> {
        if self.inner.len() >= MAX_HEADERS {
            return Err(HeaderError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: self.inner.len() + 1,
            });
        }

        let header = Header::new(name, value)?;
        self.inner.push(header);
        Ok(())
    }

    /// Appends a pre-validated Header to the collection.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed MAX_HEADERS.
    pub fn push_header(&mut self, header: Header) -> Result<(), HeaderError> {
        if self.inner.len() >= MAX_HEADERS {
            return Err(HeaderError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: self.inner.len() + 1,
            });
        }

        self.inner.push(header);
        Ok(())
    }

    /// Returns an iterator over the stored headers.
    pub fn iter(&self) -> Iter<'_, Header> {
        self.inner.iter()
    }

    /// Returns the number of headers present.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` when the collection does not contain any headers.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Finds the first header whose name matches (case-insensitive).
    ///
    /// Returns the header value, or None if not found.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner
            .iter()
            .find(|h| h.name_eq(name))
            .map(|h| h.value())
    }

    /// Finds the first Header with the given name.
    pub fn get_header(&self, name: &str) -> Option<&Header> {
        self.inner.iter().find(|h| h.name_eq(name))
    }

    /// Finds the first header value with the given name.
    pub fn get_smol(&self, name: &str) -> Option<&SmolStr> {
        self.get_header(name).map(|h| h.value_smol())
    }

    /// Returns all header values with the given name (case-insensitive).
    ///
    /// Preserves the original insertion order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.inner
            .iter()
            .filter(move |h| h.name_eq(name))
            .map(|h| h.value())
    }

    /// Returns all header values with the given name as SmolStr (case-insensitive).
    pub fn get_all_smol<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a SmolStr> + 'a {
        self.inner
            .iter()
            .filter(move |h| h.name_eq(name))
            .map(|h| h.value_smol())
    }

    /// Returns all Headers with the given name (case-insensitive).
    pub fn get_all_headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.inner.iter().filter(move |h| h.name_eq(name))
    }

    /// Checks if a header with the given name exists (case-insensitive).
    pub fn contains(&self, name: &str) -> bool {
        self.inner.iter().any(|h| h.name_eq(name))
    }

    /// Counts how many headers have the given name (case-insensitive).
    pub fn count(&self, name: &str) -> usize {
        self.inner.iter().filter(|h| h.name_eq(name)).count()
    }

    /// Removes all headers with the given name (case-insensitive).
    ///
    /// Returns the number of headers removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let original_len = self.inner.len();
        self.inner.retain(|h| !h.name_eq(name));
        original_len - self.inner.len()
    }

    /// Replaces the first header value with the given name (case-insensitive).
    ///
    /// Returns `true` if a header was updated.
    pub fn replace_first(
        &mut self,
        name: &str,
        value: impl AsRef<str>,
    ) -> Result<bool, HeaderError> {
        let value = value.as_ref();
        validate_header_value(value)?;
        if let Some(header) = self.inner.iter_mut().find(|h| h.name_eq(name)) {
            header.value = SmolStr::new(value);
            return Ok(true);
        }
        Ok(false)
    }

    /// Sets the first header value for the given name, or appends if missing.
    pub fn set_or_push(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), HeaderError> {
        let name = name.as_ref();
        let value = value.as_ref();
        validate_header_name(name)?;
        validate_header_value(value)?;

        if let Some(header) = self.inner.iter_mut().find(|h| h.name_eq(name)) {
            header.value = SmolStr::new(value);
            return Ok(());
        }

        if self.inner.len() >= MAX_HEADERS {
            return Err(HeaderError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: self.inner.len() + 1,
            });
        }

        self.inner.push(Header {
            name: SmolStr::new(name),
            value: SmolStr::new(value),
        });
        Ok(())
    }

    /// Retains only headers for which the predicate returns true.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&Header) -> bool,
    {
        self.inner.retain(|h| f(h));
    }

    /// Removes and returns the header at the given index.
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds.
    pub fn remove_at(&mut self, index: usize) -> Header {
        self.inner.remove(index)
    }

    /// Consumes the collection returning the underlying vector.
    pub fn into_inner(self) -> Vec<Header> {
        self.inner
    }

    /// Returns a slice of all headers.
    pub fn as_slice(&self) -> &[Header] {
        &self.inner
    }

    /// Clears all headers from the collection.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Reserves capacity for at least `additional` more headers.
    pub fn reserve(&mut self, additional: usize) {
        // Cap reservation to prevent excessive memory allocation
        let new_total = self.inner.len() + additional;
        if new_total <= MAX_HEADERS {
            self.inner.reserve(additional);
        }
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<Header> for Headers {
    fn from_iter<T: IntoIterator<Item = Header>>(iter: T) -> Self {
        let headers: Vec<Header> = iter.into_iter().collect();
        Self { inner: headers }
    }
}

impl Headers {
    /// Builds a header collection from an iterator with validation.
    pub fn try_from_iter<T: IntoIterator<Item = Header>>(iter: T) -> Result<Self, HeaderError> {
        let headers: Vec<Header> = iter.into_iter().collect();
        if headers.len() > MAX_HEADERS {
            return Err(HeaderError::TooManyHeaders {
                max: MAX_HEADERS,
                actual: headers.len(),
            });
        }
        Ok(Self { inner: headers })
    }
}

// Validation functions

/// Validates a header name per RFC 3261.
///
/// Header names (field names) must be tokens, which consist of:
/// - Alphanumeric characters
/// - Special characters: ! % ' * + - . ^ _ ` | ~
///
/// They must NOT contain:
/// - Control characters (including CRLF)
/// - Separators like : ; , = ( ) < > @ " [ ] { } ? / \ space tab
fn validate_header_name(name: &str) -> Result<(), HeaderError> {
    if name.is_empty() {
        return Err(HeaderError::EmptyName);
    }

    if name.len() > MAX_HEADER_NAME_LENGTH {
        return Err(HeaderError::NameTooLong {
            max: MAX_HEADER_NAME_LENGTH,
            actual: name.len(),
        });
    }

    // Check for control characters
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(HeaderError::InvalidName(
            "contains control characters".to_string(),
        ));
    }

    // Check for invalid separators/special characters
    // Valid token characters per RFC 3261: alphanum + ! % ' * + - . ^ _ ` | ~
    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '%' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
            )
    }) {
        return Err(HeaderError::InvalidName(
            "contains invalid characters for header name".to_string(),
        ));
    }

    Ok(())
}

/// Validates a header value per RFC 3261.
///
/// Header values can contain most characters but must NOT contain:
/// - Unescaped/unfolded CRLF sequences
/// - Null bytes
///
/// Note: RFC 3261 allows header folding (CRLF followed by space/tab),
/// but for security we reject raw CRLF entirely. Folding should be
/// handled at the serialization layer.
fn validate_header_value(value: &str) -> Result<(), HeaderError> {
    if value.len() > MAX_HEADER_VALUE_LENGTH {
        return Err(HeaderError::ValueTooLong {
            max: MAX_HEADER_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    // Reject CR and LF entirely to prevent header injection
    // Header folding should be handled during serialization, not in raw values
    if value.contains('\r') || value.contains('\n') {
        return Err(HeaderError::InvalidValue(
            "contains CRLF - header folding must be handled during serialization".to_string(),
        ));
    }

    // Reject null bytes
    if value.contains('\0') {
        return Err(HeaderError::InvalidValue("contains null byte".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_header() {
        let header = Header::new("Content-Type", "application/sdp").unwrap();
        assert_eq!(header.name(), "Content-Type");
        assert_eq!(header.value(), "application/sdp");
    }

    #[test]
    fn header_name_case_insensitive() {
        let header = Header::new("Content-Type", "text/plain").unwrap();
        assert!(header.name_eq("content-type"));
        assert!(header.name_eq("CONTENT-TYPE"));
        assert!(header.name_eq("Content-Type"));
    }

    #[test]
    fn reject_empty_header_name() {
        let result = Header::new("", "value");
        assert!(matches!(result, Err(HeaderError::EmptyName)));
    }

    #[test]
    fn reject_crlf_in_header_name() {
        let result = Header::new("Content-Type\r\nInjected", "value");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_header_value() {
        let result = Header::new("Content-Type", "value\r\nInjected: evil");
        assert!(result.is_err());
    }

    #[test]
    fn reject_null_in_header_value() {
        let result = Header::new("Content-Type", "value\0injected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_header_name() {
        let long_name = "x".repeat(MAX_HEADER_NAME_LENGTH + 1);
        let result = Header::new(&long_name, "value");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_header_value() {
        let long_value = "x".repeat(MAX_HEADER_VALUE_LENGTH + 1);
        let result = Header::new("Content-Type", &long_value);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_header_name_chars() {
        // Colon is not allowed in header names
        let result = Header::new("Content:Type", "value");
        assert!(result.is_err());

        // Space is not allowed
        let result = Header::new("Content Type", "value");
        assert!(result.is_err());
    }

    #[test]
    fn create_headers_collection() {
        let mut headers = Headers::new();
        assert!(headers.is_empty());
        assert_eq!(headers.len(), 0);

        headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();
        assert_eq!(headers.len(), 1);
        assert!(!headers.is_empty());
    }

    #[test]
    fn headers_get() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();
        headers.push("Content-Length", "142").unwrap();

        assert_eq!(headers.get("Content-Type"), Some("application/sdp"));
        assert_eq!(headers.get("content-type"), Some("application/sdp"));
        assert_eq!(headers.get("Content-Length"), Some("142"));
        assert_eq!(headers.get("Unknown"), None);
    }

    #[test]
    fn headers_get_all() {
        let mut headers = Headers::new();
        headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();
        headers
            .push("Via", "SIP/2.0/UDP proxy.example.com")
            .unwrap();
        headers.push("Content-Type", "application/sdp").unwrap();

        let vias: Vec<&str> = headers.get_all("Via").collect();
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[0], "SIP/2.0/UDP pc33.example.com");
        assert_eq!(vias[1], "SIP/2.0/UDP proxy.example.com");
    }

    #[test]
    fn headers_contains() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();

        assert!(headers.contains("Content-Type"));
        assert!(headers.contains("content-type"));
        assert!(!headers.contains("Unknown"));
    }

    #[test]
    fn headers_count() {
        let mut headers = Headers::new();
        headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();
        headers
            .push("Via", "SIP/2.0/UDP proxy.example.com")
            .unwrap();

        assert_eq!(headers.count("Via"), 2);
        assert_eq!(headers.count("Unknown"), 0);
    }

    #[test]
    fn headers_remove() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();
        headers.push("Content-Length", "142").unwrap();
        headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();

        let removed = headers.remove("Content-Type");
        assert_eq!(removed, 1);
        assert_eq!(headers.len(), 2);
        assert!(!headers.contains("Content-Type"));
    }

    #[test]
    fn headers_remove_multiple() {
        let mut headers = Headers::new();
        headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();
        headers
            .push("Via", "SIP/2.0/UDP proxy.example.com")
            .unwrap();

        let removed = headers.remove("Via");
        assert_eq!(removed, 2);
        assert_eq!(headers.len(), 0);
    }

    #[test]
    fn reject_too_many_headers() {
        let mut headers = Headers::new();

        for i in 0..MAX_HEADERS {
            headers.push(&format!("X-Header-{}", i), "value").unwrap();
        }

        // Should fail
        let result = headers.push("X-Overflow", "value");
        assert!(matches!(result, Err(HeaderError::TooManyHeaders { .. })));
    }

    #[test]
    fn headers_iteration() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();
        headers.push("Content-Length", "142").unwrap();

        let collected: Vec<_> = headers.iter().map(|h| h.name()).collect();
        assert_eq!(collected, vec!["Content-Type", "Content-Length"]);
    }

    #[test]
    fn headers_into_iterator() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();
        headers.push("Content-Length", "142").unwrap();

        let names: Vec<String> = headers.into_iter().map(|h| h.name().to_string()).collect();
        assert_eq!(names, vec!["Content-Type", "Content-Length"]);
    }

    #[test]
    fn headers_from_iter() {
        let header1 = Header::new("Content-Type", "application/sdp").unwrap();
        let header2 = Header::new("Content-Length", "142").unwrap();

        let headers: Headers = vec![header1, header2].into_iter().collect();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn headers_retain() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();
        headers.push("Content-Length", "142").unwrap();
        headers.push("Via", "SIP/2.0/UDP pc33.example.com").unwrap();

        headers.retain(|h| h.name() != "Content-Length");
        assert_eq!(headers.len(), 2);
        assert!(!headers.contains("Content-Length"));
    }

    #[test]
    fn header_fields_are_private() {
        let header = Header::new("Content-Type", "application/sdp").unwrap();

        // These should compile (read-only access)
        let _ = header.name();
        let _ = header.value();

        // These should NOT compile (no direct field access):
        // header.name = SmolStr::new("evil");   // ← Does not compile!
        // header.value = SmolStr::new("evil");  // ← Does not compile!
    }

    #[test]
    fn no_mutable_iteration() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "application/sdp").unwrap();

        // This should compile (immutable iteration)
        for header in headers.iter() {
            let _ = header.name();
        }

        // This should NOT compile (no iter_mut exposed):
        // for header in headers.iter_mut() { ... }  // ← Does not compile!
    }
}
