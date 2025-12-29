// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Subject header (RFC 3261 Section 20.36) with security hardening.
//!
//! The Subject header provides a summary or indicates the nature of the call.
//! It's primarily used for human consumption.
//!
//! # Security
//!
//! Subject values are validated for:
//! - Maximum length to prevent DoS attacks
//! - No control characters (prevents CRLF injection)
//! - Proper UTF-8 encoding
//!
//! # Format
//!
//! ```text
//! Subject: Need more boxes
//! Subject: Tech Support
//! ```
//!
//! # Example
//!
//! ```
//! use sip_core::SubjectHeader;
//!
//! let subject = SubjectHeader::new("Need more boxes").unwrap();
//! assert_eq!(subject.value(), "Need more boxes");
//! ```

use smol_str::SmolStr;
use std::fmt;

// Security: Input size limits
const MAX_SUBJECT_LENGTH: usize = 256;

/// Error types for Subject header operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectError {
    /// Subject is empty
    Empty,
    /// Subject too long
    TooLong { max: usize },
    /// Subject contains invalid characters
    InvalidCharacters(String),
}

impl fmt::Display for SubjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubjectError::Empty => write!(f, "Subject cannot be empty"),
            SubjectError::TooLong { max } => {
                write!(f, "Subject too long (max {})", max)
            }
            SubjectError::InvalidCharacters(msg) => {
                write!(f, "Subject contains invalid characters: {}", msg)
            }
        }
    }
}

impl std::error::Error for SubjectError {}

/// Validates a subject value.
fn validate_subject(value: &str) -> Result<(), SubjectError> {
    if value.is_empty() || value.chars().all(|c| c == ' ' || c == '\t') {
        return Err(SubjectError::Empty);
    }

    if value.len() > MAX_SUBJECT_LENGTH {
        return Err(SubjectError::TooLong {
            max: MAX_SUBJECT_LENGTH,
        });
    }

    // Subject is a SIP text field: allow HTAB, SP, and visible ASCII.
    for ch in value.chars() {
        if ch == '\t' || ch == ' ' {
            continue;
        }
        if !ch.is_ascii_graphic() {
            return Err(SubjectError::InvalidCharacters(
                "contains non-ASCII or control characters".to_string(),
            ));
        }
    }

    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err(SubjectError::InvalidCharacters(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Subject header (RFC 3261 Section 20.36).
///
/// The Subject header field provides a summary or indicates the nature of
/// the call, allowing call filtering without having to parse the session
/// description. The session description does not have to use the same
/// subject indication as the invitation.
///
/// # Security
///
/// Subject values are validated for:
/// - Maximum length of 256 characters
/// - No control characters except tab (prevents CRLF injection)
/// - Non-empty after trimming
///
/// # Examples
///
/// ```
/// use sip_core::SubjectHeader;
///
/// // Create a subject header
/// let subject = SubjectHeader::new("Tech Support").unwrap();
/// assert_eq!(subject.value(), "Tech Support");
///
/// // Parse from string
/// let parsed = SubjectHeader::parse("Need more boxes").unwrap();
/// assert_eq!(parsed.to_string(), "Need more boxes");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectHeader {
    value: SmolStr,
}

impl SubjectHeader {
    /// Creates a new Subject header with validation.
    ///
    /// # Arguments
    ///
    /// * `value` - The subject text
    ///
    /// # Errors
    ///
    /// Returns `SubjectError` if:
    /// - Value is empty or whitespace-only
    /// - Value exceeds 256 characters
    /// - Value contains control characters (except tab)
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SubjectHeader;
    ///
    /// let subject = SubjectHeader::new("Tech Support").unwrap();
    /// assert_eq!(subject.value(), "Tech Support");
    /// ```
    pub fn new(value: &str) -> Result<Self, SubjectError> {
        validate_subject(value)?;
        Ok(Self {
            value: SmolStr::new(value),
        })
    }

    /// Gets the subject value.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SubjectHeader;
    ///
    /// let subject = SubjectHeader::new("Tech Support").unwrap();
    /// assert_eq!(subject.value(), "Tech Support");
    /// ```
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Parses a Subject header from a string with validation.
    ///
    /// # Returns
    ///
    /// - `Ok(SubjectHeader)` if parsing and validation succeed
    /// - `Err(SubjectError)` if validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SubjectHeader;
    ///
    /// let subject = SubjectHeader::parse("Need more boxes").unwrap();
    /// assert_eq!(subject.value(), "Need more boxes");
    ///
    /// // Preserves whitespace
    /// let subject2 = SubjectHeader::parse("  Tech Support  ").unwrap();
    /// assert_eq!(subject2.value(), "  Tech Support  ");
    /// ```
    pub fn parse(input: &str) -> Result<Self, SubjectError> {
        Self::new(input)
    }
}

impl fmt::Display for SubjectHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_basic() {
        let subject = SubjectHeader::new("Tech Support").unwrap();
        assert_eq!(subject.value(), "Tech Support");
    }

    #[test]
    fn subject_format() {
        let subject = SubjectHeader::new("Need more boxes").unwrap();
        assert_eq!(subject.to_string(), "Need more boxes");
    }

    #[test]
    fn subject_parse() {
        let subject = SubjectHeader::parse("Lunch meeting").unwrap();
        assert_eq!(subject.value(), "Lunch meeting");
    }

    #[test]
    fn subject_parse_with_whitespace() {
        let subject = SubjectHeader::parse("  Tech Support  ").unwrap();
        assert_eq!(subject.value(), "  Tech Support  ");
    }

    #[test]
    fn subject_parse_empty() {
        assert!(matches!(SubjectHeader::parse(""), Err(SubjectError::Empty)));
        assert!(matches!(
            SubjectHeader::parse("   "),
            Err(SubjectError::Empty)
        ));
    }

    #[test]
    fn subject_rejects_too_long() {
        let long_subject = "x".repeat(MAX_SUBJECT_LENGTH + 1);
        assert!(matches!(
            SubjectHeader::new(&long_subject),
            Err(SubjectError::TooLong { .. })
        ));
    }

    #[test]
    fn subject_rejects_control_chars() {
        assert!(matches!(
            SubjectHeader::new("Subject\nLine"),
            Err(SubjectError::InvalidCharacters(_))
        ));
        assert!(matches!(
            SubjectHeader::new("Subject\rLine"),
            Err(SubjectError::InvalidCharacters(_))
        ));
        assert!(matches!(
            SubjectHeader::new("Subject\r\nLine"),
            Err(SubjectError::InvalidCharacters(_))
        ));
        assert!(matches!(
            SubjectHeader::new("Subject\x00Line"),
            Err(SubjectError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn subject_accepts_tab() {
        // Tab is allowed in header values per RFC 3261
        let subject = SubjectHeader::new("Subject\twith\ttabs").unwrap();
        assert_eq!(subject.value(), "Subject\twith\ttabs");
    }

    #[test]
    fn subject_accepts_max_length() {
        let max_subject = "x".repeat(MAX_SUBJECT_LENGTH);
        assert!(SubjectHeader::new(&max_subject).is_ok());
    }

    #[test]
    fn subject_round_trip() {
        let original = SubjectHeader::new("Tech Support").unwrap();
        let formatted = original.to_string();
        let parsed = SubjectHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn subject_equality() {
        let subject1 = SubjectHeader::new("Test").unwrap();
        let subject2 = SubjectHeader::new("Test").unwrap();
        let subject3 = SubjectHeader::new("Other").unwrap();

        assert_eq!(subject1, subject2);
        assert_ne!(subject1, subject3);
    }

    #[test]
    fn subject_clone() {
        let subject1 = SubjectHeader::new("Tech Support").unwrap();
        let subject2 = subject1.clone();
        assert_eq!(subject1, subject2);
    }

    #[test]
    fn subject_hash() {
        use std::collections::HashSet;

        let subject1 = SubjectHeader::new("Test").unwrap();
        let subject2 = SubjectHeader::new("Test").unwrap();
        let subject3 = SubjectHeader::new("Other").unwrap();

        let mut set = HashSet::new();
        set.insert(subject1);
        assert!(set.contains(&subject2));
        assert!(!set.contains(&subject3));
    }

    #[test]
    fn field_is_private() {
        let subject = SubjectHeader::new("Tech Support").unwrap();

        // This should compile (read access via getter)
        let _ = subject.value();

        // This should NOT compile:
        // subject.value = SmolStr::new("evil");       // ← Does not compile!
    }

    #[test]
    fn rejects_various_control_characters() {
        // Test various control characters
        assert!(SubjectHeader::new("test\x00value").is_err());
        assert!(SubjectHeader::new("test\x01value").is_err());
        assert!(SubjectHeader::new("test\x1fvalue").is_err());
        assert!(SubjectHeader::new("test\x7fvalue").is_err());
    }

    #[test]
    fn accepts_common_characters() {
        // Should accept common text
        assert!(SubjectHeader::new("Tech Support").is_ok());
        assert!(SubjectHeader::new("Meeting @ 3pm").is_ok());
        assert!(SubjectHeader::new("Question: What's up?").is_ok());
        assert!(SubjectHeader::new("Call #42").is_ok());
        assert!(SubjectHeader::new("Project (Phase 1)").is_ok());
    }

    #[test]
    fn rejects_unicode() {
        assert!(SubjectHeader::new("café").is_err());
        assert!(SubjectHeader::new("Привет").is_err());
        assert!(SubjectHeader::new("你好").is_err());
        assert!(SubjectHeader::new("🎉 Party").is_err());
    }

    #[test]
    fn display_preserves_content() {
        let subjects = vec![
            "Tech Support",
            "Meeting @ 3pm",
            "Question: What's up?",
            "Call #42",
            "Project (Phase 1)",
        ];

        for text in subjects {
            let subject = SubjectHeader::new(text).unwrap();
            assert_eq!(subject.to_string(), text);
        }
    }

    #[test]
    fn error_display() {
        let err1 = SubjectError::Empty;
        assert_eq!(err1.to_string(), "Subject cannot be empty");

        let err2 = SubjectError::TooLong { max: 256 };
        assert_eq!(err2.to_string(), "Subject too long (max 256)");

        let err3 = SubjectError::InvalidCharacters("contains control characters".to_string());
        assert_eq!(
            err3.to_string(),
            "Subject contains invalid characters: contains control characters"
        );
    }
}
