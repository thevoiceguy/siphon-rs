// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

const MAX_PRIORITY_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorityError {
    TooLong { max: usize, actual: usize },
    Empty,
    InvalidCharacters(String),
    ContainsControlChars,
}

impl std::fmt::Display for PriorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { max, actual } => {
                write!(f, "priority value too long (max {}, got {})", max, actual)
            }
            Self::Empty => write!(f, "priority value cannot be empty"),
            Self::InvalidCharacters(msg) => write!(f, "invalid priority characters: {}", msg),
            Self::ContainsControlChars => write!(f, "priority contains control characters"),
        }
    }
}

impl std::error::Error for PriorityError {}

/// Priority header values defined in RFC 3261.
///
/// Per RFC 3261, the Priority header indicates the urgency of the request.
/// Standard values are: emergency, urgent, normal, and non-urgent.
/// Extension values are allowed per RFC 3261.
///
/// # Security
///
/// PriorityValue validates extension values to prevent:
/// - CRLF injection attacks
/// - Control character injection
/// - Excessive length (DoS)
/// - Invalid token characters
///
/// # Examples
///
/// ```
/// use sip_core::PriorityValue;
///
/// // Standard priorities
/// let emergency = PriorityValue::Emergency;
/// assert_eq!(emergency.as_str(), "emergency");
///
/// // Extension priority (validated)
/// let custom = PriorityValue::parse("high").unwrap();
/// assert_eq!(custom.as_str(), "high");
///
/// // Invalid priority rejected
/// assert!(PriorityValue::parse("urgent\r\nInjected").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum PriorityValue {
    /// RFC 3261 - Highest priority
    Emergency,
    /// RFC 3261 - High priority
    Urgent,
    /// RFC 3261 - Normal priority (default)
    #[default]
    Normal,
    /// RFC 3261 - Low priority
    NonUrgent,
    /// Extension priority value (validated)
    Unknown(SmolStr),
}

impl PriorityValue {
    /// Returns the string representation of this priority.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Emergency => "emergency",
            Self::Urgent => "urgent",
            Self::Normal => "normal",
            Self::NonUrgent => "non-urgent",
            Self::Unknown(value) => value.as_str(),
        }
    }

    /// Parses a priority value with validation.
    ///
    /// Standard priority values are recognized case-insensitively.
    /// Extension values are validated and stored as Unknown.
    ///
    /// # Security
    ///
    /// Extension values are validated to ensure:
    /// - Length is within limits (max 32 characters)
    /// - No control characters (including CRLF)
    /// - Only valid RFC 3261 token characters
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Value is empty
    /// - Value is too long
    /// - Value contains control characters
    /// - Value contains invalid characters for a token
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::PriorityValue;
    ///
    /// // Standard values
    /// assert_eq!(
    ///     PriorityValue::parse("emergency").unwrap(),
    ///     PriorityValue::Emergency
    /// );
    ///
    /// // Case-insensitive
    /// assert_eq!(
    ///     PriorityValue::parse("URGENT").unwrap(),
    ///     PriorityValue::Urgent
    /// );
    ///
    /// // Extension values
    /// assert!(PriorityValue::parse("high").is_ok());
    ///
    /// // Invalid values
    /// assert!(PriorityValue::parse("urgent\r\nInjected").is_err());
    /// assert!(PriorityValue::parse("").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, PriorityError> {
        // Check for known priority values first (case-insensitive)
        match s.to_ascii_lowercase().as_str() {
            "emergency" => return Ok(Self::Emergency),
            "urgent" => return Ok(Self::Urgent),
            "normal" => return Ok(Self::Normal),
            "non-urgent" => return Ok(Self::NonUrgent),
            _ => {}
        }

        // Validate extension priority value
        validate_priority_token(s)?;

        // Store in lowercase for consistency
        Ok(Self::Unknown(SmolStr::new(s.to_ascii_lowercase())))
    }

    /// Returns true if this is a standard RFC 3261 priority.
    pub fn is_standard(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    /// Returns true if this is an extension priority.
    pub fn is_extension(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    /// Returns a numeric urgency level for comparison.
    ///
    /// Higher numbers indicate higher urgency:
    /// - Emergency: 3
    /// - Urgent: 2
    /// - Normal: 1
    /// - NonUrgent: 0
    /// - Unknown: None
    pub fn urgency_level(&self) -> Option<u8> {
        match self {
            Self::Emergency => Some(3),
            Self::Urgent => Some(2),
            Self::Normal => Some(1),
            Self::NonUrgent => Some(0),
            Self::Unknown(_) => None,
        }
    }
}

impl std::fmt::Display for PriorityValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for PriorityValue {
    type Err = PriorityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Validates a priority token per RFC 3261.
///
/// Priority values must be tokens, which consist of:
/// - Alphanumeric characters
/// - Special characters: ! % ' * + - . ^ _ ` | ~
///
/// They must NOT contain:
/// - Control characters (including CRLF)
/// - Separators like : ; , = ( ) < > @ " [ ] { } ? / \ space tab
fn validate_priority_token(token: &str) -> Result<(), PriorityError> {
    // Check if empty
    if token.is_empty() {
        return Err(PriorityError::Empty);
    }

    // Check length
    if token.len() > MAX_PRIORITY_LENGTH {
        return Err(PriorityError::TooLong {
            max: MAX_PRIORITY_LENGTH,
            actual: token.len(),
        });
    }

    // Check for control characters (including CRLF)
    if token.chars().any(|c| c.is_ascii_control()) {
        return Err(PriorityError::ContainsControlChars);
    }

    // Check for valid token characters per RFC 3261
    // Valid: alphanumeric + ! % ' * + - . ^ _ ` | ~
    if !token.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '%' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
            )
    }) {
        return Err(PriorityError::InvalidCharacters(
            "contains invalid characters for priority token".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_priorities() {
        assert_eq!(PriorityValue::Emergency.as_str(), "emergency");
        assert_eq!(PriorityValue::Urgent.as_str(), "urgent");
        assert_eq!(PriorityValue::Normal.as_str(), "normal");
        assert_eq!(PriorityValue::NonUrgent.as_str(), "non-urgent");
    }

    #[test]
    fn parse_standard_priorities() {
        assert_eq!(
            PriorityValue::parse("emergency").unwrap(),
            PriorityValue::Emergency
        );
        assert_eq!(
            PriorityValue::parse("urgent").unwrap(),
            PriorityValue::Urgent
        );
        assert_eq!(
            PriorityValue::parse("normal").unwrap(),
            PriorityValue::Normal
        );
        assert_eq!(
            PriorityValue::parse("non-urgent").unwrap(),
            PriorityValue::NonUrgent
        );
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(
            PriorityValue::parse("EMERGENCY").unwrap(),
            PriorityValue::Emergency
        );
        assert_eq!(
            PriorityValue::parse("Urgent").unwrap(),
            PriorityValue::Urgent
        );
        assert_eq!(
            PriorityValue::parse("NORMAL").unwrap(),
            PriorityValue::Normal
        );
    }

    #[test]
    fn extension_priorities() {
        let high = PriorityValue::parse("high").unwrap();
        assert_eq!(high.as_str(), "high");
        assert!(high.is_extension());
        assert!(!high.is_standard());

        let low = PriorityValue::parse("low").unwrap();
        assert_eq!(low.as_str(), "low");
    }

    #[test]
    fn extension_priority_normalized() {
        // Extension priorities are stored in lowercase
        let priority = PriorityValue::parse("HIGH").unwrap();
        assert_eq!(priority.as_str(), "high");
    }

    #[test]
    fn reject_empty_priority() {
        let result = PriorityValue::parse("");
        assert!(matches!(result, Err(PriorityError::Empty)));
    }

    #[test]
    fn reject_crlf_injection() {
        let result = PriorityValue::parse("urgent\r\nInjected: evil");
        assert!(matches!(result, Err(PriorityError::ContainsControlChars)));
    }

    #[test]
    fn reject_null_byte() {
        let result = PriorityValue::parse("urgent\0evil");
        assert!(matches!(result, Err(PriorityError::ContainsControlChars)));
    }

    #[test]
    fn reject_control_characters() {
        let result = PriorityValue::parse("urgent\x01\x02");
        assert!(matches!(result, Err(PriorityError::ContainsControlChars)));

        let result = PriorityValue::parse("urgent\ttab");
        assert!(matches!(result, Err(PriorityError::ContainsControlChars)));
    }

    #[test]
    fn reject_oversized_priority() {
        let long_priority = "x".repeat(MAX_PRIORITY_LENGTH + 1);
        let result = PriorityValue::parse(&long_priority);
        assert!(matches!(result, Err(PriorityError::TooLong { .. })));
    }

    #[test]
    fn reject_invalid_characters() {
        // Space is not allowed
        let result = PriorityValue::parse("very urgent");
        assert!(matches!(result, Err(PriorityError::InvalidCharacters(_))));

        // Colon is not allowed
        let result = PriorityValue::parse("urgent:high");
        assert!(matches!(result, Err(PriorityError::InvalidCharacters(_))));

        // Semicolon is not allowed
        let result = PriorityValue::parse("urgent;high");
        assert!(matches!(result, Err(PriorityError::InvalidCharacters(_))));
    }

    #[test]
    fn accept_valid_token_characters() {
        // All valid token characters should be accepted
        assert!(PriorityValue::parse("priority-value.test").is_ok());
        assert!(PriorityValue::parse("priority_value").is_ok());
        assert!(PriorityValue::parse("priority+value").is_ok());
    }

    #[test]
    fn urgency_levels() {
        assert_eq!(PriorityValue::Emergency.urgency_level(), Some(3));
        assert_eq!(PriorityValue::Urgent.urgency_level(), Some(2));
        assert_eq!(PriorityValue::Normal.urgency_level(), Some(1));
        assert_eq!(PriorityValue::NonUrgent.urgency_level(), Some(0));

        let custom = PriorityValue::parse("high").unwrap();
        assert_eq!(custom.urgency_level(), None);
    }

    #[test]
    fn is_standard() {
        assert!(PriorityValue::Emergency.is_standard());
        assert!(PriorityValue::Urgent.is_standard());
        assert!(PriorityValue::Normal.is_standard());
        assert!(PriorityValue::NonUrgent.is_standard());

        let custom = PriorityValue::parse("high").unwrap();
        assert!(!custom.is_standard());
        assert!(custom.is_extension());
    }

    #[test]
    fn default_value() {
        assert_eq!(PriorityValue::default(), PriorityValue::Normal);
    }

    #[test]
    fn display_trait() {
        assert_eq!(PriorityValue::Emergency.to_string(), "emergency");
        assert_eq!(PriorityValue::Urgent.to_string(), "urgent");

        let custom = PriorityValue::parse("high").unwrap();
        assert_eq!(custom.to_string(), "high");
    }

    #[test]
    fn from_str_trait() {
        assert_eq!(
            PriorityValue::parse("emergency").unwrap(),
            PriorityValue::Emergency
        );
        assert!(PriorityValue::parse("urgent\r\n").is_err());
    }

    #[test]
    fn parse_trait() {
        let parsed: PriorityValue = "urgent".parse().unwrap();
        assert_eq!(parsed, PriorityValue::Urgent);
    }

    #[test]
    fn edge_case_exact_max_length() {
        // Exactly MAX_PRIORITY_LENGTH should succeed
        let max_len = "p".repeat(MAX_PRIORITY_LENGTH);
        assert!(PriorityValue::parse(&max_len).is_ok());

        // One more should fail
        let over_max = "p".repeat(MAX_PRIORITY_LENGTH + 1);
        assert!(PriorityValue::parse(&over_max).is_err());
    }

    #[test]
    fn hash_and_eq() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(PriorityValue::Urgent);
        set.insert(PriorityValue::parse("urgent").unwrap());

        // Should only have one entry (they're equal)
        assert_eq!(set.len(), 1);
    }
}
