// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

const MAX_METHOD_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodError {
    TooLong { max: usize, actual: usize },
    Empty,
    InvalidCharacters(String),
    ContainsControlChars,
}

impl std::fmt::Display for MethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { max, actual } =>
                write!(f, "method too long (max {}, got {})", max, actual),
            Self::Empty =>
                write!(f, "method cannot be empty"),
            Self::InvalidCharacters(msg) =>
                write!(f, "invalid method characters: {}", msg),
            Self::ContainsControlChars =>
                write!(f, "method contains control characters"),
        }
    }
}

impl std::error::Error for MethodError {}

/// SIP request methods supported by the stack.
///
/// Per RFC 3261, method names are tokens and are case-insensitive.
/// This enum represents the standard SIP methods plus extension methods.
///
/// # Security
///
/// Method validates extension method names to prevent:
/// - CRLF injection attacks
/// - Control character injection
/// - Excessive length (DoS)
/// - Invalid token characters
///
/// # Examples
///
/// ```
/// use sip_core::Method;
///
/// let method = Method::from_token("INVITE").unwrap();
/// assert_eq!(method.as_str(), "INVITE");
///
/// let custom = Method::from_token("CUSTOMMETHOD").unwrap();
/// assert_eq!(custom.as_str(), "CUSTOMMETHOD");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// RFC 3261 - Initiates a session
    Invite,
    /// RFC 3261 - Acknowledges INVITE
    Ack,
    /// RFC 3261 - Terminates a session
    Bye,
    /// RFC 3261 - Cancels a pending request
    Cancel,
    /// RFC 3261 - Registers a contact
    Register,
    /// RFC 3261 - Queries capabilities
    Options,
    /// RFC 6086 - Mid-session information
    Info,
    /// RFC 3311 - Updates session parameters
    Update,
    /// RFC 3428 - Instant message
    Message,
    /// RFC 3262 - Provisional response acknowledgement
    Prack,
    /// RFC 3515 - Call transfer
    Refer,
    /// RFC 6665 - Event subscription
    Subscribe,
    /// RFC 6665 - Event notification
    Notify,
    /// RFC 3903 - Publish event state
    Publish,
    /// Extension method (validated)
    Unknown(SmolStr),
}

impl Method {
    /// Returns the canonical uppercase string representation for this method.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Register => "REGISTER",
            Self::Options => "OPTIONS",
            Self::Info => "INFO",
            Self::Update => "UPDATE",
            Self::Message => "MESSAGE",
            Self::Prack => "PRACK",
            Self::Refer => "REFER",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Publish => "PUBLISH",
            Self::Unknown(token) => token.as_str(),
        }
    }

    /// Parses a method token with validation.
    ///
    /// Standard SIP methods are recognized case-insensitively and returned
    /// as the appropriate enum variant. Extension methods are validated and
    /// stored as Unknown.
    ///
    /// # Security
    ///
    /// Extension method names are validated to ensure:
    /// - Length is within limits (max 32 characters)
    /// - No control characters (including CRLF)
    /// - Only valid RFC 3261 token characters
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method name is empty
    /// - Method name is too long
    /// - Method name contains control characters
    /// - Method name contains invalid characters for a token
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::Method;
    ///
    /// // Standard methods
    /// assert!(Method::from_token("INVITE").is_ok());
    /// assert!(Method::from_token("invite").is_ok()); // case-insensitive
    ///
    /// // Extension methods
    /// assert!(Method::from_token("CUSTOMMETHOD").is_ok());
    ///
    /// // Invalid methods
    /// assert!(Method::from_token("GET\r\nInjected").is_err());
    /// assert!(Method::from_token("").is_err());
    /// ```
    pub fn from_token(token: &str) -> Result<Self, MethodError> {
        // Check for known methods first (case-insensitive)
        if token.eq_ignore_ascii_case("INVITE") {
            return Ok(Self::Invite);
        } else if token.eq_ignore_ascii_case("ACK") {
            return Ok(Self::Ack);
        } else if token.eq_ignore_ascii_case("BYE") {
            return Ok(Self::Bye);
        } else if token.eq_ignore_ascii_case("CANCEL") {
            return Ok(Self::Cancel);
        } else if token.eq_ignore_ascii_case("REGISTER") {
            return Ok(Self::Register);
        } else if token.eq_ignore_ascii_case("OPTIONS") {
            return Ok(Self::Options);
        } else if token.eq_ignore_ascii_case("INFO") {
            return Ok(Self::Info);
        } else if token.eq_ignore_ascii_case("UPDATE") {
            return Ok(Self::Update);
        } else if token.eq_ignore_ascii_case("MESSAGE") {
            return Ok(Self::Message);
        } else if token.eq_ignore_ascii_case("PRACK") {
            return Ok(Self::Prack);
        } else if token.eq_ignore_ascii_case("REFER") {
            return Ok(Self::Refer);
        } else if token.eq_ignore_ascii_case("SUBSCRIBE") {
            return Ok(Self::Subscribe);
        } else if token.eq_ignore_ascii_case("NOTIFY") {
            return Ok(Self::Notify);
        } else if token.eq_ignore_ascii_case("PUBLISH") {
            return Ok(Self::Publish);
        }

        // Validate extension method
        validate_method_token(token)?;
        
        // Store in uppercase for consistency
        Ok(Self::Unknown(SmolStr::new(token.to_ascii_uppercase())))
    }

    /// Returns true if this is a known standard SIP method.
    pub fn is_standard(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    /// Returns true if this is an extension method.
    pub fn is_extension(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    /// Returns true if this method is idempotent per RFC 3261.
    ///
    /// Per RFC 3261, ACK, BYE, CANCEL, OPTIONS, and REGISTER are idempotent.
    pub fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Ack | Self::Bye | Self::Cancel | Self::Options | Self::Register
        )
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Method {
    type Err = MethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_token(s)
    }
}

/// Validates a method token per RFC 3261.
///
/// Method names must be tokens, which consist of:
/// - Alphanumeric characters
/// - Special characters: ! % ' * + - . ^ _ ` | ~
///
/// They must NOT contain:
/// - Control characters (including CRLF)
/// - Separators like : ; , = ( ) < > @ " [ ] { } ? / \ space tab
fn validate_method_token(token: &str) -> Result<(), MethodError> {
    // Check if empty
    if token.is_empty() {
        return Err(MethodError::Empty);
    }

    // Check length
    if token.len() > MAX_METHOD_LENGTH {
        return Err(MethodError::TooLong {
            max: MAX_METHOD_LENGTH,
            actual: token.len(),
        });
    }

    // Check for control characters (including CRLF)
    if token.chars().any(|c| c.is_ascii_control()) {
        return Err(MethodError::ContainsControlChars);
    }

    // Check for valid token characters per RFC 3261
    // Valid: alphanumeric + ! % ' * + - . ^ _ ` | ~
    if !token.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        matches!(c, '!' | '%' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~')
    }) {
        return Err(MethodError::InvalidCharacters(
            "contains invalid characters for method token".to_string()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_methods() {
        assert_eq!(Method::from_token("INVITE").unwrap(), Method::Invite);
        assert_eq!(Method::from_token("ACK").unwrap(), Method::Ack);
        assert_eq!(Method::from_token("BYE").unwrap(), Method::Bye);
        assert_eq!(Method::from_token("CANCEL").unwrap(), Method::Cancel);
        assert_eq!(Method::from_token("REGISTER").unwrap(), Method::Register);
        assert_eq!(Method::from_token("OPTIONS").unwrap(), Method::Options);
        assert_eq!(Method::from_token("INFO").unwrap(), Method::Info);
        assert_eq!(Method::from_token("UPDATE").unwrap(), Method::Update);
        assert_eq!(Method::from_token("MESSAGE").unwrap(), Method::Message);
        assert_eq!(Method::from_token("PRACK").unwrap(), Method::Prack);
        assert_eq!(Method::from_token("REFER").unwrap(), Method::Refer);
        assert_eq!(Method::from_token("SUBSCRIBE").unwrap(), Method::Subscribe);
        assert_eq!(Method::from_token("NOTIFY").unwrap(), Method::Notify);
        assert_eq!(Method::from_token("PUBLISH").unwrap(), Method::Publish);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(Method::from_token("invite").unwrap(), Method::Invite);
        assert_eq!(Method::from_token("Invite").unwrap(), Method::Invite);
        assert_eq!(Method::from_token("INVITE").unwrap(), Method::Invite);
        assert_eq!(Method::from_token("InViTe").unwrap(), Method::Invite);
    }

    #[test]
    fn extension_methods() {
        let method = Method::from_token("CUSTOMMETHOD").unwrap();
        assert_eq!(method.as_str(), "CUSTOMMETHOD");
        assert!(method.is_extension());
        assert!(!method.is_standard());
    }

    #[test]
    fn extension_method_normalized() {
        // Extension methods are stored in uppercase
        let method = Method::from_token("custommethod").unwrap();
        assert_eq!(method.as_str(), "CUSTOMMETHOD");
    }

    #[test]
    fn reject_empty_method() {
        let result = Method::from_token("");
        assert!(matches!(result, Err(MethodError::Empty)));
    }

    #[test]
    fn reject_crlf_injection() {
        let result = Method::from_token("GET\r\nInjected: evil");
        assert!(matches!(result, Err(MethodError::ContainsControlChars)));
    }

    #[test]
    fn reject_null_byte() {
        let result = Method::from_token("GET\0evil");
        assert!(matches!(result, Err(MethodError::ContainsControlChars)));
    }

    #[test]
    fn reject_control_characters() {
        let result = Method::from_token("GET\x01\x02");
        assert!(matches!(result, Err(MethodError::ContainsControlChars)));
        
        let result = Method::from_token("GET\ttab");
        assert!(matches!(result, Err(MethodError::ContainsControlChars)));
    }

    #[test]
    fn reject_oversized_method() {
        let long_method = "x".repeat(MAX_METHOD_LENGTH + 1);
        let result = Method::from_token(&long_method);
        assert!(matches!(result, Err(MethodError::TooLong { .. })));
    }

    #[test]
    fn reject_invalid_characters() {
        // Space is not allowed
        let result = Method::from_token("GET STUFF");
        assert!(matches!(result, Err(MethodError::InvalidCharacters(_))));
        
        // Colon is not allowed
        let result = Method::from_token("GET:STUFF");
        assert!(matches!(result, Err(MethodError::InvalidCharacters(_))));
        
        // Semicolon is not allowed
        let result = Method::from_token("GET;STUFF");
        assert!(matches!(result, Err(MethodError::InvalidCharacters(_))));
        
        // Angle brackets are not allowed
        let result = Method::from_token("GET<STUFF>");
        assert!(matches!(result, Err(MethodError::InvalidCharacters(_))));
    }

    #[test]
    fn accept_valid_token_characters() {
        // All valid token characters should be accepted
        assert!(Method::from_token("METHOD-WITH.DASH!AND%MORE").is_ok());
        assert!(Method::from_token("METHOD_WITH_UNDERSCORE").is_ok());
        assert!(Method::from_token("METHOD+PLUS").is_ok());
    }

    #[test]
    fn method_as_str() {
        assert_eq!(Method::Invite.as_str(), "INVITE");
        assert_eq!(Method::Ack.as_str(), "ACK");
        
        let custom = Method::from_token("CUSTOMMETHOD").unwrap();
        assert_eq!(custom.as_str(), "CUSTOMMETHOD");
    }

    #[test]
    fn method_display() {
        assert_eq!(Method::Invite.to_string(), "INVITE");
        assert_eq!(Method::Bye.to_string(), "BYE");
        
        let custom = Method::from_token("CUSTOM").unwrap();
        assert_eq!(custom.to_string(), "CUSTOM");
    }

    #[test]
    fn method_from_str_trait() {
        use std::str::FromStr;
        
        assert_eq!(Method::from_str("INVITE").unwrap(), Method::Invite);
        assert!(Method::from_str("INVALID\r\n").is_err());
    }

    #[test]
    fn is_standard() {
        assert!(Method::Invite.is_standard());
        assert!(Method::Register.is_standard());
        
        let custom = Method::from_token("CUSTOM").unwrap();
        assert!(!custom.is_standard());
        assert!(custom.is_extension());
    }

    #[test]
    fn is_idempotent() {
        assert!(Method::Ack.is_idempotent());
        assert!(Method::Bye.is_idempotent());
        assert!(Method::Cancel.is_idempotent());
        assert!(Method::Options.is_idempotent());
        assert!(Method::Register.is_idempotent());
        
        assert!(!Method::Invite.is_idempotent());
        assert!(!Method::Subscribe.is_idempotent());
    }

    #[test]
    fn edge_case_exact_max_length() {
        // Exactly MAX_METHOD_LENGTH should succeed
        let max_len = "M".repeat(MAX_METHOD_LENGTH);
        assert!(Method::from_token(&max_len).is_ok());
        
        // One more should fail
        let over_max = "M".repeat(MAX_METHOD_LENGTH + 1);
        assert!(Method::from_token(&over_max).is_err());
    }

    #[test]
    fn hash_and_eq() {
        use std::collections::HashSet;
        
        let mut set = HashSet::new();
        set.insert(Method::Invite);
        set.insert(Method::from_token("INVITE").unwrap());
        
        // Should only have one entry (they're equal)
        assert_eq!(set.len(), 1);
    }
}