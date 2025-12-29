// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Token list headers (RFC 3261) with security hardening.
//!
//! Provides secure handling of comma-separated token lists used in various
//! SIP headers like Allow, Supported, Require, Proxy-Require, and Unsupported.
//!
//! # Security
//!
//! Token lists are validated for:
//! - Maximum token count to prevent DoS attacks
//! - Token length limits
//! - Valid token characters per RFC 3261
//! - No control characters (prevents CRLF injection)
//!
//! # Token Format (RFC 3261)
//!
//! ```text
//! token = 1*(alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~")
//! ```
//!
//! # Examples
//!
//! ```
//! use sip_core::{TokenList, AllowHeader};
//!
//! // Parse Allow header
//! let allow = AllowHeader::parse("INVITE, ACK, OPTIONS, CANCEL, BYE").unwrap();
//! assert_eq!(allow.tokens().len(), 5);
//! assert!(allow.contains("INVITE"));
//!
//! // Create programmatically
//! let supported = TokenList::from_tokens(vec!["timer", "100rel"]).unwrap();
//! assert_eq!(supported.to_string(), "timer, 100rel");
//! ```

use smol_str::SmolStr;
use std::fmt;

// Security: Collection bounds
const MAX_TOKENS: usize = 50;
const MAX_TOKEN_LENGTH: usize = 64;

/// Error types for token list operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenListError {
    /// Token validation error
    InvalidToken(String),
    /// Too many tokens
    TooManyTokens { max: usize },
    /// Token too long
    TokenTooLong { max: usize },
    /// Empty token list
    Empty,
}

impl fmt::Display for TokenListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenListError::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
            TokenListError::TooManyTokens { max } => write!(f, "Too many tokens (max {})", max),
            TokenListError::TokenTooLong { max } => write!(f, "Token too long (max {})", max),
            TokenListError::Empty => write!(f, "Token list cannot be empty"),
        }
    }
}

impl std::error::Error for TokenListError {}

/// Validates a token per RFC 3261 token format.
fn validate_token(token: &str) -> Result<(), TokenListError> {
    if token.is_empty() {
        return Err(TokenListError::InvalidToken("token cannot be empty".to_string()));
    }

    if token.len() > MAX_TOKEN_LENGTH {
        return Err(TokenListError::TokenTooLong {
            max: MAX_TOKEN_LENGTH,
        });
    }

    // RFC 3261 token: 1*(alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~")
    for c in token.chars() {
        if !is_valid_token_char(c) {
            return Err(TokenListError::InvalidToken(format!(
                "contains invalid character: '{}'",
                c
            )));
        }
    }

    Ok(())
}

/// Checks if a character is valid in a token per RFC 3261.
fn is_valid_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

/// Represents comma-separated token header values (Allow/Supported/etc.).
///
/// # Security
///
/// TokenList enforces:
/// - Maximum of 50 tokens per list
/// - Maximum of 64 characters per token
/// - Valid token format per RFC 3261
/// - No control characters (prevents CRLF injection)
///
/// # Examples
///
/// ```
/// use sip_core::TokenList;
///
/// // Parse from comma-separated string
/// let list = TokenList::parse("INVITE, ACK, CANCEL").unwrap();
/// assert_eq!(list.tokens().len(), 3);
///
/// // Create from vector
/// let list = TokenList::from_tokens(vec!["timer", "100rel"]).unwrap();
/// assert!(list.contains("timer"));
///
/// // Add token
/// let list = TokenList::new()
///     .with_token("INVITE").unwrap()
///     .with_token("ACK").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenList {
    tokens: Vec<SmolStr>,
}

impl TokenList {
    /// Creates an empty token list.
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Creates a token list from a vector of tokens with validation.
    ///
    /// # Errors
    ///
    /// Returns `TokenListError` if:
    /// - Any token is invalid
    /// - Too many tokens
    /// - Any token is too long
    pub fn from_tokens<I, S>(tokens: I) -> Result<Self, TokenListError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut result = Vec::new();

        for token in tokens {
            if result.len() >= MAX_TOKENS {
                return Err(TokenListError::TooManyTokens { max: MAX_TOKENS });
            }

            let token_str = token.as_ref();
            validate_token(token_str)?;
            result.push(SmolStr::new(token_str));
        }

        Ok(Self { tokens: result })
    }

    /// Creates a token list from a slice of tokens with validation.
    ///
    /// Convenience method for creating from string slices.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::TokenList;
    ///
    /// let tokens = ["INVITE", "ACK", "BYE"];
    /// let list = TokenList::from_slice(&tokens).unwrap();
    /// assert_eq!(list.len(), 3);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `TokenListError` if:
    /// - Any token is invalid
    /// - Too many tokens
    /// - Any token is too long
    pub fn from_slice(tokens: &[&str]) -> Result<Self, TokenListError> {
        Self::from_tokens(tokens.iter().copied())
    }

    /// Parses a token list from a comma-separated string.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::TokenList;
    ///
    /// let list = TokenList::parse("INVITE, ACK, OPTIONS").unwrap();
    /// assert_eq!(list.tokens().len(), 3);
    /// assert!(list.contains("INVITE"));
    /// ```
    pub fn parse(input: &str) -> Result<Self, TokenListError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(TokenListError::Empty);
        }

        let tokens: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        Self::from_tokens(tokens)
    }

    /// Gets the tokens as a slice.
    pub fn tokens(&self) -> &[SmolStr] {
        &self.tokens
    }

    /// Returns the number of tokens.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns true if the token list is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Checks if the list contains a specific token (case-insensitive).
    pub fn contains(&self, token: &str) -> bool {
        self.tokens
            .iter()
            .any(|t| t.eq_ignore_ascii_case(token))
    }

    /// Adds a token to the list with validation.
    pub fn add_token(&mut self, token: &str) -> Result<(), TokenListError> {
        if self.tokens.len() >= MAX_TOKENS {
            return Err(TokenListError::TooManyTokens { max: MAX_TOKENS });
        }

        let token_str = token.trim();
        validate_token(token_str)?;
        self.tokens.push(SmolStr::new(token_str));
        Ok(())
    }

    /// Adds a token (builder pattern).
    pub fn with_token(mut self, token: &str) -> Result<Self, TokenListError> {
        self.add_token(token)?;
        Ok(self)
    }

    /// Returns an iterator over the tokens.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().map(|s| s.as_str())
    }
}

impl Default for TokenList {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TokenList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, token) in self.tokens.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", token)?;
        }
        Ok(())
    }
}

/// Allow header - lists supported SIP methods (RFC 3261 §20.5).
///
/// Used in: `Allow` header
///
/// Indicates the set of methods supported by the User Agent (UA) generating
/// the message. All methods listed MUST be supported by the UA. An OPTIONS
/// request typically includes an Allow header with all supported methods.
///
/// # Example
///
/// ```
/// use sip_core::AllowHeader;
///
/// let allow = AllowHeader::parse("INVITE, ACK, OPTIONS, CANCEL, BYE").unwrap();
/// assert!(allow.contains("INVITE"));
/// ```
pub type AllowHeader = TokenList;

/// Supported header - lists supported SIP extensions (RFC 3261 §20.37).
///
/// Used in: `Supported` header (also known as `k` in compact form)
///
/// Enumerates all the extensions supported by the UAC or UAS. An option tag
/// listed here means the UA understands the extension. Common values include:
/// - `100rel` - PRACK (RFC 3262)
/// - `timer` - Session Timers (RFC 4028)
/// - `replaces` - Call Transfer (RFC 3891)
/// - `path` - Path header (RFC 3327)
///
/// # Example
///
/// ```
/// use sip_core::SupportedHeader;
///
/// let supported = SupportedHeader::parse("timer, 100rel").unwrap();
/// assert!(supported.contains("timer"));
/// ```
pub type SupportedHeader = TokenList;

/// Require header - lists required SIP extensions (RFC 3261 §20.32).
///
/// Used in: `Require` header
///
/// Used by UACs to tell UASs about options that the UAC expects the UAS to
/// support. If a UAS does not understand an option tag listed in Require,
/// it MUST respond with 420 (Bad Extension) and include an Unsupported header
/// listing the unsupported option tags.
///
/// # Example
///
/// ```
/// use sip_core::RequireHeader;
///
/// let require = RequireHeader::from_tokens(vec!["100rel"]).unwrap();
/// assert!(require.contains("100rel"));
/// ```
pub type RequireHeader = TokenList;

/// Proxy-Require header - lists required proxy SIP extensions (RFC 3261 §20.29).
///
/// Used in: `Proxy-Require` header
///
/// Used to indicate proxy-sensitive features that MUST be supported by the
/// proxy. If a proxy does not understand an option tag listed here, it MUST
/// respond with 420 (Bad Extension) and include an Unsupported header.
///
/// # Example
///
/// ```
/// use sip_core::ProxyRequireHeader;
///
/// let proxy_require = ProxyRequireHeader::from_slice(&["path"]).unwrap();
/// assert!(proxy_require.contains("path"));
/// ```
pub type ProxyRequireHeader = TokenList;

/// Unsupported header - lists unsupported SIP extensions (RFC 3261 §20.40).
///
/// Used in: `Unsupported` header
///
/// Lists the features not supported by the UAS. This header is used in
/// 420 (Bad Extension) responses to indicate which option tags from the
/// Require or Proxy-Require headers are not supported.
///
/// # Example
///
/// ```
/// use sip_core::UnsupportedHeader;
///
/// let unsupported = UnsupportedHeader::from_slice(&["unknown-feature"]).unwrap();
/// assert!(unsupported.contains("unknown-feature"));
/// ```
pub type UnsupportedHeader = TokenList;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_list_basic() {
        let list = TokenList::from_tokens(vec!["INVITE", "ACK", "BYE"]).unwrap();
        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
        assert!(list.contains("INVITE"));
        assert!(list.contains("invite")); // case-insensitive
    }

    #[test]
    fn token_list_from_slice() {
        let tokens = ["INVITE", "ACK", "BYE"];
        let list = TokenList::from_slice(&tokens).unwrap();
        assert_eq!(list.len(), 3);
        assert!(list.contains("INVITE"));
        assert!(list.contains("ACK"));
        assert!(list.contains("BYE"));
    }

    #[test]
    fn token_list_from_slice_validates() {
        // Should reject invalid tokens
        let invalid = ["INVITE", "IN\r\nVALID"];
        assert!(TokenList::from_slice(&invalid).is_err());

        // Should reject too many
        let many: Vec<&str> = (0..=MAX_TOKENS).map(|_| "token").collect();
        let slice: Vec<&str> = many.iter().copied().collect();
        assert!(TokenList::from_slice(&slice).is_err());
    }

    #[test]
    fn token_list_parse() {
        let list = TokenList::parse("INVITE, ACK, OPTIONS, CANCEL, BYE").unwrap();
        assert_eq!(list.len(), 5);
        assert!(list.contains("OPTIONS"));
    }

    #[test]
    fn token_list_parse_with_whitespace() {
        let list = TokenList::parse("  INVITE  ,  ACK  ,  BYE  ").unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list.tokens()[0].as_str(), "INVITE");
    }

    #[test]
    fn token_list_display() {
        let list = TokenList::from_tokens(vec!["INVITE", "ACK", "BYE"]).unwrap();
        assert_eq!(list.to_string(), "INVITE, ACK, BYE");
    }

    #[test]
    fn token_list_rejects_too_many() {
        let tokens: Vec<String> = (0..=MAX_TOKENS).map(|i| format!("token{}", i)).collect();
        assert!(TokenList::from_tokens(tokens).is_err());
    }

    #[test]
    fn token_list_rejects_too_long_token() {
        let long_token = "x".repeat(MAX_TOKEN_LENGTH + 1);
        assert!(TokenList::from_tokens(vec![long_token.as_str()]).is_err());
    }

    #[test]
    fn token_list_accepts_max_length_token() {
        let max_token = "x".repeat(MAX_TOKEN_LENGTH);
        assert!(TokenList::from_tokens(vec![max_token.as_str()]).is_ok());
    }

    #[test]
    fn token_list_rejects_empty_token() {
        assert!(TokenList::from_tokens(vec![""]).is_err());
        assert!(TokenList::from_tokens(vec!["INVITE", "", "ACK"]).is_err());
    }

    #[test]
    fn token_list_rejects_invalid_chars() {
        // Spaces
        assert!(TokenList::from_tokens(vec!["INVITE ACK"]).is_err());
        
        // Control characters
        assert!(TokenList::from_tokens(vec!["INVITE\r\n"]).is_err());
        assert!(TokenList::from_tokens(vec!["IN\x00VITE"]).is_err());
        
        // Commas (these are separators, not part of tokens)
        assert!(TokenList::from_tokens(vec!["INVITE,ACK"]).is_err());
        
        // Other invalid chars
        assert!(TokenList::from_tokens(vec!["INVITE@HOME"]).is_err());
        assert!(TokenList::from_tokens(vec!["INVITE#123"]).is_err());
    }

    #[test]
    fn token_list_accepts_valid_chars() {
        // Alphanumeric
        assert!(TokenList::from_tokens(vec!["INVITE123"]).is_ok());
        
        // Valid special chars per RFC 3261
        assert!(TokenList::from_tokens(vec!["timer-draft"]).is_ok());
        assert!(TokenList::from_tokens(vec!["ext.v1"]).is_ok());
        assert!(TokenList::from_tokens(vec!["100rel"]).is_ok());
        assert!(TokenList::from_tokens(vec!["test_ext"]).is_ok());
    }

    #[test]
    fn token_list_add_token() {
        let mut list = TokenList::new();
        assert!(list.is_empty());
        
        list.add_token("INVITE").unwrap();
        list.add_token("ACK").unwrap();
        
        assert_eq!(list.len(), 2);
        assert!(list.contains("INVITE"));
    }

    #[test]
    fn token_list_add_token_rejects_when_full() {
        let mut list = TokenList::new();
        for i in 0..MAX_TOKENS {
            list.add_token(&format!("token{}", i)).unwrap();
        }
        
        assert!(list.add_token("extra").is_err());
    }

    #[test]
    fn token_list_with_token_builder() {
        let list = TokenList::new()
            .with_token("INVITE").unwrap()
            .with_token("ACK").unwrap()
            .with_token("BYE").unwrap();
        
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn token_list_iter() {
        let list = TokenList::from_tokens(vec!["INVITE", "ACK", "BYE"]).unwrap();
        let collected: Vec<&str> = list.iter().collect();
        assert_eq!(collected, vec!["INVITE", "ACK", "BYE"]);
    }

    #[test]
    fn token_list_case_insensitive_contains() {
        let list = TokenList::from_tokens(vec!["InViTe", "AcK"]).unwrap();
        assert!(list.contains("INVITE"));
        assert!(list.contains("invite"));
        assert!(list.contains("ack"));
        assert!(list.contains("ACK"));
    }

    #[test]
    fn allow_header() {
        let allow: AllowHeader = AllowHeader::parse("INVITE, ACK, OPTIONS, CANCEL, BYE").unwrap();
        assert_eq!(allow.len(), 5);
        assert!(allow.contains("INVITE"));
        assert!(allow.contains("OPTIONS"));
    }

    #[test]
    fn supported_header() {
        let supported: SupportedHeader = SupportedHeader::parse("timer, 100rel").unwrap();
        assert_eq!(supported.len(), 2);
        assert!(supported.contains("timer"));
        assert!(supported.contains("100rel"));
    }

    #[test]
    fn require_header() {
        let require: RequireHeader = RequireHeader::from_tokens(vec!["100rel"]).unwrap();
        assert!(require.contains("100rel"));
    }

    #[test]
    fn token_list_default() {
        let list = TokenList::default();
        assert!(list.is_empty());
    }

    #[test]
    fn token_list_equality() {
        let list1 = TokenList::from_tokens(vec!["INVITE", "ACK"]).unwrap();
        let list2 = TokenList::from_tokens(vec!["INVITE", "ACK"]).unwrap();
        let list3 = TokenList::from_tokens(vec!["INVITE", "BYE"]).unwrap();
        
        assert_eq!(list1, list2);
        assert_ne!(list1, list3);
    }

    #[test]
    fn token_list_clone() {
        let list1 = TokenList::from_tokens(vec!["INVITE", "ACK"]).unwrap();
        let list2 = list1.clone();
        assert_eq!(list1, list2);
    }

    #[test]
    fn field_is_private() {
        let list = TokenList::from_tokens(vec!["INVITE"]).unwrap();
        
        // This should compile (read access via getter)
        let _ = list.tokens();
        
        // This should NOT compile:
        // list.tokens = vec![];                     // ← Does not compile!
        // list.tokens.push(SmolStr::new("evil"));   // ← Does not compile!
    }

    #[test]
    fn round_trip() {
        let original = "INVITE, ACK, OPTIONS, CANCEL, BYE";
        let list = TokenList::parse(original).unwrap();
        let formatted = list.to_string();
        let reparsed = TokenList::parse(&formatted).unwrap();
        
        assert_eq!(list, reparsed);
    }

    #[test]
    fn error_display() {
        let err1 = TokenListError::Empty;
        assert_eq!(err1.to_string(), "Token list cannot be empty");
        
        let err2 = TokenListError::TooManyTokens { max: 50 };
        assert_eq!(err2.to_string(), "Too many tokens (max 50)");
        
        let err3 = TokenListError::TokenTooLong { max: 64 };
        assert_eq!(err3.to_string(), "Token too long (max 64)");
    }

    #[test]
    fn parse_single_token() {
        let list = TokenList::parse("INVITE").unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains("INVITE"));
    }

    #[test]
    fn parse_empty_tokens_between_commas() {
        // "INVITE,,ACK" should be rejected due to empty token
        assert!(TokenList::parse("INVITE,,ACK").is_err());
    }
}
