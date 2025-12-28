// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::Headers;

const MAX_BRANCH_LENGTH: usize = 256;
const MAGIC_COOKIE: &str = "z9hG4bK";
const MIN_BRANCH_LENGTH: usize = MAGIC_COOKIE.len() + 1; // cookie + at least one char

/// Errors returned when attempting to adjust Max-Forwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaxForwardsError {
    /// Max-Forwards has reached zero and cannot be decremented further
    Exhausted,
    /// Max-Forwards value is not a valid number
    Invalid,
}

impl std::fmt::Display for MaxForwardsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted => write!(f, "Max-Forwards exhausted (reached 0)"),
            Self::Invalid => write!(f, "Invalid Max-Forwards value"),
        }
    }
}

impl std::error::Error for MaxForwardsError {}

/// Decrements Max-Forwards per RFC 3261 §8.1.1.6.
///
/// Per RFC 3261, proxies and redirect servers MUST decrement the Max-Forwards
/// header field value before forwarding the request. If the received Max-Forwards
/// value is zero, the proxy MUST NOT forward the request.
///
/// If no Max-Forwards header is present, this function inserts one with the
/// default value of 70, then decrements it to 69.
///
/// # Security
///
/// Validates the Max-Forwards value to ensure it is a valid u32 number.
///
/// # Examples
///
/// ```
/// use sip_core::{Headers, decrement_max_forwards};
///
/// let mut headers = Headers::new();
/// headers.push("Max-Forwards", "70").unwrap();
///
/// let remaining = decrement_max_forwards(&mut headers).unwrap();
/// assert_eq!(remaining, 69);
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Max-Forwards is already 0 (exhausted)
/// - Max-Forwards contains an invalid value
pub fn decrement_max_forwards(headers: &mut Headers) -> Result<u32, MaxForwardsError> {
    if let Some(value) = headers.get("Max-Forwards") {
        // Parse the current value
        let value = value.trim();
        let current = value
            .parse::<u32>()
            .map_err(|_| MaxForwardsError::Invalid)?;
        
        // Check if exhausted
        if current == 0 {
            return Err(MaxForwardsError::Exhausted);
        }
        
        // Decrement (using saturating_sub for safety)
        let decremented = current.saturating_sub(1);
        
        // Update the header value
        headers
            .set_or_push("Max-Forwards", decremented.to_string())
            .map_err(|_| MaxForwardsError::Invalid)?;
        
        return Ok(decremented);
    }

    // Insert default 70 -> 69 when missing (per RFC 3261, default is 70)
    headers
        .push("Max-Forwards", "69")
        .map_err(|_| MaxForwardsError::Invalid)?;
    
    Ok(69)
}

/// Validates a branch parameter including the RFC 3261 magic cookie prefix.
///
/// Per RFC 3261, branch parameters MUST start with the magic cookie "z9hG4bK"
/// to indicate RFC 3261 compliance.
///
/// # Security
///
/// This function validates the branch parameter to ensure:
/// - It starts with the RFC 3261 magic cookie "z9hG4bK"
/// - It is within acceptable length limits (8-256 characters)
/// - It contains only valid characters (no control characters)
/// - It follows RFC 3261 token character rules
///
/// # Examples
///
/// ```
/// use sip_core::is_valid_branch;
///
/// assert!(is_valid_branch("z9hG4bKabc123"));
/// assert!(!is_valid_branch("badbranch"));
/// assert!(!is_valid_branch("z9hG4bK\r\ninjection"));
/// ```
pub fn is_valid_branch(branch: &str) -> bool {
    // Check minimum length (must have magic cookie + at least one char)
    if branch.len() < MIN_BRANCH_LENGTH {
        return false;
    }

    // Check maximum length (prevent DoS)
    if branch.len() > MAX_BRANCH_LENGTH {
        return false;
    }

    // Check for magic cookie
    if !branch.starts_with(MAGIC_COOKIE) {
        return false;
    }

    // Check for control characters (including CRLF) - security critical
    if branch.chars().any(|c| c.is_ascii_control()) {
        return false;
    }

    // Validate characters per RFC 3261 token rules
    // Valid token characters: alphanumeric + - . ! % * _ + ` ' ~
    branch.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrements_existing_header() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "5").unwrap();
        let remaining = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(remaining, 4);
        assert_eq!(headers.get("Max-Forwards"), Some("4"));
    }

    #[test]
    fn inserts_when_missing() {
        let mut headers = Headers::new();
        let remaining = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(remaining, 69);
        assert_eq!(headers.get("Max-Forwards"), Some("69"));
    }

    #[test]
    fn returns_error_when_exhausted() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "0").unwrap();
        assert_eq!(
            decrement_max_forwards(&mut headers),
            Err(MaxForwardsError::Exhausted)
        );
    }

    #[test]
    fn returns_error_when_invalid() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "bogus").unwrap();
        assert_eq!(
            decrement_max_forwards(&mut headers),
            Err(MaxForwardsError::Invalid)
        );
    }

    #[test]
    fn handles_whitespace() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "  42  ").unwrap();
        let remaining = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(remaining, 41);
    }

    #[test]
    fn multiple_decrements() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "3").unwrap();
        
        assert_eq!(decrement_max_forwards(&mut headers).unwrap(), 2);
        assert_eq!(decrement_max_forwards(&mut headers).unwrap(), 1);
        assert_eq!(decrement_max_forwards(&mut headers).unwrap(), 0);
        assert_eq!(
            decrement_max_forwards(&mut headers),
            Err(MaxForwardsError::Exhausted)
        );
    }

    // Branch validation tests
    #[test]
    fn validates_branch_cookie() {
        assert!(is_valid_branch("z9hG4bKabc123"));
        assert!(is_valid_branch("z9hG4bK1234567890"));
        assert!(is_valid_branch("z9hG4bKbranch-value.test"));
    }

    #[test]
    fn rejects_invalid_branches() {
        // No magic cookie
        assert!(!is_valid_branch("badbranch"));
        assert!(!is_valid_branch("z9hG4b"));
        
        // Too short (just the cookie, no value)
        assert!(!is_valid_branch("z9hG4bK"));
        
        // CRLF injection attempts
        assert!(!is_valid_branch("z9hG4bK\r\ninjection"));
        assert!(!is_valid_branch("z9hG4bK\x00null"));
        assert!(!is_valid_branch("z9hG4bKtest\ttab"));
        
        // Invalid characters
        assert!(!is_valid_branch("z9hG4bK<script>"));
        assert!(!is_valid_branch("z9hG4bK{bad}"));
        assert!(!is_valid_branch("z9hG4bK;semicolon"));
        assert!(!is_valid_branch("z9hG4bK:colon"));
        assert!(!is_valid_branch("z9hG4bK space"));
    }

    #[test]
    fn reject_oversized_branch() {
        let long_branch = format!("z9hG4bK{}", "x".repeat(MAX_BRANCH_LENGTH));
        assert!(!is_valid_branch(&long_branch));
    }

    #[test]
    fn accepts_valid_token_chars() {
        // All valid token characters
        assert!(is_valid_branch("z9hG4bKabc-123.test!%*_+`'~"));
    }

    #[test]
    fn exact_length_boundaries() {
        // Exactly MIN_BRANCH_LENGTH (should pass)
        assert!(is_valid_branch("z9hG4bKa"));
        
        // One less than min (should fail)
        assert!(!is_valid_branch("z9hG4b"));
        
        // Exactly MAX_BRANCH_LENGTH (should pass if valid chars)
        let max_len = format!(
            "z9hG4bK{}",
            "x".repeat(MAX_BRANCH_LENGTH - MAGIC_COOKIE.len())
        );
        assert_eq!(max_len.len(), MAX_BRANCH_LENGTH);
        assert!(is_valid_branch(&max_len));
        
        // One more than max (should fail)
        let over_max = format!(
            "z9hG4bK{}",
            "x".repeat(MAX_BRANCH_LENGTH - MAGIC_COOKIE.len() + 1)
        );
        assert_eq!(over_max.len(), MAX_BRANCH_LENGTH + 1);
        assert!(!is_valid_branch(&over_max));
    }
}
