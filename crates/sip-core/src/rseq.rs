// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RSeq and RAck headers for reliable provisional responses (RFC 3262).
//!
//! RFC 3262 defines a mechanism for reliably sending provisional responses
//! (1xx responses other than 100 Trying). This is critical for PRACK-based
//! features like early media and quality of service negotiation.
//!
//! # How It Works
//!
//! 1. UAC sends INVITE with "Supported: 100rel" or "Require: 100rel"
//! 2. UAS sends reliable provisional response (e.g., 183 Session Progress)
//!    with RSeq header containing a sequence number
//! 3. UAC acknowledges with PRACK request containing RAck header
//! 4. RAck header contains: RSeq number, CSeq number, and CSeq method
//!
//! # Example Flow
//!
//! ```text
//! UAC -> UAS:  INVITE (CSeq: 1 INVITE, Require: 100rel)
//! UAC <- UAS:  183 Session Progress (RSeq: 1, CSeq: 1 INVITE)
//! UAC -> UAS:  PRACK (RAck: 1 1 INVITE)
//! UAC <- UAS:  200 OK (for PRACK)
//! ```
//!
//! # RSeq Sequence Numbers
//!
//! - Start at a random value (per RFC 3262 §7.1)
//! - Increment by 1 for each reliable provisional response
//! - Must be monotonically increasing within a dialog
//! - Range: 1 to 2^31-1 (positive signed 32-bit integer)

use std::fmt;

const MAX_PARSE_INPUT: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RSeqError {
    InvalidSequence(u32),
    ZeroSequence,
    InvalidMethod(String),
    ParseError(String),
    InputTooLarge { max: usize, actual: usize },
    MissingField(String),
}

impl std::fmt::Display for RSeqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSequence(val) =>
                write!(f, "invalid sequence number: {} (must be 1-2147483647)", val),
            Self::ZeroSequence =>
                write!(f, "sequence number cannot be zero"),
            Self::InvalidMethod(msg) =>
                write!(f, "invalid method: {}", msg),
            Self::ParseError(msg) =>
                write!(f, "parse error: {}", msg),
            Self::InputTooLarge { max, actual } =>
                write!(f, "input too large (max {}, got {})", max, actual),
            Self::MissingField(field) =>
                write!(f, "missing required field: {}", field),
        }
    }
}

impl std::error::Error for RSeqError {}

/// Represents the RSeq header (RFC 3262).
///
/// The RSeq header contains a sequence number used to identify reliable
/// provisional responses. Each reliable provisional response within a
/// dialog must have a unique, monotonically increasing RSeq value.
///
/// # Sequence Number Range
///
/// Per RFC 3262, RSeq values must be in the range 1 to 2^31-1
/// (positive signed 32-bit integer). Zero is not a valid RSeq value.
///
/// # Examples
///
/// ```
/// use sip_core::RSeqHeader;
///
/// let rseq = RSeqHeader::new(1).unwrap();
/// assert_eq!(rseq.sequence(), 1);
/// assert_eq!(rseq.to_string(), "1");
///
/// let rseq = RSeqHeader::parse("42").unwrap();
/// assert_eq!(rseq.sequence(), 42);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RSeqHeader {
    sequence: u32,
}

impl RSeqHeader {
    /// Creates a new RSeq header with the given sequence number.
    ///
    /// # Errors
    ///
    /// Returns an error if the sequence number is zero or exceeds 2^31-1.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RSeqHeader;
    ///
    /// let rseq = RSeqHeader::new(1).unwrap();
    /// assert_eq!(rseq.sequence(), 1);
    ///
    /// // Zero is invalid
    /// assert!(RSeqHeader::new(0).is_err());
    /// ```
    pub fn new(sequence: u32) -> Result<Self, RSeqError> {
        validate_sequence(sequence)?;
        Ok(Self { sequence })
    }

    /// Returns the sequence number.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Returns the next sequence number (incremented by 1).
    ///
    /// # Errors
    ///
    /// Returns an error if incrementing would exceed 2^31-1.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RSeqHeader;
    ///
    /// let rseq = RSeqHeader::new(1).unwrap();
    /// let next = rseq.next().unwrap();
    /// assert_eq!(next.sequence(), 2);
    /// ```
    pub fn next(&self) -> Result<Self, RSeqError> {
        Self::new(self.sequence.saturating_add(1))
    }

    /// Parses an RSeq header value.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::RSeqHeader;
    ///
    /// let rseq = RSeqHeader::parse("42").unwrap();
    /// assert_eq!(rseq.sequence(), 42);
    ///
    /// let rseq = RSeqHeader::parse("  123  ").unwrap();
    /// assert_eq!(rseq.sequence(), 123);
    /// ```
    pub fn parse(input: &str) -> Result<Self, RSeqError> {
        if input.len() > MAX_PARSE_INPUT {
            return Err(RSeqError::InputTooLarge {
                max: MAX_PARSE_INPUT,
                actual: input.len(),
            });
        }

        let sequence = input
            .trim()
            .parse::<u32>()
            .map_err(|e| RSeqError::ParseError(format!("invalid number: {}", e)))?;

        Self::new(sequence)
    }
}

impl fmt::Display for RSeqHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sequence)
    }
}

/// Represents the RAck header (RFC 3262).
///
/// The RAck (Reliable Acknowledgement) header is used in PRACK requests
/// to acknowledge receipt of a reliable provisional response. It contains
/// the RSeq value being acknowledged, along with the CSeq number and method
/// from the original request.
///
/// # Format
///
/// ```text
/// RAck: <rseq> <cseq-number> <method>
/// ```
///
/// # Examples
///
/// ```
/// use sip_core::{RAckHeader, Method};
///
/// let rack = RAckHeader::new(1, 314159, Method::Invite).unwrap();
/// assert_eq!(rack.to_string(), "1 314159 INVITE");
///
/// let rack = RAckHeader::parse("42 123 INVITE").unwrap();
/// assert_eq!(rack.rseq(), 42);
/// assert_eq!(rack.cseq_number(), 123);
/// assert_eq!(rack.cseq_method(), &Method::Invite);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAckHeader {
    rseq: u32,
    cseq_number: u32,
    cseq_method: crate::Method,
}

impl RAckHeader {
    /// Creates a new RAck header.
    ///
    /// # Arguments
    ///
    /// * `rseq` - The RSeq value being acknowledged
    /// * `cseq_number` - The CSeq number from the original request
    /// * `cseq_method` - The method from the original request
    ///
    /// # Errors
    ///
    /// Returns an error if rseq or cseq_number is invalid (zero or > 2^31-1).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{RAckHeader, Method};
    ///
    /// let rack = RAckHeader::new(1, 314159, Method::Invite).unwrap();
    /// assert_eq!(rack.rseq(), 1);
    /// assert_eq!(rack.cseq_number(), 314159);
    /// ```
    pub fn new(
        rseq: u32,
        cseq_number: u32,
        cseq_method: crate::Method,
    ) -> Result<Self, RSeqError> {
        validate_sequence(rseq)?;
        validate_sequence(cseq_number)?;

        Ok(Self {
            rseq,
            cseq_number,
            cseq_method,
        })
    }

    /// Returns the RSeq value.
    pub fn rseq(&self) -> u32 {
        self.rseq
    }

    /// Returns the CSeq number.
    pub fn cseq_number(&self) -> u32 {
        self.cseq_number
    }

    /// Returns the CSeq method.
    pub fn cseq_method(&self) -> &crate::Method {
        &self.cseq_method
    }

    /// Parses a RAck header value.
    ///
    /// # Format
    ///
    /// ```text
    /// <rseq> <cseq-number> <method>
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{RAckHeader, Method};
    ///
    /// let rack = RAckHeader::parse("1 314159 INVITE").unwrap();
    /// assert_eq!(rack.rseq(), 1);
    /// assert_eq!(rack.cseq_number(), 314159);
    /// assert_eq!(rack.cseq_method(), &Method::Invite);
    /// ```
    pub fn parse(input: &str) -> Result<Self, RSeqError> {
        if input.len() > MAX_PARSE_INPUT {
            return Err(RSeqError::InputTooLarge {
                max: MAX_PARSE_INPUT,
                actual: input.len(),
            });
        }

        let parts: Vec<&str> = input.trim().split_whitespace().collect();

        if parts.len() != 3 {
            return Err(RSeqError::ParseError(
                "RAck requires 3 fields: <rseq> <cseq> <method>".to_string(),
            ));
        }

        let rseq = parts[0]
            .parse::<u32>()
            .map_err(|e| RSeqError::ParseError(format!("invalid rseq: {}", e)))?;

        let cseq_number = parts[1]
            .parse::<u32>()
            .map_err(|e| RSeqError::ParseError(format!("invalid cseq: {}", e)))?;

        let cseq_method = crate::Method::from_token(parts[2])
            .map_err(|e| RSeqError::InvalidMethod(e.to_string()))?;

        Self::new(rseq, cseq_number, cseq_method)
    }
}

impl fmt::Display for RAckHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.rseq, self.cseq_number, self.cseq_method)
    }
}

// Validation functions

/// Validates a sequence number per RFC 3262 §7.1.
///
/// RSeq and CSeq numbers must be in the range 1 to 2^31-1.
fn validate_sequence(sequence: u32) -> Result<(), RSeqError> {
    if sequence == 0 {
        return Err(RSeqError::ZeroSequence);
    }

    // RFC 3262 §7.1: RSeq is a 31-bit number (1 to 2^31-1)
    if sequence > 2_147_483_647 {
        return Err(RSeqError::InvalidSequence(sequence));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Method;

    // RSeqHeader tests

    #[test]
    fn create_rseq() {
        let rseq = RSeqHeader::new(1).unwrap();
        assert_eq!(rseq.sequence(), 1);
    }

    #[test]
    fn create_rseq_large() {
        let rseq = RSeqHeader::new(2_147_483_647).unwrap();
        assert_eq!(rseq.sequence(), 2_147_483_647);
    }

    #[test]
    fn reject_zero_rseq() {
        let result = RSeqHeader::new(0);
        assert!(matches!(result, Err(RSeqError::ZeroSequence)));
    }

    #[test]
    fn reject_invalid_rseq() {
        let result = RSeqHeader::new(2_147_483_648);
        assert!(matches!(result, Err(RSeqError::InvalidSequence(_))));
    }

    #[test]
    fn rseq_next() {
        let rseq = RSeqHeader::new(1).unwrap();
        let next = rseq.next().unwrap();
        assert_eq!(next.sequence(), 2);
    }

    #[test]
    fn rseq_next_overflow() {
        let rseq = RSeqHeader::new(2_147_483_647).unwrap();
        let result = rseq.next();
        assert!(result.is_err());
    }

    #[test]
    fn format_rseq() {
        let rseq = RSeqHeader::new(42).unwrap();
        assert_eq!(rseq.to_string(), "42");
    }

    #[test]
    fn parse_rseq() {
        let rseq = RSeqHeader::parse("42").unwrap();
        assert_eq!(rseq.sequence(), 42);
    }

    #[test]
    fn parse_rseq_with_whitespace() {
        let rseq = RSeqHeader::parse("  123  ").unwrap();
        assert_eq!(rseq.sequence(), 123);
    }

    #[test]
    fn round_trip_rseq() {
        let original = RSeqHeader::new(314159).unwrap();
        let formatted = original.to_string();
        let parsed = RSeqHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    // RAckHeader tests

    #[test]
    fn create_rack() {
        let rack = RAckHeader::new(1, 314159, Method::Invite).unwrap();
        assert_eq!(rack.rseq(), 1);
        assert_eq!(rack.cseq_number(), 314159);
        assert_eq!(rack.cseq_method(), &Method::Invite);
    }

    #[test]
    fn reject_zero_rack_rseq() {
        let result = RAckHeader::new(0, 123, Method::Invite);
        assert!(matches!(result, Err(RSeqError::ZeroSequence)));
    }

    #[test]
    fn reject_zero_rack_cseq() {
        let result = RAckHeader::new(1, 0, Method::Invite);
        assert!(matches!(result, Err(RSeqError::ZeroSequence)));
    }

    #[test]
    fn reject_invalid_rack_rseq() {
        let result = RAckHeader::new(2_147_483_648, 123, Method::Invite);
        assert!(matches!(result, Err(RSeqError::InvalidSequence(_))));
    }

    #[test]
    fn reject_invalid_rack_cseq() {
        let result = RAckHeader::new(1, 2_147_483_648, Method::Invite);
        assert!(matches!(result, Err(RSeqError::InvalidSequence(_))));
    }

    #[test]
    fn format_rack() {
        let rack = RAckHeader::new(1, 314159, Method::Invite).unwrap();
        assert_eq!(rack.to_string(), "1 314159 INVITE");
    }

    #[test]
    fn parse_rack() {
        let rack = RAckHeader::parse("1 314159 INVITE").unwrap();
        assert_eq!(rack.rseq(), 1);
        assert_eq!(rack.cseq_number(), 314159);
        assert_eq!(rack.cseq_method(), &Method::Invite);
    }

    #[test]
    fn parse_rack_with_whitespace() {
        let rack = RAckHeader::parse("  42   123   INVITE  ").unwrap();
        assert_eq!(rack.rseq(), 42);
        assert_eq!(rack.cseq_number(), 123);
    }

    #[test]
    fn parse_rack_different_methods() {
        let rack = RAckHeader::parse("1 100 UPDATE").unwrap();
        assert_eq!(rack.cseq_method(), &Method::Update);

        let rack = RAckHeader::parse("2 200 PRACK").unwrap();
        assert_eq!(rack.cseq_method(), &Method::Prack);
    }

    #[test]
    fn parse_rack_invalid_format() {
        assert!(RAckHeader::parse("1 2").is_err()); // Missing method
        assert!(RAckHeader::parse("1").is_err()); // Missing cseq and method
        assert!(RAckHeader::parse("").is_err()); // Empty
    }

    #[test]
    fn round_trip_rack() {
        let original = RAckHeader::new(42, 123, Method::Invite).unwrap();
        let formatted = original.to_string();
        let parsed = RAckHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    // Security tests

    #[test]
    fn reject_oversized_rseq_input() {
        let huge = "1".repeat(200);
        let result = RSeqHeader::parse(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_rack_input() {
        let huge = format!("1 2 {}", "INVITE".repeat(50));
        let result = RAckHeader::parse(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn fields_are_private() {
        let rseq = RSeqHeader::new(1).unwrap();
        let rack = RAckHeader::new(1, 2, Method::Invite).unwrap();

        // These should compile (read-only access)
        let _ = rseq.sequence();
        let _ = rack.rseq();
        let _ = rack.cseq_number();
        let _ = rack.cseq_method();

        // These should NOT compile:
        // rseq.sequence = 999;          // ← Does not compile!
        // rack.rseq = 999;              // ← Does not compile!
        // rack.cseq_method = Method::Bye;  // ← Does not compile!
    }

    #[test]
    fn validate_sequence_bounds() {
        // Valid range: 1 to 2^31-1
        assert!(validate_sequence(1).is_ok());
        assert!(validate_sequence(1000).is_ok());
        assert!(validate_sequence(2_147_483_647).is_ok());

        // Invalid
        assert!(validate_sequence(0).is_err());
        assert!(validate_sequence(2_147_483_648).is_err());
        assert!(validate_sequence(u32::MAX).is_err());
    }
}