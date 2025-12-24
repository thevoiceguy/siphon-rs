// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Refer-Sub header (RFC 4488).
//!
//! The Refer-Sub header allows suppression of the implicit subscription
//! created by REFER requests defined in RFC 3515.
//!
//! # Problem Solved
//!
//! RFC 3515 mandates that every REFER request creates an implicit subscription
//! where the REFER-Recipient sends NOTIFY messages about the referred request's
//! progress. This can create unnecessary network overhead when:
//!
//! - The REFER-Issuer already has alternative knowledge of progress
//! - The REFER request is guaranteed not to fork
//! - The outcome is immediately known
//!
//! # Format
//!
//! ```text
//! Refer-Sub: true
//! Refer-Sub: false
//! ```
//!
//! # Usage
//!
//! ## REFER-Issuer (Referrer)
//!
//! When the issuer knows the REFER won't fork and doesn't need NOTIFY updates:
//!
//! ```
//! use sip_core::ReferSubHeader;
//!
//! // Suppress implicit subscription
//! let refer_sub = ReferSubHeader::new(false);
//! assert_eq!(refer_sub.to_string(), "false");
//!
//! // Add to REFER request
//! // request.headers_mut().set("Refer-Sub", &refer_sub.to_string());
//! ```
//!
//! ## REFER-Recipient (Transfer Target)
//!
//! When receiving a REFER with `Refer-Sub: false`:
//!
//! ```
//! use sip_core::ReferSubHeader;
//!
//! // Parse from REFER request
//! let refer_sub = ReferSubHeader::parse("false").unwrap();
//!
//! if !refer_sub.enabled {
//!     // No implicit subscription - send 200 OK with Refer-Sub: false
//!     // Do NOT send NOTIFY messages
//! } else {
//!     // Normal RFC 3515 behavior - create subscription
//!     // Send NOTIFY messages as the referred request progresses
//! }
//! ```
//!
//! ## 200 OK Response
//!
//! If the recipient accepts suppression, it must echo the header:
//!
//! ```text
//! SIP/2.0 200 OK
//! Refer-Sub: false
//! ```
//!
//! If the header is omitted or contains `Refer-Sub: true`, the implicit
//! subscription is created per RFC 3515.
//!
//! # RFC 4488 Requirements
//!
//! - **Backwards Compatibility**: Recipients that don't support RFC 4488
//!   ignore the header and create the subscription normally
//!
//! - **Non-Forking Guarantee**: Issuers SHOULD only use `Refer-Sub: false`
//!   when certain the REFER won't fork (e.g., using GRUU)
//!
//! - **Termination**: If suppression is rejected, the issuer can terminate
//!   the subscription with `SUBSCRIBE` with `Expires: 0`
//!
//! # Example: Call Transfer Without Subscription
//!
//! ```text
//! Alice -> Bob: REFER sip:carol@example.com SIP/2.0
//!               Refer-To: <sip:carol@example.com>
//!               Refer-Sub: false
//!
//! Bob -> Alice: SIP/2.0 200 OK
//!               Refer-Sub: false
//!
//! // No NOTIFY messages sent - subscription suppressed
//! ```

use std::fmt;

/// The Refer-Sub header (RFC 4488).
///
/// Controls whether an implicit subscription is created for a REFER request.
/// When set to `false`, no NOTIFY messages are sent about the referred
/// request's progress.
///
/// # Default Behavior (RFC 3515)
///
/// Without this header, REFER creates an implicit subscription that sends
/// NOTIFY messages until the referred request completes.
///
/// # RFC 4488 Behavior
///
/// With `Refer-Sub: false`, no implicit subscription is created. This is
/// useful when the REFER-Issuer:
/// - Already knows the outcome through other means
/// - Can guarantee the REFER won't fork
/// - Wants to reduce network overhead
///
/// # Examples
///
/// ```
/// use sip_core::ReferSubHeader;
///
/// // Suppress subscription
/// let no_sub = ReferSubHeader::new(false);
/// assert!(!no_sub.enabled);
/// assert_eq!(no_sub.to_string(), "false");
///
/// // Enable subscription (explicit, same as omitting header)
/// let with_sub = ReferSubHeader::new(true);
/// assert!(with_sub.enabled);
/// assert_eq!(with_sub.to_string(), "true");
///
/// // Parse from header value
/// let parsed = ReferSubHeader::parse("false").unwrap();
/// assert!(!parsed.enabled);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReferSubHeader {
    /// Whether the implicit subscription is enabled.
    ///
    /// - `true`: Create implicit subscription (RFC 3515 behavior)
    /// - `false`: Suppress implicit subscription (RFC 4488)
    pub enabled: bool,
}

impl ReferSubHeader {
    /// Creates a new Refer-Sub header with the specified value.
    ///
    /// # Arguments
    ///
    /// * `enabled` - `true` for subscription enabled, `false` to suppress
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReferSubHeader;
    ///
    /// // Suppress subscription
    /// let refer_sub = ReferSubHeader::new(false);
    /// assert!(!refer_sub.enabled);
    ///
    /// // Enable subscription
    /// let refer_sub = ReferSubHeader::new(true);
    /// assert!(refer_sub.enabled);
    /// ```
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Creates a Refer-Sub header that suppresses the subscription.
    ///
    /// This is equivalent to `ReferSubHeader::new(false)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReferSubHeader;
    ///
    /// let refer_sub = ReferSubHeader::suppressed();
    /// assert!(!refer_sub.enabled);
    /// assert_eq!(refer_sub.to_string(), "false");
    /// ```
    pub const fn suppressed() -> Self {
        Self::new(false)
    }

    /// Creates a Refer-Sub header that enables the subscription.
    ///
    /// This is equivalent to `ReferSubHeader::new(true)` and represents
    /// the default RFC 3515 behavior.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReferSubHeader;
    ///
    /// let refer_sub = ReferSubHeader::enabled();
    /// assert!(refer_sub.enabled);
    /// assert_eq!(refer_sub.to_string(), "true");
    /// ```
    pub const fn enabled() -> Self {
        Self::new(true)
    }

    /// Parses a Refer-Sub header from a string.
    ///
    /// # Format
    ///
    /// ```text
    /// Refer-Sub: true
    /// Refer-Sub: false
    /// ```
    ///
    /// Parsing is case-insensitive and tolerates whitespace.
    ///
    /// # Returns
    ///
    /// - `Some(ReferSubHeader)` if parsing succeeds
    /// - `None` if the header value is invalid or empty
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReferSubHeader;
    ///
    /// let sub = ReferSubHeader::parse("false").unwrap();
    /// assert!(!sub.enabled);
    ///
    /// let sub = ReferSubHeader::parse("true").unwrap();
    /// assert!(sub.enabled);
    ///
    /// // Case-insensitive
    /// let sub = ReferSubHeader::parse("FALSE").unwrap();
    /// assert!(!sub.enabled);
    ///
    /// // Whitespace tolerance
    /// let sub = ReferSubHeader::parse("  false  ").unwrap();
    /// assert!(!sub.enabled);
    ///
    /// // Invalid values
    /// assert!(ReferSubHeader::parse("").is_none());
    /// assert!(ReferSubHeader::parse("maybe").is_none());
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let value = input.trim();
        match value.to_ascii_lowercase().as_str() {
            "true" => Some(Self::new(true)),
            "false" => Some(Self::new(false)),
            _ => None,
        }
    }

    /// Returns `true` if the subscription is suppressed (disabled).
    ///
    /// This is equivalent to checking `!enabled`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReferSubHeader;
    ///
    /// let refer_sub = ReferSubHeader::new(false);
    /// assert!(refer_sub.is_suppressed());
    ///
    /// let refer_sub = ReferSubHeader::new(true);
    /// assert!(!refer_sub.is_suppressed());
    /// ```
    pub const fn is_suppressed(&self) -> bool {
        !self.enabled
    }
}

impl fmt::Display for ReferSubHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", if self.enabled { "true" } else { "false" })
    }
}

impl Default for ReferSubHeader {
    /// Returns the default value: subscription enabled (RFC 3515 behavior).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReferSubHeader;
    ///
    /// let default = ReferSubHeader::default();
    /// assert!(default.enabled);
    /// ```
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_true() {
        let refer_sub = ReferSubHeader::new(true);
        assert!(refer_sub.enabled);
    }

    #[test]
    fn new_false() {
        let refer_sub = ReferSubHeader::new(false);
        assert!(!refer_sub.enabled);
    }

    #[test]
    fn suppressed() {
        let refer_sub = ReferSubHeader::suppressed();
        assert!(!refer_sub.enabled);
        assert!(refer_sub.is_suppressed());
    }

    #[test]
    fn enabled() {
        let refer_sub = ReferSubHeader::enabled();
        assert!(refer_sub.enabled);
        assert!(!refer_sub.is_suppressed());
    }

    #[test]
    fn is_suppressed() {
        assert!(ReferSubHeader::new(false).is_suppressed());
        assert!(!ReferSubHeader::new(true).is_suppressed());
    }

    #[test]
    fn format_true() {
        let refer_sub = ReferSubHeader::new(true);
        assert_eq!(refer_sub.to_string(), "true");
    }

    #[test]
    fn format_false() {
        let refer_sub = ReferSubHeader::new(false);
        assert_eq!(refer_sub.to_string(), "false");
    }

    #[test]
    fn parse_true() {
        let refer_sub = ReferSubHeader::parse("true").unwrap();
        assert!(refer_sub.enabled);
    }

    #[test]
    fn parse_false() {
        let refer_sub = ReferSubHeader::parse("false").unwrap();
        assert!(!refer_sub.enabled);
    }

    #[test]
    fn parse_case_insensitive() {
        assert!(ReferSubHeader::parse("TRUE").unwrap().enabled);
        assert!(ReferSubHeader::parse("True").unwrap().enabled);
        assert!(!ReferSubHeader::parse("FALSE").unwrap().enabled);
        assert!(!ReferSubHeader::parse("False").unwrap().enabled);
    }

    #[test]
    fn parse_with_whitespace() {
        let refer_sub = ReferSubHeader::parse("  true  ").unwrap();
        assert!(refer_sub.enabled);

        let refer_sub = ReferSubHeader::parse("  false  ").unwrap();
        assert!(!refer_sub.enabled);
    }

    #[test]
    fn parse_empty() {
        assert!(ReferSubHeader::parse("").is_none());
        assert!(ReferSubHeader::parse("   ").is_none());
    }

    #[test]
    fn parse_invalid() {
        assert!(ReferSubHeader::parse("maybe").is_none());
        assert!(ReferSubHeader::parse("yes").is_none());
        assert!(ReferSubHeader::parse("no").is_none());
        assert!(ReferSubHeader::parse("1").is_none());
        assert!(ReferSubHeader::parse("0").is_none());
    }

    #[test]
    fn round_trip_true() {
        let original = ReferSubHeader::new(true);
        let formatted = original.to_string();
        let parsed = ReferSubHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_false() {
        let original = ReferSubHeader::new(false);
        let formatted = original.to_string();
        let parsed = ReferSubHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn default_is_enabled() {
        let default = ReferSubHeader::default();
        assert!(default.enabled);
        assert!(!default.is_suppressed());
    }

    #[test]
    fn rfc_4488_example_suppressed() {
        // REFER with Refer-Sub: false
        let refer_sub = ReferSubHeader::parse("false").unwrap();
        assert!(refer_sub.is_suppressed());

        // 200 OK echoes Refer-Sub: false
        assert_eq!(refer_sub.to_string(), "false");
    }

    #[test]
    fn rfc_4488_example_enabled() {
        // REFER with Refer-Sub: true (or omitted)
        let refer_sub = ReferSubHeader::parse("true").unwrap();
        assert!(!refer_sub.is_suppressed());

        // 200 OK can echo Refer-Sub: true or omit it
        assert_eq!(refer_sub.to_string(), "true");
    }

    #[test]
    fn backwards_compatibility() {
        // Legacy systems omit the header, equivalent to enabled
        let default = ReferSubHeader::default();
        assert!(default.enabled);

        // New systems can explicitly request suppression
        let suppressed = ReferSubHeader::suppressed();
        assert!(suppressed.is_suppressed());
    }
}
