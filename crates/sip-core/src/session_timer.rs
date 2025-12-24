// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Session Timer headers (RFC 4028).
//!
//! RFC 4028 defines session timers to detect and clean up "dead" SIP sessions.
//! Without session timers, call stateful proxies cannot determine when sessions
//! have ended if BYE messages are lost or never sent.
//!
//! ## Headers
//!
//! - **Session-Expires**: Maximum session duration with optional refresher parameter
//! - **Min-SE**: Minimum acceptable session expiration interval
//!
//! ## Format
//!
//! ```text
//! Session-Expires: 1800
//! Session-Expires: 1800;refresher=uac
//! Session-Expires: 3600;refresher=uas
//! Min-SE: 90
//! ```
//!
//! ## Usage
//!
//! ### Creating Session-Expires header
//!
//! ```
//! use sip_core::{SessionExpires, RefresherRole};
//!
//! // Session expires in 30 minutes (1800s), UAC is refresher
//! let session_expires = SessionExpires::new(1800)
//!     .with_refresher(RefresherRole::Uac);
//!
//! assert_eq!(session_expires.delta_seconds, 1800);
//! assert_eq!(session_expires.refresher, Some(RefresherRole::Uac));
//! ```
//!
//! ### Parsing Session-Expires header
//!
//! ```
//! use sip_core::{SessionExpires, RefresherRole};
//!
//! let se = SessionExpires::parse("1800;refresher=uas").unwrap();
//! assert_eq!(se.delta_seconds, 1800);
//! assert_eq!(se.refresher, Some(RefresherRole::Uas));
//! ```
//!
//! ### Creating Min-SE header
//!
//! ```
//! use sip_core::MinSessionExpires;
//!
//! // Minimum session interval is 120 seconds
//! let min_se = MinSessionExpires::new(120);
//! assert_eq!(min_se.delta_seconds, 120);
//! ```
//!
//! ## RFC 4028 Requirements
//!
//! - **Minimum value**: Session-Expires and Min-SE MUST be at least 90 seconds
//! - **Default Session-Expires**: 1800 seconds (30 minutes) is recommended
//! - **Refresh timing**: Refresher SHOULD send refresh at Session-Expires/2
//! - **422 Response**: When Session-Expires < Min-SE, return 422 with Min-SE header
//!
//! ## Refresher Role
//!
//! The `refresher` parameter in Session-Expires identifies which endpoint must
//! send periodic re-INVITE or UPDATE requests to keep the session alive:
//!
//! - **refresher=uac**: User Agent Client is responsible for refresh
//! - **refresher=uas**: User Agent Server is responsible for refresh
//!
//! If the refresher fails to send refresh before Session-Expires, the session
//! is considered dead and both sides terminate the dialog.

use std::fmt;

/// The Session-Expires header (RFC 4028).
///
/// Session-Expires conveys the session interval - the maximum time a session
/// can remain active without a refresh. It appears in INVITE and UPDATE requests
/// and their 2xx responses.
///
/// # Format
///
/// ```text
/// Session-Expires = delta-seconds *(SEMI se-params)
/// se-params = refresher-param / generic-param
/// refresher-param = "refresher" EQUAL ("uac" / "uas")
/// ```
///
/// # Examples
///
/// ```
/// use sip_core::{SessionExpires, RefresherRole};
///
/// // 30 minute session, no specific refresher
/// let se1 = SessionExpires::new(1800);
/// assert_eq!(se1.to_string(), "1800");
///
/// // 1 hour session, UAC must refresh
/// let se2 = SessionExpires::new(3600).with_refresher(RefresherRole::Uac);
/// assert_eq!(se2.to_string(), "3600;refresher=uac");
///
/// // Parse from string
/// let se3 = SessionExpires::parse("1800;refresher=uas").unwrap();
/// assert_eq!(se3.delta_seconds, 1800);
/// assert_eq!(se3.refresher, Some(RefresherRole::Uas));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionExpires {
    /// Session interval in seconds (minimum 90, recommended default 1800)
    pub delta_seconds: u32,
    /// Optional refresher role (uac or uas)
    pub refresher: Option<RefresherRole>,
}

impl SessionExpires {
    /// Creates a new Session-Expires header with the given interval.
    ///
    /// # Arguments
    ///
    /// * `delta_seconds` - Session interval in seconds (should be >= 90)
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// let se = SessionExpires::new(1800);
    /// assert_eq!(se.delta_seconds, 1800);
    /// assert_eq!(se.refresher, None);
    /// ```
    pub fn new(delta_seconds: u32) -> Self {
        Self {
            delta_seconds,
            refresher: None,
        }
    }

    /// Sets the refresher role.
    ///
    /// # Arguments
    ///
    /// * `role` - Which endpoint (UAC or UAS) is responsible for refresh
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::{SessionExpires, RefresherRole};
    ///
    /// let se = SessionExpires::new(1800).with_refresher(RefresherRole::Uac);
    /// assert_eq!(se.refresher, Some(RefresherRole::Uac));
    /// ```
    pub fn with_refresher(mut self, role: RefresherRole) -> Self {
        self.refresher = Some(role);
        self
    }

    /// Parses a Session-Expires header from a string.
    ///
    /// # Format
    ///
    /// ```text
    /// Session-Expires: delta-seconds
    /// Session-Expires: delta-seconds;refresher=uac
    /// Session-Expires: delta-seconds;refresher=uas
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(SessionExpires)` if parsing succeeds
    /// - `None` if the header is invalid or empty
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::{SessionExpires, RefresherRole};
    ///
    /// let se1 = SessionExpires::parse("1800").unwrap();
    /// assert_eq!(se1.delta_seconds, 1800);
    /// assert_eq!(se1.refresher, None);
    ///
    /// let se2 = SessionExpires::parse("3600;refresher=uac").unwrap();
    /// assert_eq!(se2.delta_seconds, 3600);
    /// assert_eq!(se2.refresher, Some(RefresherRole::Uac));
    ///
    /// let se3 = SessionExpires::parse("  1800 ; refresher=uas  ").unwrap();
    /// assert_eq!(se3.delta_seconds, 1800);
    /// assert_eq!(se3.refresher, Some(RefresherRole::Uas));
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }

        // Split on semicolon to separate delta-seconds from parameters
        let parts: Vec<&str> = input.split(';').collect();

        // Parse delta-seconds
        let delta_seconds = parts[0].trim().parse::<u32>().ok()?;

        // Parse optional refresher parameter
        let mut refresher = None;
        for part in &parts[1..] {
            let param = part.trim();
            if let Some(value) = param.strip_prefix("refresher=") {
                refresher = RefresherRole::parse(value.trim());
            }
        }

        Some(Self {
            delta_seconds,
            refresher,
        })
    }

    /// Returns the minimum acceptable session interval per RFC 4028 (90 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// assert_eq!(SessionExpires::minimum(), 90);
    /// ```
    pub const fn minimum() -> u32 {
        90
    }

    /// Returns the recommended default session interval per RFC 4028 (1800 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// assert_eq!(SessionExpires::default_interval(), 1800);
    /// ```
    pub const fn default_interval() -> u32 {
        1800
    }

    /// Returns true if this session interval is valid per RFC 4028 (>= 90 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// assert!(SessionExpires::new(1800).is_valid());
    /// assert!(SessionExpires::new(90).is_valid());
    /// assert!(!SessionExpires::new(60).is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        self.delta_seconds >= Self::minimum()
    }
}

impl fmt::Display for SessionExpires {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.delta_seconds)?;
        if let Some(ref refresher) = self.refresher {
            write!(f, ";refresher={}", refresher.as_str())?;
        }
        Ok(())
    }
}

/// The Min-SE header (RFC 4028).
///
/// Min-SE (Minimum Session-Expires) defines the smallest session interval
/// that a server will accept. If a request contains a Session-Expires value
/// smaller than Min-SE, the server responds with 422 Session Interval Too Small.
///
/// # Format
///
/// ```text
/// Min-SE = delta-seconds
/// ```
///
/// # Default
///
/// RFC 4028 specifies a default minimum of 90 seconds if Min-SE is not present.
///
/// # Examples
///
/// ```
/// use sip_core::MinSessionExpires;
///
/// // Minimum 90 seconds (RFC 4028 default)
/// let min_se1 = MinSessionExpires::new(90);
/// assert_eq!(min_se1.to_string(), "90");
///
/// // Minimum 2 minutes (120 seconds)
/// let min_se2 = MinSessionExpires::new(120);
/// assert_eq!(min_se2.to_string(), "120");
///
/// // Parse from string
/// let min_se3 = MinSessionExpires::parse("300").unwrap();
/// assert_eq!(min_se3.delta_seconds, 300);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MinSessionExpires {
    /// Minimum session interval in seconds (default 90 per RFC 4028)
    pub delta_seconds: u32,
}

impl MinSessionExpires {
    /// Creates a new Min-SE header with the given minimum interval.
    ///
    /// # Arguments
    ///
    /// * `delta_seconds` - Minimum session interval in seconds (should be >= 90)
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// let min_se = MinSessionExpires::new(120);
    /// assert_eq!(min_se.delta_seconds, 120);
    /// ```
    pub fn new(delta_seconds: u32) -> Self {
        Self { delta_seconds }
    }

    /// Parses a Min-SE header from a string.
    ///
    /// # Format
    ///
    /// ```text
    /// Min-SE: delta-seconds
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(MinSessionExpires)` if parsing succeeds
    /// - `None` if the header is invalid or empty
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// let min_se = MinSessionExpires::parse("90").unwrap();
    /// assert_eq!(min_se.delta_seconds, 90);
    ///
    /// let min_se2 = MinSessionExpires::parse("  120  ").unwrap();
    /// assert_eq!(min_se2.delta_seconds, 120);
    ///
    /// assert!(MinSessionExpires::parse("").is_none());
    /// assert!(MinSessionExpires::parse("invalid").is_none());
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }

        let delta_seconds = input.parse::<u32>().ok()?;
        Some(Self { delta_seconds })
    }

    /// Returns the RFC 4028 default minimum (90 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// assert_eq!(MinSessionExpires::default_minimum(), 90);
    /// ```
    pub const fn default_minimum() -> u32 {
        90
    }

    /// Returns true if this minimum is valid per RFC 4028 (>= 90 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// assert!(MinSessionExpires::new(90).is_valid());
    /// assert!(MinSessionExpires::new(120).is_valid());
    /// assert!(!MinSessionExpires::new(60).is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        self.delta_seconds >= Self::default_minimum()
    }
}

impl fmt::Display for MinSessionExpires {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.delta_seconds)
    }
}

/// Refresher role for session timers (RFC 4028).
///
/// Identifies which endpoint is responsible for sending periodic refresh
/// requests (re-INVITE or UPDATE) to keep the session alive.
///
/// # Values
///
/// - **Uac**: User Agent Client must send refresh
/// - **Uas**: User Agent Server must send refresh
///
/// # Example
///
/// ```
/// use sip_core::RefresherRole;
///
/// let uac = RefresherRole::Uac;
/// assert_eq!(uac.as_str(), "uac");
///
/// let uas = RefresherRole::parse("uas").unwrap();
/// assert_eq!(uas, RefresherRole::Uas);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefresherRole {
    /// User Agent Client is the refresher
    Uac,
    /// User Agent Server is the refresher
    Uas,
}

impl RefresherRole {
    /// Converts the role to its string representation.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::RefresherRole;
    ///
    /// assert_eq!(RefresherRole::Uac.as_str(), "uac");
    /// assert_eq!(RefresherRole::Uas.as_str(), "uas");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            RefresherRole::Uac => "uac",
            RefresherRole::Uas => "uas",
        }
    }

    /// Parses a refresher role from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - String containing "uac" or "uas" (case-insensitive)
    ///
    /// # Returns
    ///
    /// - `Some(RefresherRole)` if parsing succeeds
    /// - `None` if the input is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::RefresherRole;
    ///
    /// assert_eq!(RefresherRole::parse("uac"), Some(RefresherRole::Uac));
    /// assert_eq!(RefresherRole::parse("uas"), Some(RefresherRole::Uas));
    /// assert_eq!(RefresherRole::parse("UAC"), Some(RefresherRole::Uac));
    /// assert_eq!(RefresherRole::parse("UAS"), Some(RefresherRole::Uas));
    /// assert_eq!(RefresherRole::parse("invalid"), None);
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_lowercase().as_str() {
            "uac" => Some(RefresherRole::Uac),
            "uas" => Some(RefresherRole::Uas),
            _ => None,
        }
    }
}

impl fmt::Display for RefresherRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SessionExpires tests

    #[test]
    fn session_expires_new() {
        let se = SessionExpires::new(1800);
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, None);
    }

    #[test]
    fn session_expires_with_refresher() {
        let se = SessionExpires::new(1800).with_refresher(RefresherRole::Uac);
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(RefresherRole::Uac));
    }

    #[test]
    fn session_expires_format_no_refresher() {
        let se = SessionExpires::new(3600);
        assert_eq!(se.to_string(), "3600");
    }

    #[test]
    fn session_expires_format_with_refresher_uac() {
        let se = SessionExpires::new(1800).with_refresher(RefresherRole::Uac);
        assert_eq!(se.to_string(), "1800;refresher=uac");
    }

    #[test]
    fn session_expires_format_with_refresher_uas() {
        let se = SessionExpires::new(1800).with_refresher(RefresherRole::Uas);
        assert_eq!(se.to_string(), "1800;refresher=uas");
    }

    #[test]
    fn session_expires_parse_simple() {
        let se = SessionExpires::parse("1800").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, None);
    }

    #[test]
    fn session_expires_parse_with_refresher_uac() {
        let se = SessionExpires::parse("1800;refresher=uac").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(RefresherRole::Uac));
    }

    #[test]
    fn session_expires_parse_with_refresher_uas() {
        let se = SessionExpires::parse("3600;refresher=uas").unwrap();
        assert_eq!(se.delta_seconds, 3600);
        assert_eq!(se.refresher, Some(RefresherRole::Uas));
    }

    #[test]
    fn session_expires_parse_with_whitespace() {
        let se = SessionExpires::parse("  1800 ; refresher=uac  ").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(RefresherRole::Uac));
    }

    #[test]
    fn session_expires_parse_empty() {
        assert!(SessionExpires::parse("").is_none());
        assert!(SessionExpires::parse("   ").is_none());
    }

    #[test]
    fn session_expires_parse_invalid() {
        assert!(SessionExpires::parse("invalid").is_none());
        assert!(SessionExpires::parse("abc123").is_none());
    }

    #[test]
    fn session_expires_round_trip() {
        let original = SessionExpires::new(1800).with_refresher(RefresherRole::Uas);
        let formatted = original.to_string();
        let parsed = SessionExpires::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn session_expires_minimum() {
        assert_eq!(SessionExpires::minimum(), 90);
    }

    #[test]
    fn session_expires_default_interval() {
        assert_eq!(SessionExpires::default_interval(), 1800);
    }

    #[test]
    fn session_expires_is_valid() {
        assert!(SessionExpires::new(90).is_valid());
        assert!(SessionExpires::new(1800).is_valid());
        assert!(SessionExpires::new(3600).is_valid());
        assert!(!SessionExpires::new(60).is_valid());
        assert!(!SessionExpires::new(89).is_valid());
    }

    // MinSessionExpires tests

    #[test]
    fn min_session_expires_new() {
        let min_se = MinSessionExpires::new(120);
        assert_eq!(min_se.delta_seconds, 120);
    }

    #[test]
    fn min_session_expires_format() {
        let min_se = MinSessionExpires::new(90);
        assert_eq!(min_se.to_string(), "90");
    }

    #[test]
    fn min_session_expires_parse() {
        let min_se = MinSessionExpires::parse("120").unwrap();
        assert_eq!(min_se.delta_seconds, 120);
    }

    #[test]
    fn min_session_expires_parse_with_whitespace() {
        let min_se = MinSessionExpires::parse("  90  ").unwrap();
        assert_eq!(min_se.delta_seconds, 90);
    }

    #[test]
    fn min_session_expires_parse_empty() {
        assert!(MinSessionExpires::parse("").is_none());
        assert!(MinSessionExpires::parse("   ").is_none());
    }

    #[test]
    fn min_session_expires_parse_invalid() {
        assert!(MinSessionExpires::parse("invalid").is_none());
        assert!(MinSessionExpires::parse("abc").is_none());
    }

    #[test]
    fn min_session_expires_round_trip() {
        let original = MinSessionExpires::new(300);
        let formatted = original.to_string();
        let parsed = MinSessionExpires::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn min_session_expires_default_minimum() {
        assert_eq!(MinSessionExpires::default_minimum(), 90);
    }

    #[test]
    fn min_session_expires_is_valid() {
        assert!(MinSessionExpires::new(90).is_valid());
        assert!(MinSessionExpires::new(120).is_valid());
        assert!(MinSessionExpires::new(300).is_valid());
        assert!(!MinSessionExpires::new(60).is_valid());
        assert!(!MinSessionExpires::new(89).is_valid());
    }

    // RefresherRole tests

    #[test]
    fn refresher_role_as_str() {
        assert_eq!(RefresherRole::Uac.as_str(), "uac");
        assert_eq!(RefresherRole::Uas.as_str(), "uas");
    }

    #[test]
    fn refresher_role_format() {
        assert_eq!(RefresherRole::Uac.to_string(), "uac");
        assert_eq!(RefresherRole::Uas.to_string(), "uas");
    }

    #[test]
    fn refresher_role_parse() {
        assert_eq!(RefresherRole::parse("uac"), Some(RefresherRole::Uac));
        assert_eq!(RefresherRole::parse("uas"), Some(RefresherRole::Uas));
    }

    #[test]
    fn refresher_role_parse_case_insensitive() {
        assert_eq!(RefresherRole::parse("UAC"), Some(RefresherRole::Uac));
        assert_eq!(RefresherRole::parse("UAS"), Some(RefresherRole::Uas));
        assert_eq!(RefresherRole::parse("Uac"), Some(RefresherRole::Uac));
        assert_eq!(RefresherRole::parse("Uas"), Some(RefresherRole::Uas));
    }

    #[test]
    fn refresher_role_parse_with_whitespace() {
        assert_eq!(RefresherRole::parse("  uac  "), Some(RefresherRole::Uac));
        assert_eq!(RefresherRole::parse("  uas  "), Some(RefresherRole::Uas));
    }

    #[test]
    fn refresher_role_parse_invalid() {
        assert_eq!(RefresherRole::parse("invalid"), None);
        assert_eq!(RefresherRole::parse(""), None);
        assert_eq!(RefresherRole::parse("proxy"), None);
    }

    #[test]
    fn refresher_role_round_trip() {
        let uac = RefresherRole::Uac;
        let formatted = uac.to_string();
        let parsed = RefresherRole::parse(&formatted).unwrap();
        assert_eq!(parsed, uac);

        let uas = RefresherRole::Uas;
        let formatted = uas.to_string();
        let parsed = RefresherRole::parse(&formatted).unwrap();
        assert_eq!(parsed, uas);
    }

    // Integration tests

    #[test]
    fn session_expires_with_min_se_validation() {
        let session_expires = SessionExpires::new(1800);
        let min_se = MinSessionExpires::new(90);

        assert!(session_expires.delta_seconds >= min_se.delta_seconds);
    }

    #[test]
    fn session_expires_below_min_se() {
        let session_expires = SessionExpires::new(60);
        let min_se = MinSessionExpires::new(90);

        assert!(session_expires.delta_seconds < min_se.delta_seconds);
    }

    #[test]
    fn rfc_4028_default_values() {
        // RFC 4028 specifies minimum 90s, default 1800s
        assert_eq!(SessionExpires::minimum(), 90);
        assert_eq!(SessionExpires::default_interval(), 1800);
        assert_eq!(MinSessionExpires::default_minimum(), 90);
    }
}
