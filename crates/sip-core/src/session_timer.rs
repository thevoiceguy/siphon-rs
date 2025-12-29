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
//! let session_expires = SessionExpires::new(1800).unwrap()
//!     .with_refresher(RefresherRole::Uac);
//!
//! assert_eq!(session_expires.delta_seconds(), 1800);
//! assert_eq!(session_expires.refresher(), Some(RefresherRole::Uac));
//! ```
//!
//! ### Parsing Session-Expires header
//!
//! ```
//! use sip_core::{SessionExpires, RefresherRole};
//!
//! let se = SessionExpires::parse("1800;refresher=uas").unwrap();
//! assert_eq!(se.delta_seconds(), 1800);
//! assert_eq!(se.refresher(), Some(RefresherRole::Uas));
//! ```
//!
//! ### Creating Min-SE header
//!
//! ```
//! use sip_core::MinSessionExpires;
//!
//! // Minimum session interval is 120 seconds
//! let min_se = MinSessionExpires::new(120).unwrap();
//! assert_eq!(min_se.delta_seconds(), 120);
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

// =============================================================================
// Security Hardening: Constants and Error Types
// =============================================================================

/// Maximum allowed session expiration interval (24 hours).
///
/// While RFC 4028 doesn't specify a hard maximum, 24 hours is a reasonable
/// practical limit for session timers.
const MAX_SESSION_EXPIRES: u32 = 86400;

/// Maximum allowed Min-SE value (2 hours).
///
/// Limits the minimum session interval servers can require.
const MAX_MIN_SE: u32 = 7200;

/// Error types for session timer validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTimerError {
    /// Value is below the minimum allowed (90 seconds per RFC 4028)
    TooSmall {
        field: &'static str,
        min: u32,
        actual: u32,
    },
    /// Value exceeds the maximum allowed
    TooLarge {
        field: &'static str,
        max: u32,
        actual: u32,
    },
    /// Invalid format or parse error
    InvalidFormat(String),
    /// Contains invalid characters
    InvalidCharacter(String),
}

impl fmt::Display for SessionTimerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionTimerError::TooSmall { field, min, actual } => {
                write!(f, "{} too small: {} < {} (minimum)", field, actual, min)
            }
            SessionTimerError::TooLarge { field, max, actual } => {
                write!(f, "{} too large: {} > {} (maximum)", field, actual, max)
            }
            SessionTimerError::InvalidFormat(msg) => {
                write!(f, "Invalid format: {}", msg)
            }
            SessionTimerError::InvalidCharacter(msg) => {
                write!(f, "Invalid character: {}", msg)
            }
        }
    }
}

impl std::error::Error for SessionTimerError {}

// =============================================================================
// End of Security Constants and Error Types
// =============================================================================

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
/// let se1 = SessionExpires::new(1800).unwrap();
/// assert_eq!(se1.to_string(), "1800");
///
/// // 1 hour session, UAC must refresh
/// let se2 = SessionExpires::new(3600).unwrap().with_refresher(RefresherRole::Uac);
/// assert_eq!(se2.to_string(), "3600;refresher=uac");
///
/// // Parse from string
/// let se3 = SessionExpires::parse("1800;refresher=uas").unwrap();
/// assert_eq!(se3.delta_seconds(), 1800);
/// assert_eq!(se3.refresher(), Some(RefresherRole::Uas));
/// ```
///
/// # Security
///
/// Fields are private with validated accessors to prevent invalid values.
/// All inputs are validated against RFC 4028 requirements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionExpires {
    /// Session interval in seconds (minimum 90, recommended default 1800)
    delta_seconds: u32,
    /// Optional refresher role (uac or uas)
    refresher: Option<RefresherRole>,
}

impl SessionExpires {
    /// Creates a new Session-Expires header with the given interval.
    ///
    /// # Arguments
    ///
    /// * `delta_seconds` - Session interval in seconds (must be 90-86400)
    ///
    /// # Returns
    ///
    /// Returns `Ok(SessionExpires)` if valid, or `Err` if:
    /// - `delta_seconds` < 90 (RFC 4028 minimum)
    /// - `delta_seconds` > 86400 (24 hours, practical maximum)
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// let se = SessionExpires::new(1800).unwrap();
    /// assert_eq!(se.delta_seconds(), 1800);
    /// assert_eq!(se.refresher(), None);
    ///
    /// // Too small
    /// assert!(SessionExpires::new(60).is_err());
    ///
    /// // Too large
    /// assert!(SessionExpires::new(100000).is_err());
    /// ```
    pub fn new(delta_seconds: u32) -> Result<Self, SessionTimerError> {
        if delta_seconds < Self::minimum() {
            return Err(SessionTimerError::TooSmall {
                field: "Session-Expires",
                min: Self::minimum(),
                actual: delta_seconds,
            });
        }
        if delta_seconds > Self::maximum() {
            return Err(SessionTimerError::TooLarge {
                field: "Session-Expires",
                max: Self::maximum(),
                actual: delta_seconds,
            });
        }
        Ok(Self {
            delta_seconds,
            refresher: None,
        })
    }

    /// Gets the session interval in seconds.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// let se = SessionExpires::new(1800).unwrap();
    /// assert_eq!(se.delta_seconds(), 1800);
    /// ```
    pub fn delta_seconds(&self) -> u32 {
        self.delta_seconds
    }

    /// Gets the refresher role, if specified.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::{SessionExpires, RefresherRole};
    ///
    /// let se = SessionExpires::new(1800).unwrap()
    ///     .with_refresher(RefresherRole::Uac);
    /// assert_eq!(se.refresher(), Some(RefresherRole::Uac));
    /// ```
    pub fn refresher(&self) -> Option<RefresherRole> {
        self.refresher
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
    /// let se = SessionExpires::new(1800).unwrap()
    ///     .with_refresher(RefresherRole::Uac);
    /// assert_eq!(se.refresher(), Some(RefresherRole::Uac));
    /// ```
    pub fn with_refresher(mut self, role: RefresherRole) -> Self {
        self.refresher = Some(role);
        self
    }

    /// Parses a Session-Expires header from a string with validation.
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
    /// - `Some(SessionExpires)` if parsing and validation succeed
    /// - `None` if the header is invalid, empty, or out of range
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::{SessionExpires, RefresherRole};
    ///
    /// let se1 = SessionExpires::parse("1800").unwrap();
    /// assert_eq!(se1.delta_seconds(), 1800);
    /// assert_eq!(se1.refresher(), None);
    ///
    /// let se2 = SessionExpires::parse("3600;refresher=uac").unwrap();
    /// assert_eq!(se2.delta_seconds(), 3600);
    /// assert_eq!(se2.refresher(), Some(RefresherRole::Uac));
    ///
    /// let se3 = SessionExpires::parse("  1800 ; refresher=uas  ").unwrap();
    /// assert_eq!(se3.delta_seconds(), 1800);
    /// assert_eq!(se3.refresher(), Some(RefresherRole::Uas));
    ///
    /// // Invalid values return None
    /// assert!(SessionExpires::parse("60").is_none());  // Too small
    /// assert!(SessionExpires::parse("100000").is_none());  // Too large
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        // Security: Check for control characters BEFORE trimming
        if input.chars().any(|c| c.is_control()) {
            return None;
        }

        let input = input.trim();
        if input.is_empty() {
            return None;
        }

        // Split on semicolon to separate delta-seconds from parameters
        let parts: Vec<&str> = input.split(';').collect();

        // Parse delta-seconds
        let delta_seconds = parts[0].trim().parse::<u32>().ok()?;

        // Security: Validate range
        if delta_seconds < Self::minimum() || delta_seconds > Self::maximum() {
            return None;
        }

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

    /// Returns the maximum acceptable session interval (24 hours).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// assert_eq!(SessionExpires::maximum(), 86400);
    /// ```
    pub const fn maximum() -> u32 {
        MAX_SESSION_EXPIRES
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

    /// Returns true if this session interval is valid per RFC 4028.
    ///
    /// Checks if value is within the valid range (90-86400 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SessionExpires;
    ///
    /// assert!(SessionExpires::new(1800).unwrap().is_valid());
    /// assert!(SessionExpires::new(90).unwrap().is_valid());
    /// assert!(SessionExpires::new(86400).unwrap().is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        self.delta_seconds >= Self::minimum() && self.delta_seconds <= Self::maximum()
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
/// let min_se1 = MinSessionExpires::new(90).unwrap();
/// assert_eq!(min_se1.to_string(), "90");
///
/// // Minimum 2 minutes (120 seconds)
/// let min_se2 = MinSessionExpires::new(120).unwrap();
/// assert_eq!(min_se2.to_string(), "120");
///
/// // Parse from string
/// let min_se3 = MinSessionExpires::parse("300").unwrap();
/// assert_eq!(min_se3.delta_seconds(), 300);
/// ```
///
/// # Security
///
/// Fields are private with validated accessors to prevent invalid values.
/// All inputs are validated against RFC 4028 requirements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MinSessionExpires {
    /// Minimum session interval in seconds (default 90 per RFC 4028)
    delta_seconds: u32,
}

impl MinSessionExpires {
    /// Creates a new Min-SE header with the given minimum interval.
    ///
    /// # Arguments
    ///
    /// * `delta_seconds` - Minimum session interval in seconds (must be 90-7200)
    ///
    /// # Returns
    ///
    /// Returns `Ok(MinSessionExpires)` if valid, or `Err` if:
    /// - `delta_seconds` < 90 (RFC 4028 minimum)
    /// - `delta_seconds` > 7200 (2 hours, practical maximum)
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// let min_se = MinSessionExpires::new(120).unwrap();
    /// assert_eq!(min_se.delta_seconds(), 120);
    ///
    /// // Too small
    /// assert!(MinSessionExpires::new(60).is_err());
    ///
    /// // Too large
    /// assert!(MinSessionExpires::new(10000).is_err());
    /// ```
    pub fn new(delta_seconds: u32) -> Result<Self, SessionTimerError> {
        if delta_seconds < Self::default_minimum() {
            return Err(SessionTimerError::TooSmall {
                field: "Min-SE",
                min: Self::default_minimum(),
                actual: delta_seconds,
            });
        }
        if delta_seconds > Self::maximum() {
            return Err(SessionTimerError::TooLarge {
                field: "Min-SE",
                max: Self::maximum(),
                actual: delta_seconds,
            });
        }
        Ok(Self { delta_seconds })
    }

    /// Gets the minimum session interval in seconds.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// let min_se = MinSessionExpires::new(120).unwrap();
    /// assert_eq!(min_se.delta_seconds(), 120);
    /// ```
    pub fn delta_seconds(&self) -> u32 {
        self.delta_seconds
    }

    /// Parses a Min-SE header from a string with validation.
    ///
    /// # Format
    ///
    /// ```text
    /// Min-SE: delta-seconds
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(MinSessionExpires)` if parsing and validation succeed
    /// - `None` if the header is invalid, empty, or out of range
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// let min_se = MinSessionExpires::parse("90").unwrap();
    /// assert_eq!(min_se.delta_seconds(), 90);
    ///
    /// let min_se2 = MinSessionExpires::parse("  120  ").unwrap();
    /// assert_eq!(min_se2.delta_seconds(), 120);
    ///
    /// assert!(MinSessionExpires::parse("").is_none());
    /// assert!(MinSessionExpires::parse("invalid").is_none());
    /// assert!(MinSessionExpires::parse("60").is_none());  // Too small
    /// assert!(MinSessionExpires::parse("10000").is_none());  // Too large
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        // Security: Check for control characters BEFORE trimming
        if input.chars().any(|c| c.is_control()) {
            return None;
        }

        let input = input.trim();
        if input.is_empty() {
            return None;
        }

        let delta_seconds = input.parse::<u32>().ok()?;

        // Security: Validate range
        if delta_seconds < Self::default_minimum() || delta_seconds > Self::maximum() {
            return None;
        }

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

    /// Returns the maximum acceptable Min-SE value (2 hours).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// assert_eq!(MinSessionExpires::maximum(), 7200);
    /// ```
    pub const fn maximum() -> u32 {
        MAX_MIN_SE
    }

    /// Returns true if this minimum is valid per RFC 4028.
    ///
    /// Checks if value is within the valid range (90-7200 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::MinSessionExpires;
    ///
    /// assert!(MinSessionExpires::new(90).unwrap().is_valid());
    /// assert!(MinSessionExpires::new(120).unwrap().is_valid());
    /// assert!(MinSessionExpires::new(7200).unwrap().is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        self.delta_seconds >= Self::default_minimum() && self.delta_seconds <= Self::maximum()
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
        let se = SessionExpires::new(1800).unwrap();
        assert_eq!(se.delta_seconds(), 1800);
        assert_eq!(se.refresher(), None);
    }

    #[test]
    fn session_expires_with_refresher() {
        let se = SessionExpires::new(1800)
            .unwrap()
            .with_refresher(RefresherRole::Uac);
        assert_eq!(se.delta_seconds(), 1800);
        assert_eq!(se.refresher(), Some(RefresherRole::Uac));
    }

    #[test]
    fn session_expires_format_no_refresher() {
        let se = SessionExpires::new(3600).unwrap();
        assert_eq!(se.to_string(), "3600");
    }

    #[test]
    fn session_expires_format_with_refresher_uac() {
        let se = SessionExpires::new(1800)
            .unwrap()
            .with_refresher(RefresherRole::Uac);
        assert_eq!(se.to_string(), "1800;refresher=uac");
    }

    #[test]
    fn session_expires_format_with_refresher_uas() {
        let se = SessionExpires::new(1800)
            .unwrap()
            .with_refresher(RefresherRole::Uas);
        assert_eq!(se.to_string(), "1800;refresher=uas");
    }

    #[test]
    fn session_expires_parse_simple() {
        let se = SessionExpires::parse("1800").unwrap();
        assert_eq!(se.delta_seconds(), 1800);
        assert_eq!(se.refresher(), None);
    }

    #[test]
    fn session_expires_parse_with_refresher_uac() {
        let se = SessionExpires::parse("1800;refresher=uac").unwrap();
        assert_eq!(se.delta_seconds(), 1800);
        assert_eq!(se.refresher(), Some(RefresherRole::Uac));
    }

    #[test]
    fn session_expires_parse_with_refresher_uas() {
        let se = SessionExpires::parse("3600;refresher=uas").unwrap();
        assert_eq!(se.delta_seconds(), 3600);
        assert_eq!(se.refresher(), Some(RefresherRole::Uas));
    }

    #[test]
    fn session_expires_parse_with_whitespace() {
        let se = SessionExpires::parse("  1800 ; refresher=uac  ").unwrap();
        assert_eq!(se.delta_seconds(), 1800);
        assert_eq!(se.refresher(), Some(RefresherRole::Uac));
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
        let original = SessionExpires::new(1800)
            .unwrap()
            .with_refresher(RefresherRole::Uas);
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
        assert!(SessionExpires::new(90).unwrap().is_valid());
        assert!(SessionExpires::new(1800).unwrap().is_valid());
        assert!(SessionExpires::new(3600).unwrap().is_valid());
        // Values below minimum should fail to construct
        assert!(SessionExpires::new(60).is_err());
        assert!(SessionExpires::new(89).is_err());
    }

    // MinSessionExpires tests

    #[test]
    fn min_session_expires_new() {
        let min_se = MinSessionExpires::new(120).unwrap();
        assert_eq!(min_se.delta_seconds(), 120);
    }

    #[test]
    fn min_session_expires_format() {
        let min_se = MinSessionExpires::new(90).unwrap();
        assert_eq!(min_se.to_string(), "90");
    }

    #[test]
    fn min_session_expires_parse() {
        let min_se = MinSessionExpires::parse("120").unwrap();
        assert_eq!(min_se.delta_seconds(), 120);
    }

    #[test]
    fn min_session_expires_parse_with_whitespace() {
        let min_se = MinSessionExpires::parse("  90  ").unwrap();
        assert_eq!(min_se.delta_seconds(), 90);
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
        let original = MinSessionExpires::new(300).unwrap();
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
        assert!(MinSessionExpires::new(90).unwrap().is_valid());
        assert!(MinSessionExpires::new(120).unwrap().is_valid());
        assert!(MinSessionExpires::new(300).unwrap().is_valid());
        // Values below minimum should fail to construct
        assert!(MinSessionExpires::new(60).is_err());
        assert!(MinSessionExpires::new(89).is_err());
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
        let session_expires = SessionExpires::new(1800).unwrap();
        let min_se = MinSessionExpires::new(90).unwrap();

        assert!(session_expires.delta_seconds() >= min_se.delta_seconds());
    }

    #[test]
    fn session_expires_below_min_se() {
        // Test that a valid session_expires can be less than a valid min_se
        let session_expires = SessionExpires::new(100).unwrap();
        let min_se = MinSessionExpires::new(120).unwrap();

        assert!(session_expires.delta_seconds() < min_se.delta_seconds());
    }

    #[test]
    fn rfc_4028_default_values() {
        // RFC 4028 specifies minimum 90s, default 1800s
        assert_eq!(SessionExpires::minimum(), 90);
        assert_eq!(SessionExpires::default_interval(), 1800);
        assert_eq!(MinSessionExpires::default_minimum(), 90);
    }

    // Security tests

    #[test]
    fn reject_session_expires_too_small() {
        // Below minimum (90 seconds)
        assert!(SessionExpires::new(0).is_err());
        assert!(SessionExpires::new(60).is_err());
        assert!(SessionExpires::new(89).is_err());

        // At minimum should succeed
        assert!(SessionExpires::new(90).is_ok());
    }

    #[test]
    fn reject_session_expires_too_large() {
        // Above maximum (86400 seconds = 24 hours)
        assert!(SessionExpires::new(86401).is_err());
        assert!(SessionExpires::new(100000).is_err());
        assert!(SessionExpires::new(u32::MAX).is_err());

        // At maximum should succeed
        assert!(SessionExpires::new(86400).is_ok());
    }

    #[test]
    fn reject_session_expires_with_control_characters() {
        // Control characters in delta-seconds field
        assert!(SessionExpires::parse("1800\x00").is_none());
        assert!(SessionExpires::parse("1800\x01").is_none());
        assert!(SessionExpires::parse("1800\r\n").is_none());
        assert!(SessionExpires::parse("\x001800").is_none());

        // Control characters in refresher parameter
        assert!(SessionExpires::parse("1800;refresher=\x00uac").is_none());
        assert!(SessionExpires::parse("1800;refresher=uac\x01").is_none());
    }

    #[test]
    fn reject_session_expires_parse_out_of_range() {
        // Parser should reject values outside valid range
        assert!(SessionExpires::parse("60").is_none());
        assert!(SessionExpires::parse("89").is_none());
        assert!(SessionExpires::parse("100000").is_none());
        assert!(SessionExpires::parse("999999999").is_none());

        // Valid values should parse
        assert!(SessionExpires::parse("90").is_some());
        assert!(SessionExpires::parse("1800").is_some());
        assert!(SessionExpires::parse("86400").is_some());
    }

    #[test]
    fn reject_min_se_too_small() {
        // Below minimum (90 seconds)
        assert!(MinSessionExpires::new(0).is_err());
        assert!(MinSessionExpires::new(60).is_err());
        assert!(MinSessionExpires::new(89).is_err());

        // At minimum should succeed
        assert!(MinSessionExpires::new(90).is_ok());
    }

    #[test]
    fn reject_min_se_too_large() {
        // Above maximum (7200 seconds = 2 hours)
        assert!(MinSessionExpires::new(7201).is_err());
        assert!(MinSessionExpires::new(10000).is_err());
        assert!(MinSessionExpires::new(u32::MAX).is_err());

        // At maximum should succeed
        assert!(MinSessionExpires::new(7200).is_ok());
    }

    #[test]
    fn reject_min_se_with_control_characters() {
        // Control characters should be rejected
        assert!(MinSessionExpires::parse("120\x00").is_none());
        assert!(MinSessionExpires::parse("120\x01").is_none());
        assert!(MinSessionExpires::parse("120\r\n").is_none());
        assert!(MinSessionExpires::parse("\x00120").is_none());
    }

    #[test]
    fn reject_min_se_parse_out_of_range() {
        // Parser should reject values outside valid range
        assert!(MinSessionExpires::parse("60").is_none());
        assert!(MinSessionExpires::parse("89").is_none());
        assert!(MinSessionExpires::parse("10000").is_none());
        assert!(MinSessionExpires::parse("999999999").is_none());

        // Valid values should parse
        assert!(MinSessionExpires::parse("90").is_some());
        assert!(MinSessionExpires::parse("120").is_some());
        assert!(MinSessionExpires::parse("7200").is_some());
    }

    #[test]
    fn session_expires_fields_are_private() {
        // This test verifies that fields are private by attempting to use
        // only public API. If this compiles, encapsulation is maintained.
        let se = SessionExpires::new(1800)
            .unwrap()
            .with_refresher(RefresherRole::Uac);

        // Can only access via getters
        assert_eq!(se.delta_seconds(), 1800);
        assert_eq!(se.refresher(), Some(RefresherRole::Uac));

        // The following would not compile if uncommented (private fields):
        // let _ = se.delta_seconds;
        // let _ = se.refresher;
    }

    #[test]
    fn min_session_expires_fields_are_private() {
        // This test verifies that fields are private by attempting to use
        // only public API. If this compiles, encapsulation is maintained.
        let min_se = MinSessionExpires::new(120).unwrap();

        // Can only access via getters
        assert_eq!(min_se.delta_seconds(), 120);

        // The following would not compile if uncommented (private field):
        // let _ = min_se.delta_seconds;
    }

    #[test]
    fn session_expires_error_messages() {
        // Verify error messages are informative
        match SessionExpires::new(60) {
            Err(SessionTimerError::TooSmall { field, min, actual }) => {
                assert_eq!(field, "Session-Expires");
                assert_eq!(min, 90);
                assert_eq!(actual, 60);
            }
            _ => panic!("Expected TooSmall error"),
        }

        match SessionExpires::new(100000) {
            Err(SessionTimerError::TooLarge { field, max, actual }) => {
                assert_eq!(field, "Session-Expires");
                assert_eq!(max, 86400);
                assert_eq!(actual, 100000);
            }
            _ => panic!("Expected TooLarge error"),
        }
    }

    #[test]
    fn min_session_expires_error_messages() {
        // Verify error messages are informative
        match MinSessionExpires::new(60) {
            Err(SessionTimerError::TooSmall { field, min, actual }) => {
                assert_eq!(field, "Min-SE");
                assert_eq!(min, 90);
                assert_eq!(actual, 60);
            }
            _ => panic!("Expected TooSmall error"),
        }

        match MinSessionExpires::new(10000) {
            Err(SessionTimerError::TooLarge { field, max, actual }) => {
                assert_eq!(field, "Min-SE");
                assert_eq!(max, 7200);
                assert_eq!(actual, 10000);
            }
            _ => panic!("Expected TooLarge error"),
        }
    }
}
