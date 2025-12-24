// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP Replaces header (RFC 3891).
//!
//! The Replaces header enables distributed peer-to-peer call control by allowing
//! one SIP dialog to logically replace another. This supports features like:
//! - Attended call transfer
//! - Call pickup
//! - Call parking and retrieval
//!
//! # Format
//!
//! ```text
//! Replaces: call-id; to-tag=value; from-tag=value [; early-only]
//! ```
//!
//! # Example
//!
//! ```text
//! Replaces: 425928@bobster.example.org;to-tag=7743;from-tag=6472
//! Replaces: 98asjd8@test.com;to-tag=12345;from-tag=67890;early-only
//! ```

use std::fmt;

use smol_str::SmolStr;

/// The Replaces header (RFC 3891).
///
/// The Replaces header is used to logically replace an existing SIP dialog with
/// a new one. It contains the Call-ID and dialog tags that identify the dialog
/// to be replaced.
///
/// # Required Parameters
///
/// - `call_id`: The Call-ID of the dialog to replace
/// - `to_tag`: The local tag from the To header of the dialog being replaced
/// - `from_tag`: The remote tag from the From header of the dialog being replaced
///
/// # Optional Parameters
///
/// - `early_only`: If true, only allows replacement of early (non-confirmed) dialogs.
///   This prevents race conditions where a dialog confirms while the Replaces
///   request is in transit.
///
/// # Usage Scenarios
///
/// ## Attended Transfer
///
/// 1. Alice calls Bob (Call A established)
/// 2. Bob puts Alice on hold
/// 3. Bob calls Charlie (Call B established - consultation call)
/// 4. Bob sends REFER to Alice with Replaces header pointing to Call B
/// 5. Alice sends INVITE to Charlie with Replaces header
/// 6. Charlie's phone replaces Call B with the new call to Alice
/// 7. Bob disconnects from both calls
///
/// Result: Alice and Charlie are connected, Bob is out of the picture.
///
/// ## Call Pickup
///
/// 1. Alice calls Bob's desk phone (ringing)
/// 2. Bob is in the lab and sees his desk phone ringing
/// 3. Bob's lab phone sends INVITE with Replaces to pick up the call
/// 4. The desk phone call is replaced by the lab phone call
///
/// Result: Alice is connected to Bob at his lab phone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplacesHeader {
    /// Call-ID of the dialog to replace
    pub call_id: SmolStr,
    /// Local tag (to-tag) of the dialog to replace
    pub to_tag: SmolStr,
    /// Remote tag (from-tag) of the dialog to replace
    pub from_tag: SmolStr,
    /// If true, only allows replacement of early (non-confirmed) dialogs
    pub early_only: bool,
}

impl ReplacesHeader {
    /// Creates a new Replaces header.
    ///
    /// # Arguments
    ///
    /// * `call_id` - The Call-ID of the dialog to replace
    /// * `to_tag` - The local tag (to-tag) of the dialog being replaced
    /// * `from_tag` - The remote tag (from-tag) of the dialog being replaced
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReplacesHeader;
    ///
    /// let replaces = ReplacesHeader::new(
    ///     "425928@bobster.example.org",
    ///     "7743",
    ///     "6472"
    /// );
    /// ```
    pub fn new(call_id: &str, to_tag: &str, from_tag: &str) -> Self {
        Self {
            call_id: SmolStr::new(call_id),
            to_tag: SmolStr::new(to_tag),
            from_tag: SmolStr::new(from_tag),
            early_only: false,
        }
    }

    /// Sets the early-only flag.
    ///
    /// When set to true, the Replaces header will only match early (non-confirmed)
    /// dialogs. If the target dialog has already been confirmed, the request will
    /// fail with a 486 Busy response.
    ///
    /// This is useful to prevent race conditions where a dialog transitions to
    /// confirmed state while the Replaces request is in transit.
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReplacesHeader;
    ///
    /// let replaces = ReplacesHeader::new(
    ///     "call123@example.com",
    ///     "tag1",
    ///     "tag2"
    /// ).with_early_only(true);
    /// ```
    pub fn with_early_only(mut self, early_only: bool) -> Self {
        self.early_only = early_only;
        self
    }

    /// Returns true if the early-only flag is set.
    pub fn is_early_only(&self) -> bool {
        self.early_only
    }

    /// Parses a Replaces header from a string.
    ///
    /// # Format
    ///
    /// ```text
    /// call-id; to-tag=value; from-tag=value [; early-only]
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(ReplacesHeader)` if parsing succeeds
    /// - `None` if the header is malformed or missing required parameters
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::ReplacesHeader;
    ///
    /// let header = ReplacesHeader::parse(
    ///     "425928@bobster.example.org;to-tag=7743;from-tag=6472"
    /// ).unwrap();
    ///
    /// assert_eq!(header.call_id, "425928@bobster.example.org");
    /// assert_eq!(header.to_tag, "7743");
    /// assert_eq!(header.from_tag, "6472");
    /// assert!(!header.early_only);
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();

        // Split by semicolon to separate call-id from parameters
        let parts: Vec<&str> = input.split(';').map(|s| s.trim()).collect();

        if parts.is_empty() {
            return None;
        }

        let call_id = parts[0];

        let mut to_tag = None;
        let mut from_tag = None;
        let mut early_only = false;

        // Parse parameters
        for part in &parts[1..] {
            if part.eq_ignore_ascii_case("early-only") {
                early_only = true;
            } else if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if key.eq_ignore_ascii_case("to-tag") {
                    to_tag = Some(value);
                } else if key.eq_ignore_ascii_case("from-tag") {
                    from_tag = Some(value);
                }
            }
        }

        // Both to-tag and from-tag are required
        let to_tag = to_tag?;
        let from_tag = from_tag?;

        Some(Self {
            call_id: SmolStr::new(call_id),
            to_tag: SmolStr::new(to_tag),
            from_tag: SmolStr::new(from_tag),
            early_only,
        })
    }
}

impl fmt::Display for ReplacesHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{};to-tag={};from-tag={}",
            self.call_id, self.to_tag, self.from_tag
        )?;

        if self.early_only {
            write!(f, ";early-only")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_replaces_header() {
        let replaces = ReplacesHeader::new("425928@bobster.example.org", "7743", "6472");

        assert_eq!(replaces.call_id, "425928@bobster.example.org");
        assert_eq!(replaces.to_tag, "7743");
        assert_eq!(replaces.from_tag, "6472");
        assert!(!replaces.early_only);
    }

    #[test]
    fn replaces_with_early_only() {
        let replaces =
            ReplacesHeader::new("call123@example.com", "tag1", "tag2").with_early_only(true);

        assert!(replaces.is_early_only());
        assert_eq!(replaces.early_only, true);
    }

    #[test]
    fn format_replaces_header() {
        let replaces = ReplacesHeader::new("425928@bobster.example.org", "7743", "6472");

        let formatted = replaces.to_string();
        assert_eq!(
            formatted,
            "425928@bobster.example.org;to-tag=7743;from-tag=6472"
        );
    }

    #[test]
    fn format_replaces_with_early_only() {
        let replaces =
            ReplacesHeader::new("98asjd8@test.com", "12345", "67890").with_early_only(true);

        let formatted = replaces.to_string();
        assert_eq!(
            formatted,
            "98asjd8@test.com;to-tag=12345;from-tag=67890;early-only"
        );
    }

    #[test]
    fn parse_basic_replaces() {
        let input = "425928@bobster.example.org;to-tag=7743;from-tag=6472";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id, "425928@bobster.example.org");
        assert_eq!(replaces.to_tag, "7743");
        assert_eq!(replaces.from_tag, "6472");
        assert!(!replaces.early_only);
    }

    #[test]
    fn parse_replaces_with_early_only() {
        let input = "98asjd8@test.com;to-tag=12345;from-tag=67890;early-only";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id, "98asjd8@test.com");
        assert_eq!(replaces.to_tag, "12345");
        assert_eq!(replaces.from_tag, "67890");
        assert!(replaces.early_only);
    }

    #[test]
    fn parse_replaces_with_whitespace() {
        let input = "call123@example.com ; to-tag=abc ; from-tag=def ; early-only";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id, "call123@example.com");
        assert_eq!(replaces.to_tag, "abc");
        assert_eq!(replaces.from_tag, "def");
        assert!(replaces.early_only);
    }

    #[test]
    fn parse_replaces_case_insensitive() {
        let input = "call@example.com;TO-TAG=123;FROM-TAG=456;EARLY-ONLY";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id, "call@example.com");
        assert_eq!(replaces.to_tag, "123");
        assert_eq!(replaces.from_tag, "456");
        assert!(replaces.early_only);
    }

    #[test]
    fn parse_missing_to_tag() {
        let input = "call@example.com;from-tag=456";
        assert!(ReplacesHeader::parse(input).is_none());
    }

    #[test]
    fn parse_missing_from_tag() {
        let input = "call@example.com;to-tag=123";
        assert!(ReplacesHeader::parse(input).is_none());
    }

    #[test]
    fn parse_empty_string() {
        assert!(ReplacesHeader::parse("").is_none());
    }

    #[test]
    fn parse_only_call_id() {
        let input = "call@example.com";
        assert!(ReplacesHeader::parse(input).is_none());
    }

    #[test]
    fn round_trip_replaces() {
        let original =
            ReplacesHeader::new("test@example.com", "tag-a", "tag-b").with_early_only(true);

        let formatted = original.to_string();
        let parsed = ReplacesHeader::parse(&formatted).unwrap();

        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_without_early_only() {
        let original = ReplacesHeader::new("abc123@host.com", "local", "remote");

        let formatted = original.to_string();
        let parsed = ReplacesHeader::parse(&formatted).unwrap();

        assert_eq!(parsed, original);
    }
}
