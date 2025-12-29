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

const MAX_CALL_ID_LENGTH: usize = 256;
const MAX_TAG_LENGTH: usize = 128;
const MAX_PARSE_INPUT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplacesError {
    CallIdTooLong { max: usize, actual: usize },
    TagTooLong { max: usize, actual: usize },
    InvalidCallId(String),
    InvalidTag(String),
    EmptyCallId,
    EmptyTag,
    MissingToTag,
    MissingFromTag,
    InputTooLarge { max: usize, actual: usize },
    ParseError(String),
}

impl std::fmt::Display for ReplacesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CallIdTooLong { max, actual } => {
                write!(f, "Call-ID too long (max {}, got {})", max, actual)
            }
            Self::TagTooLong { max, actual } => {
                write!(f, "tag too long (max {}, got {})", max, actual)
            }
            Self::InvalidCallId(msg) => write!(f, "invalid Call-ID: {}", msg),
            Self::InvalidTag(msg) => write!(f, "invalid tag: {}", msg),
            Self::EmptyCallId => write!(f, "Call-ID cannot be empty"),
            Self::EmptyTag => write!(f, "tag cannot be empty"),
            Self::MissingToTag => write!(f, "missing required to-tag parameter"),
            Self::MissingFromTag => write!(f, "missing required from-tag parameter"),
            Self::InputTooLarge { max, actual } => {
                write!(f, "input too large (max {}, got {})", max, actual)
            }
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for ReplacesError {}

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
///
/// # Security
///
/// ReplacesHeader validates all fields to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplacesHeader {
    call_id: SmolStr,
    to_tag: SmolStr,
    from_tag: SmolStr,
    early_only: bool,
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
    /// # Errors
    ///
    /// Returns an error if any parameter is invalid.
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
    /// ).unwrap();
    /// ```
    pub fn new(
        call_id: impl AsRef<str>,
        to_tag: impl AsRef<str>,
        from_tag: impl AsRef<str>,
    ) -> Result<Self, ReplacesError> {
        validate_call_id(call_id.as_ref())?;
        validate_tag(to_tag.as_ref())?;
        validate_tag(from_tag.as_ref())?;

        Ok(Self {
            call_id: SmolStr::new(call_id.as_ref()),
            to_tag: SmolStr::new(to_tag.as_ref()),
            from_tag: SmolStr::new(from_tag.as_ref()),
            early_only: false,
        })
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
    /// ).unwrap().with_early_only(true);
    /// ```
    pub fn with_early_only(mut self, early_only: bool) -> Self {
        self.early_only = early_only;
        self
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the to-tag.
    pub fn to_tag(&self) -> &str {
        &self.to_tag
    }

    /// Returns the from-tag.
    pub fn from_tag(&self) -> &str {
        &self.from_tag
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
    /// - `Ok(ReplacesHeader)` if parsing succeeds
    /// - `Err(ReplacesError)` if the header is malformed or missing required parameters
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
    /// assert_eq!(header.call_id(), "425928@bobster.example.org");
    /// assert_eq!(header.to_tag(), "7743");
    /// assert_eq!(header.from_tag(), "6472");
    /// assert!(!header.is_early_only());
    /// ```
    pub fn parse(input: &str) -> Result<Self, ReplacesError> {
        if input.len() > MAX_PARSE_INPUT {
            return Err(ReplacesError::InputTooLarge {
                max: MAX_PARSE_INPUT,
                actual: input.len(),
            });
        }

        let input = input.trim();

        // Split by semicolon to separate call-id from parameters
        let parts: Vec<&str> = input.split(';').map(|s| s.trim()).collect();

        if parts.is_empty() {
            return Err(ReplacesError::ParseError("empty input".to_string()));
        }

        let call_id = parts[0];
        validate_call_id(call_id)?;

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
                    validate_tag(value)?;
                    if to_tag.is_some() {
                        return Err(ReplacesError::ParseError(
                            "duplicate to-tag parameter".to_string(),
                        ));
                    }
                    to_tag = Some(value);
                } else if key.eq_ignore_ascii_case("from-tag") {
                    validate_tag(value)?;
                    if from_tag.is_some() {
                        return Err(ReplacesError::ParseError(
                            "duplicate from-tag parameter".to_string(),
                        ));
                    }
                    from_tag = Some(value);
                } else {
                    return Err(ReplacesError::ParseError(format!(
                        "unknown parameter: {}",
                        key
                    )));
                }
            } else {
                return Err(ReplacesError::ParseError(
                    "parameter missing '='".to_string(),
                ));
            }
        }

        // Both to-tag and from-tag are required
        let to_tag = to_tag.ok_or(ReplacesError::MissingToTag)?;
        let from_tag = from_tag.ok_or(ReplacesError::MissingFromTag)?;

        Ok(Self {
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

// Validation functions

fn validate_call_id(call_id: &str) -> Result<(), ReplacesError> {
    if call_id.is_empty() {
        return Err(ReplacesError::EmptyCallId);
    }

    if call_id.len() > MAX_CALL_ID_LENGTH {
        return Err(ReplacesError::CallIdTooLong {
            max: MAX_CALL_ID_LENGTH,
            actual: call_id.len(),
        });
    }

    if call_id.chars().any(|c| c.is_ascii_control()) {
        return Err(ReplacesError::InvalidCallId(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), ReplacesError> {
    if tag.is_empty() {
        return Err(ReplacesError::EmptyTag);
    }

    if tag.len() > MAX_TAG_LENGTH {
        return Err(ReplacesError::TagTooLong {
            max: MAX_TAG_LENGTH,
            actual: tag.len(),
        });
    }

    if tag.chars().any(|c| c.is_ascii_control()) {
        return Err(ReplacesError::InvalidTag(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_replaces_header() {
        let replaces = ReplacesHeader::new("425928@bobster.example.org", "7743", "6472").unwrap();

        assert_eq!(replaces.call_id(), "425928@bobster.example.org");
        assert_eq!(replaces.to_tag(), "7743");
        assert_eq!(replaces.from_tag(), "6472");
        assert!(!replaces.is_early_only());
    }

    #[test]
    fn replaces_with_early_only() {
        let replaces = ReplacesHeader::new("call123@example.com", "tag1", "tag2")
            .unwrap()
            .with_early_only(true);

        assert!(replaces.is_early_only());
    }

    #[test]
    fn format_replaces_header() {
        let replaces = ReplacesHeader::new("425928@bobster.example.org", "7743", "6472").unwrap();

        let formatted = replaces.to_string();
        assert_eq!(
            formatted,
            "425928@bobster.example.org;to-tag=7743;from-tag=6472"
        );
    }

    #[test]
    fn format_replaces_with_early_only() {
        let replaces = ReplacesHeader::new("98asjd8@test.com", "12345", "67890")
            .unwrap()
            .with_early_only(true);

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

        assert_eq!(replaces.call_id(), "425928@bobster.example.org");
        assert_eq!(replaces.to_tag(), "7743");
        assert_eq!(replaces.from_tag(), "6472");
        assert!(!replaces.is_early_only());
    }

    #[test]
    fn parse_replaces_with_early_only() {
        let input = "98asjd8@test.com;to-tag=12345;from-tag=67890;early-only";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id(), "98asjd8@test.com");
        assert_eq!(replaces.to_tag(), "12345");
        assert_eq!(replaces.from_tag(), "67890");
        assert!(replaces.is_early_only());
    }

    #[test]
    fn parse_replaces_with_whitespace() {
        let input = "call123@example.com ; to-tag=abc ; from-tag=def ; early-only";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id(), "call123@example.com");
        assert_eq!(replaces.to_tag(), "abc");
        assert_eq!(replaces.from_tag(), "def");
        assert!(replaces.is_early_only());
    }

    #[test]
    fn parse_replaces_case_insensitive() {
        let input = "call@example.com;TO-TAG=123;FROM-TAG=456;EARLY-ONLY";
        let replaces = ReplacesHeader::parse(input).unwrap();

        assert_eq!(replaces.call_id(), "call@example.com");
        assert_eq!(replaces.to_tag(), "123");
        assert_eq!(replaces.from_tag(), "456");
        assert!(replaces.is_early_only());
    }

    #[test]
    fn reject_duplicate_to_tag() {
        let input = "call@example.com;to-tag=123;to-tag=456;from-tag=789";
        assert!(ReplacesHeader::parse(input).is_err());
    }

    #[test]
    fn reject_duplicate_from_tag() {
        let input = "call@example.com;to-tag=123;from-tag=456;from-tag=789";
        assert!(ReplacesHeader::parse(input).is_err());
    }

    #[test]
    fn reject_unknown_param() {
        let input = "call@example.com;to-tag=123;from-tag=456;foo=bar";
        assert!(ReplacesHeader::parse(input).is_err());
    }

    #[test]
    fn reject_param_missing_equals() {
        let input = "call@example.com;to-tag=123;from-tag=456;foo";
        assert!(ReplacesHeader::parse(input).is_err());
    }

    #[test]
    fn parse_missing_to_tag() {
        let input = "call@example.com;from-tag=456";
        assert!(matches!(
            ReplacesHeader::parse(input),
            Err(ReplacesError::MissingToTag)
        ));
    }

    #[test]
    fn parse_missing_from_tag() {
        let input = "call@example.com;to-tag=123";
        assert!(matches!(
            ReplacesHeader::parse(input),
            Err(ReplacesError::MissingFromTag)
        ));
    }

    #[test]
    fn parse_empty_string() {
        assert!(ReplacesHeader::parse("").is_err());
    }

    #[test]
    fn parse_only_call_id() {
        let input = "call@example.com";
        assert!(matches!(
            ReplacesHeader::parse(input),
            Err(ReplacesError::MissingToTag)
        ));
    }

    #[test]
    fn round_trip_replaces() {
        let original = ReplacesHeader::new("test@example.com", "tag-a", "tag-b")
            .unwrap()
            .with_early_only(true);

        let formatted = original.to_string();
        let parsed = ReplacesHeader::parse(&formatted).unwrap();

        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_without_early_only() {
        let original = ReplacesHeader::new("abc123@host.com", "local", "remote").unwrap();

        let formatted = original.to_string();
        let parsed = ReplacesHeader::parse(&formatted).unwrap();

        assert_eq!(parsed, original);
    }

    // Security tests

    #[test]
    fn reject_crlf_in_call_id() {
        let result = ReplacesHeader::new("call123\r\nInjected: evil", "tag1", "tag2");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_to_tag() {
        let result = ReplacesHeader::new("call123@example.com", "tag1\r\ninjected", "tag2");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_from_tag() {
        let result = ReplacesHeader::new("call123@example.com", "tag1", "tag2\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_call_id() {
        let result = ReplacesHeader::new("", "tag1", "tag2");
        assert!(matches!(result, Err(ReplacesError::EmptyCallId)));
    }

    #[test]
    fn reject_empty_to_tag() {
        let result = ReplacesHeader::new("call123@example.com", "", "tag2");
        assert!(matches!(result, Err(ReplacesError::EmptyTag)));
    }

    #[test]
    fn reject_empty_from_tag() {
        let result = ReplacesHeader::new("call123@example.com", "tag1", "");
        assert!(matches!(result, Err(ReplacesError::EmptyTag)));
    }

    #[test]
    fn reject_oversized_call_id() {
        let long_call_id = "x".repeat(MAX_CALL_ID_LENGTH + 1);
        let result = ReplacesHeader::new(&long_call_id, "tag1", "tag2");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_tag() {
        let long_tag = "x".repeat(MAX_TAG_LENGTH + 1);
        let result = ReplacesHeader::new("call123@example.com", &long_tag, "tag2");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_parse_input() {
        let huge = format!(
            "call@example.com;to-tag=tag1;from-tag=tag2{}",
            ";param=value".repeat(200)
        );
        let result = ReplacesHeader::parse(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn parse_validates_call_id() {
        let input = "call\r\ninjected@example.com;to-tag=tag1;from-tag=tag2";
        let result = ReplacesHeader::parse(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_validates_tags() {
        let input = "call@example.com;to-tag=tag1\r\ninjected;from-tag=tag2";
        let result = ReplacesHeader::parse(input);
        assert!(result.is_err());
    }

    #[test]
    fn fields_are_private() {
        let replaces = ReplacesHeader::new("call@example.com", "tag1", "tag2").unwrap();

        // These should compile (read-only access)
        let _ = replaces.call_id();
        let _ = replaces.to_tag();
        let _ = replaces.from_tag();
        let _ = replaces.is_early_only();

        // These should NOT compile:
        // replaces.call_id = SmolStr::new("evil");  // ← Does not compile!
        // replaces.to_tag = SmolStr::new("evil");   // ← Does not compile!
        // replaces.early_only = true;               // ← Does not compile!
    }
}
