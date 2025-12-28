// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt;
use std::str::FromStr;

/// RFC 3323 Privacy header value.
///
/// The Privacy header indicates the privacy requirements of the user agent.
/// Multiple privacy values can be specified in a single Privacy header.
///
/// # Privacy Values
///
/// - **none**: No privacy requested
/// - **header**: Hide headers like Subject, Call-Info, Organization, User-Agent, Reply-To, In-Reply-To
/// - **session**: Hide session description (SDP)
/// - **user**: Hide user-level privacy (combination of header + session)
/// - **id**: Hide identity information (From, Contact, etc.)
/// - **critical**: Request must fail if privacy cannot be provided
///
/// # Examples
///
/// ```
/// use sip_core::PrivacyValue;
///
/// let priv_val = PrivacyValue::Id;
/// assert_eq!(priv_val.as_str(), "id");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivacyValue {
    /// No privacy requested
    None,
    /// Hide non-essential headers (Subject, Call-Info, Organization, User-Agent, Reply-To, In-Reply-To)
    Header,
    /// Hide session description (SDP)
    Session,
    /// User-level privacy (header + session)
    User,
    /// Hide identity information (From, Contact, etc.)
    Id,
    /// Request must fail if privacy cannot be provided
    Critical,
}

impl PrivacyValue {
    /// Returns the string representation of this privacy value.
    pub fn as_str(&self) -> &'static str {
        match self {
            PrivacyValue::None => "none",
            PrivacyValue::Header => "header",
            PrivacyValue::Session => "session",
            PrivacyValue::User => "user",
            PrivacyValue::Id => "id",
            PrivacyValue::Critical => "critical",
        }
    }

    /// Returns true if this privacy value requires identity anonymization.
    pub fn requires_identity_anonymization(&self) -> bool {
        matches!(self, PrivacyValue::Id | PrivacyValue::User)
    }

    /// Returns true if this privacy value requires header privacy.
    pub fn requires_header_privacy(&self) -> bool {
        matches!(self, PrivacyValue::Header | PrivacyValue::User)
    }

    /// Returns true if this privacy value requires session privacy.
    pub fn requires_session_privacy(&self) -> bool {
        matches!(self, PrivacyValue::Session | PrivacyValue::User)
    }
}

impl FromStr for PrivacyValue {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(PrivacyValue::None),
            "header" => Ok(PrivacyValue::Header),
            "session" => Ok(PrivacyValue::Session),
            "user" => Ok(PrivacyValue::User),
            "id" => Ok(PrivacyValue::Id),
            "critical" => Ok(PrivacyValue::Critical),
            _ => Err(()),
        }
    }
}

impl fmt::Display for PrivacyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// RFC 3323 Privacy header.
///
/// The Privacy header indicates the privacy requirements of the user agent.
/// Multiple privacy values can be specified.
///
/// # Examples
///
/// ```
/// use sip_core::{PrivacyHeader, PrivacyValue};
///
/// let header = PrivacyHeader::new(vec![PrivacyValue::Id, PrivacyValue::Critical]);
/// assert_eq!(header.to_string(), "id; critical");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyHeader {
    pub values: Vec<PrivacyValue>,
}

impl PrivacyHeader {
    /// Create a new Privacy header with the given values.
    pub fn new(values: Vec<PrivacyValue>) -> Self {
        Self { values }
    }

    /// Create a Privacy header with a single value.
    pub fn single(value: PrivacyValue) -> Self {
        Self {
            values: vec![value],
        }
    }

    /// Returns true if this Privacy header contains the given value.
    pub fn contains(&self, value: PrivacyValue) -> bool {
        self.values.contains(&value)
    }

    /// Returns true if the 'critical' privacy value is present.
    pub fn is_critical(&self) -> bool {
        self.contains(PrivacyValue::Critical)
    }

    /// Returns true if the 'none' privacy value is present.
    pub fn is_none(&self) -> bool {
        self.contains(PrivacyValue::None)
    }

    /// Returns true if identity anonymization is required.
    pub fn requires_identity_anonymization(&self) -> bool {
        self.values
            .iter()
            .any(|v| v.requires_identity_anonymization())
    }

    /// Returns true if header privacy is required.
    pub fn requires_header_privacy(&self) -> bool {
        self.values.iter().any(|v| v.requires_header_privacy())
    }

    /// Returns true if session privacy is required.
    pub fn requires_session_privacy(&self) -> bool {
        self.values.iter().any(|v| v.requires_session_privacy())
    }

    /// Parse a Privacy header value string.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{PrivacyHeader, PrivacyValue};
    ///
    /// let header = PrivacyHeader::parse("id; critical").unwrap();
    /// assert_eq!(header.values.len(), 2);
    /// assert!(header.contains(PrivacyValue::Id));
    /// assert!(header.contains(PrivacyValue::Critical));
    /// ```
    #[allow(clippy::result_unit_err)]
    pub fn parse(s: &str) -> Result<Self, ()> {
        let values: Result<Vec<_>, _> = s
            .split(';')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(PrivacyValue::from_str)
            .collect();

        Ok(Self { values: values? })
    }
}

impl fmt::Display for PrivacyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.values.is_empty() {
            return Ok(());
        }

        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{}", value)?;
        }
        Ok(())
    }
}

/// Helper function to parse Privacy header from headers.
///
/// # Examples
///
/// ```
/// use sip_core::{Headers, parse_privacy_header, PrivacyValue};
/// use smol_str::SmolStr;
///
/// let mut headers = Headers::new();
/// headers.push(SmolStr::new("Privacy"), SmolStr::new("id; critical")).unwrap();
///
/// let privacy = parse_privacy_header(&headers).unwrap();
/// assert!(privacy.contains(PrivacyValue::Id));
/// assert!(privacy.is_critical());
/// ```
pub fn parse_privacy_header(headers: &crate::Headers) -> Option<PrivacyHeader> {
    let header_value = headers.get("Privacy")?;
    PrivacyHeader::parse(header_value).ok()
}

/// Privacy enforcement functions for proxies and B2BUAs.
///
/// These functions apply privacy requirements to SIP requests by removing
/// or anonymizing headers as specified in RFC 3323.
/// Headers that should be removed when 'header' privacy is requested.
const REMOVABLE_HEADERS: &[&str] = &[
    "Subject",
    "Call-Info",
    "Organization",
    "User-Agent",
    "Reply-To",
    "In-Reply-To",
    "Server",
];

/// Enforces privacy on a request by removing or anonymizing headers.
///
/// This function applies RFC 3323 privacy requirements to a SIP request.
/// It modifies the request's headers based on the Privacy header values.
///
/// # Arguments
/// * `headers` - The headers to enforce privacy on (will be modified in place)
/// * `privacy` - The Privacy header specifying requirements
///
/// # Privacy Enforcement
///
/// - **none**: No privacy applied
/// - **header**: Removes Subject, Call-Info, Organization, User-Agent, Reply-To, In-Reply-To, Server
/// - **session**: Marks that SDP should be removed (caller must handle)
/// - **user**: Applies both header and session privacy
/// - **id**: Anonymizes From and Contact headers
/// - **critical**: Indicates privacy must be enforced (handled by caller)
///
/// # Examples
///
/// ```
/// use sip_core::{Headers, PrivacyHeader, PrivacyValue, enforce_privacy};
/// use smol_str::SmolStr;
///
/// let mut headers = Headers::new();
/// headers.push(SmolStr::new("From"), SmolStr::new("<sip:alice@example.com>")).unwrap();
/// headers.push(SmolStr::new("Subject"), SmolStr::new("Confidential Call")).unwrap();
///
/// let privacy = PrivacyHeader::new(vec![PrivacyValue::Header, PrivacyValue::Id]);
/// enforce_privacy(&mut headers, &privacy);
///
/// // Subject should be removed
/// assert!(headers.get("Subject").is_none());
/// // From should be anonymized
/// assert!(headers.get("From").unwrap().contains("anonymous"));
/// ```
pub fn enforce_privacy(headers: &mut crate::Headers, privacy: &PrivacyHeader) {
    // If 'none' is present, no privacy enforcement
    if privacy.is_none() {
        return;
    }

    // Remove headers if 'header' or 'user' privacy is requested
    if privacy.requires_header_privacy() {
        for header_name in REMOVABLE_HEADERS {
            headers.remove(header_name);
        }
    }

    // Anonymize identity headers if 'id' or 'user' privacy is requested
    if privacy.requires_identity_anonymization() {
        anonymize_identity_headers(headers);
    }

    // Note: Session privacy (SDP removal) must be handled by the caller
    // as it requires modifying the body, not just headers
}

/// Anonymizes identity headers (From, Contact) per RFC 3323.
///
/// This replaces the identity in From and Contact headers with
/// "anonymous@anonymous.invalid" while preserving tags and parameters.
///
/// Per RFC 3325 §9.2, this also removes P-Asserted-Identity and
/// P-Preferred-Identity headers at trust domain boundaries when
/// identity privacy is requested.
fn anonymize_identity_headers(headers: &mut crate::Headers) {
    use smol_str::SmolStr;

    // Anonymize From header
    if let Some(from) = headers.get("From") {
        let anonymized = anonymize_identity_header(from);
        headers.remove("From");
        headers.push(SmolStr::new("From"), SmolStr::new(anonymized)).unwrap();
    }

    // Anonymize Contact header
    if let Some(contact) = headers.get("Contact") {
        let anonymized = anonymize_identity_header(contact);
        headers.remove("Contact");
        headers.push(SmolStr::new("Contact"), SmolStr::new(anonymized)).unwrap();
    }

    // Remove P-Asserted-Identity per RFC 3325 §9.2
    // When Privacy:id is requested, P-Asserted-Identity MUST be removed
    // at trust domain boundaries
    headers.remove("P-Asserted-Identity");

    // Remove P-Preferred-Identity per RFC 3325 §9.2
    // When Privacy:id is requested, P-Preferred-Identity SHOULD be removed
    headers.remove("P-Preferred-Identity");
}

/// Anonymizes a single identity header value.
///
/// Replaces the URI with "anonymous@anonymous.invalid" while preserving
/// display name (if "Anonymous"), tags, and parameters.
fn anonymize_identity_header(header_value: &str) -> String {
    // Replace the URI with anonymous.invalid, preserving only header parameters.
    let (_, params) = split_header_params(header_value);
    if params.is_empty() {
        "\"Anonymous\" <sip:anonymous@anonymous.invalid>".to_string()
    } else {
        format!("\"Anonymous\" <sip:anonymous@anonymous.invalid>{}", params)
    }
}

fn split_header_params(value: &str) -> (&str, &str) {
    let mut in_quotes = false;
    let mut in_angle = false;
    let mut escape = false;

    for (idx, ch) in value.char_indices() {
        if escape {
            escape = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => {
                escape = true;
            }
            '"' => {
                in_quotes = !in_quotes;
            }
            '<' if !in_quotes => {
                in_angle = true;
            }
            '>' if !in_quotes => {
                in_angle = false;
            }
            ';' if !in_quotes && !in_angle => {
                return (&value[..idx], &value[idx..]);
            }
            _ => {}
        }
    }

    (value, "")
}

/// Checks if privacy enforcement is required.
///
/// Returns true if the request contains a Privacy header requesting privacy.
///
/// # Examples
///
/// ```
/// use sip_core::{Headers, requires_privacy_enforcement};
/// use smol_str::SmolStr;
///
/// let mut headers = Headers::new();
/// headers.push(SmolStr::new("Privacy"), SmolStr::new("id")).unwrap();
///
/// assert!(requires_privacy_enforcement(&headers));
/// ```
pub fn requires_privacy_enforcement(headers: &crate::Headers) -> bool {
    if let Some(privacy) = parse_privacy_header(headers) {
        !privacy.is_none()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_value_as_str() {
        assert_eq!(PrivacyValue::None.as_str(), "none");
        assert_eq!(PrivacyValue::Header.as_str(), "header");
        assert_eq!(PrivacyValue::Session.as_str(), "session");
        assert_eq!(PrivacyValue::User.as_str(), "user");
        assert_eq!(PrivacyValue::Id.as_str(), "id");
        assert_eq!(PrivacyValue::Critical.as_str(), "critical");
    }

    #[test]
    fn privacy_value_from_str() {
        assert_eq!(PrivacyValue::from_str("none"), Ok(PrivacyValue::None));
        assert_eq!(PrivacyValue::from_str("header"), Ok(PrivacyValue::Header));
        assert_eq!(PrivacyValue::from_str("session"), Ok(PrivacyValue::Session));
        assert_eq!(PrivacyValue::from_str("user"), Ok(PrivacyValue::User));
        assert_eq!(PrivacyValue::from_str("id"), Ok(PrivacyValue::Id));
        assert_eq!(
            PrivacyValue::from_str("critical"),
            Ok(PrivacyValue::Critical)
        );
        assert_eq!(PrivacyValue::from_str("NONE"), Ok(PrivacyValue::None));
        assert_eq!(PrivacyValue::from_str("ID"), Ok(PrivacyValue::Id));
        assert!(PrivacyValue::from_str("invalid").is_err());
    }

    #[test]
    fn privacy_value_display() {
        assert_eq!(PrivacyValue::None.to_string(), "none");
        assert_eq!(PrivacyValue::Id.to_string(), "id");
        assert_eq!(PrivacyValue::Critical.to_string(), "critical");
    }

    #[test]
    fn privacy_value_requirements() {
        assert!(PrivacyValue::Id.requires_identity_anonymization());
        assert!(PrivacyValue::User.requires_identity_anonymization());
        assert!(!PrivacyValue::Header.requires_identity_anonymization());

        assert!(PrivacyValue::Header.requires_header_privacy());
        assert!(PrivacyValue::User.requires_header_privacy());
        assert!(!PrivacyValue::Id.requires_header_privacy());

        assert!(PrivacyValue::Session.requires_session_privacy());
        assert!(PrivacyValue::User.requires_session_privacy());
        assert!(!PrivacyValue::Header.requires_session_privacy());
    }

    #[test]
    fn privacy_header_single() {
        let header = PrivacyHeader::single(PrivacyValue::Id);
        assert_eq!(header.values.len(), 1);
        assert!(header.contains(PrivacyValue::Id));
    }

    #[test]
    fn privacy_header_multiple() {
        let header = PrivacyHeader::new(vec![PrivacyValue::Id, PrivacyValue::Critical]);
        assert_eq!(header.values.len(), 2);
        assert!(header.contains(PrivacyValue::Id));
        assert!(header.contains(PrivacyValue::Critical));
        assert!(header.is_critical());
    }

    #[test]
    fn privacy_header_is_none() {
        let header = PrivacyHeader::single(PrivacyValue::None);
        assert!(header.is_none());
        assert!(!header.is_critical());
    }

    #[test]
    fn privacy_header_requirements() {
        let header = PrivacyHeader::new(vec![PrivacyValue::Id, PrivacyValue::Critical]);
        assert!(header.requires_identity_anonymization());
        assert!(!header.requires_header_privacy());
        assert!(!header.requires_session_privacy());

        let header = PrivacyHeader::single(PrivacyValue::User);
        assert!(header.requires_identity_anonymization());
        assert!(header.requires_header_privacy());
        assert!(header.requires_session_privacy());

        let header = PrivacyHeader::single(PrivacyValue::Header);
        assert!(!header.requires_identity_anonymization());
        assert!(header.requires_header_privacy());
        assert!(!header.requires_session_privacy());
    }

    #[test]
    fn privacy_header_parse_single() {
        let header = PrivacyHeader::parse("id").unwrap();
        assert_eq!(header.values.len(), 1);
        assert!(header.contains(PrivacyValue::Id));
    }

    #[test]
    fn privacy_header_parse_multiple() {
        let header = PrivacyHeader::parse("id; critical").unwrap();
        assert_eq!(header.values.len(), 2);
        assert!(header.contains(PrivacyValue::Id));
        assert!(header.contains(PrivacyValue::Critical));
    }

    #[test]
    fn privacy_header_parse_whitespace() {
        let header = PrivacyHeader::parse("  id  ;  critical  ").unwrap();
        assert_eq!(header.values.len(), 2);
        assert!(header.contains(PrivacyValue::Id));
        assert!(header.contains(PrivacyValue::Critical));
    }

    #[test]
    fn privacy_header_parse_case_insensitive() {
        let header = PrivacyHeader::parse("ID; CRITICAL").unwrap();
        assert_eq!(header.values.len(), 2);
        assert!(header.contains(PrivacyValue::Id));
        assert!(header.contains(PrivacyValue::Critical));
    }

    #[test]
    fn privacy_header_parse_invalid() {
        assert!(PrivacyHeader::parse("invalid").is_err());
        assert!(PrivacyHeader::parse("id; invalid").is_err());
    }

    #[test]
    fn privacy_header_display() {
        let header = PrivacyHeader::single(PrivacyValue::Id);
        assert_eq!(header.to_string(), "id");

        let header = PrivacyHeader::new(vec![PrivacyValue::Id, PrivacyValue::Critical]);
        assert_eq!(header.to_string(), "id; critical");

        let header = PrivacyHeader::new(vec![
            PrivacyValue::Header,
            PrivacyValue::Session,
            PrivacyValue::Critical,
        ]);
        assert_eq!(header.to_string(), "header; session; critical");
    }

    #[test]
    fn privacy_header_display_empty() {
        let header = PrivacyHeader::new(vec![]);
        assert_eq!(header.to_string(), "");
    }

    #[test]
    fn parse_privacy_header_from_headers() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(SmolStr::new("Privacy"), SmolStr::new("id; critical")).unwrap();

        let privacy = parse_privacy_header(&headers).unwrap();
        assert_eq!(privacy.values.len(), 2);
        assert!(privacy.contains(PrivacyValue::Id));
        assert!(privacy.contains(PrivacyValue::Critical));
    }

    #[test]
    fn parse_privacy_header_missing() {
        use crate::Headers;

        let headers = Headers::new();
        assert!(parse_privacy_header(&headers).is_none());
    }

    #[test]
    fn enforce_privacy_none_does_nothing() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>"),
        ).unwrap();
        headers.push(SmolStr::new("Subject"), SmolStr::new("Test Call")).unwrap();

        let privacy = PrivacyHeader::single(PrivacyValue::None);
        enforce_privacy(&mut headers, &privacy);

        // Nothing should be removed
        assert!(headers.get("From").is_some());
        assert!(headers.get("Subject").is_some());
    }

    #[test]
    fn enforce_privacy_header_removes_headers() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>"),
        ).unwrap();
        headers.push(SmolStr::new("Subject"), SmolStr::new("Confidential")).unwrap();
        headers.push(SmolStr::new("User-Agent"), SmolStr::new("MySIPPhone/1.0")).unwrap();
        headers.push(SmolStr::new("Organization"), SmolStr::new("ACME Corp")).unwrap();
        headers.push(
            SmolStr::new("Call-Info"),
            SmolStr::new("<http://example.com>"),
        ).unwrap();
        headers.push(SmolStr::new("To"), SmolStr::new("<sip:bob@example.com>")).unwrap();

        let privacy = PrivacyHeader::single(PrivacyValue::Header);
        enforce_privacy(&mut headers, &privacy);

        // Removable headers should be gone
        assert!(headers.get("Subject").is_none());
        assert!(headers.get("User-Agent").is_none());
        assert!(headers.get("Organization").is_none());
        assert!(headers.get("Call-Info").is_none());

        // Essential headers should remain
        assert!(headers.get("From").is_some());
        assert!(headers.get("To").is_some());
    }

    #[test]
    fn enforce_privacy_id_anonymizes_identity() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=abc123"),
        ).unwrap();
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:alice@192.168.1.100:5060>"),
        ).unwrap();

        let privacy = PrivacyHeader::single(PrivacyValue::Id);
        enforce_privacy(&mut headers, &privacy);

        // From should be anonymized but preserve tag
        let from = headers.get("From").unwrap();
        assert!(from.contains("anonymous@anonymous.invalid"));
        assert!(from.contains("tag=abc123"));

        // Contact should be anonymized
        let contact = headers.get("Contact").unwrap();
        assert!(contact.contains("anonymous@anonymous.invalid"));
    }

    #[test]
    fn enforce_privacy_user_applies_all() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>"),
        ).unwrap();
        headers.push(SmolStr::new("Subject"), SmolStr::new("Test")).unwrap();
        headers.push(SmolStr::new("User-Agent"), SmolStr::new("TestUA")).unwrap();

        let privacy = PrivacyHeader::single(PrivacyValue::User);
        enforce_privacy(&mut headers, &privacy);

        // Header privacy: Subject and User-Agent removed
        assert!(headers.get("Subject").is_none());
        assert!(headers.get("User-Agent").is_none());

        // Identity privacy: From anonymized
        let from = headers.get("From").unwrap();
        assert!(from.contains("anonymous@anonymous.invalid"));
    }

    #[test]
    fn enforce_privacy_multiple_values() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>"),
        ).unwrap();
        headers.push(SmolStr::new("Subject"), SmolStr::new("Private")).unwrap();
        headers.push(SmolStr::new("Organization"), SmolStr::new("Secret Inc")).unwrap();

        let privacy = PrivacyHeader::new(vec![
            PrivacyValue::Id,
            PrivacyValue::Header,
            PrivacyValue::Critical,
        ]);
        enforce_privacy(&mut headers, &privacy);

        // Both id and header privacy applied
        assert!(headers.get("Subject").is_none());
        assert!(headers.get("Organization").is_none());
        let from = headers.get("From").unwrap();
        assert!(from.contains("anonymous@anonymous.invalid"));
    }

    #[test]
    fn anonymize_identity_preserves_tag() {
        let original = "<sip:alice@example.com>;tag=xyz789;expires=3600";
        let anonymized = anonymize_identity_header(original);

        assert!(anonymized.contains("anonymous@anonymous.invalid"));
        assert!(anonymized.contains("tag=xyz789"));
        assert!(anonymized.contains("expires=3600"));
    }

    #[test]
    fn anonymize_identity_without_params() {
        let original = "<sip:alice@example.com>";
        let anonymized = anonymize_identity_header(original);

        assert!(anonymized.contains("anonymous@anonymous.invalid"));
        assert_eq!(
            anonymized,
            "\"Anonymous\" <sip:anonymous@anonymous.invalid>"
        );
    }

    #[test]
    fn anonymize_identity_ignores_semicolon_in_quotes() {
        let original = "\"Bob;CEO\" <sip:alice@example.com>;tag=xyz";
        let anonymized = anonymize_identity_header(original);
        assert!(anonymized.contains("anonymous@anonymous.invalid"));
        assert!(anonymized.contains("tag=xyz"));
        assert!(!anonymized.contains("alice@example.com"));
        assert!(!anonymized.contains("Bob;CEO"));
    }

    #[test]
    fn requires_privacy_enforcement_returns_true() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(SmolStr::new("Privacy"), SmolStr::new("id")).unwrap();

        assert!(requires_privacy_enforcement(&headers));
    }

    #[test]
    fn requires_privacy_enforcement_returns_false_for_none() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(SmolStr::new("Privacy"), SmolStr::new("none")).unwrap();

        assert!(!requires_privacy_enforcement(&headers));
    }

    #[test]
    fn requires_privacy_enforcement_returns_false_when_missing() {
        use crate::Headers;

        let headers = Headers::new();
        assert!(!requires_privacy_enforcement(&headers));
    }

    #[test]
    fn enforce_privacy_removes_p_asserted_identity() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=123"),
        ).unwrap();
        headers.push(
            SmolStr::new("P-Asserted-Identity"),
            SmolStr::new("<sip:alice@example.com>"),
        ).unwrap();
        headers.push(
            SmolStr::new("P-Preferred-Identity"),
            SmolStr::new("<sip:alice@example.com>"),
        ).unwrap();

        let privacy = PrivacyHeader::single(PrivacyValue::Id);
        enforce_privacy(&mut headers, &privacy);

        // P-Asserted-Identity should be removed
        assert!(headers.get("P-Asserted-Identity").is_none());

        // P-Preferred-Identity should be removed
        assert!(headers.get("P-Preferred-Identity").is_none());

        // From should be anonymized (not removed)
        assert!(headers.get("From").is_some());
        assert!(headers.get("From").unwrap().contains("anonymous"));
    }

    #[test]
    fn enforce_privacy_with_user_removes_p_headers() {
        use crate::Headers;
        use smol_str::SmolStr;

        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From"),
            SmolStr::new("<sip:alice@example.com>;tag=123"),
        ).unwrap();
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:alice@192.168.1.100>"),
        ).unwrap();
        headers.push(
            SmolStr::new("P-Asserted-Identity"),
            SmolStr::new("<sip:alice@example.com>, <tel:+15551234567>"),
        ).unwrap();
        headers.push(
            SmolStr::new("P-Preferred-Identity"),
            SmolStr::new("<tel:+15551234567>"),
        ).unwrap();
        headers.push(SmolStr::new("Subject"), SmolStr::new("Test Call")).unwrap();

        let privacy = PrivacyHeader::new(vec![PrivacyValue::User]);
        enforce_privacy(&mut headers, &privacy);

        // P-Asserted-Identity should be removed
        assert!(headers.get("P-Asserted-Identity").is_none());

        // P-Preferred-Identity should be removed
        assert!(headers.get("P-Preferred-Identity").is_none());

        // Subject should be removed (user = header + session + id)
        assert!(headers.get("Subject").is_none());

        // From and Contact should be anonymized
        assert!(headers.get("From").unwrap().contains("anonymous"));
        assert!(headers.get("Contact").unwrap().contains("anonymous"));
    }
}
