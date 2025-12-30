// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::Uri;
use smol_str::SmolStr;
use std::collections::BTreeMap;

const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;
pub const MAX_ENTRIES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryInfoError {
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    TooManyEntries { max: usize, actual: usize },
    InvalidEntry(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    DuplicateParam(String),
    EmptyEntries,
}

impl std::fmt::Display for HistoryInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParamNameTooLong { max, actual } => {
                write!(f, "param name too long (max {}, got {})", max, actual)
            }
            Self::ParamValueTooLong { max, actual } => {
                write!(f, "param value too long (max {}, got {})", max, actual)
            }
            Self::TooManyParams { max, actual } => {
                write!(f, "too many params (max {}, got {})", max, actual)
            }
            Self::TooManyEntries { max, actual } => {
                write!(f, "too many entries (max {}, got {})", max, actual)
            }
            Self::InvalidEntry(msg) => write!(f, "invalid entry: {}", msg),
            Self::InvalidParamName(msg) => write!(f, "invalid param name: {}", msg),
            Self::InvalidParamValue(msg) => write!(f, "invalid param value: {}", msg),
            Self::DuplicateParam(name) => write!(f, "duplicate parameter: {}", name),
            Self::EmptyEntries => write!(f, "history-info must have at least one entry"),
        }
    }
}

impl std::error::Error for HistoryInfoError {}

/// Represents a single History-Info entry.
///
/// Per RFC 7044, each History-Info entry contains a URI and parameters
/// that provide information about request routing history.
///
/// # Security
///
/// HistoryInfoEntry validates all parameters to prevent:
/// - CRLF injection
/// - Control character injection
/// - Excessive parameter counts (DoS)
/// - Parameter name/value length limits
///
/// Common parameters include:
/// - `index` - Position in the history
/// - `rc` - Reason for retargeting
/// - `mp` - Multipart indicator
///
/// # Examples
///
/// ```
/// use sip_core::{HistoryInfoEntry, Uri};
///
/// let uri = Uri::parse("sip:alice@example.com").unwrap();
/// let entry = HistoryInfoEntry::new(uri)
///     .with_param("index", Some("1"))
///     .unwrap()
///     .with_param("rc", Some("486"))
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfoEntry {
    uri: Uri,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl HistoryInfoEntry {
    /// Creates a new History-Info entry with the given URI.
    pub fn new(uri: Uri) -> Self {
        Self {
            uri,
            params: BTreeMap::new(),
        }
    }

    /// Adds a parameter with validation.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Result<Self, HistoryInfoError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(&mut self, name: &str, value: Option<&str>) -> Result<(), HistoryInfoError> {
        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(HistoryInfoError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(HistoryInfoError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, value.map(SmolStr::new));
        Ok(())
    }

    /// Returns the URI for this entry.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns an iterator over the parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref().map(|s| s.as_str())))
    }

    /// Gets a parameter value by name (case-insensitive).
    pub fn get_param(&self, name: &str) -> Option<Option<&str>> {
        self.params
            .get(&SmolStr::new(name.to_ascii_lowercase()))
            .map(|v| v.as_ref().map(|s| s.as_str()))
    }

    /// Gets the index parameter if present.
    ///
    /// The index parameter indicates the position of this entry in the
    /// chronological history.
    pub fn index(&self) -> Option<&str> {
        self.get_param("index").and_then(|v| v)
    }

    /// Gets the reason code (rc) parameter if present.
    ///
    /// The rc parameter indicates the reason for retargeting
    /// (typically a SIP response code like "486").
    pub fn reason_code(&self) -> Option<&str> {
        self.get_param("rc").and_then(|v| v)
    }

    /// Returns the number of parameters.
    pub fn param_count(&self) -> usize {
        self.params.len()
    }
}

/// History-Info header containing ordered entries.
///
/// Per RFC 7044, the History-Info header field provides a standard
/// mechanism for capturing request history information to enable a
/// variety of services for networks and end-users.
///
/// # Security
///
/// HistoryInfoHeader enforces:
/// - Maximum entry count to prevent DoS
/// - Non-empty entry list requirement
///
/// # Examples
///
/// ```
/// use sip_core::{HistoryInfoHeader, HistoryInfoEntry, Uri};
///
/// let uri1 = Uri::parse("sip:alice@example.com").unwrap();
/// let entry1 = HistoryInfoEntry::new(uri1)
///     .with_param("index", Some("1"))
///     .unwrap();
///
/// let uri2 = Uri::parse("sip:bob@example.com").unwrap();
/// let entry2 = HistoryInfoEntry::new(uri2)
///     .with_param("index", Some("2"))
///     .unwrap();
///
/// let header = HistoryInfoHeader::new(vec![entry1, entry2]).unwrap();
/// assert_eq!(header.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfoHeader {
    entries: Vec<HistoryInfoEntry>,
}

impl HistoryInfoHeader {
    /// Creates a new History-Info header with the given entries.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The entries list is empty
    /// - The entries list exceeds MAX_ENTRIES
    pub fn new(entries: Vec<HistoryInfoEntry>) -> Result<Self, HistoryInfoError> {
        if entries.is_empty() {
            return Err(HistoryInfoError::EmptyEntries);
        }

        if entries.len() > MAX_ENTRIES {
            return Err(HistoryInfoError::TooManyEntries {
                max: MAX_ENTRIES,
                actual: entries.len(),
            });
        }

        Ok(Self { entries })
    }

    /// Creates a header with a single entry.
    pub fn single(entry: HistoryInfoEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Appends an entry to the header.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed MAX_ENTRIES.
    pub fn push(&mut self, entry: HistoryInfoEntry) -> Result<(), HistoryInfoError> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(HistoryInfoError::TooManyEntries {
                max: MAX_ENTRIES,
                actual: self.entries.len() + 1,
            });
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Returns an iterator over the entries.
    pub fn entries(&self) -> impl Iterator<Item = &HistoryInfoEntry> {
        self.entries.iter()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if there are no entries (should never happen after construction).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the entry at the given index.
    pub fn get(&self, index: usize) -> Option<&HistoryInfoEntry> {
        self.entries.get(index)
    }

    /// Returns the first entry.
    pub fn first(&self) -> Option<&HistoryInfoEntry> {
        self.entries.first()
    }

    /// Returns the last entry (most recent in chronological order).
    pub fn last(&self) -> Option<&HistoryInfoEntry> {
        self.entries.last()
    }

    /// Finds an entry by its index parameter value.
    pub fn find_by_index(&self, index: &str) -> Option<&HistoryInfoEntry> {
        self.entries.iter().find(|e| e.index() == Some(index))
    }

    /// Returns all entries as a slice.
    pub fn as_slice(&self) -> &[HistoryInfoEntry] {
        &self.entries
    }
}

// Validation functions

fn validate_param_name(name: &str) -> Result<(), HistoryInfoError> {
    if name.is_empty() {
        return Err(HistoryInfoError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(HistoryInfoError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(HistoryInfoError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    // Parameter names should be tokens
    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.' | '_' | '!' | '%' | '*' | '+' | '`' | '\'' | '~'
            )
    }) {
        return Err(HistoryInfoError::InvalidParamName(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), HistoryInfoError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(HistoryInfoError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(HistoryInfoError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    // Parameter values must be tokens (quoted strings not supported).
    if !value.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.' | '_' | '!' | '%' | '*' | '+' | '`' | '\'' | '~'
            )
    }) {
        return Err(HistoryInfoError::InvalidParamValue(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_uri(s: &str) -> Uri {
        // Assuming Uri has a parse method
        // For testing, you'd use actual Uri::parse or create a mock
        Uri::parse(s).expect("failed to parse URI")
    }

    #[test]
    fn create_history_info_entry() {
        let uri = mock_uri("sip:alice@example.com");
        let entry = HistoryInfoEntry::new(uri.clone());
        assert_eq!(entry.uri(), &uri);
        assert_eq!(entry.param_count(), 0);
    }

    #[test]
    fn entry_with_params() {
        let uri = mock_uri("sip:alice@example.com");
        let entry = HistoryInfoEntry::new(uri)
            .with_param("index", Some("1"))
            .unwrap()
            .with_param("rc", Some("486"))
            .unwrap();

        assert_eq!(entry.index(), Some("1"));
        assert_eq!(entry.reason_code(), Some("486"));
        assert_eq!(entry.param_count(), 2);
    }

    #[test]
    fn reject_crlf_in_param_name() {
        let uri = mock_uri("sip:alice@example.com");
        let result = HistoryInfoEntry::new(uri).with_param("param\r\ninjected", Some("value"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_param_value() {
        let uri = mock_uri("sip:alice@example.com");
        let result = HistoryInfoEntry::new(uri).with_param("index", Some("1\r\ninjected"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_params() {
        let uri = mock_uri("sip:alice@example.com");
        let mut entry = HistoryInfoEntry::new(uri);

        for i in 0..MAX_PARAMS {
            entry.add_param(&format!("p{}", i), Some("value")).unwrap();
        }

        // Should fail
        let result = entry.add_param("overflow", Some("value"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_params() {
        let uri = mock_uri("sip:alice@example.com");
        let result = HistoryInfoEntry::new(uri)
            .with_param("index", Some("1"))
            .unwrap()
            .with_param("index", Some("2"));
        assert!(result.is_err());
    }

    #[test]
    fn params_case_insensitive() {
        let uri = mock_uri("sip:alice@example.com");
        let entry = HistoryInfoEntry::new(uri)
            .with_param("Index", Some("1"))
            .unwrap();

        assert_eq!(entry.get_param("index"), Some(Some("1")));
        assert_eq!(entry.get_param("INDEX"), Some(Some("1")));
    }

    #[test]
    fn create_history_info_header() {
        let uri = mock_uri("sip:alice@example.com");
        let entry = HistoryInfoEntry::new(uri);
        let header = HistoryInfoHeader::new(vec![entry]).unwrap();

        assert_eq!(header.len(), 1);
        assert!(!header.is_empty());
    }

    #[test]
    fn reject_empty_entries() {
        let result = HistoryInfoHeader::new(vec![]);
        assert!(matches!(result, Err(HistoryInfoError::EmptyEntries)));
    }

    #[test]
    fn reject_too_many_entries() {
        let uri = mock_uri("sip:alice@example.com");
        let entries = vec![HistoryInfoEntry::new(uri); MAX_ENTRIES + 1];
        let result = HistoryInfoHeader::new(entries);
        assert!(result.is_err());
    }

    #[test]
    fn header_push_entry() {
        let uri1 = mock_uri("sip:alice@example.com");
        let entry1 = HistoryInfoEntry::new(uri1);
        let mut header = HistoryInfoHeader::new(vec![entry1]).unwrap();

        let uri2 = mock_uri("sip:bob@example.com");
        let entry2 = HistoryInfoEntry::new(uri2);
        header.push(entry2).unwrap();

        assert_eq!(header.len(), 2);
    }

    #[test]
    fn reject_push_beyond_max() {
        let uri = mock_uri("sip:alice@example.com");
        let entries = vec![HistoryInfoEntry::new(uri.clone()); MAX_ENTRIES];
        let mut header = HistoryInfoHeader::new(entries).unwrap();

        let result = header.push(HistoryInfoEntry::new(uri));
        assert!(result.is_err());
    }

    #[test]
    fn header_access_methods() {
        let uri1 = mock_uri("sip:alice@example.com");
        let entry1 = HistoryInfoEntry::new(uri1)
            .with_param("index", Some("1"))
            .unwrap();

        let uri2 = mock_uri("sip:bob@example.com");
        let entry2 = HistoryInfoEntry::new(uri2)
            .with_param("index", Some("2"))
            .unwrap();

        let header = HistoryInfoHeader::new(vec![entry1, entry2]).unwrap();

        assert_eq!(header.first().unwrap().index(), Some("1"));
        assert_eq!(header.last().unwrap().index(), Some("2"));
        assert_eq!(header.get(0).unwrap().index(), Some("1"));
        assert_eq!(header.get(1).unwrap().index(), Some("2"));
        assert!(header.get(2).is_none());
    }

    #[test]
    fn find_by_index() {
        let uri1 = mock_uri("sip:alice@example.com");
        let entry1 = HistoryInfoEntry::new(uri1)
            .with_param("index", Some("1"))
            .unwrap();

        let uri2 = mock_uri("sip:bob@example.com");
        let entry2 = HistoryInfoEntry::new(uri2)
            .with_param("index", Some("2"))
            .unwrap();

        let header = HistoryInfoHeader::new(vec![entry1, entry2]).unwrap();

        assert!(header.find_by_index("1").is_some());
        assert!(header.find_by_index("2").is_some());
        assert!(header.find_by_index("3").is_none());
    }

    #[test]
    fn header_iteration() {
        let uri1 = mock_uri("sip:alice@example.com");
        let uri2 = mock_uri("sip:bob@example.com");

        let entry1 = HistoryInfoEntry::new(uri1);
        let entry2 = HistoryInfoEntry::new(uri2);

        let header = HistoryInfoHeader::new(vec![entry1, entry2]).unwrap();

        let count = header.entries().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn fields_are_private() {
        let uri = mock_uri("sip:alice@example.com");
        let entry = HistoryInfoEntry::new(uri);

        // These should compile (read-only access)
        let _ = entry.uri();
        let _ = entry.params();

        // These should NOT compile (no direct field access):
        // entry.uri = mock_uri("sip:evil.com");  // ← Does not compile!
        // entry.params.clear();                   // ← Does not compile!
    }
}
