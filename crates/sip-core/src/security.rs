// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3329 Security Agreement implementation with comprehensive security hardening.

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

// Security: Input size limits
const MAX_MECHANISM_NAME_LENGTH: usize = 64;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS_PER_ENTRY: usize = 20;
const MAX_ENTRIES: usize = 10;

/// Error types for security agreement operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// Input validation error
    ValidationError(String),
    /// Too many items
    TooManyItems { field: &'static str, max: usize },
    /// Invalid format
    InvalidFormat(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            SecurityError::TooManyItems { field, max } => {
                write!(f, "Too many {} (max {})", field, max)
            }
            SecurityError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

// Validation functions

fn validate_mechanism_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() {
        return Err(SecurityError::ValidationError(
            "Mechanism name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_MECHANISM_NAME_LENGTH {
        return Err(SecurityError::ValidationError(format!(
            "Mechanism name too long (max {})",
            MAX_MECHANISM_NAME_LENGTH
        )));
    }

    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(SecurityError::ValidationError(
            "Mechanism name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() {
        return Err(SecurityError::ValidationError(
            "Parameter name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(SecurityError::ValidationError(format!(
            "Parameter name too long (max {})",
            MAX_PARAM_NAME_LENGTH
        )));
    }

    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == ';' || c == '=' || c == ',')
    {
        return Err(SecurityError::ValidationError(
            "Parameter name contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), SecurityError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(SecurityError::ValidationError(format!(
            "Parameter value too long (max {})",
            MAX_PARAM_VALUE_LENGTH
        )));
    }

    if value.chars().any(|c| c.is_control()) {
        return Err(SecurityError::ValidationError(
            "Parameter value contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_q_value(q: f32) -> Result<(), SecurityError> {
    if !q.is_finite() {
        return Err(SecurityError::ValidationError(
            "Q value must be finite".to_string(),
        ));
    }

    if !(0.0..=1.0).contains(&q) {
        return Err(SecurityError::ValidationError(
            "Q value must be between 0.0 and 1.0".to_string(),
        ));
    }

    Ok(())
}

/// RFC 3329 Security Mechanism names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityMechanism {
    /// Transport Layer Security (TLS)
    Tls,
    /// Digest Authentication
    Digest,
    /// IPsec with IKE key management
    IpsecIke,
    /// IPsec with manual key management
    IpsecMan,
    /// Other/custom security mechanism
    Other(SmolStr),
}

impl SecurityMechanism {
    /// Returns the mechanism name as a string.
    pub fn as_str(&self) -> &str {
        match self {
            SecurityMechanism::Tls => "tls",
            SecurityMechanism::Digest => "digest",
            SecurityMechanism::IpsecIke => "ipsec-ike",
            SecurityMechanism::IpsecMan => "ipsec-man",
            SecurityMechanism::Other(s) => s.as_str(),
        }
    }

    /// Parses a mechanism name from a string with validation.
    pub fn parse(s: &str) -> Result<Self, SecurityError> {
        validate_mechanism_name(s)?;

        Ok(match s.to_lowercase().as_str() {
            "tls" => SecurityMechanism::Tls,
            "digest" => SecurityMechanism::Digest,
            "ipsec-ike" => SecurityMechanism::IpsecIke,
            "ipsec-man" => SecurityMechanism::IpsecMan,
            _ => SecurityMechanism::Other(SmolStr::new(s)),
        })
    }
}

impl fmt::Display for SecurityMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// RFC 3329 Security Agreement entry.
///
/// # Security
///
/// SecurityEntry validates all inputs and enforces bounds on parameter collections
/// to prevent DoS attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEntry {
    mechanism: SecurityMechanism,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl SecurityEntry {
    /// Creates a new security entry with the given mechanism.
    pub fn new(mechanism: SecurityMechanism) -> Self {
        Self {
            mechanism,
            params: BTreeMap::new(),
        }
    }

    /// Gets the mechanism.
    pub fn mechanism(&self) -> &SecurityMechanism {
        &self.mechanism
    }

    /// Gets all parameters.
    pub fn params(&self) -> &BTreeMap<SmolStr, Option<SmolStr>> {
        &self.params
    }

    /// Sets a parameter value with validation.
    pub fn set_param(&mut self, name: &str, value: Option<&str>) -> Result<(), SecurityError> {
        if self.params.len() >= MAX_PARAMS_PER_ENTRY {
            return Err(SecurityError::TooManyItems {
                field: "parameters",
                max: MAX_PARAMS_PER_ENTRY,
            });
        }

        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        self.params
            .insert(SmolStr::new(name), value.map(SmolStr::new));
        Ok(())
    }

    /// Gets a parameter value.
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Sets the preference value (q parameter) with validation.
    ///
    /// The q value must be between 0.0 and 1.0.
    /// Default is 0.001 per RFC 3329.
    pub fn set_preference(&mut self, q: f32) -> Result<(), SecurityError> {
        validate_q_value(q)?;

        let q_str = if q == 1.0 {
            "1".to_string()
        } else {
            format!("{:.3}", q)
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        };

        self.set_param("q", Some(&q_str))
    }

    /// Gets the preference value (q parameter).
    pub fn preference(&self) -> Option<f32> {
        self.get_param("q")
            .and_then(|v| v.as_ref())
            .and_then(|s| parse_q_value(s.as_str()))
    }

    /// Creates a TLS security entry with default parameters.
    pub fn tls() -> Self {
        Self::new(SecurityMechanism::Tls)
    }

    /// Creates a Digest security entry with algorithm.
    pub fn digest(algorithm: &str, qop: Option<&str>) -> Result<Self, SecurityError> {
        let mut entry = Self::new(SecurityMechanism::Digest);
        entry.set_param("d-alg", Some(algorithm))?;
        if let Some(q) = qop {
            entry.set_param("d-qop", Some(q))?;
        }
        Ok(entry)
    }

    /// Creates an IPsec-IKE security entry.
    pub fn ipsec_ike(
        algorithm: &str,
        protocol: &str,
        mode: &str,
    ) -> Result<Self, SecurityError> {
        let mut entry = Self::new(SecurityMechanism::IpsecIke);
        entry.set_param("algorithm", Some(algorithm))?;
        entry.set_param("protocol", Some(protocol))?;
        entry.set_param("mode", Some(mode))?;
        Ok(entry)
    }
}

impl fmt::Display for SecurityEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mechanism)?;
        for (key, value) in &self.params {
            if let Some(v) = value {
                write!(f, ";{}={}", key, v)?;
            } else {
                write!(f, ";{}", key)?;
            }
        }
        Ok(())
    }
}

/// RFC 3329 Security-Client header.
///
/// # Security
///
/// SecurityClientHeader validates all entries and enforces bounds to prevent DoS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityClientHeader {
    entries: Vec<SecurityEntry>,
}

impl SecurityClientHeader {
    /// Creates a new Security-Client header with validated entries.
    pub fn new(entries: Vec<SecurityEntry>) -> Result<Self, SecurityError> {
        if entries.len() > MAX_ENTRIES {
            return Err(SecurityError::TooManyItems {
                field: "security entries",
                max: MAX_ENTRIES,
            });
        }
        Ok(Self { entries })
    }

    /// Creates a Security-Client header with a single mechanism.
    pub fn single(entry: SecurityEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Gets all entries.
    pub fn entries(&self) -> &[SecurityEntry] {
        &self.entries
    }

    /// Returns true if the header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of security mechanisms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns entries sorted by preference (highest first).
    pub fn sorted_by_preference(&self) -> Vec<&SecurityEntry> {
        let mut entries: Vec<&SecurityEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| {
            let qa = a.preference().unwrap_or(0.001);
            let qb = b.preference().unwrap_or(0.001);
            qb.total_cmp(&qa)
        });
        entries
    }
}

impl fmt::Display for SecurityClientHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

/// RFC 3329 Security-Server header.
///
/// # Security
///
/// SecurityServerHeader validates all entries and enforces bounds to prevent DoS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityServerHeader {
    entries: Vec<SecurityEntry>,
}

impl SecurityServerHeader {
    /// Creates a new Security-Server header with validated entries.
    pub fn new(entries: Vec<SecurityEntry>) -> Result<Self, SecurityError> {
        if entries.len() > MAX_ENTRIES {
            return Err(SecurityError::TooManyItems {
                field: "security entries",
                max: MAX_ENTRIES,
            });
        }
        Ok(Self { entries })
    }

    /// Creates a Security-Server header with a single mechanism.
    pub fn single(entry: SecurityEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Gets all entries.
    pub fn entries(&self) -> &[SecurityEntry] {
        &self.entries
    }

    /// Returns true if the header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of security mechanisms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns entries sorted by preference (highest first).
    pub fn sorted_by_preference(&self) -> Vec<&SecurityEntry> {
        let mut entries: Vec<&SecurityEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| {
            let qa = a.preference().unwrap_or(0.001);
            let qb = b.preference().unwrap_or(0.001);
            qb.total_cmp(&qa)
        });
        entries
    }

    /// Finds the best matching mechanism supported by both client and server.
    ///
    /// Returns the entry with the highest combined preference that appears
    /// in both lists.
    pub fn find_best_match(&self, client: &SecurityClientHeader) -> Option<&SecurityEntry> {
        let mut best: Option<(&SecurityEntry, f32)> = None;

        for server_entry in &self.entries {
            if let Some(client_entry) = client
                .entries
                .iter()
                .find(|c| c.mechanism == server_entry.mechanism)
            {
                let server_q = server_entry.preference().unwrap_or(0.001);
                let client_q = client_entry.preference().unwrap_or(0.001);
                let combined = server_q * client_q;

                if best.is_none_or(|(_, score)| combined > score) {
                    best = Some((server_entry, combined));
                }
            }
        }

        best.map(|(entry, _)| entry)
    }
}

impl fmt::Display for SecurityServerHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

/// RFC 3329 Security-Verify header.
///
/// # Security
///
/// SecurityVerifyHeader validates all entries and enforces bounds to prevent DoS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityVerifyHeader {
    entries: Vec<SecurityEntry>,
}

impl SecurityVerifyHeader {
    /// Creates a new Security-Verify header with validated entries.
    pub fn new(entries: Vec<SecurityEntry>) -> Result<Self, SecurityError> {
        if entries.len() > MAX_ENTRIES {
            return Err(SecurityError::TooManyItems {
                field: "security entries",
                max: MAX_ENTRIES,
            });
        }
        Ok(Self { entries })
    }

    /// Creates a Security-Verify header with a single mechanism.
    pub fn single(entry: SecurityEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Gets all entries.
    pub fn entries(&self) -> &[SecurityEntry] {
        &self.entries
    }

    /// Returns true if the header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of security mechanisms.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Verifies that this matches the expected server entry.
    ///
    /// Returns true if the mechanisms match. This is used by servers
    /// to verify that the client is using the agreed security mechanism.
    pub fn matches(&self, server_entry: &SecurityEntry) -> bool {
        self.entries
            .iter()
            .any(|e| e.mechanism == server_entry.mechanism)
    }
}

impl fmt::Display for SecurityVerifyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry)?;
        }
        Ok(())
    }
}

/// Parses a Security-Client header from a header value string.
pub fn parse_security_client(value: &str) -> Result<SecurityClientHeader, SecurityError> {
    let entries = parse_security_entries(value)?;
    SecurityClientHeader::new(entries)
}

/// Parses a Security-Server header from a header value string.
pub fn parse_security_server(value: &str) -> Result<SecurityServerHeader, SecurityError> {
    let entries = parse_security_entries(value)?;
    SecurityServerHeader::new(entries)
}

/// Parses a Security-Verify header from a header value string.
pub fn parse_security_verify(value: &str) -> Result<SecurityVerifyHeader, SecurityError> {
    let entries = parse_security_entries(value)?;
    SecurityVerifyHeader::new(entries)
}

/// Parses security entries from a comma-separated list.
fn parse_security_entries(value: &str) -> Result<Vec<SecurityEntry>, SecurityError> {
    let mut entries = Vec::new();

    for part in split_unquoted(value, ',') {
        if entries.len() >= MAX_ENTRIES {
            return Err(SecurityError::TooManyItems {
                field: "security entries",
                max: MAX_ENTRIES,
            });
        }

        let trimmed = part.trim();
        if !trimmed.is_empty() {
            entries.push(parse_single_security_entry(trimmed)?);
        }
    }

    if entries.is_empty() {
        return Err(SecurityError::InvalidFormat(
            "No security entries found".to_string(),
        ));
    }

    Ok(entries)
}

/// Parses a single security entry: mechanism-name;param1=value1;param2=value2
fn parse_single_security_entry(value: &str) -> Result<SecurityEntry, SecurityError> {
    let mut parts = split_unquoted(value, ';').into_iter();
    let mechanism_name = parts
        .next()
        .ok_or_else(|| SecurityError::InvalidFormat("Empty entry".to_string()))?
        .trim()
        .to_string();

    if mechanism_name.is_empty() {
        return Err(SecurityError::InvalidFormat(
            "Empty mechanism name".to_string(),
        ));
    }

    let mechanism = SecurityMechanism::parse(&mechanism_name)?;
    let mut entry = SecurityEntry::new(mechanism);

    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }

        if let Some((key, val)) = split_once_unquoted(param, '=') {
            let key = key.trim();
            let val = val.trim();

            // Special validation for q parameter
            if key.eq_ignore_ascii_case("q") {
                if parse_q_value(val).is_some() {
                    entry.set_param(key, Some(val))?;
                }
                // Silently ignore invalid q values
            } else {
                entry.set_param(key, Some(val))?;
            }
        } else {
            entry.set_param(param, None)?;
        }
    }

    Ok(entry)
}

fn split_unquoted(input: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escape = false;

    for ch in input.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }

        if in_quotes && ch == '\\' {
            escape = true;
            current.push(ch);
            continue;
        }

        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
            continue;
        }

        if ch == sep && !in_quotes {
            parts.push(current);
            current = String::new();
            continue;
        }

        current.push(ch);
    }

    parts.push(current);
    parts
}

fn split_once_unquoted(input: &str, sep: char) -> Option<(String, String)> {
    let mut in_quotes = false;
    let mut escape = false;

    for (idx, ch) in input.char_indices() {
        if escape {
            escape = false;
            continue;
        }

        if in_quotes && ch == '\\' {
            escape = true;
            continue;
        }

        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }

        if ch == sep && !in_quotes {
            let left = input[..idx].to_string();
            let right = input[idx + ch.len_utf8()..].to_string();
            return Some((left, right));
        }
    }

    None
}

fn parse_q_value(value: &str) -> Option<f32> {
    let q = value.parse::<f32>().ok()?;
    if q.is_finite() && (0.0..=1.0).contains(&q) {
        Some(q)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_mechanism_parse() {
        assert_eq!(
            SecurityMechanism::parse("tls").unwrap(),
            SecurityMechanism::Tls
        );
        assert_eq!(
            SecurityMechanism::parse("TLS").unwrap(),
            SecurityMechanism::Tls
        );
        assert_eq!(
            SecurityMechanism::parse("digest").unwrap(),
            SecurityMechanism::Digest
        );
        assert_eq!(
            SecurityMechanism::parse("ipsec-ike").unwrap(),
            SecurityMechanism::IpsecIke
        );
        assert_eq!(
            SecurityMechanism::parse("ipsec-man").unwrap(),
            SecurityMechanism::IpsecMan
        );

        if let SecurityMechanism::Other(s) = SecurityMechanism::parse("custom").unwrap() {
            assert_eq!(s.as_str(), "custom");
        } else {
            panic!("Expected Other variant");
        }
    }

    #[test]
    fn security_mechanism_parse_rejects_empty() {
        assert!(SecurityMechanism::parse("").is_err());
    }

    #[test]
    fn security_mechanism_parse_rejects_too_long() {
        let long_name = "x".repeat(MAX_MECHANISM_NAME_LENGTH + 1);
        assert!(SecurityMechanism::parse(&long_name).is_err());
    }

    #[test]
    fn security_mechanism_parse_rejects_control_chars() {
        assert!(SecurityMechanism::parse("tls\r\n").is_err());
        assert!(SecurityMechanism::parse("tls ").is_err());
    }

    #[test]
    fn security_mechanism_display() {
        assert_eq!(SecurityMechanism::Tls.to_string(), "tls");
        assert_eq!(SecurityMechanism::Digest.to_string(), "digest");
        assert_eq!(SecurityMechanism::IpsecIke.to_string(), "ipsec-ike");
    }

    #[test]
    fn security_entry_basic() {
        let mut entry = SecurityEntry::new(SecurityMechanism::Tls);
        assert_eq!(entry.mechanism(), &SecurityMechanism::Tls);
        assert!(entry.params().is_empty());

        entry.set_param("q", Some("0.5")).unwrap();
        assert_eq!(
            entry.get_param("q").unwrap().as_ref().unwrap().as_str(),
            "0.5"
        );
    }

    #[test]
    fn security_entry_rejects_too_many_params() {
        let mut entry = SecurityEntry::tls();

        for i in 0..MAX_PARAMS_PER_ENTRY {
            entry
                .set_param(&format!("param{}", i), Some("value"))
                .unwrap();
        }

        // Next one should fail
        assert!(entry.set_param("extra", Some("value")).is_err());
    }

    #[test]
    fn security_entry_rejects_invalid_param_name() {
        let mut entry = SecurityEntry::tls();

        // Empty name
        assert!(entry.set_param("", Some("value")).is_err());

        // Too long
        let long_name = "x".repeat(MAX_PARAM_NAME_LENGTH + 1);
        assert!(entry.set_param(&long_name, Some("value")).is_err());

        // Invalid characters
        assert!(entry.set_param("name;", Some("value")).is_err());
        assert!(entry.set_param("name=", Some("value")).is_err());
        assert!(entry.set_param("name,", Some("value")).is_err());
    }

    #[test]
    fn security_entry_rejects_invalid_param_value() {
        let mut entry = SecurityEntry::tls();

        // Too long
        let long_value = "x".repeat(MAX_PARAM_VALUE_LENGTH + 1);
        assert!(entry.set_param("q", Some(&long_value)).is_err());

        // Control characters (except tab)
        assert!(entry.set_param("q", Some("val\r\nue")).is_err());
    }

    #[test]
    fn security_entry_preference() {
        let mut entry = SecurityEntry::tls();
        entry.set_preference(0.8).unwrap();
        assert_eq!(entry.preference(), Some(0.8));

        entry.set_preference(1.0).unwrap();
        assert_eq!(entry.preference(), Some(1.0));
    }

    #[test]
    fn security_entry_preference_validates_range() {
        let mut entry = SecurityEntry::tls();

        assert!(entry.set_preference(-0.1).is_err());
        assert!(entry.set_preference(1.1).is_err());
        assert!(entry.set_preference(f32::NAN).is_err());
        assert!(entry.set_preference(f32::INFINITY).is_err());
    }

    #[test]
    fn security_entry_display() {
        let mut entry = SecurityEntry::tls();
        entry.set_preference(0.5).unwrap();
        assert_eq!(entry.to_string(), "tls;q=0.5");

        let mut digest = SecurityEntry::digest("SHA-256", Some("auth")).unwrap();
        digest.set_preference(0.3).unwrap();
        assert_eq!(digest.to_string(), "digest;d-alg=SHA-256;d-qop=auth;q=0.3");
    }

    #[test]
    fn security_client_header() {
        let tls = SecurityEntry::tls();
        let digest = SecurityEntry::digest("MD5", Some("auth")).unwrap();

        let header = SecurityClientHeader::new(vec![tls, digest]).unwrap();
        assert_eq!(header.len(), 2);
        assert!(!header.is_empty());
    }

    #[test]
    fn security_client_header_rejects_too_many_entries() {
        let mut entries = Vec::new();
        for _ in 0..=MAX_ENTRIES {
            entries.push(SecurityEntry::tls());
        }

        assert!(SecurityClientHeader::new(entries).is_err());
    }

    #[test]
    fn security_client_display() {
        let mut tls = SecurityEntry::tls();
        tls.set_preference(0.5).unwrap();

        let mut digest = SecurityEntry::digest("SHA-256", None).unwrap();
        digest.set_preference(0.3).unwrap();

        let header = SecurityClientHeader::new(vec![tls, digest]).unwrap();
        let display = header.to_string();
        assert!(display.contains("tls;q=0.5"));
        assert!(display.contains("digest;d-alg=SHA-256;q=0.3"));
        assert!(display.contains(", "));
    }

    #[test]
    fn security_server_find_best_match() {
        let mut client_tls = SecurityEntry::tls();
        client_tls.set_preference(0.5).unwrap();

        let mut client_digest = SecurityEntry::digest("MD5", Some("auth")).unwrap();
        client_digest.set_preference(0.8).unwrap();

        let client = SecurityClientHeader::new(vec![client_tls, client_digest]).unwrap();

        let mut server_tls = SecurityEntry::tls();
        server_tls.set_preference(0.9).unwrap();

        let mut server_digest = SecurityEntry::digest("MD5", Some("auth")).unwrap();
        server_digest.set_preference(0.3).unwrap();

        let server = SecurityServerHeader::new(vec![server_tls.clone(), server_digest]).unwrap();

        let best = server.find_best_match(&client);
        assert!(best.is_some());
        assert_eq!(best.unwrap().mechanism(), &SecurityMechanism::Tls);
    }

    #[test]
    fn security_server_find_best_match_combines_preferences() {
        let mut client_tls = SecurityEntry::tls();
        client_tls.set_preference(0.2).unwrap();

        let mut client_digest = SecurityEntry::digest("MD5", Some("auth")).unwrap();
        client_digest.set_preference(0.9).unwrap();

        let client = SecurityClientHeader::new(vec![client_tls, client_digest]).unwrap();

        let mut server_tls = SecurityEntry::tls();
        server_tls.set_preference(0.9).unwrap();

        let mut server_digest = SecurityEntry::digest("MD5", Some("auth")).unwrap();
        server_digest.set_preference(0.4).unwrap();

        let server = SecurityServerHeader::new(vec![server_tls, server_digest]).unwrap();

        let best = server.find_best_match(&client);
        assert!(best.is_some());
        assert_eq!(best.unwrap().mechanism(), &SecurityMechanism::Digest);
    }

    #[test]
    fn security_verify_matches() {
        let tls = SecurityEntry::tls();
        let verify = SecurityVerifyHeader::single(tls.clone());

        assert!(verify.matches(&tls));

        let digest = SecurityEntry::digest("MD5", None).unwrap();
        assert!(!verify.matches(&digest));
    }

    #[test]
    fn parse_security_client() {
        let value = "tls;q=0.5, digest;d-alg=SHA-256;d-qop=auth;q=0.3";
        let header = super::parse_security_client(value).unwrap();

        assert_eq!(header.len(), 2);
        assert_eq!(header.entries()[0].mechanism(), &SecurityMechanism::Tls);
        assert_eq!(header.entries()[0].preference(), Some(0.5));
        assert_eq!(
            header.entries()[1].mechanism(),
            &SecurityMechanism::Digest
        );
        assert_eq!(header.entries()[1].preference(), Some(0.3));
    }

    #[test]
    fn parse_security_server() {
        let value = "ipsec-ike;algorithm=des-ede3-cbc;protocol=esp;mode=trans";
        let header = super::parse_security_server(value).unwrap();

        assert_eq!(header.len(), 1);
        assert_eq!(
            header.entries()[0].mechanism(),
            &SecurityMechanism::IpsecIke
        );
        assert_eq!(
            header.entries()[0]
                .get_param("algorithm")
                .unwrap()
                .as_ref()
                .unwrap()
                .as_str(),
            "des-ede3-cbc"
        );
    }

    #[test]
    fn parse_security_client_rejects_too_many_entries() {
        let mut entries = vec!["tls"];
        for _i in 0..MAX_ENTRIES {
            entries.push("digest");
        }
        let value = entries.join(", ");

        assert!(super::parse_security_client(&value).is_err());
    }

    #[test]
    fn parse_security_client_rejects_empty() {
        assert!(super::parse_security_client("").is_err());
        assert!(super::parse_security_client("  ").is_err());
    }

    #[test]
    fn parse_security_client_handles_quoted_separators() {
        let value = "tls;token=\"a,b;c\", digest";
        let header = super::parse_security_client(value).unwrap();
        assert_eq!(header.len(), 2);
        assert_eq!(header.entries()[0].mechanism(), &SecurityMechanism::Tls);
        assert_eq!(
            header.entries()[0]
                .get_param("token")
                .unwrap()
                .as_ref()
                .unwrap()
                .as_str(),
            "\"a,b;c\""
        );
    }

    #[test]
    fn get_param_is_case_insensitive() {
        let value = "tls;Q=0.5";
        let header = super::parse_security_client(value).unwrap();
        assert_eq!(header.entries()[0].preference(), Some(0.5));
        assert!(header.entries()[0].get_param("q").is_some());
    }

    #[test]
    fn security_sorted_by_preference() {
        let mut tls = SecurityEntry::tls();
        tls.set_preference(0.3).unwrap();

        let mut digest = SecurityEntry::digest("MD5", None).unwrap();
        digest.set_preference(0.8).unwrap();

        let mut ipsec = SecurityEntry::ipsec_ike("des", "esp", "trans").unwrap();
        ipsec.set_preference(0.5).unwrap();

        let header = SecurityClientHeader::new(vec![tls, digest, ipsec]).unwrap();
        let sorted = header.sorted_by_preference();

        assert_eq!(sorted[0].mechanism(), &SecurityMechanism::Digest);
        assert_eq!(sorted[1].mechanism(), &SecurityMechanism::IpsecIke);
        assert_eq!(sorted[2].mechanism(), &SecurityMechanism::Tls);
    }

    #[test]
    fn security_sorted_by_preference_ignores_invalid_q() {
        let mut tls = SecurityEntry::tls();
        tls.set_param("q", Some("NaN")).unwrap();

        let mut digest = SecurityEntry::digest("MD5", None).unwrap();
        digest.set_preference(0.8).unwrap();

        let header = SecurityClientHeader::new(vec![tls, digest]).unwrap();
        let sorted = header.sorted_by_preference();

        assert_eq!(sorted[0].mechanism(), &SecurityMechanism::Digest);
    }

    #[test]
    fn fields_are_private() {
        let entry = SecurityEntry::tls();
        let client = SecurityClientHeader::single(entry);

        // These should compile (read access via getters)
        let _ = client.entries();
        let _ = client.entries()[0].mechanism();

        // These should NOT compile:
        // client.entries = vec![];              // ← Does not compile!
        // entry.mechanism = SecurityMechanism::Digest; // ← Does not compile!
    }
}
