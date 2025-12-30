// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP version handling (RFC 3261 §7.1).
//!
//! SIP/2.0 is the only version currently defined.

use std::fmt;

/// SIP version supported by the stack.
///
/// # Security
///
/// SipVersion is a simple enum with no data fields and no validation needed.
/// The parse() function validates input format to prevent malformed versions.
///
/// # Examples
///
/// ```
/// use sip_core::SipVersion;
///
/// // Get version string
/// assert_eq!(SipVersion::V2.as_str(), "SIP/2.0");
///
/// // Parse version
/// let version = SipVersion::parse("SIP/2.0").unwrap();
/// assert_eq!(version, SipVersion::V2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SipVersion {
    /// SIP version 2.0 (RFC 3261)
    V2,
}

/// Error type for SIP version parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    /// Invalid version format
    InvalidFormat(String),
    /// Unsupported version
    UnsupportedVersion(String),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::InvalidFormat(msg) => write!(f, "Invalid version format: {}", msg),
            VersionError::UnsupportedVersion(ver) => {
                write!(f, "Unsupported SIP version: {}", ver)
            }
        }
    }
}

impl std::error::Error for VersionError {}

impl SipVersion {
    /// Returns the SIP version string (e.g. `SIP/2.0`).
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::SipVersion;
    ///
    /// assert_eq!(SipVersion::V2.as_str(), "SIP/2.0");
    /// ```
    pub const fn as_str(self) -> &'static str {
        match self {
            SipVersion::V2 => "SIP/2.0",
        }
    }

    /// Parses a SIP version string.
    ///
    /// # Format
    ///
    /// The expected format is: `SIP/<major>.<minor>`
    ///
    /// Currently only `SIP/2.0` is supported per RFC 3261.
    ///
    /// # Errors
    ///
    /// Returns `VersionError` if:
    /// - Format is invalid (not `SIP/X.Y`)
    /// - Version is not 2.0
    /// - Contains control characters
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::SipVersion;
    ///
    /// // Valid version
    /// assert_eq!(SipVersion::parse("SIP/2.0").unwrap(), SipVersion::V2);
    ///
    /// // Case insensitive
    /// assert_eq!(SipVersion::parse("sip/2.0").unwrap(), SipVersion::V2);
    ///
    /// // Invalid versions
    /// assert!(SipVersion::parse("SIP/1.0").is_err());
    /// assert!(SipVersion::parse("SIP/3.0").is_err());
    /// assert!(SipVersion::parse("HTTP/1.1").is_err());
    /// ```
    pub fn parse(input: &str) -> Result<Self, VersionError> {
        // Check for control characters (security)
        if input.chars().any(|c| c.is_control() && c != '\t') {
            return Err(VersionError::InvalidFormat(
                "contains control characters".to_string(),
            ));
        }

        let trimmed = input.trim_matches(|c| c == ' ' || c == '\t');
        if trimmed.is_empty() {
            return Err(VersionError::InvalidFormat("empty input".to_string()));
        }

        // Must start with "SIP/" (case-insensitive)
        let prefix = trimmed
            .get(..4)
            .ok_or_else(|| VersionError::InvalidFormat("must start with 'SIP/'".to_string()))?;
        if !prefix.eq_ignore_ascii_case("SIP/") {
            return Err(VersionError::InvalidFormat(
                "must start with 'SIP/'".to_string(),
            ));
        }

        let version_part = &trimmed[4..];
        let (major_str, minor_str) = version_part.split_once('.').ok_or_else(|| {
            VersionError::InvalidFormat("expected 'SIP/<major>.<minor>'".to_string())
        })?;
        if major_str.is_empty()
            || minor_str.is_empty()
            || !major_str.chars().all(|c| c.is_ascii_digit())
            || !minor_str.chars().all(|c| c.is_ascii_digit())
        {
            return Err(VersionError::InvalidFormat(
                "expected 'SIP/<major>.<minor>'".to_string(),
            ));
        }

        let major = major_str
            .parse::<u16>()
            .map_err(|_| VersionError::InvalidFormat("invalid major".to_string()))?;
        let minor = minor_str
            .parse::<u16>()
            .map_err(|_| VersionError::InvalidFormat("invalid minor".to_string()))?;

        if major == 2 && minor == 0 {
            Ok(SipVersion::V2)
        } else {
            Err(VersionError::UnsupportedVersion(version_part.to_string()))
        }
    }

    /// Returns the major version number.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::SipVersion;
    ///
    /// assert_eq!(SipVersion::V2.major(), 2);
    /// ```
    pub const fn major(self) -> u8 {
        match self {
            SipVersion::V2 => 2,
        }
    }

    /// Returns the minor version number.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::SipVersion;
    ///
    /// assert_eq!(SipVersion::V2.minor(), 0);
    /// ```
    pub const fn minor(self) -> u8 {
        match self {
            SipVersion::V2 => 0,
        }
    }
}

impl Default for SipVersion {
    /// Returns the default SIP version (2.0).
    fn default() -> Self {
        SipVersion::V2
    }
}

impl fmt::Display for SipVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_as_str() {
        assert_eq!(SipVersion::V2.as_str(), "SIP/2.0");
    }

    #[test]
    fn version_display() {
        assert_eq!(SipVersion::V2.to_string(), "SIP/2.0");
    }

    #[test]
    fn version_parse_valid() {
        assert_eq!(SipVersion::parse("SIP/2.0").unwrap(), SipVersion::V2);
    }

    #[test]
    fn version_parse_case_insensitive() {
        assert_eq!(SipVersion::parse("sip/2.0").unwrap(), SipVersion::V2);
        assert_eq!(SipVersion::parse("SIP/2.0").unwrap(), SipVersion::V2);
        assert_eq!(SipVersion::parse("Sip/2.0").unwrap(), SipVersion::V2);
    }

    #[test]
    fn version_parse_with_whitespace() {
        assert_eq!(SipVersion::parse("  SIP/2.0  ").unwrap(), SipVersion::V2);
        assert_eq!(SipVersion::parse("\tSIP/2.0\t").unwrap(), SipVersion::V2);
    }

    #[test]
    fn version_parse_rejects_invalid_format() {
        assert!(SipVersion::parse("HTTP/1.1").is_err());
        assert!(SipVersion::parse("SIP").is_err());
        assert!(SipVersion::parse("2.0").is_err());
        assert!(SipVersion::parse("SIP:2.0").is_err());
        assert!(SipVersion::parse("").is_err());
    }

    #[test]
    fn version_parse_rejects_unsupported_versions() {
        assert!(SipVersion::parse("SIP/1.0").is_err());
        assert!(SipVersion::parse("SIP/1.1").is_err());
        assert!(SipVersion::parse("SIP/3.0").is_err());
    }

    #[test]
    fn version_parse_rejects_control_chars() {
        assert!(SipVersion::parse("SIP/2.0\r\n").is_err());
        assert!(SipVersion::parse("SIP/2.0\x00").is_err());
        assert!(SipVersion::parse("SIP\r\n/2.0").is_err());
    }

    #[test]
    fn version_major_minor() {
        assert_eq!(SipVersion::V2.major(), 2);
        assert_eq!(SipVersion::V2.minor(), 0);
    }

    #[test]
    fn version_default() {
        assert_eq!(SipVersion::default(), SipVersion::V2);
    }

    #[test]
    fn version_equality() {
        let v1 = SipVersion::V2;
        let v2 = SipVersion::V2;
        assert_eq!(v1, v2);
    }

    #[test]
    fn version_copy() {
        let v1 = SipVersion::V2;
        let v2 = v1; // Copy
        assert_eq!(v1, v2);
    }

    #[test]
    fn version_ordering() {
        let v1 = SipVersion::V2;
        let v2 = SipVersion::V2;
        assert!(v1 <= v2);
        assert!(v1 >= v2);
    }

    #[test]
    fn version_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(SipVersion::V2);
        assert!(set.contains(&SipVersion::V2));
    }

    #[test]
    fn error_display() {
        let err1 = VersionError::InvalidFormat("test".to_string());
        assert_eq!(err1.to_string(), "Invalid version format: test");

        let err2 = VersionError::UnsupportedVersion("3.0".to_string());
        assert_eq!(err2.to_string(), "Unsupported SIP version: 3.0");
    }

    #[test]
    fn round_trip() {
        let original = SipVersion::V2;
        let formatted = original.to_string();
        let parsed = SipVersion::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn version_is_const() {
        // These should compile as const
        const VERSION_STR: &str = SipVersion::V2.as_str();
        const MAJOR: u8 = SipVersion::V2.major();
        const MINOR: u8 = SipVersion::V2.minor();

        assert_eq!(VERSION_STR, "SIP/2.0");
        assert_eq!(MAJOR, 2);
        assert_eq!(MINOR, 0);
    }
}
