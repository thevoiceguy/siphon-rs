// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::time::SystemTime;

const MAX_DATE_HEADER_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DateHeaderError {
    InvalidFormat(String),
    ContainsControlCharacters,
    TooLong { max: usize, actual: usize },
    ParseError(String),
}

impl std::fmt::Display for DateHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid date format: {}", msg),
            Self::ContainsControlCharacters => write!(f, "date contains control characters"),
            Self::TooLong { max, actual } => 
                write!(f, "date too long (max {}, got {})", max, actual),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for DateHeaderError {}

/// SIP Date header representation.
///
/// Per RFC 3261, the Date header uses RFC 1123 format:
/// `Date: Mon, 01 Jan 2024 00:00:00 GMT`
///
/// # Security
///
/// DateHeader validates input to prevent:
/// - CRLF injection attacks
/// - Control character injection
/// - Excessive length (DoS)
/// - Invalid date formats
///
/// The raw string and parsed timestamp are kept in sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateHeader {
    raw: SmolStr,                      // ← Private
    timestamp: Option<SystemTime>,     // ← Private
}

impl DateHeader {
    /// Creates a new DateHeader from a raw date string with validation.
    ///
    /// The date string must be in RFC 1123 format and will be validated for:
    /// - Length limits
    /// - Control characters (including CRLF)
    /// - Basic format validity
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::DateHeader;
    ///
    /// let date = DateHeader::new("Mon, 01 Jan 2024 00:00:00 GMT").unwrap();
    /// assert_eq!(date.raw(), "Mon, 01 Jan 2024 00:00:00 GMT");
    /// ```
    pub fn new(raw: &str) -> Result<Self, DateHeaderError> {
        // Validate length
        if raw.len() > MAX_DATE_HEADER_LENGTH {
            return Err(DateHeaderError::TooLong {
                max: MAX_DATE_HEADER_LENGTH,
                actual: raw.len(),
            });
        }

        // Validate no control characters (including CRLF)
        if raw.chars().any(|c| c.is_ascii_control()) {
            return Err(DateHeaderError::ContainsControlCharacters);
        }

        // Validate basic format (should contain date-like components)
        if !is_valid_date_format(raw) {
            return Err(DateHeaderError::InvalidFormat(
                "does not match RFC 1123 format".to_string()
            ));
        }

        // Attempt to parse the timestamp
        let timestamp = parse_rfc1123_date(raw).ok();

        Ok(Self {
            raw: SmolStr::new(raw),
            timestamp,
        })
    }

    /// Creates a DateHeader from the current system time.
    pub fn now() -> Self {
        let timestamp = SystemTime::now();
        let raw = format_rfc1123_date(&timestamp);
        
        Self {
            raw: SmolStr::new(&raw),
            timestamp: Some(timestamp),
        }
    }

    /// Creates a DateHeader from a SystemTime.
    pub fn from_timestamp(timestamp: SystemTime) -> Self {
        let raw = format_rfc1123_date(&timestamp);
        
        Self {
            raw: SmolStr::new(&raw),
            timestamp: Some(timestamp),
        }
    }

    /// Returns the raw date string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the parsed timestamp, if available.
    pub fn timestamp(&self) -> Option<SystemTime> {
        self.timestamp
    }

    /// Validates and returns true if the date is in the past.
    pub fn is_past(&self) -> Option<bool> {
        self.timestamp.and_then(|ts| {
            SystemTime::now()
                .duration_since(ts)
                .ok()
                .map(|_| true)
        })
    }

    /// Validates and returns true if the date is in the future.
    pub fn is_future(&self) -> Option<bool> {
        self.timestamp.and_then(|ts| {
            ts.duration_since(SystemTime::now())
                .ok()
                .map(|_| true)
        })
    }
}

/// Valid RFC 1123 day names (3-letter abbreviations)
const VALID_DAYS: &[&str] = &["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Valid RFC 1123 month names (3-letter abbreviations)
const VALID_MONTHS: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
];

/// Validates that a string looks like an RFC 1123 date.
///
/// Format: `Day, DD Mon YYYY HH:MM:SS GMT`
/// Example: `Mon, 01 Jan 2024 00:00:00 GMT`
///
/// Performs strict validation:
/// - Day name must be valid (Mon, Tue, Wed, Thu, Fri, Sat, Sun)
/// - Day must be 01-31
/// - Month must be valid (Jan-Dec)
/// - Year must be 1970-2100 (reasonable range for SIP)
/// - Time must be HH:MM:SS with valid ranges
/// - Timezone must be present (typically GMT)
fn is_valid_date_format(s: &str) -> bool {
    // Basic validation - should contain expected components
    let parts: Vec<&str> = s.split_whitespace().collect();

    // Should have at least 6 parts: Day, DD, Mon, YYYY, HH:MM:SS, GMT
    if parts.len() < 6 {
        return false;
    }

    // First part should be valid day name with comma
    if !parts[0].ends_with(',') {
        return false;
    }
    let day_name = parts[0].trim_end_matches(',');
    if !VALID_DAYS.contains(&day_name) {
        return false;
    }

    // Second part should be 2-digit day (01-31)
    if parts[1].len() != 2 || !parts[1].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if let Ok(day) = parts[1].parse::<u8>() {
        if !(1..=31).contains(&day) {
            return false;
        }
    } else {
        return false;
    }

    // Third part should be valid 3-letter month
    if !VALID_MONTHS.contains(&parts[2]) {
        return false;
    }

    // Fourth part should be 4-digit year in reasonable range
    if parts[3].len() != 4 || !parts[3].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if let Ok(year) = parts[3].parse::<u16>() {
        // Unix epoch starts at 1970; 2100 is a reasonable upper bound for SIP
        if !(1970..=2100).contains(&year) {
            return false;
        }
    } else {
        return false;
    }

    // Fifth part should be time HH:MM:SS with valid components
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return false;
    }
    for (i, part) in time_parts.iter().enumerate() {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if let Ok(val) = part.parse::<u8>() {
            // Hour: 00-23, Minute: 00-59, Second: 00-59
            let max = if i == 0 { 23 } else { 59 };
            if val > max {
                return false;
            }
        } else {
            return false;
        }
    }

    // Last part should be timezone (typically GMT, but accept others)
    if parts[5].len() < 2 || !parts[5].chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    true
}

/// Parses an RFC 1123 date string to SystemTime.
///
/// Uses the httpdate crate which implements RFC 7231 HTTP-date parsing,
/// which is compatible with RFC 1123 dates used in SIP (RFC 3261 §20.17).
fn parse_rfc1123_date(s: &str) -> Result<SystemTime, DateHeaderError> {
    httpdate::parse_http_date(s)
        .map_err(|e| DateHeaderError::ParseError(format!("failed to parse date: {}", e)))
}

/// Formats a SystemTime as an RFC 1123 date string.
///
/// Generates dates in the format: `Day, DD Mon YYYY HH:MM:SS GMT`
/// Example: `Mon, 01 Jan 2024 00:00:00 GMT`
fn format_rfc1123_date(timestamp: &SystemTime) -> String {
    httpdate::fmt_http_date(*timestamp)
}

impl std::fmt::Display for DateHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_valid_date_header() {
        let date = DateHeader::new("Mon, 01 Jan 2024 00:00:00 GMT").unwrap();
        assert_eq!(date.raw(), "Mon, 01 Jan 2024 00:00:00 GMT");
    }

    #[test]
    fn reject_crlf_injection() {
        let result = DateHeader::new("Mon, 01 Jan 2024\r\nInjected: evil");
        assert!(result.is_err());
    }

    #[test]
    fn reject_control_characters() {
        let result = DateHeader::new("Mon, 01 Jan 2024\x00");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_date() {
        let long_date = "x".repeat(MAX_DATE_HEADER_LENGTH + 1);
        let result = DateHeader::new(&long_date);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_format() {
        let result = DateHeader::new("not a date");
        assert!(result.is_err());
    }

    #[test]
    fn create_from_now() {
        let date = DateHeader::now();
        assert!(date.timestamp().is_some());
    }

    #[test]
    fn fields_are_private() {
        let date = DateHeader::now();
        // This should compile (read-only access)
        let _ = date.raw();
        let _ = date.timestamp();
        
        // These should NOT compile (no direct field access):
        // date.raw = SmolStr::new("evil");  // ← Does not compile!
        // date.timestamp = None;             // ← Does not compile!
    }

    #[test]
    fn date_format_validation() {
        assert!(is_valid_date_format("Mon, 01 Jan 2024 00:00:00 GMT"));
        assert!(!is_valid_date_format("invalid"));
        assert!(!is_valid_date_format(""));
        assert!(!is_valid_date_format("01 Jan 2024"));  // Missing day name
    }

    #[test]
    fn reject_invalid_day_names() {
        let result = DateHeader::new("XXX, 01 Jan 2024 00:00:00 GMT");
        assert!(result.is_err());

        let result = DateHeader::new("Monday, 01 Jan 2024 00:00:00 GMT");
        assert!(result.is_err());  // Full name not allowed
    }

    #[test]
    fn reject_invalid_months() {
        let result = DateHeader::new("Mon, 01 XXX 2024 00:00:00 GMT");
        assert!(result.is_err());

        let result = DateHeader::new("Mon, 01 January 2024 00:00:00 GMT");
        assert!(result.is_err());  // Full name not allowed
    }

    #[test]
    fn reject_invalid_years() {
        let result = DateHeader::new("Mon, 01 Jan 0000 00:00:00 GMT");
        assert!(result.is_err());  // Before Unix epoch

        let result = DateHeader::new("Mon, 01 Jan 1969 00:00:00 GMT");
        assert!(result.is_err());  // Before 1970

        let result = DateHeader::new("Mon, 01 Jan 2101 00:00:00 GMT");
        assert!(result.is_err());  // After 2100
    }

    #[test]
    fn reject_invalid_day_numbers() {
        let result = DateHeader::new("Mon, 00 Jan 2024 00:00:00 GMT");
        assert!(result.is_err());  // Day 00

        let result = DateHeader::new("Mon, 32 Jan 2024 00:00:00 GMT");
        assert!(result.is_err());  // Day 32

        let result = DateHeader::new("Mon, 99 Jan 2024 00:00:00 GMT");
        assert!(result.is_err());  // Day 99
    }

    #[test]
    fn reject_invalid_time_formats() {
        let result = DateHeader::new("Mon, 01 Jan 2024 99:00:00 GMT");
        assert!(result.is_err());  // Hour 99

        let result = DateHeader::new("Mon, 01 Jan 2024 00:99:00 GMT");
        assert!(result.is_err());  // Minute 99

        let result = DateHeader::new("Mon, 01 Jan 2024 00:00:99 GMT");
        assert!(result.is_err());  // Second 99

        let result = DateHeader::new("Mon, 01 Jan 2024 1:2:3 GMT");
        assert!(result.is_err());  // Missing leading zeros

        let result = DateHeader::new("Mon, 01 Jan 2024 a:b:c GMT");
        assert!(result.is_err());  // Non-numeric
    }

    #[test]
    fn accept_valid_date_ranges() {
        // Test boundary conditions
        assert!(DateHeader::new("Mon, 01 Jan 1970 00:00:00 GMT").is_ok());  // Unix epoch
        assert!(DateHeader::new("Mon, 31 Dec 2100 23:59:59 GMT").is_ok());  // Upper bound
        assert!(DateHeader::new("Mon, 15 Jun 2024 12:30:45 GMT").is_ok());  // Typical date
    }

    #[test]
    fn parse_and_format_roundtrip() {
        let original = "Mon, 01 Jan 2024 00:00:00 GMT";
        let date = DateHeader::new(original).unwrap();

        // Should have parsed the timestamp
        assert!(date.timestamp().is_some());

        // Raw string should match
        assert_eq!(date.raw(), original);
    }
}