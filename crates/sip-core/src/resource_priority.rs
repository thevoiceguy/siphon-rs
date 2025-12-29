// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Resource-Priority header (RFC 4412).
//!
//! The Resource-Priority header enables differentiated services for emergency
//! and priority telecommunications. It allows SIP requests to be marked with
//! namespace-specific priority values that intermediaries can use to make
//! resource allocation and admission control decisions.
//!
//! # Format
//!
//! ```text
//! Resource-Priority: namespace.priority
//! Resource-Priority: namespace.priority, namespace2.priority2
//! ```
//!
//! # Common Namespaces
//!
//! - **dsn**: Defense Switched Network (military)
//! - **drsn**: Defense Red Switched Network  
//! - **q735**: ITU-T Q.735 priorities
//! - **ets**: Emergency Telecommunications Service
//! - **wps**: Wireless Priority Service
//!
//! # Examples
//!
//! ```text
//! Resource-Priority: dsn.flash-override
//! Resource-Priority: wps.0, ets.1
//! Accept-Resource-Priority: dsn.*, wps.*
//! ```

use smol_str::SmolStr;
use std::fmt;

const MAX_NAMESPACE_LENGTH: usize = 64;
const MAX_PRIORITY_LENGTH: usize = 64;
const MAX_VALUES: usize = 10;
const MAX_PARSE_INPUT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourcePriorityError {
    NamespaceTooLong { max: usize, actual: usize },
    PriorityTooLong { max: usize, actual: usize },
    TooManyValues { max: usize, actual: usize },
    InvalidNamespace(String),
    InvalidPriority(String),
    EmptyNamespace,
    EmptyPriority,
    InputTooLarge { max: usize, actual: usize },
    ParseError(String),
}

impl std::fmt::Display for ResourcePriorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NamespaceTooLong { max, actual } =>
                write!(f, "namespace too long (max {}, got {})", max, actual),
            Self::PriorityTooLong { max, actual } =>
                write!(f, "priority too long (max {}, got {})", max, actual),
            Self::TooManyValues { max, actual } =>
                write!(f, "too many values (max {}, got {})", max, actual),
            Self::InvalidNamespace(msg) =>
                write!(f, "invalid namespace: {}", msg),
            Self::InvalidPriority(msg) =>
                write!(f, "invalid priority: {}", msg),
            Self::EmptyNamespace =>
                write!(f, "namespace cannot be empty"),
            Self::EmptyPriority =>
                write!(f, "priority cannot be empty"),
            Self::InputTooLarge { max, actual } =>
                write!(f, "input too large (max {}, got {})", max, actual),
            Self::ParseError(msg) =>
                write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for ResourcePriorityError {}

/// Represents a single namespace.priority value.
///
/// # Examples
///
/// ```
/// use sip_core::ResourcePriorityValue;
///
/// let value = ResourcePriorityValue::new("dsn", "flash-override").unwrap();
/// assert_eq!(value.namespace(), "dsn");
/// assert_eq!(value.priority(), "flash-override");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePriorityValue {
    namespace: SmolStr,
    priority: SmolStr,
}

impl ResourcePriorityValue {
    /// Creates a new resource priority value.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace or priority is invalid.
    pub fn new(
        namespace: impl AsRef<str>,
        priority: impl AsRef<str>,
    ) -> Result<Self, ResourcePriorityError> {
        validate_namespace(namespace.as_ref())?;
        validate_priority(priority.as_ref())?;

        Ok(Self {
            namespace: SmolStr::new(namespace.as_ref()),
            priority: SmolStr::new(priority.as_ref()),
        })
    }

    /// Returns the namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the priority.
    pub fn priority(&self) -> &str {
        &self.priority
    }

    /// Parses a namespace.priority value.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ResourcePriorityValue;
    ///
    /// let value = ResourcePriorityValue::parse("dsn.flash").unwrap();
    /// assert_eq!(value.namespace(), "dsn");
    /// assert_eq!(value.priority(), "flash");
    /// ```
    pub fn parse(input: &str) -> Result<Self, ResourcePriorityError> {
        let input = input.trim();

        let (namespace, priority) = input
            .split_once('.')
            .ok_or_else(|| ResourcePriorityError::ParseError("missing '.' separator".to_string()))?;

        Self::new(namespace, priority)
    }
}

impl fmt::Display for ResourcePriorityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.namespace, self.priority)
    }
}

/// Represents Resource-Priority/Accept-Resource-Priority headers (RFC 4412).
///
/// The Resource-Priority header indicates the priority level for resource
/// allocation and admission control. Multiple namespace.priority values
/// can be specified in order of preference.
///
/// # Security
///
/// ResourcePriorityHeader validates all inputs and enforces bounds.
///
/// # Examples
///
/// ```
/// use sip_core::{ResourcePriorityHeader, ResourcePriorityValue};
///
/// let mut header = ResourcePriorityHeader::new();
/// header.add_value(ResourcePriorityValue::new("dsn", "flash-override").unwrap()).unwrap();
/// header.add_value(ResourcePriorityValue::new("wps", "0").unwrap()).unwrap();
///
/// assert_eq!(header.to_string(), "dsn.flash-override, wps.0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePriorityHeader {
    values: Vec<ResourcePriorityValue>,
}

impl ResourcePriorityHeader {
    /// Creates a new empty Resource-Priority header.
    pub fn new() -> Self {
        Self {
            values: Vec::new(),
        }
    }

    /// Creates a Resource-Priority header with a single value.
    pub fn single(value: ResourcePriorityValue) -> Self {
        Self {
            values: vec![value],
        }
    }

    /// Adds a value to the header.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of values is exceeded.
    pub fn add_value(&mut self, value: ResourcePriorityValue) -> Result<(), ResourcePriorityError> {
        if self.values.len() >= MAX_VALUES {
            return Err(ResourcePriorityError::TooManyValues {
                max: MAX_VALUES,
                actual: self.values.len() + 1,
            });
        }
        self.values.push(value);
        Ok(())
    }

    /// Returns the values.
    pub fn values(&self) -> &[ResourcePriorityValue] {
        &self.values
    }

    /// Returns the number of values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if there are no values.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Parses a Resource-Priority header value.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ResourcePriorityHeader;
    ///
    /// let header = ResourcePriorityHeader::parse("dsn.flash, wps.0").unwrap();
    /// assert_eq!(header.len(), 2);
    /// ```
    pub fn parse(input: &str) -> Result<Self, ResourcePriorityError> {
        if input.len() > MAX_PARSE_INPUT {
            return Err(ResourcePriorityError::InputTooLarge {
                max: MAX_PARSE_INPUT,
                actual: input.len(),
            });
        }

        let mut values = Vec::new();

        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if values.len() >= MAX_VALUES {
                return Err(ResourcePriorityError::TooManyValues {
                    max: MAX_VALUES,
                    actual: values.len() + 1,
                });
            }

            values.push(ResourcePriorityValue::parse(part)?);
        }

        Ok(Self { values })
    }
}

impl Default for ResourcePriorityHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ResourcePriorityHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", value)?;
        }
        Ok(())
    }
}

// Validation functions

fn validate_namespace(namespace: &str) -> Result<(), ResourcePriorityError> {
    if namespace.is_empty() {
        return Err(ResourcePriorityError::EmptyNamespace);
    }

    if namespace.len() > MAX_NAMESPACE_LENGTH {
        return Err(ResourcePriorityError::NamespaceTooLong {
            max: MAX_NAMESPACE_LENGTH,
            actual: namespace.len(),
        });
    }

    // RFC 4412: namespace is a token (alphanumeric + special chars)
    // Block control characters and whitespace
    if namespace.chars().any(|c| c.is_ascii_control() || c.is_whitespace()) {
        return Err(ResourcePriorityError::InvalidNamespace(
            "contains control characters or whitespace".to_string(),
        ));
    }

    Ok(())
}

fn validate_priority(priority: &str) -> Result<(), ResourcePriorityError> {
    if priority.is_empty() {
        return Err(ResourcePriorityError::EmptyPriority);
    }

    if priority.len() > MAX_PRIORITY_LENGTH {
        return Err(ResourcePriorityError::PriorityTooLong {
            max: MAX_PRIORITY_LENGTH,
            actual: priority.len(),
        });
    }

    // RFC 4412: priority is a token (alphanumeric + special chars)
    // Block control characters and whitespace
    if priority.chars().any(|c| c.is_ascii_control() || c.is_whitespace()) {
        return Err(ResourcePriorityError::InvalidPriority(
            "contains control characters or whitespace".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_priority_value() {
        let value = ResourcePriorityValue::new("dsn", "flash-override").unwrap();
        assert_eq!(value.namespace(), "dsn");
        assert_eq!(value.priority(), "flash-override");
    }

    #[test]
    fn format_priority_value() {
        let value = ResourcePriorityValue::new("wps", "0").unwrap();
        assert_eq!(value.to_string(), "wps.0");
    }

    #[test]
    fn parse_priority_value() {
        let value = ResourcePriorityValue::parse("dsn.flash").unwrap();
        assert_eq!(value.namespace(), "dsn");
        assert_eq!(value.priority(), "flash");
    }

    #[test]
    fn parse_priority_value_with_dash() {
        let value = ResourcePriorityValue::parse("dsn.flash-override").unwrap();
        assert_eq!(value.namespace(), "dsn");
        assert_eq!(value.priority(), "flash-override");
    }

    #[test]
    fn create_empty_header() {
        let header = ResourcePriorityHeader::new();
        assert!(header.is_empty());
        assert_eq!(header.len(), 0);
    }

    #[test]
    fn create_single_value_header() {
        let value = ResourcePriorityValue::new("dsn", "flash").unwrap();
        let header = ResourcePriorityHeader::single(value);
        assert_eq!(header.len(), 1);
    }

    #[test]
    fn add_values_to_header() {
        let mut header = ResourcePriorityHeader::new();
        header.add_value(ResourcePriorityValue::new("dsn", "flash").unwrap()).unwrap();
        header.add_value(ResourcePriorityValue::new("wps", "0").unwrap()).unwrap();
        assert_eq!(header.len(), 2);
    }

    #[test]
    fn format_header_single_value() {
        let mut header = ResourcePriorityHeader::new();
        header.add_value(ResourcePriorityValue::new("dsn", "flash-override").unwrap()).unwrap();
        assert_eq!(header.to_string(), "dsn.flash-override");
    }

    #[test]
    fn format_header_multiple_values() {
        let mut header = ResourcePriorityHeader::new();
        header.add_value(ResourcePriorityValue::new("dsn", "flash").unwrap()).unwrap();
        header.add_value(ResourcePriorityValue::new("wps", "0").unwrap()).unwrap();
        assert_eq!(header.to_string(), "dsn.flash, wps.0");
    }

    #[test]
    fn parse_header_single_value() {
        let header = ResourcePriorityHeader::parse("dsn.flash-override").unwrap();
        assert_eq!(header.len(), 1);
        assert_eq!(header.values()[0].namespace(), "dsn");
        assert_eq!(header.values()[0].priority(), "flash-override");
    }

    #[test]
    fn parse_header_multiple_values() {
        let header = ResourcePriorityHeader::parse("dsn.flash, wps.0").unwrap();
        assert_eq!(header.len(), 2);
        assert_eq!(header.values()[0].to_string(), "dsn.flash");
        assert_eq!(header.values()[1].to_string(), "wps.0");
    }

    #[test]
    fn parse_header_with_whitespace() {
        let header = ResourcePriorityHeader::parse("  dsn.flash  ,  wps.0  ").unwrap();
        assert_eq!(header.len(), 2);
    }

    #[test]
    fn round_trip_value() {
        let original = ResourcePriorityValue::new("q735", "1").unwrap();
        let formatted = original.to_string();
        let parsed = ResourcePriorityValue::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_header() {
        let mut original = ResourcePriorityHeader::new();
        original.add_value(ResourcePriorityValue::new("dsn", "flash").unwrap()).unwrap();
        original.add_value(ResourcePriorityValue::new("wps", "0").unwrap()).unwrap();

        let formatted = original.to_string();
        let parsed = ResourcePriorityHeader::parse(&formatted).unwrap();
        assert_eq!(parsed, original);
    }

    // Security tests

    #[test]
    fn reject_empty_namespace() {
        let result = ResourcePriorityValue::new("", "flash");
        assert!(matches!(result, Err(ResourcePriorityError::EmptyNamespace)));
    }

    #[test]
    fn reject_empty_priority() {
        let result = ResourcePriorityValue::new("dsn", "");
        assert!(matches!(result, Err(ResourcePriorityError::EmptyPriority)));
    }

    #[test]
    fn reject_crlf_in_namespace() {
        let result = ResourcePriorityValue::new("dsn\r\ninjected", "flash");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_priority() {
        let result = ResourcePriorityValue::new("dsn", "flash\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_whitespace_in_namespace() {
        let result = ResourcePriorityValue::new("dsn test", "flash");
        assert!(result.is_err());
    }

    #[test]
    fn reject_whitespace_in_priority() {
        let result = ResourcePriorityValue::new("dsn", "flash override");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_namespace() {
        let long_namespace = "x".repeat(MAX_NAMESPACE_LENGTH + 1);
        let result = ResourcePriorityValue::new(&long_namespace, "flash");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_priority() {
        let long_priority = "x".repeat(MAX_PRIORITY_LENGTH + 1);
        let result = ResourcePriorityValue::new("dsn", &long_priority);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_values() {
        let mut header = ResourcePriorityHeader::new();

        for i in 0..MAX_VALUES {
            header.add_value(
                ResourcePriorityValue::new("dsn", &format!("{}", i)).unwrap()
            ).unwrap();
        }

        let result = header.add_value(
            ResourcePriorityValue::new("dsn", "overflow").unwrap()
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_parse_input() {
        let huge = "dsn.flash, ".repeat(100);
        let result = ResourcePriorityHeader::parse(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_separator() {
        let result = ResourcePriorityValue::parse("dsnflash");
        assert!(matches!(result, Err(ResourcePriorityError::ParseError(_))));
    }

    #[test]
    fn fields_are_private() {
        let value = ResourcePriorityValue::new("dsn", "flash").unwrap();
        let header = ResourcePriorityHeader::new();

        // These should compile (read-only access)
        let _ = value.namespace();
        let _ = value.priority();
        let _ = header.values();

        // These should NOT compile:
        // value.namespace = SmolStr::new("evil");  // ← Does not compile!
        // header.values.clear();                    // ← Does not compile!
    }
}