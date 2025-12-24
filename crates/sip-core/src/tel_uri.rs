// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Tel URI support per RFC 2806 (and updated by RFC 3966).
///
/// A tel URI represents a telephone number, which can be either:
/// - Global: Uses E.164 format, starts with '+' (e.g., tel:+1-555-123-4567)
/// - Local: Requires phone-context parameter (e.g., tel:555-1234;phone-context=example.com)
///
/// RFC 3966 (which obsoletes RFC 2806) defines the current tel URI format.
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

/// Parsed representation of a tel URI (RFC 3966).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TelUri {
    /// Raw tel URI string (for serialization)
    pub raw: SmolStr,

    /// The telephone number (without visual separators for E.164 global numbers)
    /// For global numbers: "+15551234567"
    /// For local numbers: "5551234" or original format
    pub number: SmolStr,

    /// True if this is a global number (E.164 format starting with '+')
    pub is_global: bool,

    /// Phone context for local numbers (required for local, invalid for global)
    pub phone_context: Option<SmolStr>,

    /// URI parameters (e.g., isub, ext, phone-context)
    pub parameters: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl TelUri {
    /// Creates a new TelUri from components.
    pub fn new(number: impl Into<SmolStr>, is_global: bool) -> Self {
        let number = number.into();
        let raw = if is_global {
            SmolStr::new(format!("tel:{}", number))
        } else {
            SmolStr::new(format!("tel:{}", number))
        };

        Self {
            raw,
            number,
            is_global,
            phone_context: None,
            parameters: BTreeMap::new(),
        }
    }

    /// Attempts to parse a tel URI from the provided string.
    ///
    /// # Examples
    /// ```
    /// use sip_core::TelUri;
    ///
    /// // Global number (E.164)
    /// let uri = TelUri::parse("tel:+1-555-123-4567").unwrap();
    /// assert!(uri.is_global);
    /// assert_eq!(uri.number.as_str(), "+15551234567");
    ///
    /// // Local number with phone-context
    /// let uri = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
    /// assert!(!uri.is_global);
    /// assert_eq!(uri.phone_context.as_ref().unwrap().as_str(), "example.com");
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        let raw = SmolStr::new(input.to_owned());

        // Must start with "tel:"
        let rest = input.strip_prefix("tel:")?;

        // Split into number and parameters
        let mut parts = rest.split(';');
        let number_part = parts.next()?.trim();

        if number_part.is_empty() {
            return None;
        }

        // Determine if global (starts with '+') or local
        let is_global = number_part.starts_with('+');

        // For global numbers, remove visual separators (-, ., space, parentheses)
        // RFC 3966 §5.1.1: Visual separators are for human readability only
        let normalized_number = if is_global {
            normalize_global_number(number_part)
        } else {
            SmolStr::new(number_part.to_owned())
        };

        // Parse parameters
        let mut parameters = BTreeMap::new();
        let mut phone_context = None;

        for param in parts {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }

            if let Some((key, value)) = param.split_once('=') {
                let key = SmolStr::new(key.trim().to_owned());
                let value = SmolStr::new(value.trim().to_owned());

                // Special handling for phone-context
                if key.as_str().eq_ignore_ascii_case("phone-context") {
                    phone_context = Some(value.clone());
                }

                parameters.insert(key, Some(value));
            } else {
                parameters.insert(SmolStr::new(param.to_owned()), None);
            }
        }

        // Validate: local numbers MUST have phone-context
        if !is_global && phone_context.is_none() {
            // RFC 3966 §5.1.4: Local numbers require phone-context
            return None;
        }

        // Validate: global numbers MUST NOT have phone-context
        if is_global && phone_context.is_some() {
            // RFC 3966 §5.1.4: Global numbers cannot have phone-context
            return None;
        }

        Some(Self {
            raw,
            number: normalized_number,
            is_global,
            phone_context,
            parameters,
        })
    }

    /// Returns the tel URI as a string.
    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    /// Returns the telephone number.
    pub fn number(&self) -> &str {
        self.number.as_str()
    }

    /// Adds a parameter to the tel URI.
    pub fn with_parameter(
        mut self,
        key: impl Into<SmolStr>,
        value: Option<impl Into<SmolStr>>,
    ) -> Self {
        let key = key.into();
        let value = value.map(|v| v.into());
        self.parameters.insert(key, value);
        self
    }

    /// Sets the phone-context for local numbers.
    pub fn with_phone_context(mut self, context: impl Into<SmolStr>) -> Self {
        let context = context.into();
        if !self.is_global {
            self.phone_context = Some(context.clone());
            self.parameters
                .insert(SmolStr::new("phone-context".to_owned()), Some(context));
        }
        self
    }
}

impl fmt::Display for TelUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Normalizes a global telephone number by removing visual separators.
/// RFC 3966 §5.1.1: Visual separators (-, ., space, parentheses) are for readability.
fn normalize_global_number(number: &str) -> SmolStr {
    let normalized: String = number
        .chars()
        .filter(|c| !matches!(c, '-' | '.' | ' ' | '(' | ')'))
        .collect();
    SmolStr::new(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_tel_uri() {
        let uri = TelUri::parse("tel:+1-555-123-4567").unwrap();
        assert!(uri.is_global);
        assert_eq!(uri.number.as_str(), "+15551234567");
        assert!(uri.phone_context.is_none());
    }

    #[test]
    fn parses_global_with_visual_separators() {
        let uri = TelUri::parse("tel:+1(555)123.4567").unwrap();
        assert!(uri.is_global);
        assert_eq!(uri.number.as_str(), "+15551234567");
    }

    #[test]
    fn parses_local_with_phone_context() {
        let uri = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
        assert!(!uri.is_global);
        assert_eq!(uri.number.as_str(), "5551234");
        assert_eq!(uri.phone_context.as_ref().unwrap().as_str(), "example.com");
    }

    #[test]
    fn rejects_local_without_phone_context() {
        let uri = TelUri::parse("tel:5551234");
        assert!(uri.is_none());
    }

    #[test]
    fn rejects_global_with_phone_context() {
        let uri = TelUri::parse("tel:+15551234;phone-context=example.com");
        assert!(uri.is_none());
    }

    #[test]
    fn parses_with_extension() {
        let uri = TelUri::parse("tel:+1-555-123-4567;ext=1234").unwrap();
        assert!(uri.is_global);
        assert_eq!(
            uri.parameters
                .get("ext")
                .unwrap()
                .as_ref()
                .unwrap()
                .as_str(),
            "1234"
        );
    }

    #[test]
    fn rejects_non_tel_scheme() {
        assert!(TelUri::parse("sip:user@example.com").is_none());
    }

    #[test]
    fn creates_tel_uri_programmatically() {
        let uri = TelUri::new("+15551234567", true);
        assert!(uri.is_global);
        assert_eq!(uri.as_str(), "tel:+15551234567");
    }
}
