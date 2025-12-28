// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::collections::BTreeMap;

const MAX_PACKAGE_LENGTH: usize = 64;
const MAX_ID_LENGTH: usize = 256;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;
const MAX_STATE_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventHeaderError {
    PackageTooLong { max: usize, actual: usize },
    IdTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    StateTooLong { max: usize, actual: usize },
    InvalidPackage(String),
    InvalidId(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    InvalidState(String),
    DuplicateParam(String),
}

impl std::fmt::Display for EventHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PackageTooLong { max, actual } => {
                write!(f, "package too long (max {}, got {})", max, actual)
            }
            Self::InvalidPackage(msg) => write!(f, "invalid package: {}", msg),
            Self::TooManyParams { max, actual } => {
                write!(f, "too many params (max {}, got {})", max, actual)
            }
            Self::DuplicateParam(name) => write!(f, "duplicate parameter: {}", name),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for EventHeaderError {}

/// Represents the Event (and Allow-Events) header.
///
/// Per RFC 3265, the Event header specifies the event package being used
/// for a subscription. Format: `Event: package[.subtype] [;id=value] [;params]`
///
/// # Security
///
/// EventHeader validates all input to prevent:
/// - CRLF injection in package names, IDs, and parameters
/// - Control character injection
/// - Excessive length (DoS)
/// - Unbounded parameter lists
///
/// # Examples
///
/// ```
/// use sip_core::EventHeader;
///
/// let event = EventHeader::new("presence")
///     .unwrap()
///     .with_id("abc123")
///     .unwrap()
///     .with_param("priority", Some("urgent"))
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHeader {
    package: SmolStr,
    id: Option<SmolStr>,
    params: BTreeMap<SmolStr, Option<SmolStr>>, // Use BTreeMap for deduplication
}

impl EventHeader {
    /// Creates a new Event header with the given package.
    ///
    /// The package name must be a valid token (per RFC 3261) and will be
    /// validated for length and invalid characters.
    pub fn new(package: &str) -> Result<Self, EventHeaderError> {
        validate_package(package)?;

        Ok(Self {
            package: SmolStr::new(package),
            id: None,
            params: BTreeMap::new(),
        })
    }

    /// Sets the event ID.
    pub fn with_id(mut self, id: &str) -> Result<Self, EventHeaderError> {
        validate_id(id)?;
        self.id = Some(SmolStr::new(id));
        Ok(self)
    }

    /// Adds a parameter.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Result<Self, EventHeaderError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(&mut self, name: &str, value: Option<&str>) -> Result<(), EventHeaderError> {
        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(EventHeaderError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(EventHeaderError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, value.map(SmolStr::new));
        Ok(())
    }

    /// Returns the event package name.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Returns the event ID, if present.
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(|s| s.as_str())
    }

    /// Returns an iterator over the parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref().map(|s| s.as_str())))
    }

    /// Gets a parameter value by name (case-insensitive).
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }
}

/// Represents Subscription-State header.
///
/// Per RFC 3265, the Subscription-State header indicates the current state
/// of a subscription. Format: `Subscription-State: state [;params]`
///
/// # Security
///
/// SubscriptionStateHeader validates all input to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionStateHeader {
    state: SubscriptionState,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl SubscriptionStateHeader {
    /// Creates a new Subscription-State header.
    pub fn new(state: SubscriptionState) -> Self {
        Self {
            state,
            params: BTreeMap::new(),
        }
    }

    /// Adds a parameter.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Result<Self, EventHeaderError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(&mut self, name: &str, value: Option<&str>) -> Result<(), EventHeaderError> {
        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(EventHeaderError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(EventHeaderError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, value.map(SmolStr::new));
        Ok(())
    }

    /// Returns the subscription state.
    pub fn state(&self) -> &SubscriptionState {
        &self.state
    }

    /// Returns an iterator over the parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref().map(|s| s.as_str())))
    }

    /// Gets a parameter value by name (case-insensitive).
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionState {
    Active,
    Pending,
    Terminated,
    Unknown(SmolStr),
}

impl SubscriptionState {
    /// Creates a SubscriptionState from a string with validation.
    pub fn parse(s: &str) -> Result<Self, EventHeaderError> {
        match s.to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "pending" => Ok(Self::Pending),
            "terminated" => Ok(Self::Terminated),
            _ => {
                validate_state(s)?;
                Ok(Self::Unknown(SmolStr::new(s)))
            }
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Terminated => "terminated",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

impl std::str::FromStr for SubscriptionState {
    type Err = EventHeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// Validation functions

fn validate_package(package: &str) -> Result<(), EventHeaderError> {
    if package.is_empty() {
        return Err(EventHeaderError::InvalidPackage(
            "empty package".to_string(),
        ));
    }

    if package.len() > MAX_PACKAGE_LENGTH {
        return Err(EventHeaderError::PackageTooLong {
            max: MAX_PACKAGE_LENGTH,
            actual: package.len(),
        });
    }

    // Check for control characters
    if package.chars().any(|c| c.is_ascii_control()) {
        return Err(EventHeaderError::InvalidPackage(
            "contains control characters".to_string(),
        ));
    }

    // Package should be a token (alphanumeric, hyphen, dot, underscore)
    if !is_token(package) {
        return Err(EventHeaderError::InvalidPackage(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_id(id: &str) -> Result<(), EventHeaderError> {
    if id.is_empty() {
        return Err(EventHeaderError::InvalidId("empty id".to_string()));
    }

    if id.len() > MAX_ID_LENGTH {
        return Err(EventHeaderError::IdTooLong {
            max: MAX_ID_LENGTH,
            actual: id.len(),
        });
    }

    if id.chars().any(|c| c.is_ascii_control()) {
        return Err(EventHeaderError::InvalidId(
            "contains control characters".to_string(),
        ));
    }

    if !is_token(id) {
        return Err(EventHeaderError::InvalidId(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), EventHeaderError> {
    if name.is_empty() {
        return Err(EventHeaderError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(EventHeaderError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(EventHeaderError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    // Parameter names should be tokens
    if !is_token(name) {
        return Err(EventHeaderError::InvalidParamName(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), EventHeaderError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(EventHeaderError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(EventHeaderError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    if !is_token(value) {
        return Err(EventHeaderError::InvalidParamValue(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_state(state: &str) -> Result<(), EventHeaderError> {
    if state.is_empty() {
        return Err(EventHeaderError::InvalidState("empty state".to_string()));
    }

    if state.len() > MAX_STATE_LENGTH {
        return Err(EventHeaderError::StateTooLong {
            max: MAX_STATE_LENGTH,
            actual: state.len(),
        });
    }

    if state.chars().any(|c| c.is_ascii_control()) {
        return Err(EventHeaderError::InvalidState(
            "contains control characters".to_string(),
        ));
    }

    if !is_token(state) {
        return Err(EventHeaderError::InvalidState(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_event_header() {
        let event = EventHeader::new("presence").unwrap();
        assert_eq!(event.package(), "presence");
        assert_eq!(event.id(), None);
    }

    #[test]
    fn event_with_id() {
        let event = EventHeader::new("presence")
            .unwrap()
            .with_id("abc123")
            .unwrap();
        assert_eq!(event.id(), Some("abc123"));
    }

    #[test]
    fn event_with_params() {
        let event = EventHeader::new("presence")
            .unwrap()
            .with_param("priority", Some("urgent"))
            .unwrap()
            .with_param("version", Some("1.0"))
            .unwrap();

        assert_eq!(
            event.get_param("priority"),
            Some(&Some(SmolStr::new("urgent")))
        );
        assert_eq!(event.get_param("version"), Some(&Some(SmolStr::new("1.0"))));
    }

    #[test]
    fn reject_crlf_in_package() {
        let result = EventHeader::new("presence\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_package() {
        let long_package = "x".repeat(MAX_PACKAGE_LENGTH + 1);
        let result = EventHeader::new(&long_package);
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_id() {
        let result = EventHeader::new("presence")
            .unwrap()
            .with_id("abc\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_id_characters() {
        let result = EventHeader::new("presence").unwrap().with_id("bad id");
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_params() {
        let mut event = EventHeader::new("presence").unwrap();

        for i in 0..MAX_PARAMS {
            event.add_param(&format!("p{}", i), None).unwrap();
        }

        // Should fail
        let result = event.add_param("overflow", None);
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_params() {
        let result = EventHeader::new("presence")
            .unwrap()
            .with_param("priority", Some("high"))
            .unwrap()
            .with_param("priority", Some("low"));
        assert!(result.is_err());
    }

    #[test]
    fn params_case_insensitive() {
        let event = EventHeader::new("presence")
            .unwrap()
            .with_param("Priority", Some("high"))
            .unwrap();

        assert_eq!(
            event.get_param("priority"),
            Some(&Some(SmolStr::new("high")))
        );
    }

    #[test]
    fn subscription_state_creation() {
        let state = SubscriptionStateHeader::new(SubscriptionState::Active);
        assert_eq!(state.state().as_str(), "active");
    }

    #[test]
    fn subscription_state_from_str() {
        assert!(matches!(
            SubscriptionState::parse("active").unwrap(),
            SubscriptionState::Active
        ));
        assert!(matches!(
            SubscriptionState::parse("pending").unwrap(),
            SubscriptionState::Pending
        ));
        assert!(matches!(
            SubscriptionState::parse("terminated").unwrap(),
            SubscriptionState::Terminated
        ));
    }

    #[test]
    fn subscription_state_unknown() {
        let state = SubscriptionState::parse("custom-state").unwrap();
        assert_eq!(state.as_str(), "custom-state");
    }

    #[test]
    fn allow_token_chars_in_state() {
        let state = SubscriptionState::parse("custom~state").unwrap();
        assert_eq!(state.as_str(), "custom~state");
    }

    #[test]
    fn reject_invalid_state() {
        let result = SubscriptionState::parse("bad\r\nstate");
        assert!(result.is_err());
    }

    #[test]
    fn subscription_state_fromstr_trait() {
        use std::str::FromStr;
        let state = SubscriptionState::from_str("active").unwrap();
        assert!(matches!(state, SubscriptionState::Active));
    }

    #[test]
    fn reject_invalid_param_value() {
        let result = EventHeader::new("presence")
            .unwrap()
            .with_param("priority", Some("bad;value"));
        assert!(result.is_err());
    }

    #[test]
    fn subscription_state_with_params() {
        let state = SubscriptionStateHeader::new(SubscriptionState::Active)
            .with_param("expires", Some("3600"))
            .unwrap()
            .with_param("retry-after", Some("60"))
            .unwrap();

        assert_eq!(
            state.get_param("expires"),
            Some(&Some(SmolStr::new("3600")))
        );
    }
}
