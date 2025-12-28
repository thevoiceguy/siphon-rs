// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::Uri;
use smol_str::SmolStr;
use std::collections::BTreeMap;

const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;
const MAX_GEO_VALUES: usize = 10;
const MAX_ERROR_CODE_LENGTH: usize = 16;
const MAX_ERROR_DESCRIPTION_LENGTH: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeolocationError {
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    TooManyValues { max: usize, actual: usize },
    ErrorCodeTooLong { max: usize, actual: usize },
    DescriptionTooLong { max: usize, actual: usize },
    InvalidParamName(String),
    InvalidParamValue(String),
    InvalidErrorCode(String),
    InvalidDescription(String),
    DuplicateParam(String),
    EmptyValues,
}

impl std::fmt::Display for GeolocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParamNameTooLong { max, actual } => {
                write!(f, "param name too long (max {}, got {})", max, actual)
            }
            Self::TooManyParams { max, actual } => {
                write!(f, "too many params (max {}, got {})", max, actual)
            }
            Self::TooManyValues { max, actual } => write!(
                f,
                "too many geolocation values (max {}, got {})",
                max, actual
            ),
            Self::InvalidParamName(msg) => write!(f, "invalid param name: {}", msg),
            Self::DuplicateParam(name) => write!(f, "duplicate parameter: {}", name),
            Self::EmptyValues => write!(f, "geolocation header must have at least one value"),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for GeolocationError {}

/// Represents a single Geolocation header value.
///
/// Per RFC 6442, each geolocation value contains a URI pointing to location
/// information (e.g., a PIDF-LO document) and optional parameters.
///
/// # Security
///
/// GeolocationValue validates all input to prevent:
/// - CRLF injection in parameters
/// - Control character injection
/// - Excessive length (DoS)
/// - Unbounded parameter lists
///
/// # Privacy
///
/// Geolocation data is highly sensitive. Consider:
/// - Using HTTPS URIs for location data
/// - Implementing access controls
/// - Following GDPR/CCPA requirements
/// - Using encryption when transmitting
///
/// # Examples
///
/// ```
/// use sip_core::{GeolocationValue, Uri};
///
/// let uri = Uri::parse("https://example.com/location.xml").unwrap();
/// let geo = GeolocationValue::new(uri)
///     .with_param("cid", Some("abc123"))
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationValue {
    uri: Uri,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl GeolocationValue {
    /// Creates a new geolocation value with the given URI.
    pub fn new(uri: Uri) -> Self {
        Self {
            uri,
            params: BTreeMap::new(),
        }
    }

    /// Adds a parameter with validation.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Result<Self, GeolocationError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(&mut self, name: &str, value: Option<&str>) -> Result<(), GeolocationError> {
        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(GeolocationError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(GeolocationError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, value.map(SmolStr::new));
        Ok(())
    }

    /// Returns the location URI.
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
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }
}

/// Geolocation header (list of location values).
///
/// Per RFC 6442, the Geolocation header contains one or more URIs pointing
/// to location information.
///
/// # Security
///
/// - Validates all location values
/// - Limits the number of values to prevent DoS
/// - Ensures at least one value is present
///
/// # Examples
///
/// ```
/// use sip_core::{GeolocationHeader, GeolocationValue, Uri};
///
/// let uri = Uri::parse("https://example.com/location.xml").unwrap();
/// let value = GeolocationValue::new(uri);
/// let header = GeolocationHeader::new(vec![value]).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationHeader {
    values: Vec<GeolocationValue>,
}

impl GeolocationHeader {
    /// Creates a new Geolocation header with the given values.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The values list is empty
    /// - The values list exceeds MAX_GEO_VALUES
    pub fn new(values: Vec<GeolocationValue>) -> Result<Self, GeolocationError> {
        if values.is_empty() {
            return Err(GeolocationError::EmptyValues);
        }

        if values.len() > MAX_GEO_VALUES {
            return Err(GeolocationError::TooManyValues {
                max: MAX_GEO_VALUES,
                actual: values.len(),
            });
        }

        Ok(Self { values })
    }

    /// Creates a header with a single value.
    pub fn single(value: GeolocationValue) -> Self {
        Self {
            values: vec![value],
        }
    }

    /// Returns an iterator over the location values.
    pub fn values(&self) -> impl Iterator<Item = &GeolocationValue> {
        self.values.iter()
    }

    /// Returns the number of location values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if there are no values (should never happen after construction).
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the first location value.
    pub fn first(&self) -> Option<&GeolocationValue> {
        self.values.first()
    }
}

/// Geolocation-Error header.
///
/// Per RFC 6442, this header indicates an error in processing location information.
/// Format: `Geolocation-Error: code "description" ;params`
///
/// # Security
///
/// GeolocationErrorHeader validates all fields to prevent injection attacks.
///
/// # Examples
///
/// ```
/// use sip_core::GeolocationErrorHeader;
///
/// let error = GeolocationErrorHeader::new()
///     .with_code("404")
///     .unwrap()
///     .with_description("Location not found")
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationErrorHeader {
    code: Option<SmolStr>,
    description: Option<SmolStr>,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl GeolocationErrorHeader {
    /// Creates a new empty Geolocation-Error header.
    pub fn new() -> Self {
        Self {
            code: None,
            description: None,
            params: BTreeMap::new(),
        }
    }

    /// Sets the error code.
    pub fn with_code(mut self, code: &str) -> Result<Self, GeolocationError> {
        validate_error_code(code)?;
        self.code = Some(SmolStr::new(code));
        Ok(self)
    }

    /// Sets the error description.
    pub fn with_description(mut self, description: &str) -> Result<Self, GeolocationError> {
        validate_description(description)?;
        self.description = Some(SmolStr::new(description));
        Ok(self)
    }

    /// Adds a parameter.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Result<Self, GeolocationError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(&mut self, name: &str, value: Option<&str>) -> Result<(), GeolocationError> {
        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(GeolocationError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(GeolocationError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, value.map(SmolStr::new));
        Ok(())
    }

    /// Returns the error code.
    pub fn code(&self) -> Option<&str> {
        self.code.as_ref().map(|s| s.as_str())
    }

    /// Returns the error description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_ref().map(|s| s.as_str())
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

impl Default for GeolocationErrorHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Geolocation-Routing header.
///
/// Per RFC 6442, this header controls whether location information should
/// be used for routing decisions.
///
/// # Security
///
/// GeolocationRoutingHeader validates all parameters to prevent injection attacks.
///
/// # Examples
///
/// ```
/// use sip_core::GeolocationRoutingHeader;
///
/// let routing = GeolocationRoutingHeader::new()
///     .with_param("routing-allowed", Some("yes"))
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationRoutingHeader {
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl GeolocationRoutingHeader {
    /// Creates a new Geolocation-Routing header.
    pub fn new() -> Self {
        Self {
            params: BTreeMap::new(),
        }
    }

    /// Adds a parameter.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Result<Self, GeolocationError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(&mut self, name: &str, value: Option<&str>) -> Result<(), GeolocationError> {
        validate_param_name(name)?;

        if let Some(v) = value {
            validate_param_value(v)?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(GeolocationError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(GeolocationError::DuplicateParam(name.to_string()));
        }

        self.params.insert(name_key, value.map(SmolStr::new));
        Ok(())
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

    /// Returns true if there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

impl Default for GeolocationRoutingHeader {
    fn default() -> Self {
        Self::new()
    }
}

// Validation functions

fn validate_param_name(name: &str) -> Result<(), GeolocationError> {
    if name.is_empty() {
        return Err(GeolocationError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(GeolocationError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(GeolocationError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    // Parameter names should be tokens
    if !is_token(name) {
        return Err(GeolocationError::InvalidParamName(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), GeolocationError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(GeolocationError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(GeolocationError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    if !is_token(value) {
        return Err(GeolocationError::InvalidParamValue(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_error_code(code: &str) -> Result<(), GeolocationError> {
    if code.is_empty() {
        return Err(GeolocationError::InvalidErrorCode("empty code".to_string()));
    }

    if code.len() > MAX_ERROR_CODE_LENGTH {
        return Err(GeolocationError::ErrorCodeTooLong {
            max: MAX_ERROR_CODE_LENGTH,
            actual: code.len(),
        });
    }

    if code.chars().any(|c| c.is_ascii_control()) {
        return Err(GeolocationError::InvalidErrorCode(
            "contains control characters".to_string(),
        ));
    }

    // Error codes should be numeric or alphanumeric
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(GeolocationError::InvalidErrorCode(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_description(description: &str) -> Result<(), GeolocationError> {
    if description.len() > MAX_ERROR_DESCRIPTION_LENGTH {
        return Err(GeolocationError::DescriptionTooLong {
            max: MAX_ERROR_DESCRIPTION_LENGTH,
            actual: description.len(),
        });
    }

    // Allow most printable characters but not control characters
    if description.chars().any(|c| c.is_ascii_control()) {
        return Err(GeolocationError::InvalidDescription(
            "contains control characters".to_string(),
        ));
    }

    if description.chars().any(|c| matches!(c, '"' | '\\')) {
        return Err(GeolocationError::InvalidDescription(
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

    fn mock_uri() -> Uri {
        Uri::parse("https://example.com/location.xml").expect("mock URI should parse")
    }

    #[test]
    fn create_geolocation_value() {
        let uri = mock_uri();
        let geo = GeolocationValue::new(uri.clone());
        assert_eq!(geo.uri(), &uri);
    }

    #[test]
    fn geolocation_value_with_params() {
        let uri = mock_uri();
        let geo = GeolocationValue::new(uri)
            .with_param("cid", Some("abc123"))
            .unwrap()
            .with_param("inserted-by", Some("proxy"))
            .unwrap();

        assert_eq!(geo.get_param("cid"), Some(&Some(SmolStr::new("abc123"))));
    }

    #[test]
    fn reject_crlf_in_param_name() {
        let uri = mock_uri();
        let result = GeolocationValue::new(uri).with_param("param\r\ninjected", Some("value"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_param_value() {
        let uri = mock_uri();
        let result = GeolocationValue::new(uri).with_param("param", Some("value\r\ninjected"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_param_value() {
        let uri = mock_uri();
        let result = GeolocationValue::new(uri).with_param("param", Some("bad value"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_params() {
        let uri = mock_uri();
        let mut geo = GeolocationValue::new(uri);

        for i in 0..MAX_PARAMS {
            geo.add_param(&format!("p{}", i), None).unwrap();
        }

        // Should fail
        let result = geo.add_param("overflow", None);
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_params() {
        let uri = mock_uri();
        let result = GeolocationValue::new(uri)
            .with_param("cid", Some("123"))
            .unwrap()
            .with_param("cid", Some("456"));
        assert!(result.is_err());
    }

    #[test]
    fn create_geolocation_header() {
        let uri = mock_uri();
        let value = GeolocationValue::new(uri);
        let header = GeolocationHeader::new(vec![value]).unwrap();
        assert_eq!(header.len(), 1);
    }

    #[test]
    fn reject_empty_geolocation_header() {
        let result = GeolocationHeader::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_geo_values() {
        let uri = mock_uri();
        let values = vec![GeolocationValue::new(uri); MAX_GEO_VALUES + 1];
        let result = GeolocationHeader::new(values);
        assert!(result.is_err());
    }

    #[test]
    fn create_geolocation_error() {
        let error = GeolocationErrorHeader::new()
            .with_code("404")
            .unwrap()
            .with_description("Location not found")
            .unwrap();

        assert_eq!(error.code(), Some("404"));
        assert_eq!(error.description(), Some("Location not found"));
    }

    #[test]
    fn reject_crlf_in_error_code() {
        let result = GeolocationErrorHeader::new().with_code("404\r\ninjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_description() {
        let result = GeolocationErrorHeader::new().with_description("Not found\r\nInjected: evil");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_description_chars() {
        let result = GeolocationErrorHeader::new().with_description("Not \"found\"");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_description() {
        let long_desc = "x".repeat(MAX_ERROR_DESCRIPTION_LENGTH + 1);
        let result = GeolocationErrorHeader::new().with_description(&long_desc);
        assert!(result.is_err());
    }

    #[test]
    fn create_geolocation_routing() {
        let routing = GeolocationRoutingHeader::new()
            .with_param("routing-allowed", Some("yes"))
            .unwrap();

        assert_eq!(
            routing.get_param("routing-allowed"),
            Some(&Some(SmolStr::new("yes")))
        );
    }

    #[test]
    fn params_case_insensitive() {
        let routing = GeolocationRoutingHeader::new()
            .with_param("Routing-Allowed", Some("yes"))
            .unwrap();

        assert_eq!(
            routing.get_param("routing-allowed"),
            Some(&Some(SmolStr::new("yes")))
        );
    }
}
