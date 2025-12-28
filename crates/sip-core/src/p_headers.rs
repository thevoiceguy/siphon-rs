// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

use crate::uri::Uri;
use crate::SipUri;
use crate::TelUri;

const MAX_DISPLAY_NAME_LENGTH: usize = 256;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;
const MAX_IDENTITIES: usize = 10;
const MAX_NETWORK_IDS: usize = 20;
const MAX_NETWORK_ID_LENGTH: usize = 256;
const MAX_ACCESS_TYPE_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PHeaderError {
    DisplayNameTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    TooManyIdentities { max: usize, actual: usize },
    TooManyNetworkIds { max: usize, actual: usize },
    NetworkIdTooLong { max: usize, actual: usize },
    AccessTypeTooLong { max: usize, actual: usize },
    InvalidDisplayName(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    InvalidAccessType(String),
    InvalidNetworkId(String),
    DuplicateParam(String),
    EmptyIdentities,
    EmptyNetworkIds,
    InvalidTelUri(String),
    ParseError(String),
}

impl std::fmt::Display for PHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DisplayNameTooLong { max, actual } =>
                write!(f, "display name too long (max {}, got {})", max, actual),
            Self::TooManyIdentities { max, actual } =>
                write!(f, "too many identities (max {}, got {})", max, actual),
            Self::InvalidDisplayName(msg) =>
                write!(f, "invalid display name: {}", msg),
            Self::EmptyIdentities =>
                write!(f, "identities cannot be empty"),
            Self::InvalidTelUri(msg) =>
                write!(f, "invalid tel URI: {}", msg),
            Self::ParseError(msg) =>
                write!(f, "parse error: {}", msg),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for PHeaderError {}

/// Generic identity structure used by P-Asserted-Identity and P-Preferred-Identity.
///
/// Unlike `NameAddr`, this can hold both SIP URIs and Tel URIs, which is required
/// by RFC 3325 P-Asserted-Identity headers.
///
/// # Security
///
/// PIdentity validates all fields to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PIdentity {
    display_name: Option<SmolStr>,
    uri: Uri,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl PIdentity {
    /// Creates a PIdentity from a URI with no display name.
    pub fn from_uri(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: BTreeMap::new(),
        }
    }

    /// Creates a PIdentity with a display name.
    ///
    /// # Errors
    ///
    /// Returns an error if the display name contains control characters or is too long.
    pub fn with_display_name(mut self, name: impl AsRef<str>) -> Result<Self, PHeaderError> {
        validate_display_name(name.as_ref())?;
        self.display_name = Some(SmolStr::new(name.as_ref()));
        Ok(self)
    }

    /// Adds a parameter.
    pub fn with_param(
        mut self,
        name: impl AsRef<str>,
        value: Option<impl AsRef<str>>,
    ) -> Result<Self, PHeaderError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(
        &mut self,
        name: impl AsRef<str>,
        value: Option<impl AsRef<str>>,
    ) -> Result<(), PHeaderError> {
        let name = name.as_ref();
        validate_param_name(name)?;

        if let Some(v) = value.as_ref() {
            validate_param_value(v.as_ref())?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(PHeaderError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(&name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(PHeaderError::DuplicateParam(name.to_string()));
        }

        let mapped_value = value.as_ref().map(|v| SmolStr::new(v.as_ref()));
        self.params.insert(name_key, mapped_value);
        Ok(())
    }

    /// Returns the display name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_ref().map(|s| s.as_str())
    }

    /// Returns the URI.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns an iterator over parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params.iter().map(|(k, v)| {
            (k.as_str(), v.as_ref().map(|s| s.as_str()))
        })
    }

    /// Gets a parameter value by name (case-insensitive).
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(&name.to_ascii_lowercase()))
    }
}

impl fmt::Display for PIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.display_name {
            write!(f, "\"{}\" <{}>", name, self.uri)?;
        } else {
            write!(f, "<{}>", self.uri)?;
        }

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

/// P-Access-Network-Info header (access-type plus params).
///
/// # Security
///
/// Validates all fields to prevent injection attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PAccessNetworkInfo {
    access_type: SmolStr,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl PAccessNetworkInfo {
    /// Creates a new P-Access-Network-Info header.
    ///
    /// # Errors
    ///
    /// Returns an error if the access type is invalid.
    pub fn new(access_type: impl AsRef<str>) -> Result<Self, PHeaderError> {
        validate_access_type(access_type.as_ref())?;
        
        Ok(Self {
            access_type: SmolStr::new(access_type.as_ref()),
            params: BTreeMap::new(),
        })
    }

    /// Adds a parameter.
    pub fn with_param(
        mut self,
        name: impl AsRef<str>,
        value: Option<impl AsRef<str>>,
    ) -> Result<Self, PHeaderError> {
        self.add_param(name, value)?;
        Ok(self)
    }

    /// Adds a parameter (mutable version).
    pub fn add_param(
        &mut self,
        name: impl AsRef<str>,
        value: Option<impl AsRef<str>>,
    ) -> Result<(), PHeaderError> {
        let name = name.as_ref();
        validate_param_name(name)?;

        if let Some(v) = value.as_ref() {
            validate_param_value(v.as_ref())?;
        }

        if self.params.len() >= MAX_PARAMS {
            return Err(PHeaderError::TooManyParams {
                max: MAX_PARAMS,
                actual: self.params.len() + 1,
            });
        }

        let name_key = SmolStr::new(&name.to_ascii_lowercase());

        if self.params.contains_key(&name_key) {
            return Err(PHeaderError::DuplicateParam(name.to_string()));
        }

        let mapped_value = value.as_ref().map(|v| SmolStr::new(v.as_ref()));
        self.params.insert(name_key, mapped_value);
        Ok(())
    }

    /// Returns the access type.
    pub fn access_type(&self) -> &str {
        &self.access_type
    }

    /// Returns an iterator over parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params.iter().map(|(k, v)| {
            (k.as_str(), v.as_ref().map(|s| s.as_str()))
        })
    }

    /// Gets a parameter value by name (case-insensitive).
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(&name.to_ascii_lowercase()))
    }
}

/// P-Visited-Network-ID header.
///
/// # Security
///
/// Validates network IDs and enforces bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PVisitedNetworkIdHeader {
    values: Vec<SmolStr>,
}

impl PVisitedNetworkIdHeader {
    /// Creates a new P-Visited-Network-ID header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The values list is empty
    /// - Any value is invalid
    /// - Too many values
    pub fn new(values: Vec<impl AsRef<str>>) -> Result<Self, PHeaderError> {
        if values.is_empty() {
            return Err(PHeaderError::EmptyNetworkIds);
        }

        if values.len() > MAX_NETWORK_IDS {
            return Err(PHeaderError::TooManyNetworkIds {
                max: MAX_NETWORK_IDS,
                actual: values.len(),
            });
        }

        let mut validated_values = Vec::new();
        for value in values {
            validate_network_id(value.as_ref())?;
            validated_values.push(SmolStr::new(value.as_ref()));
        }

        Ok(Self {
            values: validated_values,
        })
    }

    /// Returns an iterator over network IDs.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.values.iter().map(|s| s.as_str())
    }

    /// Returns the number of network IDs.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if there are no network IDs (should never happen after construction).
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// RFC 3325 P-Asserted-Identity header.
///
/// The P-Asserted-Identity header is used by trusted proxies to assert
/// the identity of the originator of a request within a trust domain.
///
/// # Trust Domain
///
/// P-Asserted-Identity should only be inserted by trusted entities and
/// should only be trusted when received from trusted entities. At trust
/// domain boundaries, this header should be removed.
///
/// # Security
///
/// Validates all identities and enforces bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PAssertedIdentityHeader {
    identities: Vec<PIdentity>,
}

impl PAssertedIdentityHeader {
    /// Creates a P-Asserted-Identity header with a single SIP URI.
    pub fn single_sip(uri: SipUri) -> Self {
        Self {
            identities: vec![PIdentity::from_uri(Uri::Sip(uri))],
        }
    }

    /// Creates a P-Asserted-Identity header with a single Tel URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the tel number is invalid.
    pub fn single_tel(number: impl AsRef<str>) -> Result<Self, PHeaderError> {
        let number = number.as_ref();
        let tel_uri_str = if number.starts_with("tel:") {
            number.to_string()
        } else {
            format!("tel:{}", number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str)
            .ok_or_else(|| PHeaderError::InvalidTelUri(tel_uri_str.clone()))?;
        
        Ok(Self {
            identities: vec![PIdentity::from_uri(Uri::Tel(tel_uri))],
        })
    }

    /// Creates a P-Asserted-Identity header with both SIP and Tel URIs.
    ///
    /// # Errors
    ///
    /// Returns an error if the tel number is invalid.
    pub fn sip_and_tel(
        sip_uri: SipUri,
        tel_number: impl AsRef<str>,
    ) -> Result<Self, PHeaderError> {
        let tel_number = tel_number.as_ref();
        let tel_uri_str = if tel_number.starts_with("tel:") {
            tel_number.to_string()
        } else {
            format!("tel:{}", tel_number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str)
            .ok_or_else(|| PHeaderError::InvalidTelUri(tel_uri_str.clone()))?;
        
        Ok(Self {
            identities: vec![
                PIdentity::from_uri(Uri::Sip(sip_uri)),
                PIdentity::from_uri(Uri::Tel(tel_uri)),
            ],
        })
    }

    /// Creates a P-Asserted-Identity header with a list of identities.
    ///
    /// # Errors
    ///
    /// Returns an error if the identities list is empty or exceeds limits.
    pub fn new(identities: Vec<PIdentity>) -> Result<Self, PHeaderError> {
        if identities.is_empty() {
            return Err(PHeaderError::EmptyIdentities);
        }

        if identities.len() > MAX_IDENTITIES {
            return Err(PHeaderError::TooManyIdentities {
                max: MAX_IDENTITIES,
                actual: identities.len(),
            });
        }

        Ok(Self { identities })
    }

    /// Returns an iterator over identities.
    pub fn identities(&self) -> impl Iterator<Item = &PIdentity> {
        self.identities.iter()
    }

    /// Returns true if this header contains at least one Tel URI identity.
    pub fn has_tel_identity(&self) -> bool {
        self.identities.iter().any(|id| id.uri.is_tel())
    }

    /// Returns true if this header contains at least one SIP URI identity.
    pub fn has_sip_identity(&self) -> bool {
        self.identities.iter().any(|id| id.uri.is_sip())
    }

    /// Returns the first SIP URI identity if present.
    pub fn sip_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_sip())
            .map(|id| id.uri.as_str())
    }

    /// Returns the first Tel URI identity if present.
    pub fn tel_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_tel())
            .map(|id| id.uri.as_str())
    }

    /// Returns the number of identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Returns true if the header is empty (should never happen after construction).
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

impl fmt::Display for PAssertedIdentityHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, identity) in self.identities.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", identity)?;
        }
        Ok(())
    }
}

/// RFC 3325 P-Preferred-Identity header.
///
/// The P-Preferred-Identity header is used by a UAC to express a preference
/// about which identity should be asserted by a trusted proxy.
///
/// # Security
///
/// Validates all identities and enforces bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PPreferredIdentityHeader {
    identities: Vec<PIdentity>,
}

impl PPreferredIdentityHeader {
    /// Creates a P-Preferred-Identity header with a single SIP URI.
    pub fn single_sip(uri: SipUri) -> Self {
        Self {
            identities: vec![PIdentity::from_uri(Uri::Sip(uri))],
        }
    }

    /// Creates a P-Preferred-Identity header with a single Tel URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the tel number is invalid.
    pub fn single_tel(number: impl AsRef<str>) -> Result<Self, PHeaderError> {
        let number = number.as_ref();
        let tel_uri_str = if number.starts_with("tel:") {
            number.to_string()
        } else {
            format!("tel:{}", number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str)
            .ok_or_else(|| PHeaderError::InvalidTelUri(tel_uri_str.clone()))?;
        
        Ok(Self {
            identities: vec![PIdentity::from_uri(Uri::Tel(tel_uri))],
        })
    }

    /// Creates a P-Preferred-Identity header with both SIP and Tel URIs.
    ///
    /// # Errors
    ///
    /// Returns an error if the tel number is invalid.
    pub fn sip_and_tel(
        sip_uri: SipUri,
        tel_number: impl AsRef<str>,
    ) -> Result<Self, PHeaderError> {
        let tel_number = tel_number.as_ref();
        let tel_uri_str = if tel_number.starts_with("tel:") {
            tel_number.to_string()
        } else {
            format!("tel:{}", tel_number)
        };

        let tel_uri = TelUri::parse(&tel_uri_str)
            .ok_or_else(|| PHeaderError::InvalidTelUri(tel_uri_str.clone()))?;
        
        Ok(Self {
            identities: vec![
                PIdentity::from_uri(Uri::Sip(sip_uri)),
                PIdentity::from_uri(Uri::Tel(tel_uri)),
            ],
        })
    }

    /// Creates a P-Preferred-Identity header with a list of identities.
    ///
    /// # Errors
    ///
    /// Returns an error if the identities list is empty or exceeds limits.
    pub fn new(identities: Vec<PIdentity>) -> Result<Self, PHeaderError> {
        if identities.is_empty() {
            return Err(PHeaderError::EmptyIdentities);
        }

        if identities.len() > MAX_IDENTITIES {
            return Err(PHeaderError::TooManyIdentities {
                max: MAX_IDENTITIES,
                actual: identities.len(),
            });
        }

        Ok(Self { identities })
    }

    /// Returns an iterator over identities.
    pub fn identities(&self) -> impl Iterator<Item = &PIdentity> {
        self.identities.iter()
    }

    /// Returns true if this header contains at least one Tel URI identity.
    pub fn has_tel_identity(&self) -> bool {
        self.identities.iter().any(|id| id.uri.is_tel())
    }

    /// Returns true if this header contains at least one SIP URI identity.
    pub fn has_sip_identity(&self) -> bool {
        self.identities.iter().any(|id| id.uri.is_sip())
    }

    /// Returns the first SIP URI identity if present.
    pub fn sip_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_sip())
            .map(|id| id.uri.as_str())
    }

    /// Returns the first Tel URI identity if present.
    pub fn tel_identity(&self) -> Option<&str> {
        self.identities
            .iter()
            .find(|id| id.uri.is_tel())
            .map(|id| id.uri.as_str())
    }

    /// Returns the number of identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Returns true if the header is empty (should never happen after construction).
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

impl fmt::Display for PPreferredIdentityHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, identity) in self.identities.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", identity)?;
        }
        Ok(())
    }
}

/// Helper function to parse P-Asserted-Identity from headers.
pub fn parse_p_asserted_identity(
    headers: &crate::Headers,
) -> Result<Option<PAssertedIdentityHeader>, PHeaderError> {
    let mut identities = Vec::new();
    for value in headers.get_all_smol("P-Asserted-Identity") {
        let parsed = parse_p_identities(value.as_str())?;
        identities.extend(parsed);
    }

    if identities.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PAssertedIdentityHeader::new(identities)?))
    }
}

/// Helper function to parse P-Preferred-Identity from headers.
pub fn parse_p_preferred_identity(
    headers: &crate::Headers,
) -> Result<Option<PPreferredIdentityHeader>, PHeaderError> {
    let mut identities = Vec::new();
    for value in headers.get_all_smol("P-Preferred-Identity") {
        let parsed = parse_p_identities(value.as_str())?;
        identities.extend(parsed);
    }

    if identities.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PPreferredIdentityHeader::new(identities)?))
    }
}

/// Parses one or more identities from a header value.
fn parse_p_identities(value: &str) -> Result<Vec<PIdentity>, PHeaderError> {
    split_identities(value)
        .into_iter()
        .map(parse_p_identity)
        .collect()
}

/// Simple parser for P-Identity format: "Display Name" <uri>;params
fn parse_p_identity(value: &str) -> Result<PIdentity, PHeaderError> {
    let input = value.trim();
    if input.is_empty() {
        return Err(PHeaderError::ParseError("empty input".to_string()));
    }

    // Try to parse as URI in brackets: <uri>
    if let Some((start, end)) = find_unquoted_angle_brackets(input)? {
        let display = input[..start].trim().trim_matches('"');
        let uri_str = input[start + 1..end].trim();
        let params_str = input[end + 1..].trim();

        let uri = Uri::parse(uri_str)
            .ok_or_else(|| PHeaderError::ParseError("invalid URI".to_string()))?;

        let mut identity = PIdentity {
            display_name: None,
            uri,
            params: BTreeMap::new(),
        };

        if !display.is_empty() {
            validate_display_name(display)?;
            identity.display_name = Some(SmolStr::new(display));
        }

        if !params_str.is_empty() {
            add_params_from_str(&mut identity, params_str)?;
        }

        Ok(identity)
    } else {
        // Plain URI without brackets
        let (uri_part, params_part) = split_uri_and_params(input);
        let uri = Uri::parse(uri_part)
            .ok_or_else(|| PHeaderError::ParseError("invalid URI".to_string()))?;
        
        let mut identity = PIdentity {
            display_name: None,
            uri,
            params: BTreeMap::new(),
        };

        if let Some(params_str) = params_part {
            add_params_from_str(&mut identity, params_str)?;
        }

        Ok(identity)
    }
}

fn find_unquoted_angle_brackets(input: &str) -> Result<Option<(usize, usize)>, PHeaderError> {
    let mut in_quotes = false;
    let mut start = None;
    for (idx, ch) in input.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => {
                if start.is_some() {
                    return Err(PHeaderError::ParseError(
                        "nested angle brackets".to_string(),
                    ));
                }
                start = Some(idx);
            }
            '>' if !in_quotes => {
                if let Some(s) = start {
                    return Ok(Some((s, idx)));
                }
                return Err(PHeaderError::ParseError(
                    "closing bracket without opening bracket".to_string(),
                ));
            }
            _ => {}
        }
    }
    if start.is_some() {
        return Err(PHeaderError::ParseError(
            "missing closing bracket".to_string(),
        ));
    }
    Ok(None)
}

fn split_identities(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut in_angle = false;

    for (idx, ch) in value.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => in_angle = true,
            '>' if !in_quotes => in_angle = false,
            ',' if !in_quotes && !in_angle => {
                let slice = value[start..idx].trim();
                if !slice.is_empty() {
                    parts.push(slice);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }

    let tail = value[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }

    parts
}

fn split_uri_and_params(value: &str) -> (&str, Option<&str>) {
    if let Some((uri, params)) = value.split_once(';') {
        (uri.trim(), Some(params.trim()))
    } else {
        (value.trim(), None)
    }
}

fn add_params_from_str(identity: &mut PIdentity, params_str: &str) -> Result<(), PHeaderError> {
    for raw_param in params_str.split(';') {
        let param = raw_param.trim();
        if param.is_empty() {
            continue;
        }
        if let Some((name, value)) = param.split_once('=') {
            identity.add_param(name.trim(), Some(value.trim()))?;
        } else {
            identity.add_param(param, Option::<&str>::None)?;
        }
    }
    Ok(())
}

// Validation functions

fn validate_display_name(name: &str) -> Result<(), PHeaderError> {
    if name.len() > MAX_DISPLAY_NAME_LENGTH {
        return Err(PHeaderError::DisplayNameTooLong {
            max: MAX_DISPLAY_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(PHeaderError::InvalidDisplayName(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), PHeaderError> {
    if name.is_empty() {
        return Err(PHeaderError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(PHeaderError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(PHeaderError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric() || 
        matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    }) {
        return Err(PHeaderError::InvalidParamName(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), PHeaderError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(PHeaderError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(PHeaderError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_access_type(access_type: &str) -> Result<(), PHeaderError> {
    if access_type.is_empty() {
        return Err(PHeaderError::InvalidAccessType("empty access type".to_string()));
    }

    if access_type.len() > MAX_ACCESS_TYPE_LENGTH {
        return Err(PHeaderError::AccessTypeTooLong {
            max: MAX_ACCESS_TYPE_LENGTH,
            actual: access_type.len(),
        });
    }

    if access_type.chars().any(|c| c.is_ascii_control()) {
        return Err(PHeaderError::InvalidAccessType(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_network_id(network_id: &str) -> Result<(), PHeaderError> {
    if network_id.is_empty() {
        return Err(PHeaderError::InvalidNetworkId("empty network ID".to_string()));
    }

    if network_id.len() > MAX_NETWORK_ID_LENGTH {
        return Err(PHeaderError::NetworkIdTooLong {
            max: MAX_NETWORK_ID_LENGTH,
            actual: network_id.len(),
        });
    }

    if network_id.chars().any(|c| c.is_ascii_control()) {
        return Err(PHeaderError::InvalidNetworkId(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_asserted_identity_single_sip() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai = PAssertedIdentityHeader::single_sip(uri);

        assert_eq!(pai.len(), 1);
        assert!(pai.has_sip_identity());
        assert!(!pai.has_tel_identity());
        assert_eq!(pai.sip_identity(), Some("sip:alice@example.com"));
    }

    #[test]
    fn p_asserted_identity_single_tel() {
        let pai = PAssertedIdentityHeader::single_tel("+15551234567").unwrap();

        assert_eq!(pai.len(), 1);
        assert!(!pai.has_sip_identity());
        assert!(pai.has_tel_identity());
        assert_eq!(pai.tel_identity(), Some("tel:+15551234567"));
    }

    #[test]
    fn reject_crlf_in_display_name() {
        let uri = Uri::parse("sip:alice@example.com").unwrap();
        let result = PIdentity::from_uri(uri)
            .with_display_name("Alice\r\nInjected");
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_display_name() {
        let uri = Uri::parse("sip:alice@example.com").unwrap();
        let long_name = "x".repeat(MAX_DISPLAY_NAME_LENGTH + 1);
        let result = PIdentity::from_uri(uri)
            .with_display_name(&long_name);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_identities() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let identities = vec![PIdentity::from_uri(Uri::Sip(uri)); MAX_IDENTITIES + 1];
        let result = PAssertedIdentityHeader::new(identities);
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_identities() {
        let result = PAssertedIdentityHeader::new(vec![]);
        assert!(matches!(result, Err(PHeaderError::EmptyIdentities)));
    }

    #[test]
    fn reject_too_many_params() {
        let uri = Uri::parse("sip:alice@example.com").unwrap();
        let mut identity = PIdentity::from_uri(uri);
        
        for i in 0..MAX_PARAMS {
            identity.add_param(&format!("p{}", i), Some("value")).unwrap();
        }
        
        let result = identity.add_param("overflow", Some("value"));
        assert!(result.is_err());
    }

    #[test]
    fn fields_are_private() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let pai = PAssertedIdentityHeader::single_sip(uri);
        let identity = pai.identities().next().unwrap();
        
        // These should compile (read-only access)
        let _ = identity.display_name();
        let _ = identity.uri();
        let _ = pai.has_sip_identity();
        
        // These should NOT compile (no direct field access):
        // identity.display_name = Some(...);  // ← Does not compile!
        // pai.identities.clear();             // ← Does not compile!
    }

    #[test]
    fn parse_p_identity_with_display() {
        let identity = parse_p_identity("\"Alice Smith\" <sip:alice@example.com>").unwrap();
        assert_eq!(identity.uri().as_str(), "sip:alice@example.com");
        assert_eq!(identity.display_name(), Some("Alice Smith"));
    }

    #[test]
    fn parse_p_identity_with_angle_in_display() {
        let identity = parse_p_identity("\"Bob <Ops>\" <sip:bob@example.com>").unwrap();
        assert_eq!(identity.uri().as_str(), "sip:bob@example.com");
        assert_eq!(identity.display_name(), Some("Bob <Ops>"));
    }

    #[test]
    fn parse_p_identity_with_params() {
        let identity =
            parse_p_identity("\"Alice\" <sip:alice@example.com>;foo=bar;secure").unwrap();
        assert_eq!(identity.uri().as_str(), "sip:alice@example.com");
        assert_eq!(identity.display_name(), Some("Alice"));
        assert_eq!(identity.get_param("foo").and_then(|v| v.as_ref()).map(|v| v.as_str()), Some("bar"));
        assert!(identity.get_param("secure").is_some());
    }

    #[test]
    fn parse_p_identity_list_with_commas() {
        let values = parse_p_identities("\"Alice\" <sip:alice@example.com>, <tel:+15551234567>")
            .unwrap();
        assert_eq!(values.len(), 2);
        assert!(values[0].uri().is_sip());
        assert!(values[1].uri().is_tel());
    }

    #[test]
    fn reject_invalid_parse_input() {
        // Missing closing bracket
        let result = parse_p_identity("<sip:alice@example.com");
        assert!(result.is_err());
        
        // Empty input
        let result = parse_p_identity("");
        assert!(result.is_err());
    }
}
