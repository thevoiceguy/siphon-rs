// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::{SipUri, TelUri, Uri};

/// Generic SIP name-addr structure used by many headers (From/To/Contact/etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    display_name: Option<SmolStr>,
    uri: Uri,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl NameAddr {
    pub const MAX_DISPLAY_NAME_LEN: usize = 256;
    pub const MAX_PARAM_COUNT: usize = 64;
    pub const MAX_PARAM_NAME_LEN: usize = 64;
    pub const MAX_PARAM_VALUE_LEN: usize = 256;

    pub fn new(
        display_name: Option<SmolStr>,
        uri: Uri,
        params: BTreeMap<SmolStr, Option<SmolStr>>,
    ) -> Result<Self, NameAddrError> {
        if let Some(ref name) = display_name {
            validate_text("display name", name.as_str(), Self::MAX_DISPLAY_NAME_LEN)?;
        }

        if params.len() > Self::MAX_PARAM_COUNT {
            return Err(NameAddrError::TooManyParams {
                max: Self::MAX_PARAM_COUNT,
                actual: params.len(),
            });
        }

        let mut normalized_params = BTreeMap::new();
        for (name, value) in params {
            let name_lower = name.to_ascii_lowercase();
            validate_param_name(name_lower.as_str())?;
            let name_key = SmolStr::new(name_lower.as_str());
            if normalized_params.contains_key(&name_key) {
                return Err(NameAddrError::DuplicateParam(name_lower));
            }

            if let Some(ref val) = value {
                validate_text("param value", val.as_str(), Self::MAX_PARAM_VALUE_LEN)?;
            }

            normalized_params.insert(name_key, value);
        }

        Ok(Self {
            display_name,
            uri,
            params: normalized_params,
        })
    }

    pub fn from_uri(uri: Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: BTreeMap::new(),
        }
    }

    pub fn display_name(&self) -> Option<&SmolStr> {
        self.display_name.as_ref()
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn sip_uri(&self) -> Option<&SipUri> {
        self.uri.as_sip()
    }

    pub fn tel_uri(&self) -> Option<&TelUri> {
        self.uri.as_tel()
    }

    pub fn params(&self) -> impl Iterator<Item = (&SmolStr, &Option<SmolStr>)> {
        self.params.iter()
    }

    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }

    pub fn params_map(&self) -> &BTreeMap<SmolStr, Option<SmolStr>> {
        &self.params
    }

    pub fn insert_param(
        &mut self,
        name: SmolStr,
        value: Option<SmolStr>,
    ) -> Result<Option<Option<SmolStr>>, NameAddrError> {
        let name_lower = name.to_ascii_lowercase();
        validate_param_name(name_lower.as_str())?;
        let name_key = SmolStr::new(name_lower.as_str());
        if !self.params.contains_key(&name_key) && self.params.len() >= Self::MAX_PARAM_COUNT
        {
            return Err(NameAddrError::TooManyParams {
                max: Self::MAX_PARAM_COUNT,
                actual: self.params.len() + 1,
            });
        }
        if let Some(ref val) = value {
            validate_text("param value", val.as_str(), Self::MAX_PARAM_VALUE_LEN)?;
        }
        Ok(self.params.insert(name_key, value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameAddrError {
    InvalidText {
        field: &'static str,
    },
    TextTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    TooManyParams {
        max: usize,
        actual: usize,
    },
    InvalidParamName(String),
    DuplicateParam(String),
}

impl std::fmt::Display for NameAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameAddrError::InvalidText { field } => {
                write!(f, "{} contains invalid characters", field)
            }
            NameAddrError::TextTooLong { field, max, actual } => {
                write!(f, "{} exceeds max length {} (got {})", field, max, actual)
            }
            NameAddrError::TooManyParams { max, actual } => {
                write!(f, "too many params (max {}, got {})", max, actual)
            }
            NameAddrError::InvalidParamName(name) => {
                write!(f, "invalid param name {}", name)
            }
            NameAddrError::DuplicateParam(name) => {
                write!(f, "duplicate param {}", name)
            }
        }
    }
}

impl std::error::Error for NameAddrError {}

fn validate_text(field: &'static str, value: &str, max_len: usize) -> Result<(), NameAddrError> {
    if value.len() > max_len {
        return Err(NameAddrError::TextTooLong {
            field,
            max: max_len,
            actual: value.len(),
        });
    }
    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
        return Err(NameAddrError::InvalidText { field });
    }
    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), NameAddrError> {
    if name.is_empty() || name.len() > NameAddr::MAX_PARAM_NAME_LEN {
        return Err(NameAddrError::InvalidParamName(name.to_string()));
    }
    if name.contains('\r') || name.contains('\n') || name.contains('\0') {
        return Err(NameAddrError::InvalidParamName(name.to_string()));
    }
    let valid = name.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    });
    if !valid {
        return Err(NameAddrError::InvalidParamName(name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_addr_rejects_crlf_in_display_name() {
        let uri = Uri::from(SipUri::parse("sip:alice@example.com").unwrap());
        let name = SmolStr::new("Alice\r\nInjected");
        let err = NameAddr::new(Some(name), uri, BTreeMap::new()).unwrap_err();
        assert!(matches!(err, NameAddrError::InvalidText { .. }));
    }

    #[test]
    fn name_addr_rejects_invalid_param_name() {
        let uri = Uri::from(SipUri::parse("sip:alice@example.com").unwrap());
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("bad name"), None);
        let err = NameAddr::new(None, uri, params).unwrap_err();
        assert!(matches!(err, NameAddrError::InvalidParamName(_)));
    }

    #[test]
    fn name_addr_rejects_duplicate_params_case_insensitive() {
        let uri = Uri::from(SipUri::parse("sip:alice@example.com").unwrap());
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("Tag"), None);
        params.insert(SmolStr::new("tag"), None);
        let err = NameAddr::new(None, uri, params).unwrap_err();
        assert!(matches!(err, NameAddrError::DuplicateParam(_)));
    }

    #[test]
    fn name_addr_rejects_crlf_in_param_value() {
        let uri = Uri::from(SipUri::parse("sip:alice@example.com").unwrap());
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("tag"), Some(SmolStr::new("abc\r\ndef")));
        let err = NameAddr::new(None, uri, params).unwrap_err();
        assert!(matches!(err, NameAddrError::InvalidText { .. }));
    }
}
