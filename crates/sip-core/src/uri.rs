// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;
use std::fmt;

use percent_encoding::percent_decode_str;
use smol_str::SmolStr;

use crate::TelUri;

/// Parsed representation of a SIP URI (RFC 3261 §19).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipUri {
    pub raw: SmolStr,
    pub sips: bool,
    pub user: Option<SmolStr>,
    pub host: SmolStr,
    pub port: Option<u16>,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
    pub headers: BTreeMap<SmolStr, SmolStr>,
}

impl SipUri {
    /// Constructs a `sip:` URI with the given host and default settings.
    pub fn new(host: SmolStr) -> Self {
        Self {
            raw: host.clone(),
            sips: false,
            user: None,
            host,
            port: None,
            params: BTreeMap::new(),
            headers: BTreeMap::new(),
        }
    }

    /// Attempts to parse a SIP or SIPS URI from the provided string.
    pub fn parse(input: &str) -> Option<Self> {
        let raw = SmolStr::new(input.to_owned());
        let (scheme, rest) = input.split_once(':')?;
        let sips = scheme.eq_ignore_ascii_case("sips");
        if !sips && !scheme.eq_ignore_ascii_case("sip") {
            return None;
        }

        let (addr_part, headers_part) = match rest.split_once('?') {
            Some((addr, headers)) => (addr, Some(headers)),
            None => (rest, None),
        };

        let mut params = BTreeMap::new();
        let mut addr_iter = addr_part.split(';');
        let base = addr_iter.next()?.trim();
        for param in addr_iter {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            if let Some((k, v)) = param.split_once('=') {
                params.insert(
                    SmolStr::new(k.trim().to_owned()),
                    Some(SmolStr::new(v.trim().to_owned())),
                );
            } else {
                params.insert(SmolStr::new(param.to_owned()), None);
            }
        }

        let (user, host_port) = match base.split_once('@') {
            Some((user, host)) => (
                percent_decode_str(user.trim())
                    .decode_utf8()
                    .ok()
                    .map(|s| SmolStr::new(s.to_string())),
                host.trim(),
            ),
            None => (None, base.trim()),
        };

        if host_port.is_empty() {
            return None;
        }

        let (host, port) = split_host_port(host_port.trim())?;
        let host = percent_decode_str(host)
            .decode_utf8()
            .ok()?
            .to_ascii_lowercase();

        let mut headers = BTreeMap::new();
        if let Some(headers_part) = headers_part {
            for pair in headers_part.split('&') {
                if pair.is_empty() {
                    continue;
                }
                if let Some((k, v)) = pair.split_once('=') {
                    headers.insert(
                        SmolStr::new(k.trim().to_owned()),
                        SmolStr::new(v.trim().to_owned()),
                    );
                }
            }
        }

        Some(Self {
            raw,
            sips,
            user,
            host: SmolStr::new(host),
            port,
            params,
            headers,
        })
    }

    /// Returns the original textual representation of the URI.
    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }
}

/// Unified URI type supporting both SIP URIs (RFC 3261) and tel URIs (RFC 3966).
///
/// This enum allows handling of both SIP/SIPS URIs and telephone number URIs
/// in a type-safe manner. The parser automatically detects the URI scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Uri {
    /// SIP or SIPS URI (e.g., sip:user@example.com, sips:+15551234567@example.com)
    Sip(SipUri),
    /// Telephone URI (e.g., tel:+1-555-123-4567, tel:5551234;phone-context=example.com)
    Tel(TelUri),
    /// Absolute URI (e.g., http://example.com/info, https://example.com/loc)
    Absolute(SmolStr),
}

impl Uri {
    /// Parses a URI string, automatically detecting whether it's a SIP or tel URI.
    ///
    /// # Examples
    /// ```
    /// use sip_core::Uri;
    ///
    /// // Parse SIP URI
    /// let uri = Uri::parse("sip:alice@example.com").unwrap();
    ///
    /// // Parse tel URI
    /// let uri = Uri::parse("tel:+1-555-123-4567").unwrap();
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        // Try tel URI first (more specific prefix)
        if input.starts_with("tel:") {
            TelUri::parse(input).map(Uri::Tel)
        } else if input.starts_with("sip:") || input.starts_with("sips:") {
            SipUri::parse(input).map(Uri::Sip)
        } else {
            parse_absolute_uri(input).map(Uri::Absolute)
        }
    }

    /// Returns the URI as a string.
    pub fn as_str(&self) -> &str {
        match self {
            Uri::Sip(uri) => uri.as_str(),
            Uri::Tel(uri) => uri.as_str(),
            Uri::Absolute(uri) => uri.as_str(),
        }
    }

    /// Returns true if this is a SIP or SIPS URI.
    pub fn is_sip(&self) -> bool {
        matches!(self, Uri::Sip(_))
    }

    /// Returns true if this is a tel URI.
    pub fn is_tel(&self) -> bool {
        matches!(self, Uri::Tel(_))
    }

    /// Returns true if this is an absolute URI (non-sip, non-tel).
    pub fn is_absolute(&self) -> bool {
        matches!(self, Uri::Absolute(_))
    }

    /// Returns the inner SipUri if this is a SIP URI, None otherwise.
    pub fn as_sip(&self) -> Option<&SipUri> {
        match self {
            Uri::Sip(uri) => Some(uri),
            Uri::Tel(_) => None,
            Uri::Absolute(_) => None,
        }
    }

    /// Returns the inner TelUri if this is a tel URI, None otherwise.
    pub fn as_tel(&self) -> Option<&TelUri> {
        match self {
            Uri::Tel(uri) => Some(uri),
            Uri::Sip(_) => None,
            Uri::Absolute(_) => None,
        }
    }

    /// Returns the absolute URI string if present.
    pub fn as_absolute(&self) -> Option<&str> {
        match self {
            Uri::Absolute(uri) => Some(uri.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<SipUri> for Uri {
    fn from(uri: SipUri) -> Self {
        Uri::Sip(uri)
    }
}

impl From<TelUri> for Uri {
    fn from(uri: TelUri) -> Self {
        Uri::Tel(uri)
    }
}

fn parse_absolute_uri(input: &str) -> Option<SmolStr> {
    let trimmed = input.trim();
    let mut chars = trimmed.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let mut idx = 1;
    for ch in chars {
        if ch == ':' {
            break;
        }
        if !(ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.') {
            return None;
        }
        idx += ch.len_utf8();
    }
    if !trimmed[idx..].starts_with(':') {
        return None;
    }
    let remainder = &trimmed[idx + 1..];
    if remainder.is_empty() {
        return None;
    }
    Some(SmolStr::new(trimmed.to_owned()))
}

/// Splits a host[:port] or IPv6 literal "[host]:port" string.
fn split_host_port(input: &str) -> Option<(&str, Option<u16>)> {
    if input.starts_with('[') {
        let end = input.find(']')?;
        let host = &input[1..end];
        let remainder = &input[end + 1..];
        if remainder.starts_with(':') {
            let port = remainder[1..].parse().ok()?;
            Some((host, Some(port)))
        } else {
            Some((host, None))
        }
    } else if let Some(idx) = input.rfind(':') {
        if input.matches(':').count() > 1 {
            return None;
        }
        let (host, port_str) = input.split_at(idx);
        if port_str.len() > 1 && port_str[1..].chars().all(|c| c.is_ascii_digit()) {
            let port = port_str[1..].parse().ok()?;
            Some((host, Some(port)))
        } else {
            Some((input, None))
        }
    } else {
        Some((input, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sip_uri_via_uri_enum() {
        let uri = Uri::parse("sip:alice@example.com").unwrap();
        assert!(uri.is_sip());
        assert!(!uri.is_tel());

        let sip_uri = uri.as_sip().unwrap();
        assert_eq!(sip_uri.host.as_str(), "example.com");
        assert_eq!(sip_uri.user.as_ref().unwrap().as_str(), "alice");
    }

    #[test]
    fn parses_tel_uri_via_uri_enum() {
        let uri = Uri::parse("tel:+1-555-123-4567").unwrap();
        assert!(uri.is_tel());
        assert!(!uri.is_sip());

        let tel_uri = uri.as_tel().unwrap();
        assert!(tel_uri.is_global);
        assert_eq!(tel_uri.number.as_str(), "+15551234567");
    }

    #[test]
    fn uri_enum_display() {
        let sip_uri = Uri::parse("sip:alice@example.com").unwrap();
        assert_eq!(sip_uri.to_string(), "sip:alice@example.com");

        let tel_uri = Uri::parse("tel:+15551234567").unwrap();
        assert_eq!(tel_uri.to_string(), "tel:+15551234567");
    }

    #[test]
    fn uri_enum_from_conversions() {
        let sip = SipUri::parse("sip:alice@example.com").unwrap();
        let uri: Uri = sip.into();
        assert!(uri.is_sip());

        let tel = TelUri::parse("tel:+15551234567").unwrap();
        let uri: Uri = tel.into();
        assert!(uri.is_tel());
    }

    #[test]
    fn rejects_unbracketed_ipv6_host() {
        let uri = SipUri::parse("sip:2001:db8::1");
        assert!(uri.is_none());
    }
}
