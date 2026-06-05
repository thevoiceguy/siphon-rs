// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 8224 `Identity` header parsing.
//!
//! The modern (full-form PASSporT) `Identity` header carries a compact-JWS
//! PASSporT token followed by header parameters:
//!
//! ```text
//! Identity: eyJhbG...header.eyJ...payload.sig;info=<https://cert.example.org/cert.crt>;alg=ES256;ppt=shaken
//! ```
//!
//! This parses the structure and decodes the embedded PASSporT. It does
//! NOT verify the signature or fetch the `info` certificate.

use crate::error::IdentityError;
use crate::passport::Passport;

/// Maximum accepted `Identity` header length. A SHAKEN header (PASSporT +
/// cert URL) runs ~1 KB; 8 KB leaves generous headroom while bounding the
/// work an attacker can force with an oversized header (DoS guard).
const MAX_HEADER_LEN: usize = 8192;

/// A parsed RFC 8224 `Identity` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityHeader {
    /// The decoded PASSporT carried by the header.
    pub passport: Passport,
    /// The `info` parameter URI (cert location), angle brackets stripped.
    /// RFC 8224 §4: usually mirrors the PASSporT's `x5u`; the verifier
    /// uses `x5u` as authoritative and may cross-check `info`.
    pub info: Option<String>,
    /// The `alg` parameter (signature algorithm; default/SHAKEN: `ES256`).
    pub alg: Option<String>,
    /// The `ppt` parameter (PASSporT type; SHAKEN: `shaken`).
    pub ppt: Option<String>,
    /// The raw compact-JWS token, retained for logging / re-emission.
    pub raw_token: String,
}

impl IdentityHeader {
    /// Parse the value of an `Identity` header (everything after
    /// `Identity:`). Whitespace around the token and parameters is
    /// tolerated per SIP LWS rules.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        if value.len() > MAX_HEADER_LEN {
            return Err(IdentityError::HeaderTooLong {
                max: MAX_HEADER_LEN,
                actual: value.len(),
            });
        }

        let mut segments = value.split(';');
        let token = segments.next().unwrap_or("").trim();
        if token.is_empty() {
            return Err(IdentityError::EmptyToken);
        }

        let passport = Passport::decode(token)?;

        let mut info = None;
        let mut alg = None;
        let mut ppt = None;
        for seg in segments {
            let seg = seg.trim();
            if seg.is_empty() {
                continue;
            }
            let (key, val) = match seg.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                // A bare param with no value isn't meaningful for the
                // params we care about; ignore unknown valueless tokens.
                None => continue,
            };
            // Header parameter names are case-insensitive (RFC 3261 §7.3.1).
            match key.to_ascii_lowercase().as_str() {
                "info" => info = Some(strip_angle_brackets(val)?),
                "alg" => alg = Some(unquote(val).to_string()),
                "ppt" => ppt = Some(unquote(val).to_string()),
                // Unknown params (RFC 8224 allows extensions) are ignored.
                _ => {}
            }
        }

        Ok(Self {
            passport,
            info,
            alg,
            ppt,
            raw_token: token.to_string(),
        })
    }
}

/// `info` is a URI in angle brackets: `<https://…>`. Require them — a
/// bare URI is malformed per RFC 8224 §4.
fn strip_angle_brackets(s: &str) -> Result<String, IdentityError> {
    let s = s.trim();
    s.strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .map(|inner| inner.trim().to_string())
        .ok_or_else(|| IdentityError::InvalidParam(format!("info must be <URI>, got {s:?}")))
}

/// Strip surrounding double quotes from a parameter value if present.
fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}
