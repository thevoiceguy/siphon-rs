// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Errors for Identity-header / PASSporT parsing.

use std::fmt;

/// Failure modes when parsing an RFC 8224 `Identity` header or the
/// RFC 8225 PASSporT it carries.
///
/// Parsing errors are kept distinct from (future) *verification* failures:
/// a header that parses cleanly but fails signature/cert checks is a
/// verification outcome, not an `IdentityError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The header value exceeded the configured size limit (DoS guard).
    HeaderTooLong { max: usize, actual: usize },
    /// The header value was empty or had no PASSporT token before the
    /// first `;` parameter.
    EmptyToken,
    /// The PASSporT was not a 3-part compact JWS (`header.payload.sig`).
    MalformedJws { parts: usize },
    /// A base64url segment failed to decode.
    Base64(String),
    /// A decoded segment was not valid JSON.
    Json(String),
    /// A required field was absent (e.g. `x5u` in the protected header).
    MissingField(&'static str),
    /// A field held a value outside its allowed set (e.g. `attest` not
    /// one of A/B/C).
    InvalidField { field: &'static str, value: String },
    /// A header parameter was malformed (e.g. `info` without `<…>`).
    InvalidParam(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooLong { max, actual } => {
                write!(f, "Identity header too long (max {max}, got {actual})")
            }
            Self::EmptyToken => write!(f, "Identity header has no PASSporT token"),
            Self::MalformedJws { parts } => {
                write!(
                    f,
                    "PASSporT is not a 3-part compact JWS (got {parts} parts)"
                )
            }
            Self::Base64(msg) => write!(f, "base64url decode failed: {msg}"),
            Self::Json(msg) => write!(f, "PASSporT JSON decode failed: {msg}"),
            Self::MissingField(field) => write!(f, "PASSporT missing required field: {field}"),
            Self::InvalidField { field, value } => {
                write!(f, "PASSporT field {field} has invalid value: {value:?}")
            }
            Self::InvalidParam(msg) => write!(f, "Identity header parameter invalid: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {}
