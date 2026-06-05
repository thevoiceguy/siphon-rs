// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 8225 PASSporT decoding, with the SHAKEN (ATIS-1000074) claim set.
//!
//! A PASSporT is a JWS (RFC 7515) in compact serialization:
//! `base64url(protected) "." base64url(payload) "." base64url(signature)`.
//! This module decodes the three segments into typed values and preserves
//! the exact signing input + raw signature so a later verification step
//! (ES256 over the cert fetched from `x5u`) can run without re-parsing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::error::IdentityError;

/// SHAKEN attestation level (ATIS-1000074 §5.2.3). Indicates how much the
/// signing provider vouches for the calling number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationLevel {
    /// Full attestation — the provider authenticated the customer and
    /// confirmed their right to use the calling number.
    A,
    /// Partial attestation — the provider authenticated the call origin
    /// but cannot confirm the number is authorized.
    B,
    /// Gateway attestation — the provider authenticated where it received
    /// the call but nothing about its origin.
    C,
}

impl AttestationLevel {
    /// Parse the single-character `attest` claim value.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        match s {
            "A" => Ok(Self::A),
            "B" => Ok(Self::B),
            "C" => Ok(Self::C),
            other => Err(IdentityError::InvalidField {
                field: "attest",
                value: other.to_string(),
            }),
        }
    }

    /// The wire character (`"A"` / `"B"` / `"C"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
        }
    }
}

/// Decoded PASSporT protected header (RFC 8225 §3 + SHAKEN profile).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportHeader {
    /// Signature algorithm. SHAKEN mandates `ES256`.
    pub alg: String,
    /// Token type — `passport` per RFC 8225.
    pub typ: Option<String>,
    /// PASSporT extension type — `shaken` for SHAKEN.
    pub ppt: Option<String>,
    /// URI of the signing certificate (RFC 8225 §8). The verifier fetches
    /// and chain-validates this against the STI-PA trust anchors.
    pub x5u: String,
}

/// Decoded PASSporT claim set (RFC 8225 §5 + SHAKEN extensions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportClaims {
    /// SHAKEN attestation level, when present and valid.
    pub attest: Option<AttestationLevel>,
    /// Originating telephone number (`orig.tn`), in E.164-ish form.
    pub orig_tn: Option<String>,
    /// Destination telephone number(s) (`dest.tn`).
    pub dest_tns: Vec<String>,
    /// Issued-at (`iat`) unix timestamp; the verifier enforces freshness.
    pub iat: Option<i64>,
    /// SHAKEN origination identifier (`origid`), a UUID traceback handle.
    pub origid: Option<String>,
}

/// A decoded PASSporT plus the material needed to verify it later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passport {
    /// Decoded protected header.
    pub header: PassportHeader,
    /// Decoded claim set.
    pub claims: PassportClaims,
    /// Exact bytes the signature covers: ASCII
    /// `base64url(protected) "." base64url(payload)`. Held verbatim so
    /// verification signs over precisely what the issuer signed (any
    /// re-serialization could change byte-for-byte content).
    pub signing_input: Vec<u8>,
    /// Raw signature bytes (for ES256, the 64-byte `r ‖ s` JOSE form).
    pub signature: Vec<u8>,
}

// ── serde shapes (private; mapped into the public typed structs) ─────────

#[derive(Deserialize)]
struct RawHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    ppt: Option<String>,
    #[serde(default)]
    x5u: Option<String>,
}

#[derive(Deserialize)]
struct RawClaims {
    #[serde(default)]
    attest: Option<String>,
    #[serde(default)]
    orig: Option<Orig>,
    #[serde(default)]
    dest: Option<Dest>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    origid: Option<String>,
}

#[derive(Deserialize)]
struct Orig {
    #[serde(default)]
    tn: Option<String>,
}

#[derive(Deserialize)]
struct Dest {
    #[serde(default)]
    tn: Option<Vec<String>>,
}

impl Passport {
    /// Decode a compact-JWS PASSporT token (the part of the Identity
    /// header before its first `;` parameter). Validates structure and
    /// the SHAKEN-required fields, but does NOT verify the signature or
    /// fetch/validate the certificate — that is the verifier's job.
    pub fn decode(token: &str) -> Result<Self, IdentityError> {
        let mut parts = token.split('.');
        let (Some(p_b64), Some(c_b64), Some(s_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            // Recount for a precise error.
            let n = token.split('.').count();
            return Err(IdentityError::MalformedJws { parts: n });
        };

        let header_json = b64url(p_b64)?;
        let claims_json = b64url(c_b64)?;
        let signature = b64url(s_b64)?;

        let raw_header: RawHeader = serde_json::from_slice(&header_json)
            .map_err(|e| IdentityError::Json(format!("protected header: {e}")))?;
        let raw_claims: RawClaims = serde_json::from_slice(&claims_json)
            .map_err(|e| IdentityError::Json(format!("payload: {e}")))?;

        let x5u = raw_header.x5u.ok_or(IdentityError::MissingField("x5u"))?;

        let attest = match raw_claims.attest.as_deref() {
            Some(s) => Some(AttestationLevel::parse(s)?),
            None => None,
        };

        let header = PassportHeader {
            alg: raw_header.alg,
            typ: raw_header.typ,
            ppt: raw_header.ppt,
            x5u,
        };
        let claims = PassportClaims {
            attest,
            orig_tn: raw_claims.orig.and_then(|o| o.tn),
            dest_tns: raw_claims.dest.and_then(|d| d.tn).unwrap_or_default(),
            iat: raw_claims.iat,
            origid: raw_claims.origid,
        };

        // Signing input is the first two segments joined by '.', as ASCII.
        let mut signing_input = Vec::with_capacity(p_b64.len() + 1 + c_b64.len());
        signing_input.extend_from_slice(p_b64.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(c_b64.as_bytes());

        Ok(Self {
            header,
            claims,
            signing_input,
            signature,
        })
    }
}

fn b64url(s: &str) -> Result<Vec<u8>, IdentityError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| IdentityError::Base64(e.to_string()))
}
