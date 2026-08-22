// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 8225 / SHAKEN PASSporT **signing** (feature `sign`).
//!
//! The complement to [`crate::Passport::verify_signature`]: build a SHAKEN
//! PASSporT (ATIS-1000074) from a claim set, sign it ES256, and produce the
//! compact-JWS token and the RFC 8224 `Identity` header value an
//! authenticating provider puts on an outbound INVITE.
//!
//! This is a **provider-side** primitive. Whether a given deployment is
//! *entitled* to assert a number — the SPC token / Service Provider Code and
//! the STI certificate its `x5u` points at — is an operating-authority
//! question this crate does not decide; it signs what it is told to sign with
//! the key it is given. A gateway that is not an authorized provider MUST NOT
//! present a self-signed PASSporT as attestation.
//!
//! Round-trips exactly through [`crate::Passport::decode`] +
//! `verify_signature`: the header and payload are serialized to canonical
//! JSON, base64url-joined as the signing input, ES256-signed to the 64-byte
//! `r ‖ s` JOSE form, and appended — the same three-segment shape the
//! decoder consumes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SecureRandom;
use ring::signature::EcdsaKeyPair;
use serde::Serialize;

use crate::passport::AttestationLevel;

/// Why signing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// A claim required by the SHAKEN profile was not supplied.
    MissingField(&'static str),
    /// JSON serialization of the header or claims failed.
    Json(String),
    /// The ECDSA signing operation failed (bad key, RNG failure).
    Signing(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required PASSporT field {field:?}"),
            Self::Json(msg) => write!(f, "PASSporT JSON serialization failed: {msg}"),
            Self::Signing(msg) => write!(f, "ES256 signing failed: {msg}"),
        }
    }
}

impl std::error::Error for SignError {}

/// The claim set for a SHAKEN PASSporT to sign.
#[derive(Debug, Clone)]
pub struct PassportParams {
    /// URI of the signing certificate (`x5u`); the verifier fetches and
    /// chain-validates it against the STI-PA anchors.
    pub x5u: String,
    /// Attestation level the provider vouches (A/B/C).
    pub attest: AttestationLevel,
    /// Originating telephone number (`orig.tn`), E.164.
    pub orig_tn: String,
    /// Destination telephone number(s) (`dest.tn`); at least one required.
    pub dest_tns: Vec<String>,
    /// Issued-at (`iat`) unix timestamp.
    pub iat: i64,
    /// SHAKEN origination identifier (`origid`), a UUID traceback handle.
    pub origid: Option<String>,
}

#[derive(Serialize)]
struct SignHeader<'a> {
    alg: &'a str,
    ppt: &'a str,
    typ: &'a str,
    x5u: &'a str,
}

#[derive(Serialize)]
struct SignClaims<'a> {
    attest: &'a str,
    dest: Dest<'a>,
    iat: i64,
    orig: Orig<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origid: Option<&'a str>,
}

#[derive(Serialize)]
struct Orig<'a> {
    tn: &'a str,
}

#[derive(Serialize)]
struct Dest<'a> {
    tn: &'a [String],
}

/// A signed PASSporT: the compact-JWS token and the parameters needed to
/// assemble the RFC 8224 `Identity` header.
#[derive(Debug, Clone)]
pub struct SignedPassport {
    /// The compact JWS: `base64url(header).base64url(payload).base64url(sig)`.
    pub token: String,
    /// The `x5u` the header carries (also the header's `info` URI).
    pub x5u: String,
}

impl SignedPassport {
    /// The full RFC 8224 `Identity` header *value* (without the `Identity:`
    /// name): `<token>;info=<x5u>;alg=ES256;ppt=shaken`.
    pub fn identity_header_value(&self) -> String {
        format!("{};info=<{}>;alg=ES256;ppt=shaken", self.token, self.x5u)
    }
}

/// Sign a SHAKEN PASSporT with an ES256 (`EcdsaKeyPair`, P-256) key.
///
/// The key MUST be the private key of the certificate `params.x5u` points at;
/// the RNG is used for ECDSA's per-signature nonce. The returned token
/// verifies through [`crate::Passport::decode`] + `verify_signature` against
/// that certificate's public key.
pub fn sign(
    params: &PassportParams,
    key: &EcdsaKeyPair,
    rng: &dyn SecureRandom,
) -> Result<SignedPassport, SignError> {
    if params.dest_tns.is_empty() {
        return Err(SignError::MissingField("dest.tn"));
    }
    if params.orig_tn.is_empty() {
        return Err(SignError::MissingField("orig.tn"));
    }
    let header = SignHeader {
        alg: "ES256",
        ppt: "shaken",
        typ: "passport",
        x5u: &params.x5u,
    };
    let claims = SignClaims {
        attest: params.attest.as_str(),
        dest: Dest {
            tn: &params.dest_tns,
        },
        iat: params.iat,
        orig: Orig {
            tn: &params.orig_tn,
        },
        origid: params.origid.as_deref(),
    };
    let header_json = serde_json::to_vec(&header).map_err(|e| SignError::Json(e.to_string()))?;
    let claims_json = serde_json::to_vec(&claims).map_err(|e| SignError::Json(e.to_string()))?;
    let p_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let c_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

    let mut signing_input = Vec::with_capacity(p_b64.len() + 1 + c_b64.len());
    signing_input.extend_from_slice(p_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(c_b64.as_bytes());

    let sig = key
        .sign(rng, &signing_input)
        .map_err(|_| SignError::Signing("ECDSA sign failed".to_string()))?;
    let s_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Ok(SignedPassport {
        token: format!("{p_b64}.{c_b64}.{s_b64}"),
        x5u: params.x5u.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Passport;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn keypair(rng: &SystemRandom) -> EcdsaKeyPair {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng).unwrap()
    }

    #[test]
    fn sign_then_decode_and_verify_round_trips() {
        let rng = SystemRandom::new();
        let key = keypair(&rng);
        let params = PassportParams {
            x5u: "https://cert.example.org/sti.crt".to_string(),
            attest: AttestationLevel::A,
            orig_tn: "+12155551212".to_string(),
            dest_tns: vec!["+13035551234".to_string()],
            iat: 1_760_000_000,
            origid: Some("d5b8f9a0-0000-4000-8000-000000000000".to_string()),
        };
        let signed = sign(&params, &key, &rng).unwrap();

        // Decodes to the claims we signed.
        let pass = Passport::decode(&signed.token).unwrap();
        assert_eq!(pass.header.alg, "ES256");
        assert_eq!(pass.header.ppt.as_deref(), Some("shaken"));
        assert_eq!(pass.header.x5u, params.x5u);
        assert_eq!(pass.claims.attest, Some(AttestationLevel::A));
        assert_eq!(pass.claims.orig_tn.as_deref(), Some("+12155551212"));
        assert_eq!(pass.claims.dest_tns, vec!["+13035551234".to_string()]);
        assert_eq!(pass.claims.iat, Some(1_760_000_000));
        assert_eq!(
            pass.claims.origid.as_deref(),
            Some("d5b8f9a0-0000-4000-8000-000000000000")
        );

        // Verifies under the signing key's public point.
        let pub_sec1 = key.public_key().as_ref();
        pass.verify_signature(pub_sec1).unwrap();

        // A different key does not verify.
        let other = keypair(&rng);
        assert!(pass.verify_signature(other.public_key().as_ref()).is_err());
    }

    #[test]
    fn identity_header_value_is_wellformed() {
        let rng = SystemRandom::new();
        let key = keypair(&rng);
        let signed = sign(
            &PassportParams {
                x5u: "https://cert.example.org/sti.crt".to_string(),
                attest: AttestationLevel::B,
                orig_tn: "+12155551212".to_string(),
                dest_tns: vec!["+13035551234".to_string()],
                iat: 1_760_000_000,
                origid: None,
            },
            &key,
            &rng,
        )
        .unwrap();
        let value = signed.identity_header_value();
        assert!(value.contains(";info=<https://cert.example.org/sti.crt>"));
        assert!(value.ends_with(";alg=ES256;ppt=shaken"));
        // The header value parses back through the RFC 8224 reader.
        let parsed = crate::IdentityHeader::parse(&value).unwrap();
        assert_eq!(parsed.passport.claims.attest, Some(AttestationLevel::B));
    }

    #[test]
    fn missing_dest_is_rejected() {
        let rng = SystemRandom::new();
        let key = keypair(&rng);
        let err = sign(
            &PassportParams {
                x5u: "https://c/x".to_string(),
                attest: AttestationLevel::A,
                orig_tn: "+1".to_string(),
                dest_tns: vec![],
                iat: 0,
                origid: None,
            },
            &key,
            &rng,
        )
        .unwrap_err();
        assert_eq!(err, SignError::MissingField("dest.tn"));
    }
}
