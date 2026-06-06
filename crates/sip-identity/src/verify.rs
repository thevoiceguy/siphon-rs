// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! ES256 signature verification for a decoded PASSporT.
//!
//! SHAKEN (ATIS-1000074) mandates `alg = ES256` — ECDSA on NIST P-256 with
//! SHA-256, and the JOSE *fixed* signature encoding (the 64-byte `r ‖ s`
//! concatenation, not ASN.1 DER). [`ring`]'s `ECDSA_P256_SHA256_FIXED`
//! consumes exactly that, over the signing input
//! [`Passport`](crate::Passport) preserved verbatim at decode time.
//!
//! This verifies the *signature*; obtaining a trustworthy public key —
//! fetching the `x5u` certificate and validating its chain to a STI-PA
//! trust anchor — is the next layer. Callers pass the verifying key as the
//! uncompressed SEC1 point extracted from the signing certificate's
//! SubjectPublicKeyInfo.

use std::fmt;

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

use crate::passport::Passport;

/// Length of an uncompressed SEC1 P-256 public key: `0x04 ‖ X(32) ‖ Y(32)`.
const P256_UNCOMPRESSED_LEN: usize = 65;

/// Why ES256 verification failed. Distinct from
/// [`IdentityError`](crate::IdentityError) (parsing) — a PASSporT can parse
/// cleanly yet fail to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The PASSporT's `alg` is not `ES256` (the only algorithm SHAKEN
    /// permits). We refuse to guess at another algorithm.
    UnsupportedAlg(String),
    /// The supplied public key is not a 65-byte uncompressed P-256 point.
    MalformedKey { len: usize },
    /// The signature did not verify against the key over the signing input.
    /// `ring` does not distinguish "bad signature" from "key didn't match",
    /// so both land here — for a verifier the meaning is the same: do not
    /// trust this PASSporT.
    SignatureInvalid,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlg(alg) => {
                write!(
                    f,
                    "unsupported PASSporT alg {alg:?} (SHAKEN requires ES256)"
                )
            }
            Self::MalformedKey { len } => write!(
                f,
                "public key is not a 65-byte uncompressed P-256 point (got {len} bytes)"
            ),
            Self::SignatureInvalid => write!(f, "ES256 signature did not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl Passport {
    /// Verify this PASSporT's ES256 signature against `public_key_sec1` —
    /// the signing certificate's public key as an uncompressed SEC1 P-256
    /// point (`0x04 ‖ X ‖ Y`, 65 bytes).
    ///
    /// Returns `Ok(())` only when `alg == ES256`, the key is a well-formed
    /// P-256 point, and the signature verifies over the exact signing input
    /// the issuer signed. This says nothing about whether the *certificate*
    /// is trustworthy — that's the caller's chain-validation step.
    pub fn verify_signature(&self, public_key_sec1: &[u8]) -> Result<(), VerifyError> {
        if self.header.alg != "ES256" {
            return Err(VerifyError::UnsupportedAlg(self.header.alg.clone()));
        }
        if public_key_sec1.len() != P256_UNCOMPRESSED_LEN || public_key_sec1[0] != 0x04 {
            return Err(VerifyError::MalformedKey {
                len: public_key_sec1.len(),
            });
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_sec1)
            .verify(&self.signing_input, &self.signature)
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    struct SignedToken {
        token: String,
        public_key: Vec<u8>,
    }

    /// Build a real ES256-signed PASSporT token for `header_json` /
    /// `payload_json`, returning the token and the matching public key.
    fn sign(header_json: &str, payload_json: &str) -> SignedToken {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let signing_input = format!(
            "{}.{}",
            b64(header_json.as_bytes()),
            b64(payload_json.as_bytes())
        );
        let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
        SignedToken {
            token: format!("{signing_input}.{}", b64(sig.as_ref())),
            public_key: key_pair.public_key().as_ref().to_vec(),
        }
    }

    const HEADER: &str =
        r#"{"alg":"ES256","typ":"passport","ppt":"shaken","x5u":"https://c.example/c.crt"}"#;
    const PAYLOAD: &str = r#"{"attest":"A","dest":{"tn":["+12155551213"]},"iat":1443208345,"orig":{"tn":"+12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#;

    #[test]
    fn valid_signature_verifies() {
        let s = sign(HEADER, PAYLOAD);
        let p = Passport::decode(&s.token).unwrap();
        assert_eq!(p.verify_signature(&s.public_key), Ok(()));
    }

    #[test]
    fn tampered_payload_fails() {
        let s = sign(HEADER, PAYLOAD);
        // Re-assemble the token with a different payload (attest C) but the
        // original signature → signing input no longer matches.
        let tampered_payload = PAYLOAD.replace(r#""attest":"A""#, r#""attest":"C""#);
        let (hdr_b64, rest) = s.token.split_once('.').unwrap();
        let sig_b64 = rest.rsplit_once('.').unwrap().1;
        let forged = format!("{hdr_b64}.{}.{sig_b64}", b64(tampered_payload.as_bytes()));
        let p = Passport::decode(&forged).unwrap();
        assert_eq!(
            p.verify_signature(&s.public_key),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let s = sign(HEADER, PAYLOAD);
        let other = sign(HEADER, PAYLOAD); // different keypair
        let p = Passport::decode(&s.token).unwrap();
        assert_eq!(
            p.verify_signature(&other.public_key),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn non_es256_alg_rejected() {
        let header = r#"{"alg":"RS256","ppt":"shaken","x5u":"https://c/c.crt"}"#;
        let s = sign(header, PAYLOAD);
        let p = Passport::decode(&s.token).unwrap();
        assert_eq!(
            p.verify_signature(&s.public_key),
            Err(VerifyError::UnsupportedAlg("RS256".into()))
        );
    }

    #[test]
    fn malformed_key_rejected() {
        let s = sign(HEADER, PAYLOAD);
        let p = Passport::decode(&s.token).unwrap();
        // Truncated key.
        assert_eq!(
            p.verify_signature(&s.public_key[..40]),
            Err(VerifyError::MalformedKey { len: 40 })
        );
        // Right length, wrong prefix (compressed-point tag).
        let mut bad = s.public_key.clone();
        bad[0] = 0x02;
        assert_eq!(
            p.verify_signature(&bad),
            Err(VerifyError::MalformedKey { len: 65 })
        );
    }
}
