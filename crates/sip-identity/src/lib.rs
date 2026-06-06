// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! STIR/SHAKEN caller identity for siphon-rs.
//!
//! This crate handles the **caller-identity** side of SIP: the RFC 8224
//! `Identity` header and the RFC 8225 PASSporT it carries, in the SHAKEN
//! (ATIS-1000074) profile. The consuming application (e.g. SiphonAI) reads
//! the `Identity` header off an inbound INVITE via
//! [`sip_core::Headers::get`], hands the value to [`IdentityHeader::parse`],
//! and surfaces / acts on the result.
//!
//! ## Scope of this revision
//!
//! **Parsing + ES256 verification + X.509 chain validation.** This decodes
//! the header + PASSporT, verifies the ES256 signature
//! ([`Passport::verify_signature`] against a supplied key), and validates
//! the signing certificate chains to a STI-PA trust anchor while verifying
//! the signature under that validated cert ([`Passport::verify_with_chain`]).
//!
//! Still **not** here:
//!
//! - fetching the `x5u` certificate (async network I/O + TTL cache — owned
//!   by the application layer), and
//! - the TN-Authorization-List ↔ `orig` authorization check and `iat`
//!   freshness (higher-level claim checks).
//!
//! A parsed-but-unverified [`IdentityHeader`] asserts only
//! *well-formedness*; treat attestation as untrusted until
//! [`Passport::verify_with_chain`] (or signature + caller-side chain) passes.
//!
//! ```
//! use sip_identity::{IdentityHeader, AttestationLevel};
//! # use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
//! # let hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"passport","ppt":"shaken","x5u":"https://c.example/c.crt"}"#);
//! # let pld = URL_SAFE_NO_PAD.encode(br#"{"attest":"A","dest":{"tn":["+12155551213"]},"iat":1443208345,"orig":{"tn":"+12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#);
//! # let sig = URL_SAFE_NO_PAD.encode(&[1u8; 64]);
//! # let value = format!("{hdr}.{pld}.{sig};info=<https://c.example/c.crt>;alg=ES256;ppt=shaken");
//! let parsed = IdentityHeader::parse(&value).unwrap();
//! assert_eq!(parsed.passport.claims.attest, Some(AttestationLevel::A));
//! assert_eq!(parsed.passport.claims.orig_tn.as_deref(), Some("+12155551212"));
//! ```

mod chain;
mod error;
mod header;
mod passport;
mod verify;

pub use error::IdentityError;
pub use header::IdentityHeader;
pub use passport::{AttestationLevel, Passport, PassportClaims, PassportHeader};
pub use verify::VerifyError;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Build a compact-JWS token from raw header/payload JSON + a dummy
    /// 64-byte signature.
    fn token(header_json: &str, payload_json: &str) -> String {
        format!(
            "{}.{}.{}",
            b64(header_json.as_bytes()),
            b64(payload_json.as_bytes()),
            b64(&[0x01u8; 64])
        )
    }

    const HEADER: &str =
        r#"{"alg":"ES256","typ":"passport","ppt":"shaken","x5u":"https://cert.example.org/c.crt"}"#;
    const PAYLOAD: &str = r#"{"attest":"A","dest":{"tn":["+12155551213"]},"iat":1443208345,"orig":{"tn":"+12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#;

    #[test]
    fn passport_decodes_shaken_claims() {
        let p = Passport::decode(&token(HEADER, PAYLOAD)).unwrap();
        assert_eq!(p.header.alg, "ES256");
        assert_eq!(p.header.typ.as_deref(), Some("passport"));
        assert_eq!(p.header.ppt.as_deref(), Some("shaken"));
        assert_eq!(p.header.x5u, "https://cert.example.org/c.crt");
        assert_eq!(p.claims.attest, Some(AttestationLevel::A));
        assert_eq!(p.claims.orig_tn.as_deref(), Some("+12155551212"));
        assert_eq!(p.claims.dest_tns, vec!["+12155551213".to_string()]);
        assert_eq!(p.claims.iat, Some(1443208345));
        assert_eq!(
            p.claims.origid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426655440000")
        );
        assert_eq!(p.signature.len(), 64);
    }

    #[test]
    fn signing_input_is_first_two_segments_verbatim() {
        let t = token(HEADER, PAYLOAD);
        let p = Passport::decode(&t).unwrap();
        let two_segments = t.rsplit_once('.').unwrap().0; // strip the signature
        assert_eq!(p.signing_input, two_segments.as_bytes());
    }

    #[test]
    fn identity_header_parses_token_and_params() {
        let value = format!(
            "{};info=<https://cert.example.org/c.crt>;alg=ES256;ppt=shaken",
            token(HEADER, PAYLOAD)
        );
        let h = IdentityHeader::parse(&value).unwrap();
        assert_eq!(h.info.as_deref(), Some("https://cert.example.org/c.crt"));
        assert_eq!(h.alg.as_deref(), Some("ES256"));
        assert_eq!(h.ppt.as_deref(), Some("shaken"));
        assert_eq!(h.passport.claims.attest, Some(AttestationLevel::A));
    }

    #[test]
    fn tolerates_lws_and_case_insensitive_params() {
        let value = format!(
            "{} ; INFO=<https://c.example/c.crt> ; Alg=ES256 ; ppt=shaken",
            token(HEADER, PAYLOAD)
        );
        let h = IdentityHeader::parse(&value).unwrap();
        assert_eq!(h.info.as_deref(), Some("https://c.example/c.crt"));
        assert_eq!(h.alg.as_deref(), Some("ES256"));
    }

    #[test]
    fn attestation_levels_parse_and_reject() {
        assert_eq!(AttestationLevel::parse("A").unwrap(), AttestationLevel::A);
        assert_eq!(AttestationLevel::parse("B").unwrap(), AttestationLevel::B);
        assert_eq!(AttestationLevel::parse("C").unwrap(), AttestationLevel::C);
        assert!(matches!(
            AttestationLevel::parse("D"),
            Err(IdentityError::InvalidField {
                field: "attest",
                ..
            })
        ));
    }

    #[test]
    fn rejects_non_three_part_jws() {
        let two = format!("{}.{}", b64(HEADER.as_bytes()), b64(PAYLOAD.as_bytes()));
        assert_eq!(
            Passport::decode(&two),
            Err(IdentityError::MalformedJws { parts: 2 })
        );
    }

    #[test]
    fn requires_x5u() {
        let no_x5u = r#"{"alg":"ES256","typ":"passport","ppt":"shaken"}"#;
        assert_eq!(
            Passport::decode(&token(no_x5u, PAYLOAD)),
            Err(IdentityError::MissingField("x5u"))
        );
    }

    #[test]
    fn info_requires_angle_brackets() {
        let value = format!(
            "{};info=https://cert.example.org/c.crt;alg=ES256",
            token(HEADER, PAYLOAD)
        );
        assert!(matches!(
            IdentityHeader::parse(&value),
            Err(IdentityError::InvalidParam(_))
        ));
    }

    #[test]
    fn empty_token_rejected() {
        assert_eq!(
            IdentityHeader::parse(";info=<https://x/y>"),
            Err(IdentityError::EmptyToken)
        );
    }

    #[test]
    fn oversized_header_rejected() {
        let value = "a".repeat(9000);
        assert!(matches!(
            IdentityHeader::parse(&value),
            Err(IdentityError::HeaderTooLong { max: 8192, .. })
        ));
    }

    #[test]
    fn bad_base64_segment_rejected() {
        // '!' is not a base64url character.
        let bad = format!("{}.!!!.{}", b64(HEADER.as_bytes()), b64(&[1u8; 64]));
        assert!(matches!(
            Passport::decode(&bad),
            Err(IdentityError::Base64(_))
        ));
    }

    #[test]
    fn absent_optional_claims_default_cleanly() {
        // Minimal valid PASSporT: only alg + x5u in header, empty claims.
        let p =
            Passport::decode(&token(r#"{"alg":"ES256","x5u":"https://c/c.crt"}"#, "{}")).unwrap();
        assert_eq!(p.claims.attest, None);
        assert_eq!(p.claims.orig_tn, None);
        assert!(p.claims.dest_tns.is_empty());
        assert_eq!(p.claims.iat, None);
        assert_eq!(p.header.typ, None);
    }
}
