// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! X.509 certificate-chain validation for STIR/SHAKEN signing certs.
//!
//! Verifying a PASSporT signature ([`Passport::verify_signature`]) proves a
//! key signed the claims; it says nothing about *whose* key. This module
//! closes that gap: it validates that the signing certificate chains to a
//! configured STI-PA trust anchor and then verifies the PASSporT signature
//! using the public key from that validated certificate — so a passing
//! result means "an authority trusted by our anchors vouches for this key,
//! and that key signed these claims."
//!
//! ## What is and isn't checked
//!
//! - **Checked:** DER well-formedness, chain to a trust anchor, validity
//!   window (via the caller-supplied `now`), and the ES256 PASSporT
//!   signature under the end-entity cert.
//! - **Not checked here:** EKU is *not* constrained — RFC 8226 STIR
//!   certificates are profiled by the TN Authorization List extension, not
//!   an extended-key-usage, so requiring (say) `serverAuth` would wrongly
//!   reject valid SHAKEN certs. Revocation (CRL/OCSP) is not consulted.
//!   The TN Authorization List ↔ `orig` authorization check (ATIS-1000080
//!   §6.4.1) and `iat` freshness are separate, higher-level steps.
//!
//! Certificate *fetching* (`x5u`) is deliberately not here: it is async
//! network I/O with a TTL cache, owned by the application layer that has
//! the runtime, the cache lifecycle, and the cache-TTL config.

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{
    anchor_from_trusted_cert, EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter,
};

use crate::passport::Passport;
use crate::verify::VerifyError;

/// Accept any (or no) Extended Key Usage. RFC 8226 STIR certificates carry
/// no mandated EKU, so we impose none — chain + TN-authorization (elsewhere)
/// are what bound the certificate's authority.
struct AnyEku;

impl ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, _ekus: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

impl Passport {
    /// Validate the signing certificate chain and verify this PASSporT's
    /// ES256 signature under the end-entity certificate.
    ///
    /// - `end_entity_der` — the signing (leaf) certificate, DER.
    /// - `intermediates` — any intermediate CA certificates, DER, in any order.
    /// - `trust_anchor_ders` — the STI-PA root(s), DER (e.g. loaded from
    ///   `contrib/sti-pa-roots.pem`).
    /// - `now` — current time, for the certificate validity window.
    ///
    /// Returns `Ok(())` only when the chain validates to an anchor at `now`
    /// **and** the PASSporT signature verifies under the leaf's key.
    pub fn verify_with_chain(
        &self,
        end_entity_der: &[u8],
        intermediates: &[&[u8]],
        trust_anchor_ders: &[&[u8]],
        now: UnixTime,
    ) -> Result<(), VerifyError> {
        if self.header.alg != "ES256" {
            return Err(VerifyError::UnsupportedAlg(self.header.alg.clone()));
        }

        let ee_der = CertificateDer::from(end_entity_der);
        let ee = EndEntityCert::try_from(&ee_der)
            .map_err(|e| VerifyError::CertParse(format!("end-entity: {e}")))?;

        // Trust anchors borrow their backing cert DERs, so both Vecs must
        // outlive the verify call below.
        let anchor_certs: Vec<CertificateDer> = trust_anchor_ders
            .iter()
            .map(|d| CertificateDer::from(*d))
            .collect();
        let anchors = anchor_certs
            .iter()
            .map(|c| anchor_from_trusted_cert(c))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VerifyError::CertParse(format!("trust anchor: {e}")))?;

        let intermediate_certs: Vec<CertificateDer> = intermediates
            .iter()
            .map(|d| CertificateDer::from(*d))
            .collect();

        // Accept the full set of supported cert-signature algorithms in the
        // chain (the leaf's PASSporT signature is separately pinned to ES256
        // below). SHAKEN leaves are ECDSA P-256; upstream CAs vary.
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediate_certs,
            now,
            AnyEku,
            None, // no revocation (CRL/OCSP) in this revision
            None, // no extra path constraints
        )
        .map_err(|e| VerifyError::ChainInvalid(e.to_string()))?;

        // The cert is trusted — now confirm it actually signed this PASSporT.
        // webpki's ECDSA verifier expects the ASN.1/DER signature encoding,
        // but a JOSE/JWS ES256 signature is the fixed 64-byte `r ‖ s` form,
        // so convert before handing it over.
        let der_sig = jose_es256_to_der(&self.signature).ok_or(VerifyError::SignatureInvalid)?;
        ee.verify_signature(
            webpki::ring::ECDSA_P256_SHA256,
            &self.signing_input,
            &der_sig,
        )
        .map_err(|_| VerifyError::SignatureInvalid)
    }
}

/// Convert a JOSE/JWS ES256 signature (fixed 64-byte `r ‖ s`) into the
/// ASN.1 DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` that
/// X.509 verifiers (webpki) expect. Returns `None` if the input isn't 64
/// bytes. The two 32-byte halves encode to at most 35 bytes each, so the
/// SEQUENCE body stays well under 128 bytes (single-byte DER lengths).
fn jose_es256_to_der(sig: &[u8]) -> Option<Vec<u8>> {
    if sig.len() != 64 {
        return None;
    }
    let mut body = der_unsigned_integer(&sig[..32]);
    body.extend(der_unsigned_integer(&sig[32..]));
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x30); // SEQUENCE
    out.push(body.len() as u8);
    out.extend(body);
    Some(out)
}

/// DER-encode a big-endian unsigned integer as an ASN.1 `INTEGER`: strip
/// leading zero bytes, then prepend `0x00` if the high bit is set (so it's
/// not misread as negative).
fn der_unsigned_integer(be: &[u8]) -> Vec<u8> {
    let mut v = be;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let needs_pad = v[0] & 0x80 != 0;
    let len = v.len() + usize::from(needs_pad);
    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02); // INTEGER
    out.push(len as u8);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rcgen::{CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use rustls_pki_types::UnixTime;
    use time::{Duration, OffsetDateTime};

    const PAYLOAD: &str = r#"{"attest":"A","dest":{"tn":["+12155551213"]},"iat":1443208345,"orig":{"tn":"+12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#;

    /// A throwaway CA + leaf, plus a PASSporT token signed by the leaf's key.
    struct Fixture {
        ca_der: Vec<u8>,
        leaf_der: Vec<u8>,
        token: String,
        /// Cert validity window: not_before .. not_after (unix seconds).
        not_before: i64,
        not_after: i64,
    }

    fn fixture() -> Fixture {
        // Pin a deterministic validity window (≈2024 → +1 year).
        let not_before = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let not_after = not_before + Duration::days(365);

        // CA (self-signed).
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test STI-PA Root".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        let ca = ca_params.self_signed(&ca_key).unwrap();

        // Leaf, signed by the CA.
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["sti.example.com".into()]).unwrap();
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        // Sign a PASSporT with the leaf's private key (PKCS8 → ring).
        let pkcs8 = leaf_key.serialize_der();
        let rng = SystemRandom::new();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).unwrap();
        let header = r#"{"alg":"ES256","typ":"passport","ppt":"shaken","x5u":"https://c/c.crt"}"#;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.as_bytes()),
            URL_SAFE_NO_PAD.encode(PAYLOAD.as_bytes())
        );
        let sig = signer.sign(&rng, signing_input.as_bytes()).unwrap();
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));

        Fixture {
            ca_der: ca.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            token,
            not_before: not_before.unix_timestamp(),
            not_after: not_after.unix_timestamp(),
        }
    }

    fn at(secs: i64) -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs as u64))
    }

    #[test]
    fn valid_chain_and_signature() {
        let f = fixture();
        let p = Passport::decode(&f.token).unwrap();
        let now = at((f.not_before + f.not_after) / 2);
        assert_eq!(
            p.verify_with_chain(&f.leaf_der, &[], &[&f.ca_der], now),
            Ok(())
        );
    }

    #[test]
    fn untrusted_anchor_rejected() {
        let f = fixture();
        let other = fixture(); // unrelated CA
        let p = Passport::decode(&f.token).unwrap();
        let now = at((f.not_before + f.not_after) / 2);
        // Leaf from `f`, but only `other`'s CA is trusted.
        assert!(matches!(
            p.verify_with_chain(&f.leaf_der, &[], &[&other.ca_der], now),
            Err(VerifyError::ChainInvalid(_))
        ));
    }

    #[test]
    fn expired_cert_rejected() {
        let f = fixture();
        let p = Passport::decode(&f.token).unwrap();
        let now = at(f.not_after + 86_400); // a day after expiry
        assert!(matches!(
            p.verify_with_chain(&f.leaf_der, &[], &[&f.ca_der], now),
            Err(VerifyError::ChainInvalid(_))
        ));
    }

    #[test]
    fn tampered_payload_fails_signature_even_with_valid_chain() {
        let f = fixture();
        // Swap the payload (valid chain, but signature no longer matches).
        let tampered = PAYLOAD.replace(r#""attest":"A""#, r#""attest":"C""#);
        let (hdr_b64, rest) = f.token.split_once('.').unwrap();
        let sig_b64 = rest.rsplit_once('.').unwrap().1;
        let forged = format!(
            "{hdr_b64}.{}.{sig_b64}",
            URL_SAFE_NO_PAD.encode(tampered.as_bytes())
        );
        let p = Passport::decode(&forged).unwrap();
        let now = at((f.not_before + f.not_after) / 2);
        assert_eq!(
            p.verify_with_chain(&f.leaf_der, &[], &[&f.ca_der], now),
            Err(VerifyError::SignatureInvalid)
        );
    }
}
