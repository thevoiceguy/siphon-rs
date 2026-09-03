// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Verified peer certificate identity for TLS transports.
//!
//! When a TLS (or WSS) connection completes its handshake with a
//! certificate that rustls **verified** — a client certificate
//! chaining to the listener's client-CA bundle, or the server
//! certificate an outbound connection was dialed against — the
//! transport captures the leaf's identity fields once and attaches
//! them to every [`InboundPacket`](crate::InboundPacket) framed on
//! that connection. The transaction layer copies it onto the
//! `TransportContext`, so a transaction user can authorize a request
//! by *who the connection proved itself to be* rather than by
//! anything the SIP message claims about itself.
//!
//! The struct is a plain data holder. It deliberately carries no
//! policy: matching a SAN against an expected node id, deciding
//! whether a missing identity is fatal, and so on belong to the
//! application. Per RFC 5922 §7.1 a SIP identity in a certificate is
//! carried in `subjectAltName` as a `sip:` URI, a DNS name, or (as a
//! fallback) the subject Common Name — all three are exposed here.
//!
//! Presence is the verification signal: rustls only reports a peer
//! certificate it accepted, so a `Some(PeerIdentity)` on a packet
//! means the chain validated against the roots the connection was
//! configured with. A `None` on a TLS packet means the peer
//! presented nothing (the listener ran with
//! `ClientAuthMode::Optional` or no client auth at all).

use std::fmt;
use std::net::IpAddr;

/// Identity fields of a peer's verified leaf certificate.
///
/// Built by the transport after a successful handshake (see
/// [`PeerIdentity::from_der`], `tls` feature) or by hand via
/// [`PeerIdentity::builder`] in tests and non-TLS code paths.
/// Fields are private; use the accessors.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    subject: String,
    common_name: Option<String>,
    dns_names: Vec<String>,
    uri_names: Vec<String>,
    ip_names: Vec<IpAddr>,
    email_names: Vec<String>,
    fingerprint_sha256: [u8; 32],
    der: Vec<u8>,
}

impl PeerIdentity {
    /// Starts building an identity from its subject distinguished
    /// name (RFC 4514 string form, e.g. `CN=node-1,O=Example`).
    pub fn builder(subject: impl Into<String>) -> PeerIdentityBuilder {
        PeerIdentityBuilder {
            inner: PeerIdentity {
                subject: subject.into(),
                common_name: None,
                dns_names: Vec::new(),
                uri_names: Vec::new(),
                ip_names: Vec::new(),
                email_names: Vec::new(),
                fingerprint_sha256: [0; 32],
                der: Vec::new(),
            },
        }
    }

    /// Subject distinguished name in RFC 4514 string form.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// First `commonName` attribute of the subject, if any.
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// `dNSName` entries of the subjectAltName extension, in
    /// certificate order.
    pub fn dns_names(&self) -> &[String] {
        &self.dns_names
    }

    /// `uniformResourceIdentifier` entries of the subjectAltName
    /// extension (RFC 5922 §7.1 `sip:` URIs live here), in
    /// certificate order.
    pub fn uri_names(&self) -> &[String] {
        &self.uri_names
    }

    /// `iPAddress` entries of the subjectAltName extension.
    pub fn ip_names(&self) -> &[IpAddr] {
        &self.ip_names
    }

    /// `rfc822Name` entries of the subjectAltName extension.
    pub fn email_names(&self) -> &[String] {
        &self.email_names
    }

    /// SHA-256 digest of the leaf certificate's DER encoding — the
    /// value operators pin when they want "exactly this certificate"
    /// rather than "anything this CA signed".
    pub fn fingerprint_sha256(&self) -> &[u8; 32] {
        &self.fingerprint_sha256
    }

    /// [`fingerprint_sha256`](Self::fingerprint_sha256) as lowercase
    /// hex without separators.
    pub fn fingerprint_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.fingerprint_sha256 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    /// The leaf certificate, DER-encoded, for consumers that need
    /// something this struct does not surface (custom extensions,
    /// issuer, validity).
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// `true` when `name` equals one of the DNS SANs, compared
    /// ASCII-case-insensitively (DNS names are case-insensitive; RFC
    /// 4343). No wildcard expansion — a `*.example.com` SAN only
    /// matches the literal string `*.example.com`.
    pub fn has_dns_name(&self, name: &str) -> bool {
        self.dns_names.iter().any(|n| n.eq_ignore_ascii_case(name))
    }

    /// `true` when `uri` equals one of the URI SANs byte-for-byte.
    /// URI comparison rules are scheme-specific (RFC 3261 §19.1.4 for
    /// `sip:`), so anything looser than exact equality is the
    /// caller's decision.
    pub fn has_uri_name(&self, uri: &str) -> bool {
        self.uri_names.iter().any(|n| n == uri)
    }

    /// Every name the certificate asserts, for logging and for
    /// callers matching one expected id against "any SAN or the CN":
    /// URI SANs, then DNS SANs, then IP SANs, then e-mail SANs, then
    /// the Common Name if it is not already present.
    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(
            self.uri_names.len() + self.dns_names.len() + self.ip_names.len() + 1,
        );
        out.extend(self.uri_names.iter().cloned());
        out.extend(self.dns_names.iter().cloned());
        out.extend(self.ip_names.iter().map(|ip| ip.to_string()));
        out.extend(self.email_names.iter().cloned());
        if let Some(cn) = &self.common_name {
            if !out.iter().any(|n| n == cn) {
                out.push(cn.clone());
            }
        }
        out
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The DER blob is hundreds of opaque bytes; the fingerprint
        // identifies the certificate just as well in a log line.
        f.debug_struct("PeerIdentity")
            .field("subject", &self.subject)
            .field("common_name", &self.common_name)
            .field("dns_names", &self.dns_names)
            .field("uri_names", &self.uri_names)
            .field("ip_names", &self.ip_names)
            .field("email_names", &self.email_names)
            .field("fingerprint_sha256", &self.fingerprint_hex())
            .finish()
    }
}

impl fmt::Display for PeerIdentity {
    /// `subject` followed by the SANs, e.g.
    /// `CN=node-1,O=Example san=[sip:node-1@example.com, node-1.example.com]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.subject)?;
        let mut sans = self.uri_names.to_vec();
        sans.extend(self.dns_names.iter().cloned());
        sans.extend(self.ip_names.iter().map(|ip| ip.to_string()));
        sans.extend(self.email_names.iter().cloned());
        if !sans.is_empty() {
            write!(f, " san=[{}]", sans.join(", "))?;
        }
        Ok(())
    }
}

/// Builder returned by [`PeerIdentity::builder`].
#[derive(Debug, Clone)]
pub struct PeerIdentityBuilder {
    inner: PeerIdentity,
}

impl PeerIdentityBuilder {
    /// Sets the subject Common Name.
    pub fn common_name(mut self, cn: impl Into<String>) -> Self {
        self.inner.common_name = Some(cn.into());
        self
    }

    /// Appends a `dNSName` SAN.
    pub fn dns_name(mut self, name: impl Into<String>) -> Self {
        self.inner.dns_names.push(name.into());
        self
    }

    /// Appends a URI SAN.
    pub fn uri_name(mut self, uri: impl Into<String>) -> Self {
        self.inner.uri_names.push(uri.into());
        self
    }

    /// Appends an `iPAddress` SAN.
    pub fn ip_name(mut self, ip: IpAddr) -> Self {
        self.inner.ip_names.push(ip);
        self
    }

    /// Appends an `rfc822Name` SAN.
    pub fn email_name(mut self, email: impl Into<String>) -> Self {
        self.inner.email_names.push(email.into());
        self
    }

    /// Sets the SHA-256 fingerprint of the DER certificate.
    pub fn fingerprint_sha256(mut self, digest: [u8; 32]) -> Self {
        self.inner.fingerprint_sha256 = digest;
        self
    }

    /// Sets the DER-encoded leaf certificate.
    pub fn der(mut self, der: Vec<u8>) -> Self {
        self.inner.der = der;
        self
    }

    /// Finishes the identity.
    pub fn build(self) -> PeerIdentity {
        self.inner
    }
}

#[cfg(feature = "tls")]
impl PeerIdentity {
    /// Parses the identity fields out of a DER-encoded X.509
    /// certificate.
    ///
    /// This does **not** verify anything — call it only on a
    /// certificate rustls has already accepted (which is what the
    /// transport does). Unknown SAN kinds (`otherName`, directory
    /// names, registered ids) are skipped; a SAN extension that fails
    /// to decode leaves the SAN lists empty rather than failing the
    /// whole parse, since the subject is still usable.
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        use sha2::{Digest, Sha256};
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("failed to parse peer certificate: {e}"))?;

        let subject = cert.subject().to_string();
        let common_name = cert
            .subject()
            .iter_common_name()
            .find_map(|attr| attr.as_str().ok())
            .map(str::to_owned);

        let mut dns_names = Vec::new();
        let mut uri_names = Vec::new();
        let mut ip_names = Vec::new();
        let mut email_names = Vec::new();
        match cert.subject_alternative_name() {
            Ok(Some(ext)) => {
                for name in &ext.value.general_names {
                    match name {
                        GeneralName::DNSName(d) => dns_names.push((*d).to_owned()),
                        GeneralName::URI(u) => uri_names.push((*u).to_owned()),
                        GeneralName::RFC822Name(e) => email_names.push((*e).to_owned()),
                        GeneralName::IPAddress(bytes) => match bytes.len() {
                            4 => {
                                let mut b = [0u8; 4];
                                b.copy_from_slice(bytes);
                                ip_names.push(IpAddr::from(b));
                            }
                            16 => {
                                let mut b = [0u8; 16];
                                b.copy_from_slice(bytes);
                                ip_names.push(IpAddr::from(b));
                            }
                            other => {
                                tracing::debug!(len = other, "ignoring malformed iPAddress SAN")
                            }
                        },
                        _ => {}
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%e, %subject, "peer certificate subjectAltName failed to decode; SAN lists empty");
            }
        }

        let digest = Sha256::digest(der);
        let mut fingerprint_sha256 = [0u8; 32];
        fingerprint_sha256.copy_from_slice(&digest);

        Ok(Self {
            subject,
            common_name,
            dns_names,
            uri_names,
            ip_names,
            email_names,
            fingerprint_sha256,
            der: der.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PeerIdentity {
        PeerIdentity::builder("CN=node-1,O=Example")
            .common_name("node-1")
            .dns_name("Node-1.Example.COM")
            .uri_name("sip:node-1@example.com")
            .ip_name("10.0.0.7".parse().unwrap())
            .email_name("ops@example.com")
            .fingerprint_sha256([0xab; 32])
            .der(vec![0x30, 0x03, 0x02, 0x01, 0x01])
            .build()
    }

    #[test]
    fn accessors_round_trip_builder_input() {
        let id = sample();
        assert_eq!(id.subject(), "CN=node-1,O=Example");
        assert_eq!(id.common_name(), Some("node-1"));
        assert_eq!(id.dns_names(), ["Node-1.Example.COM"]);
        assert_eq!(id.uri_names(), ["sip:node-1@example.com"]);
        assert_eq!(id.ip_names(), ["10.0.0.7".parse::<IpAddr>().unwrap()]);
        assert_eq!(id.email_names(), ["ops@example.com"]);
        assert_eq!(id.fingerprint_sha256(), &[0xab; 32]);
        assert_eq!(id.der(), &[0x30, 0x03, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn dns_match_is_case_insensitive_and_literal() {
        let id = sample();
        assert!(id.has_dns_name("node-1.example.com"));
        assert!(id.has_dns_name("NODE-1.EXAMPLE.COM"));
        assert!(!id.has_dns_name("node-2.example.com"));
        assert!(!id.has_dns_name("example.com"));
    }

    #[test]
    fn uri_match_is_exact() {
        let id = sample();
        assert!(id.has_uri_name("sip:node-1@example.com"));
        assert!(!id.has_uri_name("SIP:node-1@example.com"));
        assert!(!id.has_uri_name("sip:node-1@example.com;transport=tls"));
    }

    #[test]
    fn names_lists_sans_then_cn_without_duplicates() {
        let id = sample();
        assert_eq!(
            id.names(),
            [
                "sip:node-1@example.com",
                "Node-1.Example.COM",
                "10.0.0.7",
                "ops@example.com",
                "node-1",
            ]
        );
        // CN that duplicates a DNS SAN is not repeated.
        let dup = PeerIdentity::builder("CN=a.example.com")
            .common_name("a.example.com")
            .dns_name("a.example.com")
            .build();
        assert_eq!(dup.names(), ["a.example.com"]);
    }

    #[test]
    fn fingerprint_hex_is_lowercase_64_chars() {
        let id = sample();
        assert_eq!(id.fingerprint_hex(), "ab".repeat(32));
    }

    #[test]
    fn display_and_debug_show_names_not_der() {
        let id = sample();
        let shown = id.to_string();
        assert!(shown.starts_with("CN=node-1,O=Example san=[sip:node-1@example.com, "));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("fingerprint_sha256: \"abab"));
        assert!(!dbg.contains("der"));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn from_der_extracts_subject_and_every_san_kind() {
        use rcgen::{CertificateParams, DnType, KeyPair, SanType};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "node-1.example.com");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Example");
        params.subject_alt_names = vec![
            SanType::DnsName("node-1.example.com".try_into().unwrap()),
            SanType::URI("sip:node-1@example.com".try_into().unwrap()),
            SanType::IpAddress("192.0.2.7".parse().unwrap()),
            SanType::IpAddress("2001:db8::7".parse().unwrap()),
            SanType::Rfc822Name("ops@example.com".try_into().unwrap()),
        ];
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();

        let id = PeerIdentity::from_der(&der).unwrap();
        assert_eq!(id.common_name(), Some("node-1.example.com"));
        assert!(
            id.subject().contains("CN=node-1.example.com"),
            "{}",
            id.subject()
        );
        assert!(id.subject().contains("O=Example"), "{}", id.subject());
        assert_eq!(id.dns_names(), ["node-1.example.com"]);
        assert_eq!(id.uri_names(), ["sip:node-1@example.com"]);
        assert_eq!(
            id.ip_names(),
            [
                "192.0.2.7".parse::<IpAddr>().unwrap(),
                "2001:db8::7".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(id.email_names(), ["ops@example.com"]);
        assert_eq!(id.der(), der.as_slice());
        // Fingerprint is a real SHA-256 of the DER.
        use sha2::{Digest, Sha256};
        assert_eq!(id.fingerprint_sha256(), Sha256::digest(&der).as_slice());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn from_der_rejects_garbage() {
        assert!(PeerIdentity::from_der(b"not a certificate").is_err());
    }
}
