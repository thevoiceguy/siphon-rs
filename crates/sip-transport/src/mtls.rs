// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Mutual TLS for SIP over TLS (`tls` feature).
//!
//! Three pieces, each usable on its own:
//!
//! 1. **Server side** — [`load_rustls_server_config_with_client_auth`]
//!    builds a `ServerConfig` that asks connecting peers for a
//!    certificate and verifies it against a client-CA bundle.
//!    [`ClientAuthMode::Required`] fails the handshake for a peer
//!    that presents nothing; [`ClientAuthMode::Optional`] lets such a
//!    peer through (it just gets no [`PeerIdentity`]) while still
//!    rejecting a peer whose certificate does not chain. The
//!    no-client-auth path is unchanged: `load_rustls_server_config`
//!    still never asks.
//! 2. **Client side** — [`ClientIdentity::load`] +
//!    [`build_rustls_client_config`] produce a `ClientConfig` that
//!    presents a certificate on outbound connections. It drops into
//!    the existing `TlsConfig` / `TlsPool::send_tls` plumbing; nothing
//!    about SNI or root handling changes.
//! 3. **Identity propagation** — after a handshake the transport
//!    reads the verified peer certificate off the rustls connection
//!    and stamps a [`PeerIdentity`] on every `InboundPacket` from
//!    that connection (see [`PeerIdentity`] for the contract).
//!
//! Every loader reads PEM. Private keys are refused unless the file
//! is owner-only readable, the same guard the server key has always
//! had.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{danger::ClientCertVerifier, WebPkiClientVerifier},
    ClientConfig, RootCertStore, ServerConfig,
};

use crate::PeerIdentity;

/// Whether a TLS listener insists on a client certificate.
///
/// Both modes verify a presented certificate against the client-CA
/// bundle; they differ only in what happens when the peer presents
/// none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMode {
    /// Request a certificate; accept the handshake without one. Use
    /// this to roll mTLS out across a fleet where some peers cannot
    /// yet present a certificate — the transaction user sees
    /// `peer_identity() == None` for those and can decide per request.
    Optional,
    /// Request a certificate; fail the handshake without one. The
    /// peer never gets to send a SIP message.
    Required,
}

impl ClientAuthMode {
    /// Lowercase name, as accepted by [`FromStr`].
    pub fn as_str(self) -> &'static str {
        match self {
            ClientAuthMode::Optional => "optional",
            ClientAuthMode::Required => "required",
        }
    }
}

impl fmt::Display for ClientAuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ClientAuthMode {
    type Err = anyhow::Error;

    /// Accepts `optional` / `required` (ASCII case-insensitive).
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "optional" => Ok(ClientAuthMode::Optional),
            "required" => Ok(ClientAuthMode::Required),
            other => Err(anyhow!(
                "invalid client auth mode {other:?}: expected \"optional\" or \"required\""
            )),
        }
    }
}

/// A certificate chain plus private key this side presents to the
/// peer — on the server side via `with_single_cert`, on the client
/// side via `with_client_auth_cert`.
pub struct ClientIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material, even by accident.
        f.debug_struct("ClientIdentity")
            .field("certs", &self.certs.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl ClientIdentity {
    /// Wraps an already-parsed chain and key.
    pub fn new(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        Self { certs, key }
    }

    /// Loads the chain and key from PEM files. The key file must be
    /// owner-only readable (see [`load_private_key`]).
    pub fn load(cert_path: &str, key_path: &str) -> Result<Self> {
        let certs = load_cert_chain(cert_path)?;
        let key = load_private_key(key_path)?;
        Ok(Self { certs, key })
    }

    /// The certificate chain, leaf first.
    pub fn certs(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }

    /// Splits into the parts rustls' builders take.
    pub fn into_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.certs, self.key)
    }
}

/// Reads every certificate in a PEM file. Errors on an unreadable
/// file, a malformed entry, or an empty bundle — a CA bundle with
/// zero roots would silently reject every peer, which is the kind of
/// misconfiguration that should fail at startup.
pub fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow!("failed to read certificate file {path}: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid certificate in {path}: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {path}"));
    }
    Ok(certs)
}

/// Reads a PEM private key (PKCS#8, PKCS#1, or SEC1), refusing a
/// file readable by anyone other than its owner.
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    use rustls_pki_types::pem::PemObject;

    // A world- or group-readable key is an immediate disclosure to
    // every local user — same guard as the server key and siphond's
    // --auth-users.
    crate::enforce_secure_key_perms(path)?;
    PrivateKeyDer::from_pem_file(path).map_err(|e| anyhow!("no private keys found in {path}: {e}"))
}

/// Loads a client-CA bundle into a `RootCertStore`. Every certificate
/// in the file becomes a trust anchor; a peer certificate must chain
/// to one of them to be accepted.
pub fn load_client_ca_roots(path: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_cert_chain(path)? {
        roots
            .add(cert)
            .map_err(|e| anyhow!("invalid CA certificate in {path}: {e}"))?;
    }
    Ok(roots)
}

/// Builds the verifier a `ServerConfig` uses to check client
/// certificates against `roots` under `mode`.
pub fn client_cert_verifier(
    roots: RootCertStore,
    mode: ClientAuthMode,
) -> Result<Arc<dyn ClientCertVerifier>> {
    let builder = WebPkiClientVerifier::builder(Arc::new(roots));
    let builder = match mode {
        ClientAuthMode::Optional => builder.allow_unauthenticated(),
        ClientAuthMode::Required => builder,
    };
    builder
        .build()
        .map_err(|e| anyhow!("failed to build client certificate verifier: {e}"))
}

/// Assembles a `ServerConfig` from parsed parts. `client_auth =
/// None` reproduces the historic no-client-auth listener; `Some`
/// installs the verifier from [`client_cert_verifier`].
///
/// Uses `with_single_cert`, which ignores SNI entirely — SIP peers
/// routinely send an IP literal as SNI, which an SNI-aware resolver
/// would reject (rustls issue #130). Honors `SIPHON_TLS12_ONLY=1`
/// for peers that cannot negotiate TLS 1.3.
pub fn build_rustls_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_auth: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<Arc<ServerConfig>> {
    let tls12_only = std::env::var("SIPHON_TLS12_ONLY")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
        .unwrap_or(false);

    let builder = if tls12_only {
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
    } else {
        ServerConfig::builder()
    };

    let builder = match client_auth {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };

    let config = builder
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("failed to create TLS config: {e}"))?;
    Ok(Arc::new(config))
}

/// Loads a server `ServerConfig` that requests and verifies client
/// certificates: `cert_path` / `key_path` are this listener's own
/// identity, `client_ca_path` is the PEM bundle client certificates
/// must chain to, and `mode` decides whether a peer without one is
/// let in. Companion to `load_rustls_server_config`, which never asks
/// for a client certificate.
pub fn load_rustls_server_config_with_client_auth(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
    mode: ClientAuthMode,
) -> Result<Arc<ServerConfig>> {
    let certs = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;
    let roots = load_client_ca_roots(client_ca_path)?;
    let verifier = client_cert_verifier(roots, mode)?;
    build_rustls_server_config(certs, key, Some(verifier))
}

/// Builds the `ClientConfig` for outbound TLS. `roots` verifies the
/// servers we dial (the caller assembles it — webpki roots, a
/// private CA, or both); `identity`, when given, is presented to a
/// server that asks for a client certificate. With `None` the
/// result is the classic root-store-only client.
pub fn build_rustls_client_config(
    roots: RootCertStore,
    identity: Option<ClientIdentity>,
) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match identity {
        Some(identity) => {
            let (certs, key) = identity.into_parts();
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow!("failed to install TLS client certificate: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Turns the peer certificate chain rustls reports after a handshake
/// into a [`PeerIdentity`] for the leaf. `None` when the peer
/// presented no certificate. A leaf that rustls accepted but our
/// parser cannot read is logged and treated as no identity rather
/// than tearing the connection down — the connection is still
/// authenticated at the TLS layer; only the identity extraction
/// failed, and a transaction user that needs the identity will
/// refuse the request on `None`.
pub(crate) fn peer_identity_from_certs(
    certs: Option<&[CertificateDer<'_>]>,
    peer: std::net::SocketAddr,
) -> Option<Arc<PeerIdentity>> {
    let leaf = certs?.first()?;
    match PeerIdentity::from_der(leaf.as_ref()) {
        Ok(identity) => Some(Arc::new(identity)),
        Err(e) => {
            tracing::warn!(%peer, %e, "verified peer certificate could not be parsed; no peer identity");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn client_auth_mode_parses_case_insensitively() {
        assert_eq!(
            "optional".parse::<ClientAuthMode>().unwrap(),
            ClientAuthMode::Optional
        );
        assert_eq!(
            " Required ".parse::<ClientAuthMode>().unwrap(),
            ClientAuthMode::Required
        );
        assert!("off".parse::<ClientAuthMode>().is_err());
        assert_eq!(ClientAuthMode::Required.to_string(), "required");
    }

    fn pem_file(dir: &tempfile::TempDir, name: &str, body: &str, mode: u32) -> String {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn load_cert_chain_rejects_empty_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = pem_file(&dir, "empty.pem", "", 0o644);
        let err = load_cert_chain(&path).unwrap_err();
        assert!(err.to_string().contains("no certificates found"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn load_private_key_refuses_group_readable_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = pem_file(&dir, "key.pem", &key.serialize_pem(), 0o640);
        let err = load_private_key(&path).unwrap_err();
        assert!(err.to_string().contains("insecure permissions"), "{err}");
    }

    #[test]
    fn client_identity_loads_from_pem_and_redacts_key_in_debug() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["node.example".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = pem_file(&dir, "cert.pem", &cert.pem(), 0o644);
        let key_path = pem_file(&dir, "key.pem", &key.serialize_pem(), 0o600);

        let identity = ClientIdentity::load(&cert_path, &key_path).unwrap();
        assert_eq!(identity.certs().len(), 1);
        let dbg = format!("{identity:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("PRIVATE"));

        // And it installs into a ClientConfig without complaint.
        let roots = RootCertStore::empty();
        build_rustls_client_config(roots, Some(identity)).unwrap();
    }

    #[test]
    fn load_client_ca_roots_populates_store() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = pem_file(&dir, "ca.pem", &ca.pem(), 0o644);
        let roots = load_client_ca_roots(&path).unwrap();
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn peer_identity_from_certs_handles_absent_and_garbage() {
        let peer: std::net::SocketAddr = "127.0.0.1:5061".parse().unwrap();
        assert!(peer_identity_from_certs(None, peer).is_none());
        assert!(peer_identity_from_certs(Some(&[]), peer).is_none());
        let garbage = [CertificateDer::from(vec![0u8; 8])];
        assert!(peer_identity_from_certs(Some(&garbage), peer).is_none());
    }
}
