// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Loopback mutual-TLS tests (issue #129).
//!
//! A private CA (rcgen) issues a server certificate and client
//! certificates. Each test starts a real `run_tls` listener with a
//! `ServerConfig` from `mtls::build_rustls_server_config`, dials it
//! with a `ClientConfig` from `mtls::build_rustls_client_config`, and
//! checks what the listener hands the inbound channel:
//!
//! * `Required` + a certificate from the CA → handshake succeeds and
//!   the `InboundPacket` carries the client's `PeerIdentity` (CN,
//!   DNS SAN, `sip:` URI SAN).
//! * `Required` + no certificate → the handshake fails; nothing
//!   reaches the channel.
//! * `Required` + a certificate from a *different* CA → rejected.
//! * `Optional` + no certificate → accepted with `peer_identity() ==
//!   None`; with a certificate → identity present.
//! * Outbound `TlsPool::send_tls` presenting a client identity → the
//!   listener sees it, and the response flowing back down the pooled
//!   connection carries the *server's* identity.

#![cfg(feature = "tls")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, SanType,
};
use sip_transport::mtls::{
    build_rustls_client_config, build_rustls_server_config, client_cert_verifier, ClientAuthMode,
    ClientIdentity,
};
use sip_transport::pool::TlsPool;
use sip_transport::{run_tls, InboundPacket, TransportKind};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

const OPTIONS: &[u8] = b"OPTIONS sip:node-2@localhost SIP/2.0\r\n\
Via: SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bK-mtls\r\n\
Call-ID: mtls-1\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

const OK: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bK-mtls\r\n\
Call-ID: mtls-1\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

impl Ca {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.self_signed(&key).expect("ca cert");
        Self { cert, key }
    }

    fn der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert.der().to_vec())
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.der()).expect("add root");
        roots
    }

    /// Issues a leaf for `cn` with a DNS SAN of `cn` and a `sip:` URI
    /// SAN, usable for `eku`.
    fn issue(&self, cn: &str, eku: ExtendedKeyUsagePurpose) -> ClientIdentity {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.subject_alt_names = vec![
            SanType::DnsName(cn.try_into().expect("dns san")),
            SanType::URI(format!("sip:{cn}").try_into().expect("uri san")),
        ];
        params.extended_key_usages = vec![eku];
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("sign leaf");
        ClientIdentity::new(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
    }
}

fn install_provider() {
    // rustls 0.23 needs an explicit process-wide provider when more
    // than one is linkable (rcgen pulls in aws-lc-rs).
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn server_config(ca: &Ca, mode: Option<ClientAuthMode>) -> Arc<ServerConfig> {
    let (certs, key) = ca
        .issue("localhost", ExtendedKeyUsagePurpose::ServerAuth)
        .into_parts();
    let verifier = mode.map(|m| client_cert_verifier(ca.roots(), m).expect("verifier"));
    build_rustls_server_config(certs, key, verifier).expect("server config")
}

fn client_config(ca: &Ca, identity: Option<ClientIdentity>) -> Arc<ClientConfig> {
    build_rustls_client_config(ca.roots(), identity).expect("client config")
}

/// Starts `run_tls` on an ephemeral port; returns the address, the
/// packet channel, and the listener task (aborted by the caller).
async fn start_listener(
    config: Arc<ServerConfig>,
) -> (
    SocketAddr,
    mpsc::Receiver<InboundPacket>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (tx, rx) = mpsc::channel::<InboundPacket>(8);
    let handle = tokio::spawn(async move {
        let _ = run_tls(&addr.to_string(), config, tx).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    (addr, rx, handle)
}

/// Dials `addr`, completes the handshake, and writes one OPTIONS.
/// Returns the handshake result so rejection tests can assert on it.
async fn dial_and_send(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let stream = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, stream).await?;
    tls.write_all(OPTIONS).await?;
    tls.flush().await?;
    Ok(tls)
}

async fn recv_packet(rx: &mut mpsc::Receiver<InboundPacket>) -> Option<InboundPacket> {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn required_mode_accepts_ca_issued_client_and_exposes_identity() {
    install_provider();
    let ca = Ca::new("test-ca");
    let (addr, mut rx, listener) =
        start_listener(server_config(&ca, Some(ClientAuthMode::Required))).await;

    let client = ca.issue("node-1.example.com", ExtendedKeyUsagePurpose::ClientAuth);
    let expected_fingerprint = {
        use sha2::{Digest, Sha256};
        Sha256::digest(client.certs()[0].as_ref()).to_vec()
    };
    let _conn = dial_and_send(addr, client_config(&ca, Some(client)))
        .await
        .expect("handshake with CA-issued client cert must succeed");

    let packet = recv_packet(&mut rx)
        .await
        .expect("OPTIONS reaches the channel");
    assert_eq!(packet.transport(), TransportKind::Tls);
    let identity = packet
        .peer_identity()
        .expect("packet carries the verified client identity");
    assert_eq!(identity.common_name(), Some("node-1.example.com"));
    assert!(identity.has_dns_name("NODE-1.example.com"));
    assert!(identity.has_uri_name("sip:node-1.example.com"));
    assert_eq!(
        identity.fingerprint_sha256().as_slice(),
        expected_fingerprint
    );

    listener.abort();
}

#[tokio::test]
async fn required_mode_rejects_client_without_certificate() {
    install_provider();
    let ca = Ca::new("test-ca");
    let (addr, mut rx, listener) =
        start_listener(server_config(&ca, Some(ClientAuthMode::Required))).await;

    let result = dial_and_send(addr, client_config(&ca, None)).await;
    // rustls surfaces the server's alert either during connect() or
    // on the first write/flush after it; either way the peer never
    // gets a SIP message through.
    let rejected = match result {
        Err(_) => true,
        Ok(mut tls) => {
            let mut buf = [0u8; 16];
            use tokio::io::AsyncReadExt;
            matches!(
                tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await,
                Ok(Err(_)) | Ok(Ok(0))
            )
        }
    };
    assert!(rejected, "handshake without a client certificate must fail");
    assert!(
        recv_packet(&mut rx).await.is_none(),
        "no packet may reach the channel from an unauthenticated peer"
    );

    listener.abort();
}

#[tokio::test]
async fn required_mode_rejects_certificate_from_other_ca() {
    install_provider();
    let ca = Ca::new("test-ca");
    let rogue = Ca::new("rogue-ca");
    let (addr, mut rx, listener) =
        start_listener(server_config(&ca, Some(ClientAuthMode::Required))).await;

    // Trusts our server, but presents a leaf the server's client-CA
    // bundle does not chain to.
    let client = rogue.issue("node-x.example.com", ExtendedKeyUsagePurpose::ClientAuth);
    let result = dial_and_send(addr, client_config(&ca, Some(client))).await;
    let rejected = match result {
        Err(_) => true,
        Ok(mut tls) => {
            let mut buf = [0u8; 16];
            use tokio::io::AsyncReadExt;
            matches!(
                tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await,
                Ok(Err(_)) | Ok(Ok(0))
            )
        }
    };
    assert!(
        rejected,
        "a certificate from an untrusted CA must be refused"
    );
    assert!(recv_packet(&mut rx).await.is_none());

    listener.abort();
}

#[tokio::test]
async fn optional_mode_admits_bare_client_without_identity_but_reports_one_when_presented() {
    install_provider();
    let ca = Ca::new("test-ca");
    let (addr, mut rx, listener) =
        start_listener(server_config(&ca, Some(ClientAuthMode::Optional))).await;

    let _bare = dial_and_send(addr, client_config(&ca, None))
        .await
        .expect("optional mode admits a peer with no certificate");
    let packet = recv_packet(&mut rx)
        .await
        .expect("bare peer's OPTIONS arrives");
    assert!(
        packet.peer_identity().is_none(),
        "no certificate presented ⇒ no identity"
    );

    let client = ca.issue("node-2.example.com", ExtendedKeyUsagePurpose::ClientAuth);
    let _authed = dial_and_send(addr, client_config(&ca, Some(client)))
        .await
        .expect("optional mode verifies a presented certificate");
    let packet = recv_packet(&mut rx)
        .await
        .expect("authed peer's OPTIONS arrives");
    assert_eq!(
        packet.peer_identity().map(|id| id.common_name()),
        Some(Some("node-2.example.com"))
    );

    listener.abort();
}

#[tokio::test]
async fn no_client_auth_listener_is_unchanged() {
    install_provider();
    let ca = Ca::new("test-ca");
    let (addr, mut rx, listener) = start_listener(server_config(&ca, None)).await;

    // A client that would present a cert is never asked for one.
    let client = ca.issue("node-3.example.com", ExtendedKeyUsagePurpose::ClientAuth);
    let _conn = dial_and_send(addr, client_config(&ca, Some(client)))
        .await
        .expect("plain listener still accepts");
    let packet = recv_packet(&mut rx).await.expect("OPTIONS arrives");
    assert!(
        packet.peer_identity().is_none(),
        "a listener that never requests a certificate reports no identity"
    );

    listener.abort();
}

#[tokio::test]
async fn outbound_pool_presents_client_identity_and_reports_server_identity() {
    install_provider();
    let ca = Ca::new("test-ca");
    let (addr, mut server_rx, listener) =
        start_listener(server_config(&ca, Some(ClientAuthMode::Required))).await;

    // Outbound side: a pool whose ClientConfig carries our identity.
    let pool = TlsPool::new();
    let (pool_tx, mut pool_rx) = mpsc::channel::<InboundPacket>(8);
    pool.set_inbound_tx(pool_tx).await;
    let ours = ca.issue("node-a.example.com", ExtendedKeyUsagePurpose::ClientAuth);
    let config = client_config(&ca, Some(ours));
    pool.send_tls(
        addr,
        "localhost".to_string(),
        config,
        Bytes::from_static(OPTIONS),
    )
    .await
    .expect("pooled mTLS send succeeds");

    // Listener sees who dialed it...
    let request = recv_packet(&mut server_rx).await.expect("request arrives");
    let who = request.peer_identity().expect("client identity on request");
    assert_eq!(who.common_name(), Some("node-a.example.com"));

    // ...and answers down the same connection.
    request
        .stream()
        .expect("tls packet carries its writer")
        .send(Bytes::from_static(OK))
        .await
        .expect("write response");

    // The pool's reader delivers the response stamped with the
    // server's verified identity.
    let response = recv_packet(&mut pool_rx)
        .await
        .expect("response arrives via pool");
    assert_eq!(response.transport(), TransportKind::Tls);
    let server_id = response
        .peer_identity()
        .expect("server identity on pooled response");
    assert_eq!(server_id.common_name(), Some("localhost"));
    assert!(server_id.has_dns_name("localhost"));

    listener.abort();
}
