// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Transport layer initialization and dispatcher implementation.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sip_transaction::{TransportContext, TransportDispatcher, TransportKind};
#[cfg(feature = "tls")]
use sip_transport::{
    build_rustls_client_config, load_rustls_server_config_with_client_auth, ClientAuthMode,
    ClientIdentity,
};
#[cfg(feature = "tls")]
use sip_transport::{load_rustls_server_config, run_tls};
use sip_transport::{
    pool::{ConnectionPool, TlsClientConfig, TlsPool},
    run_tcp, run_udp, send_stream, send_udp, DefaultTransportPolicy, InboundPacket,
    TransportPolicy,
};
#[cfg(feature = "ws")]
use sip_transport::{run_ws, run_wss};
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::mpsc};
#[cfg(feature = "tls")]
use tokio_rustls::rustls;
#[cfg(any(feature = "tls", feature = "ws"))]
use tracing::info;
use tracing::warn;

/// Start all transport layers and return the transport dispatcher and UDP socket.
///
/// `require_tls`: when `true`, siphond refuses to start if a TLS cert /
/// key pair was supplied but fails to load (bad file, mismatched key,
/// insecure permissions). Without this flag the daemon would silently
/// fall back to cleartext, which is a footgun for operators who meant
/// to enforce SIPS.
/// Everything the `--tls-*` flags say about TLS, in one place.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsOptions<'a> {
    /// `--tls-cert`: the listener's own certificate chain (PEM).
    pub cert: Option<&'a str>,
    /// `--tls-key`: the listener's private key (PEM).
    pub key: Option<&'a str>,
    /// `--require-tls`: fail closed when the cert/key won't load.
    pub require_tls: bool,
    /// `--tls-client-ca`: mutual TLS trust bundle for client certs.
    pub client_ca: Option<&'a str>,
    /// `--tls-client-auth`: `optional` | `required`.
    pub client_auth: Option<&'a str>,
    /// `--tls-client-cert`: identity presented on outbound TLS.
    pub client_cert: Option<&'a str>,
    /// `--tls-client-key`: key for `client_cert`.
    pub client_key: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
pub async fn start_transports(
    udp_bind: &str,
    tcp_bind: &str,
    tls_bind: &str,
    tls: &TlsOptions<'_>,
    #[cfg(feature = "ws")] ws_bind: Option<&str>,
    #[cfg(feature = "ws")] wss_bind: Option<&str>,
    tx: mpsc::Sender<InboundPacket>,
) -> Result<(Arc<dyn TransportDispatcher>, Arc<UdpSocket>)> {
    // Create UDP socket
    let udp_socket = Arc::new(UdpSocket::bind(udp_bind).await?);
    let recv_socket = Arc::clone(&udp_socket);

    // Create connection pools
    let tcp_pool = Arc::new(ConnectionPool::new());
    let tls_pool = Arc::new(TlsPool::new());
    // Route responses on outbound TLS connections back into the inbound
    // pipeline. Without this the TLS pool opens a connection, sends the
    // request, and never reads the response (the reader task was
    // previously absent, silently dropping all 1xx/2xx on outbound TLS).
    tls_pool.set_inbound_tx(tx.clone()).await;

    // Prepare optional TLS client config (system roots, default
    // crypto, plus the outbound client identity if one was given).
    let tls_client_config = build_tls_client_config(tls.client_cert, tls.client_key)?;

    // Create transport dispatcher (clone socket since we need to return it too)
    let dispatcher = Arc::new(SiphonTransportDispatcher::new(
        Arc::clone(&udp_socket),
        Arc::new(DefaultTransportPolicy::default()),
        tcp_pool,
        tls_pool,
        tls_client_config,
    ));

    // Spawn UDP listener
    tokio::spawn({
        let tx = tx.clone();
        async move {
            if let Err(e) = run_udp(recv_socket, tx).await {
                tracing::error!(%e, "UDP listener exited");
            }
        }
    });

    // Spawn TCP listener
    tokio::spawn({
        let bind = tcp_bind.to_string();
        let tx = tx.clone();
        async move {
            if let Err(e) = run_tcp(&bind, tx).await {
                tracing::error!(%e, "TCP listener exited");
            }
        }
    });

    // Load TLS config once for TLS/WSS. When the operator supplied both
    // --tls-cert and --tls-key, a load failure is a configuration error:
    // with --require-tls we refuse to start rather than silently
    // downgrade to cleartext. Without --require-tls the legacy
    // warn-and-continue behaviour is preserved for backwards compat.
    let require_tls = tls.require_tls;
    #[cfg(feature = "tls")]
    let tls_server_config = if let (Some(cert), Some(key)) = (tls.cert, tls.key) {
        // Mutual TLS when --tls-client-ca/--tls-client-auth are set;
        // clap guarantees they come as a pair. A bad mode string or an
        // unloadable CA bundle is always fatal — there is no sensible
        // cleartext fallback for "verify the peer's certificate".
        let loaded = match (tls.client_ca, tls.client_auth) {
            (Some(ca), Some(mode)) => {
                let mode: ClientAuthMode = mode
                    .parse()
                    .map_err(|e| anyhow!("--tls-client-auth: {e}"))?;
                info!(client_ca = %ca, %mode, "mutual TLS enabled on SIPS/WSS listeners");
                load_rustls_server_config_with_client_auth(cert, key, ca, mode)
            }
            _ => load_rustls_server_config(cert, key),
        };
        match loaded {
            Ok(config) => Some(config),
            Err(e) => {
                if require_tls || tls.client_ca.is_some() {
                    return Err(anyhow!(
                        "TLS is required (--require-tls) but loading cert/key failed: {e}"
                    ));
                }
                warn!(%e, "Failed to load TLS config; TLS disabled (pass --require-tls to fail-closed)");
                None
            }
        }
    } else {
        if tls.cert.is_some() || tls.key.is_some() {
            // Partial TLS args is always a misconfig — fail-closed even
            // without --require-tls since continuing silently would be
            // surprising.
            return Err(anyhow!(
                "Both --tls-cert and --tls-key must be provided to enable TLS"
            ));
        }
        if require_tls {
            return Err(anyhow!(
                "--require-tls set but neither --tls-cert nor --tls-key provided"
            ));
        }
        None
    };
    #[cfg(not(feature = "tls"))]
    if require_tls {
        return Err(anyhow!(
            "--require-tls set but siphond was built without the `tls` feature"
        ));
    }
    #[cfg(not(feature = "tls"))]
    if tls.client_ca.is_some() || tls.client_cert.is_some() {
        return Err(anyhow!(
            "--tls-client-* flags need siphond built with the `tls` feature"
        ));
    }
    #[cfg(not(feature = "tls"))]
    let _ = (tls.cert, tls.key, tls.client_auth, tls.client_key, tls_bind);

    // Spawn TLS listener if certificate and key are provided
    #[cfg(feature = "tls")]
    if let Some(config) = tls_server_config.clone() {
        let bind = tls_bind.to_string();
        let tx_tls = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_tls(&bind, config, tx_tls).await {
                tracing::error!(%e, "TLS listener exited");
            }
        });
        info!(%tls_bind, "TLS listener enabled");
    }

    #[cfg(feature = "ws")]
    {
        if let Some(bind) = ws_bind {
            let bind = bind.to_string();
            info!(%bind, "WS listener enabled");
            let tx_ws = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_ws(&bind, tx_ws).await {
                    tracing::error!(%e, "WS listener exited");
                }
            });
        }
        #[cfg(feature = "tls")]
        if let Some(bind) = wss_bind {
            let bind = bind.to_string();
            if let Some(config) = tls_server_config.clone() {
                info!(%bind, "WSS listener enabled");
                let tx_wss = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_wss(&bind, config, tx_wss).await {
                        tracing::error!(%e, "WSS listener exited");
                    }
                });
            } else {
                warn!("WSS listener requested but TLS config missing; skipping");
            }
        }
    }

    Ok((dispatcher, udp_socket))
}

/// Builds a client TLS config using system roots, presenting
/// `client_cert` / `client_key` (PEM paths) to servers that request a
/// client certificate when both are given.
pub fn build_tls_client_config(
    client_cert: Option<&str>,
    client_key: Option<&str>,
) -> Result<Option<Arc<TlsClientConfig>>> {
    #[cfg(feature = "tls")]
    {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let identity = match (client_cert, client_key) {
            (Some(cert), Some(key)) => {
                let identity = ClientIdentity::load(cert, key)
                    .map_err(|e| anyhow!("--tls-client-cert/--tls-client-key: {e}"))?;
                info!(cert = %cert, "outbound TLS client certificate loaded");
                Some(identity)
            }
            _ => None,
        };

        return build_rustls_client_config(root_store, identity).map(Some);
    }

    #[allow(unreachable_code)]
    {
        let _ = (client_cert, client_key);
        Ok(None)
    }
}

/// Transport dispatcher implementation for siphond.
struct SiphonTransportDispatcher {
    udp_socket: Arc<UdpSocket>,
    policy: Arc<dyn TransportPolicy>,
    tcp_pool: Arc<ConnectionPool>,
    tls_pool: Arc<TlsPool>,
    tls_config: Option<Arc<TlsClientConfig>>,
}

impl SiphonTransportDispatcher {
    fn new(
        udp_socket: Arc<UdpSocket>,
        policy: Arc<dyn TransportPolicy>,
        tcp_pool: Arc<ConnectionPool>,
        tls_pool: Arc<TlsPool>,
        tls_config: Option<Arc<TlsClientConfig>>,
    ) -> Self {
        Self {
            udp_socket,
            policy,
            tcp_pool,
            tls_pool,
            tls_config,
        }
    }
}

#[async_trait]
impl TransportDispatcher for SiphonTransportDispatcher {
    async fn dispatch(&self, ctx: &TransportContext, payload: Bytes) -> Result<()> {
        let start = std::time::Instant::now();
        let desired = to_sip_transport(ctx.transport());
        let selected = self.policy.choose(
            desired,
            payload.len(),
            matches!(
                ctx.transport(),
                TransportKind::Tls | TransportKind::Wss | TransportKind::TlsSctp
            ),
        );

        let target = match selected {
            sip_transport::TransportKind::Tcp | sip_transport::TransportKind::Tls
                if ctx.stream().is_none() =>
            {
                warn!(
                    ?selected,
                    ?desired,
                    peer = %ctx.peer(),
                    "Policy requested stream transport but no stream available; falling back"
                );
                desired
            }
            other => other,
        };

        match target {
            sip_transport::TransportKind::Udp => {
                send_udp(self.udp_socket.as_ref(), &ctx.peer(), &payload).await?;
            }
            sip_transport::TransportKind::Tcp => {
                if let Some(writer) = &ctx.stream() {
                    send_stream(target, writer, payload).await?;
                } else {
                    self.tcp_pool.send_tcp(ctx.peer(), payload).await?;
                }
            }
            sip_transport::TransportKind::Tls => {
                if let Some(writer) = &ctx.stream() {
                    send_stream(target, writer, payload).await?;
                } else {
                    let cfg = self
                        .tls_config
                        .clone()
                        .ok_or_else(|| anyhow!("TLS client config missing"))?;
                    let server_name = ctx
                        .server_name()
                        .map(String::from)
                        .unwrap_or_else(|| ctx.peer().ip().to_string());
                    self.tls_pool
                        .send_tls(ctx.peer(), server_name, cfg, payload)
                        .await?;
                }
            }
            sip_transport::TransportKind::Sctp | sip_transport::TransportKind::TlsSctp => {
                return Err(anyhow!("SCTP transport not supported"));
            }
            sip_transport::TransportKind::Ws => {
                #[cfg(feature = "ws")]
                {
                    let url = ctx.ws_uri().map(|s| s.to_string()).unwrap_or_else(|| {
                        let host = ctx
                            .server_name()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| ctx.peer().ip().to_string());
                        format!("ws://{}:{}", host, ctx.peer().port())
                    });
                    sip_transport::send_ws(&url, payload).await?;
                }
                #[cfg(not(feature = "ws"))]
                {
                    return Err(anyhow!("WebSocket transport not enabled"));
                }
            }
            sip_transport::TransportKind::Wss => {
                #[cfg(feature = "ws")]
                {
                    let url = ctx.ws_uri().map(|s| s.to_string()).unwrap_or_else(|| {
                        let host = ctx
                            .server_name()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| ctx.peer().ip().to_string());
                        format!("wss://{}:{}", host, ctx.peer().port())
                    });
                    sip_transport::send_wss(&url, payload).await?;
                }
                #[cfg(not(feature = "ws"))]
                {
                    return Err(anyhow!("Secure WebSocket transport not enabled"));
                }
            }
        }

        // Metrics are emitted by the lower-level transport layer (on_packet_sent, etc.)
        let _ = start; // Latency tracking removed: OpLabel doesn't support dispatch operations
        Ok(())
    }
}

fn to_sip_transport(kind: TransportKind) -> sip_transport::TransportKind {
    match kind {
        TransportKind::Udp => sip_transport::TransportKind::Udp,
        TransportKind::Tcp => sip_transport::TransportKind::Tcp,
        TransportKind::Tls => sip_transport::TransportKind::Tls,
        TransportKind::Ws => sip_transport::TransportKind::Ws,
        TransportKind::Wss => sip_transport::TransportKind::Wss,
        TransportKind::Sctp => sip_transport::TransportKind::Sctp,
        TransportKind::TlsSctp => sip_transport::TransportKind::TlsSctp,
    }
}
