/// Transport layer initialization and dispatcher implementation.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sip_transaction::{TransportContext, TransportDispatcher, TransportKind};
use sip_transport::{
    load_rustls_server_config,
    pool::{ConnectionPool, TlsClientConfig, TlsPool},
    run_tcp, run_tls, run_udp, send_stream, send_udp, DefaultTransportPolicy, InboundPacket,
    TransportPolicy,
};
#[cfg(feature = "ws")]
use sip_transport::{run_ws, run_wss};
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::mpsc};
#[cfg(feature = "tls")]
use tokio_rustls::rustls;
use tracing::{info, warn};

/// Start all transport layers and return the transport dispatcher and UDP socket.
pub async fn start_transports(
    udp_bind: &str,
    tcp_bind: &str,
    tls_bind: &str,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
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

    // Prepare optional TLS client config (system roots, default crypto)
    let tls_client_config = build_tls_client_config();

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

    // Load TLS config once for TLS/WSS
    #[cfg(feature = "tls")]
    let tls_server_config = if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        match load_rustls_server_config(cert, key) {
            Ok(config) => Some(config),
            Err(e) => {
                warn!(%e, "Failed to load TLS config; TLS disabled");
                None
            }
        }
    } else {
        if tls_cert.is_some() || tls_key.is_some() {
            warn!("Both --tls-cert and --tls-key must be provided to enable TLS");
        }
        None
    };

    // Spawn TLS listener if certificate and key are provided
    #[cfg(feature = "tls")]
    if let Some(config) = tls_server_config.clone() {
        let bind = tls_bind.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_tls(&bind, config, tx).await {
                tracing::error!(%e, "TLS listener exited");
            }
        });
        info!(%tls_bind, "TLS listener enabled");
    }

    #[cfg(feature = "ws")]
    {
        if let Some(bind) = ws_bind {
            let tx_ws = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_ws(bind, tx_ws).await {
                    tracing::error!(%e, "WS listener exited");
                }
            });
            info!(%bind, "WS listener enabled");
        }
        #[cfg(feature = "tls")]
        if let Some(bind) = wss_bind {
            if let Some(config) = tls_server_config.clone() {
                let tx_wss = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_wss(bind, config, tx_wss).await {
                        tracing::error!(%e, "WSS listener exited");
                    }
                });
                info!(%bind, "WSS listener enabled");
            } else {
                warn!("WSS listener requested but TLS config missing; skipping");
            }
        }
    }

    Ok((dispatcher, udp_socket))
}

/// Builds a client TLS config using system roots.
pub fn build_tls_client_config() -> Option<Arc<TlsClientConfig>> {
    #[cfg(feature = "tls")]
    {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        return Some(Arc::new(config));
    }

    #[allow(unreachable_code)]
    None
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
        let desired = to_sip_transport(ctx.transport);
        let selected = self.policy.choose(
            desired,
            payload.len(),
            matches!(
                ctx.transport,
                TransportKind::Tls | TransportKind::Wss | TransportKind::TlsSctp
            ),
        );

        let target = match selected {
            sip_transport::TransportKind::Tcp | sip_transport::TransportKind::Tls
                if ctx.stream.is_none() =>
            {
                warn!(
                    ?selected,
                    ?desired,
                    peer = %ctx.peer,
                    "Policy requested stream transport but no stream available; falling back"
                );
                desired
            }
            other => other,
        };

        match target {
            sip_transport::TransportKind::Udp => {
                send_udp(self.udp_socket.as_ref(), &ctx.peer, &payload).await?;
            }
            sip_transport::TransportKind::Tcp => {
                if let Some(writer) = &ctx.stream {
                    send_stream(target, writer, payload).await?;
                } else {
                    self.tcp_pool.send_tcp(ctx.peer, payload).await?;
                }
            }
            sip_transport::TransportKind::Tls => {
                if let Some(writer) = &ctx.stream {
                    send_stream(target, writer, payload).await?;
                } else {
                    let cfg = self
                        .tls_config
                        .clone()
                        .ok_or_else(|| anyhow!("TLS client config missing"))?;
                    let server_name = ctx
                        .server_name
                        .clone()
                        .unwrap_or_else(|| ctx.peer.ip().to_string());
                    self.tls_pool
                        .send_tls(ctx.peer, server_name, cfg, payload)
                        .await?;
                }
            }
            sip_transport::TransportKind::Sctp | sip_transport::TransportKind::TlsSctp => {
                return Err(anyhow!("SCTP transport not supported"));
            }
            sip_transport::TransportKind::Ws => {
                #[cfg(feature = "ws")]
                {
                    let url = ctx.ws_uri.clone().unwrap_or_else(|| {
                        let host = ctx
                            .server_name
                            .clone()
                            .unwrap_or_else(|| ctx.peer.ip().to_string());
                        format!("ws://{}:{}", host, ctx.peer.port())
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
                    let url = ctx.ws_uri.clone().unwrap_or_else(|| {
                        let host = ctx
                            .server_name
                            .clone()
                            .unwrap_or_else(|| ctx.peer.ip().to_string());
                        format!("wss://{}:{}", host, ctx.peer.port())
                    });
                    sip_transport::send_wss(&url, payload).await?;
                }
                #[cfg(not(feature = "ws"))]
                {
                    return Err(anyhow!("Secure WebSocket transport not enabled"));
                }
            }
        }

        sip_observe::transport_metrics().on_latency(
            selected.as_str(),
            "dispatch",
            start.elapsed().as_nanos() as u64,
        );
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
