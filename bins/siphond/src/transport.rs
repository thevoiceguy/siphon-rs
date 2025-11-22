/// Transport layer initialization and dispatcher implementation.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sip_transaction::{TransportContext, TransportDispatcher, TransportKind};
use sip_transport::{
    load_rustls_server_config, run_tcp, run_tls, run_udp, send_stream, send_udp,
    DefaultTransportPolicy, InboundPacket, TransportPolicy,
    pool::{ConnectionPool, TlsClientConfig, TlsPool},
};
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::mpsc};
use tracing::warn;

/// Start all transport layers and return the transport dispatcher.
pub async fn start_transports(
    udp_bind: &str,
    tcp_bind: &str,
    tls_bind: &str,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tx: mpsc::Sender<InboundPacket>,
) -> Result<Arc<dyn TransportDispatcher>> {
    // Create UDP socket
    let udp_socket = Arc::new(UdpSocket::bind(udp_bind).await?);
    let recv_socket = Arc::clone(&udp_socket);

    // Create connection pools
    let tcp_pool = Arc::new(ConnectionPool::new());
    let tls_pool = Arc::new(TlsPool::new());

    // Create transport dispatcher
    let dispatcher = Arc::new(SiphonTransportDispatcher::new(
        udp_socket,
        Arc::new(DefaultTransportPolicy::default()),
        tcp_pool,
        tls_pool,
        None, // TLS client config - TODO: load if needed
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

    // Spawn TLS listener if certificate and key are provided
    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        match load_rustls_server_config(cert, key) {
            Ok(config) => {
                let bind = tls_bind.to_string();
                tokio::spawn(async move {
                    if let Err(e) = run_tls(&bind, config, tx).await {
                        tracing::error!(%e, "TLS listener exited");
                    }
                });
            }
            Err(e) => {
                warn!(%e, "Failed to load TLS config; TLS disabled");
            }
        }
    } else if tls_cert.is_some() || tls_key.is_some() {
        warn!("Both --tls-cert and --tls-key must be provided to enable TLS");
    }

    Ok(dispatcher)
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
        let desired = to_sip_transport(ctx.transport);
        let selected = self.policy.choose(
            desired,
            payload.len(),
            matches!(ctx.transport, TransportKind::Tls),
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
                    let server_name = ctx.peer.ip().to_string();
                    self.tls_pool
                        .send_tls(ctx.peer, server_name, cfg, payload)
                        .await?;
                }
            }
            sip_transport::TransportKind::Sctp | sip_transport::TransportKind::TlsSctp => {
                return Err(anyhow!("SCTP transport not supported"));
            }
        }

        Ok(())
    }
}

fn to_sip_transport(kind: TransportKind) -> sip_transport::TransportKind {
    match kind {
        TransportKind::Udp => sip_transport::TransportKind::Udp,
        TransportKind::Tcp => sip_transport::TransportKind::Tcp,
        TransportKind::Tls => sip_transport::TransportKind::Tls,
    }
}
