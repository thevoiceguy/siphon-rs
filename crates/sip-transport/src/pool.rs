use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::mpsc::{self, Sender},
};

/// Simple TCP connection pool that reuses writer channels per peer.
#[derive(Debug, Default)]
pub struct ConnectionPool {
    tcp: DashMap<SocketAddr, Sender<Bytes>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends bytes over a pooled TCP connection; opens one if missing.
    pub async fn send_tcp(&self, addr: SocketAddr, payload: Bytes) -> Result<()> {
        if let Some(sender) = self.tcp.get(&addr) {
            if sender.send(payload.clone()).await.is_ok() {
                return Ok(());
            }
            self.tcp.remove(&addr);
        }
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        self.tcp.insert(addr, tx.clone());
        tokio::spawn(async move {
            if let Ok(mut stream) = TcpStream::connect(addr).await {
                while let Some(buf) = rx.recv().await {
                    if stream.write_all(&buf).await.is_err() {
                        break;
                    }
                }
            }
        });
        tx.send(payload)
            .await
            .map_err(|_| anyhow!("connection writer closed"))
    }
}

#[cfg(feature = "tls")]
use tokio_rustls::{
    rustls::{ClientConfig, pki_types::ServerName},
    TlsConnector,
};

#[cfg(feature = "tls")]
/// Simple TLS connection pool keyed by (addr, server_name).
#[derive(Debug, Default)]
pub struct TlsPool {
    inner: DashMap<(SocketAddr, String), Sender<Bytes>>,
}

#[cfg(feature = "tls")]
pub type TlsClientConfig = ClientConfig;

#[cfg(feature = "tls")]
impl TlsPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn send_tls(
        &self,
        addr: SocketAddr,
        server_name: String,
        config: std::sync::Arc<ClientConfig>,
        payload: Bytes,
    ) -> Result<()> {
        let key = (addr, server_name.clone());
        if let Some(sender) = self.inner.get(&key) {
            if sender.send(payload.clone()).await.is_ok() {
                return Ok(());
            }
            self.inner.remove(&key);
        }

        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        self.inner.insert(key.clone(), tx.clone());
        let connector = TlsConnector::from(config.clone());
        tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await;
            let server_name = match ServerName::try_from(server_name.clone()) {
                Ok(sn) => sn,
                Err(_) => return,
            };
            if let Ok(stream) = stream {
                if let Ok(mut tls_stream) = connector.connect(server_name, stream).await {
                    while let Some(buf) = rx.recv().await {
                        if tls_stream.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        tx.send(payload)
            .await
            .map_err(|_| anyhow!("tls connection writer closed"))
    }
}
