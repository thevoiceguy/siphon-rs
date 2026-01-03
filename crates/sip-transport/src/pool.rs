// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{
        mpsc::{self, Sender},
        Mutex,
    },
};
use tracing::{debug, warn};

use crate::{drain_sip_frames, InboundPacket, TransportKind, MAX_BUFFER_SIZE};

/// Maximum number of pooled TCP connections (prevents file descriptor exhaustion).
const MAX_POOL_SIZE: usize = 1000;

/// Idle timeout for pooled connections (close after 5 minutes of inactivity).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Connection entry with activity tracking for eviction.
#[derive(Debug, Clone)]
struct PoolEntry {
    sender: Sender<Bytes>,
    last_used: Instant,
}

impl PoolEntry {
    fn new(sender: Sender<Bytes>) -> Self {
        Self {
            sender,
            last_used: Instant::now(),
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    fn is_idle(&self, timeout: Duration) -> bool {
        self.last_used.elapsed() > timeout
    }
}

/// TCP connection pool with idle timeout and size limits.
#[derive(Debug)]
pub struct ConnectionPool {
    tcp: DashMap<SocketAddr, PoolEntry>,
    max_size: usize,
    idle_timeout: Duration,
    inbound_tx: Arc<Mutex<Option<Sender<InboundPacket>>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            tcp: DashMap::new(),
            max_size: MAX_POOL_SIZE,
            idle_timeout: IDLE_TIMEOUT,
            inbound_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates a new pool with custom limits.
    pub fn with_limits(max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            tcp: DashMap::new(),
            max_size,
            idle_timeout,
            inbound_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Registers an inbound packet sink so responses on outbound TCP connections
    /// get routed back into the SIP handler/transaction layer.
    pub async fn set_inbound_tx(&self, tx: Sender<InboundPacket>) {
        debug!("ConnectionPool: set_inbound_tx called, enabling TCP client reader tasks");
        let mut guard = self.inbound_tx.lock().await;
        *guard = Some(tx);
    }

    /// Returns the current number of pooled connections.
    pub fn len(&self) -> usize {
        self.tcp.len()
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty()
    }

    /// Removes idle connections that exceed the idle timeout.
    pub fn cleanup_idle(&self) -> usize {
        let mut removed = 0;
        self.tcp.retain(|addr, entry| {
            if entry.is_idle(self.idle_timeout) {
                debug!(peer = %addr, "removing idle connection");
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Evicts the least recently used connections to make room.
    /// Removes approximately 10% of capacity.
    fn evict_lru(&self) {
        let evict_count = (self.max_size / 10).max(1);

        // Collect entries sorted by last_used (oldest first)
        let mut entries: Vec<_> = self
            .tcp
            .iter()
            .map(|entry| (*entry.key(), entry.value().last_used))
            .collect();

        entries.sort_by_key(|(_, last_used)| *last_used);

        // Remove oldest entries
        for (addr, _) in entries.iter().take(evict_count) {
            debug!(peer = %addr, "evicting LRU connection");
            self.tcp.remove(addr);
        }
    }

    /// Sends bytes over a pooled TCP connection; opens one if missing.
    pub async fn send_tcp(&self, addr: SocketAddr, payload: Bytes) -> Result<()> {
        // Try to use existing connection
        if let Some(mut entry) = self.tcp.get_mut(&addr) {
            entry.touch(); // Update last activity time
            if entry.sender.send(payload.clone()).await.is_ok() {
                return Ok(());
            }
            // Connection failed, remove it
            drop(entry);
            self.tcp.remove(&addr);
        }

        // Check if we need to make room
        if self.tcp.len() >= self.max_size {
            // Try cleanup first
            self.cleanup_idle();

            // If still at capacity, evict LRU
            if self.tcp.len() >= self.max_size {
                self.evict_lru();
            }
        }

        // Create new connection
        let stream = TcpStream::connect(addr).await?;
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        self.tcp.insert(addr, PoolEntry::new(tx.clone()));

        // Writer task (existing behavior)
        let writer_tx = tx.clone();
        tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
                // Flush the stream to ensure data is sent on the wire
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // Optional reader task to deliver responses back to the inbound pipeline
        if let Some(inbound_tx) = self.inbound_tx.lock().await.clone() {
            let peer = addr;
            debug!(peer = %peer, "spawning TCP client reader task for outbound connection");
            tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(4096);
                debug!(peer = %peer, "TCP client reader task started");
                loop {
                    if buf.len() >= MAX_BUFFER_SIZE {
                        warn!(
                            peer = %peer,
                            buffer_size = buf.len(),
                            "tcp client buffer exceeded MAX_BUFFER_SIZE, closing connection"
                        );
                        break;
                    }

                    match reader.read_buf(&mut buf).await {
                        Ok(0) => {
                            debug!(peer = %peer, "TCP client connection closed by peer");
                            break;
                        }
                        Ok(n) => {
                            debug!(peer = %peer, bytes = n, "TCP client read {} bytes", n);
                            match drain_sip_frames(&mut buf) {
                                Ok(frames) => {
                                    debug!(peer = %peer, frame_count = frames.len(), "TCP client drained {} SIP frames", frames.len());
                                    for payload in frames {
                                        // Extract first line for logging
                                        let first_line = payload
                                            .split(|&b| b == b'\r' || b == b'\n')
                                            .next()
                                            .and_then(|line| std::str::from_utf8(line).ok())
                                            .unwrap_or("<invalid>");
                                        debug!(peer = %peer, first_line = %first_line, "TCP client sending frame to inbound_tx");

                                        let packet = InboundPacket {
                                            transport: TransportKind::Tcp,
                                            peer,
                                            payload,
                                            stream: Some(writer_tx.clone()),
                                        };
                                        if inbound_tx.send(packet).await.is_err() {
                                            warn!(peer = %peer, "TCP client inbound_tx channel closed");
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                warn!(
                                    peer = %peer,
                                    error = %e,
                                    "tcp client framing error, closing connection"
                                );
                                break;
                            }
                        }
                        },
                        Err(e) => {
                            warn!(
                                peer = %peer,
                                error = %e,
                                "tcp client read error, closing connection"
                            );
                            break;
                        }
                    }
                }
            });
        }

        let result = tx
            .send(payload)
            .await
            .map_err(|_| anyhow!("connection writer closed"));
        if result.is_err() {
            self.tcp.remove(&addr);
        }
        result
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tls")]
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig},
    TlsConnector,
};

#[cfg(feature = "tls")]
/// TLS connection pool with idle timeout and size limits.
#[derive(Debug, Default)]
pub struct TlsPool {
    inner: DashMap<(SocketAddr, String), PoolEntry>,
    max_size: usize,
    idle_timeout: Duration,
}

#[cfg(feature = "tls")]
pub type TlsClientConfig = ClientConfig;

#[cfg(feature = "tls")]
impl TlsPool {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            max_size: MAX_POOL_SIZE,
            idle_timeout: IDLE_TIMEOUT,
        }
    }

    /// Creates a new pool with custom limits.
    pub fn with_limits(max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            max_size,
            idle_timeout,
        }
    }

    /// Returns the current number of pooled connections.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Removes idle connections that exceed the idle timeout.
    pub fn cleanup_idle(&self) -> usize {
        let mut removed = 0;
        self.inner.retain(|(addr, _), entry| {
            if entry.is_idle(self.idle_timeout) {
                debug!(peer = %addr, "removing idle TLS connection");
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Evicts the least recently used connections to make room.
    /// Removes approximately 10% of capacity.
    fn evict_lru(&self) {
        let evict_count = (self.max_size / 10).max(1);

        // Collect entries sorted by last_used (oldest first)
        let mut entries: Vec<_> = self
            .inner
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().last_used))
            .collect();

        entries.sort_by_key(|(_, last_used)| *last_used);

        // Remove oldest entries
        for (key, _) in entries.iter().take(evict_count) {
            debug!(peer = %key.0, server = %key.1, "evicting LRU TLS connection");
            self.inner.remove(key);
        }
    }

    pub async fn send_tls(
        &self,
        addr: SocketAddr,
        server_name: String,
        config: std::sync::Arc<ClientConfig>,
        payload: Bytes,
    ) -> Result<()> {
        let key = (addr, server_name.clone());

        // Try to use existing connection
        if let Some(mut entry) = self.inner.get_mut(&key) {
            entry.touch(); // Update last activity time
            if entry.sender.send(payload.clone()).await.is_ok() {
                return Ok(());
            }
            // Connection failed, remove it
            drop(entry);
            self.inner.remove(&key);
        }

        // Check if we need to make room
        if self.inner.len() >= self.max_size {
            // Try cleanup first
            self.cleanup_idle();

            // If still at capacity, evict LRU
            if self.inner.len() >= self.max_size {
                self.evict_lru();
            }
        }

        // Create new connection
        let connector = TlsConnector::from(config.clone());
        let server_name =
            ServerName::try_from(server_name).map_err(|_| anyhow!("invalid TLS server name"))?;
        let stream = TcpStream::connect(addr).await?;
        let mut tls_stream = connector.connect(server_name, stream).await?;

        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        self.inner.insert(key.clone(), PoolEntry::new(tx.clone()));

        tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if tls_stream.write_all(&buf).await.is_err() {
                    break;
                }
                // Flush the stream to ensure data is sent on the wire
                if tls_stream.flush().await.is_err() {
                    break;
                }
            }
            // Perform proper TLS shutdown when connection closes
            let _ = tls_stream.shutdown().await;
        });

        let result = tx
            .send(payload)
            .await
            .map_err(|_| anyhow!("tls connection writer closed"));
        if result.is_err() {
            self.inner.remove(&key);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn pool_entry_tracks_activity() {
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        let mut entry = PoolEntry::new(tx);

        let initial = entry.last_used;
        std::thread::sleep(Duration::from_millis(10));
        entry.touch();

        assert!(entry.last_used > initial, "touch() should update last_used");
    }

    #[test]
    fn pool_entry_detects_idle() {
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        let entry = PoolEntry::new(tx);

        // Should not be idle immediately
        assert!(!entry.is_idle(Duration::from_secs(1)));

        // Simulate old entry
        let old_entry = PoolEntry {
            sender: entry.sender,
            last_used: Instant::now() - Duration::from_secs(10),
        };

        assert!(old_entry.is_idle(Duration::from_secs(5)));
    }

    #[test]
    fn connection_pool_respects_max_size() {
        let pool = ConnectionPool::with_limits(10, Duration::from_secs(60));

        // Manually insert entries to simulate pool usage
        for i in 0..15 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060 + i);
            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            pool.tcp.insert(addr, PoolEntry::new(tx));
        }

        assert_eq!(pool.len(), 15);

        // Trigger eviction
        pool.evict_lru();

        // Should have removed ~10% (1-2 entries)
        assert!(pool.len() < 15);
        assert!(pool.len() >= 13); // Should remove at least 1
    }

    #[test]
    fn connection_pool_cleanup_removes_idle() {
        let pool = ConnectionPool::with_limits(100, Duration::from_millis(50));

        // Add some connections
        for i in 0..5 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060 + i);
            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            pool.tcp.insert(addr, PoolEntry::new(tx));
        }

        assert_eq!(pool.len(), 5);

        // Wait for idle timeout
        std::thread::sleep(Duration::from_millis(60));

        // Cleanup should remove all entries
        let removed = pool.cleanup_idle();
        assert_eq!(removed, 5);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn connection_pool_preserves_active_connections() {
        let pool = ConnectionPool::with_limits(100, Duration::from_millis(50));

        // Add connections
        for i in 0..5 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060 + i);
            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            pool.tcp.insert(addr, PoolEntry::new(tx));
        }

        // Keep some active by touching them
        let active_addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5061),
        ];

        // Wait a bit then touch active connections
        std::thread::sleep(Duration::from_millis(30));
        for addr in &active_addrs {
            if let Some(mut entry) = pool.tcp.get_mut(addr) {
                entry.touch();
            }
        }

        // Wait for idle timeout of untouched connections
        std::thread::sleep(Duration::from_millis(30));

        let removed = pool.cleanup_idle();
        assert_eq!(removed, 3, "Should remove 3 idle connections");
        assert_eq!(pool.len(), 2, "Should preserve 2 active connections");

        // Verify the active ones are still there
        for addr in &active_addrs {
            assert!(pool.tcp.contains_key(addr));
        }
    }

    #[test]
    fn connection_pool_len_and_empty() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060);
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        pool.tcp.insert(addr, PoolEntry::new(tx));

        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_pool_respects_max_size() {
        let pool = TlsPool::with_limits(10, Duration::from_secs(60));

        // Manually insert entries
        for i in 0..15 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5061 + i);
            let key = (addr, format!("host{}.example.com", i));
            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            pool.inner.insert(key, PoolEntry::new(tx));
        }

        assert_eq!(pool.len(), 15);

        // Trigger eviction
        pool.evict_lru();

        assert!(pool.len() < 15);
        assert!(pool.len() >= 13);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_pool_cleanup_removes_idle() {
        let pool = TlsPool::with_limits(100, Duration::from_millis(50));

        // Add some connections
        for i in 0..5 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5061 + i);
            let key = (addr, format!("host{}.example.com", i));
            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            pool.inner.insert(key, PoolEntry::new(tx));
        }

        assert_eq!(pool.len(), 5);

        // Wait for idle timeout
        std::thread::sleep(Duration::from_millis(60));

        // Cleanup should remove all entries
        let removed = pool.cleanup_idle();
        assert_eq!(removed, 5);
        assert_eq!(pool.len(), 0);
    }
}
