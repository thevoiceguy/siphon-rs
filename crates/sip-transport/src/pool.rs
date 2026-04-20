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
        Mutex, OwnedSemaphorePermit, Semaphore,
    },
};
use tracing::{debug, warn};

use crate::{drain_sip_frames, InboundPacket, TransportKind, MAX_BUFFER_SIZE};

/// Maximum number of pooled TCP connections (prevents file descriptor exhaustion).
const MAX_POOL_SIZE: usize = 1000;

/// Idle timeout for pooled connections (close after 5 minutes of inactivity).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Connection entry with activity tracking for eviction.
#[derive(Debug)]
struct PoolEntry {
    sender: Sender<Bytes>,
    last_used: Instant,
    /// Abort handles for spawned tasks (writer + reader) to clean up on eviction.
    task_handles: Vec<tokio::task::AbortHandle>,
    /// Semaphore permit reserving this entry's slot in the pool. Dropping
    /// the PoolEntry releases the permit, which is what enforces the cap
    /// atomically across concurrent inserts.
    _permit: OwnedSemaphorePermit,
}

impl Drop for PoolEntry {
    fn drop(&mut self) {
        for handle in &self.task_handles {
            handle.abort();
        }
    }
}

impl PoolEntry {
    fn new(sender: Sender<Bytes>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            sender,
            last_used: Instant::now(),
            task_handles: Vec::new(),
            _permit: permit,
        }
    }

    /// Test-only constructor that mints a fresh semaphore permit. Tests that
    /// poke the pool's internals directly don't go through `reserve_slot`,
    /// so this gives them a no-op permit to satisfy the type.
    #[cfg(test)]
    fn for_tests(sender: Sender<Bytes>) -> Self {
        let sema = Arc::new(Semaphore::new(1));
        let permit = sema.try_acquire_owned().expect("permit available");
        Self::new(sender, permit)
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    fn is_idle(&self, timeout: Duration) -> bool {
        self.last_used.elapsed() > timeout
    }
}

/// Connection pool with idle timeout and size limits for TCP and WebSocket.
#[derive(Debug)]
pub struct ConnectionPool {
    tcp: DashMap<SocketAddr, PoolEntry>,
    #[cfg(feature = "ws")]
    ws: DashMap<String, PoolEntry>,
    max_size: usize,
    idle_timeout: Duration,
    inbound_tx: Arc<Mutex<Option<Sender<InboundPacket>>>>,
    /// One permit per pool slot. Held by `PoolEntry::_permit` so the cap is
    /// enforced atomically: callers must successfully `try_acquire_owned`
    /// before opening a new connection, and the slot is freed automatically
    /// when the entry is dropped (eviction, send failure, idle cleanup).
    /// Shared across TCP and WS so the total connection count is the cap.
    permits: Arc<Semaphore>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            tcp: DashMap::new(),
            #[cfg(feature = "ws")]
            ws: DashMap::new(),
            max_size: MAX_POOL_SIZE,
            idle_timeout: IDLE_TIMEOUT,
            inbound_tx: Arc::new(Mutex::new(None)),
            permits: Arc::new(Semaphore::new(MAX_POOL_SIZE)),
        }
    }

    /// Creates a new pool with custom limits.
    pub fn with_limits(max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            tcp: DashMap::new(),
            #[cfg(feature = "ws")]
            ws: DashMap::new(),
            max_size,
            idle_timeout,
            inbound_tx: Arc::new(Mutex::new(None)),
            permits: Arc::new(Semaphore::new(max_size)),
        }
    }

    /// Reserves a slot in the pool, atomically. Tries to acquire a permit;
    /// if none is available, runs `cleanup_idle` (which drops idle entries
    /// and releases their permits) and retries; if still saturated, evicts
    /// LRU entries and retries one last time. Returns `None` only when even
    /// after eviction every slot is held by a fresh, in-use connection.
    fn reserve_slot(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(p) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(p);
        }
        self.cleanup_idle();
        if let Ok(p) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(p);
        }
        self.evict_lru();
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    /// Registers an inbound packet sink so responses on outbound TCP connections
    /// get routed back into the SIP handler/transaction layer.
    pub async fn set_inbound_tx(&self, tx: Sender<InboundPacket>) {
        debug!("ConnectionPool: set_inbound_tx called, enabling TCP client reader tasks");
        let mut guard = self.inbound_tx.lock().await;
        *guard = Some(tx);
    }

    /// Returns the current number of pooled connections (TCP + WS).
    pub fn len(&self) -> usize {
        let count = self.tcp.len();
        #[cfg(feature = "ws")]
        let count = count + self.ws.len();
        count
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        let empty = self.tcp.is_empty();
        #[cfg(feature = "ws")]
        let empty = empty && self.ws.is_empty();
        empty
    }

    /// Removes idle connections that exceed the idle timeout.
    pub fn cleanup_idle(&self) -> usize {
        let mut removed = 0;
        self.tcp.retain(|addr, entry| {
            if entry.is_idle(self.idle_timeout) {
                debug!(peer = %addr, "removing idle TCP connection");
                removed += 1;
                false
            } else {
                true
            }
        });
        #[cfg(feature = "ws")]
        self.ws.retain(|url, entry| {
            if entry.is_idle(self.idle_timeout) {
                debug!(url = %url, "removing idle WS connection");
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
        debug!(peer = %addr, "send_tcp called");

        // Try to use existing connection
        if let Some(mut entry) = self.tcp.get_mut(&addr) {
            debug!(peer = %addr, "found existing TCP connection, reusing");
            entry.touch(); // Update last activity time
            if entry.sender.send(payload.clone()).await.is_ok() {
                debug!(peer = %addr, "reused existing TCP connection successfully");
                return Ok(());
            }
            // Connection failed, remove it
            debug!(peer = %addr, "existing TCP connection failed, removing");
            drop(entry);
            self.tcp.remove(&addr);
        }

        debug!(peer = %addr, "no existing connection found, creating new TCP connection");

        // Atomically reserve a slot before doing anything expensive (DNS,
        // TCP connect, TLS handshake). If we cannot reserve — even after
        // dropping idle entries and evicting LRU — bail out *before*
        // opening a socket so concurrent callers can't blow the pool cap.
        let permit = self
            .reserve_slot()
            .ok_or_else(|| anyhow!("connection pool exhausted ({} slots)", self.max_size))?;

        // Create new connection with timeout
        debug!(peer = %addr, "connecting to TCP peer");
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| anyhow!("TCP pool connect timeout after 5s to {}", addr))?
        ?;
        debug!(peer = %addr, "TCP connection established");
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let mut entry = PoolEntry::new(tx.clone(), permit);
        debug!(peer = %addr, "creating new pool entry");

        // Writer task
        let writer_tx = tx.clone();
        let writer_handle = tokio::spawn(async move {
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
        entry.task_handles.push(writer_handle.abort_handle());

        // Optional reader task to deliver responses back to the inbound pipeline
        let inbound_tx_guard = self.inbound_tx.lock().await;
        let has_inbound_tx = inbound_tx_guard.is_some();
        debug!(peer = %addr, has_inbound_tx = %has_inbound_tx, "checking if inbound_tx is set");

        if let Some(inbound_tx) = inbound_tx_guard.clone() {
            drop(inbound_tx_guard);
            let peer = addr;
            debug!(peer = %peer, "spawning TCP client reader task for outbound connection");
            let reader_handle = tokio::spawn(async move {
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
                        }
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
            entry.task_handles.push(reader_handle.abort_handle());
        } else {
            drop(inbound_tx_guard);
            debug!(peer = %addr, "inbound_tx is None, skipping TCP client reader task");
        }

        self.tcp.insert(addr, entry);
        debug!(peer = %addr, "inserted connection into pool");

        let result = tx
            .send(payload)
            .await
            .map_err(|_| anyhow!("connection writer closed"));
        if result.is_err() {
            self.tcp.remove(&addr);
        }
        result
    }

    /// Sends bytes over a pooled WebSocket connection; opens one if missing.
    ///
    /// The connection is keyed by `url` (e.g. `ws://host:port/`). If an
    /// existing connection is cached and alive, the payload is sent as a
    /// `Binary` WebSocket frame on that connection. If the cached connection
    /// has dropped, or no cached connection exists, a new connection is
    /// opened (with the RFC 7118 `sip` subprotocol negotiation) and cached.
    ///
    /// A background reader task is spawned per connection (when
    /// `set_inbound_tx` has been called) to route WS frames received from
    /// the peer back into the inbound handler, so that responses on the
    /// same WS connection are processed correctly.
    #[cfg(feature = "ws")]
    pub async fn send_ws(&self, url: &str, payload: Bytes) -> Result<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::{
            client::IntoClientRequest, http::header::HeaderValue, Message,
        };

        let key = url.to_string();
        debug!(url = %key, "send_ws called");

        // Try to use existing connection
        if let Some(mut entry) = self.ws.get_mut(&key) {
            entry.touch();
            if entry.sender.send(payload.clone()).await.is_ok() {
                debug!(url = %key, "reused existing WS connection successfully");
                return Ok(());
            }
            drop(entry);
            self.ws.remove(&key);
            debug!(url = %key, "existing WS connection failed, removed");
        }

        // Atomically reserve a slot (shared semaphore across TCP and WS) so
        // we can't blow the pool cap by racing concurrent callers.
        let permit = self
            .reserve_slot()
            .ok_or_else(|| anyhow!("connection pool exhausted ({} slots)", self.max_size))?;

        // Open new WS connection
        debug!(url = %key, "opening new WS connection");
        let mut request = key.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));

        let (ws_stream, _response) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio_tungstenite::connect_async(request),
        )
        .await
        .map_err(|_| anyhow!("WS connect timeout after 5s to {}", key))?
        ?;

        crate::transport_metrics().on_connect(crate::TransportLabel::Ws);
        debug!(url = %key, "WS connection established");

        let (mut sink, mut stream) = ws_stream.split();
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let mut entry = PoolEntry::new(tx.clone(), permit);

        // Writer task — reads from channel and sends WS Binary frames
        let writer_key = key.clone();
        let writer_handle = tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if sink.send(Message::Binary(buf.to_vec())).await.is_err() {
                    debug!(url = %writer_key, "WS writer: send failed, exiting");
                    break;
                }
                crate::transport_metrics().on_packet_sent(crate::TransportLabel::Ws);
            }
        });
        entry.task_handles.push(writer_handle.abort_handle());

        // Optional reader task — feeds received frames back to inbound handler
        let inbound_tx_guard = self.inbound_tx.lock().await;
        if let Some(inbound_tx) = inbound_tx_guard.clone() {
            drop(inbound_tx_guard);
            // We need the peer SocketAddr for the InboundPacket. Parse it
            // from the URL host:port. If that fails (unlikely for a just-
            // connected URL), skip the reader — outbound-only is still useful.
            let peer_addr = parse_ws_peer_addr(&key);
            if let Some(peer) = peer_addr {
                let reader_key = key.clone();
                let reader_handle = tokio::spawn(async move {
                    while let Some(msg) = stream.next().await {
                        match msg {
                            Ok(Message::Binary(data)) => {
                                let packet = InboundPacket {
                                    transport: TransportKind::Ws,
                                    peer,
                                    payload: Bytes::from(data),
                                    stream: None,
                                };
                                if inbound_tx.send(packet).await.is_err() {
                                    debug!(url = %reader_key, "WS reader: inbound channel closed");
                                    break;
                                }
                            }
                            Ok(Message::Text(text)) => {
                                let packet = InboundPacket {
                                    transport: TransportKind::Ws,
                                    peer,
                                    payload: Bytes::from(text.into_bytes()),
                                    stream: None,
                                };
                                if inbound_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Message::Close(_)) => {
                                debug!(url = %reader_key, "WS reader: peer sent Close");
                                break;
                            }
                            Ok(_) => {} // Ping/Pong handled by tungstenite
                            Err(e) => {
                                debug!(url = %reader_key, error = %e, "WS reader: error");
                                break;
                            }
                        }
                    }
                });
                entry.task_handles.push(reader_handle.abort_handle());
            }
        } else {
            drop(inbound_tx_guard);
        }

        self.ws.insert(key.clone(), entry);

        let result = tx
            .send(payload)
            .await
            .map_err(|_| anyhow!("WS connection writer closed"));
        if result.is_err() {
            self.ws.remove(&key);
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

/// Parse the peer SocketAddr from a ws[s]://host:port/ URL.
///
/// Returns `None` when the host cannot be resolved to an IP or the port is
/// missing and not inferable from the scheme.
#[cfg(feature = "ws")]
fn parse_ws_peer_addr(url: &str) -> Option<SocketAddr> {
    // Strip scheme: ws:// or wss://
    let rest = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))?;
    let default_port: u16 = if url.starts_with("wss") { 443 } else { 80 };
    // Strip path / query
    let authority = rest.split('/').next().unwrap_or(rest);
    // Handle IPv6 brackets: [::1]:port
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port_str) = bracketed.split_once(']')?;
        let port = port_str
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        let ip: std::net::IpAddr = host.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    } else {
        // IPv4 or hostname — if it's a hostname we can't resolve it without
        // async DNS, so just try parsing as an IP.
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().unwrap_or(default_port)),
            None => (authority, default_port),
        };
        let ip: std::net::IpAddr = host.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    }
}

#[cfg(feature = "tls")]
/// TLS connection pool with idle timeout and size limits.
#[derive(Debug)]
pub struct TlsPool {
    inner: DashMap<(SocketAddr, String), PoolEntry>,
    max_size: usize,
    idle_timeout: Duration,
    /// Permits enforcing the pool cap atomically; see ConnectionPool.
    permits: Arc<Semaphore>,
    /// Inbound packet sink. When set, each `send_tls`-opened connection
    /// spawns a reader task that drains SIP frames and forwards them here.
    /// Without this, responses to outbound TLS requests (e.g. 200 OK to
    /// REGISTER, 1xx/2xx to INVITE) are silently dropped because the
    /// receiving end of the TLS socket is never read.
    inbound_tx: Arc<Mutex<Option<Sender<InboundPacket>>>>,
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
            permits: Arc::new(Semaphore::new(MAX_POOL_SIZE)),
            inbound_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates a new pool with custom limits.
    pub fn with_limits(max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            max_size,
            idle_timeout,
            permits: Arc::new(Semaphore::new(max_size)),
            inbound_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Registers an inbound packet sink so responses on outbound TLS
    /// connections get routed back into the SIP handler/transaction layer.
    /// Symmetric with `ConnectionPool::set_inbound_tx`.
    pub async fn set_inbound_tx(&self, tx: Sender<InboundPacket>) {
        let mut guard = self.inbound_tx.lock().await;
        *guard = Some(tx);
    }

    /// Atomic permit reservation; see `ConnectionPool::reserve_slot`.
    fn reserve_slot(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(p) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(p);
        }
        self.cleanup_idle();
        if let Ok(p) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(p);
        }
        self.evict_lru();
        Arc::clone(&self.permits).try_acquire_owned().ok()
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

        // Atomically reserve a slot before connecting; see ConnectionPool.
        let permit = self
            .reserve_slot()
            .ok_or_else(|| anyhow!("TLS pool exhausted ({} slots)", self.max_size))?;

        // Create new connection with timeout
        let connector = TlsConnector::from(config.clone());
        let server_name =
            ServerName::try_from(server_name).map_err(|_| anyhow!("invalid TLS server name"))?;
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| anyhow!("TLS pool connect timeout after 5s to {}", addr))?
        ?;
        let tls_stream = connector.connect(server_name, stream).await?;
        // Split so the reader and writer tasks own separate halves; without
        // this the writer task holds the only handle to the TLS stream and
        // we never read responses (the original send_tls bug).
        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let writer_tx = tx.clone();
        let mut entry = PoolEntry::new(tx.clone(), permit);

        let writer_handle = tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
                // Flush the stream to ensure data is sent on the wire
                if writer.flush().await.is_err() {
                    break;
                }
            }
            // Perform proper TLS shutdown when connection closes.
            let _ = writer.shutdown().await;
        });
        entry.task_handles.push(writer_handle.abort_handle());

        // Optional reader task to deliver responses back to the inbound
        // pipeline. Mirrors ConnectionPool::send_tcp's reader-task pattern;
        // previously absent, which silently swallowed responses to all
        // outbound TLS requests.
        let inbound_tx_guard = self.inbound_tx.lock().await;
        if let Some(inbound_tx) = inbound_tx_guard.clone() {
            drop(inbound_tx_guard);
            let peer = addr;
            let reader_handle = tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(4096);
                loop {
                    if buf.len() >= MAX_BUFFER_SIZE {
                        warn!(
                            peer = %peer,
                            buffer_size = buf.len(),
                            "tls client buffer exceeded MAX_BUFFER_SIZE, closing connection"
                        );
                        break;
                    }
                    match reader.read_buf(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => match drain_sip_frames(&mut buf) {
                            Ok(frames) => {
                                for payload in frames {
                                    let packet = InboundPacket {
                                        transport: TransportKind::Tls,
                                        peer,
                                        payload,
                                        stream: Some(writer_tx.clone()),
                                    };
                                    if inbound_tx.send(packet).await.is_err() {
                                        warn!(peer = %peer, "tls client inbound_tx channel closed");
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    peer = %peer,
                                    error = %e,
                                    "tls client framing error, closing connection"
                                );
                                break;
                            }
                        },
                        Err(e) => {
                            warn!(
                                peer = %peer,
                                error = %e,
                                "tls client read error, closing connection"
                            );
                            break;
                        }
                    }
                }
            });
            entry.task_handles.push(reader_handle.abort_handle());
        } else {
            drop(inbound_tx_guard);
        }

        self.inner.insert(key.clone(), entry);

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
        let mut entry = PoolEntry::for_tests(tx);

        let initial = entry.last_used;
        std::thread::sleep(Duration::from_millis(10));
        entry.touch();

        assert!(entry.last_used > initial, "touch() should update last_used");
    }

    #[test]
    fn pool_entry_detects_idle() {
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        let entry = PoolEntry::for_tests(tx);

        // Should not be idle immediately
        assert!(!entry.is_idle(Duration::from_secs(1)));

        // Simulate old entry
        let (tx2, _rx2) = mpsc::channel::<Bytes>(1);
        let mut old_entry = PoolEntry::for_tests(tx2);
        old_entry.last_used = Instant::now() - Duration::from_secs(10);

        assert!(old_entry.is_idle(Duration::from_secs(5)));
    }

    #[test]
    fn connection_pool_respects_max_size() {
        let pool = ConnectionPool::with_limits(10, Duration::from_secs(60));

        // Manually insert entries to simulate pool usage
        for i in 0..15 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060 + i);
            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            pool.tcp.insert(addr, PoolEntry::for_tests(tx));
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
            pool.tcp.insert(addr, PoolEntry::for_tests(tx));
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
            pool.tcp.insert(addr, PoolEntry::for_tests(tx));
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

    /// Hammer `reserve_slot` from many threads to confirm the semaphore
    /// never permits more than `max_size` entries to be alive at once.
    /// Without the semaphore the previous len()-then-insert could be
    /// raced; this is the regression test for that.
    #[test]
    fn reserve_slot_caps_concurrent_acquisitions() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let max = 8;
        let pool = Arc::new(ConnectionPool::with_limits(max, Duration::from_secs(60)));
        let alive = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..32 {
            let pool = Arc::clone(&pool);
            let alive = Arc::clone(&alive);
            let peak = Arc::clone(&peak);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    if let Some(_permit) = pool.reserve_slot() {
                        let now = alive.fetch_add(1, Ordering::AcqRel) + 1;
                        peak.fetch_max(now, Ordering::AcqRel);
                        // Hold the permit briefly to actually contend.
                        std::thread::sleep(Duration::from_micros(50));
                        alive.fetch_sub(1, Ordering::AcqRel);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let observed_peak = peak.load(Ordering::Acquire);
        assert!(
            observed_peak <= max,
            "pool cap breached: peak {observed_peak} > {max}"
        );
        // We expect the cap to actually be reached under contention; if not,
        // the test isn't actually exercising the semaphore. Tolerate a small
        // gap in case scheduling stays unfair on tiny machines.
        assert!(
            observed_peak >= max / 2,
            "test didn't contend enough; peak={observed_peak}"
        );
    }

    #[test]
    fn connection_pool_len_and_empty() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060);
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        pool.tcp.insert(addr, PoolEntry::for_tests(tx));

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
            pool.inner.insert(key, PoolEntry::for_tests(tx));
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
            pool.inner.insert(key, PoolEntry::for_tests(tx));
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
