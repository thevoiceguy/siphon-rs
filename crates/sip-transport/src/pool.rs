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
        broadcast,
        mpsc::{self, Sender},
        Mutex, OwnedSemaphorePermit, Semaphore,
    },
};
use tracing::{debug, warn};

/// Events surfaced from the pool as connections die or encounter
/// errors. Observers subscribe via
/// [`ConnectionPool::subscribe_events`] /
/// [`TlsPool::subscribe_events`] and use the stream for logging,
/// metrics, or a per-application reconnect policy.
///
/// RFC 3261 §18.4 requires transport errors to surface to the
/// transaction layer. The existing `dispatch_with_pool` path does
/// that reactively — on the next send the transaction notices the
/// failure and fires `TransportError` on its FSM. This event stream
/// is complementary: it gives proactive visibility so operators can
/// see the failure at the moment it happens, even for idle
/// connections that aren't currently driving a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// A connection was closed cleanly (peer FIN, graceful shutdown,
    /// idle sweeper). The pool entry has been removed.
    Closed {
        transport: TransportKind,
        peer: SocketAddr,
    },
    /// A connection failed (write / read / flush error, connect
    /// timeout, TLS handshake failure). The pool entry has been
    /// removed; the next send to this peer will open a fresh one.
    Failed {
        transport: TransportKind,
        peer: SocketAddr,
        reason: String,
    },
}

/// Default capacity of the pool event broadcast channel. Slow
/// subscribers see Lagged if they fall behind by more than this;
/// events are still delivered to subscribers that keep up.
const CONNECTION_EVENT_CHANNEL_CAPACITY: usize = 256;

use crate::{drain_sip_frames, InboundPacket, TransportKind, MAX_BUFFER_SIZE};

/// Maximum number of pooled TCP connections (prevents file descriptor exhaustion).
const MAX_POOL_SIZE: usize = 1000;

/// Idle timeout for pooled connections (close after 5 minutes of inactivity).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default outbound CRLF keepalive interval (RFC 6223 / RFC 5626 §3.5.1).
///
/// The peer-to-peer mapping for NAT and stateful firewalls typically
/// expires after about two minutes of idle time. 95 seconds leaves
/// ~25 seconds of slack before the most common 120s timeout — long
/// enough to not spam the wire, short enough to refresh the binding
/// reliably.
///
/// Apps can override via `ConnectionPool::with_keepalive_interval` /
/// `TlsPool::with_keepalive_interval`, or disable entirely by
/// passing `None`.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(95);

/// The double-CRLF ping frame emitted on TCP / TLS keepalive ticks.
/// Peers respond with a single CRLF pong that our inbound framer
/// absorbs automatically — no handler intervention required.
pub(crate) const CRLF_KEEPALIVE_PING: &[u8] = b"\r\n\r\n";

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

/// Drives a writer half of a TCP / TLS stream, consuming send frames
/// from the supplied channel and interleaving RFC 6223 CRLF keepalive
/// pings on a configurable interval.
///
/// Exits when the channel is closed, when a write fails, or when a
/// keepalive ping fails — each of those indicates the connection is
/// no longer usable and the pool entry should be reaped. The
/// keepalive timer resets after every real send so busy connections
/// never emit spurious pings.
///
/// Passing `keepalive = None` disables the ping entirely — useful for
/// tests and for transports where the keepalive is unwanted.
async fn run_stream_writer_with_keepalive<W>(
    writer: &mut W,
    rx: &mut mpsc::Receiver<Bytes>,
    keepalive: Option<Duration>,
) where
    W: AsyncWriteExt + Unpin,
{
    // `interval_at` starts the first tick after the duration, not
    // immediately — exactly the "keep binding alive while idle"
    // behaviour we want.
    let mut keepalive_timer = keepalive.map(|d| {
        let mut i = tokio::time::interval_at(tokio::time::Instant::now() + d, d);
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    });

    loop {
        tokio::select! {
            // Biased: drain payloads first so a busy connection
            // doesn't race the keepalive tick.
            biased;

            maybe_buf = rx.recv() => {
                let Some(buf) = maybe_buf else {
                    // Channel closed — pool entry was dropped.
                    break;
                };
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
                // Real traffic means the NAT binding is fresh; reset
                // the keepalive countdown.
                if let Some(t) = keepalive_timer.as_mut() {
                    t.reset();
                }
            }

            _ = async {
                match keepalive_timer.as_mut() {
                    Some(t) => { t.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if writer.write_all(CRLF_KEEPALIVE_PING).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Watches a writer task's `JoinHandle` and removes the corresponding
/// pool entry when the writer exits — for any reason: graceful close
/// (channel drained), peer-closed write, or a panic inside the writer.
///
/// Previously the writer was spawned with a bare `tokio::spawn` and its
/// `JoinHandle` discarded, so:
///   * a panic was silently swallowed by the runtime;
///   * the `PoolEntry` lingered in the map with a dead writer, and the
///     next `send_*` for that key would fail at the `sender.send()` call
///     before the entry was finally cleaned up.
///
/// The supervisor removes the entry proactively and emits a `warn!` on
/// panic so operators see the failure.
fn spawn_writer_supervisor<K, F>(
    writer: tokio::task::JoinHandle<()>,
    map: Arc<DashMap<K, PoolEntry>>,
    key: K,
    transport: &'static str,
    format_key: F,
    event_emitter: Option<WriterEventEmitter>,
) where
    K: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
    F: FnOnce(&K) -> String + Send + 'static,
{
    tokio::spawn(async move {
        let outcome = writer.await;
        let key_label = format_key(&key);
        let mut event_reason: Option<String> = None;
        match outcome {
            Ok(()) => {
                debug!(
                    transport,
                    peer = %key_label,
                    "pool writer task exited, removing entry"
                );
            }
            Err(e) if e.is_panic() => {
                warn!(
                    transport,
                    peer = %key_label,
                    "pool writer task panicked, removing entry"
                );
                event_reason = Some("writer panicked".to_string());
            }
            Err(e) => {
                debug!(
                    transport,
                    peer = %key_label,
                    error = %e,
                    "pool writer task cancelled, removing entry"
                );
                event_reason = Some(format!("writer cancelled: {e}"));
            }
        }
        map.remove(&key);

        // Emit a ConnectionEvent so observers (metrics, reconnect
        // policies) see the death without waiting for the next send
        // attempt. The emitter knows the peer SocketAddr; WS
        // supervisors don't provide one (URL-keyed).
        if let Some(emitter) = event_emitter {
            let event = match event_reason {
                Some(reason) => ConnectionEvent::Failed {
                    transport: emitter.transport,
                    peer: emitter.peer,
                    reason,
                },
                None => ConnectionEvent::Closed {
                    transport: emitter.transport,
                    peer: emitter.peer,
                },
            };
            // Ignore send failure — it just means no subscribers
            // are currently listening, which is fine.
            let _ = emitter.tx.send(event);
        }
    });
}

/// Bundle of data needed for the supervisor to synthesise a
/// [`ConnectionEvent`] on writer-task exit. TCP and TLS pools pass
/// this through; WS passes `None` (no SocketAddr available).
struct WriterEventEmitter {
    transport: TransportKind,
    peer: SocketAddr,
    tx: broadcast::Sender<ConnectionEvent>,
}

/// Connection pool with idle timeout and size limits for TCP and WebSocket.
#[derive(Debug)]
pub struct ConnectionPool {
    // DashMap is wrapped in Arc so a per-connection supervisor task can
    // hold a reference and remove the dead entry when the writer task
    // exits (graceful, peer-closed, or panicked). Without this a dead
    // writer's PoolEntry lingered until the next send_tcp failure.
    tcp: Arc<DashMap<SocketAddr, PoolEntry>>,
    #[cfg(feature = "ws")]
    ws: Arc<DashMap<String, PoolEntry>>,
    max_size: usize,
    idle_timeout: Duration,
    inbound_tx: Arc<Mutex<Option<Sender<InboundPacket>>>>,
    /// One permit per pool slot. Held by `PoolEntry::_permit` so the cap is
    /// enforced atomically: callers must successfully `try_acquire_owned`
    /// before opening a new connection, and the slot is freed automatically
    /// when the entry is dropped (eviction, send failure, idle cleanup).
    /// Shared across TCP and WS so the total connection count is the cap.
    permits: Arc<Semaphore>,
    /// RFC 6223 outbound keepalive interval for TCP connections. `None`
    /// disables the background CRLF ping. WebSocket connections don't
    /// use this — tokio-tungstenite handles WS-native ping/pong.
    keepalive_interval: Option<Duration>,
    /// Broadcast channel for [`ConnectionEvent`]s. Kept as a single
    /// sender per pool; subscribers call [`Self::subscribe_events`]
    /// to obtain a receiver. No subscribers == events are discarded
    /// (broadcast semantics).
    events_tx: broadcast::Sender<ConnectionEvent>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(CONNECTION_EVENT_CHANNEL_CAPACITY);
        Self {
            tcp: Arc::new(DashMap::new()),
            #[cfg(feature = "ws")]
            ws: Arc::new(DashMap::new()),
            max_size: MAX_POOL_SIZE,
            idle_timeout: IDLE_TIMEOUT,
            inbound_tx: Arc::new(Mutex::new(None)),
            permits: Arc::new(Semaphore::new(MAX_POOL_SIZE)),
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            events_tx,
        }
    }

    /// Creates a new pool with custom limits.
    pub fn with_limits(max_size: usize, idle_timeout: Duration) -> Self {
        let (events_tx, _) = broadcast::channel(CONNECTION_EVENT_CHANNEL_CAPACITY);
        Self {
            tcp: Arc::new(DashMap::new()),
            #[cfg(feature = "ws")]
            ws: Arc::new(DashMap::new()),
            max_size,
            idle_timeout,
            inbound_tx: Arc::new(Mutex::new(None)),
            permits: Arc::new(Semaphore::new(max_size)),
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            events_tx,
        }
    }

    /// Subscribe to [`ConnectionEvent`]s emitted by this pool.
    ///
    /// Each subscriber receives every event from the moment of
    /// subscription forward — there's no replay of past events. If
    /// a subscriber falls more than
    /// `CONNECTION_EVENT_CHANNEL_CAPACITY` events behind, it sees
    /// `RecvError::Lagged` from the stream; events after the lag
    /// are still delivered. Typical subscribers: a tracing sink
    /// that logs connection deaths, a Prometheus counter for
    /// transport failures, or an app-level reconnect policy.
    pub fn subscribe_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.events_tx.subscribe()
    }

    /// Configure the outbound RFC 6223 CRLF keepalive interval for
    /// TCP connections.
    ///
    /// Passing `Some(d)` schedules a `\r\n\r\n` ping every `d` after
    /// the last write on each pooled connection; peers MAY respond
    /// with a single-CRLF pong, which the inbound framer absorbs
    /// automatically. Passing `None` disables the background ping.
    /// The timer resets after every real send, so busy connections
    /// effectively never ping.
    pub fn with_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Returns the current keepalive interval (`None` if disabled).
    pub fn keepalive_interval(&self) -> Option<Duration> {
        self.keepalive_interval
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
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("TCP pool connect timeout after 5s to {}", addr))??;
        debug!(peer = %addr, "TCP connection established");
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let mut entry = PoolEntry::new(tx.clone(), permit);
        debug!(peer = %addr, "creating new pool entry");

        // Writer task. Drains the send channel and emits periodic
        // RFC 6223 keepalive pings (`\r\n\r\n`) on idle — the channel
        // branch resets the keepalive timer on every real send, so
        // busy connections never ping spuriously.
        let writer_tx = tx.clone();
        let keepalive = self.keepalive_interval;
        let writer_handle = tokio::spawn(async move {
            run_stream_writer_with_keepalive(&mut writer, &mut rx, keepalive).await;
        });
        entry.task_handles.push(writer_handle.abort_handle());
        // Supervise the writer: whenever it exits (graceful close,
        // peer-closed write, or panic) remove the entry from the pool
        // so the next send for this addr opens a fresh connection
        // instead of sending into a dead channel. Panics are surfaced
        // as a warning; previously they were silently dropped by
        // `tokio::spawn`.
        spawn_writer_supervisor(
            writer_handle,
            Arc::clone(&self.tcp),
            addr,
            "tcp",
            move |peer| format!("{peer}"),
            Some(WriterEventEmitter {
                transport: TransportKind::Tcp,
                peer: addr,
                tx: self.events_tx.clone(),
            }),
        );

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
        .map_err(|_| anyhow!("WS connect timeout after 5s to {}", key))??;

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
        spawn_writer_supervisor(
            writer_handle,
            Arc::clone(&self.ws),
            key.clone(),
            "ws",
            |url| url.clone(),
            // WS connections are URL-keyed — no SocketAddr available
            // for ConnectionEvent. Observers that want WS events can
            // rely on tokio-tungstenite's native ping/pong telemetry.
            None,
        );

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
    // Arc-wrapped so the per-connection writer supervisor can remove
    // the entry when the writer exits; see ConnectionPool.
    inner: Arc<DashMap<(SocketAddr, String), PoolEntry>>,
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
    /// RFC 6223 outbound keepalive interval. `None` disables.
    keepalive_interval: Option<Duration>,
    /// Broadcast channel for [`ConnectionEvent`]s; symmetric with
    /// [`ConnectionPool::events_tx`].
    events_tx: broadcast::Sender<ConnectionEvent>,
}

#[cfg(feature = "tls")]
pub type TlsClientConfig = ClientConfig;

/// Cadence of the background idle sweep for TlsPool. TLS connections
/// are expensive to establish, so we don't poll too aggressively; 30s
/// matches the WS ping cadence used elsewhere.
#[cfg(feature = "tls")]
const TLS_POOL_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

#[cfg(feature = "tls")]
impl TlsPool {
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(CONNECTION_EVENT_CHANNEL_CAPACITY);
        let pool = Self {
            inner: Arc::new(DashMap::new()),
            max_size: MAX_POOL_SIZE,
            idle_timeout: IDLE_TIMEOUT,
            permits: Arc::new(Semaphore::new(MAX_POOL_SIZE)),
            inbound_tx: Arc::new(Mutex::new(None)),
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            events_tx,
        };
        pool.spawn_idle_sweeper();
        pool
    }

    /// Creates a new pool with custom limits.
    pub fn with_limits(max_size: usize, idle_timeout: Duration) -> Self {
        let (events_tx, _) = broadcast::channel(CONNECTION_EVENT_CHANNEL_CAPACITY);
        let pool = Self {
            inner: Arc::new(DashMap::new()),
            max_size,
            idle_timeout,
            permits: Arc::new(Semaphore::new(max_size)),
            inbound_tx: Arc::new(Mutex::new(None)),
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            events_tx,
        };
        pool.spawn_idle_sweeper();
        pool
    }

    /// Subscribe to [`ConnectionEvent`]s emitted by this TLS pool.
    /// See [`ConnectionPool::subscribe_events`] for semantics.
    pub fn subscribe_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.events_tx.subscribe()
    }

    /// Configure the RFC 6223 CRLF keepalive interval for TLS
    /// connections. Same semantics as
    /// [`ConnectionPool::with_keepalive_interval`].
    pub fn with_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Returns the current TLS keepalive interval (`None` if disabled).
    pub fn keepalive_interval(&self) -> Option<Duration> {
        self.keepalive_interval
    }

    /// Registers an inbound packet sink so responses on outbound TLS
    /// connections get routed back into the SIP handler/transaction layer.
    /// Symmetric with `ConnectionPool::set_inbound_tx`.
    pub async fn set_inbound_tx(&self, tx: Sender<InboundPacket>) {
        let mut guard = self.inbound_tx.lock().await;
        *guard = Some(tx);
    }

    /// Spawn a background task that sweeps idle TLS connections.
    ///
    /// `cleanup_idle` only runs opportunistically inside `reserve_slot`,
    /// i.e. when a new connection is being opened. If the workload goes
    /// quiet, idle TLS connections accumulate until eviction or process
    /// exit. This task wakes every `TLS_POOL_SWEEP_INTERVAL` and prunes
    /// entries past the idle timeout, bounding steady-state memory.
    ///
    /// The task holds a `Weak` reference to the map so it exits cleanly
    /// when the pool is dropped; no shutdown signal needed.
    fn spawn_idle_sweeper(&self) {
        // TlsPool can be constructed in synchronous contexts (tests, CLI
        // init paths); only arm the background sweep when we're on a
        // tokio runtime.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = Arc::downgrade(&self.inner);
        let idle_timeout = self.idle_timeout;
        handle.spawn(async move {
            let mut interval = tokio::time::interval(TLS_POOL_SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                let mut swept = 0usize;
                inner.retain(|(addr, _), entry| {
                    if entry.is_idle(idle_timeout) {
                        debug!(peer = %addr, "tls pool sweeper: dropping idle connection");
                        swept += 1;
                        false
                    } else {
                        true
                    }
                });
                if swept > 0 {
                    debug!(swept, "tls pool idle sweep complete");
                }
            }
        });
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
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("TLS pool connect timeout after 5s to {}", addr))??;
        let tls_stream = connector.connect(server_name, stream).await?;
        // Split so the reader and writer tasks own separate halves; without
        // this the writer task holds the only handle to the TLS stream and
        // we never read responses (the original send_tls bug).
        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let writer_tx = tx.clone();
        let mut entry = PoolEntry::new(tx.clone(), permit);

        // TLS writer task with keepalive (RFC 6223). Same idle-reset
        // semantics as the TCP pool; we read `keepalive_interval`
        // from the pool struct.
        let keepalive = self.keepalive_interval;
        let writer_handle = tokio::spawn(async move {
            run_stream_writer_with_keepalive(&mut writer, &mut rx, keepalive).await;
            // Perform proper TLS shutdown when connection closes.
            let _ = writer.shutdown().await;
        });
        entry.task_handles.push(writer_handle.abort_handle());
        spawn_writer_supervisor(
            writer_handle,
            Arc::clone(&self.inner),
            key.clone(),
            "tls",
            |(peer, server_name)| format!("{peer} ({server_name})"),
            Some(WriterEventEmitter {
                transport: TransportKind::Tls,
                peer: key.0,
                tx: self.events_tx.clone(),
            }),
        );

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

    /// Regression test: when the writer task returns (or panics), the
    /// supervisor must remove the corresponding pool entry. Previously
    /// the entry lingered until a subsequent `send_tcp` attempt failed.
    #[tokio::test]
    async fn supervisor_removes_entry_when_writer_exits() {
        let pool = Arc::new(ConnectionPool::with_limits(4, Duration::from_secs(60)));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5060);
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        pool.tcp.insert(addr, PoolEntry::for_tests(tx));
        assert_eq!(pool.len(), 1);

        // Spawn a writer that exits immediately. The supervisor should
        // then reach in and remove the (addr, entry).
        let writer = tokio::spawn(async {});
        spawn_writer_supervisor(
            writer,
            Arc::clone(&pool.tcp),
            addr,
            "tcp",
            move |peer| format!("{peer}"),
            None,
        );

        // Give the supervisor a moment to run.
        for _ in 0..20 {
            if pool.len() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            pool.len(),
            0,
            "supervisor must remove entry after writer exit"
        );
    }

    #[tokio::test]
    async fn supervisor_removes_entry_when_writer_panics() {
        let pool = Arc::new(ConnectionPool::with_limits(4, Duration::from_secs(60)));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5061);
        let (tx, _rx) = mpsc::channel::<Bytes>(1);
        pool.tcp.insert(addr, PoolEntry::for_tests(tx));

        let writer = tokio::spawn(async {
            panic!("simulated writer crash");
        });
        spawn_writer_supervisor(
            writer,
            Arc::clone(&pool.tcp),
            addr,
            "tcp",
            move |peer| format!("{peer}"),
            None,
        );

        for _ in 0..20 {
            if pool.len() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(pool.len(), 0, "supervisor must remove entry even on panic");
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

    // =====================================================================
    // RFC 6223 / RFC 5626 §3.5 outbound CRLF keepalive
    // =====================================================================

    /// Spawns a loopback TCP listener that records every byte the
    /// client sends into a shared `Vec<u8>`. Returns the listener's
    /// addr and a handle to the captured bytes.
    async fn spawn_capture_listener() -> (
        SocketAddr,
        Arc<tokio::sync::Mutex<Vec<u8>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::net::TcpListener;
        let captured: Arc<tokio::sync::Mutex<Vec<u8>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cap = Arc::clone(&captured);
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            cap.lock().await.extend_from_slice(&buf[..n]);
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        (addr, captured, handle)
    }

    #[tokio::test]
    async fn tcp_pool_emits_crlf_keepalive_when_idle() {
        // Short keepalive interval so the test is fast. The first
        // tick happens `interval` after channel open; wait longer
        // than that and assert bytes showed up on the wire.
        let (addr, captured, _) = spawn_capture_listener().await;
        let pool = ConnectionPool::new().with_keepalive_interval(Some(Duration::from_millis(80)));

        // Send one real frame so the pool opens a connection.
        pool.send_tcp(
            addr,
            Bytes::from_static(b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n"),
        )
        .await
        .unwrap();

        // Wait through at least two keepalive ticks. The initial
        // send resets the timer, so ~160ms of idle yields ~1-2 pings.
        tokio::time::sleep(Duration::from_millis(240)).await;

        let bytes = captured.lock().await;
        let content = &*bytes;
        assert!(
            content.windows(4).filter(|w| *w == b"\r\n\r\n").count() >= 2,
            "expected at least one keepalive CRLFCRLF after OPTIONS; got {} bytes total",
            content.len(),
        );
    }

    #[tokio::test]
    async fn tcp_pool_keepalive_disabled_emits_no_pings() {
        let (addr, captured, _) = spawn_capture_listener().await;
        let pool = ConnectionPool::new().with_keepalive_interval(None);

        // Open the connection with one small frame.
        let frame = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        pool.send_tcp(addr, Bytes::from_static(frame))
            .await
            .unwrap();

        // Wait long enough for a keepalive to fire IF it were armed.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let bytes = captured.lock().await;
        // Expect exactly the OPTIONS bytes — no extra CRLFs injected.
        assert_eq!(
            bytes.as_slice(),
            frame,
            "keepalive=None MUST NOT emit CRLF pings",
        );
    }

    // =====================================================================
    // RFC 3261 §18.4: transport-error observability
    // =====================================================================

    #[tokio::test]
    async fn connection_event_emitted_when_peer_closes_tcp() {
        use tokio::net::TcpListener;

        // Spawn a listener that accepts one connection and immediately
        // drops it, simulating a peer-side close (or middlebox RST).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        // Short keepalive so the writer notices the dead peer quickly
        // — without it the writer sits idle on rx.recv() and the
        // supervisor only reaps the entry when someone tries to send
        // again. The keepalive ping IS such a send attempt.
        let pool = ConnectionPool::new().with_keepalive_interval(Some(Duration::from_millis(80)));
        let mut events = pool.subscribe_events();

        // Open a connection with one send.
        let frame = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let _ = pool.send_tcp(addr, Bytes::from_static(frame)).await;

        // Wait for the supervisor to observe the writer task exiting.
        let event = tokio::time::timeout(Duration::from_secs(2), events.recv()).await;
        let event = event
            .expect("supervisor must emit a ConnectionEvent within 2s")
            .expect("broadcast channel should deliver");

        match event {
            ConnectionEvent::Closed { transport, peer }
            | ConnectionEvent::Failed {
                transport, peer, ..
            } => {
                assert_eq!(transport, TransportKind::Tcp);
                assert_eq!(peer, addr);
            }
        }
    }

    #[tokio::test]
    async fn connection_event_subscribers_see_multiple_deaths() {
        // Two separate connections die; a single subscriber receives
        // both events in order.
        use tokio::net::TcpListener;

        async fn one_shot_close(addr: SocketAddr) {
            let listener = TcpListener::bind(addr).await.unwrap();
            tokio::spawn(async move {
                if let Ok((stream, _)) = listener.accept().await {
                    drop(stream);
                }
            });
        }

        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = l1.local_addr().unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = l2.local_addr().unwrap();
        drop(l1);
        drop(l2);
        one_shot_close(addr1).await;
        one_shot_close(addr2).await;

        let pool = ConnectionPool::new().with_keepalive_interval(Some(Duration::from_millis(80)));
        let mut events = pool.subscribe_events();

        let frame = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let _ = pool.send_tcp(addr1, Bytes::from_static(frame)).await;
        let _ = pool.send_tcp(addr2, Bytes::from_static(frame)).await;

        let mut seen = std::collections::HashSet::new();
        for _ in 0..2 {
            let ev = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap()
                .unwrap();
            let peer = match ev {
                ConnectionEvent::Closed { peer, .. } | ConnectionEvent::Failed { peer, .. } => peer,
            };
            seen.insert(peer);
        }
        assert!(seen.contains(&addr1), "event for addr1 missing");
        assert!(seen.contains(&addr2), "event for addr2 missing");
    }

    #[tokio::test]
    async fn tcp_pool_keepalive_timer_resets_on_real_send() {
        // A busy connection should never emit a keepalive. We send
        // every 40ms and keepalive is configured at 100ms — each
        // real send resets the timer so the tick never arrives.
        let (addr, captured, _) = spawn_capture_listener().await;
        let pool = ConnectionPool::new().with_keepalive_interval(Some(Duration::from_millis(100)));

        let frame: &[u8] = b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        for _ in 0..6 {
            pool.send_tcp(addr, Bytes::from_static(frame))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        let bytes = captured.lock().await;
        let content = &*bytes;
        // Bytes on the wire are exactly the 6 OPTIONS frames
        // concatenated. Each frame ends in CRLFCRLF, so the
        // count-of-CRLFCRLF should equal the number of frames (6),
        // not more.
        let crlf_pairs = content.windows(4).filter(|w| *w == b"\r\n\r\n").count();
        assert_eq!(
            crlf_pairs, 6,
            "expected exactly one CRLFCRLF per OPTIONS (no extra keepalives); got {crlf_pairs}",
        );
    }
}
