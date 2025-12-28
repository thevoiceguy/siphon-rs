// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use sip_core::{Headers, Method, Request, Response};
use sip_transport::pool::ConnectionPool;
use smol_str::SmolStr;
use tokio::{
    sync::{mpsc, oneshot},
    time,
};
use tracing::{debug, error, warn};

use crate::metrics::TransactionRole;
use crate::top_via;

use crate::{
    branch_from_via,
    fsm::{
        ClientAction, ClientInviteAction, ClientInviteEvent, ClientInviteFsm, ClientNonInviteEvent,
        ClientNonInviteFsm, ServerAction, ServerInviteAction, ServerInviteEvent, ServerInviteFsm,
        ServerNonInviteEvent, ServerNonInviteFsm, TransportKind,
    },
    metrics::{TransactionMetrics, TransactionOutcome, TransportType},
    request_branch_id,
    timers::{TimerDefaults, Transport, TransportAwareTimers},
    TransactionKey, TransactionTimer,
};

const MAX_TIMER_BUCKETS: usize = 10_000;

/// Default SIP timer values per RFC 3261 §17
const T1_DEFAULT: Duration = Duration::from_millis(500); // RTT estimate
const T2_DEFAULT: Duration = Duration::from_secs(4); // Maximum retransmit interval
const T4_DEFAULT: Duration = Duration::from_secs(5); // Maximum duration a message remains in network

/// Transaction limits for DoS protection.
///
/// # Security Considerations
///
/// Without limits, an attacker can exhaust server memory by creating unlimited
/// transactions with unique branch IDs. These limits prevent resource exhaustion.
///
/// ## Recommended Values:
/// - **Small server** (1-10 concurrent calls): 1,000 transactions
/// - **Medium server** (10-100 concurrent calls): 10,000 transactions
/// - **Large server** (100-1000 concurrent calls): 100,000 transactions
/// - **Carrier-grade** (1000+ concurrent calls): 500,000 transactions
///
/// ## Memory Impact:
/// Each transaction consumes approximately 1-2 KB of memory. At the default
/// limit of 10,000 transactions, this is ~10-20 MB of memory.
///
/// # Examples
///
/// Using preset configurations:
/// ```
/// use sip_transaction::TransactionLimits;
///
/// // Small server (1-10 concurrent calls)
/// let small = TransactionLimits::small();
/// assert_eq!(small.max_server_transactions, 1_000);
/// assert_eq!(small.max_client_transactions, 1_000);
///
/// // Medium server (10-100 concurrent calls) - default
/// let medium = TransactionLimits::medium();
/// assert_eq!(medium.max_server_transactions, 10_000);
///
/// // Large server (100-1000 concurrent calls)
/// let large = TransactionLimits::large();
/// assert_eq!(large.max_server_transactions, 100_000);
///
/// // Carrier-grade (1000+ concurrent calls)
/// let carrier = TransactionLimits::carrier_grade();
/// assert_eq!(carrier.max_server_transactions, 500_000);
/// ```
///
/// Custom limits:
/// ```
/// use sip_transaction::TransactionLimits;
///
/// // Different limits for client and server
/// let custom = TransactionLimits::new(5_000, 2_000);
/// assert_eq!(custom.max_server_transactions, 5_000);
/// assert_eq!(custom.max_client_transactions, 2_000);
///
/// // Unlimited (testing only - NOT for production)
/// let unlimited = TransactionLimits::unlimited();
/// assert_eq!(unlimited.max_server_transactions, usize::MAX);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TransactionLimits {
    /// Maximum number of server transactions (incoming requests)
    pub max_server_transactions: usize,
    /// Maximum number of client transactions (outgoing requests)
    pub max_client_transactions: usize,
}

impl Default for TransactionLimits {
    fn default() -> Self {
        Self {
            // Conservative defaults suitable for medium-sized servers
            max_server_transactions: 10_000,
            max_client_transactions: 10_000,
        }
    }
}

impl TransactionLimits {
    /// Creates limits with custom values for server and client transactions.
    pub fn new(max_server: usize, max_client: usize) -> Self {
        Self {
            max_server_transactions: max_server,
            max_client_transactions: max_client,
        }
    }

    /// Unlimited transactions (use only for testing).
    pub fn unlimited() -> Self {
        Self {
            max_server_transactions: usize::MAX,
            max_client_transactions: usize::MAX,
        }
    }

    /// Small server preset (1-10 concurrent calls).
    pub fn small() -> Self {
        Self::new(1_000, 1_000)
    }

    /// Medium server preset (10-100 concurrent calls) - default.
    pub fn medium() -> Self {
        Self::default()
    }

    /// Large server preset (100-1000 concurrent calls).
    pub fn large() -> Self {
        Self::new(100_000, 100_000)
    }

    /// Carrier-grade preset (1000+ concurrent calls).
    pub fn carrier_grade() -> Self {
        Self::new(500_000, 500_000)
    }
}

/// Dispatches outbound data generated by the transaction manager.
#[async_trait]
pub trait TransportDispatcher: Send + Sync + 'static {
    /// Sends the provided bytes using the supplied context.
    async fn dispatch(&self, ctx: &TransportContext, payload: Bytes) -> Result<()>;
}

/// Application callbacks invoked for client transaction events.
#[async_trait]
pub trait ClientTransactionUser: Send + Sync + 'static {
    async fn on_provisional(&self, key: &TransactionKey, response: &Response);
    async fn on_final(&self, key: &TransactionKey, response: &Response);
    async fn on_terminated(&self, key: &TransactionKey, reason: &str);
    async fn send_ack(
        &self,
        key: &TransactionKey,
        response: Response,
        ctx: &TransportContext,
        is_2xx: bool,
    );
    async fn send_prack(&self, key: &TransactionKey, response: Response, ctx: &TransportContext);
    async fn on_transport_error(&self, key: &TransactionKey);
}

/// Context captured for a server transaction so retransmissions reuse the same transport.
#[derive(Debug, Clone)]
pub struct TransportContext {
    pub transport: TransportKind,
    pub peer: SocketAddr,
    pub stream: Option<mpsc::Sender<Bytes>>,
    /// Optional server name (SNI) for TLS transports.
    pub server_name: Option<String>,
    /// Optional WS/WSS target URI override.
    pub ws_uri: Option<String>,
    /// Optional UDP socket for sending ACKs and other messages over UDP.
    /// Required for ClientTransactionUser implementations that need to send
    /// ACK for 2xx responses (e.g., REFER transfers, UAC call flows).
    pub udp_socket: Option<std::sync::Arc<tokio::net::UdpSocket>>,
}

impl TransportContext {
    pub fn new(
        transport: TransportKind,
        peer: SocketAddr,
        stream: Option<mpsc::Sender<Bytes>>,
    ) -> Self {
        Self {
            transport,
            peer,
            stream,
            server_name: None,
            ws_uri: None,
            udp_socket: None,
        }
    }

    /// Builder-style helper to set server name (for TLS SNI).
    pub fn with_server_name(mut self, name: Option<String>) -> Self {
        self.server_name = name;
        self
    }

    /// Builder-style helper to set an explicit WS/WSS URI.
    pub fn with_ws_uri(mut self, uri: Option<String>) -> Self {
        self.ws_uri = uri;
        self
    }

    /// Builder-style helper to set the UDP socket.
    /// Required for sending ACKs for 2xx responses over UDP.
    pub fn with_udp_socket(mut self, socket: Option<std::sync::Arc<tokio::net::UdpSocket>>) -> Self {
        self.udp_socket = socket;
        self
    }
}

enum ManagerCommand {
    ServerTimerFired {
        key: TransactionKey,
        timer: TransactionTimer,
    },
    ClientTimerFired {
        key: TransactionKey,
        timer: TransactionTimer,
    },
    ClientTransportError {
        key: TransactionKey,
    },
    ServerTransportError {
        key: TransactionKey,
    },
}

/// Entry stored for each active server-side transaction.
struct ServerEntry {
    kind: ServerKind,
    ctx: TransportContext,
    timers: HashMap<TransactionTimer, oneshot::Sender<()>>,
    start_time: Instant,
    method: Method,
}

enum ServerKind {
    Invite(ServerInviteFsm),
    NonInvite(ServerNonInviteFsm),
}

struct ClientEntry {
    kind: ClientKind,
    ctx: TransportContext,
    tu: Arc<dyn ClientTransactionUser>,
    timers: HashMap<TransactionTimer, oneshot::Sender<()>>,
    start_time: Instant,
    method: Method,
}

enum ClientKind {
    Invite(ClientInviteFsm),
    NonInvite(ClientNonInviteFsm),
}

enum ClientRuntimeActions {
    Invite(Vec<ClientInviteAction>),
    NonInvite(Vec<ClientAction>),
}

fn map_server_actions(actions: Vec<ServerAction>) -> Vec<ServerInviteAction> {
    actions
        .into_iter()
        .map(|action| match action {
            ServerAction::Transmit { bytes, transport } => {
                ServerInviteAction::Transmit { bytes, transport }
            }
            ServerAction::Schedule { timer, duration } => {
                ServerInviteAction::Schedule { timer, duration }
            }
            ServerAction::Cancel(timer) => ServerInviteAction::Cancel(timer),
            ServerAction::Terminate { reason } => ServerInviteAction::Terminate { reason },
        })
        .collect()
}

impl ServerEntry {
    fn cancel_timer(&mut self, timer: TransactionTimer) {
        if let Some(cancel) = self.timers.remove(&timer) {
            let _ = cancel.send(());
        }
    }

    fn cancel_all(&mut self) {
        for (_, cancel) in self.timers.drain() {
            let _ = cancel.send(());
        }
    }
}

impl ClientEntry {
    fn cancel_timer(&mut self, timer: TransactionTimer) {
        if let Some(cancel) = self.timers.remove(&timer) {
            let _ = cancel.send(());
        }
    }

    fn cancel_all(&mut self) {
        for (_, cancel) in self.timers.drain() {
            let _ = cancel.send(());
        }
    }
}

/// Owns SIP transactions and manages timers/actions.
#[derive(Clone)]
pub struct TransactionManager {
    inner: Arc<ManagerInner>,
    cmd_tx: mpsc::Sender<ManagerCommand>,
}

struct ManagerInner {
    dispatcher: Arc<dyn TransportDispatcher>,
    server: DashMap<TransactionKey, ServerEntry>,
    client: DashMap<TransactionKey, ClientEntry>,
    // Removed client_index - build TransactionKey directly from response
    timer_defaults: TimerDefaults,
    pool: ConnectionPool,
    metrics: TransactionMetrics,
    limits: TransactionLimits,
}

/// Helper to convert TransportKind to Transport for timer calculations
fn transport_kind_to_transport(kind: TransportKind) -> Transport {
    match kind {
        TransportKind::Udp => Transport::Udp,
        TransportKind::Tcp => Transport::Tcp,
        TransportKind::Tls => Transport::Tls,
        TransportKind::Ws => Transport::Tcp,
        TransportKind::Wss => Transport::Tls,
        TransportKind::Sctp => Transport::Tcp,
        TransportKind::TlsSctp => Transport::Tls,
    }
}

impl TransactionManager {
    async fn dispatch_with_pool(&self, ctx: &TransportContext, bytes: Bytes) -> Result<()> {
        match ctx.transport {
            TransportKind::Tcp if ctx.stream.is_none() => {
                self.inner.pool.send_tcp(ctx.peer, bytes).await
            }
            _ => self.inner.dispatcher.dispatch(ctx, bytes).await,
        }
    }

    /// Creates a new transaction manager using the supplied dispatcher.
    pub fn new(dispatcher: Arc<dyn TransportDispatcher>) -> Self {
        Self::with_timers(dispatcher, T1_DEFAULT, T2_DEFAULT, T4_DEFAULT)
    }

    /// Creates a transaction manager with custom limits for DoS protection.
    pub fn with_limits(
        dispatcher: Arc<dyn TransportDispatcher>,
        limits: TransactionLimits,
    ) -> Self {
        Self::with_timers_and_limits(dispatcher, T1_DEFAULT, T2_DEFAULT, T4_DEFAULT, limits)
    }

    /// Creates a transaction manager using custom T1/T2/T4 timers (test hook).
    pub fn with_timers(
        dispatcher: Arc<dyn TransportDispatcher>,
        t1: Duration,
        t2: Duration,
        t4: Duration,
    ) -> Self {
        Self::with_timers_and_limits(dispatcher, t1, t2, t4, TransactionLimits::default())
    }

    /// Creates a transaction manager with custom timers and limits.
    pub fn with_timers_and_limits(
        dispatcher: Arc<dyn TransportDispatcher>,
        t1: Duration,
        t2: Duration,
        t4: Duration,
        limits: TransactionLimits,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(128);
        let manager = Self {
            inner: Arc::new(ManagerInner {
                dispatcher,
                server: DashMap::new(),
                client: DashMap::new(),
                timer_defaults: TimerDefaults { t1, t2, t4 },
                pool: ConnectionPool::new(),
                metrics: TransactionMetrics::new(),
                limits,
            }),
            cmd_tx,
        };
        manager.spawn_command_loop(cmd_rx);
        manager
    }

    /// Gets a reference to the metrics collector.
    pub fn metrics(&self) -> &TransactionMetrics {
        &self.inner.metrics
    }

    /// Enforces server transaction limits by evicting oldest transaction if at limit.
    ///
    /// Returns true if a transaction was evicted (limit reached), false otherwise.
    fn enforce_server_transaction_limit(&self) -> bool {
        let current_count = self.inner.server.len();
        if current_count >= self.inner.limits.max_server_transactions {
            // Find and evict the oldest server transaction
            if let Some(oldest_key) = self.find_oldest_server_transaction() {
                tracing::warn!(
                    key = ?oldest_key,
                    current_count = current_count,
                    limit = self.inner.limits.max_server_transactions,
                    "Server transaction limit reached, evicting oldest transaction"
                );
                if let Some((_, mut entry)) = self.inner.server.remove(&oldest_key) {
                    entry.cancel_all();
                }
                return true;
            }
        }
        false
    }

    /// Enforces client transaction limits by evicting oldest transaction if at limit.
    ///
    /// Returns true if a transaction was evicted (limit reached), false otherwise.
    fn enforce_client_transaction_limit(&self) -> bool {
        let current_count = self.inner.client.len();
        if current_count >= self.inner.limits.max_client_transactions {
            // Find and evict the oldest client transaction
            if let Some(oldest_key) = self.find_oldest_client_transaction() {
                tracing::warn!(
                    key = ?oldest_key,
                    current_count = current_count,
                    limit = self.inner.limits.max_client_transactions,
                    "Client transaction limit reached, evicting oldest transaction"
                );
                if let Some((_, mut entry)) = self.inner.client.remove(&oldest_key) {
                    entry.cancel_all();
                    // Notify TU that transaction was terminated due to resource limits
                    let tu = entry.tu.clone();
                    let key_clone = oldest_key.clone();
                    tokio::spawn(async move {
                        tu.on_terminated(&key_clone, "resource limit exceeded")
                            .await;
                    });
                }
                return true;
            }
        }
        false
    }

    /// Finds the oldest server transaction based on start_time.
    fn find_oldest_server_transaction(&self) -> Option<TransactionKey> {
        self.inner
            .server
            .iter()
            .min_by_key(|entry| entry.start_time)
            .map(|entry| entry.key().clone())
    }

    /// Finds the oldest client transaction based on start_time.
    fn find_oldest_client_transaction(&self) -> Option<TransactionKey> {
        self.inner
            .client
            .iter()
            .min_by_key(|entry| entry.start_time)
            .map(|entry| entry.key().clone())
    }

    fn extract_branch(headers: &Headers) -> Option<SmolStr> {
        let via = headers.get("Via")?;
        let branch = branch_from_via(via)?;
        Some(SmolStr::new(branch))
    }

    fn extract_cseq_method(headers: &Headers) -> Option<Method> {
        let cseq = headers.get("CSeq")?;
        // CSeq format: "123 INVITE" or "456 CANCEL"
        let method_str = cseq.split_whitespace().nth(1)?;
        Some(Method::from_token(method_str))
    }

    fn spawn_command_loop(&self, mut rx: mpsc::Receiver<ManagerCommand>) {
        let manager = self.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ManagerCommand::ServerTimerFired { key, timer } => {
                        manager.handle_server_timer(key, timer).await;
                    }
                    ManagerCommand::ClientTimerFired { key, timer } => {
                        manager.handle_client_timer(key, timer).await;
                    }
                    ManagerCommand::ClientTransportError { key } => {
                        manager.process_client_transport_error(key).await;
                    }
                    ManagerCommand::ServerTransportError { key } => {
                        manager.process_server_transport_error(key).await;
                    }
                }
            }
        });
    }

    /// Registers an inbound request and returns a handle to respond.
    pub async fn receive_request(
        &self,
        request: Request,
        ctx: TransportContext,
    ) -> ServerTransactionHandle {
        let branch = request_branch_id(&request).unwrap_or_else(crate::generate_branch_id);
        let key = TransactionKey {
            branch,
            method: request.start.method.clone(),
            is_server: true,
        };

        if request.start.method == Method::Ack {
            let invite_key = TransactionKey {
                branch: key.branch.clone(),
                method: Method::Invite,
                is_server: true,
            };
            if let Some(mut entry) = self.inner.server.get_mut(&invite_key) {
                if let ServerKind::Invite(fsm) = &mut entry.kind {
                    let actions = fsm.on_event(ServerInviteEvent::ReceiveAck);
                    drop(entry);
                    self.apply_server_actions(&invite_key, actions).await;
                    return ServerTransactionHandle {
                        manager: self.clone(),
                        key: invite_key,
                    };
                }
            }
        }

        if let Some(mut entry) = self.inner.server.get_mut(&key) {
            let actions = match &mut entry.kind {
                ServerKind::Invite(fsm) => fsm.on_retransmit(),
                ServerKind::NonInvite(fsm) => map_server_actions(fsm.on_retransmit()),
            };
            drop(entry);
            self.apply_server_actions(&key, actions).await;
            return ServerTransactionHandle {
                manager: self.clone(),
                key,
            };
        }

        // If a CANCEL arrives, notify the matching INVITE transaction (if any).
        if request.start.method.as_str() == "CANCEL" {
            let invite_key = TransactionKey {
                branch: key.branch.clone(),
                method: Method::Invite,
                is_server: true,
            };
            if let Some(mut entry) = self.inner.server.get_mut(&invite_key) {
                if let ServerKind::Invite(fsm) = &mut entry.kind {
                    let actions = fsm.on_event(ServerInviteEvent::ReceiveCancel);
                    drop(entry);
                    self.apply_server_actions(&invite_key, actions).await;
                }
            }
        }

        // Create transport-aware timers based on the transport type
        let transport = transport_kind_to_transport(ctx.transport);
        let timers = TransportAwareTimers::with_defaults(transport, self.inner.timer_defaults);

        let method = request.start.method.clone();
        let transport_type = TransportType::from(transport);
        self.inner.metrics.record_start(
            transport_type,
            &format!("{:?}", method),
            TransactionRole::Server,
        );
        if let Some(via) = top_via(&request) {
            self.inner.metrics.record_via_transport(via);
        }
        let mut entry = ServerEntry {
            kind: match method {
                Method::Invite => ServerKind::Invite(ServerInviteFsm::new(timers)),
                _ => ServerKind::NonInvite(ServerNonInviteFsm::new(timers)),
            },
            ctx,
            timers: HashMap::new(),
            start_time: Instant::now(),
            method,
        };

        let actions = match &mut entry.kind {
            ServerKind::Invite(fsm) => fsm.on_event(ServerInviteEvent::ReceiveInvite(request)),
            ServerKind::NonInvite(fsm) => {
                map_server_actions(fsm.on_event(ServerNonInviteEvent::ReceiveRequest(request)))
            }
        };

        // Enforce transaction limits (evict oldest if at limit)
        self.enforce_server_transaction_limit();

        self.inner.server.insert(key.clone(), entry);
        self.apply_server_actions(&key, actions).await;

        ServerTransactionHandle {
            manager: self.clone(),
            key,
        }
    }

    /// Starts a client transaction and transmits the initial request.
    pub async fn start_client_transaction(
        &self,
        request: Request,
        ctx: TransportContext,
        tu: Arc<dyn ClientTransactionUser>,
    ) -> Result<TransactionKey> {
        let branch = request_branch_id(&request)
            .ok_or_else(|| anyhow!("missing Via branch for client transaction"))?;
        let method = request.start.method.clone();
        let key = TransactionKey {
            branch: branch.clone(),
            method: method.clone(),
            is_server: false,
        };

        // Debug: Log transaction creation
        debug!(
            branch = %key.branch,
            method = ?key.method,
            call_id = ?request.headers.get("Call-ID"),
            "Starting client transaction"
        );

        // Create transport-aware timers based on the transport type
        let transport = transport_kind_to_transport(ctx.transport);
        let timers = TransportAwareTimers::with_defaults(transport, self.inner.timer_defaults);
        let transport_type = TransportType::from(transport);

        let (kind, actions) = if method == Method::Invite {
            let mut fsm = ClientInviteFsm::new(timers);
            let actions = fsm.on_event(ClientInviteEvent::SendInvite(request));
            (
                ClientKind::Invite(fsm),
                ClientRuntimeActions::Invite(actions),
            )
        } else {
            let mut fsm = ClientNonInviteFsm::new(timers);
            let actions = fsm.on_event(ClientNonInviteEvent::SendRequest(request));
            (
                ClientKind::NonInvite(fsm),
                ClientRuntimeActions::NonInvite(actions),
            )
        };

        let entry = ClientEntry {
            kind,
            ctx: ctx.clone(),
            tu,
            timers: HashMap::new(),
            start_time: Instant::now(),
            method: key.method.clone(),
        };

        // Enforce transaction limits (evict oldest if at limit)
        self.enforce_client_transaction_limit();

        self.inner.client.insert(key.clone(), entry);
        self.inner.metrics.record_start(
            transport_type,
            &format!("{:?}", key.method),
            TransactionRole::Client,
        );
        self.apply_client_actions(&key, actions).await;
        Ok(key)
    }

    /// Feeds a network response into the appropriate client transaction.
    pub async fn receive_response(&self, response: Response) {
        // Extract branch from Via header
        let branch = match Self::extract_branch(&response.headers) {
            Some(b) => b,
            None => {
                debug!("Response has no branch in Via header");
                return;
            }
        };

        // Extract method from CSeq header
        let method = match Self::extract_cseq_method(&response.headers) {
            Some(m) => m,
            None => {
                debug!("Response has no method in CSeq header");
                return;
            }
        };

        // Build transaction key (is_server=false for client transactions)
        let key = TransactionKey {
            branch: branch.clone(),
            method: method.clone(),
            is_server: false,
        };

        // Debug: Log transaction matching attempt
        let has_transaction = self.inner.client.contains_key(&key);
        debug!(
            branch = %key.branch,
            method = ?key.method,
            has_transaction = has_transaction,
            total_client_transactions = self.inner.client.len(),
            status = response.start.code,
            "Attempting to match response to client transaction"
        );

        // If no match, log all existing client transaction keys for debugging
        if !has_transaction && !self.inner.client.is_empty() {
            warn!(
                branch = %key.branch,
                method = ?key.method,
                status = response.start.code,
                "No matching client transaction for response"
            );

            // Log first few transaction keys for debugging
            let mut count = 0;
            for existing_key in self.inner.client.iter() {
                if count < 5 {
                    debug!(
                        existing_branch = %existing_key.key().branch,
                        existing_method = ?existing_key.key().method,
                        "Existing client transaction key"
                    );
                    count += 1;
                }
            }
        }

        // Look up and dispatch to client transaction
        if has_transaction {
            self.dispatch_response(&key, response).await;
        }
    }

    async fn handle_server_timer(&self, key: TransactionKey, timer: TransactionTimer) {
        // Record timer firing for metrics
        self.inner.metrics.record_timer_fired(timer);

        if let Some(mut entry) = self.inner.server.get_mut(&key) {
            entry.cancel_timer(timer);
            let transport_type =
                TransportType::from(transport_kind_to_transport(entry.ctx.transport));
            self.inner.metrics.record_retransmission(transport_type);
            let actions = match &mut entry.kind {
                ServerKind::Invite(fsm) => fsm.on_event(ServerInviteEvent::TimerFired(timer)),
                ServerKind::NonInvite(fsm) => {
                    map_server_actions(fsm.on_event(ServerNonInviteEvent::TimerFired(timer)))
                }
            };
            drop(entry);
            self.apply_server_actions(&key, actions).await;
        }
    }

    async fn handle_client_timer(&self, key: TransactionKey, timer: TransactionTimer) {
        // Record timer firing for metrics
        self.inner.metrics.record_timer_fired(timer);

        if let Some(mut entry) = self.inner.client.get_mut(&key) {
            entry.cancel_timer(timer);
            let transport_type =
                TransportType::from(transport_kind_to_transport(entry.ctx.transport));
            self.inner.metrics.record_retransmission(transport_type);
            let actions = match &mut entry.kind {
                ClientKind::Invite(fsm) => {
                    ClientRuntimeActions::Invite(fsm.on_event(ClientInviteEvent::TimerFired(timer)))
                }
                ClientKind::NonInvite(fsm) => ClientRuntimeActions::NonInvite(
                    fsm.on_event(ClientNonInviteEvent::TimerFired(timer)),
                ),
            };
            drop(entry);
            self.apply_client_actions(&key, actions).await;
        }
    }

    async fn process_client_transport_error(&self, key: TransactionKey) {
        if let Some(actions) = self.client_transport_error_actions(&key).await {
            self.apply_client_actions(&key, actions).await;
        }
    }

    async fn process_server_transport_error(&self, key: TransactionKey) {
        if let Some(actions) = self.server_transport_error_actions(&key) {
            self.apply_server_actions(&key, actions).await;
        } else if let Some((_, entry)) = self.inner.server.remove(&key) {
            // If no actions, still record outcome for metrics.
            let duration = entry.start_time.elapsed();
            let transport = TransportType::from(transport_kind_to_transport(entry.ctx.transport));
            self.inner.metrics.record_transaction_duration(
                transport,
                &format!("{:?}", entry.method),
                duration,
            );
            self.inner
                .metrics
                .record_transaction_outcome(transport, TransactionOutcome::TransportError);
            self.inner.metrics.record_complete(
                transport,
                &format!("{:?}", entry.method),
                TransactionRole::Server,
            );
        }
    }

    async fn client_transport_error_actions(
        &self,
        key: &TransactionKey,
    ) -> Option<ClientRuntimeActions> {
        if let Some(mut entry) = self.inner.client.get_mut(key) {
            let actions = match &mut entry.kind {
                ClientKind::Invite(fsm) => {
                    ClientRuntimeActions::Invite(fsm.on_event(ClientInviteEvent::TransportError))
                }
                ClientKind::NonInvite(fsm) => ClientRuntimeActions::NonInvite(
                    fsm.on_event(ClientNonInviteEvent::TransportError),
                ),
            };
            let tu = entry.tu.clone();
            drop(entry);
            tu.on_transport_error(key).await;
            Some(actions)
        } else {
            None
        }
    }

    fn server_transport_error_actions(
        &self,
        key: &TransactionKey,
    ) -> Option<Vec<ServerInviteAction>> {
        if let Some(mut entry) = self.inner.server.get_mut(key) {
            let actions = match &mut entry.kind {
                ServerKind::Invite(fsm) => fsm.on_event(ServerInviteEvent::TransportError),
                ServerKind::NonInvite(fsm) => {
                    map_server_actions(fsm.on_event(ServerNonInviteEvent::TransportError))
                }
            };
            drop(entry);
            Some(actions)
        } else {
            None
        }
    }

    async fn apply_server_actions(&self, key: &TransactionKey, actions: Vec<ServerInviteAction>) {
        for action in actions {
            match action {
                ServerInviteAction::Transmit {
                    bytes,
                    transport: _,
                } => {
                    if let Some(entry) = self.inner.server.get(key) {
                        let ctx = entry.ctx.clone();
                        drop(entry);
                        if let Err(e) = self.dispatch_with_pool(&ctx, bytes.clone()).await {
                            error!(%e, key = ?key, "server transport dispatch failed");
                            let _ = self
                                .cmd_tx
                                .send(ManagerCommand::ServerTransportError { key: key.clone() })
                                .await;
                        }
                    }
                }
                ServerInviteAction::Schedule { timer, duration } => {
                    self.schedule_timer(key.clone(), timer, duration);
                }
                ServerInviteAction::Cancel(timer) => {
                    if let Some(mut entry) = self.inner.server.get_mut(key) {
                        entry.cancel_timer(timer);
                    }
                }
                ServerInviteAction::Terminate { .. } => {
                    if let Some((_, mut entry)) = self.inner.server.remove(key) {
                        entry.cancel_all();
                        let duration = entry.start_time.elapsed();
                        let transport =
                            TransportType::from(transport_kind_to_transport(entry.ctx.transport));
                        self.inner.metrics.record_transaction_duration(
                            transport,
                            &format!("{:?}", entry.method),
                            duration,
                        );
                        self.inner
                            .metrics
                            .record_transaction_outcome(transport, TransactionOutcome::Completed);
                        self.inner.metrics.record_complete(
                            transport,
                            &format!("{:?}", entry.method),
                            TransactionRole::Server,
                        );
                    }
                }
            }
        }
    }

    async fn apply_client_actions(&self, key: &TransactionKey, actions: ClientRuntimeActions) {
        match actions {
            ClientRuntimeActions::Invite(actions) => {
                self.apply_client_invite_actions(key, actions).await;
            }
            ClientRuntimeActions::NonInvite(actions) => {
                self.apply_client_non_invite_actions(key, actions).await;
            }
        }
    }

    async fn apply_client_invite_actions(
        &self,
        key: &TransactionKey,
        actions: Vec<ClientInviteAction>,
    ) {
        for action in actions {
            match action {
                ClientInviteAction::Transmit { bytes, .. } => {
                    if let Some(entry) = self.inner.client.get(key) {
                        let transport_type =
                            TransportType::from(transport_kind_to_transport(entry.ctx.transport));
                        self.inner.metrics.record_retransmission(transport_type);
                    }
                    if let Some(entry) = self.inner.client.get(key) {
                        let ctx = entry.ctx.clone();
                        drop(entry);
                        if let Err(e) = self.dispatch_with_pool(&ctx, bytes).await {
                            error!(%e, key = ?key, "client transport dispatch failed");
                            let _ = self
                                .cmd_tx
                                .send(ManagerCommand::ClientTransportError { key: key.clone() })
                                .await;
                        }
                    }
                }
                ClientInviteAction::Deliver(response) => {
                    if let Some(entry) = self.inner.client.get(key) {
                        let tu = entry.tu.clone();
                        drop(entry);
                        if response.start.code < 200 {
                            tu.on_provisional(key, &response).await;
                        } else {
                            tu.on_final(key, &response).await;
                        }
                    }
                }
                ClientInviteAction::ExpectPrack(response) => {
                    if let Some(entry) = self.inner.client.get(key) {
                        let tu = entry.tu.clone();
                        let ctx = entry.ctx.clone();
                        drop(entry);
                        tu.send_prack(key, response, &ctx).await;
                    }
                }
                ClientInviteAction::GenerateAck { response, is_2xx } => {
                    if let Some(entry) = self.inner.client.get(key) {
                        let tu = entry.tu.clone();
                        let ctx = entry.ctx.clone();
                        drop(entry);
                        tu.send_ack(key, response, &ctx, is_2xx).await;
                    }
                }
                ClientInviteAction::Schedule { timer, duration } => {
                    self.schedule_client_timer(key.clone(), timer, duration);
                }
                ClientInviteAction::Cancel(timer) => {
                    if let Some(mut entry) = self.inner.client.get_mut(key) {
                        entry.cancel_timer(timer);
                    }
                }
                ClientInviteAction::Terminate { reason } => {
                    if let Some(mut entry) = self.inner.client.get_mut(key) {
                        entry.cancel_all();
                        let tu = entry.tu.clone();
                        drop(entry);
                        tu.on_terminated(key, reason.as_str()).await;
                    }
                    self.inner.client.remove(key);
                }
            }
        }
    }

    async fn apply_client_non_invite_actions(
        &self,
        key: &TransactionKey,
        actions: Vec<ClientAction>,
    ) {
        for action in actions {
            match action {
                ClientAction::Transmit { bytes, .. } => {
                    if let Some(entry) = self.inner.client.get(key) {
                        let transport_type =
                            TransportType::from(transport_kind_to_transport(entry.ctx.transport));
                        self.inner.metrics.record_retransmission(transport_type);
                    }
                    if let Some(entry) = self.inner.client.get(key) {
                        let ctx = entry.ctx.clone();
                        drop(entry);
                        if let Err(e) = self.dispatch_with_pool(&ctx, bytes).await {
                            error!(%e, key = ?key, "client transport dispatch failed");
                            let _ = self
                                .cmd_tx
                                .send(ManagerCommand::ClientTransportError { key: key.clone() })
                                .await;
                        }
                    }
                }
                ClientAction::Deliver(response) => {
                    if let Some(entry) = self.inner.client.get(key) {
                        let tu = entry.tu.clone();
                        drop(entry);
                        if response.start.code < 200 {
                            tu.on_provisional(key, &response).await;
                        } else {
                            tu.on_final(key, &response).await;
                        }
                    }
                }
                ClientAction::Schedule { timer, duration } => {
                    self.schedule_client_timer(key.clone(), timer, duration);
                }
                ClientAction::Cancel(timer) => {
                    if let Some(mut entry) = self.inner.client.get_mut(key) {
                        entry.cancel_timer(timer);
                    }
                }
                ClientAction::Terminate { reason } => {
                    if let Some((_, entry)) = self.inner.client.remove(key) {
                        let duration = entry.start_time.elapsed();
                        let transport =
                            TransportType::from(transport_kind_to_transport(entry.ctx.transport));
                        let outcome = if reason.contains("Timer") {
                            TransactionOutcome::Timeout
                        } else if reason.contains("transport") {
                            TransactionOutcome::TransportError
                        } else if reason.contains("CANCEL") {
                            TransactionOutcome::Cancelled
                        } else {
                            TransactionOutcome::Completed
                        };

                        self.inner.metrics.record_transaction_duration(
                            transport,
                            &format!("{:?}", entry.method),
                            duration,
                        );
                        self.inner
                            .metrics
                            .record_transaction_outcome(transport, outcome);
                        self.inner.metrics.record_complete(
                            transport,
                            &format!("{:?}", entry.method),
                            TransactionRole::Client,
                        );

                        entry.tu.on_terminated(key, reason.as_str()).await;
                    }
                }
            }
        }
    }

    fn schedule_client_timer(
        &self,
        key: TransactionKey,
        timer: TransactionTimer,
        duration: Duration,
    ) {
        if duration.is_zero() {
            let mut should_fire = false;
            if let Some(mut entry) = self.inner.client.get_mut(&key) {
                entry.cancel_timer(timer);
                should_fire = true;
            }
            if should_fire {
                let cmd_tx = self.cmd_tx.clone();
                tokio::spawn(async move {
                    let _ = cmd_tx
                        .send(ManagerCommand::ClientTimerFired { key, timer })
                        .await;
                });
            }
            return;
        }
        if let Some(mut entry) = self.inner.client.get_mut(&key) {
            entry.cancel_timer(timer);
            let (cancel_tx, mut cancel_rx) = oneshot::channel();
            entry.timers.insert(timer, cancel_tx);
            if entry.timers.len() > MAX_TIMER_BUCKETS {
                error!(key = ?key, "too many client timers; dropping new timer");
                entry.timers.remove(&timer);
                return;
            }
            let cmd_tx = self.cmd_tx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = time::sleep(duration) => {
                        let _ = cmd_tx.send(ManagerCommand::ClientTimerFired { key, timer }).await;
                    }
                    _ = &mut cancel_rx => {}
                }
            });
        }
    }

    fn schedule_timer(&self, key: TransactionKey, timer: TransactionTimer, duration: Duration) {
        if duration.is_zero() {
            let mut should_fire = false;
            if let Some(mut entry) = self.inner.server.get_mut(&key) {
                entry.cancel_timer(timer);
                should_fire = true;
            }
            if should_fire {
                let cmd_tx = self.cmd_tx.clone();
                tokio::spawn(async move {
                    let _ = cmd_tx
                        .send(ManagerCommand::ServerTimerFired { key, timer })
                        .await;
                });
            }
            return;
        }
        if let Some(mut entry) = self.inner.server.get_mut(&key) {
            entry.cancel_timer(timer);
            let (cancel_tx, mut cancel_rx) = oneshot::channel();
            entry.timers.insert(timer, cancel_tx);
            if entry.timers.len() > MAX_TIMER_BUCKETS {
                error!(key = ?key, "too many server timers; dropping new timer");
                entry.timers.remove(&timer);
                return;
            }
            let cmd_tx = self.cmd_tx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = time::sleep(duration) => {
                        let _ = cmd_tx.send(ManagerCommand::ServerTimerFired { key, timer }).await;
                    }
                    _ = &mut cancel_rx => { }
                }
            });
        }
    }

    pub async fn send_provisional(&self, key: &TransactionKey, response: Response) {
        if let Some(mut entry) = self.inner.server.get_mut(key) {
            let actions = match &mut entry.kind {
                ServerKind::Invite(fsm) => {
                    fsm.on_event(ServerInviteEvent::SendProvisional(response))
                }
                ServerKind::NonInvite(fsm) => map_server_actions(
                    fsm.on_event(ServerNonInviteEvent::SendProvisional(response)),
                ),
            };
            drop(entry);
            self.apply_server_actions(key, actions).await;
        }
    }

    pub async fn send_final(&self, key: &TransactionKey, response: Response) {
        if let Some(mut entry) = self.inner.server.get_mut(key) {
            let actions = match &mut entry.kind {
                ServerKind::Invite(fsm) => fsm.on_event(ServerInviteEvent::SendFinal(response)),
                ServerKind::NonInvite(fsm) => {
                    map_server_actions(fsm.on_event(ServerNonInviteEvent::SendFinal(response)))
                }
            };
            drop(entry);
            self.apply_server_actions(key, actions).await;
        }
    }

    pub async fn ack_received(&self, key: &TransactionKey) {
        if let Some(mut entry) = self.inner.server.get_mut(key) {
            let actions = match &mut entry.kind {
                ServerKind::Invite(fsm) => fsm.on_event(ServerInviteEvent::ReceiveAck),
                ServerKind::NonInvite(fsm) => {
                    map_server_actions(fsm.on_event(ServerNonInviteEvent::AckReceived))
                }
            };
            drop(entry);
            self.apply_server_actions(key, actions).await;
        }
    }

    async fn dispatch_response(&self, key: &TransactionKey, response: Response) {
        if let Some(mut entry) = self.inner.client.get_mut(key) {
            let is_provisional = response.start.code < 200;
            let actions = match (is_provisional, response) {
                (true, response) => match &mut entry.kind {
                    ClientKind::Invite(fsm) => ClientRuntimeActions::Invite(
                        fsm.on_event(ClientInviteEvent::ReceiveProvisional(response)),
                    ),
                    ClientKind::NonInvite(fsm) => ClientRuntimeActions::NonInvite(
                        fsm.on_event(ClientNonInviteEvent::ReceiveProvisional(response)),
                    ),
                },
                (false, response) => match &mut entry.kind {
                    ClientKind::Invite(fsm) => ClientRuntimeActions::Invite(
                        fsm.on_event(ClientInviteEvent::ReceiveFinal(response)),
                    ),
                    ClientKind::NonInvite(fsm) => ClientRuntimeActions::NonInvite(
                        fsm.on_event(ClientNonInviteEvent::ReceiveFinal(response)),
                    ),
                },
            };
            drop(entry);
            self.apply_client_actions(key, actions).await;
        }
    }
}

#[derive(Clone)]
pub struct ServerTransactionHandle {
    manager: TransactionManager,
    key: TransactionKey,
}

impl ServerTransactionHandle {
    pub async fn send_final(&self, response: Response) {
        self.manager.send_final(&self.key, response).await;
    }

    pub async fn send_provisional(&self, response: Response) {
        self.manager.send_provisional(&self.key, response).await;
    }

    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    pub async fn ack_received(&self) {
        self.manager.ack_received(&self.key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::{
        headers::Headers,
        method::Method,
        msg::{RequestLine, StatusLine},
        uri::SipUri,
    };
    use smol_str::SmolStr;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct TestDispatcher {
        sent: Mutex<Vec<(TransportKind, Bytes)>>,
    }

    #[derive(Default)]
    struct TestClientTu {
        provisional: Mutex<Vec<u16>>,
        finals: Mutex<Vec<u16>>,
        terminated: Mutex<Vec<String>>,
        sent_acks: Mutex<Vec<(bool, u16)>>,
        sent_pracks: Mutex<Vec<u16>>,
        transport_errors: Mutex<u32>,
    }

    #[async_trait]
    impl TransportDispatcher for TestDispatcher {
        async fn dispatch(&self, ctx: &TransportContext, payload: Bytes) -> Result<()> {
            let mut guard = self.sent.lock().await;
            guard.push((ctx.transport, payload));
            Ok(())
        }
    }

    #[async_trait]
    impl ClientTransactionUser for TestClientTu {
        async fn on_provisional(&self, _key: &TransactionKey, response: &Response) {
            let mut guard = self.provisional.lock().await;
            guard.push(response.start.code);
        }

        async fn on_final(&self, _key: &TransactionKey, response: &Response) {
            let mut guard = self.finals.lock().await;
            guard.push(response.start.code);
        }

        async fn on_terminated(&self, _key: &TransactionKey, reason: &str) {
            let mut guard = self.terminated.lock().await;
            guard.push(reason.to_owned());
        }

        async fn send_ack(
            &self,
            _key: &TransactionKey,
            response: Response,
            _ctx: &TransportContext,
            is_2xx: bool,
        ) {
            let mut guard = self.sent_acks.lock().await;
            guard.push((is_2xx, response.start.code));
        }

        async fn send_prack(
            &self,
            _key: &TransactionKey,
            response: Response,
            _ctx: &TransportContext,
        ) {
            let mut guard = self.sent_pracks.lock().await;
            guard.push(response.start.code);
        }

        async fn on_transport_error(&self, _key: &TransactionKey) {
            let mut guard = self.transport_errors.lock().await;
            *guard += 1;
        }
    }

    fn build_request(method: Method) -> Request {
        Request::new(
            RequestLine::new(method, SipUri::parse("sip:example.com").unwrap()),
            Headers::new(),
            Bytes::new(),
        )
    }

    fn build_response(code: u16) -> Response {
        Response::new(
            StatusLine::new(code, SmolStr::new("OK")),
            Headers::new(),
            Bytes::new(),
        )
    }

    fn build_client_request(method: Method, branch: &str) -> Request {
        let mut headers = Headers::new();
        let via = format!("SIP/2.0/UDP host.invalid;branch={}", branch);
        headers.push_unchecked(SmolStr::new("Via"), SmolStr::new(via));
        Request::new(
            RequestLine::new(method, SipUri::parse("sip:example.com").unwrap()),
            headers,
            Bytes::new(),
        )
    }

    fn build_response_with_branch(code: u16, branch: &str, method: Method) -> Response {
        let mut headers = Headers::new();
        let via = format!("SIP/2.0/UDP host.invalid;branch={}", branch);
        headers.push_unchecked(SmolStr::new("Via"), SmolStr::new(via));
        // Add CSeq header with method for transaction matching
        let cseq = format!("1 {}", method.as_str());
        headers.push_unchecked(SmolStr::new("CSeq"), SmolStr::new(cseq));
        Response::new(
            StatusLine::new(code, SmolStr::new("OK")),
            headers,
            Bytes::new(),
        )
    }

    fn build_response_with_branch_reliable(code: u16, branch: &str, method: Method) -> Response {
        let mut response = build_response_with_branch(code, branch, method);
        response
            .headers
            .push(SmolStr::new("Require"), SmolStr::new("100rel"));
        response
            .headers
            .push(SmolStr::new("RSeq"), SmolStr::new("1"));
        response
    }

    async fn expect_termination(tu: &Arc<TestClientTu>, needle: &str) {
        for _ in 0..50 {
            {
                let reasons = tu.terminated.lock().await;
                if reasons.iter().any(|reason| reason.contains(needle)) {
                    return;
                }
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        let reasons = tu.terminated.lock().await;
        panic!(
            "transaction did not record termination reason containing '{needle}', got {:?}",
            *reasons
        );
    }

    #[tokio::test]
    async fn manager_sends_final_response() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let manager = TransactionManager::new(dispatcher.clone());
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5060".parse().unwrap(), None);
        let handle = manager
            .receive_request(build_request(Method::Options), ctx)
            .await;
        handle.send_final(build_response(200)).await;

        let sent = dispatcher.sent.lock().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, TransportKind::Udp);
    }

    #[tokio::test]
    async fn client_non_invite_transaction_notifies_tu() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let manager = TransactionManager::new(dispatcher);
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5080".parse().unwrap(), None);
        let tu = Arc::new(TestClientTu::default());
        let branch = "z9hG4bKnoninvite";
        let _key = manager
            .start_client_transaction(
                build_client_request(Method::Options, branch),
                ctx.clone(),
                tu.clone(),
            )
            .await
            .unwrap();

        manager
            .receive_response(build_response_with_branch(180, branch, Method::Options))
            .await;
        manager
            .receive_response(build_response_with_branch(200, branch, Method::Options))
            .await;

        let provisional = tu.provisional.lock().await;
        assert_eq!(provisional.as_slice(), &[180]);
        drop(provisional);

        let finals = tu.finals.lock().await;
        assert_eq!(finals.as_slice(), &[200]);
    }

    #[tokio::test]
    async fn client_invite_transaction_generates_prack_and_ack() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let manager = TransactionManager::new(dispatcher);
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5082".parse().unwrap(), None);
        let tu = Arc::new(TestClientTu::default());
        let branch = "z9hG4bKinvite";
        manager
            .start_client_transaction(
                build_client_request(Method::Invite, branch),
                ctx.clone(),
                tu.clone(),
            )
            .await
            .unwrap();

        manager
            .receive_response(build_response_with_branch_reliable(
                183,
                branch,
                Method::Invite,
            ))
            .await;
        manager
            .receive_response(build_response_with_branch(200, branch, Method::Invite))
            .await;

        let provisional = tu.provisional.lock().await;
        assert_eq!(provisional.as_slice(), &[183]);
        drop(provisional);

        let pracks = tu.sent_pracks.lock().await;
        assert_eq!(pracks.as_slice(), &[183]);
        drop(pracks);

        let finals = tu.finals.lock().await;
        assert_eq!(finals.as_slice(), &[200]);
        drop(finals);

        let acks = tu.sent_acks.lock().await;
        assert_eq!(acks.as_slice(), &[(true, 200)]);
    }

    #[tokio::test]
    async fn client_non_invite_retransmits_on_timer_e() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let manager = TransactionManager::with_timers(
            dispatcher.clone(),
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(25),
        );
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5084".parse().unwrap(), None);
        let tu = Arc::new(TestClientTu::default());
        let branch = "z9hG4bKtimerE";
        let key = manager
            .start_client_transaction(
                build_client_request(Method::Options, branch),
                ctx.clone(),
                tu.clone(),
            )
            .await
            .unwrap();

        {
            let sent = dispatcher.sent.lock().await;
            assert_eq!(sent.len(), 1);
        }

        time::sleep(Duration::from_millis(15)).await;
        let sent = dispatcher.sent.lock().await;
        assert_eq!(
            sent.len(),
            2,
            "Timer E should trigger a retransmission of the request"
        );

        manager
            .handle_client_timer(key.clone(), TransactionTimer::F)
            .await;
        expect_termination(&tu, "Timer F expired").await;
        assert!(
            manager.inner.client.is_empty(),
            "client transaction should be removed after Timer F"
        );
    }

    #[tokio::test]
    async fn client_invite_retransmits_and_times_out() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let manager = TransactionManager::with_timers(
            dispatcher.clone(),
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(25),
        );
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5086".parse().unwrap(), None);
        let tu = Arc::new(TestClientTu::default());
        let branch = "z9hG4bKtimerA";
        manager
            .start_client_transaction(
                build_client_request(Method::Invite, branch),
                ctx.clone(),
                tu.clone(),
            )
            .await
            .unwrap();

        {
            let sent = dispatcher.sent.lock().await;
            assert_eq!(sent.len(), 1);
        }

        time::sleep(Duration::from_millis(15)).await;
        {
            let sent = dispatcher.sent.lock().await;
            assert_eq!(
                sent.len(),
                2,
                "Timer A should retransmit the INVITE before any response is received"
            );
        }

        expect_termination(&tu, "Timer B expired").await;
    }

    #[tokio::test]
    async fn server_retransmits_on_duplicate_request() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let manager = TransactionManager::with_timers(
            dispatcher.clone(),
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(250),
        );
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5090".parse().unwrap(), None);
        let mut request = build_request(Method::Invite);
        request.headers.push_unchecked(
            SmolStr::new("Via"),
            SmolStr::new("SIP/2.0/UDP host;branch=z9hG4bKretrans".to_owned()),
        );
        let handle = manager.receive_request(request.clone(), ctx.clone()).await;
        handle.send_final(build_response(486)).await;

        {
            let sent = dispatcher.sent.lock().await;
            assert_eq!(sent.len(), 1);
        }

        // Same request/branch arriving again should retransmit last final response.
        manager.receive_request(request, ctx).await;
        let sent = dispatcher.sent.lock().await;
        assert_eq!(sent.len(), 2);
    }

    #[tokio::test]
    async fn server_transaction_limit_enforced() {
        let dispatcher = Arc::new(TestDispatcher::default());
        // Create manager with very small limit for testing
        let limits = TransactionLimits::new(5, 5);
        let manager = TransactionManager::with_timers_and_limits(
            dispatcher.clone(),
            Duration::from_secs(1),
            Duration::from_secs(4),
            Duration::from_secs(5),
            limits,
        );
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5060".parse().unwrap(), None);

        // Create 5 transactions (at limit)
        for i in 0..5 {
            let mut request = build_request(Method::Invite);
            request.headers.push_unchecked(
                SmolStr::new("Via"),
                SmolStr::new(format!("SIP/2.0/UDP host;branch=z9hG4bKtest{}", i)),
            );
            manager.receive_request(request, ctx.clone()).await;
        }

        // Verify we have 5 server transactions
        assert_eq!(manager.inner.server.len(), 5);

        // Add one more transaction - should trigger eviction
        let mut request = build_request(Method::Invite);
        request.headers.push_unchecked(
            SmolStr::new("Via"),
            SmolStr::new("SIP/2.0/UDP host;branch=z9hG4bKtest_overflow".to_owned()),
        );
        manager.receive_request(request, ctx).await;

        // Should still have 5 transactions (oldest evicted, new one added)
        assert_eq!(manager.inner.server.len(), 5);
    }

    #[tokio::test]
    async fn client_transaction_limit_enforced() {
        let dispatcher = Arc::new(TestDispatcher::default());
        // Create manager with very small limit for testing
        let limits = TransactionLimits::new(5, 3);
        let manager = TransactionManager::with_timers_and_limits(
            dispatcher.clone(),
            Duration::from_secs(1),
            Duration::from_secs(4),
            Duration::from_secs(5),
            limits,
        );
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5060".parse().unwrap(), None);
        let tu = Arc::new(TestClientTu::default());

        // Create 3 client transactions (at limit)
        for i in 0..3 {
            let mut request = build_request(Method::Invite);
            request.headers.push_unchecked(
                SmolStr::new("Via"),
                SmolStr::new(format!("SIP/2.0/UDP host;branch=z9hG4bKclient{}", i)),
            );
            let _ = manager
                .start_client_transaction(request, ctx.clone(), tu.clone())
                .await;
        }

        // Verify we have 3 client transactions
        assert_eq!(manager.inner.client.len(), 3);

        // Add one more transaction - should trigger eviction
        let mut request = build_request(Method::Invite);
        request.headers.push_unchecked(
            SmolStr::new("Via"),
            SmolStr::new("SIP/2.0/UDP host;branch=z9hG4bKclient_overflow".to_owned()),
        );
        let _ = manager
            .start_client_transaction(request, ctx.clone(), tu.clone())
            .await;

        // Should still have 3 transactions (oldest evicted, new one added)
        assert_eq!(manager.inner.client.len(), 3);
    }

    #[tokio::test]
    async fn oldest_transaction_evicted_first() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let limits = TransactionLimits::new(3, 3);
        let manager = TransactionManager::with_timers_and_limits(
            dispatcher.clone(),
            Duration::from_secs(1),
            Duration::from_secs(4),
            Duration::from_secs(5),
            limits,
        );
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5060".parse().unwrap(), None);

        // Create 3 transactions with small delays to ensure ordering
        for i in 0..3 {
            let mut request = build_request(Method::Options);
            request.headers.push_unchecked(
                SmolStr::new("Via"),
                SmolStr::new(format!("SIP/2.0/UDP host;branch=z9hG4bKorder{}", i)),
            );
            manager.receive_request(request, ctx.clone()).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Verify first transaction exists
        let first_key = TransactionKey {
            branch: SmolStr::new("z9hG4bKorder0"),
            method: Method::Options,
            is_server: true,
        };
        assert!(manager.inner.server.contains_key(&first_key));

        // Add one more - should evict the oldest (first one)
        let mut request = build_request(Method::Options);
        request.headers.push_unchecked(
            SmolStr::new("Via"),
            SmolStr::new("SIP/2.0/UDP host;branch=z9hG4bKorder3".to_owned()),
        );
        manager.receive_request(request, ctx).await;

        // First transaction should be gone
        assert!(!manager.inner.server.contains_key(&first_key));

        // Last transaction should exist
        let last_key = TransactionKey {
            branch: SmolStr::new("z9hG4bKorder3"),
            method: Method::Options,
            is_server: true,
        };
        assert!(manager.inner.server.contains_key(&last_key));
    }

    #[tokio::test]
    async fn unlimited_transactions_for_testing() {
        let dispatcher = Arc::new(TestDispatcher::default());
        let limits = TransactionLimits::unlimited();
        let manager = TransactionManager::with_limits(dispatcher.clone(), limits);
        let ctx =
            TransportContext::new(TransportKind::Udp, "127.0.0.1:5060".parse().unwrap(), None);

        // Create many transactions without hitting limit
        for i in 0..100 {
            let mut request = build_request(Method::Options);
            request.headers.push_unchecked(
                SmolStr::new("Via"),
                SmolStr::new(format!("SIP/2.0/UDP host;branch=z9hG4bKunlim{}", i)),
            );
            manager.receive_request(request, ctx.clone()).await;
        }

        // Should have all 100 transactions
        assert_eq!(manager.inner.server.len(), 100);
    }
}
