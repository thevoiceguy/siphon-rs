// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Integrated UAC with full transaction, transport, and DNS integration.
///
/// This module provides a production-ready UAC implementation that integrates:
/// - Transaction layer (automatic retransmissions, state management)
/// - Transport layer (DNS-driven transport selection, Via/Contact auto-filling)
/// - Authentication (automatic retry on 401/407)
/// - Dialog and subscription management
///
/// # Architecture
///
/// The integrated UAC uses composition over modification:
/// - Embeds the low-level `UserAgentClient` helper for request generation
/// - Adds transaction/transport/DNS integration on top
/// - Provides async methods that return handles with awaitable responses
///
/// # Example
///
/// ```ignore
/// use sip_uac::integrated::{IntegratedUAC, UACConfig};
/// use sip_transaction::TransactionManager;
/// use sip_dns::SipResolver;
/// use std::sync::Arc;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Build integrated UAC
/// let uac = IntegratedUAC::builder()
///     .local_uri("sip:alice@example.com")
///     .local_addr("192.168.1.100:5060")
///     .credentials("alice", "password")
///     .transaction_manager(tx_mgr)
///     .resolver(resolver)
///     .dispatcher(dispatcher)
///     .build()?;
///
/// // Make a call - automatically handles transactions, DNS, auth
/// let target = "sip:bob@example.com";
/// let call = uac.invite(target, Some(sdp)).await?;
///
/// // Wait for response
/// match call.await_final().await {
///     Ok(response) if response.code() == 200 => {
///         println!("Call connected!");
///     }
///     Ok(response) => {
///         println!("Call rejected: {}", response.code());
///     }
///     Err(e) => {
///         println!("Call failed: {}", e);
///     }
/// }
/// # Ok(())
/// # }
/// ```
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri};
use sip_dialog::{Dialog, DialogManager, DialogStateType, Subscription, SubscriptionManager};
use sip_dns::{DnsTarget, Resolver, SipResolver};
use sip_parse::serialize_request;
use sip_sdp::{profiles, SessionDescription};
use sip_transaction::{
    ClientTransactionUser, TransactionKey, TransactionManager, TransportContext,
    TransportDispatcher,
};
use smol_str::SmolStr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::{auth_utils::extract_realm, UserAgentClient};

/// Trait for generating SDP answers in late offer scenarios.
///
/// In a late offer flow:
/// 1. Caller sends INVITE without SDP
/// 2. Callee responds with 200 OK containing SDP offer
/// 3. Caller must send ACK with SDP answer
///
/// This trait allows applications to dynamically generate the SDP answer
/// based on the received offer and dialog context using RFC 3264 negotiation.
#[async_trait]
pub trait SdpAnswerGenerator: Send + Sync {
    /// Generate an SDP answer for the given SDP offer.
    ///
    /// # Arguments
    /// * `offer` - The SDP offer received in the 200 OK response (parsed)
    /// * `dialog` - The dialog context for this call
    ///
    /// # Returns
    /// The SDP answer to be sent in the ACK, or an error if answer generation fails
    async fn generate_answer(
        &self,
        offer: &SessionDescription,
        dialog: &Dialog,
    ) -> Result<SessionDescription>;
}

/// Configuration for IntegratedUAC behavior.
#[derive(Clone)]
pub struct UACConfig {
    /// Automatically retry requests on 401/407 auth challenges (default: true)
    pub auto_retry_auth: bool,

    /// Maximum number of authentication retries (default: 2)
    pub max_auth_retries: u32,

    /// Consecutive RFC 4028 session refresh failures before the timer task
    /// gives up and reports [`SessionTimerStop::Exhausted`] (default: 3).
    ///
    /// A `408`/`481` is terminal on the first occurrence regardless of this
    /// value — the peer has said the dialog is gone. This counts the failures
    /// that might still be transient: timeouts, transport errors, and non-2xx
    /// rejections. `0` is treated as 1.
    pub max_session_refresh_failures: u32,

    /// Default REGISTER expires value in seconds (default: 3600)
    pub default_register_expires: u32,

    /// Default SUBSCRIBE expires value in seconds (default: 3600)
    pub default_subscribe_expires: u32,

    /// User-Agent header value (default: "siphon-rs/0.1.0")
    pub user_agent: String,

    /// Automatically fill Via header from local transport context (default: true)
    pub auto_via_filling: bool,

    /// Automatically fill Contact header from local transport context (default: true)
    pub auto_contact_filling: bool,

    /// Automatically resolve DNS per RFC 3263 (default: true)
    pub auto_dns_resolution: bool,

    /// Optional SDP answer generator for late offer scenarios (default: None)
    ///
    /// When set, this will be invoked when receiving a 200 OK with SDP offer
    /// after sending an INVITE without SDP (late offer flow per RFC 3264).
    /// The generator provides the SDP answer to be sent in the ACK.
    pub sdp_answer_generator: Option<Arc<dyn SdpAnswerGenerator>>,

    /// SDP profile for generating offers (default: None - requires explicit SDP)
    ///
    /// When set, the UAC can generate SDP offers automatically using
    /// pre-configured profiles (AudioOnly, AudioVideo, Custom).
    pub sdp_profile: Option<profiles::SdpProfile>,
    pub sdp_profile_builder: Option<profiles::MediaProfileBuilder>,

    /// Local RTP audio port for SDP (default: 8000)
    pub local_audio_port: u16,

    /// Local RTP video port for SDP (default: 8002)
    pub local_video_port: u16,

    /// Enable keepalives (CRLF or OPTIONS) per transport.
    pub keepalive_policy: KeepalivePolicy,

    /// Advertised address for Via (overrides local_addr/public_addr).
    pub via_advertised: Option<SocketAddr>,

    /// Advertised address for Contact (overrides local_addr/public_addr).
    pub contact_advertised: Option<SocketAddr>,

    /// Optional dynamic resolver for public address (e.g., STUN).
    pub public_addr_resolver: Option<Arc<dyn PublicAddrResolver>>,

    /// Optional credential provider callback (per realm).
    pub credential_provider: Option<Arc<dyn CredentialProvider>>,

    /// Optional full WS/WSS URI override for outbound requests (e.g., ws://lb:80/sip).
    pub ws_target_uri: Option<String>,

    /// Optional WS path suffix to append when building ws://host/path from DNS target.
    pub ws_path: Option<String>,

    /// Enable RFC 5626 outbound behavior (adds ;ob/+sip.instance on REGISTER and Supported: outbound).
    pub enable_outbound: bool,

    /// Optional instance-id (RFC 5626) used for +sip.instance on REGISTER.
    pub instance_id: Option<String>,

    /// Optional flow token salt reserved for GRUU token generation.
    pub flow_token_salt: Option<String>,

    /// Registration identifier for outbound flows (RFC 5626 reg-id).
    pub outbound_reg_id: u32,

    /// TLS certificate name (SNI + verification) to use when dialing a
    /// target whose host is an IP literal (default: None).
    ///
    /// In-dialog requests are routed by the dialog's route set, and
    /// carrier edges Record-Route themselves as IP literals. A fresh
    /// TLS dial to such a hop would use the IP as SNI and fail the
    /// certificate check — real carrier certs carry no IP SANs (issue
    /// #76). Set this to the trunk's hostname (e.g.
    /// `example.pstn.twilio.com`) so fresh dials verify against the
    /// configured name instead. Targets that already resolve to a
    /// hostname are unaffected.
    pub tls_server_name: Option<String>,
}

impl Default for UACConfig {
    fn default() -> Self {
        Self {
            auto_retry_auth: true,
            max_auth_retries: 2,
            max_session_refresh_failures: 3,
            default_register_expires: 3600,
            default_subscribe_expires: 3600,
            user_agent: "siphon-rs/0.1.0".to_string(),
            auto_via_filling: true,
            auto_contact_filling: true,
            auto_dns_resolution: true,
            sdp_answer_generator: None,
            sdp_profile: None,
            sdp_profile_builder: None,
            local_audio_port: 8000,
            local_video_port: 8002,
            keepalive_policy: KeepalivePolicy::default(),
            via_advertised: None,
            contact_advertised: None,
            public_addr_resolver: None,
            credential_provider: None,
            ws_target_uri: None,
            ws_path: None,
            enable_outbound: false,
            instance_id: None,
            flow_token_salt: None,
            outbound_reg_id: 1,
            tls_server_name: None,
        }
    }
}

/// Keepalive policy for maintaining NAT/LB bindings.
#[derive(Clone)]
pub struct KeepalivePolicy {
    /// Enable CRLF keepalives on UDP.
    pub enable_udp: bool,
    /// Enable CRLF keepalives on TCP/TLS.
    pub enable_stream: bool,
    /// Enable OPTIONS pings.
    pub enable_options: bool,
    /// Interval for keepalives (seconds).
    pub interval_secs: u64,
}

/// Resolve current public address (e.g., via STUN or control-plane).
#[async_trait]
pub trait PublicAddrResolver: Send + Sync {
    async fn resolve(&self) -> Option<SocketAddr>;
}

/// Provide credentials dynamically (per realm) for authentication challenges.
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    async fn credentials(&self, realm: &str) -> Option<(String, String)>;
}

impl Default for KeepalivePolicy {
    fn default() -> Self {
        Self {
            enable_udp: true,
            enable_stream: true,
            enable_options: false,
            interval_secs: 30,
        }
    }
}

/// Target for a SIP request - either a URI (auto-resolves DNS) or pre-resolved target.
#[derive(Debug, Clone)]
pub enum RequestTarget {
    /// SIP URI - will be resolved via DNS per RFC 3263
    Uri(SipUri),

    /// Pre-resolved DNS target (host, port, transport)
    Resolved(DnsTarget),
}

impl RequestTarget {
    /// Convert to a SipUri if possible.
    pub fn to_uri(&self) -> Option<SipUri> {
        match self {
            RequestTarget::Uri(uri) => Some(uri.clone()),
            RequestTarget::Resolved(dns) => {
                let scheme = match dns.transport() {
                    sip_dns::Transport::Tls => "sips",
                    _ => "sip",
                };
                SipUri::parse(&format!("{}:{}:{}", scheme, dns.host(), dns.port())).ok()
            }
        }
    }
}

impl From<SipUri> for RequestTarget {
    fn from(uri: SipUri) -> Self {
        RequestTarget::Uri(uri)
    }
}

/// An established inbound connection to send requests through (RFC 5626 flow).
///
/// When a peer reaches us over a connection-oriented transport (TCP/TLS),
/// in-dialog requests we originate (BYE, REFER, re-INVITE) must ride the
/// *same* connection: the peer's Contact usually names an ephemeral source
/// port that nothing listens on, so opening a fresh connection per RFC 3263
/// resolution fails. A `Flow` bundles what the `*_via_flow` methods need to
/// reuse the connection instead.
///
/// `local_addr` is the local address of the listener that owns the
/// connection. When set, the auto-filled `Via` advertises that listener's
/// port instead of the UAC's configured (default-listener) port, keeping
/// `Via` consistent with the transport the request actually leaves on —
/// the same rule the UAS applies to `Contact`. Optional because responses
/// ride the connection regardless (RFC 3261 §18.2.2).
#[derive(Clone)]
pub struct Flow {
    stream: mpsc::Sender<Bytes>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
}

impl Flow {
    /// Creates a flow from a connection's write handle and the peer's address.
    pub fn new(stream: mpsc::Sender<Bytes>, peer_addr: SocketAddr) -> Self {
        Self {
            stream,
            peer_addr,
            local_addr: None,
        }
    }

    /// Sets the local address of the listener that owns this connection,
    /// so the auto-filled `Via` can advertise the matching port.
    pub fn with_local_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = Some(local_addr);
        self
    }
}

/// Build the auto-filled `Via` header value for a request.
///
/// - **host** comes from the advertised address (`via_advertised` /
///   public / local preference chain), so NAT advertisement is unchanged.
/// - **port** comes from `flow_local` — the local address of the listener
///   that owns the connection the request is sent through — when known,
///   falling back to the advertised port otherwise. On a multi-listener
///   daemon (UDP on one port, TLS on another) the configured address names
///   the default listener, so a flow-routed request would otherwise emit
///   e.g. `SIP/2.0/TLS <ip>:5060` for a request leaving over the TLS
///   listener's connection. Cosmetic (responses ride the connection per
///   RFC 3261 §18.2.2), but keeps `Via` consistent with the `Contact` the
///   UAS side advertises for the same dialog.
fn build_via_value(
    transport: &str,
    advertised: SocketAddr,
    flow_local: Option<SocketAddr>,
    branch: &str,
) -> String {
    let mut addr = advertised;
    if let Some(local) = flow_local {
        addr.set_port(local.port());
    }
    format!("SIP/2.0/{} {};branch={};rport", transport, addr, branch)
}

/// From tag of an outbound request, for seeding the early-dialog
/// placeholder `DialogId` so it agrees with the on-wire From header.
/// The helper generates a fresh tag per dialog-forming request
/// (RFC 3261 §8.1.1.3), so the tag must be read back from the request
/// rather than from any per-client state.
fn request_from_tag(request: &Request) -> SmolStr {
    request
        .headers()
        .get_smol("From")
        .and_then(sip_dialog::extract_tag)
        .unwrap_or_default()
}

/// Applies the configured TLS certificate name to a resolved target
/// whose SNI would otherwise be an IP literal (issue #76). Route sets
/// from carrier edges name IP literals; a fresh TLS dial to one would
/// send the IP as SNI and fail verification against a
/// hostname-only certificate. Targets already carrying a hostname
/// (from the URI or an RFC 3263 reference identity) are left alone,
/// as are non-TLS transports.
fn apply_tls_server_name(target: DnsTarget, tls_server_name: Option<&str>) -> DnsTarget {
    let Some(name) = tls_server_name else {
        return target;
    };
    let tls_transport = matches!(
        target.transport(),
        sip_dns::Transport::Tls | sip_dns::Transport::Wss | sip_dns::Transport::TlsSctp
    );
    if tls_transport && target.sni().parse::<std::net::IpAddr>().is_ok() {
        target.with_tls_name(name)
    } else {
        target
    }
}

fn prepare_in_dialog_request(dialog: &mut Dialog, request: &mut Request) -> SipUri {
    let method = request.method().clone();
    let body = request.body().clone();
    let mut headers = request.headers().clone();

    // Increment local CSeq and overwrite header with the new value
    let cseq = dialog.next_local_cseq();
    headers.remove("CSeq");
    headers
        .push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} {}", cseq, method.as_str())),
        )
        .unwrap();

    // Ensure Route headers reflect the dialog route set
    headers.remove("Route");
    if dialog.route_set().is_empty() {
        let request_uri = dialog.remote_target().clone();
        let new_request =
            Request::new(RequestLine::new(method, request_uri.clone()), headers, body)
                .expect("valid in-dialog request");
        *request = new_request;
        return request_uri;
    }

    let first_route = dialog.route_set().first().cloned().unwrap();
    let loose_route = first_route.params().contains_key(&SmolStr::new("lr"));

    if loose_route {
        let request_uri = dialog.remote_target().clone();
        for route in dialog.route_set().iter() {
            headers
                .push(
                    SmolStr::new("Route"),
                    SmolStr::new(format!("<{}>", route.as_str())),
                )
                .unwrap();
        }
        let new_request =
            Request::new(RequestLine::new(method, request_uri.clone()), headers, body)
                .expect("valid in-dialog request");
        *request = new_request;
        // RFC 3261: For loose routing, return first route as transport target
        first_route
    } else {
        // Strict routing: first route becomes Request-URI, remote target appended to Route
        let request_uri = first_route.clone();
        for route in dialog.route_set().iter().skip(1) {
            headers
                .push(
                    SmolStr::new("Route"),
                    SmolStr::new(format!("<{}>", route.as_str())),
                )
                .unwrap();
        }
        headers
            .push(
                SmolStr::new("Route"),
                SmolStr::new(format!("<{}>", dialog.remote_target().as_str())),
            )
            .unwrap();
        let new_request =
            Request::new(RequestLine::new(method, request_uri.clone()), headers, body)
                .expect("valid in-dialog request");
        *request = new_request;
        request_uri
    }
}

fn apply_route_set_to_request(dialog: &Dialog, request: &mut Request) {
    let method = request.method().clone();
    let body = request.body().clone();
    let mut headers = request.headers().clone();

    headers.remove("Route");
    if dialog.route_set().is_empty() {
        let request_uri = dialog.remote_target().clone();
        let new_request =
            Request::new(RequestLine::new(method, request_uri.clone()), headers, body)
                .expect("valid in-dialog request");
        *request = new_request;
        return;
    }

    let first_route = dialog.route_set().first().cloned().unwrap();
    let loose_route = first_route.params().contains_key(&SmolStr::new("lr"));

    if loose_route {
        let request_uri = dialog.remote_target().clone();
        for route in dialog.route_set().iter() {
            headers
                .push(
                    SmolStr::new("Route"),
                    SmolStr::new(format!("<{}>", route.as_str())),
                )
                .unwrap();
        }
        let new_request = Request::new(RequestLine::new(method, request_uri), headers, body)
            .expect("valid in-dialog request");
        *request = new_request;
    } else {
        let request_uri = first_route.clone();
        for route in dialog.route_set().iter().skip(1) {
            headers
                .push(
                    SmolStr::new("Route"),
                    SmolStr::new(format!("<{}>", route.as_str())),
                )
                .unwrap();
        }
        headers
            .push(
                SmolStr::new("Route"),
                SmolStr::new(format!("<{}>", dialog.remote_target().as_str())),
            )
            .unwrap();
        let new_request = Request::new(RequestLine::new(method, request_uri), headers, body)
            .expect("valid in-dialog request");
        *request = new_request;
    }
}

fn apply_in_dialog_response(
    dialog_manager: &DialogManager,
    dialog: &mut Dialog,
    response: &Response,
) -> Result<()> {
    if (200..300).contains(&response.code()) {
        dialog.update_from_response(response);
        let _ = dialog_manager.insert(dialog.clone());
        return Ok(());
    }

    if matches!(response.code(), 408 | 481) {
        dialog.terminate();
        let _ = dialog_manager.insert(dialog.clone());
        return Err(anyhow!(
            "Received {} for in-dialog {}",
            response.code(),
            response.reason()
        ));
    }

    Ok(())
}

impl From<DnsTarget> for RequestTarget {
    fn from(target: DnsTarget) -> Self {
        RequestTarget::Resolved(target)
    }
}

impl From<&str> for RequestTarget {
    fn from(s: &str) -> Self {
        // Try to parse as SIP URI
        if let Ok(uri) = SipUri::parse(s) {
            RequestTarget::Uri(uri)
        } else {
            // For invalid URIs, we'll fail at resolution time
            RequestTarget::Uri(SipUri::parse("sip:invalid").unwrap())
        }
    }
}

/// What the RFC 4028 session-timer task is doing for a call.
///
/// Published on the [`watch`] channel returned by
/// [`CallHandle::session_timer_state`]. A timer that has stopped is the one
/// state a consumer must not miss: nothing is keeping the session alive after
/// it, and the peer will expire the call at its `Session-Expires` deadline
/// (issue #93).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTimerState {
    /// No timer has been armed on this call.
    Idle,
    /// The most recent refresh was answered 2xx.
    Healthy {
        /// When that refresh completed.
        last_refresh: std::time::Instant,
    },
    /// Refreshes are failing but the task is still retrying.
    Failing {
        /// Failures since the last success.
        consecutive: u32,
    },
    /// The task has exited. Nothing is refreshing the session any more.
    Stopped {
        /// Why it exited.
        reason: SessionTimerStop,
    },
}

/// Why a session-timer task stopped refreshing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTimerStop {
    /// The peer answered `408`/`481`: the dialog no longer exists, and
    /// retrying cannot bring it back (RFC 3261 §12.2.1.2). Terminal on the
    /// first occurrence rather than after `max_session_refresh_failures`.
    DialogGone,
    /// `max_session_refresh_failures` consecutive refreshes failed.
    Exhausted {
        /// How many in a row.
        consecutive: u32,
    },
    /// [`CallHandle::stop_session_timer`] was called, or the call ended.
    Cancelled,
}

/// Handle for an outgoing call with dialog state and response channels.
pub struct CallHandle {
    /// The dialog for this call (updated to winning dialog when final response arrives)
    pub dialog: Arc<RwLock<Dialog>>,

    /// Transaction key for this call
    transaction_key: TransactionKey,

    /// Channel to receive provisional responses (180, 183, etc)
    provisional_rx: Arc<Mutex<mpsc::Receiver<Response>>>,

    /// Channel to receive the final response (200, 486, etc)
    final_rx: Arc<Mutex<Option<oneshot::Receiver<Response>>>>,

    /// Termination reason if transaction failed
    termination_rx: Arc<Mutex<Option<oneshot::Receiver<String>>>>,

    /// The live attempt's INVITE request (needed for CANCEL generation).
    /// Shared with the transaction user and replaced when an auth retry
    /// re-sends the INVITE, so CANCEL targets the current attempt.
    invite_request: Arc<RwLock<Arc<Request>>>,

    /// Transport context (needed for sending CANCEL)
    transport_ctx: Arc<TransportContext>,

    /// Dispatcher for sending CANCEL
    #[allow(dead_code)]
    dispatcher: Arc<dyn TransportDispatcher>,

    /// Transaction manager for creating CANCEL transaction
    transaction_manager: Arc<TransactionManager>,

    /// Early dialogs from forked responses (keyed by To-tag)
    /// RFC 3261 §13.2.2.1: Multiple provisional responses create early dialogs
    early_dialogs: Arc<Mutex<std::collections::HashMap<SmolStr, Dialog>>>,

    /// Keepalive task cancellation
    keepalive_cancel: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Session timer refresh task cancellation
    session_timer_cancel: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    /// Live state of the session timer refresh task (issue #93). Held as a
    /// sender so the task can publish without the handle being borrowed;
    /// consumers subscribe through [`Self::session_timer_state`].
    session_timer_state: Arc<watch::Sender<SessionTimerState>>,
}

impl CallHandle {
    /// Get the INVITE request for the live attempt (replaced when an
    /// auth retry re-sends the INVITE with credentials).
    pub async fn invite_request(&self) -> Arc<Request> {
        self.invite_request.read().await.clone()
    }

    /// Stop keepalives on drop if still running.
    fn stop_keepalives_sync(&self) {
        if let Ok(mut guard) = self.keepalive_cancel.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }

    /// Explicitly stop keepalives (if running).
    pub async fn stop_keepalives(&self) {
        if let Some(handle) = self.keepalive_cancel.lock().await.take() {
            handle.abort();
        }
    }

    /// Explicitly stop session timer refreshes (if running).
    pub async fn stop_session_timer(&self) {
        if let Some(handle) = self.session_timer_cancel.lock().await.take() {
            handle.abort();
            let _ = self.session_timer_state.send(SessionTimerState::Stopped {
                reason: SessionTimerStop::Cancelled,
            });
        }
    }

    /// Watch what the session-timer task is doing (issue #93).
    ///
    /// The timer's whole purpose is the promise that something is keeping the
    /// session alive. When that stops being true — the peer is gone, or
    /// refreshes have failed `max_session_refresh_failures` times in a row —
    /// the owner has to learn about it, or it will treat a dead session as
    /// healthy until the peer expires the call at its deadline.
    ///
    /// Deliberately a signal, not an action: RFC 4028 §10 suggests the
    /// refresher BYE a session it can no longer refresh, but tearing down a
    /// call is the application's decision, and it may well prefer to keep the
    /// media flowing and alert an operator. React to
    /// [`SessionTimerState::Stopped`] however suits the deployment.
    ///
    /// ```ignore
    /// let mut state = call.session_timer_state();
    /// while state.changed().await.is_ok() {
    ///     if let SessionTimerState::Stopped { reason } = *state.borrow() {
    ///         warn!(?reason, "session is no longer being refreshed");
    ///         break;
    ///     }
    /// }
    /// ```
    pub fn session_timer_state(&self) -> watch::Receiver<SessionTimerState> {
        self.session_timer_state.subscribe()
    }

    /// Starts periodic keepalives (CRLF or OPTIONS) based on policy.
    pub async fn start_keepalives(
        &self,
        policy: &KeepalivePolicy,
        target: RequestTarget,
        uac: Arc<IntegratedUAC>,
    ) {
        // Avoid multiple tasks
        if self.keepalive_cancel.lock().await.is_some() {
            return;
        }

        let interval = policy.interval_secs;
        let enable_options = policy.enable_options;
        let enable_udp = policy.enable_udp;
        let enable_stream = policy.enable_stream;
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;

                // Resolve target each time to respect DNS changes if needed
                let resolved = match uac.resolve_target(&target).await {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("Keepalive: DNS resolution failed: {}", e);
                        continue;
                    }
                };

                let ctx = match uac.create_transport_context(&resolved).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Keepalive: failed to create transport context: {}", e);
                        continue;
                    }
                };

                // Decide keepalive payload based on transport
                let is_udp = matches!(ctx.transport(), sip_transaction::TransportKind::Udp);
                let is_stream = matches!(
                    ctx.transport(),
                    sip_transaction::TransportKind::Tcp | sip_transaction::TransportKind::Tls
                );

                if (is_udp && !enable_udp) || (is_stream && !enable_stream) {
                    continue;
                }

                if enable_options {
                    if let Some(uri) = target.clone().to_uri() {
                        let helper = uac.helper.lock().await;
                        let mut opts = helper.create_options(&uri);
                        drop(helper);
                        let _ = uac
                            .auto_fill_headers(&mut opts, Some(resolved.transport()))
                            .await;
                        let _ = uac.send_non_invite_request(opts, resolved.clone()).await;
                    }
                } else {
                    // CRLF keepalive
                    let _ = uac
                        .transport_dispatcher
                        .dispatch(&ctx, Bytes::from_static(b"\r\n\r\n"))
                        .await;
                }
            }
        });

        *self.keepalive_cancel.lock().await = Some(handle);
    }

    /// Starts session timer refreshes (RFC 4028) at half the Session-Expires
    /// interval, refreshing **this handle's dialog**.
    ///
    /// Each refresh consumes a local CSeq, and that advance is committed back
    /// to [`Self::dialog`] so the owner's next in-dialog request — the
    /// teardown BYE, a hold/resume re-INVITE, a REFER — continues the sequence
    /// instead of reusing a CSeq the peer has already seen. A record-routing
    /// proxy treats a duplicate CSeq as a retransmission and answers `408`, so
    /// a timer that kept the advance to itself broke teardown on exactly the
    /// deployments session timers exist for (issue #95).
    ///
    /// The dialog is re-read at every tick rather than snapshotted when the
    /// timer is armed, so refreshes also pick up CSeq advances made by the
    /// owner in between.
    ///
    /// An owner that resolves the dialog and sends its own request while a
    /// refresh is in flight no longer collides with it (issue #99): the
    /// refresh *reserves* the CSeq it will consume before the request leaves,
    /// so the owner reads the reserved number and continues from it. This was
    /// once documented here as unclosable, on the reasoning that the
    /// alternative was serialising the two behind the dialog's write lock
    /// across a network round trip — up to Timer B/F, ~32 s — which would
    /// stall the very BYE this is meant to keep working. That is still true of
    /// serialising; reserving holds the lock for two clones and an increment.
    ///
    /// The task gives up after `max_session_refresh_failures` consecutive
    /// failures, or immediately on a `408`/`481`, and publishes why on
    /// [`Self::session_timer_state`] (issue #93). It does **not** BYE the call:
    /// that decision belongs to the owner.
    pub async fn start_session_timer(
        &self,
        session_expires: u32,
        refresher: &'static str,
        use_update: bool,
        uac: Arc<IntegratedUAC>,
    ) {
        // Avoid multiple tasks
        if self.session_timer_cancel.lock().await.is_some() {
            return;
        }

        // Safety: refresher must be "uac" or "uas"
        let refresher = if refresher.eq_ignore_ascii_case("uas") {
            "uas"
        } else {
            "uac"
        };

        let dialog = self.dialog.clone();
        let state = self.session_timer_state.clone();
        let handle = tokio::spawn(run_session_timer(
            uac,
            dialog,
            state,
            session_expires,
            refresher,
            use_update,
        ));

        *self.session_timer_cancel.lock().await = Some(handle);
    }

    /// Waits for the next provisional response (180, 183, etc).
    ///
    /// Returns None if the final response arrived first.
    ///
    /// # Forking Support
    /// If multiple provisional responses arrive from different endpoints (forking),
    /// each response will be delivered through this channel. Early dialogs are
    /// automatically tracked internally.
    /// Waits for the next provisional response (1xx).
    ///
    /// Returns None when no more provisionals will arrive (final response received).
    pub async fn await_provisional(&self) -> Option<Response> {
        self.provisional_rx.lock().await.recv().await
    }

    /// Returns all early dialogs created from forked provisional responses.
    ///
    /// # RFC 3261 §13.2.2.1 - Early Dialogs
    /// When a UAC receives a provisional response with a To-tag that differs
    /// from previous responses, it creates a new early dialog. This happens
    /// when proxies fork the INVITE to multiple destinations.
    ///
    /// # Example
    /// ```ignore
    /// let mut call = uac.invite("sip:bob@example.com", Some(sdp)).await?;
    ///
    /// // Wait for provisional responses
    /// while let Some(response) = call.await_provisional().await {
    ///     println!("Received {} from one endpoint", response.code());
    /// }
    ///
    /// // Check how many endpoints responded
    /// let early_dialogs = call.get_early_dialogs().await;
    /// println!("INVITE forked to {} endpoints", early_dialogs.len());
    /// ```
    pub async fn get_early_dialogs(&self) -> Vec<Dialog> {
        self.early_dialogs.lock().await.values().cloned().collect()
    }

    /// Waits for the final response (200, 486, etc).
    ///
    /// This will consume the internal receiver and return the final response.
    ///
    /// # Forking Behavior
    /// - If multiple 2xx responses arrive (rare), only the first is returned
    /// - The winning dialog is updated in the handle
    /// - Non-winning early dialogs are automatically discarded
    ///
    /// # Concurrency
    /// - This method takes `&self` to allow concurrent access with `cancel()`
    /// - Internal synchronization via Mutex ensures thread-safe receiver access
    pub async fn await_final(&self) -> Result<Response> {
        // Stop keepalives if running
        if let Some(handle) = self.keepalive_cancel.lock().await.take() {
            handle.abort();
        }

        let mut final_rx = self.final_rx.lock().await;
        if let Some(rx) = final_rx.take() {
            rx.await
                .map_err(|e| anyhow!("Final response channel closed: {}", e))
        } else {
            // Check if terminated
            let mut term_rx = self.termination_rx.lock().await;
            if let Some(rx) = term_rx.take() {
                let reason = rx
                    .await
                    .map_err(|_| anyhow!("Termination channel closed"))?;
                Err(anyhow!("Transaction terminated: {}", reason))
            } else {
                Err(anyhow!("No final response available"))
            }
        }
    }
}

impl Drop for CallHandle {
    fn drop(&mut self) {
        self.stop_keepalives_sync();
        if let Ok(mut guard) = self.session_timer_cancel.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

/// Trait for handling call events (hybrid callback model - trait-based).
#[async_trait]
pub trait CallEventHandler: Send + Sync + 'static {
    /// Called when a provisional response (1xx) is received.
    async fn on_provisional(&self, call: &CallHandle, response: &Response);

    /// Called when a final response (2xx-6xx) is received.
    async fn on_final(&self, call: &CallHandle, response: &Response);

    /// Called when the transaction terminates (timeout, error, etc).
    async fn on_terminated(&self, call: &CallHandle, reason: &str);
}

/// Integrated UAC with full transaction, transport, and DNS integration.
///
/// This is the production-ready UAC API that handles all the complexity of:
/// - Transaction management (retransmissions, timers, state machines)
/// - Transport selection (RFC 3263 DNS resolution)
/// - Authentication (automatic retry on 401/407)
/// - Dialog and subscription management
/// - Via/Contact header auto-filling from transport context
pub struct IntegratedUAC {
    /// Embedded low-level helper for request generation
    helper: Arc<Mutex<UserAgentClient>>,

    /// Transaction manager for reliable request/response handling
    transaction_manager: Arc<TransactionManager>,

    /// DNS resolver for RFC 3263 transport selection
    resolver: Arc<SipResolver>,

    /// Transport dispatcher for sending messages
    transport_dispatcher: Arc<dyn TransportDispatcher>,

    /// Local address for Via/Contact headers
    local_addr: SocketAddr,

    /// Optional public address for NAT scenarios (overrides local_addr in Contact)
    public_addr: Option<SocketAddr>,

    /// Configuration
    config: UACConfig,

    /// Dialog manager (shared with helper)
    dialog_manager: Arc<DialogManager>,

    /// Subscription manager (shared with helper)
    #[allow(dead_code)]
    subscription_manager: Arc<SubscriptionManager>,
}

impl IntegratedUAC {
    /// Creates a builder for IntegratedUAC.
    pub fn builder() -> IntegratedUACBuilder {
        IntegratedUACBuilder::new()
    }

    /// Get a reference to the dialog manager.
    pub fn dialog_manager(&self) -> Option<&Arc<DialogManager>> {
        Some(&self.dialog_manager)
    }

    /// Sends a REGISTER request.
    ///
    /// # Arguments
    /// * `registrar` - URI or pre-resolved target for the registrar
    /// * `expires` - Registration expiration in seconds (0 to deregister)
    ///
    /// # Returns
    /// The final response (200 OK or error)
    ///
    /// # Automatic Behavior
    /// - Fills Via header with local transport address
    /// - Fills Contact header with public address (if configured) or local address
    /// - Resolves DNS per RFC 3263 if URI provided
    /// - Retries on 401/407 with credentials (if configured)
    /// - Processes Service-Route headers from 200 OK
    pub async fn register(
        &self,
        registrar: impl Into<RequestTarget>,
        expires: Option<u32>,
    ) -> Result<Response> {
        let target = registrar.into();
        let expires = expires.unwrap_or(self.config.default_register_expires);

        // Generate request using helper
        let helper = self.helper.lock().await;
        let registrar_uri = self.extract_uri(&target)?;
        let mut request = helper.create_register(&registrar_uri, expires);
        drop(helper);

        // Resolve target and fill transport-aware headers
        let dns_target = self.resolve_target(&target).await?;
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Resolve target and send
        self.send_non_invite_request(request, dns_target).await
    }

    /// Helper to extract SipUri from RequestTarget
    fn extract_uri(&self, target: &RequestTarget) -> Result<SipUri> {
        match target {
            RequestTarget::Uri(uri) => Ok(uri.clone()),
            RequestTarget::Resolved(dns) => {
                // Reconstruct URI from DNS target
                let scheme = match dns.transport() {
                    sip_dns::Transport::Tls => "sips",
                    _ => "sip",
                };
                SipUri::parse(&format!("{}:{}:{}", scheme, dns.host(), dns.port()))
                    .map_err(|_| anyhow!("Failed to reconstruct URI from DNS target"))
            }
        }
    }

    /// Auto-fills Via and Contact headers from local/public/advertised transport context.
    async fn auto_fill_headers(
        &self,
        request: &mut Request,
        transport: Option<sip_dns::Transport>,
    ) {
        self.auto_fill_headers_for_flow(request, transport, None)
            .await
    }

    /// Like [`Self::auto_fill_headers`], but for requests sent through an
    /// existing connection: `flow_local` is the local address of the
    /// listener that owns the connection, and the auto-filled `Via`
    /// advertises its port (see [`Flow::with_local_addr`]).
    async fn auto_fill_headers_for_flow(
        &self,
        request: &mut Request,
        transport: Option<sip_dns::Transport>,
        flow_local: Option<SocketAddr>,
    ) {
        let resolved_public = self.resolve_public_addr().await;
        if self.config.auto_via_filling {
            self.fill_via_header(request, transport, resolved_public, flow_local)
                .await;
        }

        if self.config.auto_contact_filling {
            self.fill_contact_header(request, resolved_public).await;
        }
    }

    async fn resolve_public_addr(&self) -> Option<SocketAddr> {
        if let Some(resolver) = &self.config.public_addr_resolver {
            resolver.resolve().await
        } else {
            None
        }
    }

    /// Fills Via header with advertised transport address.
    async fn fill_via_header(
        &self,
        request: &mut Request,
        transport: Option<sip_dns::Transport>,
        resolved_public: Option<SocketAddr>,
        flow_local: Option<SocketAddr>,
    ) {
        // Preference: resolver → via_advertised → public_addr → local_addr
        let via_addr = self
            .config
            .via_advertised
            .or(resolved_public)
            .or(self.public_addr)
            .unwrap_or(self.local_addr);

        if let Some(via_value) = request.headers().get("Via") {
            // Extract branch parameter from placeholder
            let branch = if let Some(b) = via_value.split("branch=").nth(1) {
                let candidate = b.split(';').next().unwrap_or("").trim();
                if candidate.is_empty() {
                    crate::generate_branch()
                } else {
                    candidate.to_string()
                }
            } else {
                crate::generate_branch()
            };

            // Replace with actual Via using selected transport
            let via_transport = transport.map(|t| t.as_via_str()).unwrap_or("UDP");
            let new_via = build_via_value(via_transport, via_addr, flow_local, &branch);
            let _ = request.headers_mut().set_or_push("Via", new_via);
        }
    }

    /// Fills Contact header with public or local address.
    async fn fill_contact_header(
        &self,
        request: &mut Request,
        resolved_public: Option<SocketAddr>,
    ) {
        // Preference: resolver → contact_advertised → public_addr → local_addr
        let contact_addr = self
            .config
            .contact_advertised
            .or(resolved_public)
            .or(self.public_addr)
            .unwrap_or(self.local_addr);

        let outbound_register =
            self.config.enable_outbound && request.method() == &Method::Register;
        let mut needs_supported = false;

        if let Some(contact_str) = request.headers().get("Contact") {
            // Extract URI from Contact and update host/port
            if let Some(start) = contact_str.find("sip:") {
                let after_sip = &contact_str[start + 4..];
                let user_part = if let Some(at_pos) = after_sip.find('@') {
                    &after_sip[..at_pos]
                } else {
                    ""
                };

                // Reconstruct Contact with actual address
                let new_contact = if user_part.is_empty() {
                    format!("<sip:{}>", contact_addr)
                } else {
                    format!("<sip:{}@{}>", user_part, contact_addr)
                };

                let mut extra_params = String::new();
                if outbound_register {
                    extra_params.push_str(";ob");
                    extra_params.push_str(&format!(";reg-id={}", self.config.outbound_reg_id));
                    if let Some(instance_id) = &self.config.instance_id {
                        extra_params.push_str(&format!(";+sip.instance=\"{}\"", instance_id));
                    }
                    needs_supported = true;
                }

                // Preserve parameters (like expires)
                let updated_contact = if let Some(param_start) = contact_str.find(">;") {
                    format!(
                        "{}{}{}",
                        new_contact,
                        extra_params,
                        &contact_str[param_start + 1..]
                    )
                } else {
                    format!("{}{}", new_contact, extra_params)
                };
                let _ = request
                    .headers_mut()
                    .set_or_push("Contact", updated_contact);
            }
        }

        if outbound_register && needs_supported {
            if let Some(current) = request.headers().get("Supported") {
                let value = current.to_ascii_lowercase();
                if !value.contains("outbound") {
                    let updated = format!("{}, outbound", current);
                    let _ = request.headers_mut().set_or_push("Supported", updated);
                }
            } else {
                request
                    .headers_mut()
                    .push(SmolStr::new("Supported"), SmolStr::new("outbound"))
                    .unwrap();
            }
        }
    }

    /// Applies dialog updates based on the response (target refresh, session timers).
    fn handle_in_dialog_response(&self, dialog: &mut Dialog, response: &Response) -> Result<()> {
        apply_in_dialog_response(&self.dialog_manager, dialog, response)
    }

    /// Resolves a RequestTarget to a DnsTarget.
    async fn resolve_target(&self, target: &RequestTarget) -> Result<DnsTarget> {
        let resolved = match target {
            RequestTarget::Resolved(dns) => dns.clone(),
            RequestTarget::Uri(uri) if !self.config.auto_dns_resolution => {
                // No auto resolution - create simple target
                let port = uri.port().unwrap_or(5060);
                sip_dns::DnsTarget::unchecked_new(uri.host(), port, sip_dns::Transport::Udp)
            }
            RequestTarget::Uri(uri) => {
                // Auto-resolve via DNS
                debug!("Resolving {} via DNS (RFC 3263)", uri.as_str());

                let targets = self
                    .resolver
                    .resolve(uri)
                    .await
                    .map_err(|e| anyhow!("DNS resolution failed: {}", e))?;

                targets
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("No DNS targets found for {}", uri.as_str()))?
            }
        };
        Ok(apply_tls_server_name(
            resolved,
            self.config.tls_server_name.as_deref(),
        ))
    }

    /// Sends a non-INVITE request and waits for the final response.
    async fn send_non_invite_request(
        &self,
        request: Request,
        dns_target: DnsTarget,
    ) -> Result<Response> {
        // Create transport context from DNS target
        let ctx = self.create_transport_context(&dns_target).await?;

        // Create channels for response
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        // Create transaction user
        let tu = Arc::new(SimpleTransactionUser {
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
        });

        // Start client transaction
        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx, tu)
            .await?;

        info!(
            "Started client transaction {} for {:?}",
            key.branch(),
            request.method()
        );

        // Wait for final response or termination
        tokio::select! {
            Ok(response) = final_rx => {
                // Check if we need to retry with auth
                if (response.code() == 401 || response.code() == 407)
                    && self.config.auto_retry_auth
                {
                    warn!("Received {} challenge, retrying with authentication", response.code());
                    return self.retry_with_auth(request, response, dns_target, 1).await;
                }

                Ok(response)
            }
            Ok(reason) = term_rx => {
                Err(anyhow!("Transaction terminated: {}", reason))
            }
            else => {
                Err(anyhow!("Response channels closed"))
            }
        }
    }

    /// Retries a request with authentication after receiving 401/407.
    ///
    /// `attempt` is 1-based: 1 is the first retry (second overall send).
    /// If the retried request is itself challenged, we re-arm with the
    /// new nonce and go again up to `config.max_auth_retries`, then
    /// surface whichever challenge we received last. This honours the
    /// documented `max_auth_retries` field, which previously had no
    /// effect on the send path.
    async fn retry_with_auth(
        &self,
        original_request: Request,
        challenge: Response,
        dns_target: DnsTarget,
        attempt: u32,
    ) -> Result<Response> {
        // Extract realm for provider
        let realm = extract_realm(&challenge);

        // Create authenticated request using helper and optional provider
        let mut helper = self.helper.lock().await;
        let auth_request = helper.create_authenticated_request_with(
            &original_request,
            &challenge,
            async {
                if let Some(provider) = &self.config.credential_provider {
                    if let Some(r) = realm.as_deref() {
                        return provider.credentials(r).await;
                    }
                }
                None
            }
            .await,
        )?;
        drop(helper);

        // Auto-fill headers again (CSeq was incremented)
        let mut auth_request = auth_request;
        self.auto_fill_headers(&mut auth_request, Some(dns_target.transport()))
            .await;

        // Send authenticated request.
        let ctx = self.create_transport_context(&dns_target).await?;
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        let tu = Arc::new(SimpleTransactionUser {
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
        });

        let key = self
            .transaction_manager
            .start_client_transaction(auth_request.clone(), ctx, tu)
            .await?;

        info!(
            "Started authenticated client transaction {} (attempt {}) for {:?}",
            key.branch(),
            attempt,
            auth_request.method()
        );

        let response = tokio::select! {
            Ok(response) = final_rx => response,
            Ok(reason) = term_rx => return Err(anyhow!("Authenticated transaction terminated: {}", reason)),
            else => return Err(anyhow!("Authenticated response channels closed")),
        };

        // If we're still being challenged, retry up to the configured
        // cap. Bounded recursion: each level increments `attempt` and
        // bails once `attempt >= max_auth_retries`. Returning the last
        // challenge (rather than erroring) lets callers react to a
        // persistent rejection the same way they would to any other
        // final response.
        if (response.code() == 401 || response.code() == 407)
            && attempt < self.config.max_auth_retries
        {
            warn!(
                code = response.code(),
                attempt,
                max = self.config.max_auth_retries,
                "auth still rejected; retrying with refreshed credentials"
            );
            return Box::pin(self.retry_with_auth(auth_request, response, dns_target, attempt + 1))
                .await;
        }

        if response.code() == 401 || response.code() == 407 {
            warn!(
                code = response.code(),
                attempts = attempt,
                max = self.config.max_auth_retries,
                "auth retry limit reached; returning last challenge to caller"
            );
        }

        Ok(response)
    }

    /// Resolves a DnsTarget's host to a SocketAddr, falling back to OS
    /// DNS resolution for SRV hostnames.
    async fn resolve_peer_addr(dns_target: &DnsTarget) -> Result<SocketAddr> {
        let addr_str = format!("{}:{}", dns_target.host(), dns_target.port());
        match addr_str.parse() {
            Ok(addr) => Ok(addr),
            Err(_) => {
                // SRV targets are hostnames; resolve to first A/AAAA
                let mut addrs = tokio::net::lookup_host(&addr_str)
                    .await
                    .map_err(|e| anyhow!("DNS lookup failed for {}: {}", addr_str, e))?;
                addrs
                    .next()
                    .ok_or_else(|| anyhow!("No A/AAAA results for {}", addr_str))
            }
        }
    }

    /// Builds the pool-dialing fallback target for a `*_via_flow` send:
    /// the same transport and SNI the flow context uses, but no stream,
    /// so the dispatcher dials the resolved route-set edge through the
    /// connection pool. The peer idle-closing the inbound connection
    /// (carriers do, ~2 minutes observed) makes the flow send fail fast;
    /// this second target lets the transaction's RFC 3263 §4.3 failover
    /// recover instead of blackholing the request (issue #73). `None`
    /// when the edge can't be resolved — the flow is then the only try.
    async fn flow_fallback_context(
        &self,
        transport: sip_transaction::TransportKind,
        dns_target: &DnsTarget,
    ) -> Option<TransportContext> {
        match Self::resolve_peer_addr(dns_target).await {
            Ok(peer) => Some(
                TransportContext::new(transport, peer, None)
                    .with_server_name(Some(dns_target.sni().to_string())),
            ),
            Err(e) => {
                warn!(
                    "No pool fallback for flow send, could not resolve {}: {}",
                    dns_target.host(),
                    e
                );
                None
            }
        }
    }

    /// Creates a TransportContext from a DnsTarget.
    async fn create_transport_context(&self, dns_target: &DnsTarget) -> Result<TransportContext> {
        use sip_transaction::TransportKind;

        let transport = match dns_target.transport() {
            sip_dns::Transport::Udp => TransportKind::Udp,
            sip_dns::Transport::Tcp => TransportKind::Tcp,
            sip_dns::Transport::Tls => TransportKind::Tls,
            sip_dns::Transport::Ws => TransportKind::Ws,
            sip_dns::Transport::Wss => TransportKind::Wss,
            sip_dns::Transport::Sctp => TransportKind::Sctp,
            sip_dns::Transport::TlsSctp => TransportKind::TlsSctp,
        };

        let peer = Self::resolve_peer_addr(dns_target).await?;

        // Use the DNS target's TLS reference identity for SNI when
        // TLS/WSS is selected. `sni()` returns the original hostname when
        // `host` has been replaced by a resolved IP (RFC 5922 §4), and
        // falls back to `host` for IP-literal / SRV-name targets.
        let server_name = if matches!(transport, TransportKind::Tls | TransportKind::Wss) {
            Some(dns_target.sni().to_string())
        } else {
            None
        };

        let ws_uri = if matches!(transport, TransportKind::Ws | TransportKind::Wss) {
            if let Some(uri) = self.config.ws_target_uri.clone() {
                Some(uri)
            } else {
                let scheme = if matches!(transport, TransportKind::Wss) {
                    "wss"
                } else {
                    "ws"
                };
                let path = self
                    .config
                    .ws_path
                    .clone()
                    .unwrap_or_else(|| "/".to_string());
                let normalized_path = if path.starts_with('/') {
                    path
                } else {
                    format!("/{}", path)
                };
                Some(format!(
                    "{}://{}:{}{}",
                    scheme,
                    dns_target.host(),
                    dns_target.port(),
                    normalized_path
                ))
            }
        } else {
            None
        };

        let ctx = TransportContext::new(transport, peer, None)
            .with_server_name(server_name)
            .with_ws_uri(ws_uri);

        Ok(ctx)
    }

    /// Sends an INVITE request to establish a call.
    ///
    /// # Arguments
    /// * `target` - URI or pre-resolved target for the callee
    /// * `sdp_body` - Optional SDP offer body (early offer). Pass None for late offer.
    ///
    /// # Returns
    /// A CallHandle that can be used to await provisional and final responses
    ///
    /// # Automatic Behavior
    /// - Fills Via header with local transport address
    /// - Fills Contact header with public address (if configured) or local address
    /// - Resolves DNS per RFC 3263 if URI provided
    /// - Retries on 401/407 with credentials (if configured)
    /// - Creates dialog from 1xx/2xx responses automatically
    /// - Handles ACK for 2xx responses
    /// - Handles PRACK for reliable provisionals (if RSeq present)
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use sip_uac::integrated::IntegratedUAC;
    /// # async fn example(uac: &IntegratedUAC) -> anyhow::Result<()> {
    /// // Early offer (SDP in INVITE)
    /// let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.100\r\n...";
    /// let mut call = uac.invite("sip:bob@example.com", Some(sdp)).await?;
    ///
    /// // Wait for provisional responses
    /// while let Some(response) = call.await_provisional().await {
    ///     println!("Call progress: {}", response.code());
    /// }
    ///
    /// // Wait for final response
    /// let final_response = call.await_final().await?;
    /// if final_response.code() == 200 {
    ///     println!("Call connected!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    /// Sets the display name for the From header in subsequent requests.
    ///
    /// This is useful for B2BUA scenarios where you want to preserve the original caller's
    /// display name when forwarding calls.
    ///
    /// # Arguments
    /// * `name` - Optional display name to set, or None to clear it
    ///
    /// # Example
    /// ```no_run
    /// # use sip_uac::integrated::IntegratedUAC;
    /// # async fn example(uac: &IntegratedUAC) {
    /// // Set display name before making a call
    /// uac.set_display_name(Some("Bob Smith".to_string())).await;
    /// let call = uac.invite("sip:alice@example.com", None).await.unwrap();
    /// # }
    /// ```
    pub async fn set_display_name(&self, name: Option<String>) {
        let mut helper = self.helper.lock().await;
        helper.display_name = name;
    }

    /// Sets the From URI override for subsequent requests (useful for B2BUA identity preservation).
    ///
    /// # Security
    /// Only use in trusted contexts (e.g., after authenticating the A-leg). Clearing the override
    /// after use is recommended to avoid leaking identity into unrelated requests.
    pub async fn set_from_uri(&self, uri: Option<SipUri>) {
        let mut helper = self.helper.lock().await;
        helper.from_uri_override = uri;
    }

    pub async fn invite(
        &self,
        target: impl Into<RequestTarget>,
        sdp_body: Option<&str>,
    ) -> Result<CallHandle> {
        self.invite_with_from(target, sdp_body, None).await
    }

    /// Like [`Self::invite`], but stamps the INVITE's From header from
    /// `from_override` (the caller identity for this call) instead of the
    /// client's local identity. The override is threaded per-call, so it
    /// is safe under concurrent INVITEs on one client — unlike
    /// [`Self::set_from_uri`], which mutates shared state. `None` behaves
    /// exactly like [`Self::invite`]. Used by outbound origination to send
    /// a trunk-supplied caller-ID (e.g. an owned/verified PSTN number)
    /// that the provider will accept.
    pub async fn invite_with_from(
        &self,
        target: impl Into<RequestTarget>,
        sdp_body: Option<&str>,
        from_override: Option<SipUri>,
    ) -> Result<CallHandle> {
        let target = target.into();

        // Generate request using helper
        let helper = self.helper.lock().await;
        let target_uri = self.extract_uri(&target)?;
        let mut request =
            helper.create_invite_with_from(&target_uri, sdp_body, from_override.as_ref());
        drop(helper);

        // Resolve target
        let dns_target = self.resolve_target(&target).await?;

        // Auto-fill Via/Contact using resolved transport
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Create channels for responses
        let (prov_tx, prov_rx) = mpsc::channel(16);
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        // Create transport context
        let ctx = self.create_transport_context(&dns_target).await?;

        // Create early dialogs map for forking support
        let early_dialogs = Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Create placeholder dialog (will be updated when 2xx arrives)
        let helper = self.helper.lock().await;
        let dialog_id = sip_dialog::DialogId::unchecked_new(
            request.headers().get_smol("Call-ID").unwrap().clone(),
            request_from_tag(&request),
            SmolStr::new("pending"),
        );
        let placeholder_dialog = Dialog::unchecked_new(
            dialog_id,
            sip_dialog::DialogStateType::Early,
            helper.local_uri.clone(),
            target_uri.clone(),
            target_uri.clone(),
            1,
            0,
            None,
            vec![],
            false,
            None,
            None,
            true,
        );
        drop(helper);

        // Wrap dialog in Arc<RwLock> for sharing between CallHandle and transaction user
        let shared_dialog = Arc::new(RwLock::new(placeholder_dialog));

        // Create INVITE transaction user
        let live_request = Arc::new(RwLock::new(Arc::new(request.clone())));
        let tu = Arc::new(InviteTransactionUser {
            prov_tx,
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: request.clone(),
            config: self.config.clone(),
            ctx: ctx.clone(),
            auto_retry_auth: self.config.auto_retry_auth,
            auth_attempt: 0,
            live_request: live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            dialog: shared_dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        // Start client transaction
        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx.clone(), tu)
            .await?;

        info!(
            "Started INVITE client transaction {} to {}",
            key.branch(),
            target_uri.as_str()
        );

        Ok(CallHandle {
            dialog: shared_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: live_request,
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
            session_timer_state: Arc::new(watch::Sender::new(SessionTimerState::Idle)),
        })
    }

    /// Send an INVITE with additional SIP headers.
    pub async fn invite_with_headers(
        &self,
        target: impl Into<RequestTarget>,
        sdp_body: Option<&str>,
        extra_headers: Headers,
    ) -> Result<CallHandle> {
        let target = target.into();

        let helper = self.helper.lock().await;
        let target_uri = self.extract_uri(&target)?;
        let mut request = helper.create_invite(&target_uri, sdp_body);
        drop(helper);

        for header in extra_headers.iter() {
            request
                .headers_mut()
                .push(header.name_smol().clone(), header.value_smol().clone())
                .map_err(|e| anyhow!("failed to append extra INVITE header: {}", e))?;
        }

        let dns_target = self.resolve_target(&target).await?;
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        let (prov_tx, prov_rx) = mpsc::channel(16);
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        let ctx = self.create_transport_context(&dns_target).await?;
        let early_dialogs = Arc::new(Mutex::new(std::collections::HashMap::new()));

        let helper = self.helper.lock().await;
        let dialog_id = sip_dialog::DialogId::unchecked_new(
            request.headers().get_smol("Call-ID").unwrap().clone(),
            request_from_tag(&request),
            SmolStr::new("pending"),
        );
        let placeholder_dialog = Dialog::unchecked_new(
            dialog_id,
            sip_dialog::DialogStateType::Early,
            helper.local_uri.clone(),
            target_uri.clone(),
            target_uri.clone(),
            1,
            0,
            None,
            vec![],
            false,
            None,
            None,
            true,
        );
        drop(helper);

        let shared_dialog = Arc::new(RwLock::new(placeholder_dialog));

        let live_request = Arc::new(RwLock::new(Arc::new(request.clone())));
        let tu = Arc::new(InviteTransactionUser {
            prov_tx,
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: request.clone(),
            config: self.config.clone(),
            ctx: ctx.clone(),
            auto_retry_auth: self.config.auto_retry_auth,
            auth_attempt: 0,
            live_request: live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            dialog: shared_dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx.clone(), tu)
            .await?;

        info!(
            "Started INVITE client transaction {} to {} with extra headers",
            key.branch(),
            target_uri.as_str()
        );

        Ok(CallHandle {
            dialog: shared_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: live_request,
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
            session_timer_state: Arc::new(watch::Sender::new(SessionTimerState::Idle)),
        })
    }

    /// Send an INVITE using an existing connection (RFC 5626 flow support).
    ///
    /// This method allows sending INVITEs to TLS/TCP clients that registered
    /// through an inbound connection (NAT traversal scenario). Instead of
    /// opening a new connection to the client's ephemeral port, the INVITE
    /// is sent through the existing connection identified by the flow stream.
    ///
    /// # Arguments
    /// * `target` - URI or resolved target of the callee
    /// * `sdp_body` - Optional SDP offer (None for late offer)
    /// * `flow` - The existing connection to send through
    pub async fn invite_via_flow(
        &self,
        target: impl Into<RequestTarget>,
        sdp_body: Option<&str>,
        flow: Flow,
    ) -> Result<CallHandle> {
        let target = target.into();

        // Generate request using helper
        let helper = self.helper.lock().await;
        let target_uri = self.extract_uri(&target)?;
        let mut request = helper.create_invite(&target_uri, sdp_body);
        drop(helper);

        // Resolve target to get transport type
        let dns_target = self.resolve_target(&target).await?;

        // Auto-fill Via/Contact using resolved transport and the flow's listener port
        self.auto_fill_headers_for_flow(
            &mut request,
            Some(dns_target.transport()),
            flow.local_addr,
        )
        .await;

        // Create channels for responses
        let (prov_tx, prov_rx) = mpsc::channel(16);
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        // Create transport context WITH the flow stream for connection reuse
        use sip_transaction::TransportKind;
        let transport = match dns_target.transport() {
            sip_dns::Transport::Tls => TransportKind::Tls,
            sip_dns::Transport::Tcp => TransportKind::Tcp,
            _ => TransportKind::Tls, // Default to TLS for flow-based routing
        };
        let ctx = TransportContext::new(transport, flow.peer_addr, Some(flow.stream))
            .with_server_name(Some(dns_target.sni().to_string()))
            .with_local_addr(flow.local_addr);

        // Create early dialogs map for forking support
        let early_dialogs = Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Create placeholder dialog (will be updated when 2xx arrives)
        let helper = self.helper.lock().await;
        let dialog_id = sip_dialog::DialogId::unchecked_new(
            request.headers().get_smol("Call-ID").unwrap().clone(),
            request_from_tag(&request),
            SmolStr::new("pending"),
        );
        let placeholder_dialog = Dialog::unchecked_new(
            dialog_id,
            sip_dialog::DialogStateType::Early,
            helper.local_uri.clone(),
            target_uri.clone(),
            target_uri.clone(),
            1,
            0,
            None,
            vec![],
            false,
            None,
            None,
            true,
        );
        drop(helper);

        // Wrap dialog in Arc<RwLock> for sharing between CallHandle and transaction user
        let shared_dialog = Arc::new(RwLock::new(placeholder_dialog));

        // Create INVITE transaction user
        let live_request = Arc::new(RwLock::new(Arc::new(request.clone())));
        let tu = Arc::new(InviteTransactionUser {
            prov_tx,
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: request.clone(),
            config: self.config.clone(),
            ctx: ctx.clone(),
            auto_retry_auth: self.config.auto_retry_auth,
            auth_attempt: 0,
            live_request: live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            dialog: shared_dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        // Start client transaction
        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx.clone(), tu)
            .await?;

        info!(
            "Started INVITE client transaction {} to {} via flow",
            key.branch(),
            target_uri.as_str()
        );

        Ok(CallHandle {
            dialog: shared_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: live_request,
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
            session_timer_state: Arc::new(watch::Sender::new(SessionTimerState::Idle)),
        })
    }

    /// Send an INVITE with custom body and Content-Type.
    ///
    /// Used for SIPREC (multipart/mixed) and other non-SDP extensions.
    ///
    /// # Arguments
    /// * `target` - URI or resolved target of the callee
    /// * `body` - The request body
    /// * `content_type` - The Content-Type header value
    pub async fn invite_with_body(
        &self,
        target: impl Into<RequestTarget>,
        body: &str,
        content_type: &str,
    ) -> Result<CallHandle> {
        let target = target.into();

        // Generate request using helper
        let helper = self.helper.lock().await;
        let target_uri = self.extract_uri(&target)?;
        let mut request = helper.create_invite_with_body(&target_uri, body, content_type)?;
        drop(helper);

        // Resolve target
        let dns_target = self.resolve_target(&target).await?;

        // Auto-fill Via/Contact using resolved transport
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Create channels for responses
        let (prov_tx, prov_rx) = mpsc::channel(16);
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        // Create transport context
        let ctx = self.create_transport_context(&dns_target).await?;

        // Create early dialogs map for forking support
        let early_dialogs = Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Create placeholder dialog (will be updated when 2xx arrives)
        let helper = self.helper.lock().await;
        let dialog_id = sip_dialog::DialogId::unchecked_new(
            request.headers().get_smol("Call-ID").unwrap().clone(),
            request_from_tag(&request),
            SmolStr::new("pending"),
        );
        let placeholder_dialog = Dialog::unchecked_new(
            dialog_id,
            sip_dialog::DialogStateType::Early,
            helper.local_uri.clone(),
            target_uri.clone(),
            target_uri.clone(),
            1,
            0,
            None,
            vec![],
            false,
            None,
            None,
            true,
        );
        drop(helper);

        // Wrap dialog in Arc<RwLock> for sharing between CallHandle and transaction user
        let shared_dialog = Arc::new(RwLock::new(placeholder_dialog));

        // Create INVITE transaction user
        let live_request = Arc::new(RwLock::new(Arc::new(request.clone())));
        let tu = Arc::new(InviteTransactionUser {
            prov_tx,
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: request.clone(),
            config: self.config.clone(),
            ctx: ctx.clone(),
            auto_retry_auth: self.config.auto_retry_auth,
            auth_attempt: 0,
            live_request: live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            dialog: shared_dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        // Start client transaction
        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx.clone(), tu)
            .await?;

        info!(
            "Started INVITE (custom body) client transaction {} to {}",
            key.branch(),
            target_uri.as_str()
        );

        Ok(CallHandle {
            dialog: shared_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: live_request,
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
            session_timer_state: Arc::new(watch::Sender::new(SessionTimerState::Idle)),
        })
    }

    /// Sends a BYE request to terminate a call.
    ///
    /// # Arguments
    /// * `dialog` - The dialog to terminate
    ///
    /// # Returns
    /// The final response (typically 200 OK)
    ///
    /// # Automatic Behavior
    /// - Uses remote target from dialog for Request-URI
    /// - Applies route set from dialog
    /// - Fills Via header with local transport address
    /// - Increments local CSeq
    pub async fn bye(&self, dialog: &Dialog) -> Result<Response> {
        // Generate BYE using helper
        let helper = self.helper.lock().await;
        let mut request = helper.create_bye(dialog);
        drop(helper);

        // Apply the dialog route set (RFC 3261 §12.2.1.1). Without this the
        // BYE carries no Route headers and its Request-URI is the peer's
        // Contact — fine for a peer we talk to directly, but a record-routing
        // proxy (e.g. a carrier edge) can't correlate it and answers 481,
        // leaving the far leg stranded. Every other in-dialog sender routes
        // through this helper; BYE was the exception. Clone because the
        // public signature is `&Dialog` and the CSeq bump on a terminal
        // dialog is inconsequential.
        let mut routed = dialog.clone();
        let target_uri = prepare_in_dialog_request(&mut routed, &mut request);

        // Resolve the wire target (the loose-route proxy when record-routed,
        // else the remote target) to pick the transport for Via auto-fill.
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;

        // Auto-fill Via with resolved transport
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Send and wait for response
        self.send_non_invite_request(request, dns_target).await
    }

    /// Sends a BYE request using an existing connection (RFC 5626 flow support).
    ///
    /// This method allows sending BYE to TLS/TCP clients that registered
    /// through an inbound connection (NAT traversal scenario). Instead of
    /// opening a new connection to the client's ephemeral port, the BYE
    /// is sent through the existing connection identified by the flow.
    ///
    /// # Arguments
    /// * `dialog` - The dialog to terminate
    /// * `flow` - The existing connection to send through
    ///
    /// # Returns
    /// The final response (typically 200 OK)
    pub async fn bye_via_flow(&self, dialog: &Dialog, flow: Flow) -> Result<Response> {
        // Generate BYE using helper
        let helper = self.helper.lock().await;
        let mut request = helper.create_bye(dialog);
        drop(helper);

        // Apply the dialog route set (RFC 3261 §12.2.1.1). The BYE rides the
        // inbound flow either way, but a record-routing carrier edge still
        // needs the Route headers to correlate the request to the dialog —
        // without them it answers 481 and the caller is left in dead air
        // until session-expires. `send_refer_via_flow` already routes through
        // this helper; BYE-via-flow was the gap. See `bye` for the clone.
        let mut routed = dialog.clone();
        let target_uri = prepare_in_dialog_request(&mut routed, &mut request);

        // Determine transport type from the wire target (loose-route proxy
        // when record-routed, else the remote target).
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;

        // Auto-fill Via with resolved transport and the flow's listener port
        self.auto_fill_headers_for_flow(
            &mut request,
            Some(dns_target.transport()),
            flow.local_addr,
        )
        .await;

        info!("Sending BYE via flow for dialog {:?}", dialog.id());
        self.send_non_invite_via_flow(request, &dns_target, &flow)
            .await
    }

    /// Sends a non-INVITE request through an existing connection and waits
    /// for the final response. Shared tail of the `*_via_flow` methods: the
    /// transport context carries the flow's write handle so the transaction
    /// layer reuses the connection instead of dialing the peer.
    async fn send_non_invite_via_flow(
        &self,
        request: Request,
        dns_target: &DnsTarget,
        flow: &Flow,
    ) -> Result<Response> {
        use sip_transaction::TransportKind;
        let transport = match dns_target.transport() {
            sip_dns::Transport::Tls => TransportKind::Tls,
            sip_dns::Transport::Tcp => TransportKind::Tcp,
            _ => TransportKind::Tls, // Default to TLS for flow-based routing
        };
        let ctx = TransportContext::new(transport, flow.peer_addr, Some(flow.stream.clone()))
            .with_server_name(Some(dns_target.sni().to_string()))
            .with_local_addr(flow.local_addr);

        // Second target: dial the route-set edge through the pool if the
        // inbound connection turns out to be dead (issue #73).
        let mut targets = vec![ctx];
        targets.extend(self.flow_fallback_context(transport, dns_target).await);

        let method = request.method().clone();

        // Create channels for response
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        // Create transaction user
        let tu = Arc::new(SimpleTransactionUser {
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
        });

        // Start client transaction
        let key = self
            .transaction_manager
            .start_client_transaction_with_targets(request, targets, tu)
            .await?;

        info!("Started {} via flow transaction {}", method, key.branch());

        // Wait for response
        tokio::select! {
            Ok(response) = final_rx => {
                debug!("{} via flow response: {}", method, response.code());
                Ok(response)
            }
            Ok(reason) = term_rx => Err(anyhow!("{} transaction terminated: {}", method, reason)),
            else => Err(anyhow!("{} response channels closed", method)),
        }
    }

    /// Sends a SUBSCRIBE request to establish an event subscription.
    ///
    /// # Arguments
    /// * `target` - URI or pre-resolved target for the resource
    /// * `event` - Event package (e.g., "refer", "message-summary", "presence")
    /// * `expires` - Subscription duration in seconds (0 to unsubscribe)
    ///
    /// # Returns
    /// The final response and created subscription (if 200 OK)
    pub async fn subscribe(
        &self,
        target: impl Into<RequestTarget>,
        event: &str,
        expires: Option<u32>,
    ) -> Result<(Response, Option<Subscription>)> {
        let target = target.into();
        let expires = expires.unwrap_or(self.config.default_subscribe_expires);

        // Generate request using helper
        let helper = self.helper.lock().await;
        let target_uri = self.extract_uri(&target)?;
        let mut request = helper.create_subscribe(&target_uri, event, expires);
        drop(helper);

        // Resolve target and send
        let dns_target = self.resolve_target(&target).await?;
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;
        let response = self
            .send_non_invite_request(request.clone(), dns_target)
            .await?;

        // If 200 OK, create subscription
        let subscription = if response.code() == 200 {
            let helper = self.helper.lock().await;
            helper.process_subscribe_response(&request, &response)
        } else {
            None
        };

        Ok((response, subscription))
    }

    /// Sends a NOTIFY request (typically in response to SUBSCRIBE).
    ///
    /// # Arguments
    /// * `subscription` - The subscription to notify
    /// * `state` - Subscription state (Active/Pending/Terminated)
    /// * `body` - Notification payload
    ///
    /// # Returns
    /// The final response (typically 200 OK)
    pub async fn notify(
        &self,
        subscription: &Subscription,
        state: sip_dialog::SubscriptionState,
        body: Option<&str>,
    ) -> Result<Response> {
        // Generate NOTIFY using helper
        let helper = self.helper.lock().await;
        let mut request = helper.create_notify(subscription, state, body);
        drop(helper);

        // Use subscription contact for DNS resolution
        let target = RequestTarget::Uri(subscription.contact().clone());
        let dns_target = self.resolve_target(&target).await?;
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Send and wait for response
        self.send_non_invite_request(request, dns_target).await
    }

    /// Sends an unsolicited NOTIFY request (e.g., for MWI per RFC 3842 §5).
    ///
    /// Unlike `notify()` which requires a `Subscription`, this sends an
    /// out-of-dialog NOTIFY suitable for unsolicited event notifications.
    ///
    /// # Arguments
    /// * `target` - URI of the recipient
    /// * `event` - Event package (e.g., "message-summary")
    /// * `content_type` - MIME type for the body
    /// * `body` - Notification payload
    pub async fn send_unsolicited_notify(
        &self,
        target: &SipUri,
        event: &str,
        content_type: &str,
        body: &str,
    ) -> Result<Response> {
        let request_target = RequestTarget::Uri(target.clone());
        let dns_target = self.resolve_target(&request_target).await?;

        let helper = self.helper.lock().await;
        let mut request = helper.create_unsolicited_notify(target, event, content_type, body);
        drop(helper);

        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        self.send_non_invite_request(request, dns_target).await
    }

    /// Sends an unsolicited NOTIFY with a custom Subscription-State value.
    ///
    /// Identical to `send_unsolicited_notify` but allows specifying the
    /// Subscription-State header (e.g., `"active;expires=3600"` or
    /// `"terminated;reason=deactivated"`).
    pub async fn send_unsolicited_notify_with_state(
        &self,
        target: &SipUri,
        event: &str,
        content_type: &str,
        body: &str,
        subscription_state: &str,
    ) -> Result<Response> {
        let request_target = RequestTarget::Uri(target.clone());
        let dns_target = self.resolve_target(&request_target).await?;

        let helper = self.helper.lock().await;
        let mut request = helper.create_unsolicited_notify_with_state(
            target,
            event,
            content_type,
            body,
            subscription_state,
        );
        drop(helper);

        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        self.send_non_invite_request(request, dns_target).await
    }

    /// Sends an OPTIONS ping for connectivity checks.
    pub async fn ping_options(&self, target: impl Into<RequestTarget>) -> Result<Response> {
        let target = target.into();
        let dns_target = self.resolve_target(&target).await?;

        // Build OPTIONS
        let helper = self.helper.lock().await;
        let uri = self.extract_uri(&target)?;
        let mut request = helper.create_options(&uri);
        drop(helper);

        // Auto-fill headers
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Send and wait for response
        self.send_non_invite_request(request, dns_target).await
    }

    /// Pings a target using keepalive policy (OPTIONS when enabled, CRLF otherwise).
    pub async fn ping(&self, target: impl Into<RequestTarget>) -> Result<()> {
        let target = target.into();
        let dns_target = self.resolve_target(&target).await?;
        let ctx = self.create_transport_context(&dns_target).await?;

        if self.config.keepalive_policy.enable_options {
            let helper = self.helper.lock().await;
            let uri = self.extract_uri(&target)?;
            let mut req = helper.create_options(&uri);
            drop(helper);
            self.auto_fill_headers(&mut req, Some(dns_target.transport()))
                .await;
            let _ = self.send_non_invite_request(req, dns_target).await?;
        } else {
            let payload = Bytes::from_static(b"\r\n\r\n");
            self.transport_dispatcher.dispatch(&ctx, payload).await?;
        }
        Ok(())
    }

    /// Sends a re-INVITE to modify an existing session (RFC 3261 §14).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send re-INVITE within
    /// * `sdp_body` - Optional new SDP offer (None for session refresh without media change)
    ///
    /// # Returns
    /// A CallHandle for tracking the re-INVITE transaction
    ///
    /// # Use Cases
    /// - Session refresh (keep session alive)
    /// - Media changes (add/remove video, codec change)
    /// - Hold/resume (a=sendonly/a=sendrecv)
    /// - Transfer preparation
    pub async fn reinvite(
        &self,
        dialog: &mut Dialog,
        sdp_body: Option<&str>,
    ) -> Result<CallHandle> {
        // Generate re-INVITE using helper
        let helper = self.helper.lock().await;
        let mut request = helper.create_reinvite(dialog, sdp_body);
        drop(helper);

        let target_uri = prepare_in_dialog_request(dialog, &mut request);
        let _ = self.dialog_manager.insert(dialog.clone());
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;

        // Auto-fill Via/Contact using resolved transport
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        self.start_dialog_invite_transaction(dialog.clone(), request, dns_target)
            .await
    }

    /// Sends an UPDATE request to modify session parameters (RFC 3311).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send UPDATE within
    /// * `sdp_body` - Optional SDP for session modification
    ///
    /// # Returns
    /// The final response
    ///
    /// # RFC 3311 UPDATE vs re-INVITE
    /// - UPDATE: Lightweight session modification (no dialog refresh)
    /// - UPDATE: Can be sent before final response to initial INVITE
    /// - re-INVITE: Full dialog refresh, requires ACK, more complex
    ///
    /// Common use cases:
    /// - Early media changes (before call is answered)
    /// - QoS precondition updates
    /// - Session timer refresh without full re-INVITE
    pub async fn send_update(
        &self,
        dialog: &mut Dialog,
        sdp_body: Option<&str>,
    ) -> Result<Response> {
        let helper = self.helper.lock().await;
        let request = helper.create_update(dialog, sdp_body);
        drop(helper);

        self.send_in_dialog_non_invite(dialog, request).await
    }

    /// Backwards-compatible alias for [`send_update`].
    pub async fn update(&self, dialog: &mut Dialog, sdp_body: Option<&str>) -> Result<Response> {
        self.send_update(dialog, sdp_body).await
    }

    /// Sends a REFER request for call transfer (RFC 3515).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send REFER within (transferee)
    /// * `refer_to` - Target URI for the transfer
    /// * `target_dialog` - Optional target dialog for attended transfer (RFC 3891)
    ///
    /// # Returns
    /// The final response and created subscription (if 202 Accepted)
    ///
    /// # Call Transfer Types
    ///
    /// **Blind Transfer** (no target_dialog):
    /// ```ignore
    /// // Transfer Bob to Carol
    /// let refer_to = SipUri::parse("sip:carol@example.com").unwrap();
    /// let (response, sub) = uac.refer(&bob_dialog, &refer_to, None).await?;
    /// ```
    ///
    /// **Attended Transfer** (with target_dialog):
    /// ```ignore
    /// // 1. Call Bob (dialog_bob)
    /// // 2. Put Bob on hold
    /// // 3. Call Carol (dialog_carol)
    /// // 4. Transfer Bob to Carol (Bob will replace Carol's dialog)
    /// let refer_to = SipUri::parse("sip:carol@example.com").unwrap();
    /// let (response, sub) = uac.refer(&dialog_bob, &refer_to, Some(&dialog_carol)).await?;
    /// ```
    pub async fn refer(
        &self,
        dialog: &mut Dialog,
        refer_to: &SipUri,
        target_dialog: Option<&Dialog>,
    ) -> Result<(Response, Option<Subscription>)> {
        // Generate REFER using helper
        let helper = self.helper.lock().await;
        let request = if let Some(target) = target_dialog {
            helper.create_refer_with_replaces(dialog, refer_to, target)
        } else {
            helper.create_refer(dialog, refer_to)
        };
        drop(helper);

        // Send and wait for response
        let response = self
            .send_in_dialog_non_invite(dialog, request.clone())
            .await?;

        // If 202 Accepted, create implicit subscription to "refer" event
        let subscription = if response.code() == 202 {
            // Create subscription for NOTIFY tracking
            let helper = self.helper.lock().await;
            // REFER creates an implicit subscription with "refer" event
            helper.process_subscribe_response(&request, &response)
        } else {
            None
        };

        Ok((response, subscription))
    }

    /// Refreshes an active session per RFC 4028 using UPDATE by default.
    ///
    /// If `use_update` is false, this falls back to re-INVITE and waits for the final response.
    pub async fn refresh_session(
        &self,
        dialog: &mut Dialog,
        session_expires: u32,
        refresher: &str,
        use_update: bool,
        sdp_body: Option<&str>,
    ) -> Result<Response> {
        let helper = self.helper.lock().await;
        let request =
            helper.create_session_refresh(dialog, session_expires, refresher, use_update, sdp_body);
        drop(helper);

        if use_update {
            self.send_in_dialog_non_invite(dialog, request).await
        } else {
            self.send_in_dialog_invite(dialog, request).await
        }
    }

    /// Sends any non-INVITE request within a dialog, handling routing and CSeq.
    pub async fn send_in_dialog_non_invite(
        &self,
        dialog: &mut Dialog,
        mut request: Request,
    ) -> Result<Response> {
        let target_uri = prepare_in_dialog_request(dialog, &mut request);
        let _ = self.dialog_manager.insert(dialog.clone());
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;

        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        let response = self.send_non_invite_request(request, dns_target).await?;
        self.handle_in_dialog_response(dialog, &response)?;
        Ok(response)
    }

    /// Sends an INVITE inside an existing dialog (e.g., re-INVITE).
    pub async fn send_in_dialog_invite(
        &self,
        dialog: &mut Dialog,
        mut request: Request,
    ) -> Result<Response> {
        let target_uri = prepare_in_dialog_request(dialog, &mut request);
        let _ = self.dialog_manager.insert(dialog.clone());
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;

        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        let handle = self
            .start_dialog_invite_transaction(dialog.clone(), request, dns_target)
            .await?;
        let response = handle.await_final().await?;
        self.handle_in_dialog_response(dialog, &response)?;
        Ok(response)
    }

    /// Sends PRACK for a reliable provisional response within a dialog.
    pub async fn send_prack(
        &self,
        dialog: &mut Dialog,
        provisional: &Response,
    ) -> Result<Response> {
        let helper = self.helper.lock().await;
        let request = helper.create_prack_from_provisional(provisional, dialog)?;
        drop(helper);

        self.send_in_dialog_non_invite(dialog, request).await
    }

    /// Convenience helper for re-INVITE that waits for the final response.
    pub async fn send_reinvite(
        &self,
        dialog: &mut Dialog,
        sdp_body: Option<&str>,
    ) -> Result<Response> {
        let helper = self.helper.lock().await;
        let request = helper.create_reinvite(dialog, sdp_body);
        drop(helper);

        self.send_in_dialog_invite(dialog, request).await
    }

    /// Sends a re-INVITE through an existing connection (RFC 5626 flow support).
    ///
    /// The flow counterpart of [`Self::send_reinvite`], for the case where the
    /// UAC originates a re-INVITE on a dialog that arrived over an inbound
    /// TCP/TLS connection: the peer's Contact names an ephemeral source port
    /// nothing listens on, so the re-INVITE must reuse the connection like
    /// [`Self::bye_via_flow`] and [`Self::send_refer_via_flow`] do. In-dialog
    /// preparation (CSeq, route set, Request-URI) is identical to
    /// `send_reinvite`, and the 2xx is auto-ACKed the same way (re-INVITE ACK
    /// rides the connection per RFC 3261 §18.2.2).
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send the re-INVITE within
    /// * `sdp_body` - The offer SDP (e.g. `a=sendonly` to hold)
    /// * `flow` - The existing connection to send through
    ///
    /// # Returns
    /// The final response.
    pub async fn send_reinvite_via_flow(
        &self,
        dialog: &mut Dialog,
        sdp_body: Option<&str>,
        flow: Flow,
    ) -> Result<Response> {
        let helper = self.helper.lock().await;
        let mut request = helper.create_reinvite(dialog, sdp_body);
        drop(helper);

        // Same in-dialog preparation as send_in_dialog_invite.
        let target_uri = prepare_in_dialog_request(dialog, &mut request);
        let _ = self.dialog_manager.insert(dialog.clone());

        // Resolved only for the Via transport token; routing follows the flow.
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;
        self.auto_fill_headers_for_flow(
            &mut request,
            Some(dns_target.transport()),
            flow.local_addr,
        )
        .await;

        info!("Sending re-INVITE via flow for dialog {:?}", dialog.id());
        let handle = self
            .start_dialog_invite_transaction_via_flow(dialog.clone(), request, &dns_target, flow)
            .await?;
        let response = handle.await_final().await?;
        self.handle_in_dialog_response(dialog, &response)?;
        Ok(response)
    }

    /// Convenience helper for INFO within a dialog.
    pub async fn send_info(
        &self,
        dialog: &mut Dialog,
        content_type: &str,
        body: &str,
    ) -> Result<Response> {
        let helper = self.helper.lock().await;
        let request = helper.create_info(dialog, content_type, body)?;
        drop(helper);

        self.send_in_dialog_non_invite(dialog, request).await
    }

    /// Convenience helper for REFER within a dialog.
    pub async fn send_refer(
        &self,
        dialog: &mut Dialog,
        refer_to: &SipUri,
        target_dialog: Option<&Dialog>,
    ) -> Result<(Response, Option<Subscription>)> {
        let helper = self.helper.lock().await;
        let request = if let Some(target) = target_dialog {
            helper.create_refer_with_replaces(dialog, refer_to, target)
        } else {
            helper.create_refer(dialog, refer_to)
        };
        drop(helper);

        let response = self
            .send_in_dialog_non_invite(dialog, request.clone())
            .await?;

        let subscription = if response.code() == 202 {
            let helper = self.helper.lock().await;
            helper.process_subscribe_response(&request, &response)
        } else {
            None
        };

        Ok((response, subscription))
    }

    /// Sends a REFER through an existing connection (RFC 5626 flow support).
    ///
    /// The flow counterpart of [`Self::send_refer`], for transferring a call
    /// whose dialog arrived over an inbound TCP/TLS connection: the peer's
    /// Contact names an ephemeral source port nothing listens on, so the
    /// REFER must reuse the connection like [`Self::bye_via_flow`] does for
    /// BYE. In-dialog preparation (CSeq, route set, Request-URI) and the
    /// implicit "refer" subscription on 202 are identical to `send_refer`.
    ///
    /// # Arguments
    /// * `dialog` - The dialog to send the REFER within
    /// * `refer_to` - Transfer target URI
    /// * `target_dialog` - For attended transfer, the consult dialog to
    ///   build the `Replaces` header from (RFC 3891); `None` for blind
    /// * `flow` - The existing connection to send through
    ///
    /// # Returns
    /// The final response, plus the implicit subscription if it was 202
    pub async fn send_refer_via_flow(
        &self,
        dialog: &mut Dialog,
        refer_to: &SipUri,
        target_dialog: Option<&Dialog>,
        flow: Flow,
    ) -> Result<(Response, Option<Subscription>)> {
        let helper = self.helper.lock().await;
        let mut request = if let Some(target) = target_dialog {
            helper.create_refer_with_replaces(dialog, refer_to, target)
        } else {
            helper.create_refer(dialog, refer_to)
        };
        drop(helper);

        // Same in-dialog preparation as send_in_dialog_non_invite
        let target_uri = prepare_in_dialog_request(dialog, &mut request);
        let _ = self.dialog_manager.insert(dialog.clone());

        // Resolved only for the Via transport token; routing follows the flow
        let dns_target = self.resolve_target(&RequestTarget::Uri(target_uri)).await?;
        self.auto_fill_headers_for_flow(
            &mut request,
            Some(dns_target.transport()),
            flow.local_addr,
        )
        .await;

        info!("Sending REFER via flow for dialog {:?}", dialog.id());
        let response = self
            .send_non_invite_via_flow(request.clone(), &dns_target, &flow)
            .await?;
        self.handle_in_dialog_response(dialog, &response)?;

        let subscription = if response.code() == 202 {
            let helper = self.helper.lock().await;
            helper.process_subscribe_response(&request, &response)
        } else {
            None
        };

        Ok((response, subscription))
    }

    /// Starts an INVITE transaction for an existing dialog and returns a handle.
    async fn start_dialog_invite_transaction(
        &self,
        dialog: Dialog,
        request: Request,
        dns_target: DnsTarget,
    ) -> Result<CallHandle> {
        let (prov_tx, prov_rx) = mpsc::channel(16);
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        let ctx = self.create_transport_context(&dns_target).await?;
        let early_dialogs = Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Wrap dialog in Arc<RwLock> for sharing between CallHandle and transaction user
        let shared_dialog = Arc::new(RwLock::new(dialog));

        let live_request = Arc::new(RwLock::new(Arc::new(request.clone())));
        let tu = Arc::new(InviteTransactionUser {
            prov_tx,
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: request.clone(),
            config: self.config.clone(),
            ctx: ctx.clone(),
            auto_retry_auth: self.config.auto_retry_auth,
            auth_attempt: 0,
            live_request: live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            dialog: shared_dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx.clone(), tu)
            .await?;

        info!(
            "Started INVITE transaction {} for dialog {}",
            key.branch(),
            shared_dialog.read().await.id().call_id()
        );

        Ok(CallHandle {
            dialog: shared_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: live_request,
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
            session_timer_state: Arc::new(watch::Sender::new(SessionTimerState::Idle)),
        })
    }

    /// Flow-aware variant of [`Self::start_dialog_invite_transaction`]: the
    /// transaction's transport context reuses the supplied connection instead
    /// of resolving a fresh one (RFC 5626). Backs [`Self::send_reinvite_via_flow`].
    async fn start_dialog_invite_transaction_via_flow(
        &self,
        dialog: Dialog,
        request: Request,
        dns_target: &DnsTarget,
        flow: Flow,
    ) -> Result<CallHandle> {
        use sip_transaction::TransportKind;
        let (prov_tx, prov_rx) = mpsc::channel(16);
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        let transport = match dns_target.transport() {
            sip_dns::Transport::Tls => TransportKind::Tls,
            sip_dns::Transport::Tcp => TransportKind::Tcp,
            _ => TransportKind::Tls, // Default to TLS for flow-based routing
        };
        let ctx = TransportContext::new(transport, flow.peer_addr, Some(flow.stream))
            .with_server_name(Some(dns_target.sni().to_string()))
            .with_local_addr(flow.local_addr);

        // Second target: dial the route-set edge through the pool if the
        // inbound connection turns out to be dead (issue #73).
        let mut targets = vec![ctx.clone()];
        targets.extend(self.flow_fallback_context(transport, dns_target).await);

        let early_dialogs = Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Wrap dialog in Arc<RwLock> for sharing between CallHandle and transaction user
        let shared_dialog = Arc::new(RwLock::new(dialog));

        let live_request = Arc::new(RwLock::new(Arc::new(request.clone())));
        let tu = Arc::new(InviteTransactionUser {
            prov_tx,
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: request.clone(),
            config: self.config.clone(),
            ctx: ctx.clone(),
            auto_retry_auth: self.config.auto_retry_auth,
            auth_attempt: 0,
            live_request: live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            dialog: shared_dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        let key = self
            .transaction_manager
            .start_client_transaction_with_targets(request.clone(), targets, tu)
            .await?;

        info!(
            "Started INVITE transaction {} for dialog {} via flow",
            key.branch(),
            shared_dialog.read().await.id().call_id()
        );

        Ok(CallHandle {
            dialog: shared_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: live_request,
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
            session_timer_state: Arc::new(watch::Sender::new(SessionTimerState::Idle)),
        })
    }

    /// Sends a lightweight CRLF keepalive to keep NAT/LB bindings active.
    ///
    /// Uses the resolved transport for the provided target (UDP/TCP/TLS).
    pub async fn send_keepalive(&self, target: impl Into<RequestTarget>) -> Result<()> {
        let target = target.into();
        let dns_target = self.resolve_target(&target).await?;
        let ctx = self.create_transport_context(&dns_target).await?;

        // Double-CRLF keepalive (common for SIP over UDP/TCP to refresh bindings)
        let payload = Bytes::from_static(b"\r\n\r\n");
        self.transport_dispatcher.dispatch(&ctx, payload).await
    }
}

/// Refresh period for a session timer: half the Session-Expires interval
/// per RFC 4028 §10, so the refresh always lands well before expiry.
///
/// `session_expires` values that reached a dialog are already ≥ 90
/// (`SessionExpires::new` enforces the RFC 4028 minimum), so the half
/// interval is ≥ 45 s; the 1 s floor only guards a raw out-of-range value
/// from spinning the refresh loop. No larger floor is applied — clamping
/// upward (as the old `max(90, se/2)` did) pushed the refresh *past* the
/// halfway point for any interval under 180 s, and exactly onto the expiry
/// deadline at the RFC minimum of 90 s.
fn session_refresh_period(session_expires: u32) -> std::time::Duration {
    std::time::Duration::from_secs(u64::from(std::cmp::max(1, session_expires / 2)))
}

/// The RFC 4028 refresh loop behind [`CallHandle::start_session_timer`],
/// split out so its failure policy can be tested without standing up a whole
/// [`CallHandle`].
///
/// Refreshes at half the interval and reports what it is doing on `state`. It
/// returns — stops refreshing altogether — when the peer says the dialog is
/// gone, or after `max_session_refresh_failures` consecutive failures. It
/// never sends a BYE: RFC 4028 §10 suggests the refresher tear the session
/// down, but that is the owner's decision to make from
/// [`SessionTimerState::Stopped`] (issue #93).
async fn run_session_timer(
    uac: Arc<IntegratedUAC>,
    dialog: Arc<RwLock<Dialog>>,
    state: Arc<watch::Sender<SessionTimerState>>,
    session_expires: u32,
    refresher: &'static str,
    use_update: bool,
) {
    let max_failures = std::cmp::max(1, uac.config.max_session_refresh_failures);
    let period = session_refresh_period(session_expires);
    // The first tick must land one period out, not immediately:
    // a plain `interval` completes its first tick at once, which
    // would send a gratuitous refresh the moment the call answers.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let mut consecutive: u32 = 0;

    loop {
        ticker.tick().await;

        let outcome =
            refresh_shared_session(&uac, &dialog, session_expires, refresher, use_update).await;

        // Only a 2xx means the session was actually refreshed.
        // `apply_in_dialog_response` maps 408/481 to `Err` but returns `Ok`
        // for every other non-2xx, so a 422 or 503 that rejected the refresh
        // would otherwise count as a success — leaving the session to expire
        // while the timer reported health.
        match &outcome {
            Ok(response) if (200..300).contains(&response.code()) => {
                consecutive = 0;
                let _ = state.send(SessionTimerState::Healthy {
                    last_refresh: std::time::Instant::now(),
                });
                continue;
            }
            Ok(response) => warn!(
                "Session refresh rejected with {} {}",
                response.code(),
                response.reason()
            ),
            Err(e) => warn!("Session refresh failed: {}", e),
        }

        consecutive = consecutive.saturating_add(1);

        // A 408/481 terminated the dialog on its way through
        // `apply_in_dialog_response`: the peer says it no longer exists, and
        // no number of retries will bring it back (RFC 3261 §12.2.1.2).
        // Reading the dialog's state rather than matching on the error text
        // also catches an owner that tore the call down mid-refresh.
        if dialog.read().await.state() == DialogStateType::Terminated {
            warn!("Session refresh stopping: the dialog is gone");
            let _ = state.send(SessionTimerState::Stopped {
                reason: SessionTimerStop::DialogGone,
            });
            return;
        }

        if consecutive >= max_failures {
            error!(
                "Session refresh stopping after {} consecutive failures; \
                 nothing is keeping this session alive",
                consecutive
            );
            let _ = state.send(SessionTimerState::Stopped {
                reason: SessionTimerStop::Exhausted { consecutive },
            });
            return;
        }

        let _ = state.send(SessionTimerState::Failing { consecutive });
    }
}

/// Send one RFC 4028 refresh against a **shared** dialog, publishing the
/// CSeq it consumes back to that dialog (issue #95).
///
/// The number is **reserved before the send, not committed after the
/// response** (issue #99). Committing afterwards left the shared dialog
/// reading the pre-request CSeq for the whole round trip, so an owner that
/// resolved it in that window — to send a teardown BYE, a hold re-INVITE, a
/// REFER — built its request on the number the refresh was already using.
/// Two requests, one sequence number, which RFC 3261 §12.2.1.1 forbids, and
/// a peer is entitled to reject the second as a retransmission: #95's
/// stranded-far-leg failure arriving by a different route.
///
/// Serialising the two would close it too, but at the cost of holding the
/// write lock across a network round trip (up to Timer B/F, ~32 s), stalling
/// the very BYE this is meant to keep working. Reserving holds it for two
/// clones and an increment instead. An owner racing the refresh now reads the
/// reserved number and takes the next one.
///
/// The dialog is still cloned for the send — the request cannot be built
/// under a lock — and still committed afterwards by
/// [`commit_advanced_dialog`], which is what carries the response's target
/// refresh (RFC 5057) rather than the CSeq alone.
///
/// The commit happens on failure too, deliberately: `prepare_in_dialog_request`
/// consumes the CSeq when it *builds* the request, so a refresh that times out
/// or draws an error has still put that number on the wire. Dropping the
/// advance because the response disappointed us would hand the owner a CSeq
/// the peer has already seen — the exact reuse this fix exists to prevent.
async fn refresh_shared_session(
    uac: &IntegratedUAC,
    shared: &Arc<RwLock<Dialog>>,
    session_expires: u32,
    refresher: &str,
    use_update: bool,
) -> Result<Response> {
    // Reserve the CSeq this refresh will consume before it can be observed
    // by anyone else. `refresh_session` advances the clone by one, so the
    // clone is taken *before* the shared advance and the two agree.
    let mut dialog = {
        let mut shared = shared.write().await;
        let pre_advance = shared.clone();
        shared.next_local_cseq();
        pre_advance
    };
    let result = uac
        .refresh_session(&mut dialog, session_expires, refresher, use_update, None)
        .await;
    commit_advanced_dialog(shared, dialog).await;
    result
}

/// Publish a dialog whose local CSeq an in-dialog request just consumed.
///
/// Refuses to move the CSeq backwards. A lower value means the owner sent —
/// and committed — its own in-dialog request while this refresh was in flight,
/// so its state is the newer of the two and adopting ours wholesale would undo
/// it. Since #99 the two no longer collide on a CSeq when that happens (the
/// refresh reserved its number before sending, so the owner's request took a
/// later one); this keeps the dialog from losing the owner's other updates.
async fn commit_advanced_dialog(shared: &Arc<RwLock<Dialog>>, advanced: Dialog) {
    let mut guard = shared.write().await;
    if advanced.local_cseq() >= guard.local_cseq() {
        *guard = advanced;
    } else {
        debug!(
            "Session refresh commit skipped: dialog CSeq moved to {} while the refresh at {} was in flight",
            guard.local_cseq(),
            advanced.local_cseq()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, RequestLine, StatusLine};
    use sip_dialog::{DialogId, DialogStateType};
    use std::time::Duration;

    fn base_dialog() -> Dialog {
        let dialog_id = DialogId::unchecked_new("call", "local", "remote");
        Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Confirmed,
            SipUri::parse("sip:local@example.com").unwrap(),
            SipUri::parse("sip:remote@example.com").unwrap(),
            SipUri::parse("sip:remote@example.com").unwrap(),
            1,                             // local_cseq
            0,                             // remote_cseq
            None,                          // last_ack_cseq
            vec![],                        // route_set
            false,                         // secure
            Some(Duration::from_secs(30)), // session_expires
            None,                          // refresher
            true,                          // is_uac
        )
    }

    /// Issue #76: a fresh TLS dial to an IP-literal route-set hop must
    /// use the configured trunk hostname for SNI/verification, not the IP.
    #[test]
    fn tls_server_name_overrides_ip_literal_sni() {
        let target = DnsTarget::unchecked_new("203.0.113.5", 5061, sip_dns::Transport::Tls);
        let out = apply_tls_server_name(target, Some("example.pstn.twilio.com"));
        assert_eq!(out.sni(), "example.pstn.twilio.com");
        assert_eq!(out.host(), "203.0.113.5", "connect addr is unchanged");
    }

    /// The override must not clobber a real hostname target, an existing
    /// RFC 3263 reference identity, or non-TLS transports.
    #[test]
    fn tls_server_name_leaves_hostnames_and_non_tls_alone() {
        let hostname = DnsTarget::unchecked_new("edge.example.com", 5061, sip_dns::Transport::Tls);
        assert_eq!(
            apply_tls_server_name(hostname, Some("other.example.com")).sni(),
            "edge.example.com"
        );

        let with_ref = DnsTarget::unchecked_new("203.0.113.5", 5061, sip_dns::Transport::Tls)
            .with_tls_name("resolved.example.com");
        assert_eq!(
            apply_tls_server_name(with_ref, Some("other.example.com")).sni(),
            "resolved.example.com"
        );

        let udp = DnsTarget::unchecked_new("203.0.113.5", 5060, sip_dns::Transport::Udp);
        assert_eq!(
            apply_tls_server_name(udp, Some("other.example.com")).sni(),
            "203.0.113.5"
        );

        let no_override = DnsTarget::unchecked_new("203.0.113.5", 5061, sip_dns::Transport::Tls);
        assert_eq!(
            apply_tls_server_name(no_override, None).sni(),
            "203.0.113.5"
        );
    }

    // Helper to create dialog with custom route_set
    fn dialog_with_route_set(route_set: Vec<SipUri>) -> Dialog {
        let dialog_id = DialogId::unchecked_new("call", "local", "remote");
        Dialog::unchecked_new(
            dialog_id,
            DialogStateType::Confirmed,
            SipUri::parse("sip:local@example.com").unwrap(),
            SipUri::parse("sip:remote@example.com").unwrap(),
            SipUri::parse("sip:remote@example.com").unwrap(),
            1,                             // local_cseq
            0,                             // remote_cseq
            None,                          // last_ack_cseq
            route_set,                     // custom route_set
            false,                         // secure
            Some(Duration::from_secs(30)), // session_expires
            None,                          // refresher
            true,                          // is_uac
        )
    }

    #[test]
    fn prepare_in_dialog_respects_loose_routing() {
        let mut dialog = dialog_with_route_set(vec![
            SipUri::parse("sip:proxy.example.com;lr").expect("valid route")
        ]);

        let mut request = Request::new(
            RequestLine::new(Method::Info, dialog.remote_target().clone()),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request");

        let target = prepare_in_dialog_request(&mut dialog, &mut request);

        assert_eq!(target, dialog.route_set()[0]);
        assert_eq!(request.uri(), &dialog.remote_target().clone().into());
        assert_eq!(
            request.headers().get("Route"),
            Some("<sip:proxy.example.com;lr>")
        );
        assert_eq!(dialog.local_cseq(), 2);
        assert_eq!(request.headers().get("CSeq"), Some("2 INFO"));
    }

    #[test]
    fn prepare_in_dialog_handles_strict_routing() {
        let mut dialog = dialog_with_route_set(vec![
            SipUri::parse("sip:strict.example.com").unwrap(),
            SipUri::parse("sip:loose.example.com;lr").unwrap(),
        ]);

        let mut request = Request::new(
            RequestLine::new(Method::Update, dialog.remote_target().clone()),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request");

        let target = prepare_in_dialog_request(&mut dialog, &mut request);
        let routes: Vec<&SmolStr> = request.headers().get_all_smol("Route").collect();

        assert_eq!(target, dialog.route_set()[0]);
        assert_eq!(request.uri(), &dialog.route_set()[0].clone().into());
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].as_str(), "<sip:loose.example.com;lr>");
        assert_eq!(routes[1].as_str(), "<sip:remote@example.com>");
    }

    #[test]
    fn apply_response_updates_remote_target() {
        let mut dialog = base_dialog();
        let manager = DialogManager::new();
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:new-remote@example.com>"),
            )
            .unwrap();
        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");

        apply_in_dialog_response(&manager, &mut dialog, &response).unwrap();
        assert_eq!(
            dialog.remote_target().as_str(),
            "sip:new-remote@example.com"
        );
        assert_eq!(dialog.state(), DialogStateType::Confirmed);
    }

    #[test]
    fn apply_response_marks_termination_on_481() {
        let mut dialog = base_dialog();
        let manager = DialogManager::new();
        let response = Response::new(
            StatusLine::new(481, SmolStr::new("Call/Transaction Does Not Exist"))
                .expect("valid status line"),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid response");

        let result = apply_in_dialog_response(&manager, &mut dialog, &response);
        assert!(result.is_err());
        assert_eq!(dialog.state(), DialogStateType::Terminated);
    }

    // ── Via auto-fill: flow-routed requests advertise the listener port ──

    #[test]
    fn via_port_tracks_flow_listener() {
        // The nit from #56's sibling: a request leaving over the TLS
        // listener's connection advertised the configured (UDP) port.
        // Host stays the advertised one; only the port follows the flow.
        let advertised: SocketAddr = "203.0.113.7:5070".parse().unwrap();
        let tls_local: SocketAddr = "0.0.0.0:5071".parse().unwrap();
        let via = build_via_value("TLS", advertised, Some(tls_local), "z9hG4bKabc");
        assert_eq!(via, "SIP/2.0/TLS 203.0.113.7:5071;branch=z9hG4bKabc;rport");
    }

    #[test]
    fn via_without_flow_keeps_advertised_port() {
        let advertised: SocketAddr = "203.0.113.7:5070".parse().unwrap();
        let via = build_via_value("UDP", advertised, None, "z9hG4bKabc");
        assert_eq!(via, "SIP/2.0/UDP 203.0.113.7:5070;branch=z9hG4bKabc;rport");
    }

    // ── send_refer_via_flow: REFER rides the flow connection ──

    #[derive(Default)]
    struct CapturingDispatcher {
        sent: Mutex<Vec<(TransportContext, Bytes)>>,
    }

    #[async_trait]
    impl TransportDispatcher for CapturingDispatcher {
        async fn dispatch(&self, ctx: &TransportContext, payload: Bytes) -> Result<()> {
            self.sent.lock().await.push((ctx.clone(), payload));
            Ok(())
        }
    }

    #[tokio::test]
    async fn send_refer_via_flow_reuses_connection_and_completes_on_202() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = Arc::new(
            IntegratedUAC::builder()
                .local_uri("sip:siphon@127.0.0.1")
                .local_addr("127.0.0.1:5070")
                .unwrap()
                .transaction_manager(manager.clone())
                .resolver(Arc::new(SipResolver::from_system().unwrap()))
                .dispatcher(dispatcher.clone())
                .build()
                .unwrap(),
        );

        // UAS-side confirmed dialog whose peer arrived over TLS: the remote
        // target names the peer's ephemeral source port, which nothing
        // listens on — the whole reason the REFER must reuse the flow.
        let dialog = Dialog::unchecked_new(
            DialogId::unchecked_new("flow-call", "local-tag", "remote-tag"),
            DialogStateType::Confirmed,
            SipUri::parse("sip:siphon@127.0.0.1").unwrap(),
            SipUri::parse("sip:tester@192.0.2.10").unwrap(),
            SipUri::parse("sip:tester@192.0.2.10:49152;transport=tls").unwrap(),
            1,      // local_cseq
            1,      // remote_cseq
            None,   // last_ack_cseq
            vec![], // route_set
            false,  // secure
            None,   // session_expires
            None,   // refresher
            false,  // is_uac (we are the UAS of the original INVITE)
        );

        let (flow_tx, _flow_rx) = mpsc::channel::<Bytes>(8);
        let flow = Flow::new(flow_tx, "192.0.2.10:49152".parse().unwrap())
            .with_local_addr("127.0.0.1:5071".parse().unwrap());
        let refer_to = SipUri::parse("sip:agent@198.51.100.20:5060").unwrap();

        let task = {
            let uac = uac.clone();
            tokio::spawn(async move {
                let mut dialog = dialog;
                let result = uac
                    .send_refer_via_flow(&mut dialog, &refer_to, None, flow)
                    .await;
                (result, dialog)
            })
        };

        // Wait for the transaction layer to emit the REFER, then check it
        // went out on the flow rather than a fresh dial-out.
        let request = loop {
            if let Some((ctx, payload)) = dispatcher.sent.lock().await.first().cloned() {
                assert!(ctx.stream().is_some(), "REFER must carry the flow stream");
                assert_eq!(ctx.peer(), "192.0.2.10:49152".parse().unwrap());
                assert_eq!(ctx.local_addr(), Some("127.0.0.1:5071".parse().unwrap()));
                break sip_parse::parse_request(&payload).expect("valid REFER on the wire");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        assert_eq!(request.method(), &Method::Refer);
        assert_eq!(request.headers().get("CSeq"), Some("2 REFER"));
        assert!(request.headers().get("Refer-To").is_some());
        let via = request.headers().get("Via").unwrap();
        assert!(
            via.starts_with("SIP/2.0/TLS 127.0.0.1:5071;"),
            "Via must advertise the flow listener's port, got: {via}"
        );

        // Answer 202 Accepted so the transaction completes.
        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            headers
                .push(
                    SmolStr::new(name),
                    request.headers().get_smol(name).unwrap().clone(),
                )
                .unwrap();
        }
        let response = Response::new(
            StatusLine::new(202, SmolStr::new("Accepted")).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");
        manager.receive_response(response).await;

        let (result, dialog) = task.await.unwrap();
        let (response, _subscription) = result.unwrap();
        assert_eq!(response.code(), 202);
        assert_eq!(dialog.local_cseq(), 2);
    }

    // ── bye_via_flow: the closing BYE must carry the dialog route set ──

    /// Regression for the stranded-caller bug: force-terminating an inbound
    /// call answered through a record-routing carrier edge sent a BYE with
    /// *no* Route headers and the peer's private Contact as Request-URI. The
    /// edge could not correlate it, answered 481, and the far leg sat in dead
    /// air until session-expires. The BYE must instead loose-route through the
    /// record-route proxy, exactly as every other in-dialog request does.
    #[tokio::test]
    async fn bye_via_flow_carries_route_set_and_dialog_local_uri() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = Arc::new(
            IntegratedUAC::builder()
                .local_uri("sip:siphon@127.0.0.1")
                .local_addr("127.0.0.1:5070")
                .unwrap()
                .transaction_manager(manager.clone())
                .resolver(Arc::new(SipResolver::from_system().unwrap()))
                .dispatcher(dispatcher.clone())
                .build()
                .unwrap(),
        );

        // UAS-role confirmed dialog for an inbound call answered through a
        // record-routing edge. The route set holds the edge's loose-route
        // URI; the remote target is the peer's private (unroutable) Contact.
        // The dialog's local URI is the answered AOR — deliberately *not*
        // the UAC's configured `local_uri` — so the From-URI fix is exercised.
        // IP literal so `resolve_target` does no real DNS lookup in CI.
        let proxy = SipUri::parse("sip:198.51.100.10:5061;transport=tls;lr").unwrap();
        let local_aor = SipUri::parse("sip:+15551234567@127.0.0.1:5061;transport=tls").unwrap();
        let dialog = Dialog::unchecked_new(
            DialogId::unchecked_new("rr-call", "local-tag", "remote-tag"),
            DialogStateType::Confirmed,
            local_aor.clone(),
            SipUri::parse("sip:+15551234567@carrier.example.net").unwrap(),
            SipUri::parse("sip:+15551234567@10.8.0.4:5060;transport=udp").unwrap(),
            0,                   // local_cseq (UAS role: first outbound is CSeq 1)
            1,                   // remote_cseq
            None,                // last_ack_cseq
            vec![proxy.clone()], // route_set from Record-Route
            false,               // secure
            None,                // session_expires
            None,                // refresher
            false,               // is_uac (we answered the INVITE)
        );

        let (flow_tx, _flow_rx) = mpsc::channel::<Bytes>(8);
        let flow = Flow::new(flow_tx, "10.8.0.4:49152".parse().unwrap())
            .with_local_addr("127.0.0.1:5071".parse().unwrap());

        let task = {
            let uac = uac.clone();
            tokio::spawn(async move { uac.bye_via_flow(&dialog, flow).await })
        };

        // Grab the BYE the transaction layer emitted and check the wire form.
        let request = loop {
            if let Some((ctx, payload)) = dispatcher.sent.lock().await.first().cloned() {
                assert!(ctx.stream().is_some(), "BYE must reuse the inbound flow");
                break sip_parse::parse_request(&payload).expect("valid BYE on the wire");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        assert_eq!(request.method(), &Method::Bye);
        // The fix: the record-route proxy is present as a Route header and the
        // Request-URI is the remote target (loose routing).
        assert_eq!(
            request.headers().get("Route"),
            Some("<sip:198.51.100.10:5061;transport=tls;lr>"),
            "BYE must loose-route through the record-route proxy"
        );
        assert_eq!(
            request.uri(),
            &SipUri::parse("sip:+15551234567@10.8.0.4:5060;transport=udp")
                .unwrap()
                .into(),
            "loose routing keeps the remote target as Request-URI"
        );
        // The From URI is the dialog's local AOR, not the UAC's identity.
        let from = request.headers().get("From").unwrap();
        assert!(
            from.contains("sip:+15551234567@127.0.0.1:5061;transport=tls"),
            "From must be the dialog local URI, got: {from}"
        );
        assert!(
            !from.contains("sip:siphon@127.0.0.1"),
            "From must not be the UAC's configured identity, got: {from}"
        );

        // Answer 200 OK so the transaction — and the spawned task — complete.
        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            headers
                .push(
                    SmolStr::new(name),
                    request.headers().get_smol(name).unwrap().clone(),
                )
                .unwrap();
        }
        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");
        manager.receive_response(response).await;

        let response = task.await.unwrap().expect("BYE completes on 200");
        assert_eq!(response.code(), 200);
    }

    // ── via-flow sends recover when the inbound connection is dead ──

    /// Dispatcher shaped like the production one: a context carrying a
    /// flow stream sends through it (and surfaces the channel error when
    /// the connection's writer is gone); a context without one is a pool
    /// dial-out, captured for inspection.
    #[derive(Default)]
    struct StreamAwareDispatcher {
        pool_sent: Mutex<Vec<(TransportContext, Bytes)>>,
        flow_attempts: Mutex<usize>,
    }

    #[async_trait]
    impl TransportDispatcher for StreamAwareDispatcher {
        async fn dispatch(&self, ctx: &TransportContext, payload: Bytes) -> Result<()> {
            if let Some(stream) = ctx.stream() {
                *self.flow_attempts.lock().await += 1;
                stream
                    .send(payload)
                    .await
                    .map_err(|_| anyhow!("connection writer dropped"))?;
                Ok(())
            } else {
                self.pool_sent.lock().await.push((ctx.clone(), payload));
                Ok(())
            }
        }
    }

    /// Regression for issue #73: the peer idle-closed the inbound TCP/TLS
    /// connection, so the flow send fails fast (post-teardown-fix) — and
    /// the BYE must fail over to dialing the dialog's route-set edge
    /// through the pool instead of dying at Timer B with the caller in
    /// dead air.
    #[tokio::test]
    async fn bye_via_flow_falls_back_to_pool_when_flow_is_dead() {
        let dispatcher = Arc::new(StreamAwareDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = Arc::new(
            IntegratedUAC::builder()
                .local_uri("sip:siphon@127.0.0.1")
                .local_addr("127.0.0.1:5070")
                .unwrap()
                .transaction_manager(manager.clone())
                .resolver(Arc::new(SipResolver::from_system().unwrap()))
                .dispatcher(dispatcher.clone())
                .build()
                .unwrap(),
        );

        // Same record-routed inbound-call shape as the test above: the
        // route set names the carrier edge (IP literal: no DNS in CI),
        // the remote target is the peer's private Contact.
        let proxy = SipUri::parse("sip:198.51.100.10:5061;transport=tls;lr").unwrap();
        let dialog = Dialog::unchecked_new(
            DialogId::unchecked_new("dead-flow-call", "local-tag", "remote-tag"),
            DialogStateType::Confirmed,
            SipUri::parse("sip:+15551234567@127.0.0.1:5061;transport=tls").unwrap(),
            SipUri::parse("sip:+15551234567@carrier.example.net").unwrap(),
            SipUri::parse("sip:+15551234567@10.8.0.4:5060;transport=udp").unwrap(),
            0,                   // local_cseq
            1,                   // remote_cseq
            None,                // last_ack_cseq
            vec![proxy.clone()], // route_set from Record-Route
            false,               // secure
            None,                // session_expires
            None,                // refresher
            false,               // is_uac (we answered the INVITE)
        );

        // A dead flow: the receiver is dropped, exactly what the
        // transport's writer teardown does once the peer FINs.
        let (flow_tx, flow_rx) = mpsc::channel::<Bytes>(8);
        drop(flow_rx);
        let flow = Flow::new(flow_tx, "10.8.0.4:49152".parse().unwrap())
            .with_local_addr("127.0.0.1:5071".parse().unwrap());

        let task = {
            let uac = uac.clone();
            tokio::spawn(async move { uac.bye_via_flow(&dialog, flow).await })
        };

        // The BYE must show up as a pool dial-out to the route-set edge.
        let (ctx, request) = loop {
            if let Some((ctx, payload)) = dispatcher.pool_sent.lock().await.first().cloned() {
                break (
                    ctx,
                    sip_parse::parse_request(&payload).expect("valid BYE on the wire"),
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        assert!(
            *dispatcher.flow_attempts.lock().await >= 1,
            "the flow must be tried first"
        );
        assert!(ctx.stream().is_none(), "fallback target dials the pool");
        assert_eq!(
            ctx.peer(),
            "198.51.100.10:5061".parse().unwrap(),
            "fallback dials the route-set edge, not the peer's ephemeral port"
        );
        assert_eq!(
            ctx.server_name(),
            Some("198.51.100.10"),
            "fallback keeps the SNI for the TLS pool"
        );
        assert_eq!(request.method(), &Method::Bye);
        assert_eq!(
            request.headers().get("Route"),
            Some("<sip:198.51.100.10:5061;transport=tls;lr>"),
            "the fallback BYE still loose-routes through the edge"
        );

        // Answer 200 OK: the response completes the transaction even
        // though it was transmitted on the fallback target.
        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            headers
                .push(
                    SmolStr::new(name),
                    request.headers().get_smol(name).unwrap().clone(),
                )
                .unwrap();
        }
        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK")).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");
        manager.receive_response(response).await;

        let response = task.await.unwrap().expect("BYE completes via fallback");
        assert_eq!(response.code(), 200);
    }

    // ── builder: sharing a DialogManager with the UAS ──

    /// Build a minimally-configured UAC, optionally sharing a store.
    fn uac_with_optional_store(shared: Option<Arc<DialogManager>>) -> IntegratedUAC {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let mut builder = IntegratedUAC::builder()
            .local_uri("sip:siphon@127.0.0.1")
            .local_addr("127.0.0.1:5070")
            .unwrap()
            .transaction_manager(Arc::new(TransactionManager::new(dispatcher.clone())))
            .resolver(Arc::new(SipResolver::from_system().unwrap()))
            .dispatcher(dispatcher);
        if let Some(mgr) = shared {
            builder = builder.dialog_manager(mgr);
        }
        builder.build().unwrap()
    }

    /// An inbound in-dialog BYE as the peer would send it for a dialog we
    /// created as UAC: From carries *their* tag, To carries ours.
    fn inbound_bye(call_id: &str, our_tag: &str, their_tag: &str) -> Request {
        let mut headers = Headers::new();
        headers.push("Call-ID", call_id).unwrap();
        headers
            .push("From", &format!("<sip:remote@example.com>;tag={their_tag}"))
            .unwrap();
        headers
            .push("To", &format!("<sip:local@example.com>;tag={our_tag}"))
            .unwrap();
        Request::new(
            RequestLine::new(Method::Bye, SipUri::parse("sip:local@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
        .expect("valid BYE")
    }

    /// Both halves of the UAC — the `IntegratedUAC` handle and the inner
    /// `UserAgentClient` helper — must land on the injected store.
    /// Redirecting only one would relocate the split rather than close it,
    /// since the helper registers dialogs on its own from 2xx responses.
    #[tokio::test]
    async fn builder_shares_injected_dialog_manager_with_helper_too() {
        let shared = Arc::new(DialogManager::new());
        let uac = uac_with_optional_store(Some(shared.clone()));

        assert!(Arc::ptr_eq(uac.dialog_manager().unwrap(), &shared));
        let helper = uac.helper.lock().await;
        assert!(
            Arc::ptr_eq(&helper.dialog_manager, &shared),
            "helper must use the shared store, not its constructor default"
        );
    }

    /// Omitting the setter leaves the private store intact, so existing
    /// single-role embedders keep their current behaviour.
    #[tokio::test]
    async fn builder_without_injection_keeps_private_store() {
        let unrelated = Arc::new(DialogManager::new());
        let uac = uac_with_optional_store(None);

        assert!(!Arc::ptr_eq(uac.dialog_manager().unwrap(), &unrelated));
        let helper = uac.helper.lock().await;
        assert!(
            Arc::ptr_eq(&helper.dialog_manager, uac.dialog_manager().unwrap()),
            "un-injected UAC still agrees with itself"
        );
    }

    /// The regression this setter exists for: a dialog the UAC created
    /// must be resolvable by the lookup UAS dispatch performs on an
    /// inbound BYE. Before sharing was possible this missed, dispatch
    /// answered 481, and the outbound call never tore down.
    #[tokio::test]
    async fn uac_dialog_is_found_by_shared_manager_lookup() {
        let shared = Arc::new(DialogManager::new());
        let uac = uac_with_optional_store(Some(shared.clone()));

        // Register a confirmed UAC dialog the way the UAC does.
        let dialog = base_dialog(); // id = (call, local=our tag, remote=peer tag)
        let _ = uac.dialog_manager().unwrap().insert(dialog.clone());

        let bye = inbound_bye("call", "local", "remote");
        let found = shared
            .find_by_request(&bye)
            .expect("UAS dispatch must resolve the UAC's dialog through the shared store");
        assert_eq!(found.id(), dialog.id());
    }

    /// The same lookup against a *separate* manager still misses — this
    /// is the 481 path, pinned so the test above can't pass for the
    /// wrong reason (e.g. a global/static store).
    #[tokio::test]
    async fn unshared_uac_dialog_is_invisible_to_another_manager() {
        let uas_side = Arc::new(DialogManager::new());
        let uac = uac_with_optional_store(None);

        let _ = uac.dialog_manager().unwrap().insert(base_dialog());

        let bye = inbound_bye("call", "local", "remote");
        assert!(
            uas_side.find_by_request(&bye).is_none(),
            "a private UAC store must stay invisible to an unrelated manager"
        );
    }

    // ── INVITE auth retry on 401/407 (issue #83) ──

    fn auth_test_uac(
        dispatcher: Arc<CapturingDispatcher>,
        manager: Arc<TransactionManager>,
        config: Option<UACConfig>,
    ) -> Arc<IntegratedUAC> {
        let mut builder = IntegratedUAC::builder()
            .local_uri("sip:alice@127.0.0.1")
            .local_addr("127.0.0.1:5070")
            .unwrap()
            .credentials("alice", "secret")
            .transaction_manager(manager)
            .resolver(Arc::new(SipResolver::from_system().unwrap()))
            .dispatcher(dispatcher);
        if let Some(config) = config {
            builder = builder.config(config);
        }
        Arc::new(builder.build().unwrap())
    }

    async fn sent_requests(dispatcher: &CapturingDispatcher) -> Vec<Request> {
        dispatcher
            .sent
            .lock()
            .await
            .iter()
            .filter_map(|(_, payload)| sip_parse::parse_request(payload))
            .collect()
    }

    async fn wait_for_request<F>(dispatcher: &CapturingDispatcher, pred: F) -> Request
    where
        F: Fn(&Request) -> bool,
    {
        loop {
            if let Some(request) = sent_requests(dispatcher).await.into_iter().find(&pred) {
                return request;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn via_branch(request: &Request) -> String {
        let via = request.headers().get("Via").unwrap();
        via.split("branch=").nth(1).unwrap().to_string()
    }

    /// 401/407 challenge echoing the request's transaction identifiers,
    /// shaped like FreeSWITCH's (To tag, MD5 digest with qop).
    fn challenge_response(request: &Request, code: u16) -> Response {
        let mut headers = Headers::new();
        for name in ["Via", "From", "Call-ID", "CSeq"] {
            headers
                .push(
                    SmolStr::new(name),
                    request.headers().get_smol(name).unwrap().clone(),
                )
                .unwrap();
        }
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new(format!("{};tag=chal", request.headers().get("To").unwrap())),
            )
            .unwrap();
        let (reason, auth_header) = if code == 407 {
            ("Proxy Authentication Required", "Proxy-Authenticate")
        } else {
            ("Unauthorized", "WWW-Authenticate")
        };
        headers
            .push(
                SmolStr::new(auth_header),
                SmolStr::new(
                    "Digest realm=\"127.0.0.1\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"",
                ),
            )
            .unwrap();
        Response::new(
            StatusLine::new(code, SmolStr::new(reason)).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response")
    }

    fn ok_response(request: &Request) -> Response {
        let mut headers = Headers::new();
        for name in ["Via", "From", "Call-ID", "CSeq"] {
            headers
                .push(
                    SmolStr::new(name),
                    request.headers().get_smol(name).unwrap().clone(),
                )
                .unwrap();
        }
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new(format!(
                    "{};tag=uas-ok",
                    request.headers().get("To").unwrap()
                )),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:9196@127.0.0.1:5060>"),
            )
            .unwrap();
        Response::new(
            StatusLine::new(200, SmolStr::new("OK")).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response")
    }

    /// The headline regression from issue #83: an INVITE answered with 407
    /// must be re-sent with Proxy-Authorization (same Call-ID and From tag,
    /// CSeq+1, fresh branch, original body), and the application must see
    /// only the authenticated attempt's final response.
    #[tokio::test]
    async fn invite_407_is_retried_and_confirms_dialog() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = auth_test_uac(dispatcher.clone(), manager.clone(), None);

        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\n";
        let call = uac
            .invite("sip:9196@127.0.0.1:5060", Some(sdp))
            .await
            .unwrap();

        let invite1 = wait_for_request(&dispatcher, |r| r.method() == &Method::Invite).await;
        assert!(invite1.headers().get("Proxy-Authorization").is_none());
        assert_eq!(invite1.headers().get("CSeq"), Some("1 INVITE"));

        manager
            .receive_response(challenge_response(&invite1, 407))
            .await;

        // The transaction layer ACKs the challenge...
        let ack = wait_for_request(&dispatcher, |r| r.method() == &Method::Ack).await;
        assert_eq!(via_branch(&ack), via_branch(&invite1));

        // ...and the authenticated re-INVITE goes out as a new transaction.
        let invite2 = wait_for_request(&dispatcher, |r| {
            r.method() == &Method::Invite && r.headers().get("Proxy-Authorization").is_some()
        })
        .await;
        assert_eq!(invite2.headers().get("CSeq"), Some("2 INVITE"));
        assert_eq!(
            invite2.headers().get("Call-ID"),
            invite1.headers().get("Call-ID")
        );
        assert_eq!(invite2.headers().get("From"), invite1.headers().get("From"));
        assert_ne!(via_branch(&invite2), via_branch(&invite1));
        assert_eq!(invite2.body(), invite1.body(), "retry keeps the SDP offer");

        manager.receive_response(ok_response(&invite2)).await;

        let final_response = call.await_final().await.unwrap();
        assert_eq!(final_response.code(), 200, "only the 200 reaches the app");
        assert_eq!(call.dialog.read().await.id().remote_tag(), "uas-ok");

        // CANCEL/ACK bookkeeping follows the live attempt.
        assert_eq!(
            call.invite_request().await.headers().get("CSeq"),
            Some("2 INVITE")
        );
    }

    /// Same retry for a 401 challenge: the retry carries Authorization
    /// (not Proxy-Authorization), per the challenge header form.
    #[tokio::test]
    async fn invite_401_is_retried_with_authorization() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = auth_test_uac(dispatcher.clone(), manager.clone(), None);

        let _call = uac
            .invite("sip:9196@127.0.0.1:5060", Some("v=0\r\n"))
            .await
            .unwrap();
        let invite1 = wait_for_request(&dispatcher, |r| r.method() == &Method::Invite).await;

        manager
            .receive_response(challenge_response(&invite1, 401))
            .await;

        let invite2 = wait_for_request(&dispatcher, |r| {
            r.method() == &Method::Invite && r.headers().get("Authorization").is_some()
        })
        .await;
        assert_eq!(invite2.headers().get("CSeq"), Some("2 INVITE"));
        assert!(invite2.headers().get("Proxy-Authorization").is_none());
    }

    /// Delayed-offer INVITEs retry with the body they originally had:
    /// none. The authenticated attempt must not grow an SDP body.
    #[tokio::test]
    async fn offerless_invite_retry_keeps_empty_body() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = auth_test_uac(dispatcher.clone(), manager.clone(), None);

        let _call = uac.invite("sip:9196@127.0.0.1:5060", None).await.unwrap();
        let invite1 = wait_for_request(&dispatcher, |r| r.method() == &Method::Invite).await;
        assert!(invite1.body().is_empty());

        manager
            .receive_response(challenge_response(&invite1, 407))
            .await;

        let invite2 = wait_for_request(&dispatcher, |r| {
            r.method() == &Method::Invite && r.headers().get("Proxy-Authorization").is_some()
        })
        .await;
        assert!(invite2.body().is_empty(), "offerless retry stays offerless");
        assert_eq!(invite2.headers().get("Content-Length"), Some("0"));
    }

    /// Persistent challenges stop at `max_auth_retries`, and the last
    /// challenge is surfaced as the final response (matching non-INVITE
    /// retry semantics).
    #[tokio::test]
    async fn invite_auth_retry_limit_surfaces_last_challenge() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let config = UACConfig {
            max_auth_retries: 1,
            ..Default::default()
        };
        let uac = auth_test_uac(dispatcher.clone(), manager.clone(), Some(config));

        let call = uac
            .invite("sip:9196@127.0.0.1:5060", Some("v=0\r\n"))
            .await
            .unwrap();
        let invite1 = wait_for_request(&dispatcher, |r| r.method() == &Method::Invite).await;

        manager
            .receive_response(challenge_response(&invite1, 407))
            .await;

        let invite2 = wait_for_request(&dispatcher, |r| {
            r.method() == &Method::Invite && r.headers().get("Proxy-Authorization").is_some()
        })
        .await;

        // Challenge the authenticated attempt too: budget (1) exhausted.
        manager
            .receive_response(challenge_response(&invite2, 407))
            .await;

        let final_response = call.await_final().await.unwrap();
        assert_eq!(final_response.code(), 407, "last challenge surfaces");

        // Exactly two INVITE attempts went out (distinct branches).
        let branches: std::collections::HashSet<String> = sent_requests(&dispatcher)
            .await
            .iter()
            .filter(|r| r.method() == &Method::Invite)
            .map(via_branch)
            .collect();
        assert_eq!(branches.len(), 2);
    }

    /// `auto_retry_auth = false` preserves the old behaviour: the
    /// challenge is the final response and nothing is re-sent.
    #[tokio::test]
    async fn invite_auth_retry_disabled_surfaces_challenge() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let config = UACConfig {
            auto_retry_auth: false,
            ..Default::default()
        };
        let uac = auth_test_uac(dispatcher.clone(), manager.clone(), Some(config));

        let call = uac
            .invite("sip:9196@127.0.0.1:5060", Some("v=0\r\n"))
            .await
            .unwrap();
        let invite1 = wait_for_request(&dispatcher, |r| r.method() == &Method::Invite).await;

        manager
            .receive_response(challenge_response(&invite1, 407))
            .await;

        let final_response = call.await_final().await.unwrap();
        assert_eq!(final_response.code(), 407);
        assert!(sent_requests(&dispatcher)
            .await
            .iter()
            .all(|r| r.headers().get("Proxy-Authorization").is_none()));
    }

    /// Issue #92: the refresh period must be Session-Expires/2 with no
    /// 90 s floor. The old `max(90, se/2)` scheduled the refresh for a
    /// 90 s session (the RFC 4028 minimum) exactly on the expiry
    /// deadline, leaving zero margin.
    #[test]
    fn session_refresh_period_is_half_session_expires() {
        assert_eq!(session_refresh_period(90), Duration::from_secs(45));
        assert_eq!(session_refresh_period(100), Duration::from_secs(50));
        assert_eq!(session_refresh_period(120), Duration::from_secs(60));
        assert_eq!(session_refresh_period(180), Duration::from_secs(90));
        assert_eq!(session_refresh_period(1800), Duration::from_secs(900));
    }

    /// Out-of-range values (below the RFC 4028 minimum of 90, which
    /// `SessionExpires::new` would have rejected) must not spin the
    /// refresh loop with a zero period.
    #[test]
    fn session_refresh_period_floors_at_one_second() {
        assert_eq!(session_refresh_period(0), Duration::from_secs(1));
        assert_eq!(session_refresh_period(1), Duration::from_secs(1));
        assert_eq!(session_refresh_period(2), Duration::from_secs(1));
    }

    // ── issue #95: the refresh CSeq must reach the dialog's owner ──

    /// Confirmed dialog whose peer is an IP literal, so the in-dialog send
    /// resolves without touching DNS.
    fn refresh_dialog() -> Dialog {
        Dialog::unchecked_new(
            DialogId::unchecked_new("refresh-call", "local-tag", "remote-tag"),
            DialogStateType::Confirmed,
            SipUri::parse("sip:siphon@127.0.0.1").unwrap(),
            SipUri::parse("sip:callee@192.0.2.10").unwrap(),
            SipUri::parse("sip:callee@192.0.2.10:5060").unwrap(),
            1,      // local_cseq — the answered INVITE consumed it
            1,      // remote_cseq
            None,   // last_ack_cseq
            vec![], // route_set
            false,  // secure
            Some(Duration::from_secs(90)),
            None, // refresher
            true, // is_uac
        )
    }

    fn refresh_uac(
        dispatcher: Arc<CapturingDispatcher>,
        manager: Arc<TransactionManager>,
    ) -> Arc<IntegratedUAC> {
        Arc::new(
            IntegratedUAC::builder()
                .local_uri("sip:siphon@127.0.0.1")
                .local_addr("127.0.0.1:5080")
                .unwrap()
                .transaction_manager(manager)
                .resolver(Arc::new(SipResolver::from_system().unwrap()))
                .dispatcher(dispatcher)
                .build()
                .unwrap(),
        )
    }

    /// Bounded [`wait_for_request`]. Regressing this fix does not produce a
    /// wrong request — it produces no second request at all, because the
    /// refresh reuses the CSeq it already sent. Without the timeout that is
    /// an infinite wait; with it, the test fails in five seconds.
    async fn await_cseq(dispatcher: &CapturingDispatcher, cseq: &'static str) -> Request {
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_request(dispatcher, move |r| r.headers().get("CSeq") == Some(cseq)),
        )
        .await
        .unwrap_or_else(|_| panic!("no request with CSeq {cseq} reached the wire"))
    }

    /// Mirror the request's dialog identifiers straight back. Unlike
    /// [`ok_response`] this adds no `To` tag: an in-dialog request already
    /// carries one, and a second would land the response outside the dialog.
    fn in_dialog_response(request: &Request, code: u16, reason: &str) -> Response {
        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            headers
                .push(
                    SmolStr::new(name),
                    request.headers().get_smol(name).unwrap().clone(),
                )
                .unwrap();
        }
        Response::new(
            StatusLine::new(code, SmolStr::new(reason)).expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response")
    }

    /// The defect: refreshes advanced a CSeq only the timer task could see,
    /// so the owner's next BYE/re-INVITE/REFER reused a consumed number and
    /// a record-routing peer answered `408`. Two consecutive refreshes must
    /// leave the *shared* dialog at 3, not frozen at the arming value.
    #[tokio::test]
    async fn session_refresh_commits_the_advanced_cseq_to_the_shared_dialog() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = refresh_uac(dispatcher.clone(), manager.clone());
        let shared = Arc::new(RwLock::new(refresh_dialog()));

        for expected_cseq in ["2 INVITE", "3 INVITE"] {
            let task = {
                let (uac, shared) = (uac.clone(), shared.clone());
                tokio::spawn(async move {
                    refresh_shared_session(&uac, &shared, 90, "uac", false).await
                })
            };

            // Match on CSeq rather than send order: the auto-ACK for the
            // first refresh is dispatched between the two iterations.
            let request = await_cseq(&dispatcher, expected_cseq).await;
            assert_eq!(request.method(), &Method::Invite);
            assert!(
                request.headers().get("Session-Expires").is_some(),
                "a refresh must carry Session-Expires"
            );
            manager
                .receive_response(in_dialog_response(&request, 200, "OK"))
                .await;

            let response = task.await.unwrap().expect("refresh succeeded");
            assert_eq!(response.code(), 200);
        }

        assert_eq!(
            shared.read().await.local_cseq(),
            3,
            "both refreshes must be visible to the dialog's owner"
        );
    }

    /// A refresh that fails still consumed its CSeq: `prepare_in_dialog_request`
    /// burns the number when it builds the request, long before the response
    /// decides anything. Dropping the advance would hand the owner a CSeq the
    /// peer has already seen — the very reuse this fix prevents.
    #[tokio::test]
    async fn session_refresh_commits_the_cseq_even_when_the_refresh_fails() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = refresh_uac(dispatcher.clone(), manager.clone());
        let shared = Arc::new(RwLock::new(refresh_dialog()));

        let task = {
            let (uac, shared) = (uac.clone(), shared.clone());
            tokio::spawn(
                async move { refresh_shared_session(&uac, &shared, 90, "uac", false).await },
            )
        };

        let request = await_cseq(&dispatcher, "2 INVITE").await;
        manager
            .receive_response(in_dialog_response(
                &request,
                481,
                "Call/Transaction Does Not Exist",
            ))
            .await;

        let result = task.await.unwrap();
        assert!(result.is_err(), "481 on an in-dialog request is an error");
        let dialog = shared.read().await;
        assert_eq!(
            dialog.local_cseq(),
            2,
            "the consumed CSeq must be committed"
        );
        assert_eq!(
            dialog.state(),
            DialogStateType::Terminated,
            "481 terminates the dialog, and that must reach the owner too"
        );
    }

    /// Issue #99: the CSeq a refresh will consume must be visible to the
    /// dialog's owner *while the refresh is still in flight*, not only once
    /// it has been answered.
    ///
    /// Committing after the response left the shared dialog reading the
    /// pre-request number for a whole round trip, so an owner that resolved
    /// it in that window — to send a teardown BYE — built its request on the
    /// number the refresh was already using. Measured on a downstream owner:
    /// a refresh re-INVITE and a BYE 564 us apart, both `CSeq: 3`.
    #[tokio::test]
    async fn session_refresh_reserves_its_cseq_before_the_request_leaves() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = refresh_uac(dispatcher.clone(), manager.clone());
        let shared = Arc::new(RwLock::new(refresh_dialog()));

        let task = {
            let (uac, shared) = (uac.clone(), shared.clone());
            tokio::spawn(
                async move { refresh_shared_session(&uac, &shared, 90, "uac", false).await },
            )
        };

        // The refresh is on the wire and unanswered — the window in which the
        // owner's own request used to collide with it.
        let request = await_cseq(&dispatcher, "2 INVITE").await;

        let mut owner = shared.read().await.clone();
        assert_eq!(
            owner.local_cseq(),
            2,
            "the in-flight refresh's CSeq must already be published"
        );
        assert_eq!(
            owner.next_local_cseq(),
            3,
            "an owner request racing the refresh must continue the sequence, not reuse it"
        );

        manager
            .receive_response(in_dialog_response(&request, 200, "OK"))
            .await;
        task.await.unwrap().expect("refresh succeeded");
        assert_eq!(
            shared.read().await.local_cseq(),
            2,
            "committing the answered refresh must not advance past the reservation"
        );
    }

    // ── issue #93: a timer that has given up must say so ──

    fn refresh_uac_with_max_failures(
        dispatcher: Arc<CapturingDispatcher>,
        manager: Arc<TransactionManager>,
        max_session_refresh_failures: u32,
    ) -> Arc<IntegratedUAC> {
        Arc::new(
            IntegratedUAC::builder()
                .local_uri("sip:siphon@127.0.0.1")
                .local_addr("127.0.0.1:5080")
                .unwrap()
                .transaction_manager(manager)
                .resolver(Arc::new(SipResolver::from_system().unwrap()))
                .dispatcher(dispatcher)
                .config(UACConfig {
                    max_session_refresh_failures,
                    ..UACConfig::default()
                })
                .build()
                .unwrap(),
        )
    }

    /// Wait for the watch channel to publish a state the predicate accepts.
    /// Bounded: the defect being fixed is a loop that reports *nothing*, so an
    /// unbounded wait would hang rather than fail.
    async fn await_state<F>(rx: &mut watch::Receiver<SessionTimerState>, pred: F)
    where
        F: Fn(&SessionTimerState) -> bool,
    {
        let observed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if pred(&rx.borrow_and_update()) {
                    return;
                }
                if rx.changed().await.is_err() {
                    panic!("session timer state channel closed");
                }
            }
        })
        .await;
        assert!(
            observed.is_ok(),
            "timed out waiting for the expected session timer state; last was {:?}",
            *rx.borrow()
        );
    }

    /// The peer answering `481` means the dialog is gone: no number of
    /// retries brings it back, so the loop must stop on the first one and
    /// name the reason rather than retry until the task is dropped.
    #[tokio::test]
    async fn session_timer_stops_immediately_when_the_peer_says_the_dialog_is_gone() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        // A high threshold: 481 must be terminal regardless of it.
        let uac = refresh_uac_with_max_failures(dispatcher.clone(), manager.clone(), 99);
        let dialog = Arc::new(RwLock::new(refresh_dialog()));
        let state = Arc::new(watch::Sender::new(SessionTimerState::Idle));
        let mut rx = state.subscribe();

        // session_expires 2 → a refresh every second.
        let task = tokio::spawn(run_session_timer(
            uac,
            dialog.clone(),
            state,
            2,
            "uac",
            false,
        ));

        let first = await_cseq(&dispatcher, "2 INVITE").await;
        manager
            .receive_response(in_dialog_response(&first, 200, "OK"))
            .await;
        await_state(&mut rx, |s| matches!(s, SessionTimerState::Healthy { .. })).await;

        let second = await_cseq(&dispatcher, "3 INVITE").await;
        manager
            .receive_response(in_dialog_response(
                &second,
                481,
                "Call/Transaction Does Not Exist",
            ))
            .await;

        await_state(&mut rx, |s| {
            *s == SessionTimerState::Stopped {
                reason: SessionTimerStop::DialogGone,
            }
        })
        .await;

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the loop must exit, not keep ticking")
            .expect("task did not panic");
    }

    /// A non-2xx rejection is a failed refresh even though
    /// `apply_in_dialog_response` returns `Ok` for it. Two of them, with the
    /// threshold set to two, must stop the loop and report `Exhausted` —
    /// previously this retried forever while the owner saw nothing at all.
    #[tokio::test]
    async fn session_timer_gives_up_after_the_configured_consecutive_failures() {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let manager = Arc::new(TransactionManager::new(dispatcher.clone()));
        let uac = refresh_uac_with_max_failures(dispatcher.clone(), manager.clone(), 2);
        let dialog = Arc::new(RwLock::new(refresh_dialog()));
        let state = Arc::new(watch::Sender::new(SessionTimerState::Idle));
        let mut rx = state.subscribe();

        let task = tokio::spawn(run_session_timer(
            uac,
            dialog.clone(),
            state,
            2,
            "uac",
            false,
        ));

        // 503 leaves the dialog alive, so this is the retryable kind.
        let first = await_cseq(&dispatcher, "2 INVITE").await;
        manager
            .receive_response(in_dialog_response(&first, 503, "Service Unavailable"))
            .await;
        await_state(&mut rx, |s| {
            *s == SessionTimerState::Failing { consecutive: 1 }
        })
        .await;

        let second = await_cseq(&dispatcher, "3 INVITE").await;
        manager
            .receive_response(in_dialog_response(&second, 503, "Service Unavailable"))
            .await;

        await_state(&mut rx, |s| {
            *s == SessionTimerState::Stopped {
                reason: SessionTimerStop::Exhausted { consecutive: 2 },
            }
        })
        .await;

        assert_eq!(
            dialog.read().await.state(),
            DialogStateType::Confirmed,
            "giving up must not terminate the dialog — the BYE is the owner's call"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the loop must exit, not keep ticking")
            .expect("task did not panic");
    }

    /// The residual race, bounded: if the owner sent and committed its own
    /// in-dialog request while a refresh was in flight, the refresh's older
    /// dialog must not overwrite it and walk the CSeq backwards.
    #[tokio::test]
    async fn session_refresh_commit_never_regresses_the_owners_cseq() {
        let shared = Arc::new(RwLock::new(refresh_dialog()));

        // A refresh resolves the dialog and consumes CSeq 2...
        let mut in_flight = shared.read().await.clone();
        in_flight.next_local_cseq();

        // ...while the owner sends a hold re-INVITE and a REFER of its own.
        {
            let mut owner = shared.write().await;
            owner.next_local_cseq();
            owner.next_local_cseq();
        }

        commit_advanced_dialog(&shared, in_flight).await;

        assert_eq!(
            shared.read().await.local_cseq(),
            3,
            "the owner's newer CSeq must survive the late commit"
        );
    }
}

/// Handle returned from INVITE/re-INVITE with CANCEL capability.
impl CallHandle {
    /// Sends a CANCEL request to cancel the pending INVITE transaction.
    ///
    /// # Returns
    /// Result indicating if CANCEL was sent successfully
    ///
    /// # RFC 3261 §9.1 CANCEL Behavior
    /// - CANCEL can only be sent for pending INVITE (not yet received final response)
    /// - CANCEL uses same Call-ID, From tag, To tag, but new branch
    /// - If 200 OK arrives before CANCEL, must still send ACK and then BYE
    ///
    /// # Example
    /// ```ignore
    /// let mut call = uac.invite("sip:bob@example.com", Some(sdp)).await?;
    ///
    /// // Wait for ringing
    /// if let Some(response) = call.await_provisional().await {
    ///     if response.code() == 180 {
    ///         println!("Ringing...");
    ///     }
    /// }
    ///
    /// // User cancels the call
    /// call.cancel().await?;
    /// ```
    pub async fn cancel(&self) -> Result<Response> {
        use sip_core::{Method, RequestLine};

        info!(
            "Sending CANCEL for transaction {}",
            self.transaction_key.branch()
        );

        // Create CANCEL request per RFC 3261 §9.1
        // CANCEL uses same Call-ID, From, To, CSeq number as INVITE
        // But uses new branch parameter in Via

        let mut cancel_headers = sip_core::Headers::new();

        // Snapshot the live attempt's INVITE: after an auth retry the
        // original transaction is already complete, so the CANCEL must
        // match the current attempt's Via branch and CSeq.
        let invite_request = self.invite_request.read().await.clone();

        // Copy essential headers from INVITE
        for header in invite_request.headers().iter() {
            match header.name() {
                "Via" => {
                    // RFC 3261 §9.1: CANCEL MUST have the same Via branch as the INVITE
                    // "A CANCEL constructed by a client MUST have only a single Via header
                    // field value matching the top Via value in the request being cancelled"
                    cancel_headers
                        .push(header.name_smol().clone(), header.value_smol().clone())
                        .unwrap();
                }
                "From" | "To" | "Call-ID" => {
                    // Copy unchanged
                    cancel_headers
                        .push(header.name_smol().clone(), header.value_smol().clone())
                        .unwrap();
                }
                "CSeq" => {
                    // Same number, but CANCEL method
                    if let Some((num, _)) = header.value().split_once(' ') {
                        cancel_headers
                            .push(
                                SmolStr::new("CSeq"),
                                SmolStr::new(format!("{} CANCEL", num)),
                            )
                            .unwrap();
                    }
                }
                "Route" => {
                    // Copy Route headers
                    cancel_headers
                        .push(header.name_smol().clone(), header.value_smol().clone())
                        .unwrap();
                }
                _ => {
                    // Skip other headers
                }
            }
        }

        // Add Max-Forwards
        cancel_headers
            .push(SmolStr::new("Max-Forwards"), SmolStr::new("70"))
            .unwrap();

        // Add Content-Length
        cancel_headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();

        // Create CANCEL request
        let cancel_request = Request::new(
            RequestLine::new(Method::Cancel, invite_request.uri().clone()),
            cancel_headers,
            Bytes::new(),
        )
        .expect("valid CANCEL request");

        // Debug: log the CANCEL request details
        debug!(
            "CANCEL request - Request-URI: {}, Call-ID: {:?}, CSeq: {:?}",
            cancel_request.uri(),
            cancel_request.headers().get("Call-ID"),
            cancel_request.headers().get("CSeq")
        );

        // Send CANCEL as a new non-INVITE transaction
        let (final_tx, final_rx) = oneshot::channel();
        let (term_tx, term_rx) = oneshot::channel();

        let tu = Arc::new(SimpleTransactionUser {
            final_tx: Mutex::new(Some(final_tx)),
            term_tx: Mutex::new(Some(term_tx)),
        });

        let key = self
            .transaction_manager
            .start_client_transaction(cancel_request, (*self.transport_ctx).clone(), tu)
            .await?;

        info!("Started CANCEL transaction {}", key.branch());

        // Wait for response to CANCEL
        tokio::select! {
            Ok(response) = final_rx => Ok(response),
            Ok(reason) = term_rx => Err(anyhow!("CANCEL transaction terminated: {}", reason)),
            else => Err(anyhow!("CANCEL response channels closed")),
        }
    }
}

/// Transaction user for INVITE requests - handles ACK, PRACK, dialog creation, forking.
struct InviteTransactionUser {
    prov_tx: mpsc::Sender<Response>,
    final_tx: Mutex<Option<oneshot::Sender<Response>>>,
    term_tx: Mutex<Option<oneshot::Sender<String>>>,
    #[allow(dead_code)]
    dialog_manager: Arc<DialogManager>,
    helper: Arc<Mutex<UserAgentClient>>,
    request: Request,
    config: UACConfig,
    ctx: TransportContext,
    auto_retry_auth: bool,
    /// Which auth attempt this transaction represents (0 = original
    /// INVITE, incremented per authenticated retry).
    auth_attempt: u32,
    /// The live attempt's request, shared with the CallHandle so CANCEL
    /// targets the current transaction after an auth retry.
    live_request: Arc<RwLock<Arc<Request>>>,
    transaction_manager: Arc<TransactionManager>,
    dispatcher: Arc<dyn TransportDispatcher>,
    /// Track early dialogs for forking support (shared with CallHandle)
    early_dialogs: Arc<Mutex<std::collections::HashMap<SmolStr, Dialog>>>,
    /// Dialog reference (shared with CallHandle) - updated when 200 OK arrives
    dialog: Arc<RwLock<Dialog>>,
    local_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
}

impl InviteTransactionUser {
    /// Starts an authenticated re-INVITE after a 401/407 challenge
    /// (issue #83).
    ///
    /// The transaction layer has already ACK'd the challenge, so the
    /// authenticated request — same Call-ID and From tag, CSeq+1, fresh
    /// branch, original body, built by `create_authenticated_request_with`
    /// — goes out as a new client transaction. Its transaction user
    /// inherits this attempt's response channels and shared dialog state,
    /// so the caller's `CallHandle` transparently observes the retry.
    async fn retry_invite_with_auth(&self, challenge: &Response) -> Result<()> {
        let realm = extract_realm(challenge);
        let creds = match (&self.config.credential_provider, realm.as_deref()) {
            (Some(provider), Some(realm)) => provider.credentials(realm).await,
            _ => None,
        };

        let mut helper = self.helper.lock().await;
        let auth_request =
            helper.create_authenticated_request_with(&self.request, challenge, creds)?;
        drop(helper);

        // Hand this attempt's channels to the retry: whatever it concludes
        // with is the final the application sees.
        let final_tx = self.final_tx.lock().await.take();
        let term_tx = self.term_tx.lock().await.take();

        let tu = Arc::new(InviteTransactionUser {
            prov_tx: self.prov_tx.clone(),
            final_tx: Mutex::new(final_tx),
            term_tx: Mutex::new(term_tx),
            dialog_manager: self.dialog_manager.clone(),
            helper: self.helper.clone(),
            request: auth_request.clone(),
            config: self.config.clone(),
            ctx: self.ctx.clone(),
            auto_retry_auth: self.auto_retry_auth,
            auth_attempt: self.auth_attempt + 1,
            live_request: self.live_request.clone(),
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.dispatcher.clone(),
            early_dialogs: self.early_dialogs.clone(),
            dialog: self.dialog.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        match self
            .transaction_manager
            .start_client_transaction(auth_request.clone(), self.ctx.clone(), tu.clone())
            .await
        {
            Ok(key) => {
                // CANCEL must target the live attempt's Via branch.
                *self.live_request.write().await = Arc::new(auth_request);
                info!(
                    "Started authenticated INVITE transaction {} (attempt {})",
                    key.branch(),
                    self.auth_attempt + 1
                );
                Ok(())
            }
            Err(e) => {
                // The retry never launched: reclaim the channels so the
                // challenge is surfaced as this attempt's final.
                *self.final_tx.lock().await = tu.final_tx.lock().await.take();
                *self.term_tx.lock().await = tu.term_tx.lock().await.take();
                Err(e)
            }
        }
    }
}

#[async_trait]
impl ClientTransactionUser for InviteTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, response: &Response) {
        info!("Received provisional response: {}", response.code());

        // Create or update dialog from provisional (if it has To-tag)
        // RFC 3261 §13.2.2.1: Provisional responses with To-tags create early dialogs
        if response.code() > 100 {
            let helper = self.helper.lock().await;
            if let Some(dialog) = helper.process_invite_response(&self.request, response) {
                let to_tag = SmolStr::new(dialog.id().remote_tag());

                // Track early dialog for forking support
                let mut early_dialogs = self.early_dialogs.lock().await;

                if early_dialogs.contains_key(&to_tag) {
                    // Update existing early dialog (no bounds check needed)
                    debug!(
                        "Updated existing early dialog from {}: to-tag={}",
                        response.code(),
                        to_tag
                    );
                    early_dialogs.insert(to_tag, dialog);
                } else {
                    // New early dialog - enforce forking limit
                    if early_dialogs.len() >= crate::MAX_EARLY_DIALOGS {
                        warn!(
                            "Max early dialogs limit reached ({}), ignoring new early dialog: to-tag={}",
                            crate::MAX_EARLY_DIALOGS,
                            to_tag
                        );
                    } else {
                        debug!(
                            "Created new early dialog from {}: to-tag={} (forking detected: {} endpoints)",
                            response.code(),
                            to_tag,
                            early_dialogs.len() + 1
                        );
                        early_dialogs.insert(to_tag, dialog);
                    }
                }
            }
        }

        // Forward to application
        let _ = self.prov_tx.send(response.clone()).await;
    }

    async fn on_final(&self, _key: &TransactionKey, response: &Response) {
        info!("Received final response: {}", response.code());

        // 401/407: start an authenticated retry instead of surfacing the
        // challenge (the transaction layer has already ACK'd this final).
        // Mirrors the non-INVITE retry semantics: bounded by
        // `max_auth_retries`, with the last challenge forwarded when the
        // budget is exhausted or no retry can be built (issue #83).
        if (response.code() == 401 || response.code() == 407) && self.auto_retry_auth {
            if self.auth_attempt < self.config.max_auth_retries {
                match self.retry_invite_with_auth(response).await {
                    Ok(()) => return,
                    Err(e) => warn!(
                        code = response.code(),
                        "INVITE auth retry not started ({}); surfacing challenge to caller", e
                    ),
                }
            } else {
                warn!(
                    code = response.code(),
                    attempts = self.auth_attempt,
                    max = self.config.max_auth_retries,
                    "auth retry limit reached; returning last challenge to caller"
                );
            }
        }

        // Create or confirm dialog from 2xx and update CallHandle's dialog
        if response.code() >= 200 && response.code() < 300 {
            let helper = self.helper.lock().await;
            if let Some(confirmed_dialog) = helper.process_invite_response(&self.request, response)
            {
                info!(
                    "Confirmed dialog from {}: {} (to-tag={})",
                    response.code(),
                    confirmed_dialog.id().call_id(),
                    confirmed_dialog.id().remote_tag()
                );

                // Update the shared dialog (fixes the "pending" tag issue)
                *self.dialog.write().await = confirmed_dialog;
            }
        }

        // Forward to application
        let mut tx = self.final_tx.lock().await;
        if let Some(tx) = tx.take() {
            let _ = tx.send(response.clone());
        }
    }

    async fn on_terminated(&self, _key: &TransactionKey, reason: &str) {
        warn!("INVITE transaction terminated: {}", reason);

        let mut tx = self.term_tx.lock().await;
        if let Some(tx) = tx.take() {
            let _ = tx.send(reason.to_string());
        }
    }

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        response: Response,
        ctx: &TransportContext,
        is_2xx: bool,
    ) {
        info!(
            "Sending ACK for {} response (is_2xx={})",
            response.code(),
            is_2xx
        );

        let original_via = self.request.headers().get("Via").map(|via| via.to_string());

        let helper = self.helper.lock().await;
        let dialog = if is_2xx {
            helper.process_invite_response(&self.request, &response)
        } else {
            None
        };

        if is_2xx && dialog.is_none() {
            error!("Failed to create dialog for 2xx ACK");
            return;
        }

        // Determine if this is late offer (200 OK has SDP, INVITE didn't)
        let invite_has_sdp = !self.request.body().is_empty();
        let response_has_sdp = !response.body().is_empty();
        let late_offer = is_2xx && !invite_has_sdp && response_has_sdp;

        // For late offer, generate SDP answer using configured generator
        let sdp_body = if late_offer {
            if let Some(dialog) = dialog.as_ref() {
                if let Some(generator) = &self.config.sdp_answer_generator {
                    debug!("Late offer detected - generating SDP answer via RFC 3264 negotiation");

                    // Extract and parse SDP offer from response body
                    match std::str::from_utf8(response.body()) {
                        Ok(sdp_offer_str) => {
                            // Parse SDP offer
                            match SessionDescription::parse(sdp_offer_str) {
                                Ok(sdp_offer) => {
                                    // Generate SDP answer using RFC 3264 negotiation
                                    match generator.generate_answer(&sdp_offer, dialog).await {
                                        Ok(sdp_answer) => {
                                            // Serialize SDP answer
                                            let sdp_answer_str = sdp_answer.to_string();
                                            info!(
                                                "Generated SDP answer for late offer ({} bytes)",
                                                sdp_answer_str.len()
                                            );
                                            Some(sdp_answer_str)
                                        }
                                        Err(e) => {
                                            error!("Failed to generate SDP answer: {}", e);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse SDP offer: {}", e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode SDP offer as UTF-8: {}", e);
                            None
                        }
                    }
                } else if let Some(builder) = &self.config.sdp_profile_builder {
                    debug!("Late offer detected - generating SDP answer via profile negotiation");
                    if let Ok(sdp_offer) = SessionDescription::parse(
                        std::str::from_utf8(response.body()).unwrap_or_default(),
                    ) {
                        let addr = self.public_addr.unwrap_or(self.local_addr);
                        let sdp_answer = profiles::negotiate_answer(
                            &sdp_offer,
                            builder,
                            &self.config.user_agent,
                            &addr.to_string(),
                            self.config.local_audio_port,
                            Some(self.config.local_video_port),
                        );
                        let sdp_answer_str = sdp_answer.to_string();
                        Some(sdp_answer_str)
                    } else {
                        None
                    }
                } else {
                    warn!("Late offer scenario detected but no SDP answer generator configured");
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut ack = helper.create_ack(&self.request, &response, sdp_body.as_deref());
        drop(helper);

        if is_2xx {
            if let Some(dialog) = dialog.as_ref() {
                apply_route_set_to_request(dialog, &mut ack);
            }
        } else {
            ack.headers_mut().remove("Route");
            for route in self.request.headers().get_all_smol("Route") {
                ack.headers_mut()
                    .push(SmolStr::new("Route"), route.clone())
                    .unwrap();
            }
        }

        let via_value = if let Some(via) = original_via.as_deref() {
            if is_2xx {
                crate::replace_via_branch(via, &crate::generate_branch())
            } else {
                via.to_string()
            }
        } else if let Some(via) = ack.headers().get("Via") {
            if is_2xx {
                crate::replace_via_branch(via, &crate::generate_branch())
            } else {
                via.to_string()
            }
        } else {
            let via_transport = match ctx.transport() {
                sip_transaction::TransportKind::Udp => "UDP",
                sip_transaction::TransportKind::Tcp => "TCP",
                sip_transaction::TransportKind::Tls => "TLS",
                sip_transaction::TransportKind::Ws => "WS",
                sip_transaction::TransportKind::Wss => "WSS",
                sip_transaction::TransportKind::Sctp => "SCTP",
                sip_transaction::TransportKind::TlsSctp => "TLS-SCTP",
            };
            format!(
                "SIP/2.0/{} {};branch={}",
                via_transport,
                self.local_addr,
                crate::generate_branch()
            )
        };

        ack.headers_mut().remove("Via");
        ack.headers_mut()
            .push(SmolStr::new("Via"), SmolStr::new(via_value))
            .unwrap();

        // Serialize ACK
        let ack_bytes = serialize_request(&ack);

        // Send ACK directly (ACK for 2xx doesn't go through transaction layer)
        if let Some(stream) = &ctx.stream() {
            if let Err(e) = stream.send(ack_bytes.clone()).await {
                // The connection died between the 2xx and the ACK; retry
                // through the dispatcher's pool with the stream cleared
                // (issue #73).
                warn!(
                    "Failed to send ACK via stream ({}), retrying via dispatcher",
                    e
                );
                let fallback = ctx.clone().with_stream(None);
                if let Err(e) = self.dispatcher.dispatch(&fallback, ack_bytes).await {
                    error!("Failed to send ACK via dispatcher fallback: {}", e);
                }
            }
        } else if let Err(e) = self.dispatcher.dispatch(ctx, ack_bytes).await {
            error!("Failed to send ACK via dispatcher: {}", e);
        } else {
            debug!("ACK sent successfully");
        }
    }

    async fn send_prack(&self, _key: &TransactionKey, response: Response, ctx: &TransportContext) {
        info!("Sending PRACK for reliable provisional {}", response.code());

        // Find dialog for this response
        let helper = self.helper.lock().await;
        let dialog = helper.process_invite_response(&self.request, &response);

        if let Some(dialog) = dialog {
            // Create PRACK
            match helper.create_prack(&self.request, &response, &dialog) {
                Ok(prack) => {
                    drop(helper);

                    // PRACK is a non-INVITE client transaction (RFC 3262)
                    let tu = Arc::new(PrackTransactionUser);
                    match self
                        .transaction_manager
                        .start_client_transaction(prack.clone(), ctx.clone(), tu)
                        .await
                    {
                        Ok(key) => {
                            debug!("Started PRACK transaction {}", key.branch());
                        }
                        Err(e) => {
                            error!("Failed to start PRACK transaction: {}", e);
                        }
                    }
                }
                Err(e) => {
                    drop(helper);
                    error!("Failed to create PRACK: {}", e);
                }
            }
        } else {
            error!("Failed to create dialog for PRACK");
        }
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {
        error!("Transport error for INVITE transaction");

        let mut tx = self.term_tx.lock().await;
        if let Some(tx) = tx.take() {
            let _ = tx.send("transport error".to_string());
        }
    }
}

/// Lightweight transaction user for PRACK transactions (fire-and-forget).
struct PrackTransactionUser;

#[async_trait]
impl ClientTransactionUser for PrackTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, response: &Response) {
        debug!("PRACK provisional: {}", response.code());
    }

    async fn on_final(&self, _key: &TransactionKey, response: &Response) {
        info!("PRACK final response: {}", response.code());
    }

    async fn on_terminated(&self, _key: &TransactionKey, reason: &str) {
        warn!("PRACK transaction terminated: {}", reason);
    }

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
        _is_2xx: bool,
    ) {
        // No ACK for PRACK final responses
    }

    async fn send_prack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
    ) {
        // Nested PRACK not applicable
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {
        warn!("PRACK transport error");
    }
}

/// Simple transaction user for non-INVITE requests.
struct SimpleTransactionUser {
    final_tx: Mutex<Option<oneshot::Sender<Response>>>,
    term_tx: Mutex<Option<oneshot::Sender<String>>>,
}

#[async_trait]
impl ClientTransactionUser for SimpleTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, response: &Response) {
        debug!("Received provisional response: {}", response.code());
    }

    async fn on_final(&self, _key: &TransactionKey, response: &Response) {
        info!("Received final response: {}", response.code());

        let mut tx = self.final_tx.lock().await;
        if let Some(tx) = tx.take() {
            let _ = tx.send(response.clone());
        }
    }

    async fn on_terminated(&self, _key: &TransactionKey, reason: &str) {
        warn!("Transaction terminated: {}", reason);

        let mut tx = self.term_tx.lock().await;
        if let Some(tx) = tx.take() {
            let _ = tx.send(reason.to_string());
        }
    }

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
        _is_2xx: bool,
    ) {
        // Not used for non-INVITE
    }

    async fn send_prack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
    ) {
        // Not used for non-INVITE
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {
        error!("Transport error");

        let mut tx = self.term_tx.lock().await;
        if let Some(tx) = tx.take() {
            let _ = tx.send("transport error".to_string());
        }
    }
}

/// Builder for IntegratedUAC.
pub struct IntegratedUACBuilder {
    local_uri: Option<SipUri>,
    contact_uri: Option<SipUri>,
    local_addr: Option<SocketAddr>,
    public_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    via_advertised: Option<SocketAddr>,
    #[allow(dead_code)]
    contact_advertised: Option<SocketAddr>,
    transaction_manager: Option<Arc<TransactionManager>>,
    resolver: Option<Arc<SipResolver>>,
    dispatcher: Option<Arc<dyn TransportDispatcher>>,
    dialog_manager: Option<Arc<DialogManager>>,
    credentials: Option<(String, String)>,
    display_name: Option<String>,
    config: UACConfig,
}

impl IntegratedUACBuilder {
    fn new() -> Self {
        Self {
            local_uri: None,
            contact_uri: None,
            local_addr: None,
            public_addr: None,
            via_advertised: None,
            contact_advertised: None,
            transaction_manager: None,
            resolver: None,
            dispatcher: None,
            dialog_manager: None,
            credentials: None,
            display_name: None,
            config: UACConfig::default(),
        }
    }

    /// Sets the local SIP URI (used in From header).
    pub fn local_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.local_uri = SipUri::parse(uri.as_ref()).ok();
        self
    }

    /// Sets the contact URI (used in Contact header).
    pub fn contact_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.contact_uri = SipUri::parse(uri.as_ref()).ok();
        self
    }

    /// Enables RFC 5626 outbound support (adds ;ob and GRUU formation).
    pub fn enable_outbound(mut self, instance_id: impl AsRef<str>) -> Self {
        self.config.enable_outbound = true;
        self.config.instance_id = Some(instance_id.as_ref().to_string());
        self
    }

    /// Sets a salt used for flow token/opaque GRUU generation.
    pub fn flow_token_salt(mut self, salt: impl AsRef<str>) -> Self {
        self.config.flow_token_salt = Some(salt.as_ref().to_string());
        self
    }

    /// Sets reg-id used for outbound flows (default 1).
    pub fn outbound_reg_id(mut self, reg_id: u32) -> Self {
        self.config.outbound_reg_id = reg_id.max(1);
        self
    }

    /// Overrides the WS/WSS target URI (e.g., ws://edge.example.com/sip).
    pub fn ws_target_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.config.ws_target_uri = Some(uri.as_ref().to_string());
        self
    }

    /// Sets a WS path suffix to append when building ws://host/path from DNS targets.
    pub fn ws_path(mut self, path: impl AsRef<str>) -> Self {
        self.config.ws_path = Some(path.as_ref().to_string());
        self
    }

    /// Sets the TLS certificate name (SNI + verification) used when
    /// dialing an IP-literal target — e.g. the trunk hostname
    /// (`example.pstn.twilio.com`) for route-set hops that name the
    /// carrier edge by IP (issue #76).
    pub fn tls_server_name(mut self, name: impl AsRef<str>) -> Self {
        self.config.tls_server_name = Some(name.as_ref().to_string());
        self
    }

    /// Sets the local transport address for Via/Contact auto-filling.
    pub fn local_addr(mut self, addr: impl AsRef<str>) -> Result<Self> {
        self.local_addr = Some(
            addr.as_ref()
                .parse()
                .map_err(|e| anyhow!("Invalid local address: {}", e))?,
        );
        Ok(self)
    }

    /// Sets the public address for NAT scenarios (overrides local_addr in Contact).
    pub fn public_addr(mut self, addr: impl AsRef<str>) -> Result<Self> {
        self.public_addr = Some(
            addr.as_ref()
                .parse()
                .map_err(|e| anyhow!("Invalid public address: {}", e))?,
        );
        Ok(self)
    }

    /// Sets the Via advertised address (host:port), used only for Via.
    pub fn via_advertised_addr(mut self, addr: impl AsRef<str>) -> Result<Self> {
        self.config.via_advertised = Some(
            addr.as_ref()
                .parse()
                .map_err(|e| anyhow!("Invalid Via advertised address: {}", e))?,
        );
        Ok(self)
    }

    /// Sets the Contact advertised address (host:port), used only for Contact.
    pub fn contact_advertised_addr(mut self, addr: impl AsRef<str>) -> Result<Self> {
        self.config.contact_advertised = Some(
            addr.as_ref()
                .parse()
                .map_err(|e| anyhow!("Invalid Contact advertised address: {}", e))?,
        );
        Ok(self)
    }

    /// Sets a dynamic public address resolver (e.g., STUN).
    pub fn public_addr_resolver(mut self, resolver: Arc<dyn PublicAddrResolver>) -> Self {
        self.config.public_addr_resolver = Some(resolver);
        self
    }

    /// Sets the transaction manager.
    pub fn transaction_manager(mut self, mgr: Arc<TransactionManager>) -> Self {
        self.transaction_manager = Some(mgr);
        self
    }

    /// Sets the DNS resolver.
    pub fn resolver(mut self, resolver: Arc<SipResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Sets the transport dispatcher.
    pub fn dispatcher(mut self, dispatcher: Arc<dyn TransportDispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Shares a [`DialogManager`] with the rest of the stack — pass
    /// [`IntegratedUAS::dialog_manager`] here when the same endpoint both
    /// originates and receives calls.
    ///
    /// Without this, every `IntegratedUAC` owns a private dialog store,
    /// and dialogs it creates are invisible to UAS dispatch. Dispatch
    /// resolves an inbound in-dialog request (BYE, re-INVITE, INFO,
    /// UPDATE) through *its* manager's `find_by_request`, so a peer
    /// hanging up an outbound call gets `481 Call/Transaction Does Not
    /// Exist` and the call never tears down. `IntegratedUAS`'s own
    /// `dialog_manager()` doc already advises sharing the store; this is
    /// the UAC-side input that makes it actionable.
    ///
    /// Optional: when unset the UAC keeps its private manager, so
    /// existing single-role embedders are unaffected.
    ///
    /// A daemon running both roles passes the UAS's store — in practice
    /// `uas.dialog_manager()` — to every UAC it constructs:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use sip_dialog::DialogManager;
    /// # use sip_uac::integrated::IntegratedUAC;
    /// # fn example(shared: Arc<DialogManager>) -> anyhow::Result<()> {
    /// let uac = IntegratedUAC::builder()
    ///     .local_uri("sip:agent@example.com")
    ///     .dialog_manager(shared) // e.g. uas.dialog_manager()
    ///     // … other required setters …
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dialog_manager(mut self, mgr: Arc<DialogManager>) -> Self {
        self.dialog_manager = Some(mgr);
        self
    }

    /// Sets authentication credentials (username, password).
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.credentials = Some((username.into(), password.into()));
        self
    }

    /// Sets a credential provider (per realm).
    pub fn credential_provider(mut self, provider: Arc<dyn CredentialProvider>) -> Self {
        self.config.credential_provider = Some(provider);
        self
    }

    /// Sets the display name for From headers.
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets the SDP answer generator for late offer scenarios.
    ///
    /// When set, this generator will be invoked to create an SDP answer
    /// when receiving a 200 OK with SDP offer after sending an INVITE
    /// without SDP (late offer flow per RFC 3264).
    ///
    /// # Example
    /// ```ignore
    /// use sip_uac::integrated::{IntegratedUAC, SdpAnswerGenerator};
    /// use std::sync::Arc;
    ///
    /// struct MySdpGenerator;
    ///
    /// #[async_trait::async_trait]
    /// impl SdpAnswerGenerator for MySdpGenerator {
    ///     async fn generate_answer(
    ///         &self,
    ///         offer: &sip_sdp::SessionDescription,
    ///         dialog: &sip_dialog::Dialog,
    ///     ) -> anyhow::Result<sip_sdp::SessionDescription> {
    ///         // Parse offer and generate answer...
    ///         println!("Got offer for dialog {:?}", dialog.id);
    ///         Ok(offer.clone())
    ///     }
    /// }
    ///
    /// let uac = IntegratedUAC::builder()
    ///     .sdp_answer_generator(Arc::new(MySdpGenerator))
    ///     // ... other config
    ///     .build()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn sdp_answer_generator(mut self, generator: Arc<dyn SdpAnswerGenerator>) -> Self {
        self.config.sdp_answer_generator = Some(generator);
        self
    }

    /// Sets the SDP profile for generating offers.
    ///
    /// When set, the UAC can generate SDP offers automatically using
    /// pre-configured profiles (AudioOnly, AudioVideo).
    ///
    /// # Example
    /// ```no_run
    /// use sip_uac::integrated::IntegratedUAC;
    /// use sip_sdp::profiles::SdpProfile;
    ///
    /// let uac = IntegratedUAC::builder()
    ///     .sdp_profile(SdpProfile::AudioOnly)
    ///     .local_audio_port(8000)
    ///     // ... other config
    ///     .build()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn sdp_profile(mut self, profile: profiles::SdpProfile) -> Self {
        self.config.sdp_profile = Some(profile);
        self
    }

    /// Sets a custom SDP media profile builder for richer offers/answers.
    pub fn sdp_profile_builder(mut self, builder: profiles::MediaProfileBuilder) -> Self {
        self.config.sdp_profile_builder = Some(builder);
        self
    }

    /// Sets the local RTP audio port for SDP (default: 8000).
    pub fn local_audio_port(mut self, port: u16) -> Self {
        self.config.local_audio_port = port;
        self
    }

    /// Sets the local RTP video port for SDP (default: 8002).
    pub fn local_video_port(mut self, port: u16) -> Self {
        self.config.local_video_port = port;
        self
    }

    /// Sets the UAC configuration.
    pub fn config(mut self, config: UACConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the IntegratedUAC.
    pub fn build(self) -> Result<IntegratedUAC> {
        let local_uri = self
            .local_uri
            .ok_or_else(|| anyhow!("local_uri is required"))?;
        let local_addr = self
            .local_addr
            .ok_or_else(|| anyhow!("local_addr is required"))?;
        let transaction_manager = self
            .transaction_manager
            .ok_or_else(|| anyhow!("transaction_manager is required"))?;
        let resolver = self
            .resolver
            .ok_or_else(|| anyhow!("resolver is required"))?;
        let dispatcher = self
            .dispatcher
            .ok_or_else(|| anyhow!("dispatcher is required"))?;

        // Create embedded helper
        let contact_uri = self.contact_uri.unwrap_or_else(|| {
            // Default contact: sip:user@advertised_contact
            let user = local_uri.user().unwrap_or("user");
            let contact_host = self
                .config
                .contact_advertised
                .or(self.public_addr)
                .unwrap_or(local_addr);
            SipUri::parse(&format!("sip:{}@{}", user, contact_host)).unwrap()
        });

        let mut helper = UserAgentClient::new(local_uri, contact_uri);

        if let Some((username, password)) = self.credentials {
            helper = helper.with_credentials(&username, &password);
        }

        if let Some(display_name) = self.display_name {
            helper = helper.with_display_name(display_name)?;
        }

        // Point the helper at the shared store *before* cloning the
        // handle below, so both halves of the UAC agree.
        //
        // Redirecting only the `IntegratedUAC` handle would not fix
        // anything: the confirmed dialog for an outbound call is
        // registered by `UserAgentClient::process_invite_response`, which
        // inserts into the *helper's* manager, and that runs on every
        // INVITE response path here. Leave the helper on its constructor
        // default and the dialog still lands somewhere UAS dispatch can't
        // see — the 481 stays exactly as it was.
        if let Some(shared) = self.dialog_manager {
            helper.dialog_manager = shared;
        }

        let dialog_manager = helper.dialog_manager.clone();
        let subscription_manager = helper.subscription_manager.clone();

        Ok(IntegratedUAC {
            helper: Arc::new(Mutex::new(helper)),
            transaction_manager,
            resolver,
            transport_dispatcher: dispatcher,
            local_addr,
            public_addr: self.public_addr,
            config: self.config,
            dialog_manager,
            subscription_manager,
        })
    }
}
