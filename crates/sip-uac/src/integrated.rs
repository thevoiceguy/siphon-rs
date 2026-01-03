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
use sip_core::{Method, Request, RequestLine, Response, SipUri};
use sip_dialog::{Dialog, DialogManager, Subscription, SubscriptionManager};
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
use tokio::sync::{mpsc, oneshot, Mutex};
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
}

impl Default for UACConfig {
    fn default() -> Self {
        Self {
            auto_retry_auth: true,
            max_auth_retries: 2,
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

/// Handle for an outgoing call with dialog state and response channels.
pub struct CallHandle {
    /// The dialog for this call (updated to winning dialog when final response arrives)
    pub dialog: Dialog,

    /// Transaction key for this call
    transaction_key: TransactionKey,

    /// Channel to receive provisional responses (180, 183, etc)
    provisional_rx: Arc<Mutex<mpsc::Receiver<Response>>>,

    /// Channel to receive the final response (200, 486, etc)
    final_rx: Arc<Mutex<Option<oneshot::Receiver<Response>>>>,

    /// Termination reason if transaction failed
    termination_rx: Arc<Mutex<Option<oneshot::Receiver<String>>>>,

    /// Original INVITE request (needed for CANCEL generation)
    invite_request: Arc<Request>,

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
}

impl CallHandle {
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
        }
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

    /// Starts session timer refreshes (RFC 4028) at roughly half the Session-Expires interval.
    pub async fn start_session_timer(
        &self,
        dialog: Dialog,
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

        let handle = tokio::spawn(async move {
            let mut dialog = dialog;
            // Per RFC 4028, refresh at Session-Expires/2
            let refresh_interval = std::cmp::max(90, (session_expires / 2) as i32) as u64;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(refresh_interval));
            loop {
                ticker.tick().await;
                if let Err(e) = uac
                    .refresh_session(&mut dialog, session_expires, refresher, use_update, None)
                    .await
                {
                    warn!("Session refresh failed: {}", e);
                }
            }
        });

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
        let resolved_public = self.resolve_public_addr().await;
        if self.config.auto_via_filling {
            self.fill_via_header(request, transport, resolved_public)
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
            let new_via = format!(
                "SIP/2.0/{} {};branch={};rport",
                via_transport, via_addr, branch
            );
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
        match target {
            RequestTarget::Resolved(dns) => Ok(dns.clone()),
            RequestTarget::Uri(uri) if !self.config.auto_dns_resolution => {
                // No auto resolution - create simple target
                let port = uri.port().unwrap_or(5060);
                Ok(sip_dns::DnsTarget::unchecked_new(
                    uri.host(),
                    port,
                    sip_dns::Transport::Udp,
                ))
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
                    .ok_or_else(|| anyhow!("No DNS targets found for {}", uri.as_str()))
            }
        }
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
                    return self.retry_with_auth(request, response, dns_target).await;
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
    async fn retry_with_auth(
        &self,
        original_request: Request,
        challenge: Response,
        dns_target: DnsTarget,
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

        // Send authenticated request (non-recursive - don't retry again)
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
            "Started authenticated client transaction {} for {:?}",
            key.branch(),
            auth_request.method()
        );

        tokio::select! {
            Ok(response) = final_rx => Ok(response),
            Ok(reason) = term_rx => Err(anyhow!("Authenticated transaction terminated: {}", reason)),
            else => Err(anyhow!("Authenticated response channels closed")),
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

        // Parse host to SocketAddr, falling back to OS DNS resolution for SRV hostnames
        let addr_str = format!("{}:{}", dns_target.host(), dns_target.port());
        let peer = match addr_str.parse() {
            Ok(addr) => addr,
            Err(_) => {
                // SRV targets are hostnames; resolve to first A/AAAA
                let mut addrs = tokio::net::lookup_host(&addr_str)
                    .await
                    .map_err(|e| anyhow!("DNS lookup failed for {}: {}", addr_str, e))?;
                addrs
                    .next()
                    .ok_or_else(|| anyhow!("No A/AAAA results for {}", addr_str))?
            }
        };

        // Use hostname (from DNS target) for SNI when TLS/WSS is selected
        let server_name = if matches!(transport, TransportKind::Tls | TransportKind::Wss) {
            Some(dns_target.host().to_string())
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
                    scheme, dns_target.host(), dns_target.port(), normalized_path
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
        let target = target.into();

        // Generate request using helper
        let helper = self.helper.lock().await;
        let target_uri = self.extract_uri(&target)?;
        let mut request = helper.create_invite(&target_uri, sdp_body);
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

        // Create INVITE transaction user
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
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
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

        // Create placeholder dialog (will be updated when 1xx/2xx arrives)
        let helper = self.helper.lock().await;
        let dialog_id = sip_dialog::DialogId::unchecked_new(
            request.headers().get_smol("Call-ID").unwrap().clone(),
            helper.local_tag.clone(),
            SmolStr::new("pending"),
        );
        let placeholder_dialog = Dialog::unchecked_new(
            dialog_id,
            sip_dialog::DialogStateType::Early,
            helper.local_uri.clone(),
            target_uri.clone(),
            target_uri,
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

        Ok(CallHandle {
            dialog: placeholder_dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: Arc::new(request),
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
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

        // Use remote target from dialog for DNS resolution
        let target = RequestTarget::Uri(dialog.remote_target().clone());
        let dns_target = self.resolve_target(&target).await?;

        // Auto-fill Via with resolved transport
        self.auto_fill_headers(&mut request, Some(dns_target.transport()))
            .await;

        // Send and wait for response
        self.send_non_invite_request(request, dns_target).await
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
            transaction_manager: self.transaction_manager.clone(),
            dispatcher: self.transport_dispatcher.clone(),
            early_dialogs: early_dialogs.clone(),
            local_addr: self.local_addr,
            public_addr: self.public_addr,
        });

        let key = self
            .transaction_manager
            .start_client_transaction(request.clone(), ctx.clone(), tu)
            .await?;

        info!(
            "Started INVITE transaction {} for dialog {}",
            key.branch(), dialog.id().call_id()
        );

        Ok(CallHandle {
            dialog,
            transaction_key: key,
            provisional_rx: Arc::new(Mutex::new(prov_rx)),
            final_rx: Arc::new(Mutex::new(Some(final_rx))),
            termination_rx: Arc::new(Mutex::new(Some(term_rx))),
            invite_request: Arc::new(request),
            transport_ctx: Arc::new(ctx),
            dispatcher: self.transport_dispatcher.clone(),
            transaction_manager: self.transaction_manager.clone(),
            early_dialogs,
            keepalive_cancel: Arc::new(Mutex::new(None)),
            session_timer_cancel: Arc::new(Mutex::new(None)),
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
            1,  // local_cseq
            0,  // remote_cseq
            None,  // last_ack_cseq
            vec![],  // route_set
            false,  // secure
            Some(Duration::from_secs(30)),  // session_expires
            None,  // refresher
            true,  // is_uac
        )
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
            1,  // local_cseq
            0,  // remote_cseq
            None,  // last_ack_cseq
            route_set,  // custom route_set
            false,  // secure
            Some(Duration::from_secs(30)),  // session_expires
            None,  // refresher
            true,  // is_uac
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
        assert_eq!(dialog.remote_target().as_str(), "sip:new-remote@example.com");
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

        // Copy essential headers from INVITE
        for header in self.invite_request.headers().iter() {
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
            RequestLine::new(Method::Cancel, self.invite_request.uri().clone()),
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
    #[allow(dead_code)]
    ctx: TransportContext,
    #[allow(dead_code)]
    auto_retry_auth: bool,
    transaction_manager: Arc<TransactionManager>,
    dispatcher: Arc<dyn TransportDispatcher>,
    /// Track early dialogs for forking support (shared with CallHandle)
    early_dialogs: Arc<Mutex<std::collections::HashMap<SmolStr, Dialog>>>,
    local_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
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

        // Create or confirm dialog from 2xx
        if response.code() >= 200 && response.code() < 300 {
            let helper = self.helper.lock().await;
            if let Some(dialog) = helper.process_invite_response(&self.request, response) {
                info!(
                    "Confirmed dialog from {}: {}",
                    response.code(),
                    dialog.id().call_id()
                );
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
            if let Err(e) = stream.send(ack_bytes).await {
                error!("Failed to send ACK via stream: {}", e);
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
