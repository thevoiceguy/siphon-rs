// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Integrated UAS with full transaction, transport integration.
///
/// This module provides a production-ready UAS implementation that integrates:
/// - Transaction layer (automatic retransmissions, state management)
/// - Transport layer (Via/Contact auto-filling, connection management)
/// - Authentication (automatic 401/407 challenges)
/// - Dialog and subscription management
///
/// # Architecture
///
/// The integrated UAS uses composition over modification:
/// - Embeds the low-level `UserAgentServer` helper for response generation
/// - Adds transaction/transport integration on top
/// - Provides async trait-based request handlers for applications
///
/// # Example
///
/// ```ignore
/// use sip_uas::integrated::{IntegratedUAS, UasRequestHandler};
/// use sip_core::{Request, Response};
/// use anyhow::Result;
///
/// struct MyApp;
///
/// #[async_trait::async_trait]
/// impl UasRequestHandler for MyApp {
///     async fn on_invite(&self, request: &Request) -> Result<Response> {
///         // Handle INVITE request
///         Ok(Response::new(/* ... */))
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let uas = IntegratedUAS::builder()
///     .local_uri("sip:server@example.com")
///     .local_addr("192.168.1.100:5060")
///     .transaction_manager(tx_mgr)
///     .dispatcher(dispatcher)
///     .request_handler(Arc::new(MyApp))
///     .build()?;
///
/// // UAS will automatically handle incoming requests via the transaction manager
/// # Ok(())
/// # }
/// ```
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sip_auth::Authenticator;
use sip_core::{Method, Request, Response, SipUri, ViaHeader};
use sip_dialog::{Dialog, DialogManager, SubscriptionManager};
use sip_sdp::profiles::MediaProfileBuilder;
use sip_transaction::{
    ServerTransactionHandle, TransactionKey, TransactionManager, TransportContext,
    TransportDispatcher,
};
use smol_str::SmolStr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{AcceptInviteOutcome, NegotiatedSessionTimer, SessionTimerPolicy, UserAgentServer};
use std::time::Duration;

/// Async-flavoured sibling of [`crate::AcceptInviteOutcome`]. The helper's
/// outcome already routes the 2xx / 422 through the transaction handle,
/// so the async caller only needs to know whether a dialog was created
/// (and the negotiated timer, if any) — the prepared response is gone.
// Same rationale as `AcceptInviteOutcome`: returned once per INVITE,
// boxing would impose a deref on every caller for no measurable win.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum AcceptInviteAsyncOutcome {
    /// 200 OK was sent. `session_timer` is `Some` iff the peer requested
    /// session timers and we negotiated them successfully.
    Accepted {
        dialog: Dialog,
        session_timer: Option<NegotiatedSessionTimer>,
    },
    /// 422 was sent. No dialog created. `required_min_se` is the Min-SE
    /// the peer must use to retry.
    SessionIntervalTooSmall { required_min_se: Duration },
}

/// Methods the `IntegratedUAS` dispatch loop and the *default*
/// [`UasRequestHandler`] trait bodies answer for real: INVITE/ACK
/// (driven by `dispatch`), BYE and CANCEL (the default `on_bye` /
/// `on_cancel` send a genuine 200 OK) and OPTIONS (answered inline by
/// `dispatch`). Every other method falls through to a default body
/// that returns `405 Method Not Allowed`, so it MUST NOT appear here:
/// RFC 3261 §20.5 defines `Allow` as the methods the UAS actually
/// supports, and advertising one it then rejects with 405 is both
/// non-compliant and a free capability hint to scanners.
///
/// A handler that overrides `on_register`, `on_subscribe`, `on_refer`,
/// … to return real responses should override
/// [`UasRequestHandler::supported_methods`] to add those methods.
const DEFAULT_SUPPORTED_METHODS: &[&str] = &["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS"];

/// Builds a `405 Method Not Allowed`. RFC 3261 §21.4.6 requires the
/// response to carry an `Allow` header, and §20.5 defines that list as
/// exactly the methods this UAS supports — `allow` is that list, as
/// produced by [`UasRequestHandler::allow_header`].
fn method_not_allowed_response(request: &Request, allow: &str) -> Response {
    let mut response = UserAgentServer::create_response(request, 405, "Method Not Allowed");
    response
        .headers_mut()
        .push(SmolStr::new("Allow"), SmolStr::new(allow))
        .unwrap();
    response
}

/// Trait for handling incoming SIP requests.
///
/// Applications implement this trait to define their request handling logic.
/// Handlers can send provisional and final responses using the `ServerTransactionHandle`.
/// Default implementations send 405 Method Not Allowed for all methods.
#[async_trait]
pub trait UasRequestHandler: Send + Sync {
    /// The SIP methods this UAS supports, used to build the `Allow`
    /// header on `405 Method Not Allowed` and `OPTIONS` responses.
    ///
    /// RFC 3261 §20.5 defines `Allow` as *the set of methods supported
    /// by the UA*, and §21.4.6 requires it on every 405. Listing a
    /// method here that the UAS then answers with 405 is both
    /// non-compliant and a free capability hint to scanners.
    ///
    /// The default — `INVITE, ACK, BYE, CANCEL, OPTIONS` — is the set
    /// the `IntegratedUAS` dispatch loop and the default trait bodies
    /// answer for real. Override this if, and only if, you also
    /// override the matching `on_*` method (`on_register`,
    /// `on_subscribe`, `on_refer`, …) to return real responses.
    fn supported_methods(&self) -> &'static [&'static str] {
        DEFAULT_SUPPORTED_METHODS
    }

    /// The `Allow` header value for this UAS: [`Self::supported_methods`]
    /// rendered as the comma-separated list RFC 3261 §20.5 expects.
    fn allow_header(&self) -> String {
        self.supported_methods().join(", ")
    }

    /// Handle an incoming INVITE request.
    ///
    /// # Arguments
    /// * `request` - The INVITE request
    /// * `handle` - Transaction handle for sending responses
    /// * `ctx` - Transport context
    /// * `dialog` - Optional dialog if this is a re-INVITE
    async fn on_invite(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        dialog: Option<&Dialog>,
    ) -> Result<()> {
        let _ = (ctx, dialog);
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming ACK request (for 2xx INVITE responses).
    async fn on_ack(&self, request: &Request, dialog: &Dialog) -> Result<()> {
        let _ = (request, dialog);
        Ok(())
    }

    /// Handle an incoming BYE request.
    ///
    /// `ctx` exposes the transport `peer` so implementations can apply
    /// the same RFC 3261 §18.2.1 / RFC 3581 §4 Via mutation
    /// (`received=` / `rport=`) to in-dialog 200 OKs that the
    /// dispatch loop applies to non-dialog responses via
    /// [`IntegratedUAS::prepare_response`].
    async fn on_bye(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = (ctx, dialog);
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming CANCEL request.
    ///
    /// `ctx` exposes the transport `peer` so implementations can apply
    /// the same RFC 3261 §18.2.1 / RFC 3581 §4 Via mutation
    /// (`received=` / `rport=`) the dispatch loop applies elsewhere.
    async fn on_cancel(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
    ) -> Result<()> {
        let _ = ctx;
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming REGISTER request.
    async fn on_register(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming OPTIONS request.
    ///
    /// Default response advertises the methods the IntegratedUAS
    /// dispatch loop knows how to route (per RFC 3261 §11.2). The
    /// Contact header is left to [`IntegratedUAS::prepare_response`]
    /// so it reflects the publicly-advertised transport address.
    async fn on_options(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let mut response = UserAgentServer::accept_options(request);
        // `accept_options` stamps a baseline `Allow`; overwrite it
        // with this handler's actual capability set so OPTIONS
        // discovery and 405 responses advertise the same methods.
        response
            .headers_mut()
            .set_or_push("Allow", self.allow_header())
            .expect("allow value valid");
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming SUBSCRIBE request.
    async fn on_subscribe(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming NOTIFY request.
    async fn on_notify(&self, request: &Request, handle: ServerTransactionHandle) -> Result<()> {
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming REFER request.
    async fn on_refer(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming UPDATE request.
    async fn on_update(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming PRACK request.
    async fn on_prack(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }

    /// Handle an incoming INFO request.
    async fn on_info(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        dialog: &Dialog,
    ) -> Result<()> {
        let _ = dialog;
        let response = method_not_allowed_response(request, &self.allow_header());
        handle.send_final(response).await;
        Ok(())
    }
}

/// Configuration for IntegratedUAS behavior.
#[derive(Clone)]
pub struct UASConfig {
    /// Automatically fill Via header in responses from transport context (default: true)
    pub auto_via_filling: bool,

    /// Automatically fill Contact header in responses from local transport (default: true)
    pub auto_contact_filling: bool,

    /// Automatically send 100 Trying for INVITE requests (default: true)
    pub auto_send_100_trying: bool,

    /// User-Agent header value (default: "siphon-rs/0.1.0")
    pub user_agent: String,

    /// Require authentication for requests (default: false)
    pub require_authentication: bool,
}

impl Default for UASConfig {
    fn default() -> Self {
        Self {
            auto_via_filling: true,
            auto_contact_filling: true,
            auto_send_100_trying: true,
            user_agent: "siphon-rs/0.1.0".to_string(),
            require_authentication: false,
        }
    }
}

/// Integrated User Agent Server with full transaction and transport integration.
///
/// Automatically handles:
/// - Transaction state management and retransmissions
/// - Dialog and subscription tracking
/// - Via/Contact header auto-filling
/// - Request routing to application handlers
pub struct IntegratedUAS {
    helper: Arc<Mutex<UserAgentServer>>,
    transaction_manager: Arc<TransactionManager>,
    #[allow(dead_code)]
    transport_dispatcher: Arc<dyn TransportDispatcher>,
    local_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
    config: UASConfig,
    dialog_manager: Arc<DialogManager>,
    #[allow(dead_code)]
    subscription_manager: Arc<SubscriptionManager>,
    request_handler: Arc<dyn UasRequestHandler>,
    #[allow(dead_code)]
    sdp_profile: Option<MediaProfileBuilder>,
}

impl IntegratedUAS {
    /// Creates a builder for constructing an IntegratedUAS.
    pub fn builder() -> IntegratedUASBuilder {
        IntegratedUASBuilder::new()
    }

    /// Dispatch an incoming request to the appropriate handler.
    ///
    /// This is the main entry point for incoming requests. It routes the request
    /// to the appropriate trait method based on the SIP method.
    ///
    /// # Arguments
    /// * `request` - The incoming SIP request
    /// * `handle` - Transaction handle for sending responses
    /// * `ctx` - Transport context
    pub async fn dispatch(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
    ) -> Result<()> {
        info!(
            "Dispatching {:?} request from {}",
            request.method(),
            ctx.peer()
        );

        if self.config.require_authentication && request.method() != &Method::Ack {
            let helper = self.helper.lock().await;
            let is_authenticated = helper.verify_authentication(request)?;
            if !is_authenticated {
                let mut response = helper.create_unauthorized(request)?;
                drop(helper);
                self.auto_fill_headers(&mut response, ctx).await;
                handle.send_final(response).await;
                return Ok(());
            }
        }

        // Route based on method
        match request.method().as_str() {
            "INVITE" => {
                if let Err(mut response) = UserAgentServer::validate_invite_headers(request) {
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                    return Ok(());
                }

                let helper = self.helper.lock().await;
                let dialog = helper.dialog_manager.find_by_request(request);
                drop(helper);

                // Send 100 Trying if configured
                if self.config.auto_send_100_trying {
                    let mut trying = UserAgentServer::create_response(request, 100, "Trying");
                    self.auto_fill_headers(&mut trying, ctx).await;
                    handle.send_provisional(trying).await;
                }

                self.request_handler
                    .on_invite(request, handle, ctx, dialog.as_ref())
                    .await?;
            }
            "ACK" => {
                // ACK doesn't get a response
                let dialog = {
                    let helper = self.helper.lock().await;
                    helper.dialog_manager.find_by_request(request)
                };
                if let Some(dialog) = dialog {
                    self.request_handler.on_ack(request, &dialog).await?;
                } else {
                    warn!("Received ACK for unknown dialog");
                }
            }
            "BYE" => {
                let dialog = {
                    let helper = self.helper.lock().await;
                    helper.dialog_manager.find_by_request(request)
                };
                if let Some(dialog) = dialog {
                    self.request_handler
                        .on_bye(request, handle, ctx, &dialog)
                        .await?;
                } else {
                    warn!("Received BYE for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "CANCEL" => {
                self.request_handler.on_cancel(request, handle, ctx).await?;
                if let Some(cancel_key) = TransactionKey::from_request(request, true) {
                    let invite_key = TransactionKey::new(cancel_key.branch(), Method::Invite, true);
                    let mut response =
                        UserAgentServer::create_request_terminated_from_cancel(request);
                    self.auto_fill_headers(&mut response, ctx).await;
                    self.transaction_manager
                        .send_final(&invite_key, response)
                        .await;
                }
            }
            "REGISTER" => {
                self.request_handler.on_register(request, handle).await?;
            }
            "OPTIONS" => {
                // OPTIONS is a capability query — RFC 3261 §11. The
                // response is mechanical (Allow / Accept / Supported
                // / Contact), so we build it here rather than going
                // through the request handler. Applications that
                // need custom OPTIONS handling should disable
                // dispatch and drive the UAS directly. Going via
                // `auto_fill_headers` gives us the Contact pointing
                // at the public transport address plus the same
                // rport / received Via mutation the rest of the
                // dispatch loop emits.
                let mut response = UserAgentServer::accept_options(request);
                // Advertise exactly what the installed request handler
                // supports, not `accept_options`'s baseline (RFC 3261
                // §20.5 — `Allow` is the methods we actually answer).
                response
                    .headers_mut()
                    .set_or_push("Allow", self.request_handler.allow_header())
                    .expect("allow value valid");
                self.auto_fill_headers(&mut response, ctx).await;
                handle.send_final(response).await;
            }
            "SUBSCRIBE" => {
                self.request_handler.on_subscribe(request, handle).await?;
            }
            "NOTIFY" => {
                self.request_handler.on_notify(request, handle).await?;
            }
            "REFER" => {
                let dialog = {
                    let helper = self.helper.lock().await;
                    helper.dialog_manager.find_by_request(request)
                };
                if let Some(dialog) = dialog {
                    self.request_handler
                        .on_refer(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received REFER for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "UPDATE" => {
                let dialog = {
                    let helper = self.helper.lock().await;
                    helper.dialog_manager.find_by_request(request)
                };
                if let Some(dialog) = dialog {
                    self.request_handler
                        .on_update(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received UPDATE for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "PRACK" => {
                let dialog = {
                    let helper = self.helper.lock().await;
                    helper.dialog_manager.find_by_request(request)
                };
                if let Some(dialog) = dialog {
                    self.request_handler
                        .on_prack(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received PRACK for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            "INFO" => {
                let dialog = {
                    let helper = self.helper.lock().await;
                    helper.dialog_manager.find_by_request(request)
                };
                if let Some(dialog) = dialog {
                    self.request_handler
                        .on_info(request, handle, &dialog)
                        .await?;
                } else {
                    warn!("Received INFO for unknown dialog");
                    let mut response = UserAgentServer::create_response(
                        request,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                    self.auto_fill_headers(&mut response, ctx).await;
                    handle.send_final(response).await;
                }
            }
            _ => {
                warn!("Unsupported method: {:?}", request.method());
                let mut response =
                    UserAgentServer::create_response(request, 501, "Not Implemented");
                self.auto_fill_headers(&mut response, ctx).await;
                handle.send_final(response).await;
            }
        }

        Ok(())
    }

    /// Accept an INVITE: build a 2xx response with optional SDP body,
    /// auto-fill Via/Contact/User-Agent headers, send it via the supplied
    /// transaction handle, and register the resulting confirmed dialog
    /// with the dialog manager that `dispatch` consults on subsequent
    /// in-dialog requests (BYE, REFER, INFO, …).
    ///
    /// This is the canonical way to accept an INVITE from a
    /// [`UasRequestHandler::on_invite`] implementation. Building a 2xx
    /// manually with [`UserAgentServer::create_ok`] and sending it
    /// straight through `handle.send_final` *does not* register the
    /// dialog, and the next BYE on that call will fail dispatch with
    /// "Received BYE for unknown dialog".
    pub async fn accept_invite(
        &self,
        request: &Request,
        handle: &ServerTransactionHandle,
        ctx: &TransportContext,
        sdp_body: Option<&str>,
    ) -> Result<Dialog> {
        let helper = self.helper.lock().await;
        let (mut response, dialog) = helper.accept_invite(request, sdp_body)?;
        drop(helper);
        self.auto_fill_headers(&mut response, ctx).await;
        handle.send_final(response).await;
        Ok(dialog)
    }

    /// Session-timer-aware sibling of [`Self::accept_invite`]. Calls
    /// [`UserAgentServer::accept_invite_with_session_timer`] under the
    /// helper's lock, sends the prepared 2xx (or 422 on Min-SE violation),
    /// and returns either the dialog + negotiation outcome or a
    /// `SessionIntervalTooSmall` result so the caller can decide how to
    /// react (typically: skip dialog/session setup and let the peer
    /// retry with a larger Session-Expires).
    pub async fn accept_invite_with_session_timer(
        &self,
        request: &Request,
        handle: &ServerTransactionHandle,
        ctx: &TransportContext,
        sdp_body: Option<&str>,
        policy: &SessionTimerPolicy,
    ) -> Result<AcceptInviteAsyncOutcome> {
        let helper = self.helper.lock().await;
        let outcome = helper.accept_invite_with_session_timer(request, sdp_body, policy)?;
        drop(helper);
        match outcome {
            AcceptInviteOutcome::Accepted {
                mut response,
                dialog,
                session_timer,
            } => {
                self.auto_fill_headers(&mut response, ctx).await;
                handle.send_final(response).await;
                Ok(AcceptInviteAsyncOutcome::Accepted {
                    dialog,
                    session_timer,
                })
            }
            AcceptInviteOutcome::SessionIntervalTooSmall {
                response,
                required_min_se,
            } => {
                handle.send_final(response).await;
                Ok(AcceptInviteAsyncOutcome::SessionIntervalTooSmall { required_min_se })
            }
        }
    }

    /// Access the embedded [`UserAgentServer`] helper.
    ///
    /// Useful for callers that need to invoke helper methods (e.g.
    /// `create_response`, `reject_invite`, `with_authenticator`) and
    /// want to share state — particularly the `dialog_manager` —
    /// with the dispatcher. Holding a separate `UserAgentServer`
    /// instance alongside an `IntegratedUAS` produces two independent
    /// dialog managers and breaks dispatch lookups; use this accessor
    /// instead.
    pub fn helper(&self) -> Arc<Mutex<UserAgentServer>> {
        Arc::clone(&self.helper)
    }

    /// Access the dialog manager used by dispatch for in-dialog
    /// request lookup. Useful for tests and admin tooling.
    pub fn dialog_manager(&self) -> Arc<DialogManager> {
        Arc::clone(&self.dialog_manager)
    }

    /// Public alias of [`Self::auto_fill_headers`] so external response
    /// builders (e.g. siphon-ai's trunk-rejection 403 path) can apply
    /// the same header enrichment — Contact / User-Agent / topmost-Via
    /// `rport` + `received` — without having to reimplement the rules.
    /// Idempotent: re-calling it on a response that already has these
    /// fields is a no-op.
    pub async fn prepare_response(&self, response: &mut Response, ctx: &TransportContext) {
        self.auto_fill_headers(response, ctx).await
    }

    /// Auto-fill Via and Contact headers in responses based on
    /// transport context.
    ///
    /// - **Via**: mutates the topmost copied-from-request Via per
    ///   RFC 3261 §18.2.1 and RFC 3581 §4 — fills `rport=<src_port>`
    ///   when the request carried a bare `;rport`, and adds
    ///   `received=<src_ip>` whenever the sent-by host differs from
    ///   the actual source IP or `rport` was filled. Required for
    ///   NAT traversal.
    /// - **Contact**: pushes a single Contact pointing at the
    ///   advertised public address with the explicit `:port` and
    ///   `;transport=<proto>` for the transport this response is
    ///   going out on. Always overwrites any existing Contact when
    ///   `auto_contact_filling` is on — bare URIs that
    ///   [`UserAgentServer::create_ok`] inserts (which lack port /
    ///   transport because the UAS template has no access to the
    ///   listener metadata) get replaced here so 2xx dialog-forming
    ///   responses advertise a Contact that PBXs and SBCs can dial
    ///   back to without guessing.
    /// - **User-Agent**: added when missing.
    async fn auto_fill_headers(&self, response: &mut Response, ctx: &TransportContext) {
        if self.config.auto_via_filling {
            apply_via_rport_received(response, ctx.peer());
        }

        if self.config.auto_contact_filling {
            let addr = self.public_addr.unwrap_or(self.local_addr);
            let helper = self.helper.lock().await;
            let contact_uri = &helper.contact_uri;

            // Transport param mirrors the transport this response
            // is being sent over (UDP/TCP/TLS/WS/...). Lowercase
            // per RFC 3261 §19.1.1 / RFC 4168. Always emitted —
            // even for the UDP default — so the Contact is
            // unambiguous to peers that don't apply the default
            // and to ourselves when the SBC routes responses
            // through us on a different transport later.
            let transport = transport_param_for(ctx.transport());

            let contact_value = format!(
                "<sip:{}@{}:{};transport={}>",
                contact_uri.user().unwrap_or("server"),
                addr.ip(),
                addr.port(),
                transport,
            );

            // `set_or_push` replaces the first Contact in place if
            // one exists, or pushes a new one otherwise. This
            // unconditionally overwrites the bare Contact that
            // `create_ok` inserts, so we never end up with two
            // Contact headers in flight.
            let _ = response.headers_mut().set_or_push("Contact", contact_value);
        }

        if response.headers().get("User-Agent").is_none() {
            response
                .headers_mut()
                .push(
                    SmolStr::new("User-Agent"),
                    SmolStr::new(&self.config.user_agent),
                )
                .unwrap();
        }
    }
}

/// Apply RFC 3261 §18.2.1 / RFC 3581 §4 mutations to the topmost
/// Via header of `response`. The topmost Via was copied verbatim
/// from the request; this fills `rport=<src_port>` when it was
/// present without a value and adds `received=<src_ip>` whenever
/// the sent-by host differs from the actual packet source OR the
/// bare `rport` triggered a rewrite.
///
/// The unconditional `received=` on `rport` rewrites follows the
/// RFC 3581 §4 RECOMMENDATION: clients implementing symmetric
/// response routing want a single place to read the public
/// reflection of their address back from, even when the sent-by
/// IP happens to match the packet source. Adding it costs nothing
/// and short-circuits a class of NAT-tracking bugs in clients
/// that only inspect `received`.
///
/// Silently no-ops if the Via doesn't parse — we never want a
/// malformed inbound Via to abort the response.
fn apply_via_rport_received(response: &mut Response, source: SocketAddr) {
    let Some(top_via) = response.headers().get("Via") else {
        return;
    };
    let top_via = top_via.to_string();
    let Ok(mut via) = ViaHeader::parse(&top_via) else {
        return;
    };

    let mut changed = false;
    let mut rport_filled = false;

    // RFC 3581 §4: an inbound request with a bare `;rport` must
    // have it rewritten to the actual source port on the response.
    if matches!(via.param("rport"), Some(None))
        && via
            .set_param("rport", Some(source.port().to_string()))
            .is_ok()
    {
        changed = true;
        rport_filled = true;
    }

    // RFC 3261 §18.2.1: when the sent-by host doesn't match the
    // packet source IP, the server MUST add `received=<src_ip>`.
    // Extract the host portion from the sent-by ("host" or
    // "host:port", with IPv6 bracketed); compare against the
    // source IP. Done as strings to sidestep DNS — the requirement
    // is exact-bytes comparison per the RFC, not name resolution.
    //
    // RFC 3581 §4 additionally RECOMMENDS adding `received=` even
    // when sent-by matches src IP, provided we're also filling
    // `rport`. We honour that recommendation by piggy-backing on
    // `rport_filled` — the client asked for symmetric response
    // routing, so it gets the full pair.
    let sent_by_host = sent_by_host(via.sent_by());
    let src_ip = source.ip().to_string();
    if (sent_by_host != src_ip || rport_filled)
        && via.param("received").is_none()
        && via.set_param("received", Some(src_ip.as_str())).is_ok()
    {
        changed = true;
    }

    if changed {
        // `set_or_push` replaces just the first occurrence — exactly
        // the topmost Via, which is what we want. Subsequent Via
        // headers (if any) are response-routing artefacts and
        // mustn't be touched.
        let _ = response.headers_mut().set_or_push("Via", via.to_string());
    }
}

/// Lowercase transport token for a SIP URI `transport=` parameter
/// (RFC 3261 §19.1.1, RFC 4168). Mirrors `sip_transport::TransportKind::as_str`
/// — duplicated here because `TransportContext` (and therefore the
/// dispatch entrypoints in this crate) work in terms of the
/// `sip_transaction::TransportKind` re-export, which doesn't carry
/// the helper. The two enums are isomorphic; keep them aligned.
fn transport_param_for(kind: sip_transaction::TransportKind) -> &'static str {
    use sip_transaction::TransportKind as T;
    match kind {
        T::Udp => "udp",
        T::Tcp => "tcp",
        T::Tls => "tls",
        T::Sctp => "sctp",
        T::TlsSctp => "tls-sctp",
        T::Ws => "ws",
        T::Wss => "wss",
    }
}

/// Strip the optional `:port` from a `sent-by` value, leaving the
/// host. Handles bracketed IPv6 (`[2001:db8::1]:5060` → `2001:db8::1`).
fn sent_by_host(sent_by: &str) -> &str {
    let s = sent_by.trim();
    if let Some(stripped) = s.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return &stripped[..end];
        }
    }
    s.rsplit_once(':').map(|(host, _)| host).unwrap_or(s)
}

/// Builder for constructing IntegratedUAS instances.
pub struct IntegratedUASBuilder {
    local_uri: Option<SipUri>,
    contact_uri: Option<SipUri>,
    local_addr: Option<SocketAddr>,
    public_addr: Option<SocketAddr>,
    transaction_manager: Option<Arc<TransactionManager>>,
    dispatcher: Option<Arc<dyn TransportDispatcher>>,
    request_handler: Option<Arc<dyn UasRequestHandler>>,
    authenticator: Option<Arc<dyn Authenticator>>,
    config: UASConfig,
    sdp_profile: Option<MediaProfileBuilder>,
}

impl IntegratedUASBuilder {
    fn new() -> Self {
        Self {
            local_uri: None,
            contact_uri: None,
            local_addr: None,
            public_addr: None,
            transaction_manager: None,
            dispatcher: None,
            request_handler: None,
            authenticator: None,
            config: UASConfig::default(),
            sdp_profile: None,
        }
    }

    /// Sets the local SIP URI (used in To/Contact headers).
    pub fn local_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.local_uri = SipUri::parse(uri.as_ref()).ok();
        self
    }

    /// Sets the contact URI (used in Contact header).
    pub fn contact_uri(mut self, uri: impl AsRef<str>) -> Self {
        self.contact_uri = SipUri::parse(uri.as_ref()).ok();
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

    /// Sets the transaction manager.
    pub fn transaction_manager(mut self, mgr: Arc<TransactionManager>) -> Self {
        self.transaction_manager = Some(mgr);
        self
    }

    /// Sets the transport dispatcher.
    pub fn dispatcher(mut self, dispatcher: Arc<dyn TransportDispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Sets the request handler for processing incoming requests.
    pub fn request_handler(mut self, handler: Arc<dyn UasRequestHandler>) -> Self {
        self.request_handler = Some(handler);
        self
    }

    /// Sets the authenticator for 401 challenges.
    pub fn authenticator(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Sets the UAS configuration.
    pub fn config(mut self, config: UASConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets a default SDP media profile builder for auto-offer/answer.
    pub fn sdp_profile(mut self, builder: MediaProfileBuilder) -> Self {
        self.sdp_profile = Some(builder);
        self
    }

    /// Builds the IntegratedUAS.
    pub fn build(self) -> Result<IntegratedUAS> {
        if self.config.require_authentication && self.authenticator.is_none() {
            return Err(anyhow!(
                "authenticator is required when require_authentication is enabled"
            ));
        }

        let local_uri = self
            .local_uri
            .ok_or_else(|| anyhow!("local_uri is required"))?;
        let local_addr = self
            .local_addr
            .ok_or_else(|| anyhow!("local_addr is required"))?;
        let transaction_manager = self
            .transaction_manager
            .ok_or_else(|| anyhow!("transaction_manager is required"))?;
        let dispatcher = self
            .dispatcher
            .ok_or_else(|| anyhow!("dispatcher is required"))?;
        let request_handler = self
            .request_handler
            .ok_or_else(|| anyhow!("request_handler is required"))?;

        // Create embedded helper
        let contact_uri = self.contact_uri.unwrap_or_else(|| {
            // Default contact: sip:server@local_addr
            let user = local_uri.user().unwrap_or("server");
            SipUri::parse(&format!("sip:{}@{}", user, local_addr)).unwrap()
        });

        let helper = if let Some(authenticator) = self.authenticator {
            UserAgentServer::new(local_uri, contact_uri).with_authenticator(authenticator)
        } else {
            UserAgentServer::new(local_uri, contact_uri)
        };
        let dialog_manager = helper.dialog_manager.clone();
        let subscription_manager = helper.subscription_manager.clone();

        Ok(IntegratedUAS {
            helper: Arc::new(Mutex::new(helper)),
            transaction_manager,
            transport_dispatcher: dispatcher,
            local_addr,
            public_addr: self.public_addr,
            config: self.config,
            dialog_manager,
            subscription_manager,
            request_handler,
            sdp_profile: self.sdp_profile,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_via_rport_received, method_not_allowed_response, sent_by_host, UasRequestHandler,
        DEFAULT_SUPPORTED_METHODS,
    };
    use bytes::Bytes;
    use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
    use smol_str::SmolStr;
    use std::net::SocketAddr;

    fn response_with_via(via: &str) -> Response {
        let mut headers = Headers::new();
        headers
            .push(SmolStr::new("Via"), SmolStr::new(via))
            .unwrap();
        headers
            .push(SmolStr::new("Content-Length"), SmolStr::new("0"))
            .unwrap();
        Response::new(StatusLine::new(200, "OK").unwrap(), headers, Bytes::new()).unwrap()
    }

    #[test]
    fn sent_by_host_strips_port() {
        assert_eq!(sent_by_host("194.195.208.34:5080"), "194.195.208.34");
        assert_eq!(sent_by_host("194.195.208.34"), "194.195.208.34");
        assert_eq!(sent_by_host("example.com:5060"), "example.com");
        assert_eq!(sent_by_host("[2001:db8::1]:5060"), "2001:db8::1");
        assert_eq!(sent_by_host("[::1]"), "::1");
    }

    #[test]
    fn via_fills_bare_rport_and_adds_received() {
        // RFC 3581 §4 — request arrived with `;rport` (no value);
        // the response must rewrite it to the source port AND
        // include `received=<src_ip>` even when sent-by matches
        // the source (the §4 RECOMMENDATION beyond the §18.2.1 MUST).
        let mut response =
            response_with_via("SIP/2.0/UDP 194.195.208.34:5080;rport;branch=z9hG4bK3pZSUr1r2Z3vF");
        let source: SocketAddr = "194.195.208.34:5080".parse().unwrap();
        apply_via_rport_received(&mut response, source);
        let via = response.headers().get("Via").unwrap();
        assert!(
            via.contains("rport=5080"),
            "Via must have rport=5080 (got {via})"
        );
        assert!(
            via.contains("received=194.195.208.34"),
            "Via must have received=<src_ip> when rport was filled (got {via})"
        );
    }

    #[test]
    fn via_skips_received_when_no_rport_and_sent_by_matches() {
        // No bare rport in the request and sent-by IP matches src
        // IP → response gets neither rport nor received. This is
        // the "plain compliant client on the same network" case.
        let mut response = response_with_via("SIP/2.0/UDP 194.195.208.34:5080;branch=z9hG4bK1");
        let source: SocketAddr = "194.195.208.34:5080".parse().unwrap();
        apply_via_rport_received(&mut response, source);
        let via = response.headers().get("Via").unwrap();
        assert!(
            !via.contains("rport="),
            "no rport since not requested (got {via})"
        );
        assert!(
            !via.contains("received="),
            "no received since sent-by matches src (got {via})"
        );
    }

    #[test]
    fn via_adds_received_when_sent_by_differs_from_source() {
        // Scanner with spoofed/local sent-by; source IP is real.
        // RFC 3261 §18.2.1 — server MUST add `received=<src_ip>`.
        let mut response = response_with_via("SIP/2.0/UDP 0.0.0.0:60207;branch=z9hG4bK1322767169");
        let source: SocketAddr = "5.196.63.60:60207".parse().unwrap();
        apply_via_rport_received(&mut response, source);
        let via = response.headers().get("Via").unwrap();
        assert!(
            via.contains("received=5.196.63.60"),
            "Via must have received=5.196.63.60 (got {via})"
        );
        // No bare rport in the request → response doesn't add it.
        assert!(
            !via.contains("rport="),
            "no rport since not requested (got {via})"
        );
    }

    #[test]
    fn via_leaves_value_rport_alone() {
        // If the request already specified `rport=N` (uncommon but
        // valid), don't overwrite it. Only the bare form
        // (`Some(None)`) triggers the §4 rewrite. The §4
        // `received=` recommendation also keys off the rewrite —
        // if we didn't fill rport here, we don't add received
        // either (sent-by `host` would match neither way).
        let mut response = response_with_via("SIP/2.0/UDP host:5060;rport=9999;branch=z9hG4bK1");
        let source: SocketAddr = "192.0.2.1:5080".parse().unwrap();
        apply_via_rport_received(&mut response, source);
        let via = response.headers().get("Via").unwrap();
        assert!(
            via.contains("rport=9999"),
            "existing rport preserved (got {via})"
        );
        // sent-by `host` doesn't match `192.0.2.1` → §18.2.1 still
        // adds received= for this case.
        assert!(
            via.contains("received=192.0.2.1"),
            "Via must have received= when sent-by differs from src (got {via})"
        );
    }

    #[test]
    fn via_preserves_existing_received() {
        // If a downstream party already stamped `received=`, don't
        // overwrite it — even when we're filling rport. Trust the
        // first server in the chain to have recorded the true
        // source address.
        let mut response = response_with_via(
            "SIP/2.0/UDP 10.0.0.1:5080;rport;received=203.0.113.5;branch=z9hG4bK1",
        );
        let source: SocketAddr = "192.0.2.1:5080".parse().unwrap();
        apply_via_rport_received(&mut response, source);
        let via = response.headers().get("Via").unwrap();
        assert!(via.contains("rport=5080"), "rport still filled (got {via})");
        assert!(
            via.contains("received=203.0.113.5"),
            "pre-existing received preserved (got {via})"
        );
        assert!(
            !via.contains("received=192.0.2.1"),
            "must not overwrite existing received (got {via})"
        );
    }

    #[test]
    fn via_noop_when_unparseable() {
        // Malformed inbound Via must not abort response. The header
        // is left untouched and the function silently returns.
        let mut response = response_with_via("not a real via header");
        let source: SocketAddr = "192.0.2.1:5060".parse().unwrap();
        apply_via_rport_received(&mut response, source);
        assert_eq!(response.headers().get("Via"), Some("not a real via header"));
    }

    // ── Allow-header honesty (RFC 3261 §20.5, §21.4.6) ──────────────

    /// Minimal request for response-builder tests. `method` drives the
    /// request line; the CSeq method is cosmetic for these assertions.
    fn sample_request(method: Method) -> Request {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP test;branch=z9hG4bK405"),
            )
            .unwrap();
        headers
            .push(SmolStr::new("From"), SmolStr::new("<sip:a@test>;tag=1"))
            .unwrap();
        headers
            .push(SmolStr::new("To"), SmolStr::new("<sip:b@test>"))
            .unwrap();
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new("allow-header-test"))
            .unwrap();
        headers
            .push(SmolStr::new("CSeq"), SmolStr::new("1 OPTIONS"))
            .unwrap();
        let uri = SipUri::parse("sip:b@test").unwrap();
        Request::new(RequestLine::new(method, uri), headers, Bytes::new()).expect("valid request")
    }

    /// A handler that takes every `UasRequestHandler` default — i.e.
    /// answers only INVITE/ACK/BYE/CANCEL/OPTIONS and 405s the rest.
    struct DefaultHandler;
    impl UasRequestHandler for DefaultHandler {}

    /// A handler that overrides `on_register` to answer for real, so
    /// it must also declare REGISTER via `supported_methods`.
    struct RegistrarHandler;
    impl UasRequestHandler for RegistrarHandler {
        fn supported_methods(&self) -> &'static [&'static str] {
            &["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER"]
        }
    }

    #[test]
    fn default_handler_advertises_only_baseline_methods() {
        assert_eq!(
            DefaultHandler.supported_methods(),
            DEFAULT_SUPPORTED_METHODS
        );
        assert_eq!(
            DefaultHandler.allow_header(),
            "INVITE, ACK, BYE, CANCEL, OPTIONS"
        );
    }

    #[test]
    fn method_not_allowed_advertises_only_supported_methods() {
        // A scanner probes REGISTER on a UAS that does not implement
        // it. RFC 3261 §21.4.6 — the 405 carries `Allow`, and §20.5
        // says that list is the methods we *do* support. It must not
        // echo back REGISTER (or SUBSCRIBE/NOTIFY/REFER/…), each of
        // which would itself only return another 405.
        let response = method_not_allowed_response(
            &sample_request(Method::Register),
            &DefaultHandler.allow_header(),
        );
        assert_eq!(response.code(), 405);
        let allow = response.headers().get("Allow").expect("405 needs Allow");
        for method in &["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS"] {
            assert!(
                allow.contains(method),
                "Allow must list supported {method} (got {allow})"
            );
        }
        for method in &[
            "REGISTER",
            "SUBSCRIBE",
            "NOTIFY",
            "REFER",
            "UPDATE",
            "PRACK",
            "INFO",
        ] {
            assert!(
                !allow.contains(method),
                "405 Allow must not advertise unsupported {method} (got {allow})"
            );
        }
    }

    #[test]
    fn supported_methods_override_widens_allow_header() {
        // A handler that answers REGISTER for real declares it via
        // `supported_methods`; its 405 (for, say, SUBSCRIBE) then
        // honestly includes REGISTER but still omits SUBSCRIBE.
        let response = method_not_allowed_response(
            &sample_request(Method::Subscribe),
            &RegistrarHandler.allow_header(),
        );
        let allow = response.headers().get("Allow").expect("405 needs Allow");
        assert!(
            allow.contains("REGISTER"),
            "overridden handler must advertise REGISTER (got {allow})"
        );
        assert!(
            !allow.contains("SUBSCRIBE"),
            "still must not advertise unsupported SUBSCRIBE (got {allow})"
        );
    }
}
