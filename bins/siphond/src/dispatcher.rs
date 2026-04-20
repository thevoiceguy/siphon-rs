// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Request dispatcher that routes SIP requests to appropriate handlers.
use std::{collections::HashMap, sync::Arc};

use sip_auth::Authenticator;
use sip_core::{Method, Request};
use sip_transaction::{ServerTransactionHandle, TransportContext};
use tracing::{info, warn};

use crate::{
    handlers::{
        bye::ByeHandler, cancel::CancelHandler, info::InfoHandler, invite::InviteHandler,
        message::MessageHandler, notify::NotifyHandler, options::OptionsHandler,
        prack::PrackHandler, refer::ReferHandler, register::RegisterHandler,
        subscribe::SubscribeHandler, update::UpdateHandler, RequestHandler,
    },
    services::ServiceRegistry,
};

/// Request dispatcher routes incoming requests to method-specific handlers.
pub struct RequestDispatcher {
    handlers: HashMap<Method, Arc<dyn RequestHandler>>,
    services: Arc<ServiceRegistry>,
}

impl RequestDispatcher {
    /// Create a new dispatcher with the given service registry.
    ///
    /// Handlers are registered based on the daemon configuration:
    /// - OPTIONS: Always enabled
    /// - INVITE/CANCEL/BYE: Enabled in CallServer, FullUas, Interactive modes
    /// - REGISTER: Enabled in Registrar, FullUas modes
    /// - SUBSCRIBE: Enabled in SubscriptionServer, FullUas, Interactive modes
    /// - REFER: Enabled if feature flag is set
    pub fn new(services: Arc<ServiceRegistry>) -> Self {
        let mut handlers: HashMap<Method, Arc<dyn RequestHandler>> = HashMap::new();

        // OPTIONS is always available
        handlers.insert(Method::Options, Arc::new(OptionsHandler::new()));

        // INVITE, CANCEL, and BYE for call handling
        if services.config.enable_calls() {
            handlers.insert(Method::Invite, Arc::new(InviteHandler::new()));
            handlers.insert(Method::Cancel, Arc::new(CancelHandler::new()));
            handlers.insert(Method::Bye, Arc::new(ByeHandler::new()));
            handlers.insert(Method::Prack, Arc::new(PrackHandler::new()));
            handlers.insert(Method::Update, Arc::new(UpdateHandler::new()));
            handlers.insert(Method::Info, Arc::new(InfoHandler::new()));
            handlers.insert(Method::Message, Arc::new(MessageHandler::new()));
        }

        // REGISTER for registrar
        if services.config.enable_registrar() {
            handlers.insert(Method::Register, Arc::new(RegisterHandler::new()));
        }

        // SUBSCRIBE for event subscriptions. NOTIFY is always registered
        // alongside so we can reply 481 (RFC 6665 §4.1.4) to unsolicited
        // NOTIFYs even when SUBSCRIBE itself is disabled — otherwise the
        // dispatcher returns 501 and leaks support information.
        handlers.insert(Method::Notify, Arc::new(NotifyHandler::new()));
        if services.config.enable_subscriptions() {
            handlers.insert(Method::Subscribe, Arc::new(SubscribeHandler::new()));
        }

        // REFER for call transfer
        if services.config.features.enable_refer {
            handlers.insert(Method::Refer, Arc::new(ReferHandler::new()));
        }

        Self { handlers, services }
    }

    /// Check if the request requires authentication and if so, verify credentials.
    ///
    /// Per RFC 3261:
    /// - ACK cannot be challenged (no response can be sent)
    /// - CANCEL must be processed without authentication
    /// - REGISTER has its own auth via the registrar (handled in RegisterHandler)
    /// - OPTIONS is informational and exempt
    /// - All other methods are challenged when `--auth` is enabled
    ///
    /// Returns `true` if the request is authenticated or exempt; `false` if a
    /// 401 challenge was sent and the request should not be processed further.
    async fn check_auth(
        &self,
        request: &Request,
        handle: &ServerTransactionHandle,
        ctx: &TransportContext,
    ) -> bool {
        let authenticator = match &self.services.authenticator {
            Some(auth) => auth,
            None => return true, // No auth configured, allow all
        };

        // Methods exempt from authentication per RFC 3261
        let method = request.method();
        if matches!(
            method,
            &Method::Ack | &Method::Cancel | &Method::Options | &Method::Register
        ) {
            return true;
        }

        // Throttle authentication attempts per source IP to cap Digest
        // brute-force rate. The limiter is checked *before* the hash
        // comparison so invalid nonces don't get a free hash computation
        // at attacker-controlled rate. A blocked attempt gets 503 rather
        // than the usual 401 — returning a 401 challenge would encourage
        // the attacker to retry immediately and also lets them drain our
        // nonce pool.
        let source_ip = ctx.peer().ip().to_string();
        if !self
            .services
            .auth_rate_limiter
            .check_rate_limit(&source_ip)
        {
            warn!(%source_ip, method = ?method, "Auth attempt rate-limited");
            self.send_rate_limited(request, handle.clone()).await;
            return false;
        }

        // Try to verify the Authorization header
        match authenticator.verify(request, request.headers()) {
            Ok(true) => true, // Authenticated
            Ok(false) => {
                // No valid credentials — send 401 challenge
                info!(method = ?method, "Authentication required, sending 401 challenge");
                match authenticator.challenge(request) {
                    Ok(challenge_response) => {
                        handle.send_final(challenge_response).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to generate auth challenge");
                    }
                }
                false
            }
            Err(e) => {
                warn!(error = %e, "Authentication verification error");
                false
            }
        }
    }

    /// Sends 503 Service Unavailable when a rate limit is hit. We re-use
    /// this for any hot-path throttle (auth / REGISTER / INVITE) so the
    /// response shape is consistent.
    async fn send_rate_limited(&self, request: &Request, handle: ServerTransactionHandle) {
        use bytes::Bytes;
        use sip_core::{Headers, Response, StatusLine};
        use sip_parse::header;

        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            if let Some(value) = header(request.headers(), name) {
                let _ = headers.push(name, value.clone());
            }
        }
        // Retry-After gives the peer a cooldown hint. 30s matches the
        // register_preset refill window scale.
        let _ = headers.push("Retry-After", "30");
        let response = Response::new(
            StatusLine::new(503, "Service Unavailable").expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");
        handle.send_final(response).await;
    }

    /// Dispatch an incoming request to the appropriate handler.
    ///
    /// If no handler is registered for the method, sends 501 Not Implemented.
    pub async fn dispatch(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
    ) {
        use sip_parse::header;

        // RFC 3261 §8.1.1.3: Check Max-Forwards
        // If Max-Forwards is 0, respond with 483 Too Many Hops
        if let Some(max_forwards) = header(request.headers(), "Max-Forwards") {
            if let Ok(value) = max_forwards.parse::<u32>() {
                if value == 0 {
                    warn!(
                        method = ?request.method(),
                        "Max-Forwards is 0, rejecting with 483"
                    );
                    self.send_too_many_hops(request, handle).await;
                    return;
                }
            }
        }

        // Authenticate non-exempt methods when auth is enabled
        if !self.check_auth(request, &handle, ctx).await {
            return;
        }

        let method = request.method();

        match self.handlers.get(method) {
            Some(handler) => {
                if let Err(e) = handler.handle(request, handle, ctx, &self.services).await {
                    warn!(
                        method = ?method,
                        error = %e,
                        "Handler failed to process request"
                    );
                }
            }
            None => {
                warn!(method = ?method, "No handler registered for method");
                self.send_not_implemented(request, handle).await;
            }
        }
    }

    /// Send 483 Too Many Hops response (RFC 3261 §8.1.1.3)
    async fn send_too_many_hops(&self, request: &Request, handle: ServerTransactionHandle) {
        use bytes::Bytes;
        use sip_core::{Headers, Response, StatusLine};
        use sip_parse::header;

        let mut headers = Headers::new();

        if let Some(via) = header(request.headers(), "Via") {
            let _ = headers.push("Via", via);
        }
        if let Some(from) = header(request.headers(), "From") {
            let _ = headers.push("From", from);
        }
        if let Some(to) = header(request.headers(), "To") {
            let _ = headers.push("To", to);
        }
        if let Some(call_id) = header(request.headers(), "Call-ID") {
            let _ = headers.push("Call-ID", call_id);
        }
        if let Some(cseq) = header(request.headers(), "CSeq") {
            let _ = headers.push("CSeq", cseq);
        }

        let response = Response::new(
            StatusLine::new(483, "Too Many Hops").expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");

        handle.send_final(response).await;
    }

    /// Send 501 Not Implemented response
    async fn send_not_implemented(&self, request: &Request, handle: ServerTransactionHandle) {
        use bytes::Bytes;
        use sip_core::{Headers, Response, StatusLine};
        use sip_parse::header;

        let mut headers = Headers::new();

        if let Some(via) = header(request.headers(), "Via") {
            let _ = headers.push("Via", via);
        }
        if let Some(from) = header(request.headers(), "From") {
            let _ = headers.push("From", from);
        }
        if let Some(to) = header(request.headers(), "To") {
            let _ = headers.push("To", to);
        }
        if let Some(call_id) = header(request.headers(), "Call-ID") {
            let _ = headers.push("Call-ID", call_id);
        }
        if let Some(cseq) = header(request.headers(), "CSeq") {
            let _ = headers.push("CSeq", cseq);
        }

        let response = Response::new(
            StatusLine::new(501, "Not Implemented").expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");

        handle.send_final(response).await;
    }
}
