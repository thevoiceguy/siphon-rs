// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Request dispatcher that routes SIP requests to appropriate handlers.
use std::{collections::HashMap, sync::Arc};

use sip_core::{Method, Request};
use sip_transaction::{ServerTransactionHandle, TransportContext};
use tracing::warn;

use crate::{
    handlers::{
        bye::ByeHandler, cancel::CancelHandler, info::InfoHandler, invite::InviteHandler,
        message::MessageHandler, options::OptionsHandler, prack::PrackHandler, refer::ReferHandler,
        register::RegisterHandler, subscribe::SubscribeHandler, update::UpdateHandler,
        RequestHandler,
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

        // SUBSCRIBE for event subscriptions
        if services.config.enable_subscriptions() {
            handlers.insert(Method::Subscribe, Arc::new(SubscribeHandler::new()));
        }

        // REFER for call transfer
        if services.config.features.enable_refer {
            handlers.insert(Method::Refer, Arc::new(ReferHandler::new()));
        }

        Self { handlers, services }
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
        if let Some(max_forwards) = header(&request.headers, "Max-Forwards") {
            if let Ok(value) = max_forwards.parse::<u32>() {
                if value == 0 {
                    warn!(
                        method = ?request.start.method,
                        "Max-Forwards is 0, rejecting with 483"
                    );
                    self.send_too_many_hops(request, handle).await;
                    return;
                }
            }
        }

        let method = &request.start.method;

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

        if let Some(via) = header(&request.headers, "Via") {
            let _ = headers.push("Via", via);
        }
        if let Some(from) = header(&request.headers, "From") {
            let _ = headers.push("From", from);
        }
        if let Some(to) = header(&request.headers, "To") {
            let _ = headers.push("To", to);
        }
        if let Some(call_id) = header(&request.headers, "Call-ID") {
            let _ = headers.push("Call-ID", call_id);
        }
        if let Some(cseq) = header(&request.headers, "CSeq") {
            let _ = headers.push("CSeq", cseq);
        }

        let response = Response::new(
            StatusLine::new(483, "Too Many Hops".into()),
            headers,
            Bytes::new(),
        );

        handle.send_final(response).await;
    }

    /// Send 501 Not Implemented response
    async fn send_not_implemented(&self, request: &Request, handle: ServerTransactionHandle) {
        use bytes::Bytes;
        use sip_core::{Headers, Response, StatusLine};
        use sip_parse::header;

        let mut headers = Headers::new();

        if let Some(via) = header(&request.headers, "Via") {
            let _ = headers.push("Via", via);
        }
        if let Some(from) = header(&request.headers, "From") {
            let _ = headers.push("From", from);
        }
        if let Some(to) = header(&request.headers, "To") {
            let _ = headers.push("To", to);
        }
        if let Some(call_id) = header(&request.headers, "Call-ID") {
            let _ = headers.push("Call-ID", call_id);
        }
        if let Some(cseq) = header(&request.headers, "CSeq") {
            let _ = headers.push("CSeq", cseq);
        }

        let response = Response::new(
            StatusLine::new(501, "Not Implemented".into()),
            headers,
            Bytes::new(),
        );

        handle.send_final(response).await;
    }
}
