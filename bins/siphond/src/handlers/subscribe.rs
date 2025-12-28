// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// SUBSCRIBE/NOTIFY request handler.
///
/// Implements RFC 3265 event notification:
/// 1. Accept SUBSCRIBE requests
/// 2. Create/update subscriptions
/// 3. Send 200 OK with Expires header
/// 4. Send initial NOTIFY (RFC 3265 §3.1.4)
use anyhow::Result;
use async_trait::async_trait;
use sip_core::{Request, Response};
use sip_dialog::{Subscription, SubscriptionState};
use sip_parse::header;
use sip_transaction::{ClientTransactionUser, ServerTransactionHandle, TransactionKey, TransportContext};
use sip_uac::UserAgentClient;
use sip_uas::UserAgentServer;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::RequestHandler;
use crate::services::ServiceRegistry;

/// Simple ClientTransactionUser for NOTIFY requests that just logs responses.
struct NotifyTransactionUser;

#[async_trait]
impl ClientTransactionUser for NotifyTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, response: &Response) {
        debug!(status = response.start.code, "NOTIFY received provisional response");
    }

    async fn on_final(&self, _key: &TransactionKey, response: &Response) {
        if response.start.code >= 200 && response.start.code < 300 {
            debug!(status = response.start.code, "NOTIFY accepted");
        } else {
            warn!(status = response.start.code, reason = %response.start.reason, "NOTIFY rejected");
        }
    }

    async fn on_terminated(&self, _key: &TransactionKey, reason: &str) {
        debug!(reason, "NOTIFY transaction terminated");
    }

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
        _is_2xx: bool,
    ) {
        // NOTIFY is not INVITE, no ACK needed
    }

    async fn send_prack(&self, _key: &TransactionKey, _response: Response, _ctx: &TransportContext) {
        // PRACK not used for NOTIFY
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {
        warn!("NOTIFY transport error");
    }
}

pub struct SubscribeHandler;

impl SubscribeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Extract event package from Event header
    fn extract_event_package(request: &Request) -> Option<String> {
        let event = header(&request.headers, "Event")?;
        // Event header format: "event-package;param=value"
        let package = event.split(';').next()?.trim();
        Some(package.to_string())
    }

    /// Extract requested expiry from Expires header
    fn extract_expiry(request: &Request) -> Option<u32> {
        let expires = header(&request.headers, "Expires")?;
        expires.parse().ok()
    }

    /// Send initial NOTIFY as required by RFC 3265 §3.1.4.
    ///
    /// When a subscription is created, the notifier MUST send an initial NOTIFY
    /// immediately to establish the dialog and provide initial state.
    async fn send_initial_notify(
        subscription: &Subscription,
        services: &ServiceRegistry,
        ctx: &TransportContext,
    ) -> Result<()> {
        // Get transaction manager
        let Some(transaction_mgr) = services.transaction_mgr.get() else {
            warn!("Transaction manager not available, cannot send NOTIFY");
            return Ok(());
        };

        // Create UAC for generating NOTIFY
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Some(uri) => uri,
            None => {
                warn!("Invalid local_uri, cannot send NOTIFY");
                return Ok(());
            }
        };

        let uac = UserAgentClient::new(local_uri.clone(), local_uri.clone());

        let (content_type, body) = Self::build_notify_body(subscription);

        // Create initial NOTIFY with "active" state
        let mut notify = uac.create_notify(
            subscription,
            SubscriptionState::Active, // Initial state is always "active"
            body.as_deref(),
        );

        if let Some(content_type) = content_type {
            let _ = notify.headers.push("Content-Type", content_type);
            if let Some(body) = body.as_ref() {
                let _ = notify
                    .headers
                    .push("Content-Length", body.len().to_string());
            }
        }

        debug!(
            subscription_id = ?subscription.id,
            event = %subscription.id.event,
            "Sending initial NOTIFY"
        );

        // Send NOTIFY via transaction manager
        let tu = Arc::new(NotifyTransactionUser);
        let _key = transaction_mgr
            .start_client_transaction(notify, ctx.clone(), tu)
            .await?;

        Ok(())
    }

    fn build_notify_body(
        subscription: &Subscription,
    ) -> (Option<String>, Option<String>) {
        let event = subscription.id.event.as_str();
        match event {
            "presence" => {
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"{}\">\r\n\
  <tuple id=\"t1\">\r\n\
    <status><basic>open</basic></status>\r\n\
  </tuple>\r\n\
</presence>\r\n",
                    subscription.remote_uri.as_str()
                );
                (Some("application/pidf+xml".to_string()), Some(body))
            }
            "message-summary" => {
                let body = "Messages-Waiting: no\r\nVoice-Message: 0/0 (0/0)\r\n".to_string();
                (
                    Some("application/simple-message-summary".to_string()),
                    Some(body),
                )
            }
            "dialog" | "dialog-info" => {
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\
<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"1\" state=\"full\" entity=\"{}\">\r\n\
  <dialog id=\"d1\" call-id=\"{}\" direction=\"recipient\">\r\n\
    <state>confirmed</state>\r\n\
  </dialog>\r\n\
</dialog-info>\r\n",
                    subscription.remote_uri.as_str(),
                    subscription.id.call_id.as_str()
                );
                (Some("application/dialog-info+xml".to_string()), Some(body))
            }
            _ => (None, None),
        }
    }
}

#[async_trait]
impl RequestHandler for SubscribeHandler {
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        _ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()> {
        let call_id = header(&request.headers, "Call-ID")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        // Check if subscriptions are enabled
        if !services.config.enable_subscriptions() {
            warn!(call_id, "SUBSCRIBE rejected: subscriptions not enabled");
            let mut headers = sip_core::Headers::new();
            copy_headers(request, &mut headers);
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(501, "Not Implemented".into()),
                headers,
                bytes::Bytes::new(),
            );
            handle.send_final(response).await;
            return Ok(());
        }

        // Extract event package
        let event_package = match Self::extract_event_package(request) {
            Some(pkg) => pkg,
            None => {
                warn!(call_id, "SUBSCRIBE missing Event header");
                let bad_req = UserAgentServer::create_response(request, 400, "Bad Request");
                handle.send_final(bad_req).await;
                return Ok(());
            }
        };

        // Extract requested expiry (0 means unsubscribe)
        let requested_expiry = Self::extract_expiry(request).unwrap_or(3600);

        info!(
            call_id,
            event_package,
            expires = requested_expiry,
            "Processing SUBSCRIBE request"
        );

        // Check if auto-accept is enabled
        if !services.config.features.auto_accept_subscriptions {
            warn!(call_id, "SUBSCRIBE rejected: auto-accept disabled");
            let mut headers = sip_core::Headers::new();
            copy_headers(request, &mut headers);
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(603, "Decline".into()),
                headers,
                bytes::Bytes::new(),
            );
            handle.send_final(response).await;
            return Ok(());
        }

        // Parse local URI from config
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Some(uri) => uri,
            None => {
                warn!("Invalid local_uri in config");
                let error = UserAgentServer::create_response(request, 603, "Decline");
                handle.send_final(error).await;
                return Ok(());
            }
        };

        let contact_uri = local_uri.clone();

        // Create UAS and accept subscription
        let uas = UserAgentServer::new(local_uri, contact_uri);
        let result = uas.accept_subscribe(request, Some(requested_expiry));

        match result {
            Ok((response, mut subscription)) => {
                info!(
                    call_id,
                    event_package,
                    state = ?subscription.state,
                    expires = subscription.expires.as_secs(),
                    "Subscription created successfully"
                );

                if requested_expiry == 0 {
                    subscription.state = SubscriptionState::Terminated;
                }

                // Store subscription in manager
                services.subscription_mgr.insert(subscription.clone());

                // Send 200 OK
                handle.send_final(response).await;

                // Send initial NOTIFY as required by RFC 3265 §3.1.4
                if let Err(e) = Self::send_initial_notify(&subscription, services, _ctx).await {
                    warn!(
                        call_id,
                        event_package,
                        error = %e,
                        "Failed to send initial NOTIFY (RFC 3265 compliance issue)"
                    );
                } else {
                    info!(
                        call_id,
                        event_package,
                        "Initial NOTIFY sent successfully (RFC 3265 compliant)"
                    );
                }

                if requested_expiry == 0 {
                    services.subscription_mgr.remove(&subscription.id);
                }
            }
            Err(e) => {
                warn!(call_id, error = %e, "Failed to accept SUBSCRIBE");
                let error = uas.create_decline(request);
                handle.send_final(error).await;
            }
        }

        Ok(())
    }

    fn method(&self) -> &str {
        "SUBSCRIBE"
    }
}

/// Copy essential headers from request to response
fn copy_headers(request: &Request, headers: &mut sip_core::Headers) {
    if let Some(via) = header(&request.headers, "Via") {
        let _ = headers.push("Via", via.clone());
    }
    if let Some(from) = header(&request.headers, "From") {
        let _ = headers.push("From", from.clone());
    }
    if let Some(to) = header(&request.headers, "To") {
        let _ = headers.push("To", to.clone());
    }
    if let Some(call_id) = header(&request.headers, "Call-ID") {
        let _ = headers.push("Call-ID", call_id.clone());
    }
    if let Some(cseq) = header(&request.headers, "CSeq") {
        let _ = headers.push("CSeq", cseq.clone());
    }
}
