/// SUBSCRIBE/NOTIFY request handler.
///
/// Implements RFC 3265 event notification:
/// 1. Accept SUBSCRIBE requests
/// 2. Create/update subscriptions
/// 3. Send 200 OK with Expires header
/// 4. (Future: Send initial NOTIFY)
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::services::ServiceRegistry;

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
            Ok((response, subscription)) => {
                info!(
                    call_id,
                    event_package,
                    state = ?subscription.state,
                    expires = subscription.expires.as_secs(),
                    "Subscription created successfully"
                );

                // Store subscription in manager
                services.subscription_mgr.insert(subscription.clone());

                // Send 200 OK
                handle.send_final(response).await;

                // TODO: Send initial NOTIFY as required by RFC 3265
                //
                // Implementation requires:
                // 1. Create UserAgentClient
                // 2. Generate NOTIFY request with create_notify()
                // 3. Create ClientTransactionUser callback for handling responses
                // 4. Extract destination from subscription Contact URI
                // 5. Call transaction_mgr.start_client_transaction()
                //
                // For now, this is deferred as it requires significant integration work.
                // See: bins/siphond/src/handlers/subscribe.rs:139

                if services.transaction_mgr.get().is_some() {
                    info!(
                        call_id,
                        event_package,
                        "TODO: Initial NOTIFY should be sent here (RFC 3265 compliance)"
                    );
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
        headers.push("Via".into(), via.clone());
    }
    if let Some(from) = header(&request.headers, "From") {
        headers.push("From".into(), from.clone());
    }
    if let Some(to) = header(&request.headers, "To") {
        headers.push("To".into(), to.clone());
    }
    if let Some(call_id) = header(&request.headers, "Call-ID") {
        headers.push("Call-ID".into(), call_id.clone());
    }
    if let Some(cseq) = header(&request.headers, "CSeq") {
        headers.push("CSeq".into(), cseq.clone());
    }
}
