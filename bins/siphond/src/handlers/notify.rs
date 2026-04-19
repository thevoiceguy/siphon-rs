// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! NOTIFY request handler.
//!
//! RFC 6665 §4.1.4: a NOTIFY arriving with no matching subscription MUST be
//! rejected with `481 Subscription Does Not Exist`. Without this handler the
//! generic dispatcher returns `501 Not Implemented`, which (a) violates the RFC
//! and (b) leaks the fact that NOTIFY is supported but the subscription
//! identifier is unknown — making subscription-state probing easy.

use anyhow::Result;
use async_trait::async_trait;
use sip_core::{Headers, Request, Response, StatusLine};
use sip_dialog::SubscriptionId;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use smol_str::SmolStr;
use tracing::{info, warn};

use super::RequestHandler;
use crate::services::ServiceRegistry;

pub struct NotifyHandler;

impl NotifyHandler {
    pub fn new() -> Self {
        Self
    }

    fn extract_tag(value: &str) -> Option<SmolStr> {
        value.split(';').find_map(|part| {
            let trimmed = part.trim();
            trimmed.strip_prefix("tag=").map(SmolStr::new)
        })
    }

    fn extract_event_package(request: &Request) -> Option<String> {
        let event = header(request.headers(), "Event")?;
        let package = event.split(';').next()?.trim();
        Some(package.to_string())
    }

    /// Looks up the subscription for an incoming NOTIFY using both possible
    /// tag orderings. RFC 6665 identifies a subscription by Call-ID + tags +
    /// event package, but the (from, to) pairing depends on which side of the
    /// dialog issued the NOTIFY — so try both before giving up.
    fn find_subscription(
        request: &Request,
        services: &ServiceRegistry,
    ) -> Option<sip_dialog::Subscription> {
        let call_id = header(request.headers(), "Call-ID")?.clone();
        let from = header(request.headers(), "From")?;
        let to = header(request.headers(), "To")?;
        let from_tag = Self::extract_tag(from)?;
        let to_tag = Self::extract_tag(to)?;
        let event = Self::extract_event_package(request)?;

        // Subscriber's view: we sent SUBSCRIBE, so our local-tag is the
        // SUBSCRIBE's From-tag. NOTIFY arrives with that tag in To.
        let id_subscriber =
            SubscriptionId::unchecked_new(call_id.clone(), to_tag.clone(), from_tag.clone(), &event);
        if let Some(sub) = services.subscription_mgr.get(&id_subscriber) {
            return Some(sub);
        }

        // Notifier's view (e.g. REFER implicit subscription): the SUBSCRIBE's
        // From-tag becomes the NOTIFY's To-tag, but the subscription was
        // stored with the SUBSCRIBE-side tags.
        let id_notifier =
            SubscriptionId::unchecked_new(call_id, from_tag, to_tag, &event);
        services.subscription_mgr.get(&id_notifier)
    }
}

#[async_trait]
impl RequestHandler for NotifyHandler {
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        _ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()> {
        let call_id = header(request.headers(), "Call-ID")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        let subscription = Self::find_subscription(request, services);

        if subscription.is_none() {
            warn!(
                call_id,
                "NOTIFY rejected: no matching subscription (RFC 6665 §4.1.4)"
            );
            send_status(request, handle, 481, "Subscription Does Not Exist").await;
            return Ok(());
        }

        info!(call_id, "NOTIFY accepted for known subscription");
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "NOTIFY"
    }
}

async fn send_status(
    request: &Request,
    handle: ServerTransactionHandle,
    code: u16,
    reason: &str,
) {
    let mut headers = Headers::new();
    for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
        if let Some(value) = header(request.headers(), name) {
            let _ = headers.push(name, value.clone());
        }
    }
    let status = match StatusLine::new(code, reason) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, code, "Failed to build NOTIFY rejection status line");
            return;
        }
    };
    match Response::new(status, headers, bytes::Bytes::new()) {
        Ok(response) => handle.send_final(response).await,
        Err(e) => warn!(error = %e, "Failed to build NOTIFY rejection response"),
    }
}
