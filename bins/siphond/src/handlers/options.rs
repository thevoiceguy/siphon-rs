// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// OPTIONS request handler.
///
/// Responds with 200 OK including:
/// - Allow header (supported methods)
/// - Supported header (supported extensions)
/// - Accept header (supported content types)
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use sip_core::{Headers, Request, Response, StatusLine};
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use smol_str::SmolStr;
use tracing::info;

use super::RequestHandler;
use crate::services::ServiceRegistry;

pub struct OptionsHandler;

impl OptionsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Build Allow header based on configuration
    fn build_allow_header(services: &ServiceRegistry) -> SmolStr {
        let mut methods = vec!["OPTIONS", "ACK", "CANCEL"];

        if services.config.enable_calls() {
            methods.push("INVITE");
            methods.push("BYE");
            methods.push("UPDATE");
        }

        if services.config.enable_registrar() {
            methods.push("REGISTER");
        }

        if services.config.enable_subscriptions() {
            methods.push("SUBSCRIBE");
            methods.push("NOTIFY");
        }

        if services.config.features.enable_refer {
            methods.push("REFER");
        }

        if services.config.features.enable_prack {
            methods.push("PRACK");
        }

        SmolStr::new(methods.join(", "))
    }

    /// Build Supported header based on configuration
    fn build_supported_header(services: &ServiceRegistry) -> SmolStr {
        let mut extensions = vec!["path"];

        if services.config.features.enable_prack {
            extensions.push("100rel");
        }

        if services.config.features.enable_session_timers {
            extensions.push("timer");
        }

        if services.config.features.enable_refer {
            extensions.push("replaces");
        }

        SmolStr::new(extensions.join(", "))
    }
}

#[async_trait]
impl RequestHandler for OptionsHandler {
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        _ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()> {
        // Extract required headers from request
        let via = header(request.headers(), "Via")
            .cloned()
            .unwrap_or_default();
        let from = header(request.headers(), "From")
            .cloned()
            .unwrap_or_default();
        let mut to = header(request.headers(), "To").cloned().unwrap_or_default();
        let call_id = header(request.headers(), "Call-ID")
            .cloned()
            .unwrap_or_default();
        let cseq = header(request.headers(), "CSeq")
            .cloned()
            .unwrap_or_default();

        // Clone for logging (will be moved into headers)
        let call_id_log = call_id.clone();
        let from_log = from.clone();

        // Add to-tag if missing
        if !to.is_empty() && !to.contains(";tag=") {
            to = SmolStr::new(format!("{};tag=siphond-{}", to, rand::random::<u32>()));
        }

        // Build response headers
        let mut headers = Headers::new();
        let _ = headers.push("Via", via);
        let _ = headers.push("From", from);
        let _ = headers.push("To", to);
        let _ = headers.push("Call-ID", call_id);
        let _ = headers.push("CSeq", cseq);

        // Add capability headers
        let _ = headers.push("Allow", Self::build_allow_header(services));
        let _ = headers.push("Supported", Self::build_supported_header(services));
        let _ = headers.push(
            "Accept",
            SmolStr::new("application/sdp, application/sdp-answer"),
        );
        let _ = headers.push(
            "User-Agent",
            SmolStr::new(services.config.user_agent.clone()),
        );

        let response = Response::new(
            StatusLine::new(200, "OK").expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response");

        info!(
            call_id = %call_id_log,
            from = %from_log,
            "OPTIONS request handled successfully"
        );

        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "OPTIONS"
    }
}
