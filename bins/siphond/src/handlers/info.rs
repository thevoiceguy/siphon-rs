// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// INFO request handler.
///
/// Accepts INFO requests and validates dialog when present.
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::{proxy_utils, services::ServiceRegistry};

pub struct InfoHandler;

impl InfoHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequestHandler for InfoHandler {
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()> {
        let call_id = header(&request.headers, "Call-ID")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        if services.config.enable_proxy() {
            proxy_utils::forward_request(
                request,
                services,
                ctx,
                call_id,
                proxy_utils::ProxyForwardOptions {
                    add_record_route: false,
                    rewrite_request_uri: false,
                },
            )
            .await?;
            return Ok(());
        }

        let dialog = services.dialog_mgr.find_by_request(request);
        if dialog.is_none() {
            warn!(call_id, "INFO received for unknown dialog");
            let response =
                UserAgentServer::create_response(request, 481, "Call/Transaction Does Not Exist");
            handle.send_final(response).await;
            return Ok(());
        }

        info!(call_id, len = request.body.len(), "INFO received");
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "INFO"
    }
}
