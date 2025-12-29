// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// PRACK request handler.
///
/// Implements RFC 3262 reliable provisional response acknowledgement.
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::warn;

use super::RequestHandler;
use crate::{proxy_utils, services::ServiceRegistry};

pub struct PrackHandler;

impl PrackHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequestHandler for PrackHandler {
    async fn handle(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        services: &ServiceRegistry,
    ) -> Result<()> {
        let call_id = header(request.headers(), "Call-ID")
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

        let dialog = match services.dialog_mgr.find_by_request(request) {
            Some(dialog) => dialog,
            None => {
                warn!(call_id, "PRACK received outside of dialog");
                let response = UserAgentServer::create_response(
                    request,
                    481,
                    "Call/Transaction Does Not Exist",
                );
                handle.send_final(response).await;
                return Ok(());
            }
        };

        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Ok(uri) => uri,
            Err(_) => {
                warn!(call_id, "Invalid local_uri, rejecting PRACK");
                let response = UserAgentServer::create_response(request, 500, "Server Error");
                handle.send_final(response).await;
                return Ok(());
            }
        };

        let contact_uri = local_uri.clone();
        let mut uas = UserAgentServer::new(local_uri, contact_uri);
        uas.dialog_manager = services.dialog_mgr.clone();
        uas.subscription_manager = services.subscription_mgr.clone();
        uas.rseq_manager = services.rseq_mgr.clone();
        uas.prack_validator = services.prack_validator.clone();

        let response = uas.handle_prack(request, &dialog)?;
        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "PRACK"
    }
}
