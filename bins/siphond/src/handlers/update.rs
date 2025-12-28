// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// UPDATE request handler.
///
/// Implements RFC 3311 mid-dialog session updates.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::{proxy_utils, sdp_utils, services::ServiceRegistry};

pub struct UpdateHandler;

impl UpdateHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequestHandler for UpdateHandler {
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

        let mut dialog = match services.dialog_mgr.find_by_request(request) {
            Some(dialog) => dialog,
            None => {
                warn!(call_id, "UPDATE received for unknown dialog");
                let response = UserAgentServer::create_response(
                    request,
                    481,
                    "Call/Transaction Does Not Exist",
                );
                handle.send_final(response).await;
                return Ok(());
            }
        };

        if dialog.update_from_request(request).is_err() {
            warn!(call_id, "UPDATE rejected: invalid CSeq or dialog state");
            let response = UserAgentServer::create_response(request, 400, "Bad Request");
            handle.send_final(response).await;
            return Ok(());
        }

        let sdp_body = if !request.body.is_empty() {
            match std::str::from_utf8(&request.body) {
                Ok(offer_str) => {
                    match sdp_utils::generate_sdp_answer(&services.config, offer_str) {
                        Ok(answer) => Some(answer),
                        Err(e) => {
                            warn!(call_id, error = %e, "Failed to generate SDP answer for UPDATE");
                            let response = UserAgentServer::create_response(
                                request,
                                488,
                                "Not Acceptable Here",
                            );
                            handle.send_final(response).await;
                            return Ok(());
                        }
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };

        let local_uri = sip_core::SipUri::parse(&services.config.local_uri)
            .ok_or_else(|| anyhow!("Invalid local_uri"))?;
        let contact_uri = local_uri.clone();
        let mut uas = UserAgentServer::new(local_uri, contact_uri);
        uas.dialog_manager = services.dialog_mgr.clone();
        uas.subscription_manager = services.subscription_mgr.clone();
        uas.rseq_manager = services.rseq_mgr.clone();
        uas.prack_validator = services.prack_validator.clone();

        let response = uas.create_ok(request, sdp_body.as_deref());
        dialog.update_from_response(&response);
        services.dialog_mgr.insert(dialog);

        info!(call_id, "UPDATE accepted");
        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "UPDATE"
    }
}
