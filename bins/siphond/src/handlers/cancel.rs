// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// CANCEL request handler.
///
/// Implements RFC 3261 §9.2 CANCEL method:
/// 1. Accept CANCEL with 200 OK
/// 2. Send 487 Request Terminated to original INVITE
/// 3. In B2BUA mode: Forward CANCEL to the other leg
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::{proxy_utils, services::ServiceRegistry};

pub struct CancelHandler;

impl CancelHandler {
    pub fn new() -> Self {
        Self
    }

    /// Create a 487 Request Terminated response for the INVITE (from PendingInvite)
    fn create_487_response(pending: &crate::invite_state::PendingInvite) -> sip_core::Response {
        use sip_core::{Headers, Response, StatusLine};

        let mut headers = Headers::new();

        // Copy essential headers from INVITE (including To-tag if known)
        let _ = headers.push("Via", pending.via.clone());
        let _ = headers.push("From", pending.from.clone());
        let _ = headers.push("To", pending.to.clone());
        let _ = headers.push("Call-ID", pending.call_id.clone());
        let _ = headers.push("CSeq", pending.cseq.clone());

        let _ = headers.push("Content-Length", "0");

        Response::new(
            StatusLine::new(487, "Request Terminated".into()),
            headers,
            bytes::Bytes::new(),
        )
    }

    /// Create a 487 Request Terminated response for the INVITE (from Request - B2BUA mode)
    fn create_487_from_request(invite_request: &Request) -> sip_core::Response {
        use sip_core::{Headers, Response, StatusLine};

        let mut headers = Headers::new();

        // Copy essential headers from INVITE
        if let Some(via) = header(&invite_request.headers, "Via") {
            let _ = headers.push("Via", via.clone());
        }
        if let Some(from) = header(&invite_request.headers, "From") {
            let _ = headers.push("From", from.clone());
        }
        if let Some(to) = header(&invite_request.headers, "To") {
            let _ = headers.push("To", to.clone());
        }
        if let Some(call_id) = header(&invite_request.headers, "Call-ID") {
            let _ = headers.push("Call-ID", call_id.clone());
        }
        if let Some(cseq) = header(&invite_request.headers, "CSeq") {
            let _ = headers.push("CSeq", cseq.clone());
        }

        let _ = headers.push("Content-Length", "0");

        Response::new(
            StatusLine::new(487, "Request Terminated".into()),
            headers,
            bytes::Bytes::new(),
        )
    }

    /// Forward CANCEL to callee in B2BUA mode
    async fn forward_cancel_to_callee(
        services: &ServiceRegistry,
        incoming_call_id: &str,
    ) -> Result<()> {
        // Look up the call leg pair
        let call_leg = match services.b2bua_state.find_call_leg_by_incoming(incoming_call_id) {
            Some(leg) => leg,
            None => {
                warn!(
                    incoming_call_id,
                    "No call leg found for CANCEL - may have already completed"
                );
                return Ok(());
            }
        };

        info!(
            incoming_call_id,
            outgoing_call_id = %call_leg.outgoing_call_id,
            "Forwarding CANCEL to callee"
        );

        // Create CANCEL request matching the outgoing INVITE
        // CANCEL must have same Request-URI, To, From, Call-ID, and CSeq number (but method=CANCEL)
        let mut cancel_req = call_leg.outgoing_invite.clone();
        cancel_req.start.method = sip_core::Method::Cancel;

        // Update CSeq header to CANCEL (keep same number)
        if let Some(cseq_value) = header(&cancel_req.headers, "CSeq") {
            // Extract CSeq number: "1 INVITE" -> "1 CANCEL"
            if let Some(cseq_num) = cseq_value.split_whitespace().next() {
                let new_cseq = format!("{} CANCEL", cseq_num);
                // Remove old CSeq and add new one
                let mut new_headers = sip_core::Headers::new();
                for h in cancel_req.headers.iter() {
                    if !h.name().eq_ignore_ascii_case("CSeq") {
                        let _ = new_headers.push(h.name(), h.value());
                    }
                }
                let _ = new_headers.push("CSeq", new_cseq);
                cancel_req.headers = new_headers;
            }
        }

        // Clear body (CANCEL has no body)
        cancel_req.body = bytes::Bytes::new();

        // Update Content-Length
        let mut new_headers = sip_core::Headers::new();
        for h in cancel_req.headers.iter() {
            if !h.name().eq_ignore_ascii_case("Content-Length") {
                let _ = new_headers.push(h.name(), h.value());
            }
        }
        let _ = new_headers.push("Content-Length", "0");
        cancel_req.headers = new_headers;

        // Send CANCEL via TCP to callee
        let callee_addr = format!(
            "{}:{}",
            call_leg.callee_contact.host,
            call_leg.callee_contact.port.unwrap_or(5060)
        )
        .parse::<std::net::SocketAddr>()?;

        let payload = sip_parse::serialize_request(&cancel_req);
        sip_transport::send_tcp(&callee_addr, &payload).await?;

        info!(
            incoming_call_id,
            callee = %callee_addr,
            "CANCEL forwarded to callee successfully"
        );

        Ok(())
    }
}

#[async_trait]
impl RequestHandler for CancelHandler {
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

        info!(call_id, "Processing CANCEL request");

        if services.config.enable_proxy() {
            proxy_utils::forward_request(
                request,
                services,
                _ctx,
                call_id,
                proxy_utils::ProxyForwardOptions {
                    add_record_route: false,
                    rewrite_request_uri: false,
                },
            )
            .await?;
            return Ok(());
        }

        // Parse local URI from config
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Some(uri) => uri,
            None => {
                warn!("Invalid local_uri in config");
                let error = UserAgentServer::create_response(request, 500, "Server Error");
                handle.send_final(error).await;
                return Ok(());
            }
        };

        let contact_uri = local_uri.clone();

        // Create UAS and handle CANCEL
        let uas = UserAgentServer::new(local_uri, contact_uri);

        match uas.handle_cancel(request) {
            Ok(response) => {
                info!(call_id, "CANCEL accepted with 200 OK");

                // Send 200 OK to CANCEL
                handle.send_final(response).await;

                // Send 487 Request Terminated to the original INVITE transaction
                if services.config.enable_b2bua() {
                    // Look up the call leg to get the response channel
                    if let Some(call_leg) = services.b2bua_state.find_call_leg_by_incoming(call_id)
                    {
                        // Create 487 Request Terminated response for the INVITE
                        let response_487 = Self::create_487_from_request(&call_leg.caller_request);

                        // Send 487 through the response channel to terminate the INVITE
                        if call_leg.response_tx.send(response_487).is_ok() {
                            info!(call_id, "Sent 487 Request Terminated to INVITE transaction");
                        } else {
                            warn!(
                                call_id,
                                "Failed to send 487 - response channel closed"
                            );
                        }

                        // Forward CANCEL to the callee
                        if let Err(e) = Self::forward_cancel_to_callee(services, call_id).await {
                            warn!(
                                call_id,
                                error = %e,
                                "Failed to forward CANCEL to callee"
                            );
                        }

                        // Clean up the call leg after cancellation
                        if let Some(outgoing_call_id) = services
                            .b2bua_state
                            .find_call_leg_by_incoming(call_id)
                            .map(|leg| leg.outgoing_call_id)
                        {
                            services.b2bua_state.remove_call_leg(&outgoing_call_id);
                            info!(call_id, "Call leg removed after CANCEL");
                        }
                    } else {
                        warn!(
                            call_id,
                            "No call leg found - INVITE may have already completed"
                        );
                    }
                } else {
                    // Non-B2BUA mode: Send 487 to the original INVITE transaction
                    let pending_key =
                        crate::invite_state::InviteStateManager::key_from_request(request);
                    if let Some((key, pending_invite)) = pending_key
                        .as_deref()
                        .and_then(|key| services.invite_state.get_pending_invite(key).map(|p| (key.to_string(), p)))
                    {
                        info!(
                            call_id,
                            "Sending 487 Request Terminated to original INVITE transaction"
                        );

                        // Create 487 response using cached INVITE headers
                        let response_487 = Self::create_487_response(&pending_invite);

                        // Send 487 through the INVITE transaction handle
                        pending_invite.handle.send_final(response_487).await;

                        // Remove from pending invites
                        services.invite_state.remove_pending_invite(&key);

                        info!(call_id, "Sent 487 Request Terminated to INVITE transaction");
                    } else {
                        warn!(
                            call_id,
                            "No pending INVITE found - may have already completed"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(call_id, error = %e, "Failed to handle CANCEL");
                let error = UserAgentServer::create_response(request, 500, "Server Error");
                handle.send_final(error).await;
            }
        }

        Ok(())
    }

    fn method(&self) -> &str {
        "CANCEL"
    }
}
