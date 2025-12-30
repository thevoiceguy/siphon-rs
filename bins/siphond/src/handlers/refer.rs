// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// REFER request handler.
///
/// Implements RFC 3515 call transfer:
/// 1. Accept REFER requests
/// 2. Create implicit subscription to "refer" event
/// 3. Send 202 Accepted
/// 4. Initiate INVITE to transfer target
/// 5. Send NOTIFY messages with sipfrag progress
///
/// ## Transport Support
///
/// REFER is fully supported across all transports when the UDP socket is available:
/// - **UDP**: ACKs sent via UDP socket exposed in TransportContext (must be populated by caller)
/// - **TCP**: ACKs sent via TCP connection pool
/// - **TLS**: ACKs sent via TLS connection pool
/// - **WebSocket**: ACKs sent via WebSocket connection
///
/// ### ACK for 2xx Responses
///
/// Per RFC 3261 §13.2.2.4, the ACK for a 2xx response to INVITE is sent **outside**
/// the transaction layer (unlike ACKs for error responses which are part of the
/// transaction). This handler implements the ACK sending directly for all transports.
///
/// The UDP socket is provided via `TransportContext.udp_socket`, which is populated
/// from the ServiceRegistry during context creation in siphond. Embedders must set
/// it explicitly to enable UDP ACKs.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sip_core::{Headers, Request, Response, SipUri};
use sip_dialog::{Subscription, SubscriptionId, SubscriptionState};
use sip_parse::header;
use sip_transaction::{
    ClientTransactionUser, ServerTransactionHandle, TransactionKey, TransportContext,
};
use sip_uac::UserAgentClient;
use sip_uas::UserAgentServer;
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::RequestHandler;
use crate::{sdp_utils, services::ServiceRegistry};

pub struct ReferHandler;

/// Transaction user for REFER NOTIFY messages.
struct ReferNotifyTransactionUser;

#[async_trait]
impl ClientTransactionUser for ReferNotifyTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, _response: &Response) {}

    async fn on_final(&self, _key: &TransactionKey, _response: &Response) {}

    async fn on_terminated(&self, _key: &TransactionKey, _reason: &str) {}

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
        _is_2xx: bool,
    ) {
    }

    async fn send_prack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
    ) {
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {
        warn!("REFER NOTIFY transport error");
    }
}

struct ReferTransferTransactionUser {
    uac: UserAgentClient,
    invite: Request,
    uas: UserAgentServer,
    subscription: Arc<Mutex<Subscription>>,
    notify_ctx: TransportContext,
    transaction_mgr: Arc<sip_transaction::TransactionManager>,
    config: Arc<crate::config::DaemonConfig>,
}

impl ReferTransferTransactionUser {
    async fn send_notify(&self, status_code: u16, reason: &str) {
        let notify = {
            let mut subscription = self.subscription.lock().await;
            self.uas
                .create_notify_sipfrag(&mut subscription, status_code, reason)
        };

        let tu = Arc::new(ReferNotifyTransactionUser);
        if let Err(e) = self
            .transaction_mgr
            .start_client_transaction(notify, self.notify_ctx.clone(), tu)
            .await
        {
            warn!(error = %e, "Failed to send REFER NOTIFY");
        }
    }
}

#[async_trait]
impl ClientTransactionUser for ReferTransferTransactionUser {
    async fn on_provisional(&self, _key: &TransactionKey, response: &Response) {
        self.send_notify(response.code(), response.reason()).await;
    }

    async fn on_final(&self, _key: &TransactionKey, response: &Response) {
        self.send_notify(response.code(), response.reason()).await;
    }

    async fn on_terminated(&self, _key: &TransactionKey, reason: &str) {
        self.send_notify(503, reason).await;
    }

    async fn send_ack(
        &self,
        _key: &TransactionKey,
        response: Response,
        ctx: &TransportContext,
        is_2xx: bool,
    ) {
        if !is_2xx {
            return;
        }

        let invite_has_sdp = !self.invite.body().is_empty();
        let response_has_sdp = !response.body().is_empty();
        let late_offer = !invite_has_sdp && response_has_sdp;

        let sdp_body = if late_offer {
            match std::str::from_utf8(response.body()) {
                Ok(offer_str) => match sdp_utils::generate_sdp_answer(&self.config, offer_str) {
                    Ok(answer) => Some(answer),
                    Err(e) => {
                        warn!(error = %e, "Failed to generate SDP answer for REFER ACK");
                        None
                    }
                },
                Err(_) => None,
            }
        } else {
            None
        };

        let ack = self
            .uac
            .create_ack(&self.invite, &response, sdp_body.as_deref());
        let payload = sip_parse::serialize_request(&ack);

        match ctx.transport {
            sip_transaction::TransportKind::Tcp => {
                if let Err(e) = sip_transport::send_tcp(&ctx.peer, &payload).await {
                    warn!(error = %e, "Failed to send REFER ACK via TCP");
                }
            }
            sip_transaction::TransportKind::Tls => {
                if let Some(writer) = &ctx.stream {
                    if let Err(e) = sip_transport::send_stream(
                        sip_transport::TransportKind::Tls,
                        writer,
                        bytes::Bytes::from(payload.to_vec()),
                    )
                    .await
                    {
                        warn!(error = %e, "Failed to send REFER ACK via TLS stream");
                    }
                } else {
                    warn!(
                        "REFER ACK over TLS not sent - TLS stream not available in context. \
                         This indicates a missing stream for the inbound TLS connection."
                    );
                }
            }
            sip_transaction::TransportKind::Ws | sip_transaction::TransportKind::Wss => {
                #[cfg(feature = "ws")]
                {
                    if let Some(ws_uri) = ctx.ws_uri.as_deref() {
                        let data = bytes::Bytes::from(payload.to_vec());
                        let result = if ctx.transport == sip_transaction::TransportKind::Wss {
                            sip_transport::send_wss(ws_uri, data).await
                        } else {
                            sip_transport::send_ws(ws_uri, data).await
                        };
                        if let Err(e) = result {
                            warn!(error = %e, "Failed to send REFER ACK via WS/WSS");
                        }
                    }
                }
            }
            sip_transaction::TransportKind::Udp => {
                // Send ACK over UDP using the socket from TransportContext
                if let Some(socket) = &ctx.udp_socket {
                    if let Err(e) =
                        sip_transport::send_udp(socket.as_ref(), &ctx.peer, &payload).await
                    {
                        warn!(error = %e, "Failed to send REFER ACK via UDP");
                    }
                } else {
                    // Fallback: UDP socket not available in context
                    warn!(
                        "REFER ACK over UDP not sent - UDP socket not available in context. \
                         This should not happen with current architecture."
                    );
                }
            }
            _ => {
                warn!("REFER ACK transport not supported");
            }
        }
    }

    async fn send_prack(
        &self,
        _key: &TransactionKey,
        _response: Response,
        _ctx: &TransportContext,
    ) {
    }

    async fn on_transport_error(&self, _key: &TransactionKey) {
        self.send_notify(503, "Transport Error").await;
    }
}

impl ReferHandler {
    pub fn new() -> Self {
        Self
    }

    /// Extract Refer-To URI from header
    fn extract_refer_to(request: &Request) -> Option<String> {
        let refer_to = header(request.headers(), "Refer-To")?;
        Some(refer_to.to_string())
    }

    /// Check if this is an attended transfer (has Replaces header in Refer-To)
    fn is_attended_transfer(refer_to: &str) -> bool {
        refer_to.contains("Replaces=") || refer_to.contains("Replaces%3D")
    }

    fn extract_tag(value: &str) -> Option<SmolStr> {
        value.split(';').find_map(|part| {
            let trimmed = part.trim();
            trimmed.strip_prefix("tag=").map(SmolStr::new)
        })
    }

    fn extract_replaces(value: &str) -> Option<String> {
        let decoded = value.replace("%3D", "=");
        let start = decoded.find("Replaces=")? + "Replaces=".len();
        let tail = &decoded[start..];
        #[allow(clippy::manual_pattern_char_comparison)]
        let end = tail
            .find(|c: char| c == ';' || c == '>' || c == '&')
            .unwrap_or(tail.len());
        Some(tail[..end].to_string())
    }

    fn build_refer_subscription(
        request: &Request,
        response: &Response,
        local_uri: SipUri,
    ) -> Result<Subscription> {
        let call_id = header(request.headers(), "Call-ID")
            .ok_or_else(|| anyhow!("Missing Call-ID"))?
            .clone();
        let from = header(request.headers(), "From").ok_or_else(|| anyhow!("Missing From"))?;
        let to = header(response.headers(), "To").ok_or_else(|| anyhow!("Missing To"))?;
        let from_tag =
            Self::extract_tag(from.as_str()).ok_or_else(|| anyhow!("Missing From tag"))?;
        let to_tag = Self::extract_tag(to).ok_or_else(|| anyhow!("Missing To tag"))?;

        let remote_uri = sdp_utils::parse_name_addr_uri(from.as_str())
            .ok_or_else(|| anyhow!("Invalid From URI"))?;

        let contact = header(request.headers(), "Contact")
            .and_then(|contact| sdp_utils::parse_name_addr_uri(contact.as_str()))
            .unwrap_or_else(|| remote_uri.clone());

        let local_cseq = header(request.headers(), "CSeq")
            .and_then(|cseq| cseq.split_whitespace().next())
            .and_then(|cseq| cseq.parse::<u32>().ok())
            .unwrap_or(1);

        let subscription_id = SubscriptionId::unchecked_new(call_id, from_tag, to_tag, "refer");
        Ok(Subscription::unchecked_new(
            subscription_id,
            SubscriptionState::Active,
            local_uri,
            remote_uri,
            contact,
            Duration::from_secs(3600),
            local_cseq,
            0, // remote_cseq
        ))
    }

    async fn send_notify(
        uas: &UserAgentServer,
        subscription: &mut Subscription,
        status: u16,
        reason: &str,
        services: &ServiceRegistry,
        ctx: &TransportContext,
    ) {
        let Some(transaction_mgr) = services.transaction_mgr.get() else {
            warn!("Transaction manager not available, cannot send REFER NOTIFY");
            return;
        };
        let notify = uas.create_notify_sipfrag(subscription, status, reason);
        let tu = Arc::new(ReferNotifyTransactionUser);
        if let Err(e) = transaction_mgr
            .start_client_transaction(notify, ctx.clone(), tu)
            .await
        {
            warn!(error = %e, "Failed to send REFER NOTIFY");
        }
    }
}

#[async_trait]
impl RequestHandler for ReferHandler {
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

        // Check if REFER is enabled
        if !services.config.features.enable_refer {
            warn!(call_id, "REFER rejected: feature not enabled");
            let mut headers = sip_core::Headers::new();
            copy_headers(request, &mut headers);
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(501, "Not Implemented").expect("valid status line"),
                headers,
                bytes::Bytes::new(),
            )
            .expect("valid response");
            handle.send_final(response).await;
            return Ok(());
        }

        // Extract Refer-To header
        let refer_to = match Self::extract_refer_to(request) {
            Some(target) => target,
            None => {
                warn!(call_id, "REFER missing Refer-To header");
                let bad_req = UserAgentServer::create_response(request, 400, "Bad Request");
                handle.send_final(bad_req).await;
                return Ok(());
            }
        };

        let is_attended = Self::is_attended_transfer(&refer_to);

        info!(
            call_id,
            refer_to,
            attended = is_attended,
            "Processing REFER request"
        );

        // Check if there's a dialog (REFER is typically in-dialog)
        let dialog = services.dialog_mgr.find_by_request(request);

        if dialog.is_none() {
            warn!(
                call_id,
                "REFER received outside of a dialog - rejecting with 481"
            );
            let mut headers = sip_core::Headers::new();
            copy_headers(request, &mut headers);
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(481, "Call/Transaction Does Not Exist")
                    .expect("valid status line"),
                headers,
                bytes::Bytes::new(),
            )
            .expect("valid response");
            handle.send_final(response).await;
            return Ok(());
        }

        let dialog = dialog.unwrap();

        // Parse local URI from config
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Ok(uri) => uri,
            Err(_) => {
                warn!("Invalid local_uri in config");
                let error = UserAgentServer::reject_refer(request, 603, "Decline");
                handle.send_final(error).await;
                return Ok(());
            }
        };

        let contact_uri = local_uri.clone();

        // Create UAS and accept REFER
        let uas = UserAgentServer::new(local_uri.clone(), contact_uri.clone());
        let result = uas.accept_refer(request, &dialog);

        match result {
            Ok((response, refer_to_target)) => {
                info!(call_id, refer_to = refer_to_target, "REFER accepted");

                let response_for_subscription = response.clone();

                // Send 202 Accepted
                handle.send_final(response).await;

                let mut uas = UserAgentServer::new(local_uri.clone(), contact_uri.clone());
                uas.dialog_manager = services.dialog_mgr.clone();
                uas.subscription_manager = services.subscription_mgr.clone();
                uas.rseq_manager = services.rseq_mgr.clone();
                uas.prack_validator = services.prack_validator.clone();

                let mut subscription = match Self::build_refer_subscription(
                    request,
                    &response_for_subscription,
                    local_uri.clone(),
                ) {
                    Ok(subscription) => subscription,
                    Err(e) => {
                        warn!(call_id, error = %e, "Failed to create REFER subscription");
                        return Ok(());
                    }
                };

                services.subscription_mgr.insert(subscription.clone());

                Self::send_notify(&uas, &mut subscription, 100, "Trying", services, _ctx).await;

                let refer_uri = match sdp_utils::parse_name_addr_uri(&refer_to_target) {
                    Some(uri) => uri,
                    None => {
                        warn!(call_id, "Invalid Refer-To URI, sending failure NOTIFY");
                        Self::send_notify(
                            &uas,
                            &mut subscription,
                            400,
                            "Bad Request",
                            services,
                            _ctx,
                        )
                        .await;
                        return Ok(());
                    }
                };

                let target_port = refer_uri.port().unwrap_or(5060);
                let target_addr = format!("{}:{}", refer_uri.host(), target_port);
                let Ok(target_addr) = target_addr.parse::<std::net::SocketAddr>() else {
                    warn!(call_id, "Invalid Refer-To target address");
                    Self::send_notify(&uas, &mut subscription, 400, "Bad Request", services, _ctx)
                        .await;
                    return Ok(());
                };

                let transport_param: Option<&SmolStr> = refer_uri
                    .params()
                    .get(&SmolStr::new("transport"))
                    .and_then(|value| value.as_ref());
                let transport_param = transport_param.map(|value| value.to_ascii_lowercase());
                let transport = match transport_param.as_deref() {
                    Some("ws") => sip_transaction::TransportKind::Ws,
                    Some("wss") => sip_transaction::TransportKind::Wss,
                    Some("tls") => sip_transaction::TransportKind::Tls,
                    Some("udp") => sip_transaction::TransportKind::Udp,
                    _ => sip_transaction::TransportKind::Tcp,
                };

                let ws_uri = match transport {
                    sip_transaction::TransportKind::Ws => {
                        Some(format!("ws://{}:{}", refer_uri.host(), target_port))
                    }
                    sip_transaction::TransportKind::Wss => {
                        Some(format!("wss://{}:{}", refer_uri.host(), target_port))
                    }
                    _ => None,
                };

                let sdp_offer = match &services.config.sdp_profile {
                    crate::config::SdpProfile::None => None,
                    _ => match sdp_utils::generate_sdp_offer(&services.config) {
                        Ok(offer) => Some(offer),
                        Err(e) => {
                            warn!(call_id, error = %e, "Failed to generate SDP offer");
                            Self::send_notify(
                                &uas,
                                &mut subscription,
                                488,
                                "Not Acceptable Here",
                                services,
                                _ctx,
                            )
                            .await;
                            return Ok(());
                        }
                    },
                };

                let uac = UserAgentClient::new(local_uri.clone(), contact_uri.clone());
                let mut invite = uac.create_invite(&refer_uri, sdp_offer.as_deref());

                if let Some(replaces) = Self::extract_replaces(&refer_to_target) {
                    let _ = invite.headers_mut().push("Replaces", replaces);
                }

                let transport_name = match transport {
                    sip_transaction::TransportKind::Udp => "UDP",
                    sip_transaction::TransportKind::Tcp => "TCP",
                    sip_transaction::TransportKind::Tls => "TLS",
                    sip_transaction::TransportKind::Ws => "WS",
                    sip_transaction::TransportKind::Wss => "WSS",
                    sip_transaction::TransportKind::Sctp => "SCTP",
                    sip_transaction::TransportKind::TlsSctp => "TLS-SCTP",
                };

                // Find and replace the Via header
                let mut new_headers = Headers::new();
                let mut via_replaced = false;
                for header in invite.headers().iter() {
                    if !via_replaced && header.name().eq_ignore_ascii_case("Via") {
                        let branch = sip_transaction::branch_from_via(header.value())
                            .filter(|value| !value.is_empty())
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| sip_transaction::generate_branch_id().to_string());
                        let new_via =
                            format!("SIP/2.0/{} placeholder;branch={}", transport_name, branch);
                        new_headers.push(header.name(), new_via).unwrap();
                        via_replaced = true;
                    } else {
                        new_headers.push(header.name(), header.value()).unwrap();
                    }
                }
                *invite.headers_mut() = new_headers;

                let ctx = TransportContext::new(transport, target_addr, None)
                    .with_ws_uri(ws_uri)
                    .with_udp_socket(services.udp_socket.get().cloned());
                let Some(transaction_mgr) = services.transaction_mgr.get() else {
                    warn!(
                        call_id,
                        "Transaction manager not available, cannot initiate transfer"
                    );
                    return Ok(());
                };

                let subscription = Arc::new(Mutex::new(subscription));
                let transfer_user = ReferTransferTransactionUser {
                    uac,
                    invite: invite.clone(),
                    uas,
                    subscription,
                    notify_ctx: _ctx.clone(),
                    transaction_mgr: transaction_mgr.clone(),
                    config: services.config.clone(),
                };

                info!(
                    call_id,
                    refer_to = refer_to_target,
                    attended = is_attended,
                    "Initiating REFER transfer INVITE"
                );

                if let Err(e) = transaction_mgr
                    .start_client_transaction(invite, ctx, Arc::new(transfer_user))
                    .await
                {
                    warn!(call_id, error = %e, "Failed to start REFER transfer INVITE");
                }
            }
            Err(e) => {
                warn!(call_id, error = %e, "Failed to accept REFER");
                let error = uas.create_decline(request);
                handle.send_final(error).await;
            }
        }

        Ok(())
    }

    fn method(&self) -> &str {
        "REFER"
    }
}

/// Copy essential headers from request to response
fn copy_headers(request: &Request, headers: &mut sip_core::Headers) {
    if let Some(via) = header(request.headers(), "Via") {
        let _ = headers.push("Via", via.clone());
    }
    if let Some(from) = header(request.headers(), "From") {
        let _ = headers.push("From", from.clone());
    }
    if let Some(to) = header(request.headers(), "To") {
        let _ = headers.push("To", to.clone());
    }
    if let Some(call_id) = header(request.headers(), "Call-ID") {
        let _ = headers.push("Call-ID", call_id.clone());
    }
    if let Some(cseq) = header(request.headers(), "CSeq") {
        let _ = headers.push("CSeq", cseq.clone());
    }
}
