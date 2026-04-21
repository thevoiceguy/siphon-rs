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
            match self
                .uas
                .create_notify_sipfrag(&mut subscription, status_code, reason)
            {
                Ok(notify) => notify,
                Err(e) => {
                    warn!(error = %e, status_code, reason, "Failed to create REFER NOTIFY sipfrag");
                    return;
                }
            }
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

        match ctx.transport() {
            sip_transaction::TransportKind::Tcp => {
                if let Err(e) = sip_transport::send_tcp(&ctx.peer(), &payload).await {
                    warn!(error = %e, "Failed to send REFER ACK via TCP");
                }
            }
            sip_transaction::TransportKind::Tls => {
                if let Some(writer) = &ctx.stream() {
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
                        let result = if ctx.transport() == sip_transaction::TransportKind::Wss {
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
                if let Some(socket) = &ctx.udp_socket() {
                    if let Err(e) =
                        sip_transport::send_udp(socket.as_ref(), &ctx.peer(), &payload).await
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

    /// Extract the Replaces URI-header value from a Refer-To target and
    /// URL-decode it into its on-the-wire SIP header form.
    ///
    /// RFC 3891 Replaces value: `call-id;to-tag=...;from-tag=...[;early-only]`
    /// inside a URI is %-encoded (`;` → `%3B`, `=` → `%3D`). Earlier code
    /// only decoded `%3D`, leaving `%3B` literals that broke the receiving
    /// side's parser.
    ///
    /// The returned value is rejected unless it has both `to-tag` and
    /// `from-tag` parameters, so a malformed Refer-To cannot turn into an
    /// INVITE that misleads the transfer target.
    fn extract_replaces(value: &str) -> Option<String> {
        // Find the URI-headers segment (after `?`) so we don't accidentally
        // match `Replaces=` inside the user/host portion.
        let headers_start = value.find('?')? + 1;
        let after_q = &value[headers_start..];
        // Trim a trailing `>` if the caller passed a name-addr verbatim.
        let after_q = after_q.strip_suffix('>').unwrap_or(after_q);

        for pair in after_q.split('&') {
            let (name, raw_value) = pair.split_once('=')?;
            if !name.eq_ignore_ascii_case("Replaces") {
                continue;
            }
            let decoded = percent_decode(raw_value);
            // Defensive shape check: must contain to-tag and from-tag.
            let lower = decoded.to_ascii_lowercase();
            if !lower.contains("to-tag=") || !lower.contains("from-tag=") {
                return None;
            }
            return Some(decoded);
        }
        None
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
        let notify = match uas.create_notify_sipfrag(subscription, status, reason) {
            Ok(notify) => notify,
            Err(e) => {
                warn!(error = %e, status, reason, "Failed to create REFER NOTIFY sipfrag");
                return;
            }
        };
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

            // Try to create and send 501 response, but don't crash if it fails
            match sip_core::StatusLine::new(501, "Not Implemented") {
                Ok(status_line) => {
                    match sip_core::Response::new(status_line, headers, bytes::Bytes::new()) {
                        Ok(response) => {
                            handle.send_final(response).await;
                        }
                        Err(e) => {
                            warn!(call_id, error = %e, "Failed to create 501 response for disabled REFER");
                        }
                    }
                }
                Err(e) => {
                    warn!(call_id, error = %e, "Failed to create status line for 501 response");
                }
            }
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

            // Try to create and send 481 response, but don't crash if it fails
            match sip_core::StatusLine::new(481, "Call/Transaction Does Not Exist") {
                Ok(status_line) => {
                    match sip_core::Response::new(status_line, headers, bytes::Bytes::new()) {
                        Ok(response) => {
                            handle.send_final(response).await;
                        }
                        Err(e) => {
                            warn!(call_id, error = %e, "Failed to create 481 response for out-of-dialog REFER");
                        }
                    }
                }
                Err(e) => {
                    warn!(call_id, error = %e, "Failed to create status line for 481 response");
                }
            }
            return Ok(());
        }

        // At this point dialog must be Some because we handled None case above
        let Some(dialog) = dialog else {
            // This should be unreachable due to logic above, but handle gracefully
            warn!(call_id, "Unexpected None dialog after guard check");
            let mut headers = sip_core::Headers::new();
            copy_headers(request, &mut headers);

            // Try to create and send 481 response, but don't crash if it fails
            match sip_core::StatusLine::new(481, "Call/Transaction Does Not Exist") {
                Ok(status_line) => {
                    match sip_core::Response::new(status_line, headers, bytes::Bytes::new()) {
                        Ok(response) => {
                            handle.send_final(response).await;
                        }
                        Err(e) => {
                            warn!(call_id, error = %e, "Failed to create 481 response after guard check");
                        }
                    }
                }
                Err(e) => {
                    warn!(call_id, error = %e, "Failed to create status line for 481 response");
                }
            }
            return Ok(());
        };

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

                let _ = services.subscription_mgr.insert(subscription.clone());

                Self::send_notify(&uas, &mut subscription, 100, "Trying", services, _ctx).await;

                // Strip URI headers (?Route=, ?From=, etc.) before using the
                // Refer-To target as a request URI. RFC 3261 §19.1.5 forbids
                // copying URI headers into outgoing fields, and an attacker
                // who controls the Refer-To string would otherwise inject
                // arbitrary SIP headers into the triggered INVITE's
                // Request-URI / To / Route. Replaces is extracted separately
                // below from the original (still-encoded) refer-to string.
                let refer_uri = match sdp_utils::parse_name_addr_uri(&refer_to_target) {
                    Some(uri) => uri.without_uri_headers(),
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

                // SSRF guard: the Refer-To target is attacker-controlled (the
                // transferor dictates it via the REFER). Without a filter
                // the daemon will dial whatever address they name — including
                // 127.0.0.1 to probe loopback services, RFC 1918 ranges to
                // scan the internal network, or 0.0.0.0 / multicast.
                if !refer_target_allowed(&target_addr, &services.config) {
                    warn!(
                        call_id,
                        target = %target_addr,
                        "Refer-To target blocked by SSRF policy (non-routable address)"
                    );
                    Self::send_notify(&uas, &mut subscription, 403, "Forbidden", services, _ctx)
                        .await;
                    return Ok(());
                }

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
                        if let Err(e) = new_headers.push(header.name(), new_via) {
                            warn!(
                                header = %header.name(),
                                error = %e,
                                "Failed to push Via header to REFER INVITE, skipping"
                            );
                        }
                        via_replaced = true;
                    } else {
                        if let Err(e) = new_headers.push(header.name(), header.value()) {
                            warn!(
                                header = %header.name(),
                                error = %e,
                                "Failed to push header to REFER INVITE, skipping"
                            );
                        }
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

/// Minimal percent-decoder for ASCII URI segments. Bytes that fail to form
/// valid UTF-8 are dropped (Replaces values are ASCII per RFC 3891).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns `true` if the daemon is allowed to initiate an outbound call to
/// `target` on behalf of a REFER transferor, given the current feature flags.
///
/// REFER is in-dialog but the target URI is attacker-controlled — the
/// transferor picks it freely. Without a filter the daemon becomes an SSRF
/// / internal-scan primitive: the transferor could name `127.0.0.1`,
/// RFC 1918 ranges, `0.0.0.0`, link-local, multicast, or documentation
/// addresses. By default we refuse any non-global-unicast address; the
/// operator can opt in with `allow_private_refer_targets`.
fn refer_target_allowed(
    target: &std::net::SocketAddr,
    config: &crate::config::DaemonConfig,
) -> bool {
    if config.features.allow_private_refer_targets {
        return true;
    }
    is_global_unicast(&target.ip())
}

/// Approximates "globally-routable unicast address" without requiring
/// the unstable `IpAddr::is_global`. Accepts addresses that are not
/// loopback / private / link-local / unspecified / multicast /
/// documentation / benchmarking / broadcast.
fn is_global_unicast(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
            {
                return false;
            }
            let [a, b, _, _] = v4.octets();
            // Shared address space (RFC 6598, 100.64.0.0/10)
            if a == 100 && (64..=127).contains(&b) {
                return false;
            }
            // Benchmarking (RFC 2544, 198.18.0.0/15)
            if a == 198 && (b == 18 || b == 19) {
                return false;
            }
            // IETF protocol assignments (RFC 6890, 192.0.0.0/24)
            if a == 192 && b == 0 && v4.octets()[2] == 0 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let segs = v6.segments();
            // Link-local fe80::/10
            if segs[0] & 0xffc0 == 0xfe80 {
                return false;
            }
            // Unique local fc00::/7
            if segs[0] & 0xfe00 == 0xfc00 {
                return false;
            }
            // Documentation 2001:db8::/32
            if segs[0] == 0x2001 && segs[1] == 0xdb8 {
                return false;
            }
            // IPv4-mapped ::ffff:0:0/96 — re-check the embedded v4.
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0xffff
            {
                let mapped = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                return is_global_unicast(&IpAddr::V4(mapped));
            }
            true
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_replaces_decodes_semicolons() {
        // RFC 3891 form, percent-encoded as it would appear in a Refer-To URI.
        let refer_to = "<sip:t@example.com?Replaces=callid42%3Bto-tag%3Daaa%3Bfrom-tag%3Dbbb>";
        let got = ReferHandler::extract_replaces(refer_to).expect("decoded");
        assert_eq!(got, "callid42;to-tag=aaa;from-tag=bbb");
    }

    #[test]
    fn extract_replaces_rejects_missing_tags() {
        // Only call-id, no to-tag/from-tag → reject as malformed.
        let refer_to = "<sip:t@example.com?Replaces=callid42>";
        assert!(ReferHandler::extract_replaces(refer_to).is_none());
    }

    #[test]
    fn extract_replaces_returns_none_when_absent() {
        assert!(ReferHandler::extract_replaces("<sip:t@example.com>").is_none());
        assert!(ReferHandler::extract_replaces("<sip:t@example.com?Subject=hi>").is_none());
    }

    #[test]
    fn extract_replaces_does_not_match_in_user_part() {
        // The user-part contains the literal string "Replaces=" but we only
        // look in the URI-headers segment after `?`.
        let refer_to = "<sip:Replaces=foo@example.com>";
        assert!(ReferHandler::extract_replaces(refer_to).is_none());
    }

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("foo%3Bbar%3Dbaz"), "foo;bar=baz");
        assert_eq!(percent_decode("plain"), "plain");
        // Truncated escape is passed through literally rather than panicking.
        assert_eq!(percent_decode("ab%2"), "ab%2");
    }

    #[test]
    fn ssrf_filter_rejects_non_global_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};
        let cases: &[Ipv4Addr] = &[
            Ipv4Addr::new(127, 0, 0, 1),       // loopback
            Ipv4Addr::new(10, 0, 0, 1),        // private
            Ipv4Addr::new(172, 16, 0, 1),      // private
            Ipv4Addr::new(192, 168, 1, 1),     // private
            Ipv4Addr::new(169, 254, 1, 1),     // link-local
            Ipv4Addr::new(0, 0, 0, 0),         // unspecified
            Ipv4Addr::new(224, 0, 0, 1),       // multicast
            Ipv4Addr::new(255, 255, 255, 255), // broadcast
            Ipv4Addr::new(192, 0, 2, 1),       // documentation (TEST-NET-1)
            Ipv4Addr::new(100, 64, 0, 1),      // shared (RFC 6598)
            Ipv4Addr::new(198, 18, 0, 1),      // benchmarking (RFC 2544)
        ];
        for ip in cases {
            assert!(
                !is_global_unicast(&IpAddr::V4(*ip)),
                "{ip} should NOT be treated as globally routable"
            );
        }
    }

    #[test]
    fn ssrf_filter_accepts_global_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};
        for ip in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(203, 0, 113, 5), // documentation, but the user said yes
        ] {
            // 203.0.113.0/24 IS documentation — it should be rejected. Keep
            // only the first case as the public-IP check.
            if ip == Ipv4Addr::new(203, 0, 113, 5) {
                assert!(!is_global_unicast(&IpAddr::V4(ip)));
            } else {
                assert!(is_global_unicast(&IpAddr::V4(ip)));
            }
        }
    }

    #[test]
    fn ssrf_filter_rejects_non_global_ipv6() {
        use std::net::{IpAddr, Ipv6Addr};
        let cases: &[Ipv6Addr] = &[
            "::1".parse().unwrap(),              // loopback
            "::".parse().unwrap(),               // unspecified
            "ff02::1".parse().unwrap(),          // multicast
            "fe80::1".parse().unwrap(),          // link-local
            "fc00::1".parse().unwrap(),          // unique local
            "2001:db8::1".parse().unwrap(),      // documentation
            "::ffff:127.0.0.1".parse().unwrap(), // v4-mapped loopback
        ];
        for ip in cases {
            assert!(
                !is_global_unicast(&IpAddr::V6(*ip)),
                "{ip} should NOT be treated as globally routable"
            );
        }
    }
}
