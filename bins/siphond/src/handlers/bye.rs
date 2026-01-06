// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// BYE request handler.
///
/// Terminates an established dialog:
/// 1. Verify dialog exists
/// 2. Update dialog state to Terminated
/// 3. Send 200 OK
/// 4. Clean up dialog from manager
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::{proxy_utils, services::ServiceRegistry};

pub struct ByeHandler;

impl ByeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Handle BYE in B2BUA mode - bridge to the other call leg
    async fn handle_b2bua_bye(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        services: &ServiceRegistry,
        call_id: &str,
    ) -> Result<()> {
        use sip_core::{Headers, Method, RequestLine};
        use sip_transaction::generate_branch_id;
        use smol_str::SmolStr;

        info!(call_id, "B2BUA MODE: Processing BYE for bridging");

        // Look up call leg by incoming Call-ID
        let call_leg = services.b2bua_state.find_call_leg_by_incoming(call_id);

        if call_leg.is_none() {
            // Try looking up by outgoing Call-ID (BYE might be from callee)
            if let Some(leg) = services.b2bua_state.find_call_leg(call_id) {
                // BYE from callee to caller
                info!(
                    outgoing_call_id = %leg.outgoing_call_id,
                    incoming_call_id = %leg.incoming_call_id,
                    "B2BUA: BYE from callee, sending 200 OK and bridging to caller"
                );

                // Send 200 OK to callee
                let response = UserAgentServer::create_response(request, 200, "OK");
                handle.send_final(response).await;

                // Create BYE for caller
                // Extract caller's contact from original INVITE
                let caller_contact =
                    if let Some(contact_header) = header(leg.caller_request.headers(), "Contact") {
                        // Parse contact URI from Contact header (may have angle brackets)
                        let contact_str = contact_header;
                        if let Some(start) = contact_str.find('<') {
                            if let Some(end) = contact_str.find('>') {
                                &contact_str[start + 1..end]
                            } else {
                                contact_str
                            }
                        } else {
                            contact_str
                        }
                    } else {
                        warn!(
                            call_id,
                            "B2BUA: No Contact header in caller's INVITE, cannot send BYE"
                        );
                        services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                        return Ok(());
                    };

                // Parse caller's contact URI
                let caller_contact_uri = match sip_core::Uri::parse(caller_contact) {
                    Ok(uri) => uri,
                    Err(_) => {
                        warn!(
                            call_id,
                            contact = caller_contact,
                            "B2BUA: Failed to parse caller's contact URI"
                        );
                        services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                        return Ok(());
                    }
                };

                // Extract SipUri from Uri (we expect SIP URIs for contacts)
                let caller_sip_uri = match caller_contact_uri.as_sip() {
                    Some(sip_uri) => sip_uri,
                    None => {
                        warn!(
                            call_id,
                            "B2BUA: Caller contact is not a SIP URI (tel URI not supported for BYE)"
                        );
                        services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                        return Ok(());
                    }
                };

                // Generate branch for this BYE transaction
                let branch = generate_branch_id();

                // Build headers (we'll add Via later when we know the transport)
                let mut bye_headers_base = Headers::new();

                // From - use To from caller's INVITE + callee's to-tag (established dialog)
                // This is the remote side from Bob's perspective
                if let Some(to_tag) = &leg.callee_to_tag {
                    if let Some(to) = leg.caller_request.headers().get("To") {
                        let from_with_tag = format!("{};tag={}", to.trim_end_matches(';'), to_tag);
                        let _ = bye_headers_base
                            .push(SmolStr::new("From"), SmolStr::new(from_with_tag));
                    }
                } else {
                    warn!(
                        call_id,
                        "B2BUA: No callee to-tag stored, BYE may be rejected"
                    );
                    if let Some(to) = leg.caller_request.headers().get("To") {
                        let _ = bye_headers_base.push(SmolStr::new("From"), to);
                    }
                }

                // To - use From from caller's INVITE (this is Bob with his tag)
                // This is Bob's local side
                if let Some(from) = leg.caller_request.headers().get("From") {
                    let _ = bye_headers_base.push(SmolStr::new("To"), from);
                }

                // Call-ID - incoming call leg
                let _ = bye_headers_base
                    .push(SmolStr::new("Call-ID"), SmolStr::new(&leg.incoming_call_id));

                // CSeq - increment from caller's INVITE CSeq
                if let Some(cseq) = leg.caller_request.headers().get("CSeq") {
                    if let Some((num, _)) = cseq.split_once(' ') {
                        if let Ok(cseq_num) = num.parse::<u32>() {
                            let _ = bye_headers_base.push(
                                SmolStr::new("CSeq"),
                                SmolStr::new(format!("{} BYE", cseq_num + 1)),
                            );
                        }
                    }
                }

                // Max-Forwards
                let _ = bye_headers_base.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));

                // Content-Length
                let _ = bye_headers_base.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

                // Send BYE to caller
                let caller_addr = format!(
                    "{}:{}",
                    caller_sip_uri.host(),
                    caller_sip_uri.port().unwrap_or(5060)
                );

                if let Ok(addr) = caller_addr.parse::<std::net::SocketAddr>() {
                    // For B2BUA, prefer UDP for BYE to avoid TCP connection issues
                    // Many SIP clients send INVITE via TCP but mid-dialog requests via UDP
                    // UDP is stateless and doesn't require connection establishment

                    // Try UDP first - create headers with UDP Via
                    let via_udp = format!(
                        "SIP/2.0/UDP {};branch={}",
                        services
                            .config
                            .local_uri
                            .as_str()
                            .trim_start_matches("sip:"),
                        branch
                    );
                    let mut bye_headers_udp = Headers::new();
                    let _ = bye_headers_udp.push(SmolStr::new("Via"), SmolStr::new(via_udp));

                    // Copy base headers
                    for header in bye_headers_base.iter() {
                        if let Err(e) = bye_headers_udp.push(header.name(), header.value()) {
                            warn!(
                                header = %header.name(),
                                error = %e,
                                "Failed to push header to BYE request, skipping"
                            );
                        }
                    }

                    // Now serialize the request with correct Via
                    let bye_request_udp = match sip_core::Request::new(
                        RequestLine::new(Method::Bye, caller_sip_uri.clone()),
                        bye_headers_udp,
                        bytes::Bytes::new(),
                    ) {
                        Ok(req) => req,
                        Err(e) => {
                            warn!(
                                error = %e,
                                caller = %caller_addr,
                                "Failed to create BYE request for caller, aborting"
                            );
                            services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                            return Ok(());
                        }
                    };
                    let payload = sip_parse::serialize_request(&bye_request_udp);

                    info!(
                        call_id,
                        caller = %caller_addr,
                        "B2BUA: Sending BYE to caller via UDP"
                    );

                    // Create temporary UDP socket for sending
                    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        Ok(udp_socket) => {
                            if let Err(e) =
                                sip_transport::send_udp(&udp_socket, &addr, &payload).await
                            {
                                warn!(
                                    error = %e,
                                    caller = %caller_addr,
                                    "B2BUA: Failed to send BYE to caller via UDP, trying TCP"
                                );

                                // Fallback to TCP if UDP fails - create BYE with TCP Via
                                let via_tcp = format!(
                                    "SIP/2.0/TCP {};branch={}",
                                    services
                                        .config
                                        .local_uri
                                        .as_str()
                                        .trim_start_matches("sip:"),
                                    generate_branch_id()
                                );
                                let mut bye_headers_tcp = Headers::new();
                                let _ = bye_headers_tcp
                                    .push(SmolStr::new("Via"), SmolStr::new(via_tcp));

                                // Copy base headers
                                for header in bye_headers_base.iter() {
                                    if let Err(e) =
                                        bye_headers_tcp.push(header.name(), header.value())
                                    {
                                        warn!(
                                            header = %header.name(),
                                            error = %e,
                                            "Failed to push header to BYE request, skipping"
                                        );
                                    }
                                }

                                let bye_request_tcp = match sip_core::Request::new(
                                    RequestLine::new(Method::Bye, caller_sip_uri.clone()),
                                    bye_headers_tcp,
                                    bytes::Bytes::new(),
                                ) {
                                    Ok(req) => req,
                                    Err(e) => {
                                        warn!(
                                            error = %e,
                                            caller = %caller_addr,
                                            "Failed to create BYE request for caller (TCP fallback), aborting"
                                        );
                                        services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                                        return Ok(());
                                    }
                                };
                                let payload_tcp = sip_parse::serialize_request(&bye_request_tcp);

                                if let Err(e) = sip_transport::send_tcp(&addr, &payload_tcp).await {
                                    warn!(
                                        error = %e,
                                        caller = %caller_addr,
                                        "B2BUA: Failed to send BYE to caller via TCP"
                                    );
                                } else {
                                    info!(
                                        caller = %caller_addr,
                                        "B2BUA: BYE sent to caller successfully via TCP"
                                    );
                                }
                            } else {
                                info!(
                                    caller = %caller_addr,
                                    "B2BUA: BYE sent to caller successfully via UDP"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "B2BUA: Failed to create UDP socket for BYE, trying TCP"
                            );

                            // Fallback to TCP if we can't create UDP socket - create BYE with TCP Via
                            let via_tcp = format!(
                                "SIP/2.0/TCP {};branch={}",
                                services
                                    .config
                                    .local_uri
                                    .as_str()
                                    .trim_start_matches("sip:"),
                                generate_branch_id()
                            );
                            let mut bye_headers_tcp = Headers::new();
                            let _ =
                                bye_headers_tcp.push(SmolStr::new("Via"), SmolStr::new(via_tcp));

                            // Copy base headers
                            for header in bye_headers_base.iter() {
                                let _ = bye_headers_tcp.push(header.name(), header.value());
                            }

                            let bye_request_tcp = match sip_core::Request::new(
                                RequestLine::new(Method::Bye, caller_sip_uri.clone()),
                                bye_headers_tcp,
                                bytes::Bytes::new(),
                            ) {
                                Ok(req) => req,
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        caller = %caller_addr,
                                        "Failed to create BYE request for caller (TCP fallback after socket error), aborting"
                                    );
                                    services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                                    return Ok(());
                                }
                            };
                            let payload_tcp = sip_parse::serialize_request(&bye_request_tcp);

                            if let Err(e) = sip_transport::send_tcp(&addr, &payload_tcp).await {
                                warn!(
                                    error = %e,
                                    caller = %caller_addr,
                                    "B2BUA: Failed to send BYE to caller via TCP"
                                );
                            } else {
                                info!(
                                    caller = %caller_addr,
                                    "B2BUA: BYE sent to caller successfully via TCP"
                                );
                            }
                        }
                    }
                }

                // Clean up call leg
                services.b2bua_state.remove_call_leg(&leg.outgoing_call_id);
                info!(call_id, "B2BUA: Call leg removed, BYE bridging complete");

                return Ok(());
            }

            // Call leg not found
            warn!(call_id, "B2BUA: BYE received for unknown call leg");
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
                            warn!(call_id, error = %e, "Failed to create 481 response for unknown call leg");
                        }
                    }
                }
                Err(e) => {
                    warn!(call_id, error = %e, "Failed to create status line for 481 response");
                }
            }
            return Ok(());
        }

        // At this point call_leg must be Some because we handled None case above
        let Some(call_leg) = call_leg else {
            // This should be unreachable due to logic above, but handle gracefully
            warn!(call_id, "B2BUA: Unexpected None call_leg after guard check");
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

        info!(
            incoming_call_id = %call_leg.incoming_call_id,
            outgoing_call_id = %call_leg.outgoing_call_id,
            "B2BUA: BYE from caller, sending 200 OK and bridging to callee"
        );

        // Send 200 OK to caller
        let response = UserAgentServer::create_response(request, 200, "OK");
        handle.send_final(response).await;

        // Create BYE for callee
        let mut bye_headers = Headers::new();

        // Via
        let branch = generate_branch_id();
        let via = format!(
            "SIP/2.0/TCP {};branch={}",
            services
                .config
                .local_uri
                .as_str()
                .trim_start_matches("sip:"),
            branch
        );
        let _ = bye_headers.push(SmolStr::new("Via"), SmolStr::new(via));

        // From - same as our outgoing INVITE
        if let Some(from) = call_leg.outgoing_invite.headers().get("From") {
            let _ = bye_headers.push(SmolStr::new("From"), from);
        }

        // To - with callee's tag
        // Prefer UAC dialog's remote tag (from confirmed dialog), fallback to callee_to_tag
        let to_tag = call_leg
            .uac_dialog
            .as_ref()
            .map(|d| d.id().remote_tag().to_string())
            .or_else(|| call_leg.callee_to_tag.clone());

        if let Some(to_tag) = to_tag {
            if let Some(to) = call_leg.outgoing_invite.headers().get("To") {
                let to_with_tag = format!("{};tag={}", to, to_tag);
                let _ = bye_headers.push(SmolStr::new("To"), SmolStr::new(to_with_tag));
            }
        }

        // Call-ID - outgoing call leg
        let _ = bye_headers.push(
            SmolStr::new("Call-ID"),
            SmolStr::new(&call_leg.outgoing_call_id),
        );

        // CSeq - increment from INVITE CSeq
        if let Some(cseq) = call_leg.outgoing_invite.headers().get("CSeq") {
            if let Some((num, _)) = cseq.split_once(' ') {
                if let Ok(cseq_num) = num.parse::<u32>() {
                    let _ = bye_headers.push(
                        SmolStr::new("CSeq"),
                        SmolStr::new(format!("{} BYE", cseq_num + 1)),
                    );
                }
            }
        }

        // Max-Forwards
        let _ = bye_headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("70"));

        // Content-Length
        let _ = bye_headers.push(SmolStr::new("Content-Length"), SmolStr::new("0"));

        // Create BYE request
        let bye_request = match sip_core::Request::new(
            RequestLine::new(Method::Bye, call_leg.callee_contact.clone()),
            bye_headers,
            bytes::Bytes::new(),
        ) {
            Ok(req) => req,
            Err(e) => {
                warn!(
                    error = %e,
                    outgoing_call_id = %call_leg.outgoing_call_id,
                    "Failed to create BYE request for callee, cleaning up"
                );
                services
                    .b2bua_state
                    .remove_call_leg(&call_leg.outgoing_call_id);
                return Ok(());
            }
        };

        // Send BYE to callee
        let callee_addr = format!(
            "{}:{}",
            call_leg.callee_contact.host(),
            call_leg.callee_contact.port().unwrap_or(5060)
        );

        if let Ok(addr) = callee_addr.parse::<std::net::SocketAddr>() {
            let payload = sip_parse::serialize_request(&bye_request);
            if let Err(e) = sip_transport::send_tcp(&addr, &payload).await {
                warn!(
                    error = %e,
                    callee = %callee_addr,
                    "B2BUA: Failed to send BYE to callee"
                );
            } else {
                info!(
                    callee = %callee_addr,
                    "B2BUA: BYE sent to callee successfully"
                );
            }
        }

        // Clean up call leg
        services
            .b2bua_state
            .remove_call_leg(&call_leg.outgoing_call_id);
        info!(call_id, "B2BUA: Call leg removed, BYE bridging complete");

        Ok(())
    }
}

#[async_trait]
impl RequestHandler for ByeHandler {
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

        // B2BUA MODE: Bridge BYE to the other call leg
        if services.config.enable_b2bua() {
            return self
                .handle_b2bua_bye(request, handle, services, call_id)
                .await;
        }

        // UAS MODE: Normal BYE handling
        // Look up dialog using request
        let dialog = services.dialog_mgr.find_by_request(request);

        match dialog {
            Some(dialog) => {
                info!(
                    call_id,
                    dialog_id = %dialog.id().call_id(),
                    state = ?dialog.state(),
                    "Dialog found, processing BYE"
                );

                // Create 200 OK response
                let response = UserAgentServer::create_response(request, 200, "OK");

                // Remove dialog from manager
                services.dialog_mgr.remove(dialog.id());

                info!(call_id, "Dialog terminated successfully");

                // Send 200 OK
                handle.send_final(response).await;
            }
            None => {
                warn!(call_id, "BYE received for unknown dialog");

                // Send 481 Call/Transaction Does Not Exist
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
                                warn!(call_id, error = %e, "Failed to create 481 response for unknown dialog");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(call_id, error = %e, "Failed to create status line for 481 response");
                    }
                }
            }
        }

        Ok(())
    }

    fn method(&self) -> &str {
        "BYE"
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
