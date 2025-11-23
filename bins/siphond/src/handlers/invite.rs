/// INVITE request handler.
///
/// Implements full UAS call flow:
/// 1. Send 100 Trying
/// 2. Send 180 Ringing (with optional PRACK)
/// 3. Send 200 OK with SDP answer
/// 4. Create and track dialog
///
/// Also handles in-dialog re-INVITE for session modification.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_registrar::LocationStore;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::services::ServiceRegistry;

pub struct InviteHandler;

impl InviteHandler {
    pub fn new() -> Self {
        Self
    }

    /// Generate SDP answer based on configured profile
    fn generate_sdp_answer(services: &ServiceRegistry, offer: &str) -> Result<String> {
        // TODO: Proper SDP negotiation using sip-sdp crate
        // For now, simple pattern matching for audio codecs

        let has_audio = offer.contains("m=audio");
        let has_video = offer.contains("m=video");

        // Extract IP address from local_uri configuration
        let local_ip = if let Some(uri) = sip_core::SipUri::parse(&services.config.local_uri) {
            uri.host.to_string()
        } else {
            warn!("Failed to parse local_uri, falling back to 127.0.0.1");
            "127.0.0.1".to_string()
        };

        match &services.config.sdp_profile {
            crate::config::SdpProfile::None => {
                Err(anyhow!("SDP not supported in current configuration"))
            }
            crate::config::SdpProfile::AudioOnly => {
                if !has_audio {
                    return Err(anyhow!("No audio in offer, but only audio supported"));
                }

                // Simple audio-only answer (PCMU)
                let sdp = format!(
                    "v=0\r\n\
                     o=siphond {} {} IN IP4 {}\r\n\
                     s=siphond call\r\n\
                     c=IN IP4 {}\r\n\
                     t=0 0\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    rand::random::<u32>(),
                    rand::random::<u32>(),
                    local_ip,
                    local_ip
                );

                Ok(sdp)
            }
            crate::config::SdpProfile::AudioVideo => {
                if !has_audio {
                    return Err(anyhow!("No audio in offer"));
                }

                let mut sdp = format!(
                    "v=0\r\n\
                     o=siphond {} {} IN IP4 {}\r\n\
                     s=siphond call\r\n\
                     c=IN IP4 {}\r\n\
                     t=0 0\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    rand::random::<u32>(),
                    rand::random::<u32>(),
                    local_ip,
                    local_ip
                );

                if has_video {
                    sdp.push_str("m=video 49172 RTP/AVP 96\r\n");
                    sdp.push_str("a=rtpmap:96 H264/90000\r\n");
                }

                Ok(sdp)
            }
            crate::config::SdpProfile::Custom(path) => {
                // TODO: Load custom SDP from file
                Err(anyhow!("Custom SDP profile not yet implemented: {:?}", path))
            }
        }
    }

    /// Check if this is an in-dialog request (re-INVITE)
    fn is_in_dialog(&self, request: &Request, services: &ServiceRegistry) -> bool {
        services.dialog_mgr.find_by_request(request).is_some()
    }

    /// Handle INVITE in B2BUA mode - bridge two call legs
    async fn handle_b2bua(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        services: &ServiceRegistry,
        call_id: &str,
    ) -> Result<()> {
        use sip_uac::UserAgentClient;

        info!(call_id, "B2BUA MODE: Bridging call between users");

        // Send 100 Trying to caller immediately
        let trying = sip_uas::UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        // Extract target URI from Request-URI
        let target_uri = request.start.uri.as_sip()
            .ok_or_else(|| anyhow!("Request-URI must be SIP URI for B2BUA"))?;

        info!(call_id, target = %target_uri.as_str(), "Looking up callee in location service");

        // Look up callee in location service
        let registrar = services.registrar.as_ref()
            .ok_or_else(|| anyhow!("Registrar not available in B2BUA mode"))?;

        let bindings = registrar.location_store().lookup(target_uri.as_str())?;

        if bindings.is_empty() {
            warn!(call_id, target = %target_uri.as_str(), "Callee not found");
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(404, "Not Found".into()),
                request.headers.clone(),
                bytes::Bytes::new(),
            );
            handle.send_final(response).await;
            return Ok(());
        }

        // Parse callee's contact URI
        let callee_contact_str = bindings[0].contact.as_str();
        let callee_contact = sip_core::SipUri::parse(callee_contact_str)
            .ok_or_else(|| anyhow!("Invalid contact URI: {}", callee_contact_str))?;

        info!(call_id, callee = %callee_contact.as_str(), "Found callee, creating outgoing INVITE");

        // Parse our local URI for UAC
        let local_uri = sip_core::SipUri::parse(&services.config.local_uri)
            .ok_or_else(|| anyhow!("Invalid local_uri"))?;

        // Create UAC for outgoing leg
        let uac = UserAgentClient::new(local_uri.clone(), local_uri.clone());

        // Extract SDP from incoming INVITE (if present)
        let sdp = if !request.body.is_empty() {
            Some(std::str::from_utf8(&request.body)?)
        } else {
            None
        };

        // Create outgoing INVITE to callee
        let outgoing_invite = uac.create_invite(&callee_contact, sdp);

        // Extract outgoing Call-ID for tracking
        let outgoing_call_id = outgoing_invite.headers.get("Call-ID")
            .ok_or_else(|| anyhow!("Missing Call-ID in outgoing INVITE"))?
            .to_string();

        info!(
            call_id,
            outgoing_call_id = %outgoing_call_id,
            "Setting up B2BUA response bridging with channel"
        );

        // Create channel for relaying responses
        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();

        // Store call leg pair BEFORE sending outgoing INVITE
        // This allows us to correlate responses from callee with caller's transaction
        services.b2bua_state.store_call_leg(crate::b2bua_state::CallLegPair {
            outgoing_call_id: outgoing_call_id.clone(),
            response_tx,
            incoming_call_id: call_id.to_string(),
            caller_uri: request.headers.get("From")
                .map(|v| v.to_string())
                .unwrap_or_default(),
            callee_uri: target_uri.as_str().to_string(),
            created_at: std::time::Instant::now(),
        });

        // Spawn task to relay responses from callee to caller
        tokio::spawn(async move {
            while let Some(response) = response_rx.recv().await {
                if response.start.code >= 100 && response.start.code < 200 {
                    // Provisional response (1xx)
                    handle.send_provisional(response).await;
                } else {
                    // Final response (2xx-6xx)
                    handle.send_final(response).await;
                    break; // Stop after final response
                }
            }
        });

        info!(call_id, "Sending outgoing INVITE to callee");

        // Send INVITE to callee via TCP
        let callee_addr = format!("{}:{}", callee_contact.host, callee_contact.port.unwrap_or(5060))
            .parse::<std::net::SocketAddr>()?;

        let payload = sip_parse::serialize_request(&outgoing_invite);
        sip_transport::send_tcp(&callee_addr, &payload).await?;

        info!(
            call_id,
            outgoing_call_id = %outgoing_call_id,
            "Outgoing INVITE sent to callee - waiting for responses to bridge"
        );

        // Don't send any responses to caller yet - wait for callee's responses
        // which will be handled in main.rs packet loop and relayed back

        Ok(())
    }

    /// Generate simple SDP for testing
    fn generate_simple_sdp(local_uri: &str) -> String {
        let host = local_uri.split('@').nth(1).unwrap_or("127.0.0.1");
        format!(
            "v=0\r\n\
             o=siphond {} {} IN IP4 {}\r\n\
             s=siphond b2bua\r\n\
             c=IN IP4 {}\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            rand::random::<u32>(),
            rand::random::<u32>(),
            host,
            host
        )
    }

    /// Handle INVITE in proxy mode - forward to registered user
    async fn handle_proxy(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        services: &ServiceRegistry,
        call_id: &str,
    ) -> Result<()> {
        use sip_proxy::ProxyHelpers;
        use sip_parse::serialize_request;

        info!(call_id, "PROXY MODE: Processing INVITE for forwarding");

        // Send 100 Trying immediately
        let trying = sip_uas::UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        // Clone request for modification
        let mut proxied_req = request.clone();

        // Step 1: Check Max-Forwards
        if let Err(e) = ProxyHelpers::check_max_forwards(&mut proxied_req) {
            warn!(call_id, error = %e, "Max-Forwards exhausted");
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(483, "Too Many Hops".into()),
                request.headers.clone(),
                bytes::Bytes::new(),
            );
            handle.send_final(response).await;
            return Ok(());
        }

        // Step 2: Add Via header and store transaction state
        let proxy_host = services.config.local_uri.split('@').nth(1).unwrap_or("localhost");
        let transport_name = match ctx.transport {
            sip_transaction::TransportKind::Udp => "UDP",
            sip_transaction::TransportKind::Tcp => "TCP",
            sip_transaction::TransportKind::Tls => "TLS",
        };
        let branch = ProxyHelpers::add_via(&mut proxied_req, proxy_host, transport_name);

        // Store proxy transaction for response forwarding
        services.proxy_state.store_transaction(crate::proxy_state::ProxyTransaction {
            branch: branch.clone(),
            sender_addr: ctx.peer,
            sender_transport: ctx.transport,
            call_id: call_id.to_string(),
            created_at: std::time::Instant::now(),
        });

        // Step 3: Add Record-Route (stay in signaling path)
        if let Some(proxy_uri) = sip_core::SipUri::parse(&services.config.local_uri) {
            ProxyHelpers::add_record_route(&mut proxied_req, &proxy_uri);
        }

        // Step 4: Location service lookup
        let target_uri = proxied_req.start.uri.as_sip()
            .ok_or_else(|| anyhow!("Request-URI must be SIP URI for proxy"))?;

        info!(call_id, target = %target_uri.as_str(), "Looking up target in location service");

        // Access location store through registrar
        let registrar = services.registrar.as_ref()
            .ok_or_else(|| anyhow!("Registrar not available in proxy mode"))?;

        let bindings = registrar.location_store().lookup(target_uri.as_str())?;

        if bindings.is_empty() {
            warn!(call_id, target = %target_uri.as_str(), "User not found in location service");
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(404, "Not Found".into()),
                request.headers.clone(),
                bytes::Bytes::new(),
            );
            handle.send_final(response).await;
            return Ok(());
        }

        // Use first (highest priority) binding
        let contact_str = bindings[0].contact.as_str();
        info!(call_id, contact = %contact_str, "Found registered contact, forwarding");

        // Parse contact URI
        let contact_uri = sip_core::SipUri::parse(contact_str)
            .ok_or_else(|| anyhow!("Invalid contact URI: {}", contact_str))?;

        // Step 5: Update Request-URI to registered contact
        ProxyHelpers::set_request_uri(&mut proxied_req, contact_uri.clone());

        // Step 6: Forward via transport
        let target_addr = format!("{}:{}", contact_uri.host, contact_uri.port.unwrap_or(5060))
            .parse::<std::net::SocketAddr>()?;

        info!(call_id, target = %target_addr, "Forwarding INVITE to registered contact");

        // Serialize and send via appropriate transport
        let payload = serialize_request(&proxied_req);

        match ctx.transport {
            sip_transaction::TransportKind::Udp => {
                // For UDP, we'd need access to the socket - for now return error
                warn!(call_id, "UDP proxy forwarding not yet implemented");
                return Err(anyhow!("UDP proxy forwarding requires socket access"));
            }
            sip_transaction::TransportKind::Tcp => {
                sip_transport::send_tcp(&target_addr, &payload).await?;
                info!(call_id, "INVITE forwarded via TCP successfully");
            }
            sip_transaction::TransportKind::Tls => {
                warn!(call_id, "TLS proxy forwarding not yet implemented");
                return Err(anyhow!("TLS proxy forwarding not yet implemented"));
            }
        }

        // TODO: Response handling - proxy needs to forward responses back to caller
        // For now, this is stateless forwarding only
        warn!(call_id, "Proxy response forwarding not yet implemented - responses will not be relayed");

        Ok(())
    }
}

#[async_trait]
impl RequestHandler for InviteHandler {
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

        // B2BUA MODE: Bridge calls between two users
        if services.config.enable_b2bua() {
            return self.handle_b2bua(request, handle, ctx, services, call_id).await;
        }

        // PROXY MODE: Forward request to registered user
        if services.config.enable_proxy() {
            return self.handle_proxy(request, handle, ctx, services, call_id).await;
        }

        // UAS MODE: Accept calls ourselves
        // Check if call handling is enabled
        if !services.config.enable_calls() {
            info!(call_id, "INVITE rejected: call handling disabled");
            let decline = UserAgentServer::reject_invite(request, 603, "Decline");
            handle.send_final(decline).await;
            return Ok(());
        }

        // Handle in-dialog re-INVITE
        if self.is_in_dialog(request, services) {
            info!(call_id, "Received in-dialog re-INVITE");
            // TODO: Handle session modification
            let ok = UserAgentServer::create_response(request, 200, "OK");
            handle.send_final(ok).await;
            return Ok(());
        }

        // Check auto-accept configuration
        if !services.config.features.auto_accept_calls {
            info!(call_id, "INVITE rejected: auto-accept disabled");
            let busy = UserAgentServer::reject_invite(request, 486, "Busy Here");
            handle.send_final(busy).await;
            return Ok(());
        }

        // Parse local and contact URIs early so we can use UAS for all responses
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Some(uri) => uri,
            None => {
                warn!("Invalid local_uri in config: {}", services.config.local_uri);
                return Err(anyhow!("Invalid local_uri configuration"));
            }
        };

        let contact_uri = local_uri.clone();

        // Create UAS early so it can be used for all responses
        let uas = UserAgentServer::new(local_uri, contact_uri);

        // Send 100 Trying
        let trying = UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        info!(call_id, "Call accepted, sending 180 Ringing");

        // Send 180 Ringing (with optional reliable provisional)
        if services.config.features.enable_prack && request.headers.get("Supported").map(|s| s.contains("100rel")).unwrap_or(false) {
            // TODO: Send reliable 180 with RSeq
            let ringing = uas.create_ringing(request);
            handle.send_provisional(ringing).await;
        } else {
            let ringing = uas.create_ringing(request);
            handle.send_provisional(ringing).await;
        }

        // Generate SDP answer if offer was provided
        let sdp_answer = if !request.body.is_empty() {
            match std::str::from_utf8(&request.body) {
                Ok(offer_str) => match Self::generate_sdp_answer(services, offer_str) {
                    Ok(answer) => Some(answer),
                    Err(e) => {
                        warn!(call_id, error = %e, "Failed to generate SDP answer");
                        // Send 488 Not Acceptable Here
                        let mut headers = sip_core::Headers::new();
                        copy_dialog_headers(request, &mut headers);
                        let response = sip_core::Response::new(
                            sip_core::StatusLine::new(488, "Not Acceptable Here".into()),
                            headers,
                            bytes::Bytes::new(),
                        );
                        handle.send_final(response).await;
                        return Ok(());
                    }
                },
                Err(e) => {
                    warn!(call_id, error = %e, "Invalid UTF-8 in SDP offer");
                    None
                }
            }
        } else {
            // Late offer - should send SDP in 200 OK
            // TODO: Generate offer in 200 OK
            None
        };

        // Accept the INVITE
        let result = uas.accept_invite(request, sdp_answer.as_deref());

        match result {
            Ok((response, dialog)) => {
                info!(
                    call_id,
                    dialog_call_id = %dialog.id.call_id,
                    local_tag = %dialog.id.local_tag,
                    remote_tag = %dialog.id.remote_tag,
                    "Dialog created, sending 200 OK"
                );

                // Store dialog in manager
                services.dialog_mgr.insert(dialog);

                // Send 200 OK
                handle.send_final(response).await;
            }
            Err(e) => {
                warn!(call_id, error = %e, "Failed to accept INVITE");
                let error = uas.create_decline(request);
                handle.send_final(error).await;
            }
        }

        Ok(())
    }

    fn method(&self) -> &str {
        "INVITE"
    }
}

/// Copy dialog-forming headers from request to response headers
fn copy_dialog_headers(request: &Request, headers: &mut sip_core::Headers) {
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
