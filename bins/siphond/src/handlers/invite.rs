// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
use sip_dialog::Dialog;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use std::time::Duration;
use tracing::{info, warn};

use super::RequestHandler;
use crate::{sdp_utils, services::ServiceRegistry};

pub struct InviteHandler;

impl InviteHandler {
    pub fn new() -> Self {
        Self
    }

    fn dialog_id_key(id: &sip_dialog::DialogId) -> String {
        format!("{}:{}:{}", id.call_id, id.local_tag, id.remote_tag)
    }

    fn schedule_reliable_retransmit(
        services: &ServiceRegistry,
        key: sip_transaction::TransactionKey,
        response: sip_core::Response,
        dialog_key: String,
        rseq: u32,
    ) {
        let Some(transaction_mgr) = services.transaction_mgr.get().cloned() else {
            return;
        };
        let prack_validator = services.prack_validator.clone();

        tokio::spawn(async move {
            let mut interval = Duration::from_millis(500);
            let max_interval = Duration::from_secs(4);
            let max_total = Duration::from_secs(32);
            let mut elapsed = Duration::from_millis(0);

            loop {
                tokio::time::sleep(interval).await;
                elapsed += interval;

                if prack_validator.is_pracked(&dialog_key, rseq) {
                    break;
                }

                transaction_mgr.send_provisional(&key, response.clone()).await;

                if elapsed >= max_total {
                    break;
                }

                interval = std::cmp::min(interval * 2, max_interval);
            }
        });
    }

    /// Check if this is an in-dialog request (re-INVITE)
    fn is_in_dialog(&self, request: &Request, services: &ServiceRegistry) -> bool {
        services.dialog_mgr.find_by_request(request).is_some()
    }

    /// Handle re-INVITE in B2BUA mode - forward to the other leg
    async fn handle_b2bua_reinvite(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        _ctx: &TransportContext,
        services: &ServiceRegistry,
        call_id: &str,
    ) -> Result<()> {
        info!(call_id, "B2BUA: Processing re-INVITE for hold/resume");

        // Send 100 Trying immediately
        let trying = sip_uas::UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        // Try to find which leg this re-INVITE belongs to
        let dialog = services
            .dialog_mgr
            .find_by_request(request)
            .ok_or_else(|| anyhow!("Dialog not found for re-INVITE"))?;

        // Check if this is from the UAC leg (Alice) or UAS leg (Bob)
        let call_leg = services
            .b2bua_state
            .find_by_uac_dialog(&dialog.id)
            .or_else(|| services.b2bua_state.find_by_uas_dialog(&dialog.id))
            .ok_or_else(|| anyhow!("Call leg not found for re-INVITE"))?;

        let is_from_alice = services
            .b2bua_state
            .find_by_uac_dialog(&dialog.id)
            .is_some();

        // Extract SDP from re-INVITE to detect hold/resume
        let sdp_str = if !request.body.is_empty() {
            std::str::from_utf8(&request.body).ok()
        } else {
            None
        };

        let is_hold = sdp_str.map(|s| s.contains("a=inactive") || s.contains("a=sendonly")).unwrap_or(false);
        let is_resume = sdp_str.map(|s| s.contains("a=sendrecv")).unwrap_or(false);

        // Get the other leg's dialog for forwarding
        let other_dialog = if is_from_alice {
            // Alice → Bob: use UAS dialog to send to Bob
            call_leg
                .uas_dialog
                .as_ref()
                .ok_or_else(|| anyhow!("UAS dialog not found for forwarding"))?
        } else {
            // Bob → Alice: use UAC dialog to send to Alice
            call_leg
                .uac_dialog
                .as_ref()
                .ok_or_else(|| anyhow!("UAC dialog not found for forwarding"))?
        };

        // Log what's happening
        if is_from_alice {
            if is_hold {
                info!(call_id, "Alice is putting Bob on hold - forwarding re-INVITE to Bob");
            } else if is_resume {
                info!(call_id, "Alice is resuming call with Bob - forwarding re-INVITE to Bob");
            } else {
                info!(call_id, "Alice sent re-INVITE (session modification) - forwarding to Bob");
            }
        } else if is_hold {
            info!(call_id, "Bob is putting Alice on hold - forwarding re-INVITE to Alice");
        } else if is_resume {
            info!(call_id, "Bob is resuming call with Alice - forwarding re-INVITE to Alice");
        } else {
            info!(call_id, "Bob sent re-INVITE (session modification) - forwarding to Alice");
        }

        // Parse B2BUA URI for creating UAC
        let b2bua_contact_uri = sip_core::SipUri::parse(&services.config.local_uri)
            .ok_or_else(|| anyhow!("Invalid local_uri"))?;

        // Create UAC for outgoing re-INVITE (use B2BUA as both local and contact)
        let uac = sip_uac::UserAgentClient::new(b2bua_contact_uri.clone(), b2bua_contact_uri.clone());

        // Create outgoing re-INVITE using the other dialog
        let outgoing_reinvite = uac.create_reinvite(other_dialog, sdp_str);

        // Determine target address from the other dialog's remote target
        let target_addr = format!(
            "{}:{}",
            other_dialog.remote_target.host,
            other_dialog.remote_target.port.unwrap_or(5060)
        )
        .parse::<std::net::SocketAddr>()?;

        info!(
            call_id,
            target = %target_addr,
            "Forwarding re-INVITE to other leg"
        );

        // Send the re-INVITE via TCP
        let payload = sip_parse::serialize_request(&outgoing_reinvite);
        sip_transport::send_tcp(&target_addr, &payload).await?;

        info!(
            call_id,
            "re-INVITE forwarded successfully - sending 200 OK to original sender"
        );

        // Send 200 OK response back to the original sender
        // For a full B2BUA, we should wait for the other leg's response first,
        // but for basic hold/resume support, we can accept immediately
        let mut response_headers = sip_core::Headers::new();

        // Copy essential headers
        if let Some(via) = header(&request.headers, "Via") {
            response_headers.push("Via".into(), via.clone());
        }
        if let Some(from) = header(&request.headers, "From") {
            response_headers.push("From".into(), from.clone());
        }
        if let Some(to) = header(&request.headers, "To") {
            response_headers.push("To".into(), to.clone());
        }
        if let Some(call_id_hdr) = header(&request.headers, "Call-ID") {
            response_headers.push("Call-ID".into(), call_id_hdr.clone());
        }
        if let Some(cseq) = header(&request.headers, "CSeq") {
            response_headers.push("CSeq".into(), cseq.clone());
        }

        // Add Contact header (B2BUA's URI)
        response_headers.push("Contact".into(), format!("<{}>", services.config.local_uri).into());

        // Echo back the SDP from the original request
        if !request.body.is_empty() {
            if let Some(content_type) = header(&request.headers, "Content-Type") {
                response_headers.push("Content-Type".into(), content_type.clone());
            }
            response_headers.push("Content-Length".into(), request.body.len().to_string().into());
        } else {
            response_headers.push("Content-Length".into(), "0".into());
        }

        let response = sip_core::Response::new(
            sip_core::StatusLine::new(200, "OK".into()),
            response_headers,
            request.body.clone(), // Echo back the SDP
        );

        handle.send_final(response).await;

        info!(
            call_id,
            "200 OK sent to original sender - re-INVITE flow complete"
        );

        Ok(())
    }

    /// Handle INVITE in B2BUA mode - bridge two call legs
    async fn handle_b2bua(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        _ctx: &TransportContext,
        services: &ServiceRegistry,
        call_id: &str,
    ) -> Result<()> {
        use sip_uac::UserAgentClient;

        // Check if this is a re-INVITE (in-dialog request)
        if self.is_in_dialog(request, services) {
            return self
                .handle_b2bua_reinvite(request, handle, _ctx, services, call_id)
                .await;
        }

        info!(call_id, "B2BUA MODE: Bridging call between users");

        // Send 100 Trying to caller immediately
        let trying = sip_uas::UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        // Extract target URI from Request-URI
        let target_uri = request
            .start
            .uri
            .as_sip()
            .ok_or_else(|| anyhow!("Request-URI must be SIP URI for B2BUA"))?;

        // Normalize lookup key - strip parameters to match registration AOR format
        // The registrar stores: sip:user@host;transport=X
        // But phones may call with different transport, so we need to try multiple lookups
        let user = target_uri.user.as_deref().unwrap_or("");
        let host = &target_uri.host;

        info!(call_id, target = %target_uri.as_str(), user = %user, host = %host, "Looking up callee in location service");

        // Look up callee in location service
        let registrar = services
            .registrar
            .as_ref()
            .ok_or_else(|| anyhow!("Registrar not available in B2BUA mode"))?;

        // Try multiple lookup strategies to find the user
        // Strategy 1: Try exact match with full URI (includes transport)
        let mut bindings = registrar
            .location_store()
            .lookup(target_uri.as_str())
            .unwrap_or_default();

        // Strategy 2: Try with UDP transport if not found
        if bindings.is_empty() {
            let lookup_udp = format!("sip:{}@{};transport=UDP", user, host);
            bindings = registrar
                .location_store()
                .lookup(&lookup_udp)
                .unwrap_or_default();
            if !bindings.is_empty() {
                info!(call_id, "Found callee with UDP transport");
            }
        }

        // Strategy 3: Try with TCP transport if not found
        if bindings.is_empty() {
            let lookup_tcp = format!("sip:{}@{};transport=TCP", user, host);
            bindings = registrar
                .location_store()
                .lookup(&lookup_tcp)
                .unwrap_or_default();
            if !bindings.is_empty() {
                info!(call_id, "Found callee with TCP transport");
            }
        }

        // Strategy 4: Try without any transport parameter
        if bindings.is_empty() {
            let lookup_base = format!("sip:{}@{}", user, host);
            bindings = registrar
                .location_store()
                .lookup(&lookup_base)
                .unwrap_or_default();
            if !bindings.is_empty() {
                info!(call_id, "Found callee without transport parameter");
            }
        }

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

        // Extract the From URI from Bob's original request to preserve caller ID
        let from_header = header(&request.headers, "From")
            .ok_or_else(|| anyhow!("Missing From header"))?;

        // Parse the From URI (format: "Display Name" <sip:user@host>;tag=xxx or sip:user@host;tag=xxx)
        let from_uri = if let Some(start) = from_header.find('<') {
            // Extract URI between < and >
            let end = from_header.find('>').unwrap_or(from_header.len());
            &from_header[start + 1..end]
        } else {
            // No angle brackets, extract URI before semicolon
            from_header.split(';').next().unwrap_or(from_header.as_str()).trim()
        };

        let caller_uri = sip_core::SipUri::parse(from_uri)
            .ok_or_else(|| anyhow!("Invalid From URI: {}", from_uri))?;

        // Parse B2BUA URI for Contact (responses should route back to B2BUA)
        let b2bua_contact_uri = sip_core::SipUri::parse(&services.config.local_uri)
            .ok_or_else(|| anyhow!("Invalid local_uri"))?;

        // Create UAC for outgoing leg
        // From: caller's URI (preserves caller ID)
        // Contact: B2BUA URI (routes responses back to us)
        let uac = UserAgentClient::new(caller_uri.clone(), b2bua_contact_uri.clone());

        info!(
            call_id,
            caller = %caller_uri.as_str(),
            "Preserving caller identity in outgoing INVITE"
        );

        // Extract SDP from incoming INVITE (if present)
        let sdp = if !request.body.is_empty() {
            Some(std::str::from_utf8(&request.body)?)
        } else {
            None
        };

        // Create outgoing INVITE to callee
        let outgoing_invite = uac.create_invite(&callee_contact, sdp);

        // Extract outgoing Call-ID for tracking
        let outgoing_call_id = outgoing_invite
            .headers
            .get("Call-ID")
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
        services
            .b2bua_state
            .store_call_leg(crate::b2bua_state::CallLegPair {
                outgoing_call_id: outgoing_call_id.clone(),
                response_tx,
                incoming_call_id: call_id.to_string(),
                caller_request: request.clone(),
                outgoing_invite: outgoing_invite.clone(),
                callee_contact: callee_contact.clone(),
                callee_to_tag: None,
                uas_dialog: None, // Will be set after Bob's 200 OK ACK
                uac_dialog: None, // Will be set after Alice's 200 OK
                created_at: std::time::Instant::now(),
            });

        // Spawn task to transform and relay responses from callee to caller
        let services_clone = services.clone();
        let outgoing_call_id_clone = outgoing_call_id.clone();
        tokio::spawn(async move {
            while let Some(callee_response) = response_rx.recv().await {
                let status_code = callee_response.start.code;

                // Transform callee's response to match caller's call leg
                let transformed = Self::transform_response_for_caller(
                    &services_clone,
                    &outgoing_call_id_clone,
                    &callee_response,
                )
                .await;

                if let Some(caller_response) = transformed {
                    if caller_response.start.code >= 100 && caller_response.start.code < 200 {
                        // Provisional response (1xx)
                        handle.send_provisional(caller_response).await;
                    } else if caller_response.start.code >= 200 && caller_response.start.code < 300
                    {
                        // 2xx response - call established
                        handle.send_final(caller_response).await;

                        // DON'T remove call leg - we need it for ACK and BYE bridging
                        // Call leg will be removed when BYE is received
                        tracing::info!(
                            outgoing_call_id = %outgoing_call_id_clone,
                            status_code,
                            "B2BUA: 200 OK sent to caller - call established, keeping leg for ACK/BYE"
                        );
                        break; // Stop after final response
                    } else {
                        // Error response (3xx-6xx) - call failed
                        handle.send_final(caller_response).await;

                        // Clean up call leg after error response
                        services_clone
                            .b2bua_state
                            .remove_call_leg(&outgoing_call_id_clone);
                        tracing::info!(
                            outgoing_call_id = %outgoing_call_id_clone,
                            status_code,
                            "B2BUA: Call leg removed after error response"
                        );
                        break;
                    }
                } else {
                    tracing::error!(
                        outgoing_call_id = %outgoing_call_id_clone,
                        status_code,
                        "Failed to transform response for caller"
                    );

                    // Clean up call leg on error
                    services_clone
                        .b2bua_state
                        .remove_call_leg(&outgoing_call_id_clone);
                    break;
                }
            }
        });

        info!(call_id, "Sending outgoing INVITE to callee");

        // Send INVITE to callee via TCP
        let callee_addr = format!(
            "{}:{}",
            callee_contact.host,
            callee_contact.port.unwrap_or(5060)
        )
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

    /// Transform a response from the callee to match the caller's call leg
    /// This is the heart of B2BUA operation - we receive responses from Alice
    /// and transform them to look like they came from Bob's original INVITE dialog
    async fn transform_response_for_caller(
        services: &ServiceRegistry,
        outgoing_call_id: &str,
        callee_response: &sip_core::Response,
    ) -> Option<sip_core::Response> {
        use sip_parse::header;

        // Look up the call leg pair
        let call_leg = services.b2bua_state.find_call_leg(outgoing_call_id)?;

        tracing::info!(
            outgoing_call_id,
            incoming_call_id = %call_leg.incoming_call_id,
            status_code = callee_response.start.code,
            "Transforming response from callee to caller"
        );

        // Extract headers from caller's original request
        let caller_call_id = header(&call_leg.caller_request.headers, "Call-ID")?;
        let caller_from = header(&call_leg.caller_request.headers, "From")?;
        let caller_to = header(&call_leg.caller_request.headers, "To")?;
        let caller_cseq = header(&call_leg.caller_request.headers, "CSeq")?;

        // Build transformed response headers
        let mut new_headers = sip_core::Headers::new();

        // Copy all Via headers from caller's original request (critical for routing)
        for via in call_leg
            .caller_request
            .headers
            .iter()
            .filter(|h| h.name.as_str().eq_ignore_ascii_case("Via"))
        {
            new_headers.push("Via".into(), via.value.clone());
        }

        // Use caller's dialog identifiers
        new_headers.push("Call-ID".into(), caller_call_id.clone());
        new_headers.push("From".into(), caller_from.clone());
        new_headers.push("CSeq".into(), caller_cseq.clone());

        // Handle To header - add callee's To-tag if present (from 200 OK)
        if let Some(callee_to_tag) = header(&callee_response.headers, "To").and_then(|to_hdr| {
            // Extract tag parameter from To header
            to_hdr
                .split(';')
                .find(|part| part.trim().starts_with("tag="))
                .map(|tag_part| {
                    tag_part
                        .trim()
                        .strip_prefix("tag=")
                        .unwrap_or("")
                        .to_string()
                })
        }) {
            // Add tag to caller's To header
            let to_with_tag = format!("{};tag={}", caller_to.as_str(), callee_to_tag);
            new_headers.push("To".into(), to_with_tag.into());

            // Store the callee's To-tag for future ACK/BYE (only for 2xx responses)
            if callee_response.start.code >= 200 && callee_response.start.code < 300 {
                tracing::info!(
                    outgoing_call_id,
                    callee_to_tag = %callee_to_tag,
                    "Storing callee To-tag from 200 OK for future ACK/BYE"
                );
                services
                    .b2bua_state
                    .update_callee_to_tag(outgoing_call_id, callee_to_tag.clone());

                // Create UAC dialog (B2BUA → Alice) for handling re-INVITEs
                // Extract local URI from the From header of outgoing INVITE (B2BUA's URI)
                let local_uri = if let Some(from_hdr) = header(&call_leg.outgoing_invite.headers, "From") {
                    let from_uri = if let Some(start) = from_hdr.find('<') {
                        let end = from_hdr.find('>').unwrap_or(from_hdr.len());
                        &from_hdr[start + 1..end]
                    } else {
                        from_hdr.split(';').next().unwrap_or(from_hdr.as_str()).trim()
                    };
                    sip_core::SipUri::parse(from_uri)
                } else {
                    None
                };

                // Extract remote URI from Alice's Contact header in the 200 OK
                let remote_uri = if let Some(contact) = header(&callee_response.headers, "Contact") {
                    // Extract URI from Contact header
                    let contact_uri = if let Some(start) = contact.find('<') {
                        let end = contact.find('>').unwrap_or(contact.len());
                        &contact[start + 1..end]
                    } else {
                        contact.split(';').next().unwrap_or(contact.as_str()).trim()
                    };
                    sip_core::SipUri::parse(contact_uri)
                } else {
                    None
                };

                if let (Some(local), Some(remote)) = (local_uri, remote_uri) {
                    if let Some(uac_dialog) = sip_dialog::Dialog::new_uac(
                        &call_leg.outgoing_invite,
                        callee_response,
                        local.clone(),
                        remote,
                    ) {
                        tracing::info!(
                            outgoing_call_id,
                            uac_dialog_id = ?uac_dialog.id,
                            "Created and storing UAC dialog for re-INVITE support"
                        );
                        services
                            .b2bua_state
                            .update_uac_dialog(outgoing_call_id, uac_dialog.clone());

                        // Also store in dialog manager for easy lookup
                        services.dialog_mgr.insert(uac_dialog);
                    } else {
                        tracing::warn!(
                            outgoing_call_id,
                            "Failed to create UAC dialog from 200 OK - re-INVITEs may not work"
                        );
                    }
                } else {
                    tracing::warn!(
                        outgoing_call_id,
                        "Failed to extract URIs for UAC dialog creation"
                    );
                }

                // Also create UAS dialog (Bob → B2BUA) for handling re-INVITEs from Bob
                // We need to create a response that matches the transformed one we're sending
                let uas_response = sip_core::Response::new(
                    sip_core::StatusLine::new(200, "OK".into()),
                    new_headers.clone(),
                    callee_response.body.clone(),
                );

                // Extract local and remote URIs for UAS dialog (from Bob's perspective)
                let caller_uri_str = if let Some(start) = caller_from.find('<') {
                    let end = caller_from.find('>').unwrap_or(caller_from.len());
                    &caller_from[start + 1..end]
                } else {
                    caller_from.split(';').next().unwrap_or(caller_from.as_str()).trim()
                };

                if let Some(caller_uri) = sip_core::SipUri::parse(caller_uri_str) {
                    let b2bua_uri = sip_core::SipUri::parse(&services.config.local_uri);
                    if let Some(b2bua_uri) = b2bua_uri {
                        if let Some(uas_dialog) = sip_dialog::Dialog::new_uas(
                            &call_leg.caller_request,
                            &uas_response,
                            b2bua_uri,
                            caller_uri,
                        ) {
                            tracing::info!(
                                outgoing_call_id,
                                uas_dialog_id = ?uas_dialog.id,
                                "Created and storing UAS dialog for re-INVITE support"
                            );
                            services
                                .b2bua_state
                                .update_uas_dialog(outgoing_call_id, uas_dialog.clone());

                            // Also store in dialog manager
                            services.dialog_mgr.insert(uas_dialog);
                        } else {
                            tracing::warn!(
                                outgoing_call_id,
                                "Failed to create UAS dialog from 200 OK - re-INVITEs from caller may not work"
                            );
                        }
                    }
                }
            }
        } else {
            // No To-tag in callee's response (provisional responses may not have it)
            new_headers.push("To".into(), caller_to.clone());
        }

        // IMPORTANT: Replace Contact with B2BUA's own contact
        // This ensures ACK and BYE come through the B2BUA, not directly to callee
        // Use the local_uri from config as our contact
        let b2bua_contact = format!("<{}>", services.config.local_uri);
        new_headers.push("Contact".into(), b2bua_contact.into());

        // Copy Content-Type and Content-Length if body is present
        if !callee_response.body.is_empty() {
            if let Some(content_type) = header(&callee_response.headers, "Content-Type") {
                new_headers.push("Content-Type".into(), content_type.clone());
            }
            let content_length = callee_response.body.len().to_string();
            new_headers.push("Content-Length".into(), content_length.into());
        } else {
            new_headers.push("Content-Length".into(), "0".into());
        }

        // Copy other useful headers
        for header_name in &[
            "Allow",
            "Supported",
            "Server",
            "User-Agent",
            "RSeq",
            "Require",
        ] {
            if let Some(value) = header(&callee_response.headers, header_name) {
                new_headers.push((*header_name).into(), value.clone());
            }
        }

        // Create transformed response
        let transformed = sip_core::Response::new(
            callee_response.start.clone(),
            new_headers,
            callee_response.body.clone(), // Preserve SDP from callee
        );

        tracing::debug!(
            outgoing_call_id,
            status_code = callee_response.start.code,
            "Response transformation complete"
        );

        Some(transformed)
    }

    /// Generate simple SDP for testing
    #[allow(dead_code)]
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
        use sip_parse::serialize_request;
        use sip_proxy::ProxyHelpers;

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
        let proxy_host = services
            .config
            .local_uri
            .split('@')
            .nth(1)
            .unwrap_or("localhost");
        let transport_name = match ctx.transport {
            sip_transaction::TransportKind::Udp => "UDP",
            sip_transaction::TransportKind::Tcp => "TCP",
            sip_transaction::TransportKind::Tls => "TLS",
            sip_transaction::TransportKind::Ws => "WS",
            sip_transaction::TransportKind::Wss => "WSS",
            sip_transaction::TransportKind::Sctp => "SCTP",
            sip_transaction::TransportKind::TlsSctp => "TLS-SCTP",
        };
        let branch = ProxyHelpers::add_via(&mut proxied_req, proxy_host, transport_name);

        // Store proxy transaction for response forwarding
        services
            .proxy_state
            .store_transaction(crate::proxy_state::ProxyTransaction {
                branch: branch.clone(),
                sender_addr: ctx.peer,
                sender_transport: ctx.transport,
                sender_stream: ctx.stream.clone(),
                sender_ws_uri: ctx.ws_uri.clone(),
                call_id: call_id.to_string(),
                created_at: std::time::Instant::now(),
            });

        // Step 3: Add Record-Route (stay in signaling path)
        if let Some(proxy_uri) = sip_core::SipUri::parse(&services.config.local_uri) {
            ProxyHelpers::add_record_route(&mut proxied_req, &proxy_uri);
        }

        // Step 4: Location service lookup
        let target_uri = proxied_req
            .start
            .uri
            .as_sip()
            .ok_or_else(|| anyhow!("Request-URI must be SIP URI for proxy"))?;

        // Normalize lookup key - try multiple transport variants
        let user = target_uri.user.as_deref().unwrap_or("");
        let host = &target_uri.host;

        info!(call_id, target = %target_uri.as_str(), user = %user, host = %host, "Looking up target in location service");

        // Access location store through registrar
        let registrar = services
            .registrar
            .as_ref()
            .ok_or_else(|| anyhow!("Registrar not available in proxy mode"))?;

        // Try multiple lookup strategies to find the user
        // Strategy 1: Try exact match with full URI (includes transport)
        let mut bindings = registrar
            .location_store()
            .lookup(target_uri.as_str())
            .unwrap_or_default();

        // Strategy 2: Try with UDP transport if not found
        if bindings.is_empty() {
            let lookup_udp = format!("sip:{}@{};transport=UDP", user, host);
            bindings = registrar
                .location_store()
                .lookup(&lookup_udp)
                .unwrap_or_default();
        }

        // Strategy 3: Try with TCP transport if not found
        if bindings.is_empty() {
            let lookup_tcp = format!("sip:{}@{};transport=TCP", user, host);
            bindings = registrar
                .location_store()
                .lookup(&lookup_tcp)
                .unwrap_or_default();
        }

        // Strategy 4: Try without any transport parameter
        if bindings.is_empty() {
            let lookup_base = format!("sip:{}@{}", user, host);
            bindings = registrar
                .location_store()
                .lookup(&lookup_base)
                .unwrap_or_default();
        }

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

        // Serialize and send via strict transport selection (RFC 3263 + transport param)
        let payload = serialize_request(&proxied_req);
        let transport_param = contact_uri
            .params
            .get("transport")
            .and_then(|v| v.as_ref())
            .map(|s| s.to_ascii_lowercase());
        let transport = match transport_param.as_deref() {
            Some("udp") => sip_transaction::TransportKind::Udp,
            Some("tcp") => sip_transaction::TransportKind::Tcp,
            Some("tls") => sip_transaction::TransportKind::Tls,
            Some("ws") => sip_transaction::TransportKind::Ws,
            Some("wss") => sip_transaction::TransportKind::Wss,
            _ if contact_uri.sips => sip_transaction::TransportKind::Tls,
            _ => sip_transaction::TransportKind::Udp,
        };

        match transport {
            sip_transaction::TransportKind::Udp => {
                let socket = services
                    .udp_socket
                    .get()
                    .ok_or_else(|| anyhow!("UDP socket not available for proxy forwarding"))?;
                sip_transport::send_udp(socket.as_ref(), &target_addr, &payload).await?;
                info!(call_id, "INVITE forwarded via UDP successfully");
            }
            sip_transaction::TransportKind::Tcp => {
                sip_transport::send_tcp(&target_addr, &payload).await?;
                info!(call_id, "INVITE forwarded via TCP successfully");
            }
            sip_transaction::TransportKind::Tls => {
                #[cfg(feature = "tls")]
                {
                    let config = services
                        .tls_client_config
                        .get()
                        .ok_or_else(|| anyhow!("TLS client config not available"))?;
                    let tls = sip_transport::TlsConfig {
                        server_name: contact_uri.host.to_string(),
                        client_config: config.clone(),
                    };
                    sip_transport::send_tls(&target_addr, &payload, &tls).await?;
                    info!(call_id, "INVITE forwarded via TLS successfully");
                }
                #[cfg(not(feature = "tls"))]
                {
                    return Err(anyhow!("TLS proxy forwarding not enabled"));
                }
            }
            sip_transaction::TransportKind::Ws | sip_transaction::TransportKind::Wss => {
                #[cfg(feature = "ws")]
                {
                    let scheme = if transport == sip_transaction::TransportKind::Wss {
                        "wss"
                    } else {
                        "ws"
                    };
                    let ws_url = format!("{}://{}:{}", scheme, contact_uri.host, target_addr.port());
                    if transport == sip_transaction::TransportKind::Wss {
                        sip_transport::send_wss(&ws_url, payload).await?;
                    } else {
                        sip_transport::send_ws(&ws_url, payload).await?;
                    }
                    info!(call_id, url = %ws_url, "INVITE forwarded via WS/WSS successfully");
                }
                #[cfg(not(feature = "ws"))]
                {
                    return Err(anyhow!("WS/WSS proxy forwarding not enabled"));
                }
            }
            sip_transaction::TransportKind::Sctp | sip_transaction::TransportKind::TlsSctp => {
                return Err(anyhow!("SCTP proxy forwarding not implemented"));
            }
        }

        info!(call_id, "Proxy response forwarding enabled for this transaction");

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
            return self
                .handle_b2bua(request, handle, ctx, services, call_id)
                .await;
        }

        // PROXY MODE: Forward request to registered user
        if services.config.enable_proxy() {
            return self
                .handle_proxy(request, handle, ctx, services, call_id)
                .await;
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
            let mut dialog = match services.dialog_mgr.find_by_request(request) {
                Some(dialog) => dialog,
                None => {
                    warn!(call_id, "re-INVITE received for unknown dialog");
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
                warn!(call_id, "re-INVITE rejected: invalid CSeq or dialog state");
                let response = UserAgentServer::create_response(request, 400, "Bad Request");
                handle.send_final(response).await;
                return Ok(());
            }

            let sdp_body = if !request.body.is_empty() {
                match std::str::from_utf8(&request.body) {
                    Ok(offer_str) => match sdp_utils::generate_sdp_answer(&services.config, offer_str) {
                        Ok(answer) => Some(answer),
                        Err(e) => {
                            warn!(call_id, error = %e, "Failed to generate SDP answer for re-INVITE");
                            let response =
                                UserAgentServer::create_response(request, 488, "Not Acceptable Here");
                            handle.send_final(response).await;
                            return Ok(());
                        }
                    },
                    Err(_) => None,
                }
            } else {
                match sdp_utils::generate_sdp_offer(&services.config) {
                    Ok(offer) => Some(offer),
                    Err(e) => {
                        warn!(call_id, error = %e, "Failed to generate SDP offer for re-INVITE");
                        let response =
                            UserAgentServer::create_response(request, 488, "Not Acceptable Here");
                        handle.send_final(response).await;
                        return Ok(());
                    }
                }
            };

            let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
                Some(uri) => uri,
                None => {
                    warn!("Invalid local_uri in config");
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

            let ok = uas.create_ok(request, sdp_body.as_deref());
            dialog.update_from_response(&ok);

            if services.config.features.enable_session_timers {
                if let Some(session_expires) = dialog.session_expires {
                    let is_refresher = matches!(
                        dialog.refresher,
                        Some(sip_core::RefresherRole::Uac)
                    );
                    services.session_timer_mgr.refresh_timer(
                        dialog.id.clone(),
                        session_expires,
                        is_refresher,
                    );
                }
            }
            services.dialog_mgr.insert(dialog);
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

        if services.config.features.enable_session_timers {
            if let Err(response) =
                UserAgentServer::validate_session_timer(request, None)
            {
                handle.send_final(response).await;
                return Ok(());
            }
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
        let mut uas = UserAgentServer::new(local_uri, contact_uri);
        uas.dialog_manager = services.dialog_mgr.clone();
        uas.subscription_manager = services.subscription_mgr.clone();
        uas.rseq_manager = services.rseq_mgr.clone();
        uas.prack_validator = services.prack_validator.clone();

        // Send 100 Trying
        let trying = UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        // Store transaction handle and headers for potential CANCEL
        let mut pending_key = None;
        if let Some((key, pending)) =
            crate::invite_state::InviteStateManager::pending_from_request(
                handle.clone(),
                request,
            )
        {
            services.invite_state.store_pending_invite(key.clone(), pending);
            pending_key = Some(key);
        } else {
            warn!(call_id, "Unable to track INVITE for CANCEL (missing headers)");
        }

        // Validate SDP early (if present) before sending 180 Ringing
        // RFC 3261 §21.4.13: Send 488 Not Acceptable Here for malformed/unsupported SDP
        if !request.body.is_empty() {
            if let Ok(offer_str) = std::str::from_utf8(&request.body) {
                if let Err(e) = sdp_utils::generate_sdp_answer(&services.config, offer_str) {
                    warn!(call_id, error = %e, "SDP validation failed, rejecting with 488");
                    let mut headers = sip_core::Headers::new();
                    copy_dialog_headers(request, &mut headers);
                    let response = sip_core::Response::new(
                        sip_core::StatusLine::new(488, "Not Acceptable Here".into()),
                        headers,
                        bytes::Bytes::new(),
                    );
                    handle.send_final(response).await;
                    if let Some(key) = pending_key.as_deref() {
                        services.invite_state.remove_pending_invite(key);
                    }
                    return Ok(());
                }
            }
        }

        info!(call_id, "Call accepted, sending 180 Ringing");

        // Send 180 Ringing (with optional reliable provisional)
        if services.config.features.enable_prack
            && request
                .headers
                .get("Supported")
                .map(|s| s.contains("100rel"))
                .unwrap_or(false)
        {
            let mut ringing = uas.create_ringing(request);
            let mut reliable_info: Option<(String, u32)> = None;

            let remote_uri = header(&request.headers, "From")
                .and_then(|from| sdp_utils::parse_name_addr_uri(from.as_str()));

            if let Some(remote_uri) = remote_uri {
                if let Some(early_dialog) =
                    Dialog::new_uas(request, &ringing, uas.local_uri.clone(), remote_uri)
                {
                    services.dialog_mgr.insert(early_dialog.clone());

                    let rseq = services.rseq_mgr.next_rseq(&early_dialog.id);
                    reliable_info = Some((Self::dialog_id_key(&early_dialog.id), rseq));
                    ringing.headers.push("RSeq".into(), rseq.to_string().into());
                    ringing
                        .headers
                        .push("Require".into(), "100rel".into());
                    ringing.headers.push(
                        "Contact".into(),
                        format!("<{}>", services.config.local_uri).into(),
                    );

                    if let Some(cseq) = header(&request.headers, "CSeq")
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse::<u32>().ok())
                    {
                        services.prack_validator.register_reliable_provisional(
                            &Self::dialog_id_key(&early_dialog.id),
                            rseq,
                            cseq,
                            request.start.method.clone(),
                            180,
                        );
                    }
                }
            }

            let ringing_for_retransmit = ringing.clone();
            if let (Some(key), Some(to)) = (pending_key.as_deref(), header(&ringing.headers, "To"))
            {
                services.invite_state.update_to_header(key, to.clone());
            }
            handle.send_provisional(ringing).await;

            if let Some((dialog_key, rseq)) = reliable_info {
                Self::schedule_reliable_retransmit(
                    services,
                    handle.key().clone(),
                    ringing_for_retransmit,
                    dialog_key,
                    rseq,
                );
            }
        } else {
            let ringing = uas.create_ringing(request);
            if let (Some(key), Some(to)) = (pending_key.as_deref(), header(&ringing.headers, "To"))
            {
                services.invite_state.update_to_header(key, to.clone());
            }
            handle.send_provisional(ringing).await;
        }

        // Delay before auto-accepting to allow CANCEL to arrive
        // In real-world scenarios, this delay is natural (waiting for user to answer).
        // In auto-accept mode, we need a small delay to avoid a race condition where
        // the call is accepted (200 OK sent) before CANCEL can be processed.
        // Without this delay, the pending INVITE is removed before CANCEL arrives,
        // preventing the 487 Request Terminated response.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Generate SDP answer (already validated earlier, so this should succeed)
        let sdp_answer = if !request.body.is_empty() {
            match std::str::from_utf8(&request.body) {
                Ok(offer_str) => {
                    // SDP was already validated earlier, so this should not fail
                    sdp_utils::generate_sdp_answer(&services.config, offer_str).ok()
                }
                Err(e) => {
                    warn!(call_id, error = %e, "Invalid UTF-8 in SDP offer");
                    None
                }
            }
        } else {
            // Late offer - should send SDP in 200 OK
            warn!(
                call_id,
                "Late offer INVITE received - generating SDP offer in 200 OK and expecting answer in ACK"
            );
            match sdp_utils::generate_sdp_offer(&services.config) {
                Ok(offer) => Some(offer),
                Err(e) => {
                    warn!(call_id, error = %e, "Failed to generate SDP offer");
                    let mut headers = sip_core::Headers::new();
                    copy_dialog_headers(request, &mut headers);
                    let response = sip_core::Response::new(
                        sip_core::StatusLine::new(488, "Not Acceptable Here".into()),
                        headers,
                        bytes::Bytes::new(),
                    );
                    handle.send_final(response).await;
                    if let Some(key) = pending_key.as_deref() {
                        services.invite_state.remove_pending_invite(key);
                    }
                    return Ok(());
                }
            }
        };

        // Accept the INVITE
        let result = uas.accept_invite(request, sdp_answer.as_deref());

        match result {
            Ok((mut response, mut dialog)) => {
                if services.config.features.enable_session_timers {
                    let has_se = response.headers.get("Session-Expires").is_some();
                    if !has_se {
                        response.headers.push(
                            "Session-Expires".into(),
                            sip_dialog::session_timer_manager::DEFAULT_SESSION_EXPIRES
                                .as_secs()
                                .to_string()
                                .into(),
                        );
                        response
                            .headers
                            .push("Supported".into(), "timer".into());
                        response
                            .headers
                            .push("Min-SE".into(), "90".into());
                    }

                    dialog.update_from_response(&response);

                    if let Some(session_expires) = dialog.session_expires {
                        let is_refresher = matches!(
                            dialog.refresher,
                            Some(sip_core::RefresherRole::Uac)
                        );
                        services
                            .session_timer_mgr
                            .start_timer(dialog.id.clone(), session_expires, is_refresher);
                    }
                }

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

                // Remove from pending invites (transaction completed)
                if let Some(key) = pending_key.as_deref() {
                    services.invite_state.remove_pending_invite(key);
                }
            }
            Err(e) => {
                warn!(call_id, error = %e, "Failed to accept INVITE");
                let error = uas.create_decline(request);
                handle.send_final(error).await;

                // Remove from pending invites (transaction completed with error)
                if let Some(key) = pending_key.as_deref() {
                    services.invite_state.remove_pending_invite(key);
                }
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
