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
                     o=siphond {} {} IN IP4 127.0.0.1\r\n\
                     s=siphond call\r\n\
                     c=IN IP4 127.0.0.1\r\n\
                     t=0 0\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    rand::random::<u32>(),
                    rand::random::<u32>()
                );

                Ok(sdp)
            }
            crate::config::SdpProfile::AudioVideo => {
                if !has_audio {
                    return Err(anyhow!("No audio in offer"));
                }

                let mut sdp = format!(
                    "v=0\r\n\
                     o=siphond {} {} IN IP4 127.0.0.1\r\n\
                     s=siphond call\r\n\
                     c=IN IP4 127.0.0.1\r\n\
                     t=0 0\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    rand::random::<u32>(),
                    rand::random::<u32>()
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
}

#[async_trait]
impl RequestHandler for InviteHandler {
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

        // Check if call handling is enabled
        if !services.config.enable_calls() {
            info!(call_id, "INVITE rejected: call handling disabled");
            let decline = UserAgentServer::create_decline(request);
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
            let busy = UserAgentServer::create_busy(request);
            handle.send_final(busy).await;
            return Ok(());
        }

        // Send 100 Trying
        let trying = UserAgentServer::create_trying(request);
        handle.send_provisional(trying).await;

        info!(call_id, "Call accepted, sending 180 Ringing");

        // Send 180 Ringing (with optional reliable provisional)
        if services.config.features.enable_prack && request.headers.get("Supported").map(|s| s.contains("100rel")).unwrap_or(false) {
            // TODO: Send reliable 180 with RSeq
            let ringing = UserAgentServer::create_ringing(request);
            handle.send_provisional(ringing).await;
        } else {
            let ringing = UserAgentServer::create_ringing(request);
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

        // Parse local and contact URIs
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Some(uri) => uri,
            None => {
                warn!("Invalid local_uri in config: {}", services.config.local_uri);
                return Err(anyhow!("Invalid local_uri configuration"));
            }
        };

        let contact_uri = local_uri.clone();

        // Create UAS and accept the INVITE
        let uas = UserAgentServer::new(local_uri, contact_uri);
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
                let error = UserAgentServer::create_decline(request);
                handle.send_final(error).await;
            }
        }

        Ok(())
    }

    fn method(&self) -> &str {
        "INVITE"
    }
}

/// Extract tag parameter from header value
fn extract_tag(header: Option<&smol_str::SmolStr>) -> Option<&str> {
    let header = header?;
    for param in header.split(';') {
        let param = param.trim();
        if param.to_lowercase().starts_with("tag=") {
            return Some(&param[4..]);
        }
    }
    None
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
