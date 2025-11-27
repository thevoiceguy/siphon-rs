/// REFER request handler.
///
/// Implements RFC 3515 call transfer:
/// 1. Accept REFER requests
/// 2. Create implicit subscription to "refer" event
/// 3. Send 202 Accepted
/// 4. (Future: Send NOTIFY with sipfrag progress)
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use sip_uas::UserAgentServer;
use tracing::{info, warn};

use super::RequestHandler;
use crate::services::ServiceRegistry;

pub struct ReferHandler;

impl ReferHandler {
    pub fn new() -> Self {
        Self
    }

    /// Extract Refer-To URI from header
    fn extract_refer_to(request: &Request) -> Option<String> {
        let refer_to = header(&request.headers, "Refer-To")?;
        Some(refer_to.to_string())
    }

    /// Check if this is an attended transfer (has Replaces header in Refer-To)
    fn is_attended_transfer(refer_to: &str) -> bool {
        refer_to.contains("Replaces=") || refer_to.contains("Replaces%3D")
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
        let call_id = header(&request.headers, "Call-ID")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        // Check if REFER is enabled
        if !services.config.features.enable_refer {
            warn!(call_id, "REFER rejected: feature not enabled");
            let mut headers = sip_core::Headers::new();
            copy_headers(request, &mut headers);
            let response = sip_core::Response::new(
                sip_core::StatusLine::new(501, "Not Implemented".into()),
                headers,
                bytes::Bytes::new(),
            );
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
                sip_core::StatusLine::new(481, "Call/Transaction Does Not Exist".into()),
                headers,
                bytes::Bytes::new(),
            );
            handle.send_final(response).await;
            return Ok(());
        }

        let dialog = dialog.unwrap();

        // Parse local URI from config
        let local_uri = match sip_core::SipUri::parse(&services.config.local_uri) {
            Some(uri) => uri,
            None => {
                warn!("Invalid local_uri in config");
                let error = UserAgentServer::reject_refer(request, 603, "Decline");
                handle.send_final(error).await;
                return Ok(());
            }
        };

        let contact_uri = local_uri.clone();

        // Create UAS and accept REFER
        let uas = UserAgentServer::new(local_uri, contact_uri);
        let result = uas.accept_refer(request, &dialog);

        match result {
            Ok((response, refer_to_target)) => {
                info!(call_id, refer_to = refer_to_target, "REFER accepted");

                // Send 202 Accepted
                handle.send_final(response).await;

                // TODO: Create implicit subscription and send NOTIFY
                // TODO: Initiate the referred call
                // 1. Parse refer_to URI
                // 2. Create new INVITE transaction
                // 3. Send NOTIFY with sipfrag progress (100 Trying, 180 Ringing, 200 OK, etc.)
                //
                // For now, we just accept the REFER but don't actually perform the transfer.
                // A full implementation would:
                // - If attended: Send INVITE with Replaces header
                // - If blind: Send INVITE to refer_to target
                // - Send NOTIFYs with message/sipfrag body as call progresses

                info!(
                    call_id,
                    "REFER accepted - actual transfer not implemented yet"
                );
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
