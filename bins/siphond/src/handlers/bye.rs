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
use crate::services::ServiceRegistry;

pub struct ByeHandler;

impl ByeHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequestHandler for ByeHandler {
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

        // Look up dialog using request
        let dialog = services.dialog_mgr.find_by_request(request);

        match dialog {
            Some(dialog) => {
                info!(
                    call_id,
                    dialog_id = %dialog.id.call_id,
                    state = ?dialog.state,
                    "Dialog found, processing BYE"
                );

                // Create 200 OK response
                let response = UserAgentServer::create_response(request, 200, "OK");

                // Remove dialog from manager
                services.dialog_mgr.remove(&dialog.id);

                info!(call_id, "Dialog terminated successfully");

                // Send 200 OK
                handle.send_final(response).await;
            }
            None => {
                warn!(
                    call_id,
                    "BYE received for unknown dialog"
                );

                // Send 481 Call/Transaction Does Not Exist
                let mut headers = sip_core::Headers::new();
                copy_headers(request, &mut headers);

                let response = sip_core::Response::new(
                    sip_core::StatusLine::new(481, "Call/Transaction Does Not Exist".into()),
                    headers,
                    bytes::Bytes::new(),
                );

                handle.send_final(response).await;
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
