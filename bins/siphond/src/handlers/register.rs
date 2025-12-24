// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// REGISTER request handler.
///
/// Implements RFC 3261 §10 REGISTER processing:
/// 1. Optional authentication challenge (401 Unauthorized)
/// 2. Binding management (add/remove/update contacts)
/// 3. Response with registered contacts and expiry
use anyhow::Result;
use async_trait::async_trait;
use sip_core::Request;
use sip_parse::header;
use sip_registrar::Registrar;
use sip_transaction::{ServerTransactionHandle, TransportContext};
use tracing::{info, warn};

use super::RequestHandler;
use crate::services::ServiceRegistry;

pub struct RegisterHandler;

impl RegisterHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RequestHandler for RegisterHandler {
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

        // Check if registrar is enabled
        let registrar = match &services.registrar {
            Some(reg) => reg,
            None => {
                warn!(call_id, "REGISTER rejected: registrar not enabled");
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
        };

        info!(call_id, "Processing REGISTER request");

        // Process registration using the registrar
        let response = registrar.as_ref().handle_register(request)?;

        // Log the outcome
        match response.start.code {
            200 => {
                let to = header(&request.headers, "To")
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                let contact = header(&request.headers, "Contact")
                    .map(|s| s.as_str())
                    .unwrap_or("none");

                info!(
                    call_id,
                    aor = to,
                    contact,
                    code = response.start.code,
                    "Registration successful"
                );
            }
            401 => {
                info!(call_id, "Authentication challenge sent");
            }
            code => {
                warn!(call_id, code, reason = %response.start.reason, "Registration failed");
            }
        }

        handle.send_final(response).await;
        Ok(())
    }

    fn method(&self) -> &str {
        "REGISTER"
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
