// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    stateful::{
        forwarding, BranchInfo, BranchState, ForkMode, ProxyContext, ProxyTarget, StatefulProxy,
    },
    ProxyHelpers,
};
use anyhow::{anyhow, Result};
use sip_core::{is_valid_branch, Method, Request, RequestLine, SipUri};
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Actions returned when processing a branch response.
pub struct ProxyActions {
    pub forward: Option<ResponseAction>,
    pub cancels: Vec<Request>,
}

/// Response to forward upstream.
pub struct ResponseAction {
    pub response: sip_core::Response,
}

/// High-level proxy service that glues stateful proxy context with forwarding helpers.
pub struct ProxyService {
    proxy: StatefulProxy,
}

impl Default for ProxyService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyService {
    /// Create a new proxy service.
    pub fn new() -> Self {
        Self {
            proxy: StatefulProxy::new(),
        }
    }

    /// Start proxying a request to multiple targets.
    ///
    /// Returns the proxy context, an upstream response receiver, and the prepared outbound
    /// requests to dispatch to each target.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_forking(
        &self,
        original: Request,
        targets: Vec<ProxyTarget>,
        proxy_host: &str,
        transport: &str,
        add_record_route: bool,
        proxy_uri: Option<&SipUri>,
        fork_mode: ForkMode,
    ) -> Result<(
        Arc<ProxyContext>,
        mpsc::UnboundedReceiver<sip_core::Response>,
        Vec<(SmolStr, Request)>,
    )> {
        let call_id = original
            .headers()
            .get_smol("Call-ID")
            .cloned()
            .ok_or_else(|| anyhow!("Missing Call-ID header"))?;
        let client_branch = extract_top_via_branch(&original)?;

        let (context, response_rx) = self.proxy.start_context(
            original.clone(),
            call_id.clone(),
            SmolStr::new(client_branch),
            SmolStr::new(proxy_host),
            SmolStr::new(transport),
            fork_mode,
        );

        let mut forwarded = Vec::new();
        let mut ordered_targets = targets;
        if matches!(fork_mode, ForkMode::Sequential) {
            ordered_targets.sort_by(|a, b| {
                a.priority.cmp(&b.priority).then_with(|| {
                    b.q_value
                        .partial_cmp(&a.q_value)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            });
        }
        if matches!(fork_mode, ForkMode::None | ForkMode::Sequential) {
            ordered_targets.truncate(1);
        }

        for target in ordered_targets {
            if let Ok((request, branch)) = forwarding::prepare_forward(
                &original,
                &target.uri,
                proxy_host,
                transport,
                add_record_route,
                proxy_uri,
            ) {
                let branch_info = BranchInfo {
                    branch_id: branch.clone(),
                    target: target.uri.clone(),
                    created_at: std::time::Instant::now(),
                    state: BranchState::Trying,
                    best_response: None,
                };
                forwarded.push((branch.clone(), request.clone()));
                // Track branch in context
                context.add_branch(branch_info).await;
            }
        }

        Ok((context, response_rx, forwarded))
    }

    /// Process a response from a branch and produce actions (forward upstream, send CANCELs).
    pub async fn handle_branch_response(
        &self,
        context: &Arc<ProxyContext>,
        branch_id: &str,
        response: sip_core::Response,
    ) -> ProxyActions {
        let forward = context.process_response(branch_id, response).await;

        // Build CANCELs for losing branches if we have a winning 2xx
        let cancels = if let Some(ref resp) = forward {
            if resp.code() >= 200 && resp.code() < 300 {
                let cancel_template = build_cancel_template(
                    &context.original_request,
                    context.proxy_host.as_str(),
                    context.transport.as_str(),
                );
                context.build_cancel_requests(&cancel_template).await
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        ProxyActions {
            forward: forward.map(|r| ResponseAction { response: r }),
            cancels,
        }
    }

    /// Prepare an ACK for forwarding using proxy context (uses best response to classify 2xx vs non-2xx).
    pub async fn forward_ack(&self, context: &Arc<ProxyContext>, ack: &Request) -> Option<Request> {
        context.prepare_ack_forward(ack).await.ok()
    }
}

/// Build a CANCEL template from the original INVITE.
fn build_cancel_template(original: &Request, proxy_host: &str, transport: &str) -> Request {
    let mut headers = original.headers().clone();
    headers.remove("Content-Type");
    headers.remove("Content-Length");
    let mut cancel = Request::new(
        RequestLine::new(Method::Cancel, original.uri().clone()),
        headers,
        bytes::Bytes::new(),
    )
    .expect("valid CANCEL request");

    // Ensure the proxy is the top Via for downstream CANCELs.
    ProxyHelpers::add_via(&mut cancel, proxy_host, transport);

    // Update CSeq to CANCEL with same sequence number
    if let Some(cseq_val) = cancel.headers().get("CSeq").map(|val| val.to_string()) {
        if let Some((num, _)) = cseq_val.split_once(' ') {
            let _ = cancel
                .headers_mut()
                .set_or_push("CSeq", format!("{} CANCEL", num));
        }
    }

    cancel
}

fn extract_top_via_branch(request: &Request) -> Result<SmolStr> {
    let via = request
        .headers()
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case("Via"))
        .ok_or_else(|| anyhow!("Missing Via header"))?;

    for part in via.value().split(';') {
        let trimmed = part.trim();
        if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("branch=") {
            let branch = &trimmed[7..];
            if is_valid_branch(branch) {
                return Ok(SmolStr::new(branch));
            }
            return Err(anyhow!("Invalid Via branch parameter"));
        }
    }

    Err(anyhow!("Via header missing branch parameter"))
}
