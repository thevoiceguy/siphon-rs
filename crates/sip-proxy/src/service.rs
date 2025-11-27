use crate::{
    stateful::{
        forwarding, BranchInfo, BranchState, ForkMode, ProxyContext, ProxyTarget, StatefulProxy,
    },
    ProxyHelpers,
};
use sip_core::{Method, Request, SipUri};
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
    pub fn start_forking(
        &self,
        original: Request,
        targets: Vec<ProxyTarget>,
        proxy_host: &str,
        transport: &str,
        add_record_route: bool,
        proxy_uri: Option<&SipUri>,
        fork_mode: ForkMode,
    ) -> (
        Arc<ProxyContext>,
        mpsc::UnboundedReceiver<sip_core::Response>,
        Vec<(SmolStr, Request)>,
    ) {
        let call_id = original
            .headers
            .get("Call-ID")
            .cloned()
            .unwrap_or_else(|| SmolStr::new("unknown-callid"));
        let client_branch = ProxyHelpers::add_via(&mut original.clone(), proxy_host, transport);

        let (context, response_rx) = self.proxy.start_context(
            original.clone(),
            call_id.clone(),
            SmolStr::new(client_branch.clone()),
            fork_mode,
        );

        let mut forwarded = Vec::new();
        for target in targets {
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
                let ctx_clone = context.clone();
                tokio::spawn(async move {
                    ctx_clone.add_branch(branch_info).await;
                });
            }
        }

        (context, response_rx, forwarded)
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
            if resp.start.code >= 200 && resp.start.code < 300 {
                let cancel_template = build_cancel_template(&context.original_request);
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
fn build_cancel_template(original: &Request) -> Request {
    let mut cancel = original.clone();
    cancel.start.method = Method::Cancel;

    // Update CSeq to CANCEL with same sequence number
    if let Some(cseq_val) = cancel.headers.get("CSeq").cloned() {
        if let Some((num, _)) = cseq_val.split_once(' ') {
            for header in cancel.headers.iter_mut() {
                if header.name.as_str().eq_ignore_ascii_case("CSeq") {
                    header.value = format!("{} CANCEL", num).into();
                    break;
                }
            }
        }
    }

    cancel
}
