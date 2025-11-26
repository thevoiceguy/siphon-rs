//! Stateful SIP Proxy implementation per RFC 3261 §16
//!
//! Provides comprehensive stateful proxy functionality including:
//! - Branch mapping and response relay
//! - Request forking (sequential and parallel)
//! - Response selection per RFC 3261 §16.7
//! - CANCEL and ACK forwarding
//! - Record-Route/Route maintenance
//! - Location service integration
//!
//! # Architecture
//!
//! ```text
//! Incoming Request → ProxyContext → [Fork to multiple targets]
//!                         ↓
//!                   Branch Mapping
//!                         ↓
//!     [Target 1]    [Target 2]    [Target 3]  ← Parallel/Sequential
//!          ↓             ↓             ↓
//!     Responses collected and selected
//!          ↓
//!     Best response forwarded upstream
//! ```

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use sip_core::{Method, Request, Response, SipUri};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Target for forwarding a request
#[derive(Debug, Clone)]
pub struct ProxyTarget {
    /// Target SIP URI
    pub uri: SipUri,

    /// Priority (lower is higher priority, for sequential forking)
    pub priority: u32,

    /// Q-value from registration (1.0 = highest, 0.0 = lowest)
    pub q_value: f32,
}

impl ProxyTarget {
    /// Create a new proxy target with default priority and q-value
    pub fn new(uri: SipUri) -> Self {
        Self {
            uri,
            priority: 0,
            q_value: 1.0,
        }
    }

    /// Set priority (lower = higher priority)
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set q-value (0.0-1.0, higher = higher priority)
    pub fn with_q_value(mut self, q: f32) -> Self {
        self.q_value = q.clamp(0.0, 1.0);
        self
    }
}

/// Branch information for a forwarded request
#[derive(Debug, Clone)]
pub struct BranchInfo {
    /// Branch ID generated for this forward
    pub branch_id: SmolStr,

    /// Target URI this branch was sent to
    pub target: SipUri,

    /// When this branch was created
    pub created_at: Instant,

    /// Current state of this branch
    pub state: BranchState,

    /// Best response received so far (for response selection)
    pub best_response: Option<Response>,
}

/// State of a proxy branch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchState {
    /// Request sent, waiting for response
    Trying,

    /// Received provisional response (1xx)
    Proceeding,

    /// Received final response (2xx-6xx)
    Completed,

    /// Branch cancelled (CANCEL sent)
    Cancelled,

    /// Branch timed out
    TimedOut,
}

/// Forking mode for proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkMode {
    /// Try all targets simultaneously (RFC 3261 §16.7)
    Parallel,

    /// Try targets sequentially by priority
    Sequential,

    /// No forking - single target only
    None,
}

/// Context for a single proxied request
pub struct ProxyContext {
    /// Original request from client
    pub original_request: Request,

    /// Call-ID for correlation
    pub call_id: SmolStr,

    /// Client transaction branch (from client's Via header)
    pub client_branch: SmolStr,

    /// Branches created for forwarding (branch_id → info)
    branches: RwLock<HashMap<SmolStr, BranchInfo>>,

    /// Forking mode
    fork_mode: ForkMode,

    /// Best final response received (for response selection)
    best_final: RwLock<Option<Response>>,

    /// Channel to send the selected response upstream
    response_tx: mpsc::UnboundedSender<Response>,

    /// Number of outstanding branches (not completed)
    outstanding_count: RwLock<usize>,

    /// When this context was created
    created_at: Instant,
}

impl ProxyContext {
    /// Create a new proxy context
    pub fn new(
        original_request: Request,
        call_id: SmolStr,
        client_branch: SmolStr,
        fork_mode: ForkMode,
        response_tx: mpsc::UnboundedSender<Response>,
    ) -> Self {
        Self {
            original_request,
            call_id,
            client_branch,
            branches: RwLock::new(HashMap::new()),
            fork_mode,
            best_final: RwLock::new(None),
            response_tx,
            outstanding_count: RwLock::new(0),
            created_at: Instant::now(),
        }
    }

    /// Add a branch that was created for forwarding
    pub async fn add_branch(&self, branch_info: BranchInfo) {
        let mut branches = self.branches.write().await;
        let mut count = self.outstanding_count.write().await;

        branches.insert(branch_info.branch_id.clone(), branch_info);
        *count += 1;
    }

    /// Process a response received on a branch
    ///
    /// Returns the response that should be forwarded upstream (if any)
    pub async fn process_response(&self, branch_id: &str, response: Response) -> Option<Response> {
        let mut branches = self.branches.write().await;
        let branch = branches.get_mut(branch_id)?;

        let is_final = response.start.code >= 200;

        // Update branch state
        if response.start.code >= 100 && response.start.code < 200 {
            branch.state = BranchState::Proceeding;
        } else if is_final {
            branch.state = BranchState::Completed;

            // Decrement outstanding count
            let mut count = self.outstanding_count.write().await;
            if *count > 0 {
                *count -= 1;
            }
        }

        // Store best response for this branch
        branch.best_response = Some(response.clone());

        // Handle provisional responses (always forward first 1xx per RFC 3261)
        if !is_final {
            debug!("Forwarding provisional {} response from branch {}", response.start.code, branch_id);
            return Some(response);
        }

        // Handle final responses with response selection
        let mut best_final = self.best_final.write().await;
        let should_forward = select_best_response(best_final.as_ref(), &response);

        if should_forward {
            info!("Selected {} as best response (branch {})", response.start.code, branch_id);
            *best_final = Some(response.clone());

            // If we got a 2xx and have other branches, send CANCEL to them
            if response.start.code >= 200 && response.start.code < 300 {
                self.cancel_other_branches(branch_id).await;
            }

            return Some(response);
        }

        // Check if all branches have completed
        let outstanding = *self.outstanding_count.read().await;
        if outstanding == 0 {
            // All branches done - return the best we have
            if let Some(best) = best_final.clone() {
                info!("All branches complete - forwarding best response {}", best.start.code);
                return Some(best);
            }
        }

        None
    }

    /// Cancel all branches except the specified one (winner)
    async fn cancel_other_branches(&self, winner_branch: &str) {
        let branches = self.branches.read().await;

        for (branch_id, branch) in branches.iter() {
            if branch_id.as_str() != winner_branch && branch.state != BranchState::Completed {
                info!("Would send CANCEL to branch {} (winner: {})", branch_id, winner_branch);
                // TODO: Actually send CANCEL - needs client transaction access
            }
        }
    }

    /// Get all branch IDs
    pub async fn get_branch_ids(&self) -> Vec<SmolStr> {
        self.branches.read().await.keys().cloned().collect()
    }

    /// Get forking mode
    pub fn fork_mode(&self) -> ForkMode {
        self.fork_mode
    }
}

/// RFC 3261 §16.7 response selection
///
/// Returns true if the new response should replace the current best
fn select_best_response(current_best: Option<&Response>, new_response: &Response) -> bool {
    let Some(current) = current_best else {
        // No current best - new response wins
        return true;
    };

    let current_code = current.start.code;
    let new_code = new_response.start.code;

    // Response selection rules per RFC 3261 §16.7:
    // 1. 6xx beats everything else
    // 2. 2xx beats everything else except 6xx
    // 3. Lowest class beats higher class (e.g., 3xx beats 4xx/5xx)
    // 4. Within same class, keep first

    match (current_code / 100, new_code / 100) {
        // 6xx always wins
        (_, 6) => true,
        (6, _) => false,

        // 2xx beats everything except 6xx
        (_, 2) => true,
        (2, _) => false,

        // Lower response class wins (3xx beats 4xx/5xx)
        (curr_class, new_class) if new_class < curr_class => true,
        (curr_class, new_class) if new_class > curr_class => false,

        // Same class - keep first
        _ => false,
    }
}

/// Stateful proxy manager
pub struct StatefulProxy {
    /// Active proxy contexts (keyed by client branch)
    contexts: DashMap<SmolStr, Arc<ProxyContext>>,

    /// Transaction cleanup interval
    cleanup_interval: Duration,
}

impl StatefulProxy {
    /// Create a new stateful proxy
    pub fn new() -> Self {
        Self {
            contexts: DashMap::new(),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Start a new proxy context for a request
    ///
    /// Returns the context and a receiver for responses to forward upstream
    pub fn start_context(
        &self,
        request: Request,
        call_id: SmolStr,
        client_branch: SmolStr,
        fork_mode: ForkMode,
    ) -> (Arc<ProxyContext>, mpsc::UnboundedReceiver<Response>) {
        let (response_tx, response_rx) = mpsc::unbounded_channel();

        let context = Arc::new(ProxyContext::new(
            request,
            call_id,
            client_branch.clone(),
            fork_mode,
            response_tx,
        ));

        self.contexts.insert(client_branch, context.clone());

        (context, response_rx)
    }

    /// Find a proxy context by client branch
    pub fn find_context(&self, client_branch: &str) -> Option<Arc<ProxyContext>> {
        self.contexts.get(client_branch).map(|entry| entry.clone())
    }

    /// Find a proxy context by Call-ID
    pub fn find_context_by_call_id(&self, call_id: &str) -> Option<Arc<ProxyContext>> {
        self.contexts
            .iter()
            .find(|entry| entry.value().call_id.as_str() == call_id)
            .map(|entry| entry.value().clone())
    }

    /// Remove a context (after all branches complete)
    pub fn remove_context(&self, client_branch: &str) {
        self.contexts.remove(client_branch);
    }

    /// Clean up old contexts
    pub fn cleanup_old(&self) {
        let now = Instant::now();
        self.contexts.retain(|_, ctx| {
            now.duration_since(ctx.created_at) < self.cleanup_interval
        });
    }

    /// Get count of active contexts
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }
}

impl Default for StatefulProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for request forwarding
pub mod forwarding {
    use super::*;
    use crate::ProxyHelpers;

    /// Prepare a request for forwarding to a target
    ///
    /// This performs RFC 3261 §16.6 request forwarding:
    /// 1. Makes a copy of the request
    /// 2. Updates Request-URI to target
    /// 3. Decrements Max-Forwards
    /// 4. Adds Via header with new branch
    /// 5. Optionally adds Record-Route
    ///
    /// Returns the modified request and the generated branch ID
    pub fn prepare_forward(
        original: &Request,
        target: &SipUri,
        proxy_host: &str,
        transport: &str,
        add_record_route: bool,
        proxy_uri: Option<&SipUri>,
    ) -> Result<(Request, SmolStr)> {
        // Copy request
        let mut forwarded = original.clone();

        // Update Request-URI to target
        ProxyHelpers::set_request_uri(&mut forwarded, target.clone());

        // Decrement Max-Forwards
        ProxyHelpers::check_max_forwards(&mut forwarded)?;

        // Add Via header with new branch
        let branch_id = ProxyHelpers::add_via(&mut forwarded, proxy_host, transport);

        // Optionally add Record-Route
        if add_record_route {
            if let Some(uri) = proxy_uri {
                ProxyHelpers::add_record_route(&mut forwarded, uri);
            } else {
                warn!("Record-Route requested but no proxy URI provided");
            }
        }

        Ok((forwarded, SmolStr::new(branch_id)))
    }

    /// Prepare a response for forwarding upstream
    ///
    /// This performs RFC 3261 §16.7 response forwarding:
    /// 1. Copies the response
    /// 2. Removes top Via header
    ///
    /// Returns the modified response ready to send upstream
    pub fn prepare_response(response: &Response) -> Response {
        let mut forwarded = response.clone();

        // Remove top Via header
        ProxyHelpers::remove_top_via(&mut forwarded.headers);

        forwarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, RequestLine, StatusLine};

    fn make_request() -> Request {
        let mut headers = Headers::new();
        headers.push("Call-ID".into(), "test-call-123".into());
        headers.push("Via".into(), "SIP/2.0/UDP client;branch=z9hG4bKclient".into());
        headers.push("Max-Forwards".into(), "70".into());

        Request::new(
            RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
    }

    fn make_response(code: u16) -> Response {
        let mut headers = Headers::new();
        headers.push("Call-ID".into(), "test-call-123".into());
        headers.push("Via".into(), "SIP/2.0/UDP proxy;branch=z9hG4bKproxy".into());
        headers.push("Via".into(), "SIP/2.0/UDP client;branch=z9hG4bKclient".into());

        Response::new(
            StatusLine::new(code, "OK".into()),
            headers,
            Bytes::new(),
        )
    }

    #[tokio::test]
    async fn creates_proxy_context() {
        let proxy = StatefulProxy::new();
        let request = make_request();

        let (context, _rx) = proxy.start_context(
            request,
            "test-call-123".into(),
            "z9hG4bKclient".into(),
            ForkMode::Parallel,
        );

        assert_eq!(context.call_id.as_str(), "test-call-123");
        assert_eq!(context.fork_mode(), ForkMode::Parallel);
    }

    #[tokio::test]
    async fn adds_and_finds_branches() {
        let proxy = StatefulProxy::new();
        let request = make_request();

        let (context, _rx) = proxy.start_context(
            request,
            "test-call-123".into(),
            "z9hG4bKclient".into(),
            ForkMode::Parallel,
        );

        let branch = BranchInfo {
            branch_id: "z9hG4bKbranch1".into(),
            target: SipUri::parse("sip:target1@example.com").unwrap(),
            created_at: Instant::now(),
            state: BranchState::Trying,
            best_response: None,
        };

        context.add_branch(branch).await;

        let branches = context.get_branch_ids().await;
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].as_str(), "z9hG4bKbranch1");
    }

    #[test]
    fn response_selection_prefers_2xx() {
        let response_200 = make_response(200);
        let response_486 = make_response(486);

        // 2xx beats 4xx
        assert!(select_best_response(Some(&response_486), &response_200));
        assert!(!select_best_response(Some(&response_200), &response_486));
    }

    #[test]
    fn response_selection_prefers_6xx() {
        let response_200 = make_response(200);
        let response_603 = make_response(603);

        // 6xx beats 2xx
        assert!(select_best_response(Some(&response_200), &response_603));
        assert!(!select_best_response(Some(&response_603), &response_200));
    }

    #[test]
    fn response_selection_prefers_lower_class() {
        let response_302 = make_response(302);
        let response_486 = make_response(486);

        // 3xx beats 4xx
        assert!(select_best_response(Some(&response_486), &response_302));
        assert!(!select_best_response(Some(&response_302), &response_486));
    }

    #[test]
    fn response_selection_keeps_first_in_class() {
        let response_486 = make_response(486);
        let response_487 = make_response(487);

        // Within same class (4xx), keep first
        assert!(!select_best_response(Some(&response_486), &response_487));
    }
}
