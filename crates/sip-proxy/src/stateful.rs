// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

use crate::cancel_ack::{AckForwarder, CancelForwarder};
use crate::ProxyHelpers;
use anyhow::Result;
use dashmap::DashMap;
use sip_core::{Request, Response, SipUri};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

// Security constants for DoS prevention
const MAX_BRANCH_ID_LENGTH: usize = 128;
const MAX_BRANCHES_PER_CONTEXT: usize = 50;
const MAX_PROXY_CONTEXTS: usize = 10_000;
pub(crate) const MAX_TARGETS_PER_REQUEST: usize = 100;

/// Proxy validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// Branch ID too long (DoS prevention)
    BranchIdTooLong { max: usize, actual: usize },
    /// Branch ID contains control characters (CRLF injection)
    BranchIdContainsControlChars,
    /// Too many branches (DoS prevention)
    TooManyBranches { max: usize },
    /// Too many proxy contexts (DoS prevention)
    TooManyContexts { max: usize },
    /// Too many targets (DoS prevention)
    TooManyTargets { max: usize, actual: usize },
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::BranchIdTooLong { max, actual } => {
                write!(f, "branch ID length {} exceeds max {}", actual, max)
            }
            ProxyError::BranchIdContainsControlChars => {
                write!(f, "branch ID contains control characters (CRLF injection)")
            }
            ProxyError::TooManyBranches { max } => {
                write!(f, "too many branches (max {})", max)
            }
            ProxyError::TooManyContexts { max } => {
                write!(f, "too many proxy contexts (max {})", max)
            }
            ProxyError::TooManyTargets { max, actual } => {
                write!(f, "too many targets {} (max {})", actual, max)
            }
        }
    }
}

impl std::error::Error for ProxyError {}

/// Validates a branch ID for length and control characters
fn validate_branch_id(branch_id: &str) -> Result<(), ProxyError> {
    if branch_id.len() > MAX_BRANCH_ID_LENGTH {
        return Err(ProxyError::BranchIdTooLong {
            max: MAX_BRANCH_ID_LENGTH,
            actual: branch_id.len(),
        });
    }
    if branch_id.chars().any(|c| c.is_control()) {
        return Err(ProxyError::BranchIdContainsControlChars);
    }
    Ok(())
}

/// Target for forwarding a request
#[derive(Debug, Clone)]
pub struct ProxyTarget {
    /// Target SIP URI
    pub(crate) uri: SipUri,

    /// Priority (lower is higher priority, for sequential forking)
    pub(crate) priority: u32,

    /// Q-value from registration (1.0 = highest, 0.0 = lowest)
    pub(crate) q_value: f32,
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

    /// Returns the target URI.
    pub fn uri(&self) -> &SipUri {
        &self.uri
    }

    /// Returns the priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Returns the q-value.
    pub fn q_value(&self) -> f32 {
        self.q_value
    }
}

/// Branch information for a forwarded request
#[derive(Debug, Clone)]
pub struct BranchInfo {
    /// Branch ID generated for this forward
    pub(crate) branch_id: SmolStr,

    /// Target URI this branch was sent to
    pub(crate) target: SipUri,

    /// When this branch was created
    pub(crate) created_at: Instant,

    /// Current state of this branch
    pub(crate) state: BranchState,

    /// Best response received so far (for response selection)
    pub(crate) best_response: Option<Response>,
}

impl BranchInfo {
    /// Creates a new BranchInfo with validation.
    pub fn new(
        branch_id: impl Into<SmolStr>,
        target: SipUri,
        created_at: Instant,
        state: BranchState,
    ) -> Result<Self, ProxyError> {
        let branch_id = branch_id.into();
        validate_branch_id(&branch_id)?;
        Ok(Self {
            branch_id,
            target,
            created_at,
            state,
            best_response: None,
        })
    }

    /// Returns the branch ID.
    pub fn branch_id(&self) -> &str {
        &self.branch_id
    }

    /// Returns the target URI.
    pub fn target(&self) -> &SipUri {
        &self.target
    }

    /// Returns when this branch was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the current state.
    pub fn state(&self) -> BranchState {
        self.state
    }

    /// Returns the best response received.
    pub fn best_response(&self) -> Option<&Response> {
        self.best_response.as_ref()
    }
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
    pub(crate) original_request: Request,

    /// Call-ID for correlation
    pub(crate) call_id: SmolStr,

    /// Client transaction branch (from client's Via header)
    pub(crate) client_branch: SmolStr,

    /// Proxy hostname used for forwarding on this context
    pub(crate) proxy_host: SmolStr,

    /// Transport used for forwarding on this context
    pub(crate) transport: SmolStr,

    /// Branches created for forwarding (branch_id → info)
    branches: RwLock<HashMap<SmolStr, BranchInfo>>,

    /// Forking mode
    fork_mode: ForkMode,

    /// Best final response received (for response selection)
    best_final: RwLock<Option<Response>>,

    /// Channel to send the selected response upstream
    #[allow(dead_code)]
    response_tx: mpsc::UnboundedSender<Response>,

    /// Number of outstanding branches (not completed)
    outstanding_count: RwLock<usize>,

    /// When this context was created
    pub(crate) created_at: Instant,
}

impl ProxyContext {
    /// Create a new proxy context
    pub fn new(
        original_request: Request,
        call_id: SmolStr,
        client_branch: SmolStr,
        proxy_host: SmolStr,
        transport: SmolStr,
        fork_mode: ForkMode,
        response_tx: mpsc::UnboundedSender<Response>,
    ) -> Self {
        Self {
            original_request,
            call_id,
            client_branch,
            proxy_host,
            transport,
            branches: RwLock::new(HashMap::new()),
            fork_mode,
            best_final: RwLock::new(None),
            response_tx,
            outstanding_count: RwLock::new(0),
            created_at: Instant::now(),
        }
    }

    /// Add a branch that was created for forwarding
    pub async fn add_branch(&self, branch_info: BranchInfo) -> Result<(), ProxyError> {
        let mut branches = self.branches.write().await;

        if branches.len() >= MAX_BRANCHES_PER_CONTEXT {
            return Err(ProxyError::TooManyBranches {
                max: MAX_BRANCHES_PER_CONTEXT,
            });
        }

        let mut count = self.outstanding_count.write().await;
        branches.insert(branch_info.branch_id.clone(), branch_info);
        *count += 1;
        Ok(())
    }

    /// Process a response received on a branch
    ///
    /// Returns the response that should be forwarded upstream (if any)
    pub async fn process_response(&self, branch_id: &str, response: Response) -> Option<Response> {
        let mut branches = self.branches.write().await;
        let branch = branches.get_mut(branch_id)?;

        let is_final = response.code() >= 200;

        // Update branch state
        if response.code() >= 100 && response.code() < 200 {
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
            debug!(
                "Forwarding provisional {} response from branch {}",
                response.code(),
                branch_id
            );
            return Some(response);
        }

        // Handle final responses with response selection
        let mut best_final = self.best_final.write().await;
        let should_forward = select_best_response(best_final.as_ref(), &response);

        if should_forward {
            info!(
                "Selected {} as best response (branch {})",
                response.code(),
                branch_id
            );
            *best_final = Some(response.clone());

            // If we got a 2xx and have other branches, send CANCEL to them
            if response.code() >= 200 && response.code() < 300 {
                self.cancel_other_branches(branch_id).await;
            }

            return Some(response);
        }

        // Check if all branches have completed
        let outstanding = *self.outstanding_count.read().await;
        if outstanding == 0 {
            // All branches done - return the best we have
            if let Some(best) = best_final.clone() {
                info!(
                    "All branches complete - forwarding best response {}",
                    best.code()
                );
                return Some(best);
            }
        }

        None
    }

    /// Cancel all branches except the specified one (winner)
    ///
    /// Returns branch IDs that should receive CANCEL.
    async fn cancel_other_branches(&self, winner_branch: &str) -> Vec<SmolStr> {
        let mut branches = self.branches.write().await;
        let mut to_cancel = Vec::new();

        for (branch_id, branch) in branches.iter_mut() {
            if branch_id.as_str() != winner_branch
                && !matches!(
                    branch.state,
                    BranchState::Completed | BranchState::Cancelled
                )
            {
                info!(
                    "Marking branch {} for CANCEL (winner: {})",
                    branch_id, winner_branch
                );
                branch.state = BranchState::Cancelled;
                to_cancel.push(branch_id.clone());
            }
        }

        to_cancel
    }

    /// Build CANCEL requests for all branches marked as Cancelled/Trying/Proceeding.
    ///
    /// The provided CANCEL template should already match the original INVITE's
    /// Call-ID/From/To/CSeq; this will rewrite the Via branch per target branch.
    pub async fn build_cancel_requests(&self, cancel_template: &Request) -> Vec<Request> {
        let branches = self.branches.read().await;
        let mut cancels = Vec::new();

        for (branch_id, branch) in branches.iter() {
            if matches!(
                branch.state,
                BranchState::Cancelled | BranchState::Trying | BranchState::Proceeding
            ) {
                match CancelForwarder::prepare_cancel(cancel_template, branch_id.as_str()) {
                    Ok(mut cancel) => {
                        // Ensure Request-URI targets the original branch destination
                        ProxyHelpers::set_request_uri(&mut cancel, branch.target.clone());
                        cancels.push(cancel);
                    }
                    Err(e) => warn!("Failed to prepare CANCEL for branch {}: {}", branch_id, e),
                }
            }
        }

        cancels
    }

    /// Determine if the selected best response was 2xx (used for ACK classification).
    pub async fn best_response_is_2xx(&self) -> Option<bool> {
        let best = self.best_final.read().await;
        best.as_ref()
            .map(|resp| resp.code() >= 200 && resp.code() < 300)
    }

    /// Prepare an ACK for forwarding using transaction context to decide ACK type.
    pub async fn prepare_ack_forward(&self, ack: &Request) -> Result<Request> {
        let is_2xx = self.best_response_is_2xx().await;
        let ack_type = AckForwarder::ack_type(ack, is_2xx);
        AckForwarder::prepare_ack(ack, ack_type)
    }

    /// Get all branch IDs
    pub async fn get_branch_ids(&self) -> Vec<SmolStr> {
        self.branches.read().await.keys().cloned().collect()
    }

    /// Get forking mode
    pub fn fork_mode(&self) -> ForkMode {
        self.fork_mode
    }

    /// Returns the original request.
    pub fn original_request(&self) -> &Request {
        &self.original_request
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the client branch.
    pub fn client_branch(&self) -> &str {
        &self.client_branch
    }

    /// Returns the proxy hostname.
    pub fn proxy_host(&self) -> &str {
        &self.proxy_host
    }

    /// Returns the transport.
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// Returns when this context was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
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

    let current_code = current.code();
    let new_code = new_response.code();

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
        proxy_host: SmolStr,
        transport: SmolStr,
        fork_mode: ForkMode,
    ) -> Result<(Arc<ProxyContext>, mpsc::UnboundedReceiver<Response>), ProxyError> {
        if self.contexts.len() >= MAX_PROXY_CONTEXTS {
            return Err(ProxyError::TooManyContexts {
                max: MAX_PROXY_CONTEXTS,
            });
        }

        let (response_tx, response_rx) = mpsc::unbounded_channel();

        let context = Arc::new(ProxyContext::new(
            request,
            call_id,
            client_branch.clone(),
            proxy_host,
            transport,
            fork_mode,
            response_tx,
        ));

        self.contexts.insert(client_branch, context.clone());

        Ok((context, response_rx))
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
        self.contexts
            .retain(|_, ctx| now.duration_since(ctx.created_at) < self.cleanup_interval);
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
        ProxyHelpers::remove_top_via(forwarded.headers_mut());

        forwarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, Method, RequestLine, StatusLine};

    fn make_request() -> Request {
        let mut headers = Headers::new();
        headers.push("Call-ID", "test-call-123").unwrap();
        headers
            .push("Via", "SIP/2.0/UDP client;branch=z9hG4bKclient")
            .unwrap();
        headers.push("Max-Forwards", "70").unwrap();

        Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request")
    }

    fn make_response(code: u16) -> Response {
        let mut headers = Headers::new();
        headers.push("Call-ID", "test-call-123").unwrap();
        headers
            .push("Via", "SIP/2.0/UDP proxy;branch=z9hG4bKproxy")
            .unwrap();
        headers
            .push("Via", "SIP/2.0/UDP client;branch=z9hG4bKclient")
            .unwrap();

        Response::new(
            StatusLine::new(code, "OK").expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response")
    }

    #[tokio::test]
    async fn creates_proxy_context() {
        let proxy = StatefulProxy::new();
        let request = make_request();

        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-123".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .expect("should create context");

        assert_eq!(context.call_id(), "test-call-123");
        assert_eq!(context.fork_mode(), ForkMode::Parallel);
    }

    #[tokio::test]
    async fn adds_and_finds_branches() {
        let proxy = StatefulProxy::new();
        let request = make_request();

        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-123".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .expect("should create context");

        let branch = BranchInfo::new(
            "z9hG4bKbranch1",
            SipUri::parse("sip:target1@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .expect("should create branch");

        context.add_branch(branch).await.expect("should add branch");

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

    #[tokio::test]
    async fn prepares_ack_with_best_response_context() {
        let proxy = StatefulProxy::new();
        let invite = make_request();
        let (context, _) = proxy
            .start_context(
                invite,
                "test-call-123".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::None,
            )
            .expect("should create context");

        // Simulate a 200 OK winning response
        let resp = make_response(200);
        context.process_response("z9hG4bKclient".into(), resp).await;

        // Incoming ACK with Route header (dialog path)
        let ack = {
            let mut headers = Headers::new();
            headers.push("Call-ID", "test-call-123").unwrap();
            headers.push("CSeq", "1 ACK").unwrap();
            headers.push("Route", "<sip:proxy.example.com>").unwrap();
            Request::new(
                RequestLine::new(Method::Ack, SipUri::parse("sip:bob@example.com").unwrap()),
                headers,
                Bytes::new(),
            )
            .expect("valid request")
        };

        let forwarded = context.prepare_ack_forward(&ack).await.unwrap();

        // Route header consumed and Request-URI updated
        assert!(forwarded.headers().iter().all(|h| h.name() != "Route"));
        assert_eq!(
            forwarded.uri().as_sip().unwrap().as_str(),
            "sip:proxy.example.com"
        );
    }

    #[tokio::test]
    async fn build_cancel_requests_sets_branch_and_target() {
        let proxy = StatefulProxy::new();
        let invite = {
            let mut headers = Headers::new();
            headers.push("Call-ID", "call-123").unwrap();
            headers.push("CSeq", "1 INVITE").unwrap();
            headers
                .push("Via", "SIP/2.0/UDP client;branch=z9hG4bKclient")
                .unwrap();
            headers
                .push("From", "<sip:alice@example.com>;tag=a")
                .unwrap();
            headers.push("To", "<sip:bob@example.com>").unwrap();
            headers.push("Max-Forwards", "70").unwrap();
            Request::new(
                RequestLine::new(
                    Method::Invite,
                    SipUri::parse("sip:bob@example.com").unwrap(),
                ),
                headers,
                Bytes::new(),
            )
            .expect("valid request")
        };

        let (context, _) = proxy
            .start_context(
                invite.clone(),
                "call-123".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .expect("should create context");

        let target = SipUri::parse("sip:target@example.com").unwrap();
        let branch_info = BranchInfo::new(
            "z9hG4bKbranch1",
            target.clone(),
            Instant::now(),
            BranchState::Proceeding,
        )
        .expect("should create branch");
        context
            .add_branch(branch_info)
            .await
            .expect("should add branch");

        // Template CANCEL (matches INVITE headers)
        let cancel_template = {
            let mut headers = Headers::new();
            headers.push("Call-ID", "call-123").unwrap();
            headers.push("CSeq", "1 CANCEL").unwrap();
            headers
                .push("From", "<sip:alice@example.com>;tag=a")
                .unwrap();
            headers.push("To", "<sip:bob@example.com>").unwrap();
            headers
                .push("Via", "SIP/2.0/UDP proxy;branch=z9hG4bKtemplate")
                .unwrap();
            Request::new(
                RequestLine::new(
                    Method::Cancel,
                    SipUri::parse("sip:bob@example.com").unwrap(),
                ),
                headers,
                Bytes::new(),
            )
            .expect("valid request")
        };

        let cancels = context.build_cancel_requests(&cancel_template).await;
        assert_eq!(cancels.len(), 1);
        let cancel = &cancels[0];

        // Branch rewritten
        let via = cancel.headers().get("Via").unwrap();
        assert!(via.contains("z9hG4bKbranch1"));

        // Request-URI targets branch destination
        assert_eq!(cancel.uri().as_sip().unwrap().as_str(), target.as_str());
    }

    // ===========================================
    // Security tests: CRLF injection prevention
    // ===========================================

    #[test]
    fn rejects_branch_id_with_crlf() {
        let result = BranchInfo::new(
            "z9hG4bK\r\nbranch",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(matches!(result, Err(ProxyError::BranchIdContainsControlChars)));
    }

    #[test]
    fn rejects_branch_id_with_newline() {
        let result = BranchInfo::new(
            "z9hG4bK\nbranch",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(matches!(result, Err(ProxyError::BranchIdContainsControlChars)));
    }

    #[test]
    fn rejects_branch_id_with_tab() {
        let result = BranchInfo::new(
            "z9hG4bK\tbranch",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(matches!(result, Err(ProxyError::BranchIdContainsControlChars)));
    }

    // ===========================================
    // Security tests: Bounds checking
    // ===========================================

    #[test]
    fn rejects_oversized_branch_id() {
        let long_branch = "z".repeat(MAX_BRANCH_ID_LENGTH + 1);
        let result = BranchInfo::new(
            long_branch,
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(matches!(
            result,
            Err(ProxyError::BranchIdTooLong { max: 128, .. })
        ));
    }

    #[tokio::test]
    async fn rejects_too_many_branches_per_context() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .expect("should create context");

        // Add MAX_BRANCHES_PER_CONTEXT branches
        for i in 0..MAX_BRANCHES_PER_CONTEXT {
            let branch_info = BranchInfo::new(
                format!("z9hG4bKbranch{}", i),
                SipUri::parse("sip:target@example.com").unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .expect("should create branch");
            context
                .add_branch(branch_info)
                .await
                .expect("should add branch");
        }

        // Try to add one more - should fail
        let overflow_branch = BranchInfo::new(
            "z9hG4bKoverflow",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .expect("should create branch");

        let result = context.add_branch(overflow_branch).await;
        assert!(matches!(
            result,
            Err(ProxyError::TooManyBranches { max: 50 })
        ));
    }

    #[test]
    fn rejects_too_many_proxy_contexts() {
        let proxy = StatefulProxy::new();

        // Fill up to MAX_PROXY_CONTEXTS
        for i in 0..MAX_PROXY_CONTEXTS {
            let request = {
                let mut headers = Headers::new();
                headers.push("Call-ID", format!("call-{}", i)).unwrap();
                headers
                    .push("Via", format!("SIP/2.0/UDP client;branch=z9hG4bKclient{}", i))
                    .unwrap();
                headers.push("Max-Forwards", "70").unwrap();

                Request::new(
                    RequestLine::new(
                        Method::Invite,
                        SipUri::parse("sip:bob@example.com").unwrap(),
                    ),
                    headers,
                    Bytes::new(),
                )
                .expect("valid request")
            };

            proxy
                .start_context(
                    request,
                    format!("call-{}", i).into(),
                    format!("z9hG4bKclient{}", i).into(),
                    "proxy.example.com".into(),
                    "UDP".into(),
                    ForkMode::None,
                )
                .expect("should create context");
        }

        // Try to add one more - should fail
        let overflow_request = make_request();
        let result = proxy.start_context(
            overflow_request,
            "overflow-call".into(),
            "z9hG4bKoverflow".into(),
            "proxy.example.com".into(),
            "UDP".into(),
            ForkMode::None,
        );

        assert!(matches!(
            result,
            Err(ProxyError::TooManyContexts { max: 10_000 })
        ));
    }

    #[test]
    fn accepts_max_length_branch_id() {
        let max_branch = "z".repeat(MAX_BRANCH_ID_LENGTH);
        let result = BranchInfo::new(
            max_branch,
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_valid_branch_id() {
        let result = BranchInfo::new(
            "z9hG4bKbranch-valid123",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(result.is_ok());
    }
}
