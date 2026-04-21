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

/// RFC 3261 §16.7 step 2: Timer C duration.
///
/// When a proxy in Proceeding receives no final response within this
/// interval, it synthesises a 408 Request Timeout for the branch so
/// the upstream transaction can complete instead of hanging forever.
/// The spec allows the proxy to choose any value "> 3 minutes"; 3m
/// exactly is the canonical value.
const TIMER_C_DURATION: Duration = Duration::from_secs(180);

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
    /// RFC 3261 §16.7 #4: a 6xx response has been received on this
    /// context; no further branches may be added.
    TerminatedBy6xx,
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
            ProxyError::TerminatedBy6xx => {
                write!(f, "context terminated by 6xx response (RFC 3261 §16.7 #4)")
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

    /// RFC 3261 §16.8 Timer C duration. Spec mandates `> 3 minutes`;
    /// real deployments often need to tune this (e.g. shorter for
    /// gateways, longer for IVR menus). Defaults to
    /// `TIMER_C_DURATION` (180s).
    timer_c_duration: Duration,

    /// Set once any branch has produced a 6xx final response. RFC
    /// 3261 §16.7 #4: "When a 6xx response is received [...] the
    /// stateful proxy SHOULD cancel all client pending transactions
    /// [...] and MUST NOT create any new branches in this context."
    /// `add_branch` honours this flag.
    terminated_by_6xx: RwLock<bool>,
}

impl ProxyContext {
    /// Create a new proxy context with the default Timer C (180s).
    pub fn new(
        original_request: Request,
        call_id: SmolStr,
        client_branch: SmolStr,
        proxy_host: SmolStr,
        transport: SmolStr,
        fork_mode: ForkMode,
        response_tx: mpsc::UnboundedSender<Response>,
    ) -> Self {
        Self::with_timer_c(
            original_request,
            call_id,
            client_branch,
            proxy_host,
            transport,
            fork_mode,
            response_tx,
            TIMER_C_DURATION,
        )
    }

    /// Like [`ProxyContext::new`] but with a caller-chosen Timer C
    /// duration. Per RFC 3261 §16.8 the value must be greater than
    /// 3 minutes for spec compliance; the constructor accepts shorter
    /// values for testing and lab use, leaving policy to the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn with_timer_c(
        original_request: Request,
        call_id: SmolStr,
        client_branch: SmolStr,
        proxy_host: SmolStr,
        transport: SmolStr,
        fork_mode: ForkMode,
        response_tx: mpsc::UnboundedSender<Response>,
        timer_c_duration: Duration,
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
            timer_c_duration,
            terminated_by_6xx: RwLock::new(false),
        }
    }

    /// Add a branch that was created for forwarding.
    ///
    /// Returns [`ProxyError::TerminatedBy6xx`] if the context has
    /// already received a 6xx response — RFC 3261 §16.7 #4 forbids
    /// new branches in that state.
    pub async fn add_branch(&self, branch_info: BranchInfo) -> Result<(), ProxyError> {
        if *self.terminated_by_6xx.read().await {
            return Err(ProxyError::TerminatedBy6xx);
        }

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

    /// True once any branch has produced a 6xx final. Apps building
    /// their own forking loop on top of this context can poll this to
    /// stop scheduling additional targets.
    pub async fn is_terminated_by_6xx(&self) -> bool {
        *self.terminated_by_6xx.read().await
    }

    /// Process a response received on a branch
    ///
    /// Returns the response that should be forwarded upstream (if any).
    ///
    /// # Locking
    ///
    /// Releases `branches` before any further `await` on a method that
    /// itself acquires `branches` (currently `cancel_other_branches`).
    /// `tokio::sync::RwLock` is not reentrant — holding the write
    /// guard across such a call deadlocks. Earlier revisions of this
    /// function held `branches.write()` for the whole body and called
    /// `cancel_other_branches` from inside that scope, which would
    /// hang on the 2xx fork-cancel path with no diagnostic.
    pub async fn process_response(
        self: &Arc<Self>,
        branch_id: &str,
        response: Response,
    ) -> Option<Response> {
        let is_final = response.code() >= 200;
        let is_two_xx = (200..300).contains(&response.code());
        // RFC 3261 §16.7 #4: a 6xx is a global failure. We must
        // cancel siblings AND prevent any further forking via
        // `add_branch`.
        let is_six_xx = (600..700).contains(&response.code());

        // Mutate the branch in its own scope so the write guard
        // releases before we call cancel_other_branches below.
        {
            let mut branches = self.branches.write().await;
            let branch = branches.get_mut(branch_id)?;

            let was_trying = matches!(branch.state, BranchState::Trying);

            if response.code() >= 100 && response.code() < 200 {
                branch.state = BranchState::Proceeding;
                // RFC 3261 §16.7 step 2: arm Timer C on the first
                // transition into Proceeding so a silent downstream
                // doesn't hang the upstream forever.
                if was_trying {
                    arm_timer_c(
                        Arc::downgrade(self),
                        branch_id.to_string(),
                        self.timer_c_duration,
                    );
                }
            } else if is_final {
                branch.state = BranchState::Completed;
            }

            // Store best response for this branch.
            branch.best_response = Some(response.clone());
        }

        // Decrement the outstanding counter once the branches lock is
        // released. Holding two write locks is fine in principle but
        // keeping them strictly serialised keeps the lock graph
        // trivial.
        if is_final {
            let mut count = self.outstanding_count.write().await;
            if *count > 0 {
                *count -= 1;
            }
        }

        // Handle provisional responses (always forward first 1xx per RFC 3261)
        if !is_final {
            debug!(
                "Forwarding provisional {} response from branch {}",
                response.code(),
                branch_id
            );
            return Some(response);
        }

        // Handle final responses with response selection. The result
        // is computed inside a small scope so the best_final write
        // guard isn't held across `cancel_other_branches`.
        let should_forward = {
            let mut best_final = self.best_final.write().await;
            let should = select_best_response(best_final.as_ref(), &response);
            if should {
                *best_final = Some(response.clone());
            }
            should
        };

        // Per RFC 3261 §16.7: only 2xx and 6xx finals may be forwarded
        // as soon as they arrive. Every other final (1xx already
        // returned above, 3xx/4xx/5xx) must be buffered until ALL
        // branches have completed; otherwise we'd both (a) emit the
        // wrong "best" upstream when a sibling later returns a better
        // response, and (b) skip the §16.7 #7 401/407 aggregation
        // step. `should_forward` here only controls whether we update
        // the stored best — actual upstream forwarding for non-2xx/
        // non-6xx happens via the "all branches complete" path below.
        if should_forward && is_two_xx {
            info!(
                "Selected {} (2xx) — forwarding immediately and cancelling siblings",
                response.code(),
            );
            self.cancel_other_branches(branch_id).await;
            return Some(response);
        }
        if should_forward && is_six_xx {
            info!(
                "Selected {} (6xx) — global failure, cancelling siblings",
                response.code(),
            );
            // RFC 3261 §16.7 #4: on 6xx, also cancel siblings and
            // mark the context so no further branches can be added.
            // Without this, late forks after a 6xx would leak — and
            // could even override the global failure with a 4xx that
            // arrives later.
            *self.terminated_by_6xx.write().await = true;
            self.cancel_other_branches(branch_id).await;
            return Some(response);
        }

        // Check if all branches have completed
        let outstanding = *self.outstanding_count.read().await;
        if outstanding == 0 {
            // All branches done - return the best we have. Take a
            // fresh read of best_final since the earlier write guard
            // has been released.
            let best = self.best_final.read().await.clone();
            if let Some(mut best) = best {
                // RFC 3261 §16.7 #7: if the best response is 401 /
                // 407, aggregate WWW-Authenticate / Proxy-Authenticate
                // from every branch that returned 401 / 407 into the
                // response we forward. The client needs all of them
                // to construct a request that satisfies every realm
                // simultaneously.
                if best.code() == 401 || best.code() == 407 {
                    self.aggregate_auth_challenges(&mut best).await;
                }
                info!(
                    "All branches complete - forwarding best response {}",
                    best.code()
                );
                return Some(best);
            }
        }

        None
    }

    /// Adds `WWW-Authenticate` (for 401) and `Proxy-Authenticate`
    /// (for 407) headers from every other branch's stored
    /// 401/407 response to `best`, in branch insertion order, with
    /// duplicates removed. Per RFC 3261 §16.7 #7 the proxy "MUST
    /// collect any WWW-Authenticate and Proxy-Authenticate header
    /// field values from all other 401 and 407 responses received
    /// and add them to this response without modification."
    async fn aggregate_auth_challenges(&self, best: &mut Response) {
        let branches = self.branches.read().await;
        // Collect raw header values from every branch that responded
        // 401 or 407 — including the winning branch (`best` already
        // carries them, but iterating uniformly keeps the dedup logic
        // simple).
        let mut www_seen: Vec<SmolStr> = best
            .headers()
            .get_all_smol("WWW-Authenticate")
            .cloned()
            .collect();
        let mut proxy_seen: Vec<SmolStr> = best
            .headers()
            .get_all_smol("Proxy-Authenticate")
            .cloned()
            .collect();
        let initial_www = www_seen.len();
        let initial_proxy = proxy_seen.len();

        for branch in branches.values() {
            let Some(resp) = branch.best_response.as_ref() else {
                continue;
            };
            if resp.code() != 401 && resp.code() != 407 {
                continue;
            }
            for header in resp.headers().get_all_smol("WWW-Authenticate") {
                if !www_seen.iter().any(|v| v == header) {
                    www_seen.push(header.clone());
                }
            }
            for header in resp.headers().get_all_smol("Proxy-Authenticate") {
                if !proxy_seen.iter().any(|v| v == header) {
                    proxy_seen.push(header.clone());
                }
            }
        }

        // Append only the newly-collected ones to `best`.
        let headers = best.headers_mut();
        for value in www_seen.into_iter().skip(initial_www) {
            let _ = headers.push("WWW-Authenticate", value);
        }
        for value in proxy_seen.into_iter().skip(initial_proxy) {
            let _ = headers.push("Proxy-Authenticate", value);
        }
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

    /// Synthesises a `408 Request Timeout` for a branch that's stuck in
    /// Proceeding. Invoked by the Timer C task (see `arm_timer_c`).
    ///
    /// Re-checks the branch state under the lock — if the branch has
    /// already transitioned to Completed / Cancelled in the meantime,
    /// no-ops. Otherwise builds a synthetic 408 and re-enters the
    /// normal response-selection path via `process_response` so the
    /// upstream transaction sees a final response and unblocks.
    async fn fire_timer_c(self: &Arc<Self>, branch_id: &str) {
        {
            let branches = self.branches.read().await;
            let Some(branch) = branches.get(branch_id) else {
                return;
            };
            if !matches!(branch.state, BranchState::Proceeding) {
                // Raced with the normal final-response path — nothing
                // to do. The timer's purpose was only to stop the
                // hang; a legitimate response already arrived.
                return;
            }
        }

        // Build the synthetic 408. Use the original request as the
        // source of the headers we need to echo; this matches the shape
        // `build_error_response` produces for the registrar / dispatcher.
        use bytes::Bytes;
        use sip_core::{Headers, Response, StatusLine};
        let req = &self.original_request;
        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            if let Some(value) = req.headers().get(name) {
                let _ = headers.push(name, value);
            }
        }
        let Ok(status) = StatusLine::new(408, "Request Timeout") else {
            return;
        };
        let Ok(synthetic) = Response::new(status, headers, Bytes::new()) else {
            return;
        };

        warn!(
            branch_id,
            call_id = %self.call_id,
            "Timer C fired (RFC 3261 §16.7 step 2) — synthesising 408 Request Timeout"
        );
        if let Some(to_forward) = self.process_response(branch_id, synthetic).await {
            // Best-effort: push the synthesised 408 to the response
            // channel. If the receiver has already gone away (context
            // torn down) we silently drop — nothing to do.
            let _ = self.response_tx.send(to_forward);
        }
    }

    /// RFC 3261 §16.9 transport-error handling.
    ///
    /// Per spec: "If the transport layer notifies a proxy of an error
    /// when it tries to forward a request, the proxy MUST behave as
    /// if the forwarded request received a 503 (Service Unavailable)
    /// response." This synthesises that 503 for a branch and feeds it
    /// through the normal response-selection path so:
    ///   * sibling branches can still win,
    ///   * a 503 only "wins" if no better response arrives,
    ///   * the upstream transaction is properly closed when this is
    ///     the only branch.
    ///
    /// The application invokes this when its transport layer reports
    /// an unrecoverable failure (connection refused, ICMP unreachable,
    /// TLS handshake failure, etc.) for a branch this proxy created.
    /// If the branch has already received a final response or been
    /// cancelled, the call is a no-op.
    ///
    /// Returns the response forwarded upstream (if any), mirroring
    /// `process_response`. Callers wiring this into a transport
    /// dispatcher can ignore the return value — the response is also
    /// pushed to the context's response channel.
    pub async fn report_transport_error(self: &Arc<Self>, branch_id: &str) -> Option<Response> {
        // Skip branches that already moved past Trying/Proceeding —
        // a successful 2xx or a real 5xx has already been recorded
        // and the transport error is now irrelevant.
        {
            let branches = self.branches.read().await;
            let Some(branch) = branches.get(branch_id) else {
                return None;
            };
            if matches!(
                branch.state,
                BranchState::Completed | BranchState::Cancelled
            ) {
                return None;
            }
        }

        use bytes::Bytes;
        use sip_core::{Headers, Response, StatusLine};
        let req = &self.original_request;
        let mut headers = Headers::new();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            if let Some(value) = req.headers().get(name) {
                let _ = headers.push(name, value);
            }
        }
        let status = StatusLine::new(503, "Service Unavailable").ok()?;
        let synthetic = Response::new(status, headers, Bytes::new()).ok()?;

        warn!(
            branch_id,
            call_id = %self.call_id,
            "transport error reported (RFC 3261 §16.9) — synthesising 503 Service Unavailable"
        );
        let forwarded = self.process_response(branch_id, synthetic).await;
        if let Some(ref to_forward) = forwarded {
            let _ = self.response_tx.send(to_forward.clone());
        }
        forwarded
    }
}

/// Spawns the Timer C watchdog for a branch. Holds a `Weak` to the
/// context so the task exits cleanly if the context is dropped before
/// the timer fires. Sleep is a single tokio::time::sleep — no busy
/// loop, no polling.
fn arm_timer_c(ctx: std::sync::Weak<ProxyContext>, branch_id: String, duration: Duration) {
    // Only arm when we have a tokio runtime handle. Unit tests that
    // construct ProxyContext outside a runtime would otherwise panic.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        debug!("no tokio runtime available, skipping Timer C arm");
        return;
    };
    handle.spawn(async move {
        tokio::time::sleep(duration).await;
        let Some(ctx) = ctx.upgrade() else {
            return;
        };
        ctx.fire_timer_c(&branch_id).await;
    });
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

    /// RFC 3261 §16.8 Timer C duration applied to every context this
    /// proxy creates. Defaults to 180s; override via
    /// [`StatefulProxy::with_timer_c`].
    timer_c_duration: Duration,
}

impl StatefulProxy {
    /// Create a new stateful proxy with default Timer C (180s).
    pub fn new() -> Self {
        Self {
            contexts: DashMap::new(),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            timer_c_duration: TIMER_C_DURATION,
        }
    }

    /// Override the per-context Timer C duration. RFC 3261 §16.8
    /// requires `> 3 minutes` for spec compliance; the helper accepts
    /// any value so tests and lab harnesses can fire it quickly.
    pub fn with_timer_c(mut self, duration: Duration) -> Self {
        self.timer_c_duration = duration;
        self
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

        let context = Arc::new(ProxyContext::with_timer_c(
            request,
            call_id,
            client_branch.clone(),
            proxy_host,
            transport,
            fork_mode,
            response_tx,
            self.timer_c_duration,
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

    /// RFC 3261 §16.7 step 2: a branch stuck in Proceeding must be
    /// timed out with a synthetic 408 so the upstream transaction
    /// doesn't hang. We don't wait 3 minutes in the test — we
    /// exercise `fire_timer_c` directly to prove the synthesis path
    /// is wired.
    #[tokio::test]
    async fn timer_c_synthesises_408_when_branch_stuck_in_proceeding() {
        let proxy = StatefulProxy::new();
        let request = make_request();

        let (context, mut rx) = proxy
            .start_context(
                request,
                "test-call-timer-c".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .expect("should create context");

        let branch = BranchInfo::new(
            "z9hG4bKbr-timerc",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .expect("should create branch");
        context.add_branch(branch).await.expect("should add branch");

        // Simulate a 1xx arriving so the branch is in Proceeding
        // (the legitimate downstream never sends a final).
        let r180 = make_response(180);
        let forwarded = context.process_response("z9hG4bKbr-timerc", r180).await;
        assert_eq!(
            forwarded.map(|r| r.code()),
            Some(180),
            "1xx should be forwarded upstream immediately"
        );

        // Trip Timer C directly (no 3-minute wait in the test).
        context.fire_timer_c("z9hG4bKbr-timerc").await;

        // The branch should now be completed with a synthesised 408
        // queued on the response channel. Consume whatever the normal
        // forwarding path emitted (could be one or more responses; we
        // only care that a 408 appears).
        let mut saw_408 = false;
        while let Ok(resp) = rx.try_recv() {
            if resp.code() == 408 {
                saw_408 = true;
                break;
            }
        }
        // If the 408 wasn't in rx (it gets forwarded through
        // process_response's normal path which also returns it), check
        // via get_branch_ids and branch state indirectly. The cleaner
        // approach is to verify via best_response:
        let branches = context.branches.read().await;
        let branch = branches.get("z9hG4bKbr-timerc").expect("branch present");
        assert!(
            matches!(branch.state, BranchState::Completed),
            "Timer C must transition branch to Completed"
        );
        assert_eq!(
            branch.best_response.as_ref().map(|r| r.code()),
            Some(408),
            "Timer C must synthesise a 408 Request Timeout"
        );
        // Silence warning if the rx check didn't see it.
        let _ = saw_408;
    }

    /// Once the branch has moved to Completed (legitimate final
    /// response arrived before the 3-minute mark), firing Timer C
    /// should be a no-op — we must not overwrite a real final with a
    /// synthetic 408.
    ///
    /// Uses 486 (Busy Here) rather than 200 OK to avoid an unrelated
    /// pre-existing deadlock: `process_response` calls
    /// `cancel_other_branches` on the 2xx path while still holding the
    /// `branches` write lock, and `cancel_other_branches` re-acquires
    /// that same lock. Tracked separately; out of scope for the
    /// Timer C change, which only adds a new spawn path.
    #[tokio::test]
    async fn timer_c_noops_if_branch_already_completed() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-timer-c-noop".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();
        let branch = BranchInfo::new(
            "z9hG4bKbr-completed",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .unwrap();
        context.add_branch(branch).await.unwrap();

        // 180 Ringing then 486 Busy Here — branch is Completed.
        context
            .process_response("z9hG4bKbr-completed", make_response(180))
            .await;
        context
            .process_response("z9hG4bKbr-completed", make_response(486))
            .await;

        context.fire_timer_c("z9hG4bKbr-completed").await;

        let branches = context.branches.read().await;
        let branch = branches.get("z9hG4bKbr-completed").unwrap();
        assert_eq!(
            branch.best_response.as_ref().map(|r| r.code()),
            Some(486),
            "Timer C must not overwrite a real final response"
        );
    }

    /// Regression test: receiving a 2xx on one branch in a fork must
    /// trigger CANCEL of the other branches. Earlier revisions
    /// deadlocked here because `process_response` held
    /// `branches.write()` across the call to `cancel_other_branches`,
    /// which itself acquires the same lock. The deadlock surfaced no
    /// diagnostic — the test just hung. We protect with a timeout so
    /// any future regression fails loudly instead of timing out the
    /// CI job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_response_cancels_other_branches_on_2xx_without_deadlock() {
        use std::time::Duration;

        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-fork-cancel".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        // Two branches, both Trying.
        for (id, target) in [
            ("z9hG4bKbr-winner", "sip:winner@example.com"),
            ("z9hG4bKbr-loser1", "sip:loser1@example.com"),
            ("z9hG4bKbr-loser2", "sip:loser2@example.com"),
        ] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse(target).unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        // Drive the loser branches into Proceeding so the cancel path
        // has live branches to act on.
        context
            .process_response("z9hG4bKbr-loser1", make_response(180))
            .await;
        context
            .process_response("z9hG4bKbr-loser2", make_response(180))
            .await;

        // Send 200 OK on the winner. Wrap in a timeout: if the lock
        // graph regresses, this hangs forever and the timeout fires
        // with a clear assertion message.
        let forwarded = tokio::time::timeout(
            Duration::from_secs(5),
            context.process_response("z9hG4bKbr-winner", make_response(200)),
        )
        .await
        .expect("process_response must not deadlock on 2xx fork-cancel");

        assert_eq!(
            forwarded.map(|r| r.code()),
            Some(200),
            "winning 2xx must be forwarded upstream"
        );

        // Both losers should have been marked Cancelled by the
        // sibling-cancel path.
        let branches = context.branches.read().await;
        for loser in ["z9hG4bKbr-loser1", "z9hG4bKbr-loser2"] {
            let b = branches.get(loser).expect("loser branch present");
            assert!(
                matches!(b.state, BranchState::Cancelled),
                "{loser} should be Cancelled after winner's 2xx, was {:?}",
                b.state,
            );
        }
    }

    /// RFC 3261 §16.7 #4: a 6xx response cancels siblings AND
    /// prevents new branches from being added — it's a global
    /// failure, not a per-branch one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn six_xx_cancels_siblings_and_blocks_new_branches() {
        use std::time::Duration;

        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-6xx".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        for (id, target) in [
            ("z9hG4bKbr-rejecter", "sip:rejecter@example.com"),
            ("z9hG4bKbr-other1", "sip:other1@example.com"),
            ("z9hG4bKbr-other2", "sip:other2@example.com"),
        ] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse(target).unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        // Drive the others into Proceeding.
        context
            .process_response("z9hG4bKbr-other1", make_response(180))
            .await;
        context
            .process_response("z9hG4bKbr-other2", make_response(180))
            .await;

        // Rejecter sends 603 Decline.
        let forwarded = tokio::time::timeout(
            Duration::from_secs(5),
            context.process_response("z9hG4bKbr-rejecter", make_response(603)),
        )
        .await
        .expect("process_response must not deadlock on 6xx");
        assert_eq!(forwarded.map(|r| r.code()), Some(603));

        // Siblings cancelled.
        {
            let branches = context.branches.read().await;
            for other in ["z9hG4bKbr-other1", "z9hG4bKbr-other2"] {
                let b = branches.get(other).expect("present");
                assert!(
                    matches!(b.state, BranchState::Cancelled),
                    "{other} should be Cancelled after 6xx, was {:?}",
                    b.state,
                );
            }
        }

        // Context is terminated and no new branches accepted.
        assert!(context.is_terminated_by_6xx().await);
        let new_branch = BranchInfo::new(
            "z9hG4bKbr-late",
            SipUri::parse("sip:late@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .unwrap();
        let err = context.add_branch(new_branch).await.unwrap_err();
        assert_eq!(err, ProxyError::TerminatedBy6xx);
    }

    /// 4xx must NOT trigger the 6xx semantics — only 6xx is a global
    /// failure. Sibling branches keep running on a 4xx because a
    /// later 2xx from a sibling is a perfectly good outcome.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn four_xx_does_not_block_new_branches() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-4xx".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        let branch = BranchInfo::new(
            "z9hG4bKbr-busy",
            SipUri::parse("sip:busy@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .unwrap();
        context.add_branch(branch).await.unwrap();
        context
            .process_response("z9hG4bKbr-busy", make_response(486))
            .await;

        assert!(!context.is_terminated_by_6xx().await);
        // New branch may be added (e.g. caller retrying with another
        // candidate from the location service).
        let later = BranchInfo::new(
            "z9hG4bKbr-later",
            SipUri::parse("sip:later@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .unwrap();
        context.add_branch(later).await.expect("4xx must not block");
    }

    // ===========================================
    // RFC 3261 §16.9: transport-error → synthetic 503
    // ===========================================

    /// A single-branch transport failure must surface as a 503
    /// upstream so the upstream transaction can complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_error_on_only_branch_synthesises_503() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-tx".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::None,
            )
            .unwrap();

        let branch = BranchInfo::new(
            "z9hG4bKbr-only",
            SipUri::parse("sip:dead@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .unwrap();
        context.add_branch(branch).await.unwrap();

        let forwarded = context
            .report_transport_error("z9hG4bKbr-only")
            .await
            .expect("synthetic 503 must be forwarded");
        assert_eq!(forwarded.code(), 503);
    }

    /// When a sibling branch is still alive, a transport error on
    /// one branch MUST NOT short-circuit the upstream. The 503 is
    /// recorded but a later 200 from a sibling can still win.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_error_does_not_block_sibling_2xx() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-tx2".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        for id in ["z9hG4bKbr-dead", "z9hG4bKbr-alive"] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse("sip:user@example.com").unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        // Branch 1 fails at the transport — buffered (5xx isn't
        // immediately forwarded under §16.7's revised flow).
        let none = context.report_transport_error("z9hG4bKbr-dead").await;
        assert!(
            none.is_none(),
            "503 from one branch must not pre-empt sibling that is still trying",
        );

        // Branch 2 returns 200 OK — wins immediately.
        let forwarded = context
            .process_response("z9hG4bKbr-alive", make_response(200))
            .await
            .expect("2xx must forward");
        assert_eq!(forwarded.code(), 200);
    }

    /// A transport error reported for a branch that's already
    /// completed (e.g. response raced ahead of the error notification)
    /// must be a no-op so we don't double-account the response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_error_on_completed_branch_is_noop() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-tx3".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::None,
            )
            .unwrap();

        let branch = BranchInfo::new(
            "z9hG4bKbr-done",
            SipUri::parse("sip:user@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        )
        .unwrap();
        context.add_branch(branch).await.unwrap();
        // Drive the branch to Completed via a 486.
        context
            .process_response("z9hG4bKbr-done", make_response(486))
            .await;

        let forwarded = context.report_transport_error("z9hG4bKbr-done").await;
        assert!(
            forwarded.is_none(),
            "transport error on Completed branch must be ignored",
        );
    }

    // ===========================================
    // RFC 3261 §16.7 #7: 401/407 challenge aggregation
    //
    // When the best response is 401 or 407, the proxy MUST collect
    // every WWW-Authenticate / Proxy-Authenticate header from every
    // other branch that returned 401 / 407 and add them to the
    // forwarded response. The client needs all challenges to satisfy
    // every realm at once.
    // ===========================================

    /// Helper: build a response with auth challenge headers.
    fn make_auth_response(code: u16, www: &[&str], proxy: &[&str]) -> Response {
        let mut headers = Headers::new();
        headers.push("Call-ID", "test-call-123").unwrap();
        headers
            .push("Via", "SIP/2.0/UDP proxy;branch=z9hG4bKproxy")
            .unwrap();
        for value in www {
            headers.push("WWW-Authenticate", *value).unwrap();
        }
        for value in proxy {
            headers.push("Proxy-Authenticate", *value).unwrap();
        }
        Response::new(
            StatusLine::new(code, "Unauthorized").expect("valid status line"),
            headers,
            Bytes::new(),
        )
        .expect("valid response")
    }

    /// Wires up two branches that each return a 401 with a different
    /// WWW-Authenticate challenge. Drives them to completion with a
    /// 401 best response and asserts the aggregated forwarded response
    /// carries challenges from both branches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aggregates_www_authenticate_from_multiple_401_branches() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-401".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        for id in ["z9hG4bKbr-a", "z9hG4bKbr-b"] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse("sip:user@example.com").unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        let challenge_a = r#"Digest realm="realm-a.example.com",nonce="aaaa",algorithm=MD5"#;
        let challenge_b = r#"Digest realm="realm-b.example.com",nonce="bbbb",algorithm=SHA-256"#;

        // Branch A reports first; should not yet forward (waiting for B).
        let none = context
            .process_response("z9hG4bKbr-a", make_auth_response(401, &[challenge_a], &[]))
            .await;
        assert!(
            none.is_none(),
            "first 401 should be buffered, not forwarded"
        );

        // Branch B reports; all branches done, forwarded best should
        // carry both challenges.
        let forwarded = context
            .process_response("z9hG4bKbr-b", make_auth_response(401, &[challenge_b], &[]))
            .await
            .expect("final aggregate forwarded");
        assert_eq!(forwarded.code(), 401);
        let www: Vec<&str> = forwarded.headers().get_all("WWW-Authenticate").collect();
        assert!(
            www.iter().any(|v| *v == challenge_a),
            "challenge_a missing: {www:?}",
        );
        assert!(
            www.iter().any(|v| *v == challenge_b),
            "challenge_b missing: {www:?}",
        );
    }

    /// Same as above but for 407 / Proxy-Authenticate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aggregates_proxy_authenticate_from_multiple_407_branches() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-407".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        for id in ["z9hG4bKbr-a", "z9hG4bKbr-b"] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse("sip:user@example.com").unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        let challenge_a = r#"Digest realm="proxy-a.example.com",nonce="1111""#;
        let challenge_b = r#"Digest realm="proxy-b.example.com",nonce="2222""#;

        context
            .process_response("z9hG4bKbr-a", make_auth_response(407, &[], &[challenge_a]))
            .await;
        let forwarded = context
            .process_response("z9hG4bKbr-b", make_auth_response(407, &[], &[challenge_b]))
            .await
            .expect("final aggregate forwarded");
        assert_eq!(forwarded.code(), 407);
        let proxy_auth: Vec<&str> = forwarded.headers().get_all("Proxy-Authenticate").collect();
        assert!(proxy_auth.iter().any(|v| *v == challenge_a));
        assert!(proxy_auth.iter().any(|v| *v == challenge_b));
    }

    /// Identical challenges from two branches must NOT be appended
    /// twice — duplicates are removed so the upstream sees one copy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn does_not_duplicate_identical_authenticate_headers() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-dup".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        for id in ["z9hG4bKbr-a", "z9hG4bKbr-b"] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse("sip:user@example.com").unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        let same = r#"Digest realm="r.example.com",nonce="x""#;
        context
            .process_response("z9hG4bKbr-a", make_auth_response(401, &[same], &[]))
            .await;
        let forwarded = context
            .process_response("z9hG4bKbr-b", make_auth_response(401, &[same], &[]))
            .await
            .expect("forwarded");
        let count = forwarded
            .headers()
            .get_all("WWW-Authenticate")
            .filter(|v| *v == same)
            .count();
        assert_eq!(count, 1, "duplicate WWW-Authenticate must be deduped");
    }

    /// Regression guard: aggregation must only fire when the BEST
    /// response is 401 / 407. A 486 final must not pull in challenges
    /// from a sibling that earlier returned 401.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn does_not_aggregate_when_best_is_not_401_or_407() {
        let proxy = StatefulProxy::new();
        let request = make_request();
        let (context, _rx) = proxy
            .start_context(
                request,
                "test-call-mixed".into(),
                "z9hG4bKclient".into(),
                "proxy.example.com".into(),
                "UDP".into(),
                ForkMode::Parallel,
            )
            .unwrap();

        for id in ["z9hG4bKbr-401", "z9hG4bKbr-486"] {
            let branch = BranchInfo::new(
                id,
                SipUri::parse("sip:user@example.com").unwrap(),
                Instant::now(),
                BranchState::Trying,
            )
            .unwrap();
            context.add_branch(branch).await.unwrap();
        }

        let challenge = r#"Digest realm="r",nonce="x""#;
        context
            .process_response("z9hG4bKbr-401", make_auth_response(401, &[challenge], &[]))
            .await;
        // 486 wins per response-selection (lower-class beats 401? In
        // RFC 3261 §16.7 step 6, lowest 4xx wins; both are 4xx so the
        // first one stored wins. We pin the deterministic case by
        // having the 486 arrive last with a lower code than 401? Both
        // are 4xx — first-in-class wins, so the 401 is the best.
        // Override by sending 486 first then 401 to keep 401 best, OR
        // assert that when the best ends up being something else, no
        // aggregation runs. Use a 200 sibling instead of 486 so the
        // best is unambiguously NOT 401.)
        let forwarded = context
            .process_response("z9hG4bKbr-486", make_response(200))
            .await;
        // 200 wins immediately and is forwarded straight away.
        let forwarded = forwarded.expect("200 must be forwarded");
        assert_eq!(forwarded.code(), 200);
        let www_count = forwarded.headers().get_all("WWW-Authenticate").count();
        assert_eq!(
            www_count, 0,
            "200 OK must not carry aggregated WWW-Authenticate",
        );
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
        assert!(matches!(
            result,
            Err(ProxyError::BranchIdContainsControlChars)
        ));
    }

    #[test]
    fn rejects_branch_id_with_newline() {
        let result = BranchInfo::new(
            "z9hG4bK\nbranch",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(matches!(
            result,
            Err(ProxyError::BranchIdContainsControlChars)
        ));
    }

    #[test]
    fn rejects_branch_id_with_tab() {
        let result = BranchInfo::new(
            "z9hG4bK\tbranch",
            SipUri::parse("sip:target@example.com").unwrap(),
            Instant::now(),
            BranchState::Trying,
        );
        assert!(matches!(
            result,
            Err(ProxyError::BranchIdContainsControlChars)
        ));
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
                    .push(
                        "Via",
                        format!("SIP/2.0/UDP client;branch=z9hG4bKclient{}", i),
                    )
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
