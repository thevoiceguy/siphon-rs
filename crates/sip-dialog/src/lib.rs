// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3261 dialog state management with subscriptions and session timers.
//!
//! Implements dialog lifecycle (Early/Confirmed/Terminated), subscription tracking
//! per RFC 3265, and reliable provisional response handling (RFC 3262 PRACK).
//!
//! # Example
//! ```no_run
//! use sip_dialog::{Dialog, DialogManager};
//! use std::sync::Arc;
//! # use sip_core::{SipUri, Request, Response};
//! let manager = Arc::new(DialogManager::new());
//! # let req: Request = todo!();
//! # let resp: Response = todo!();
//! let local_uri = SipUri::parse("sip:alice@example.com").unwrap();
//! let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();
//! if let Some(dialog) = Dialog::new_uac(&req, &resp, local_uri, remote_uri) {
//!     manager.insert(dialog);
//! }
//! ```

use dashmap::DashMap;
use sip_core::{Headers, RefresherRole, Request, Response, SipUri};
use sip_parse::{header, parse_session_expires};
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Duration;

pub mod prack_validator;
pub mod session_timer_manager;
pub mod storage;
pub use storage::{DialogStore, InMemoryDialogStore};
pub mod metrics;
pub use metrics::{DialogMetrics, DialogMetricsSnapshot};

/// Dialog state per RFC 3261 §12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogStateType {
    /// Early dialog established by provisional response (1xx with tag)
    Early,
    /// Confirmed dialog established by 2xx response
    Confirmed,
    /// Dialog terminated by BYE or error
    Terminated,
}

/// Unique dialog identifier composed of Call-ID and local/remote tags (RFC 3261 §12).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: SmolStr,
    pub local_tag: SmolStr,
    pub remote_tag: SmolStr,
}

impl DialogId {
    pub fn new(
        call_id: impl Into<SmolStr>,
        local_tag: impl Into<SmolStr>,
        remote_tag: impl Into<SmolStr>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
            remote_tag: remote_tag.into(),
        }
    }

    /// Creates a dialog ID from a request, using the From tag as local tag.
    /// Returns None if Call-ID or From tag is missing.
    pub fn from_request(req: &Request) -> Option<Self> {
        let call_id = header(&req.headers, "Call-ID")?.clone();
        let from_tag = extract_tag(header(&req.headers, "From")?)?;
        let to_tag = extract_tag(header(&req.headers, "To")?)?;
        Some(Self::new(call_id, from_tag, to_tag))
    }

    /// Creates a dialog ID from a response, considering UAC perspective.
    /// For UAC: From tag is local, To tag is remote.
    pub fn from_response_uac(resp: &Response) -> Option<Self> {
        let call_id = header(&resp.headers, "Call-ID")?.clone();
        let from_tag = extract_tag(header(&resp.headers, "From")?)?;
        let to_tag = extract_tag(header(&resp.headers, "To")?)?;
        Some(Self::new(call_id, from_tag, to_tag))
    }

    /// Creates a dialog ID from a response, considering UAS perspective.
    /// For UAS: To tag is local, From tag is remote.
    pub fn from_response_uas(resp: &Response) -> Option<Self> {
        let call_id = header(&resp.headers, "Call-ID")?.clone();
        let to_tag = extract_tag(header(&resp.headers, "To")?)?;
        let from_tag = extract_tag(header(&resp.headers, "From")?)?;
        Some(Self::new(call_id, to_tag, from_tag))
    }
}

/// Complete dialog state tracking per RFC 3261 §12.
///
/// # RFC 5057 Multiple Dialog Usages
///
/// This implementation supports RFC 5057 "Multiple Dialog Usages in SIP", which
/// allows multiple methods (INVITE, SUBSCRIBE, REFER) to share a single dialog.
///
/// ## Dialog vs Dialog Usage
///
/// - **Dialog**: The shared state container identified by Call-ID and tags
/// - **Dialog Usage**: Individual association created by a specific method
///
/// A single dialog can have multiple usages:
/// - An INVITE usage for the call session
/// - Multiple SUBSCRIBE usages for different event packages
/// - REFER usages for call transfer
///
/// ## Shared State (RFC 5057 §4)
///
/// All usages within a dialog share:
/// - Dialog ID (Call-ID, local tag, remote tag)
/// - Remote target URI (updated by target refresh requests)
/// - Route set (proxy routing information)
/// - CSeq sequence space (both local and remote)
/// - Secure flag (SIPS requirement)
///
/// ## Usage-Specific State
///
/// Each usage type has its own state tracked separately:
/// - INVITE sessions: Tracked in DialogManager with session timers
/// - SUBSCRIBE usages: Tracked in SubscriptionManager with event package
/// - REFER usages: Tracked with refer-to and subscription state
///
/// ## Target Refresh (RFC 5057 §5)
///
/// Target refresh requests (re-INVITE, UPDATE, or target refresh SUBSCRIBE)
/// update the `remote_target` for the entire dialog, affecting ALL usages:
///
/// ```text
/// Dialog: Call-ID=abc, tags=1/2
///   ├─ INVITE usage (session)
///   ├─ SUBSCRIBE usage (presence)
///   └─ SUBSCRIBE usage (dialog state)
///
/// When re-INVITE updates Contact:
///   → remote_target changes for entire dialog
///   → All future requests use new remote_target
/// ```
///
/// ## Dialog Termination (RFC 5057 §6)
///
/// A dialog persists until ALL usages are terminated:
/// - BYE terminates the INVITE usage
/// - NOTIFY with Subscription-State: terminated ends SUBSCRIBE usages
/// - REFER implicit subscriptions can be suppressed (RFC 4488)
///
/// The dialog is removed from DialogManager when the last usage ends.
///
/// ## Implementation Pattern
///
/// Applications track multiple usages by maintaining separate managers:
/// ```text
/// let dialog_manager = DialogManager::new();
/// let subscription_manager = SubscriptionManager::new();
///
/// // INVITE creates dialog
/// let dialog = Dialog::new_uac(...);
/// dialog_manager.insert(dialog.clone());
///
/// // SUBSCRIBE on same dialog
/// let subscription = Subscription::new_subscriber(...);
/// subscription_manager.insert(subscription);
///
/// // Both share dialog.id, but have separate usage state
/// ```
#[derive(Debug, Clone)]
pub struct Dialog {
    /// Dialog identifier
    pub id: DialogId,

    /// Dialog state
    pub state: DialogStateType,

    /// Remote target URI (Contact header from remote party)
    pub remote_target: SipUri,

    /// Route set (from Record-Route headers, stored in reverse order)
    pub route_set: Vec<SipUri>,

    /// Local CSeq number (incremented for each request we send)
    pub local_cseq: u32,

    /// Remote CSeq number (tracked from requests we receive)
    pub remote_cseq: u32,

    /// Last ACK CSeq number (tracked separately to prevent replay)
    pub last_ack_cseq: Option<u32>,

    /// Local URI (our identity)
    pub local_uri: SipUri,

    /// Remote URI (their identity)
    pub remote_uri: SipUri,

    /// Secure flag (true for SIPS)
    pub secure: bool,

    /// Session timer expiration (RFC 4028)
    pub session_expires: Option<Duration>,

    /// Session refresher role (uac or uas)
    pub refresher: Option<RefresherRole>,

    /// Whether we are the UAC (caller) or UAS (callee)
    pub is_uac: bool,
}

impl Dialog {
    /// Creates a new dialog from UAC perspective (we initiated the call).
    pub fn new_uac(
        req: &Request,
        resp: &Response,
        local_uri: SipUri,
        remote_uri: SipUri,
    ) -> Option<Self> {
        let id = DialogId::from_response_uac(resp)?;

        // Determine state based on response code
        let state = match resp.start.code {
            100..=199 => DialogStateType::Early,
            200..=299 => DialogStateType::Confirmed,
            _ => return None, // No dialog for error responses
        };

        // Extract remote target from Contact header
        let remote_target =
            extract_contact_uri(&resp.headers).or_else(|| Some(remote_uri.clone()))?;

        // Build route set from Record-Route (stored in reverse for requests)
        let route_set = build_route_set(&resp.headers);

        // Parse CSeq from request
        let local_cseq = parse_cseq_number(&req.headers)?;
        let remote_cseq = 0; // Will be updated when we receive requests

        // Extract session timer info
        let (session_expires, refresher) = extract_session_timer(resp);

        // Check if secure before moving URIs
        let secure = local_uri.sips || remote_uri.sips;

        Some(Self {
            id,
            state,
            remote_target,
            route_set,
            local_cseq,
            remote_cseq,
            last_ack_cseq: None,
            local_uri,
            remote_uri,
            secure,
            session_expires,
            refresher,
            is_uac: true,
        })
    }

    /// Creates a new dialog from UAS perspective (we received the call).
    pub fn new_uas(
        req: &Request,
        resp: &Response,
        local_uri: SipUri,
        remote_uri: SipUri,
    ) -> Option<Self> {
        let id = DialogId::from_response_uas(resp)?;

        let state = match resp.start.code {
            100..=199 => DialogStateType::Early,
            200..=299 => DialogStateType::Confirmed,
            _ => return None,
        };

        // Extract remote target from Contact in request (caller's contact)
        let remote_target =
            extract_contact_uri(&req.headers).or_else(|| Some(remote_uri.clone()))?;

        // Build route set from Record-Route (from initial request for UAS)
        let route_set = build_route_set(&req.headers);

        // Parse CSeq from request (this is remote CSeq since they sent it)
        let remote_cseq = parse_cseq_number(&req.headers)?;
        let local_cseq = 0; // Will be incremented when we send requests

        let (session_expires, refresher) = extract_session_timer(resp);

        // Check if secure before moving URIs
        let secure = local_uri.sips || remote_uri.sips;

        Some(Self {
            id,
            state,
            remote_target,
            route_set,
            local_cseq,
            remote_cseq,
            last_ack_cseq: None,
            local_uri,
            remote_uri,
            secure,
            session_expires,
            refresher,
            is_uac: false,
        })
    }

    /// Transitions from Early to Confirmed state.
    pub fn confirm(&mut self) {
        if self.state == DialogStateType::Early {
            self.state = DialogStateType::Confirmed;
        }
    }

    /// Marks the dialog as terminated.
    pub fn terminate(&mut self) {
        self.state = DialogStateType::Terminated;
    }

    /// Returns the next CSeq number to use for outgoing requests.
    pub fn next_local_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }

    /// Updates dialog state from a received response (target refresh).
    ///
    /// # RFC 5057 Target Refresh
    ///
    /// When a target refresh response is received (e.g., 2xx to re-INVITE or UPDATE),
    /// the Contact header updates the `remote_target` for the ENTIRE dialog. This
    /// affects all usages sharing this dialog, not just the usage that sent the request.
    ///
    /// Example:
    /// ```text
    /// Dialog has INVITE usage + SUBSCRIBE usage for presence
    /// → re-INVITE receives 200 OK with new Contact
    /// → remote_target updates for dialog
    /// → Future SUBSCRIBE refreshes use new remote_target
    /// ```
    pub fn update_from_response(&mut self, resp: &Response) {
        // Update remote target if Contact present
        if let Some(contact) = extract_contact_uri(&resp.headers) {
            self.remote_target = contact;
        }

        // Update route set if Record-Route present
        let new_route_set = build_route_set(&resp.headers);
        if !new_route_set.is_empty() {
            self.route_set = new_route_set;
        }

        // Update session timer if present
        let (session_expires, refresher) = extract_session_timer(resp);
        if session_expires.is_some() {
            self.session_expires = session_expires;
            self.refresher = refresher;
        }

        // Confirm early dialog on 2xx
        if resp.start.code >= 200 && resp.start.code < 300 {
            self.confirm();
        }
    }

    /// Updates dialog state from a received request.
    ///
    /// # RFC 5057 Target Refresh
    ///
    /// Target refresh requests (re-INVITE, UPDATE, or target refresh SUBSCRIBE)
    /// update the `remote_target` for the entire dialog when they contain a Contact
    /// header. This affects all usages sharing the dialog.
    ///
    /// # CSeq Validation (RFC 5057 §4.1)
    ///
    /// All usages share a single CSeq space. This method validates that incoming
    /// requests have monotonically increasing CSeq numbers (except ACK).
    ///
    /// # Security Considerations
    ///
    /// - First CSeq must be >= 1 (RFC 3261 requires non-zero initial CSeq)
    /// - ACK CSeq must match the INVITE/re-INVITE CSeq for the dialog
    pub fn update_from_request(&mut self, req: &Request) -> Result<(), DialogError> {
        // Validate and update remote CSeq
        let cseq = parse_cseq_number(&req.headers).ok_or(DialogError::MissingHeader)?;

        // RFC 3261 requires CSeq >= 1
        if cseq == 0 {
            return Err(DialogError::InvalidCSeq);
        }

        if req.start.method.as_str() == "ACK" {
            // ACK for an INVITE dialog must reuse the INVITE's CSeq.
            if cseq != self.remote_cseq || self.remote_cseq == 0 {
                return Err(DialogError::InvalidCSeq);
            }

            // Allow retransmitted ACKs with identical CSeq.
            self.last_ack_cseq = Some(cseq);
        } else {
            // Non-ACK requests must have strictly increasing CSeq
            if cseq <= self.remote_cseq {
                return Err(DialogError::InvalidCSeq);
            }

            self.remote_cseq = cseq;
        }

        // Update remote target from Contact
        if let Some(contact) = extract_contact_uri(&req.headers) {
            self.remote_target = contact;
        }

        Ok(())
    }

    /// Checks if the dialog should be refreshed based on session timer.
    pub fn needs_refresh(&self, elapsed: Duration) -> bool {
        if let Some(expires) = self.session_expires {
            elapsed >= expires * 2 / 3 // Refresh at 2/3 of expiration
        } else {
            false
        }
    }

    /// Returns true if this dialog matches the given request.
    pub fn matches_request(&self, req: &Request) -> bool {
        if let Some(req_id) = DialogId::from_request(req) {
            // Reverse perspective: request's From is remote, To is local
            req_id.call_id == self.id.call_id
                && req_id.local_tag == self.id.remote_tag
                && req_id.remote_tag == self.id.local_tag
        } else {
            false
        }
    }
}

/// Dialog manager for tracking active dialogs.
pub struct DialogManager {
    dialogs: Arc<DashMap<DialogId, Dialog>>,
    pub metrics: Arc<metrics::DialogMetrics>,
}

impl DialogManager {
    pub fn new() -> Self {
        Self {
            dialogs: Arc::new(DashMap::new()),
            metrics: Arc::new(metrics::DialogMetrics::default()),
        }
    }

    /// Inserts or updates a dialog.
    pub fn insert(&self, dialog: Dialog) {
        self.dialogs.insert(dialog.id.clone(), dialog);
        self.metrics.record_created();
    }

    /// Retrieves a dialog by ID.
    pub fn get(&self, id: &DialogId) -> Option<Dialog> {
        self.dialogs.get(id).map(|entry| entry.clone())
    }

    /// Finds a dialog matching the given request.
    pub fn find_by_request(&self, req: &Request) -> Option<Dialog> {
        // Try to construct dialog ID from request
        if let Some(req_id) = DialogId::from_request(req) {
            // For incoming requests, swap tags (From=remote, To=local)
            let search_id = DialogId::new(
                req_id.call_id.clone(),
                req_id.remote_tag.clone(),
                req_id.local_tag.clone(),
            );
            return self.get(&search_id);
        }
        None
    }

    /// Removes a dialog.
    pub fn remove(&self, id: &DialogId) -> Option<Dialog> {
        let res = self.dialogs.remove(id).map(|(_, dialog)| dialog);
        if res.is_some() {
            self.metrics.record_terminated();
        }
        res
    }

    /// Returns the count of active dialogs.
    pub fn count(&self) -> usize {
        self.dialogs.len()
    }

    /// Removes all terminated dialogs.
    pub fn cleanup_terminated(&self) {
        self.dialogs
            .retain(|_, dialog| dialog.state != DialogStateType::Terminated);
    }

    /// Returns all dialog IDs.
    pub fn all_ids(&self) -> Vec<DialogId> {
        self.dialogs
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }
}

impl Default for DialogManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialog-related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogError {
    /// CSeq number is not greater than previous
    InvalidCSeq,
    /// Dialog not found
    NotFound,
    /// Dialog is in wrong state for operation
    InvalidState,
    /// Missing required header
    MissingHeader,
}

impl std::fmt::Display for DialogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialogError::InvalidCSeq => write!(f, "Invalid CSeq number"),
            DialogError::NotFound => write!(f, "Dialog not found"),
            DialogError::InvalidState => write!(f, "Invalid dialog state"),
            DialogError::MissingHeader => write!(f, "Missing required header"),
        }
    }
}

impl std::error::Error for DialogError {}

// Helper functions

/// Extracts tag parameter from From/To header value.
fn extract_tag(value: &SmolStr) -> Option<SmolStr> {
    value.split(';').find_map(|segment| {
        let trimmed = segment.trim();
        if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("tag=") {
            Some(SmolStr::new(trimmed[4..].to_owned()))
        } else {
            None
        }
    })
}

/// Builds route set from Record-Route headers (reversed for UAC).
fn build_route_set(headers: &Headers) -> Vec<SipUri> {
    let mut routes: Vec<SipUri> = headers
        .get_all("Record-Route")
        .flat_map(|v| split_header_values(v.as_str()))
        .filter_map(|v| parse_uri_from_header(v.as_str()))
        .collect();

    // Reverse for proper routing
    routes.reverse();
    routes
}

/// Extracts Contact URI from headers.
fn extract_contact_uri(headers: &Headers) -> Option<SipUri> {
    header(headers, "Contact").and_then(|raw| parse_uri_from_header(raw.as_str()))
}

/// Parses CSeq number from headers.
fn parse_cseq_number(headers: &Headers) -> Option<u32> {
    header(headers, "CSeq")?
        .split_whitespace()
        .next()?
        .parse::<u32>()
        .ok()
}

/// Extracts session timer information from response.
fn extract_session_timer(resp: &Response) -> (Option<Duration>, Option<RefresherRole>) {
    if let Some(se_header) = header(&resp.headers, "Session-Expires") {
        if let Some(se) = parse_session_expires(se_header) {
            return (
                Some(Duration::from_secs(se.delta_seconds as u64)),
                se.refresher,
            );
        }
    }
    (None, None)
}

/// Parses URI from header value (handles angle brackets).
fn parse_uri_from_header(raw: &str) -> Option<SipUri> {
    let trimmed = raw.trim();
    let uri_part = if let Some(start) = trimmed.find('<') {
        let end = trimmed[start + 1..].find('>')?;
        &trimmed[start + 1..start + 1 + end]
    } else {
        // No angle brackets, might have parameters after
        trimmed.split(';').next()?
    };
    SipUri::parse(uri_part.trim())
}

/// Splits a header value into comma-separated elements, respecting quotes and <>.
fn split_header_values(raw: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut angle_depth = 0usize;
    let mut start = 0usize;

    for (idx, ch) in raw.char_indices() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            '<' => {
                angle_depth = angle_depth.saturating_add(1);
            }
            '>' => {
                if angle_depth > 0 {
                    angle_depth -= 1;
                }
            }
            ',' if !in_quotes && angle_depth == 0 => {
                let part = raw[start..idx].trim();
                if !part.is_empty() {
                    parts.push(part.to_owned());
                }
                start = idx + 1;
            }
            _ => {}
        }
    }

    let part = raw[start..].trim();
    if !part.is_empty() {
        parts.push(part.to_owned());
    }

    parts
}

// ============================================================================
// Subscription Management (RFC 3265)
// ============================================================================

/// Subscription state per RFC 3265.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Subscription is active
    Active,
    /// Subscription is pending approval
    Pending,
    /// Subscription has been terminated
    Terminated,
}

impl SubscriptionState {
    pub fn as_str(self) -> &'static str {
        match self {
            SubscriptionState::Active => "active",
            SubscriptionState::Pending => "pending",
            SubscriptionState::Terminated => "terminated",
        }
    }
}

/// Unique subscription identifier composed of Call-ID, From tag, and To tag.
/// Similar to DialogId but for subscriptions (RFC 3265 §3.1.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionId {
    pub call_id: SmolStr,
    pub from_tag: SmolStr,
    pub to_tag: SmolStr,
    pub event: SmolStr,
}

impl SubscriptionId {
    pub fn new(
        call_id: impl Into<SmolStr>,
        from_tag: impl Into<SmolStr>,
        to_tag: impl Into<SmolStr>,
        event: impl Into<SmolStr>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            to_tag: to_tag.into(),
            event: event.into(),
        }
    }

    /// Creates a subscription ID from a SUBSCRIBE request or NOTIFY request.
    pub fn from_request(req: &Request) -> Option<Self> {
        let call_id = header(&req.headers, "Call-ID")?.clone();
        let from_tag = extract_tag(header(&req.headers, "From")?)?;
        let to_tag = extract_tag(header(&req.headers, "To")?)?;
        let event = header(&req.headers, "Event")?.clone();
        Some(Self::new(call_id, from_tag, to_tag, event))
    }

    /// Creates a subscription ID from request and response (notifier perspective).
    /// Uses From tag from request and To tag from response.
    pub fn from_request_response(req: &Request, resp: &Response) -> Option<Self> {
        let call_id = header(&req.headers, "Call-ID")?.clone();
        let from_tag = extract_tag(header(&req.headers, "From")?)?;
        let to_tag = extract_tag(header(&resp.headers, "To")?)?;
        let event = header(&req.headers, "Event")?.clone();
        Some(Self::new(call_id, from_tag, to_tag, event))
    }
}

/// Represents an active subscription (RFC 3265).
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub state: SubscriptionState,
    pub local_uri: SipUri,
    pub remote_uri: SipUri,
    pub contact: SipUri,
    pub expires: Duration,
    pub local_cseq: u32,
    pub remote_cseq: u32,
}

impl Subscription {
    /// Creates a new subscription from a SUBSCRIBE request (notifier perspective).
    pub fn new_notifier(
        request: &Request,
        response: &Response,
        local_uri: SipUri,
        remote_uri: SipUri,
    ) -> Option<Self> {
        let id = SubscriptionId::from_request_response(request, response)?;
        let contact = extract_contact_uri(&response.headers)?;
        let local_cseq = parse_cseq_number(&request.headers)?;

        // Parse expires from response or request
        let expires = if let Some(exp_str) = header(&response.headers, "Expires") {
            Duration::from_secs(exp_str.parse().ok()?)
        } else if let Some(exp_str) = header(&request.headers, "Expires") {
            Duration::from_secs(exp_str.parse().ok()?)
        } else {
            Duration::from_secs(3600) // Default
        };

        Some(Self {
            id,
            state: SubscriptionState::Active,
            local_uri,
            remote_uri,
            contact,
            expires,
            local_cseq,
            remote_cseq: 0,
        })
    }

    /// Creates a new subscription from a SUBSCRIBE response (subscriber perspective).
    pub fn new_subscriber(
        request: &Request,
        response: &Response,
        local_uri: SipUri,
        remote_uri: SipUri,
    ) -> Option<Self> {
        let id = SubscriptionId::from_request_response(request, response)?;
        let contact = extract_contact_uri(&response.headers)?;
        let remote_cseq = 0;
        let local_cseq = parse_cseq_number(&request.headers)?;

        // Parse expires from response
        let expires = if let Some(exp_str) = header(&response.headers, "Expires") {
            Duration::from_secs(exp_str.parse().ok()?)
        } else {
            Duration::from_secs(3600) // Default
        };

        Some(Self {
            id,
            state: SubscriptionState::Active,
            local_uri,
            remote_uri,
            contact,
            expires,
            local_cseq,
            remote_cseq,
        })
    }

    /// Returns the next local CSeq number and increments it.
    pub fn next_local_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }

    /// Updates the subscription state.
    pub fn update_state(&mut self, new_state: SubscriptionState) {
        self.state = new_state;
    }

    /// Updates the expiration time.
    pub fn update_expires(&mut self, expires: Duration) {
        self.expires = expires;
    }
}

/// Manages active subscriptions (thread-safe).
#[derive(Debug, Clone)]
pub struct SubscriptionManager {
    subscriptions: Arc<DashMap<SubscriptionId, Subscription>>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(DashMap::new()),
        }
    }

    /// Inserts or updates a subscription.
    pub fn insert(&self, subscription: Subscription) {
        self.subscriptions
            .insert(subscription.id.clone(), subscription);
    }

    /// Retrieves a subscription by ID.
    pub fn get(&self, id: &SubscriptionId) -> Option<Subscription> {
        self.subscriptions
            .get(id)
            .map(|entry| entry.value().clone())
    }

    /// Removes a subscription.
    pub fn remove(&self, id: &SubscriptionId) -> Option<Subscription> {
        self.subscriptions.remove(id).map(|(_, sub)| sub)
    }

    /// Returns all active subscriptions.
    pub fn all(&self) -> Vec<Subscription> {
        self.subscriptions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns subscriptions for a specific event package.
    pub fn by_event(&self, event: &str) -> Vec<Subscription> {
        self.subscriptions
            .iter()
            .filter(|entry| entry.value().id.event.as_str() == event)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Removes all terminated subscriptions.
    pub fn cleanup_terminated(&self) -> usize {
        let terminated: Vec<_> = self
            .subscriptions
            .iter()
            .filter(|entry| entry.value().state == SubscriptionState::Terminated)
            .map(|entry| entry.key().clone())
            .collect();

        let count = terminated.len();
        for id in terminated {
            self.subscriptions.remove(&id);
        }
        count
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// RSeq (Reliable Sequence) manager for RFC 3262 PRACK support.
///
/// Manages RSeq sequence numbers for reliable provisional responses.
/// Each dialog has its own RSeq sequence space starting at 1.
#[derive(Debug, Clone)]
pub struct RSeqManager {
    /// Map of DialogId to next RSeq number
    sequences: Arc<DashMap<DialogId, u32>>,
}

impl RSeqManager {
    pub fn new() -> Self {
        Self {
            sequences: Arc::new(DashMap::new()),
        }
    }

    /// Gets the next RSeq for a dialog and increments the counter.
    /// Returns 1 for the first call.
    pub fn next_rseq(&self, dialog_id: &DialogId) -> u32 {
        self.sequences
            .entry(dialog_id.clone())
            .and_modify(|rseq| *rseq = rseq.saturating_add(1))
            .or_insert(1)
            .clone()
    }

    /// Gets the current RSeq without incrementing.
    pub fn current_rseq(&self, dialog_id: &DialogId) -> Option<u32> {
        self.sequences.get(dialog_id).map(|entry| *entry.value())
    }

    /// Removes RSeq tracking for a dialog (when dialog terminates).
    pub fn remove(&self, dialog_id: &DialogId) {
        self.sequences.remove(dialog_id);
    }

    /// Returns the number of tracked dialogs.
    pub fn len(&self) -> usize {
        self.sequences.len()
    }

    /// Returns true if no dialogs are tracked.
    pub fn is_empty(&self) -> bool {
        self.sequences.is_empty()
    }
}

impl Default for RSeqManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::{Method, RequestLine, StatusLine};

    fn make_request(
        method: Method,
        call_id: &str,
        from_tag: &str,
        to_tag: Option<&str>,
        cseq: u32,
    ) -> Request {
        let mut headers = Headers::new();
        headers.push(SmolStr::new("Call-ID"), SmolStr::new(call_id.to_owned()));
        headers.push(
            SmolStr::new("From"),
            SmolStr::new(format!("<sip:alice@example.com>;tag={}", from_tag)),
        );
        if let Some(tag) = to_tag {
            headers.push(
                SmolStr::new("To"),
                SmolStr::new(format!("<sip:bob@example.com>;tag={}", tag)),
            );
        } else {
            headers.push(
                SmolStr::new("To"),
                SmolStr::new("<sip:bob@example.com>".to_owned()),
            );
        }
        headers.push(
            SmolStr::new("CSeq"),
            SmolStr::new(format!("{} {}", cseq, method.as_str())),
        );
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:alice@client.example.com>".to_owned()),
        );

        Request::new(
            RequestLine::new(method, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            bytes::Bytes::new(),
        )
    }

    fn make_response(code: u16, req: &Request, to_tag: &str) -> Response {
        let mut headers = Headers::new();

        // Copy all headers from request except To
        for header in req.headers.iter() {
            if header.name.as_str() != "To" {
                headers.push(header.name.clone(), header.value.clone());
            }
        }

        // Add To header with tag
        headers.push(
            SmolStr::new("To"),
            SmolStr::new(format!("<sip:bob@example.com>;tag={}", to_tag)),
        );

        // Add Contact header
        headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@server.example.com>".to_owned()),
        );

        Response::new(
            StatusLine::new(code, SmolStr::new("OK")),
            headers,
            bytes::Bytes::new(),
        )
    }

    #[test]
    fn dialog_id_from_request() {
        let req = make_request(Method::Invite, "call123", "from-tag", Some("to-tag"), 1);
        let id = DialogId::from_request(&req).unwrap();

        assert_eq!(id.call_id.as_str(), "call123");
        assert_eq!(id.local_tag.as_str(), "from-tag");
        assert_eq!(id.remote_tag.as_str(), "to-tag");
    }

    #[test]
    fn uac_dialog_creation() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let dialog = Dialog::new_uac(
            &req,
            &resp,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        assert_eq!(dialog.state, DialogStateType::Confirmed);
        assert_eq!(dialog.id.local_tag.as_str(), "uac-tag");
        assert_eq!(dialog.id.remote_tag.as_str(), "uas-tag");
        assert_eq!(dialog.local_cseq, 1);
        assert_eq!(dialog.remote_cseq, 0);
        assert!(dialog.is_uac);
    }

    #[test]
    fn uas_dialog_creation() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        assert_eq!(dialog.state, DialogStateType::Confirmed);
        assert_eq!(dialog.id.local_tag.as_str(), "uas-tag");
        assert_eq!(dialog.id.remote_tag.as_str(), "uac-tag");
        assert_eq!(dialog.local_cseq, 0);
        assert_eq!(dialog.remote_cseq, 1);
        assert!(!dialog.is_uac);
    }

    #[test]
    fn early_dialog_confirmation() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp_180 = make_response(180, &req, "uas-tag");

        let mut dialog = Dialog::new_uac(
            &req,
            &resp_180,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        assert_eq!(dialog.state, DialogStateType::Early);

        let resp_200 = make_response(200, &req, "uas-tag");
        dialog.update_from_response(&resp_200);

        assert_eq!(dialog.state, DialogStateType::Confirmed);
    }

    #[test]
    fn local_cseq_increment() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let mut dialog = Dialog::new_uac(
            &req,
            &resp,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        assert_eq!(dialog.next_local_cseq(), 2);
        assert_eq!(dialog.next_local_cseq(), 3);
        assert_eq!(dialog.next_local_cseq(), 4);
    }

    #[test]
    fn remote_cseq_validation() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let mut dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        // Remote CSeq starts at 1 from INVITE
        assert_eq!(dialog.remote_cseq, 1);

        // Receiving request with same CSeq should fail
        let req2 = make_request(Method::Invite, "call123", "uac-tag", Some("uas-tag"), 1);
        assert_eq!(
            dialog.update_from_request(&req2),
            Err(DialogError::InvalidCSeq)
        );

        // Receiving request with higher CSeq should succeed
        let req3 = make_request(Method::Bye, "call123", "uac-tag", Some("uas-tag"), 2);
        assert!(dialog.update_from_request(&req3).is_ok());
        assert_eq!(dialog.remote_cseq, 2);
    }

    #[test]
    fn dialog_manager_operations() {
        let manager = DialogManager::new();

        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let dialog = Dialog::new_uac(
            &req,
            &resp,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        let id = dialog.id.clone();

        // Insert dialog
        manager.insert(dialog.clone());
        assert_eq!(manager.count(), 1);

        // Retrieve dialog
        let retrieved = manager.get(&id).unwrap();
        assert_eq!(retrieved.id, dialog.id);

        // Find by request
        let bye_req = make_request(Method::Bye, "call123", "uas-tag", Some("uac-tag"), 2);
        let found = manager.find_by_request(&bye_req).unwrap();
        assert_eq!(found.id, dialog.id);

        // Remove dialog
        manager.remove(&id);
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn dialog_termination() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let mut dialog = Dialog::new_uac(
            &req,
            &resp,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        assert_eq!(dialog.state, DialogStateType::Confirmed);

        dialog.terminate();
        assert_eq!(dialog.state, DialogStateType::Terminated);
    }

    #[test]
    fn cleanup_terminated_dialogs() {
        let manager = DialogManager::new();

        let req1 = make_request(Method::Invite, "call1", "tag1", None, 1);
        let resp1 = make_response(200, &req1, "tag2");
        let dialog1 = Dialog::new_uac(
            &req1,
            &resp1,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        let req2 = make_request(Method::Invite, "call2", "tag3", None, 1);
        let resp2 = make_response(200, &req2, "tag4");
        let mut dialog2 = Dialog::new_uac(
            &req2,
            &resp2,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        dialog2.terminate();

        manager.insert(dialog1);
        manager.insert(dialog2);

        assert_eq!(manager.count(), 2);

        manager.cleanup_terminated();
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn target_refresh_updates_contact() {
        let req = make_request(Method::Invite, "call123", "uac-tag", None, 1);
        let resp = make_response(200, &req, "uas-tag");

        let mut dialog = Dialog::new_uac(
            &req,
            &resp,
            SipUri::parse("sip:alice@example.com").unwrap(),
            SipUri::parse("sip:bob@example.com").unwrap(),
        )
        .unwrap();

        let original_target = dialog.remote_target.clone();

        // Simulate re-INVITE with new Contact
        let reinvite_req = make_request(Method::Invite, "call123", "uac-tag", Some("uas-tag"), 2);
        let mut reinvite_resp_headers = Headers::new();

        // Copy all headers except Contact
        for header in make_response(200, &reinvite_req, "uas-tag").headers.iter() {
            if header.name.as_str() != "Contact" {
                reinvite_resp_headers.push(header.name.clone(), header.value.clone());
            }
        }

        // Add new Contact header
        reinvite_resp_headers.push(
            SmolStr::new("Contact"),
            SmolStr::new("<sip:bob@newserver.example.com>".to_owned()),
        );

        let reinvite_resp = Response::new(
            StatusLine::new(200, SmolStr::new("OK")),
            reinvite_resp_headers,
            bytes::Bytes::new(),
        );

        dialog.update_from_response(&reinvite_resp);

        assert_ne!(dialog.remote_target, original_target);
        assert_eq!(dialog.remote_target.host.as_str(), "newserver.example.com");
    }

    #[test]
    fn extract_tag_variations() {
        assert_eq!(
            extract_tag(&SmolStr::new("<sip:user@host>;tag=abc123".to_owned())),
            Some(SmolStr::new("abc123".to_owned()))
        );
        assert_eq!(
            extract_tag(&SmolStr::new("sip:user@host;tag=xyz".to_owned())),
            Some(SmolStr::new("xyz".to_owned()))
        );
        assert_eq!(
            extract_tag(&SmolStr::new(
                "<sip:user@host>;param=val;tag=test;other=val".to_owned()
            )),
            Some(SmolStr::new("test".to_owned()))
        );
        assert_eq!(
            extract_tag(&SmolStr::new("<sip:user@host>".to_owned())),
            None
        );
    }

    #[test]
    fn parse_uri_with_angle_brackets() {
        let uri = parse_uri_from_header("<sip:bob@example.com>").unwrap();
        assert_eq!(uri.host.as_str(), "example.com");

        let uri2 = parse_uri_from_header("  <sip:alice@test.com:5060>  ").unwrap();
        assert_eq!(uri2.host.as_str(), "test.com");
        assert_eq!(uri2.port, Some(5060));
    }

    #[test]
    fn parse_uri_without_angle_brackets() {
        let uri = parse_uri_from_header("sip:bob@example.com").unwrap();
        assert_eq!(uri.host.as_str(), "example.com");
    }

    #[test]
    fn cseq_validation_rejects_zero() {
        // Create UAS dialog with initial CSeq=1
        let req = make_request(Method::Invite, "call123", "alice-tag", None, 1);
        let resp = make_response(200, &req, "bob-tag");
        let mut dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        // Attempt to update with CSeq=0 should fail
        let bad_req = make_request(Method::Invite, "call123", "alice-tag", Some("bob-tag"), 0);
        assert!(dialog.update_from_request(&bad_req).is_err());
    }

    #[test]
    fn cseq_validation_requires_monotonic_increase() {
        let req = make_request(Method::Invite, "call123", "alice-tag", None, 10);
        let resp = make_response(200, &req, "bob-tag");
        let mut dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        // CSeq=11 should succeed
        let req11 = make_request(Method::Bye, "call123", "alice-tag", Some("bob-tag"), 11);
        assert!(dialog.update_from_request(&req11).is_ok());
        assert_eq!(dialog.remote_cseq, 11);

        // CSeq=11 again should fail (not strictly increasing)
        let req11_again = make_request(Method::Bye, "call123", "alice-tag", Some("bob-tag"), 11);
        assert!(dialog.update_from_request(&req11_again).is_err());

        // CSeq=10 should fail (going backwards)
        let req10 = make_request(Method::Bye, "call123", "alice-tag", Some("bob-tag"), 10);
        assert!(dialog.update_from_request(&req10).is_err());
    }

    #[test]
    fn cseq_validation_allows_large_jumps() {
        let req = make_request(Method::Invite, "call123", "alice-tag", None, 10);
        let resp = make_response(200, &req, "bob-tag");
        let mut dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        // CSeq=110 (jump of 100) should succeed (at the limit)
        let req110 = make_request(Method::Bye, "call123", "alice-tag", Some("bob-tag"), 110);
        assert!(dialog.update_from_request(&req110).is_ok());
        assert_eq!(dialog.remote_cseq, 110);

        // CSeq=212 (jump of 102) should succeed
        let req212 = make_request(Method::Bye, "call123", "alice-tag", Some("bob-tag"), 212);
        assert!(dialog.update_from_request(&req212).is_ok());
        assert_eq!(dialog.remote_cseq, 212);
    }

    #[test]
    fn cseq_validation_allows_ack_retransmission() {
        let req = make_request(Method::Invite, "call123", "alice-tag", None, 10);
        let resp = make_response(200, &req, "bob-tag");
        let mut dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        // First ACK with CSeq=10 should succeed
        let ack1 = make_request(Method::Ack, "call123", "alice-tag", Some("bob-tag"), 10);
        assert!(dialog.update_from_request(&ack1).is_ok());
        assert_eq!(dialog.last_ack_cseq, Some(10));

        // Replayed ACK with same CSeq=10 should succeed
        let ack1_replay = make_request(Method::Ack, "call123", "alice-tag", Some("bob-tag"), 10);
        assert!(dialog.update_from_request(&ack1_replay).is_ok());

        // New re-INVITE with higher CSeq
        let reinvite = make_request(Method::Invite, "call123", "alice-tag", Some("bob-tag"), 11);
        assert!(dialog.update_from_request(&reinvite).is_ok());

        // ACK with CSeq=11 for the re-INVITE should succeed
        let ack2 = make_request(Method::Ack, "call123", "alice-tag", Some("bob-tag"), 11);
        assert!(dialog.update_from_request(&ack2).is_ok());
        assert_eq!(dialog.last_ack_cseq, Some(11));

        // ACK with old CSeq=10 should still fail (even after new ACK)
        let ack_old = make_request(Method::Ack, "call123", "alice-tag", Some("bob-tag"), 10);
        assert!(dialog.update_from_request(&ack_old).is_err());
    }

    #[test]
    fn cseq_validation_ack_does_not_update_remote_cseq() {
        let req = make_request(Method::Invite, "call123", "alice-tag", None, 10);
        let resp = make_response(200, &req, "bob-tag");
        let mut dialog = Dialog::new_uas(
            &req,
            &resp,
            SipUri::parse("sip:bob@example.com").unwrap(),
            SipUri::parse("sip:alice@example.com").unwrap(),
        )
        .unwrap();

        assert_eq!(dialog.remote_cseq, 10);

        // ACK should not update remote_cseq
        let ack = make_request(Method::Ack, "call123", "alice-tag", Some("bob-tag"), 10);
        assert!(dialog.update_from_request(&ack).is_ok());
        assert_eq!(dialog.remote_cseq, 10); // Should remain unchanged

        // Next non-ACK request should still require CSeq > 10
        let bye = make_request(Method::Bye, "call123", "alice-tag", Some("bob-tag"), 11);
        assert!(dialog.update_from_request(&bye).is_ok());
        assert_eq!(dialog.remote_cseq, 11);
    }
}
