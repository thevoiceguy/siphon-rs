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

// Security: Dialog identifier limits (DoS prevention)
const MAX_CALL_ID_LENGTH: usize = 256;
const MAX_TAG_LENGTH: usize = 128;
const MAX_URI_LENGTH: usize = 512;

// Security: Collection limits (DoS prevention)
const MAX_ROUTE_SET_SIZE: usize = 50;
const MAX_EARLY_DIALOGS_PER_CALL_ID: usize = 100;
const MAX_CONFIRMED_DIALOGS: usize = 10_000;
const MAX_SUBSCRIPTIONS: usize = 10_000;

// Security: CSeq limits (integer overflow prevention)
const MAX_CSEQ_VALUE: u32 = 2_147_483_647; // i32::MAX
const MAX_CSEQ_JUMP: u32 = 1000; // Detect malicious jumps

// Security: Session timer limits (RFC 4028 compliance)
const MIN_SESSION_EXPIRES: u32 = 90; // seconds
const MAX_SESSION_EXPIRES: u32 = 86400; // 24 hours

// Security: Event package limits
const MAX_EVENT_PACKAGE_LENGTH: usize = 64;
const MAX_EVENT_ID_LENGTH: usize = 128;

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
    call_id: SmolStr,
    local_tag: SmolStr,
    remote_tag: SmolStr,
}

impl DialogId {
    /// Creates a new DialogId with validation.
    ///
    /// # Errors
    ///
    /// Returns `DialogError` if any field exceeds maximum length or contains control characters.
    pub fn new(
        call_id: impl AsRef<str>,
        local_tag: impl AsRef<str>,
        remote_tag: impl AsRef<str>,
    ) -> Result<Self, DialogError> {
        let call_id_str = call_id.as_ref();
        let local_tag_str = local_tag.as_ref();
        let remote_tag_str = remote_tag.as_ref();

        validate_call_id(call_id_str)?;
        validate_tag(local_tag_str, "local_tag")?;
        validate_tag(remote_tag_str, "remote_tag")?;

        Ok(Self {
            call_id: SmolStr::new(call_id_str),
            local_tag: SmolStr::new(local_tag_str),
            remote_tag: SmolStr::new(remote_tag_str),
        })
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the local tag.
    pub fn local_tag(&self) -> &str {
        &self.local_tag
    }

    /// Returns the remote tag.
    pub fn remote_tag(&self) -> &str {
        &self.remote_tag
    }

    /// Creates a DialogId for testing without validation (test helper).
    ///
    /// **Warning**: This bypasses validation and should only be used in tests.
    #[cfg(test)]
    pub fn test(
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

    /// Unchecked constructor for use by parser methods and internal construction.
    ///
    /// # Safety (logical)
    ///
    /// This bypasses validation. Callers **must** ensure that the provided values
    /// come from trusted sources (e.g., parsed SIP messages or internal construction).
    /// Do **not** use with untrusted/user-supplied input.
    pub fn unchecked_new(
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
        let call_id = header(req.headers(), "Call-ID")?.clone();
        let from_tag = extract_tag(header(req.headers(), "From")?)?;
        let to_tag = extract_tag(header(req.headers(), "To")?)?;
        Some(Self::unchecked_new(call_id, from_tag, to_tag))
    }

    /// Creates a dialog ID from a response, considering UAC perspective.
    /// For UAC: From tag is local, To tag is remote.
    pub fn from_response_uac(resp: &Response) -> Option<Self> {
        let call_id = header(resp.headers(), "Call-ID")?.clone();
        let from_tag = extract_tag(header(resp.headers(), "From")?)?;
        let to_tag = extract_tag(header(resp.headers(), "To")?)?;
        Some(Self::unchecked_new(call_id, from_tag, to_tag))
    }

    /// Creates a dialog ID from a response, considering UAS perspective.
    /// For UAS: To tag is local, From tag is remote.
    pub fn from_response_uas(resp: &Response) -> Option<Self> {
        let call_id = header(resp.headers(), "Call-ID")?.clone();
        let to_tag = extract_tag(header(resp.headers(), "To")?)?;
        let from_tag = extract_tag(header(resp.headers(), "From")?)?;
        Some(Self::unchecked_new(call_id, to_tag, from_tag))
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
    id: DialogId,

    /// Dialog state
    state: DialogStateType,

    /// Remote target URI (Contact header from remote party)
    remote_target: SipUri,

    /// Route set (from Record-Route headers, stored in reverse order)
    route_set: Vec<SipUri>,

    /// Local CSeq number (incremented for each request we send)
    local_cseq: u32,

    /// Remote CSeq number (tracked from requests we receive)
    remote_cseq: u32,

    /// Last ACK CSeq number (tracked separately to prevent replay)
    last_ack_cseq: Option<u32>,

    /// Local URI (our identity)
    local_uri: SipUri,

    /// Remote URI (their identity)
    remote_uri: SipUri,

    /// Secure flag (true for SIPS)
    secure: bool,

    /// Session timer expiration (RFC 4028)
    session_expires: Option<Duration>,

    /// Session refresher role (uac or uas)
    refresher: Option<RefresherRole>,

    /// Whether we are the UAC (caller) or UAS (callee)
    is_uac: bool,
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
        let state = match resp.code() {
            100..=199 => DialogStateType::Early,
            200..=299 => DialogStateType::Confirmed,
            _ => return None, // No dialog for error responses
        };

        // Extract remote target from Contact header
        let remote_target =
            extract_contact_uri(resp.headers()).or_else(|| Some(remote_uri.clone()))?;

        // Validate URIs
        validate_uri(&local_uri).ok()?;
        validate_uri(&remote_uri).ok()?;
        validate_uri(&remote_target).ok()?;

        // Build route set from Record-Route (stored in reverse for requests)
        // Note: Validation errors are converted to None to maintain Option signature
        let route_set = build_route_set(resp.headers()).ok()?;
        validate_route_set(&route_set).ok()?;

        // Parse CSeq from request
        let local_cseq = parse_cseq_number(req.headers())?;
        validate_cseq(local_cseq).ok()?;
        let remote_cseq = 0; // Will be updated when we receive requests

        // Extract session timer info
        let (session_expires, refresher) = extract_session_timer(resp);
        if let Some(expires) = session_expires {
            validate_session_expires(expires).ok()?;
        }

        // Check if secure before moving URIs
        let secure = local_uri.is_sips() || remote_uri.is_sips();

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

        let state = match resp.code() {
            100..=199 => DialogStateType::Early,
            200..=299 => DialogStateType::Confirmed,
            _ => return None,
        };

        // Extract remote target from Contact in request (caller's contact)
        let remote_target =
            extract_contact_uri(req.headers()).or_else(|| Some(remote_uri.clone()))?;

        // Validate URIs
        validate_uri(&local_uri).ok()?;
        validate_uri(&remote_uri).ok()?;
        validate_uri(&remote_target).ok()?;

        // Build route set from Record-Route (from initial request for UAS)
        // Note: Validation errors are converted to None to maintain Option signature
        let route_set = build_route_set(req.headers()).ok()?;
        validate_route_set(&route_set).ok()?;

        // Parse CSeq from request (this is remote CSeq since they sent it)
        let remote_cseq = parse_cseq_number(req.headers())?;
        validate_cseq(remote_cseq).ok()?;
        let local_cseq = 0; // Will be incremented when we send requests

        let (session_expires, refresher) = extract_session_timer(resp);
        if let Some(expires) = session_expires {
            validate_session_expires(expires).ok()?;
        }

        // Check if secure before moving URIs
        let secure = local_uri.is_sips() || remote_uri.is_sips();

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

    // Accessor methods

    /// Returns a reference to the dialog ID.
    pub fn id(&self) -> &DialogId {
        &self.id
    }

    /// Returns the dialog state.
    pub fn state(&self) -> DialogStateType {
        self.state
    }

    /// Returns a reference to the remote target URI.
    pub fn remote_target(&self) -> &SipUri {
        &self.remote_target
    }

    /// Returns a slice of the route set URIs.
    pub fn route_set(&self) -> &[SipUri] {
        &self.route_set
    }

    /// Returns the current local CSeq value.
    pub fn local_cseq(&self) -> u32 {
        self.local_cseq
    }

    /// Returns the current remote CSeq value.
    pub fn remote_cseq(&self) -> u32 {
        self.remote_cseq
    }

    /// Returns the last ACK CSeq number.
    pub fn last_ack_cseq(&self) -> Option<u32> {
        self.last_ack_cseq
    }

    /// Returns a reference to the local URI.
    pub fn local_uri(&self) -> &SipUri {
        &self.local_uri
    }

    /// Returns a reference to the remote URI.
    pub fn remote_uri(&self) -> &SipUri {
        &self.remote_uri
    }

    /// Returns whether the dialog uses secure (SIPS) transport.
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Returns the session expiration duration.
    pub fn session_expires(&self) -> Option<Duration> {
        self.session_expires
    }

    /// Returns the session refresher role.
    pub fn refresher(&self) -> Option<RefresherRole> {
        self.refresher
    }

    /// Returns whether this dialog is from UAC perspective.
    pub fn is_uac(&self) -> bool {
        self.is_uac
    }

    /// Creates a Dialog without validation.
    ///
    /// # Safety (logical)
    ///
    /// This bypasses validation. Callers **must** ensure that the provided values
    /// come from trusted sources (e.g., parsed SIP messages or internal construction).
    /// Do **not** use with untrusted/user-supplied input.
    #[allow(clippy::too_many_arguments)]
    pub fn unchecked_new(
        id: DialogId,
        state: DialogStateType,
        local_uri: SipUri,
        remote_uri: SipUri,
        remote_target: SipUri,
        local_cseq: u32,
        remote_cseq: u32,
        last_ack_cseq: Option<u32>,
        route_set: Vec<SipUri>,
        secure: bool,
        session_expires: Option<Duration>,
        refresher: Option<RefresherRole>,
        is_uac: bool,
    ) -> Self {
        Self {
            id,
            state,
            local_uri,
            remote_uri,
            remote_target,
            local_cseq,
            remote_cseq,
            last_ack_cseq,
            route_set,
            secure,
            session_expires,
            refresher,
            is_uac,
        }
    }

    /// Sets the session expiration duration with validation.
    ///
    /// # Errors
    ///
    /// Returns `DialogError` if duration is outside allowed bounds.
    pub fn set_session_expires(&mut self, expires: Duration) -> Result<(), DialogError> {
        validate_session_expires(expires)?;
        self.session_expires = Some(expires);
        Ok(())
    }

    // State transition methods

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
    /// Uses saturating arithmetic to prevent overflow at u32::MAX.
    pub fn next_local_cseq(&mut self) -> u32 {
        self.local_cseq = self.local_cseq.saturating_add(1);
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
        if let Some(contact) = extract_contact_uri(resp.headers()) {
            self.remote_target = contact;
        }

        // Update route set if Record-Route present
        if let Ok(new_route_set) = build_route_set(resp.headers()) {
            if !new_route_set.is_empty() {
                self.route_set = new_route_set;
            }
        }

        // Update session timer if present
        let (session_expires, refresher) = extract_session_timer(resp);
        if session_expires.is_some() {
            self.session_expires = session_expires;
            self.refresher = refresher;
        }

        // Confirm early dialog on 2xx
        if resp.code() >= 200 && resp.code() < 300 {
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
        let cseq = parse_cseq_number(req.headers()).ok_or(DialogError::MissingHeader)?;

        // RFC 3261 requires CSeq >= 1
        if cseq == 0 {
            return Err(DialogError::InvalidCSeq);
        }

        if req.method().as_str() == "ACK" {
            // ACK for an INVITE dialog must reuse the INVITE's CSeq.
            if cseq != self.remote_cseq || self.remote_cseq == 0 {
                return Err(DialogError::InvalidCSeq);
            }

            // Allow retransmitted ACKs with identical CSeq.
            self.last_ack_cseq = Some(cseq);
        } else {
            // Non-ACK requests must have strictly increasing CSeq
            validate_cseq(cseq)?;
            if self.remote_cseq > 0 {
                validate_cseq_increment(self.remote_cseq, cseq)?;
            }
            self.remote_cseq = cseq;
        }

        // Update remote target from Contact
        if let Some(contact) = extract_contact_uri(req.headers()) {
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
    /// Inserts a dialog into the manager.
    ///
    /// # Errors
    ///
    /// Returns `DialogError::TooManyDialogs` if the maximum number of dialogs is exceeded.
    pub fn insert(&self, dialog: Dialog) -> Result<(), DialogError> {
        // Security: Enforce maximum dialog limit (DoS prevention)
        if self.dialogs.len() >= MAX_CONFIRMED_DIALOGS {
            return Err(DialogError::TooManyDialogs {
                max: MAX_CONFIRMED_DIALOGS,
            });
        }
        if dialog.state == DialogStateType::Early {
            let early_count = self
                .dialogs
                .iter()
                .filter(|entry| {
                    entry.value().state == DialogStateType::Early
                        && entry.key().call_id == dialog.id.call_id
                        && entry.key() != &dialog.id
                })
                .count();
            if early_count >= MAX_EARLY_DIALOGS_PER_CALL_ID {
                return Err(DialogError::TooManyDialogs {
                    max: MAX_EARLY_DIALOGS_PER_CALL_ID,
                });
            }
        }
        self.dialogs.insert(dialog.id.clone(), dialog);
        self.metrics.record_created();
        Ok(())
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
            let search_id =
                DialogId::unchecked_new(req_id.call_id(), req_id.remote_tag(), req_id.local_tag());
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

    /// Finds a dialog by its SIP Call-ID header value.
    ///
    /// Returns the first dialog whose `DialogId` Call-ID matches the given value.
    /// If multiple dialogs share the same Call-ID (e.g., forking), only the first
    /// found is returned.
    pub fn find_by_call_id(&self, call_id: &str) -> Option<Dialog> {
        self.dialogs
            .iter()
            .find(|entry| entry.key().call_id() == call_id)
            .map(|entry| entry.value().clone())
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

    // Input validation errors
    /// Call-ID validation failed
    InvalidCallId(String),
    /// Tag validation failed
    InvalidTag(String),
    /// URI validation failed
    InvalidUri(String),
    /// Call-ID exceeds maximum length
    CallIdTooLong { max: usize, actual: usize },
    /// Tag exceeds maximum length
    TagTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    /// URI exceeds maximum length
    UriTooLong { max: usize, actual: usize },

    // CSeq validation errors
    /// CSeq value exceeds maximum
    CSeqTooLarge { max: u32, actual: u32 },
    /// CSeq jump exceeds maximum allowed
    CSeqJumpTooLarge { prev: u32, new: u32, max_jump: u32 },
    /// CSeq cannot be zero
    CSeqZero,

    // Collection limit errors
    /// Route set exceeds maximum size
    RouteSetTooLarge { max: usize, actual: usize },
    /// Too many dialogs in manager
    TooManyDialogs { max: usize },

    // Session timer errors
    /// Session expires value too small
    SessionExpiresTooSmall { min: u32, actual: u32 },
    /// Session expires value too large
    SessionExpiresTooLarge { max: u32, actual: u32 },

    // Security errors
    /// Field contains control characters (CRLF injection prevention)
    ContainsControlCharacters { field: &'static str },
}

impl std::fmt::Display for DialogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialogError::InvalidCSeq => write!(f, "Invalid CSeq number"),
            DialogError::NotFound => write!(f, "Dialog not found"),
            DialogError::InvalidState => write!(f, "Invalid dialog state"),
            DialogError::MissingHeader => write!(f, "Missing required header"),
            DialogError::InvalidCallId(msg) => write!(f, "Invalid Call-ID: {}", msg),
            DialogError::InvalidTag(msg) => write!(f, "Invalid tag: {}", msg),
            DialogError::InvalidUri(msg) => write!(f, "Invalid URI: {}", msg),
            DialogError::CallIdTooLong { max, actual } => {
                write!(f, "Call-ID too long: {} bytes (max: {})", actual, max)
            }
            DialogError::TagTooLong { field, max, actual } => {
                write!(f, "{} too long: {} bytes (max: {})", field, actual, max)
            }
            DialogError::UriTooLong { max, actual } => {
                write!(f, "URI too long: {} bytes (max: {})", actual, max)
            }
            DialogError::CSeqTooLarge { max, actual } => {
                write!(f, "CSeq too large: {} (max: {})", actual, max)
            }
            DialogError::CSeqJumpTooLarge {
                prev,
                new,
                max_jump,
            } => write!(
                f,
                "CSeq jump too large: {} -> {} (max jump: {})",
                prev, new, max_jump
            ),
            DialogError::CSeqZero => write!(f, "CSeq cannot be zero"),
            DialogError::RouteSetTooLarge { max, actual } => {
                write!(f, "Route set too large: {} entries (max: {})", actual, max)
            }
            DialogError::TooManyDialogs { max } => {
                write!(f, "Too many dialogs (max: {})", max)
            }
            DialogError::SessionExpiresTooSmall { min, actual } => {
                write!(f, "Session expires too small: {}s (min: {}s)", actual, min)
            }
            DialogError::SessionExpiresTooLarge { max, actual } => {
                write!(f, "Session expires too large: {}s (max: {}s)", actual, max)
            }
            DialogError::ContainsControlCharacters { field } => {
                write!(f, "{} contains control characters", field)
            }
        }
    }
}

impl std::error::Error for DialogError {}

/// Subscription-related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    /// Subscription in invalid state for operation
    InvalidState,
    /// Subscription not found
    NotFound,
    /// Missing required header
    MissingHeader,

    // Input validation errors
    /// Call-ID validation failed
    InvalidCallId(String),
    /// Tag validation failed
    InvalidTag(String),
    /// URI validation failed
    InvalidUri(String),
    /// Call-ID exceeds maximum length
    CallIdTooLong { max: usize, actual: usize },
    /// Tag exceeds maximum length
    TagTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    /// Event value exceeds maximum length
    EventTooLong { max: usize, actual: usize },

    // CSeq validation errors
    /// CSeq value exceeds maximum
    CSeqTooLarge { max: u32, actual: u32 },
    /// CSeq cannot be zero
    CSeqZero,

    // Collection limit errors
    /// Too many subscriptions in manager
    TooManySubscriptions { max: usize },

    // Security errors
    /// Field contains control characters (CRLF injection prevention)
    ContainsControlCharacters { field: &'static str },
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionError::InvalidState => write!(f, "Invalid subscription state"),
            SubscriptionError::NotFound => write!(f, "Subscription not found"),
            SubscriptionError::MissingHeader => write!(f, "Missing required header"),
            SubscriptionError::InvalidCallId(msg) => write!(f, "Invalid Call-ID: {}", msg),
            SubscriptionError::InvalidTag(msg) => write!(f, "Invalid tag: {}", msg),
            SubscriptionError::InvalidUri(msg) => write!(f, "Invalid URI: {}", msg),
            SubscriptionError::CallIdTooLong { max, actual } => {
                write!(f, "Call-ID too long: {} bytes (max: {})", actual, max)
            }
            SubscriptionError::TagTooLong { field, max, actual } => {
                write!(f, "{} too long: {} bytes (max: {})", field, actual, max)
            }
            SubscriptionError::EventTooLong { max, actual } => {
                write!(f, "Event value too long: {} bytes (max: {})", actual, max)
            }
            SubscriptionError::CSeqTooLarge { max, actual } => {
                write!(f, "CSeq too large: {} (max: {})", actual, max)
            }
            SubscriptionError::CSeqZero => write!(f, "CSeq cannot be zero"),
            SubscriptionError::TooManySubscriptions { max } => {
                write!(f, "Too many subscriptions (max: {})", max)
            }
            SubscriptionError::ContainsControlCharacters { field } => {
                write!(f, "{} contains control characters", field)
            }
        }
    }
}

impl std::error::Error for SubscriptionError {}

// Validation functions

/// Validates Call-ID for length and control characters.
fn validate_call_id(call_id: &str) -> Result<(), DialogError> {
    if call_id.is_empty() {
        return Err(DialogError::InvalidCallId("empty".to_string()));
    }
    if call_id.len() > MAX_CALL_ID_LENGTH {
        return Err(DialogError::CallIdTooLong {
            max: MAX_CALL_ID_LENGTH,
            actual: call_id.len(),
        });
    }
    if call_id.chars().any(|c| c.is_control()) {
        return Err(DialogError::ContainsControlCharacters { field: "call_id" });
    }
    Ok(())
}

/// Validates tag for length and control characters.
fn validate_tag(tag: &str, field: &'static str) -> Result<(), DialogError> {
    if tag.is_empty() {
        return Err(DialogError::InvalidTag(format!("{} is empty", field)));
    }
    if tag.len() > MAX_TAG_LENGTH {
        return Err(DialogError::TagTooLong {
            field,
            max: MAX_TAG_LENGTH,
            actual: tag.len(),
        });
    }
    if tag.chars().any(|c| c.is_control()) {
        return Err(DialogError::ContainsControlCharacters { field });
    }
    Ok(())
}

/// Validates SIP URI for length.
fn validate_uri(uri: &SipUri) -> Result<(), DialogError> {
    // Estimate URI length from components (conservative approach)
    let estimated_len = uri.user().map(|u| u.len()).unwrap_or(0)
        + uri.host().len()
        + uri.port().map(|_| 6).unwrap_or(0) // ":65535"
        + 10; // "sip:" or "sips:" + overhead

    if estimated_len > MAX_URI_LENGTH {
        return Err(DialogError::UriTooLong {
            max: MAX_URI_LENGTH,
            actual: estimated_len,
        });
    }
    Ok(())
}

/// Validates CSeq value is non-zero and within bounds.
fn validate_cseq(cseq: u32) -> Result<(), DialogError> {
    if cseq == 0 {
        return Err(DialogError::CSeqZero);
    }
    if cseq > MAX_CSEQ_VALUE {
        return Err(DialogError::CSeqTooLarge {
            max: MAX_CSEQ_VALUE,
            actual: cseq,
        });
    }
    Ok(())
}

/// Validates CSeq increment is monotonic and not excessive.
fn validate_cseq_increment(prev: u32, new: u32) -> Result<(), DialogError> {
    if new <= prev {
        return Err(DialogError::InvalidCSeq);
    }
    let jump = new.saturating_sub(prev);
    if jump > MAX_CSEQ_JUMP {
        return Err(DialogError::CSeqJumpTooLarge {
            prev,
            new,
            max_jump: MAX_CSEQ_JUMP,
        });
    }
    Ok(())
}

/// Validates session expires duration is within bounds.
fn validate_session_expires(duration: Duration) -> Result<(), DialogError> {
    let secs = duration.as_secs() as u32;
    if secs < MIN_SESSION_EXPIRES {
        return Err(DialogError::SessionExpiresTooSmall {
            min: MIN_SESSION_EXPIRES,
            actual: secs,
        });
    }
    if secs > MAX_SESSION_EXPIRES {
        return Err(DialogError::SessionExpiresTooLarge {
            max: MAX_SESSION_EXPIRES,
            actual: secs,
        });
    }
    Ok(())
}

/// Validates route set size and each URI.
fn validate_route_set(route_set: &[SipUri]) -> Result<(), DialogError> {
    if route_set.len() > MAX_ROUTE_SET_SIZE {
        return Err(DialogError::RouteSetTooLarge {
            max: MAX_ROUTE_SET_SIZE,
            actual: route_set.len(),
        });
    }
    for uri in route_set {
        validate_uri(uri)?;
    }
    Ok(())
}

/// Validates event package name for subscriptions.
fn validate_event_package(event: &str) -> Result<(), SubscriptionError> {
    let mut parts = event.split(';');
    let event_package = parts.next().unwrap_or_default().trim();
    if event_package.is_empty() {
        return Err(SubscriptionError::InvalidCallId(
            "event package empty".to_string(),
        ));
    }
    if event_package.len() > MAX_EVENT_PACKAGE_LENGTH {
        return Err(SubscriptionError::EventTooLong {
            max: MAX_EVENT_PACKAGE_LENGTH,
            actual: event_package.len(),
        });
    }
    if event_package.chars().any(|c| c.is_control()) {
        return Err(SubscriptionError::ContainsControlCharacters {
            field: "event_package",
        });
    }
    for param in parts {
        let trimmed = param.trim();
        if trimmed.len() >= 3 && trimmed[..3].eq_ignore_ascii_case("id=") {
            let id = trimmed[3..].trim().trim_matches('"');
            if id.len() > MAX_EVENT_ID_LENGTH {
                return Err(SubscriptionError::EventTooLong {
                    max: MAX_EVENT_ID_LENGTH,
                    actual: id.len(),
                });
            }
            if id.chars().any(|c| c.is_control()) {
                return Err(SubscriptionError::ContainsControlCharacters { field: "event_id" });
            }
        }
    }
    Ok(())
}

/// Validates Call-ID for subscriptions.
fn validate_subscription_call_id(call_id: &str) -> Result<(), SubscriptionError> {
    if call_id.is_empty() {
        return Err(SubscriptionError::InvalidCallId("empty".to_string()));
    }
    if call_id.len() > MAX_CALL_ID_LENGTH {
        return Err(SubscriptionError::CallIdTooLong {
            max: MAX_CALL_ID_LENGTH,
            actual: call_id.len(),
        });
    }
    if call_id.chars().any(|c| c.is_control()) {
        return Err(SubscriptionError::ContainsControlCharacters { field: "call_id" });
    }
    Ok(())
}

/// Validates tag for subscriptions.
fn validate_subscription_tag(tag: &str, field: &'static str) -> Result<(), SubscriptionError> {
    if tag.is_empty() {
        return Err(SubscriptionError::InvalidTag(format!("{} is empty", field)));
    }
    if tag.len() > MAX_TAG_LENGTH {
        return Err(SubscriptionError::TagTooLong {
            field,
            max: MAX_TAG_LENGTH,
            actual: tag.len(),
        });
    }
    if tag.chars().any(|c| c.is_control()) {
        return Err(SubscriptionError::ContainsControlCharacters { field });
    }
    Ok(())
}

/// Validates CSeq for subscriptions.
fn validate_subscription_cseq(cseq: u32) -> Result<(), SubscriptionError> {
    if cseq == 0 {
        return Err(SubscriptionError::CSeqZero);
    }
    if cseq > MAX_CSEQ_VALUE {
        return Err(SubscriptionError::CSeqTooLarge {
            max: MAX_CSEQ_VALUE,
            actual: cseq,
        });
    }
    Ok(())
}

// Helper functions

/// Extracts tag parameter from From/To header value.
fn extract_tag(value: &SmolStr) -> Option<SmolStr> {
    value.split(';').find_map(|segment| {
        let trimmed = segment.trim();
        if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("tag=") {
            Some(SmolStr::new(&trimmed[4..]))
        } else {
            None
        }
    })
}

/// Builds route set from Record-Route headers (reversed for UAC).
fn build_route_set(headers: &Headers) -> Result<Vec<SipUri>, DialogError> {
    let mut routes: Vec<SipUri> = Vec::new();

    for value in headers.get_all_smol("Record-Route") {
        for uri_str in split_header_values(value.as_str()) {
            // Security: Enforce route set size limit (DoS prevention)
            if routes.len() >= MAX_ROUTE_SET_SIZE {
                return Err(DialogError::RouteSetTooLarge {
                    max: MAX_ROUTE_SET_SIZE,
                    actual: routes.len() + 1,
                });
            }

            if let Some(uri) = parse_uri_from_header(uri_str.as_str()) {
                // Validate URI length
                validate_uri(&uri)?;
                routes.push(uri);
            }
        }
    }

    // Reverse for proper routing
    routes.reverse();
    Ok(routes)
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
    if let Some(se_header) = header(resp.headers(), "Session-Expires") {
        if let Some(se) = parse_session_expires(se_header) {
            return (
                Some(Duration::from_secs(se.delta_seconds() as u64)),
                se.refresher(),
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
    SipUri::parse(uri_part.trim()).ok()
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
                angle_depth = angle_depth.saturating_sub(1);
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
    call_id: SmolStr,
    from_tag: SmolStr,
    to_tag: SmolStr,
    event: SmolStr,
}

impl SubscriptionId {
    /// Creates a new SubscriptionId with validation.
    ///
    /// # Errors
    ///
    /// Returns `SubscriptionError` if any field exceeds maximum length or contains control characters.
    pub fn new(
        call_id: impl AsRef<str>,
        from_tag: impl AsRef<str>,
        to_tag: impl AsRef<str>,
        event: impl AsRef<str>,
    ) -> Result<Self, SubscriptionError> {
        let call_id_str = call_id.as_ref();
        let from_tag_str = from_tag.as_ref();
        let to_tag_str = to_tag.as_ref();
        let event_str = event.as_ref();

        validate_subscription_call_id(call_id_str)?;
        validate_subscription_tag(from_tag_str, "from_tag")?;
        validate_subscription_tag(to_tag_str, "to_tag")?;
        validate_event_package(event_str)?;

        Ok(Self {
            call_id: SmolStr::new(call_id_str),
            from_tag: SmolStr::new(from_tag_str),
            to_tag: SmolStr::new(to_tag_str),
            event: SmolStr::new(event_str),
        })
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the From tag.
    pub fn from_tag(&self) -> &str {
        &self.from_tag
    }

    /// Returns the To tag.
    pub fn to_tag(&self) -> &str {
        &self.to_tag
    }

    /// Returns the event package name.
    pub fn event(&self) -> &str {
        &self.event
    }

    /// Creates a SubscriptionId for testing without validation (test helper).
    ///
    /// **Warning**: This bypasses validation and should only be used in tests.
    #[cfg(test)]
    pub fn test(
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

    /// Unchecked constructor for use by parser methods and internal construction.
    ///
    /// **Warning**: This bypasses validation and should only be used when values are already trusted
    /// (e.g., from parsed SIP messages or internal construction).
    pub fn unchecked_new(
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
        let call_id = header(req.headers(), "Call-ID")?.clone();
        let from_tag = extract_tag(header(req.headers(), "From")?)?;
        let to_tag = extract_tag(header(req.headers(), "To")?)?;
        let event = header(req.headers(), "Event")?.clone();
        Some(Self::unchecked_new(call_id, from_tag, to_tag, event))
    }

    /// Creates a subscription ID from request and response (notifier perspective).
    /// Uses From tag from request and To tag from response.
    pub fn from_request_response(req: &Request, resp: &Response) -> Option<Self> {
        let call_id = header(req.headers(), "Call-ID")?.clone();
        let from_tag = extract_tag(header(req.headers(), "From")?)?;
        let to_tag = extract_tag(header(resp.headers(), "To")?)?;
        let event = header(req.headers(), "Event")?.clone();
        Some(Self::unchecked_new(call_id, from_tag, to_tag, event))
    }
}

/// Represents an active subscription (RFC 3265).
#[derive(Debug, Clone)]
pub struct Subscription {
    id: SubscriptionId,
    state: SubscriptionState,
    local_uri: SipUri,
    remote_uri: SipUri,
    contact: SipUri,
    expires: Duration,
    local_cseq: u32,
    remote_cseq: u32,
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
        let contact = extract_contact_uri(response.headers())?;
        let local_cseq = parse_cseq_number(request.headers())?;
        validate_subscription_cseq(local_cseq).ok()?;

        // Parse expires from response or request
        let expires = if let Some(exp_str) = header(response.headers(), "Expires") {
            Duration::from_secs(exp_str.parse().ok()?)
        } else if let Some(exp_str) = header(request.headers(), "Expires") {
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
        let contact = extract_contact_uri(response.headers())?;
        let remote_cseq = 0;
        let local_cseq = parse_cseq_number(request.headers())?;
        validate_subscription_cseq(local_cseq).ok()?;

        // Parse expires from response
        let expires = if let Some(exp_str) = header(response.headers(), "Expires") {
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

    // Accessor methods

    /// Returns a reference to the subscription ID.
    pub fn id(&self) -> &SubscriptionId {
        &self.id
    }

    /// Returns the subscription state.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// Returns a reference to the local URI.
    pub fn local_uri(&self) -> &SipUri {
        &self.local_uri
    }

    /// Returns a reference to the remote URI.
    pub fn remote_uri(&self) -> &SipUri {
        &self.remote_uri
    }

    /// Returns a reference to the contact URI.
    pub fn contact(&self) -> &SipUri {
        &self.contact
    }

    /// Returns the expiration duration.
    pub fn expires(&self) -> Duration {
        self.expires
    }

    /// Returns the current local CSeq value.
    pub fn local_cseq(&self) -> u32 {
        self.local_cseq
    }

    /// Returns the current remote CSeq value.
    pub fn remote_cseq(&self) -> u32 {
        self.remote_cseq
    }

    /// Creates a Subscription without validation.
    ///
    /// **Warning**: This bypasses validation and should only be used when values are already trusted
    /// (e.g., from parsed SIP messages or internal construction).
    pub fn unchecked_new(
        id: SubscriptionId,
        state: SubscriptionState,
        local_uri: SipUri,
        remote_uri: SipUri,
        contact: SipUri,
        expires: Duration,
        local_cseq: u32,
        remote_cseq: u32,
    ) -> Self {
        Self {
            id,
            state,
            local_uri,
            remote_uri,
            contact,
            expires,
            local_cseq,
            remote_cseq,
        }
    }

    // Mutation methods

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
    ///
    /// # Errors
    ///
    /// Returns `SubscriptionError::TooManySubscriptions` if the maximum number is exceeded.
    pub fn insert(&self, subscription: Subscription) -> Result<(), SubscriptionError> {
        // Security: Enforce maximum subscription limit (DoS prevention)
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return Err(SubscriptionError::TooManySubscriptions {
                max: MAX_SUBSCRIPTIONS,
            });
        }
        self.subscriptions
            .insert(subscription.id.clone(), subscription);
        Ok(())
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
        *self
            .sequences
            .entry(dialog_id.clone())
            .and_modify(|rseq| *rseq = rseq.saturating_add(1))
            .or_insert(1)
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
        headers
            .push(SmolStr::new("Call-ID"), SmolStr::new(call_id.to_owned()))
            .unwrap();
        headers
            .push(
                SmolStr::new("From"),
                SmolStr::new(format!("<sip:alice@example.com>;tag={}", from_tag)),
            )
            .unwrap();
        if let Some(tag) = to_tag {
            headers
                .push(
                    SmolStr::new("To"),
                    SmolStr::new(format!("<sip:bob@example.com>;tag={}", tag)),
                )
                .unwrap();
        } else {
            headers
                .push(
                    SmolStr::new("To"),
                    SmolStr::new("<sip:bob@example.com>".to_owned()),
                )
                .unwrap();
        }
        headers
            .push(
                SmolStr::new("CSeq"),
                SmolStr::new(format!("{} {}", cseq, method.as_str())),
            )
            .unwrap();
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:alice@client.example.com>".to_owned()),
            )
            .unwrap();

        Request::new(
            RequestLine::new(method, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            bytes::Bytes::new(),
        )
        .expect("valid request")
    }

    fn make_response(code: u16, req: &Request, to_tag: &str) -> Response {
        let mut headers = Headers::new();

        // Copy all headers from request except To
        for header in req.headers().iter() {
            if header.name() != "To" {
                headers
                    .push(header.name_smol().clone(), header.value_smol().clone())
                    .unwrap();
            }
        }

        // Add To header with tag
        headers
            .push(
                SmolStr::new("To"),
                SmolStr::new(format!("<sip:bob@example.com>;tag={}", to_tag)),
            )
            .unwrap();

        // Add Contact header
        headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:bob@server.example.com>".to_owned()),
            )
            .unwrap();

        Response::new(
            StatusLine::new(code, SmolStr::new("OK")).expect("valid status line"),
            headers,
            bytes::Bytes::new(),
        )
        .expect("valid response")
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
        manager.insert(dialog.clone()).unwrap();
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

        manager.insert(dialog1).unwrap();
        manager.insert(dialog2).unwrap();

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
        for header in make_response(200, &reinvite_req, "uas-tag")
            .headers()
            .iter()
        {
            if header.name() != "Contact" {
                reinvite_resp_headers
                    .push(header.name_smol().clone(), header.value_smol().clone())
                    .unwrap();
            }
        }

        // Add new Contact header
        reinvite_resp_headers
            .push(
                SmolStr::new("Contact"),
                SmolStr::new("<sip:bob@newserver.example.com>".to_owned()),
            )
            .unwrap();

        let reinvite_resp = Response::new(
            StatusLine::new(200, SmolStr::new("OK")).expect("valid status line"),
            reinvite_resp_headers,
            bytes::Bytes::new(),
        )
        .expect("valid response");

        dialog.update_from_response(&reinvite_resp);

        assert_ne!(dialog.remote_target, original_target);
        assert_eq!(dialog.remote_target.host(), "newserver.example.com");
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
        assert_eq!(uri.host(), "example.com");

        let uri2 = parse_uri_from_header("  <sip:alice@test.com:5060>  ").unwrap();
        assert_eq!(uri2.host(), "test.com");
        assert_eq!(uri2.port(), Some(5060));
    }

    #[test]
    fn parse_uri_without_angle_brackets() {
        let uri = parse_uri_from_header("sip:bob@example.com").unwrap();
        assert_eq!(uri.host(), "example.com");
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
