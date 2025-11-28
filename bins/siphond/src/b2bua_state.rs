/// B2BUA call leg state management.
///
/// Tracks both call legs (UAC and UAS) to enable response bridging:
/// - Maps outgoing Call-IDs to incoming transaction handles
/// - Correlates responses from callee with caller's transaction
/// - Enables proper B2BUA behavior with response relay
use dashmap::DashMap;
use sip_core::{Request, Response, SipUri};
use sip_dialog::{Dialog, DialogId};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Information about a B2BUA call leg pair
#[derive(Clone)]
pub struct CallLegPair {
    /// Call-ID of the outgoing leg (to callee)
    pub outgoing_call_id: String,

    /// Channel sender to relay responses back to caller's transaction
    pub response_tx: mpsc::UnboundedSender<Response>,

    /// Call-ID of the incoming leg (from caller)
    pub incoming_call_id: String,

    /// Caller's original request (for constructing matching responses)
    pub caller_request: Request,

    /// Outgoing INVITE request to callee (for constructing ACK)
    pub outgoing_invite: Request,

    /// Callee's contact URI (for sending ACK and BYE)
    pub callee_contact: SipUri,

    /// To-tag from callee (extracted from 200 OK To header)
    pub callee_to_tag: Option<String>,

    /// UAS dialog (Bob → B2BUA)
    pub uas_dialog: Option<Dialog>,

    /// UAC dialog (B2BUA → Alice)
    pub uac_dialog: Option<Dialog>,

    /// When this call leg pair was created
    #[allow(dead_code)]
    pub created_at: Instant,
}

/// B2BUA state manager for tracking call leg pairs
pub struct B2BUAStateManager {
    /// Map outgoing Call-ID → call leg pair
    call_legs: DashMap<String, CallLegPair>,
}

impl B2BUAStateManager {
    /// Create a new B2BUA state manager
    pub fn new() -> Self {
        Self {
            call_legs: DashMap::new(),
        }
    }

    /// Store a call leg pair for response bridging
    pub fn store_call_leg(&self, pair: CallLegPair) {
        self.call_legs.insert(pair.outgoing_call_id.clone(), pair);
    }

    /// Look up a call leg pair by outgoing Call-ID
    pub fn find_call_leg(&self, outgoing_call_id: &str) -> Option<CallLegPair> {
        self.call_legs
            .get(outgoing_call_id)
            .map(|entry| entry.clone())
    }

    /// Look up a call leg pair by incoming Call-ID (caller's Call-ID)
    /// Used for ACK and BYE bridging from caller to callee
    pub fn find_call_leg_by_incoming(&self, incoming_call_id: &str) -> Option<CallLegPair> {
        self.call_legs
            .iter()
            .find(|entry| entry.value().incoming_call_id == incoming_call_id)
            .map(|entry| entry.value().clone())
    }

    /// Remove a call leg pair (after final response)
    pub fn remove_call_leg(&self, outgoing_call_id: &str) {
        self.call_legs.remove(outgoing_call_id);
    }

    /// Update the callee's To-tag (after receiving 200 OK from callee)
    pub fn update_callee_to_tag(&self, outgoing_call_id: &str, to_tag: String) {
        if let Some(mut pair) = self.call_legs.get_mut(outgoing_call_id) {
            pair.callee_to_tag = Some(to_tag);
        }
    }

    /// Update the UAS dialog (Bob → B2BUA)
    pub fn update_uas_dialog(&self, outgoing_call_id: &str, dialog: Dialog) {
        if let Some(mut pair) = self.call_legs.get_mut(outgoing_call_id) {
            pair.uas_dialog = Some(dialog);
        }
    }

    /// Update the UAC dialog (B2BUA → Alice)
    pub fn update_uac_dialog(&self, outgoing_call_id: &str, dialog: Dialog) {
        if let Some(mut pair) = self.call_legs.get_mut(outgoing_call_id) {
            pair.uac_dialog = Some(dialog);
        }
    }

    /// Find call leg by UAC dialog ID (for in-dialog requests from Alice)
    pub fn find_by_uac_dialog(&self, dialog_id: &DialogId) -> Option<CallLegPair> {
        self.call_legs
            .iter()
            .find(|entry| {
                if let Some(ref uac_dialog) = entry.value().uac_dialog {
                    &uac_dialog.id == dialog_id
                } else {
                    false
                }
            })
            .map(|entry| entry.value().clone())
    }

    /// Find call leg by UAS dialog ID (for in-dialog requests from Bob)
    pub fn find_by_uas_dialog(&self, dialog_id: &DialogId) -> Option<CallLegPair> {
        self.call_legs
            .iter()
            .find(|entry| {
                if let Some(ref uas_dialog) = entry.value().uas_dialog {
                    &uas_dialog.id == dialog_id
                } else {
                    false
                }
            })
            .map(|entry| entry.value().clone())
    }

    /// Clean up old call legs (older than 5 minutes)
    #[allow(dead_code)]
    pub fn cleanup_old(&self, max_age: Duration) {
        let now = Instant::now();
        self.call_legs
            .retain(|_, pair| now.duration_since(pair.created_at) < max_age);
    }

    /// Get count of active call leg pairs
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.call_legs.len()
    }
}

impl Default for B2BUAStateManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared B2BUA state (can be cloned cheaply)
#[allow(dead_code)]
pub type SharedB2BUAState = Arc<B2BUAStateManager>;
