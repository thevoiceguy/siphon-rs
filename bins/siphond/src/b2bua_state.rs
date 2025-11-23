/// B2BUA call leg state management.
///
/// Tracks both call legs (UAC and UAS) to enable response bridging:
/// - Maps outgoing Call-IDs to incoming transaction handles
/// - Correlates responses from callee with caller's transaction
/// - Enables proper B2BUA behavior with response relay

use dashmap::DashMap;
use sip_core::Response;
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

    /// From URI of the caller
    #[allow(dead_code)]
    pub caller_uri: String,

    /// To URI of the callee
    #[allow(dead_code)]
    pub callee_uri: String,

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
        self.call_legs.get(outgoing_call_id).map(|entry| entry.clone())
    }

    /// Remove a call leg pair (after final response)
    pub fn remove_call_leg(&self, outgoing_call_id: &str) {
        self.call_legs.remove(outgoing_call_id);
    }

    /// Clean up old call legs (older than 5 minutes)
    #[allow(dead_code)]
    pub fn cleanup_old(&self, max_age: Duration) {
        let now = Instant::now();
        self.call_legs.retain(|_, pair| {
            now.duration_since(pair.created_at) < max_age
        });
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
