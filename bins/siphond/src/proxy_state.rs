/// Proxy transaction state tracking.
///
/// Tracks proxy transactions to enable response forwarding:
/// - Maps branch IDs to original sender addresses
/// - Correlates responses with forwarded requests
/// - Enables stateful proxy behavior

use dashmap::DashMap;
use sip_transaction::TransportKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Information about a proxied transaction
#[derive(Clone, Debug)]
pub struct ProxyTransaction {
    /// Branch ID we added in our Via header
    pub branch: String,

    /// Original sender's address (where to forward responses)
    pub sender_addr: SocketAddr,

    /// Transport to use for response
    pub sender_transport: TransportKind,

    /// Call-ID for logging
    pub call_id: String,

    /// When this transaction was created
    pub created_at: Instant,
}

/// Proxy state manager for tracking transactions
pub struct ProxyStateManager {
    /// Map branch ID → transaction info
    transactions: DashMap<String, ProxyTransaction>,
}

impl ProxyStateManager {
    /// Create a new proxy state manager
    pub fn new() -> Self {
        Self {
            transactions: DashMap::new(),
        }
    }

    /// Store a proxy transaction for response correlation
    pub fn store_transaction(&self, tx: ProxyTransaction) {
        self.transactions.insert(tx.branch.clone(), tx);
    }

    /// Look up a transaction by branch ID
    pub fn find_transaction(&self, branch: &str) -> Option<ProxyTransaction> {
        self.transactions.get(branch).map(|entry| entry.clone())
    }

    /// Remove a transaction (after final response)
    pub fn remove_transaction(&self, branch: &str) {
        self.transactions.remove(branch);
    }

    /// Clean up old transactions (older than 5 minutes)
    pub fn cleanup_old(&self, max_age: Duration) {
        let now = Instant::now();
        self.transactions.retain(|_, tx| {
            now.duration_since(tx.created_at) < max_age
        });
    }

    /// Get count of active transactions
    pub fn count(&self) -> usize {
        self.transactions.len()
    }
}

impl Default for ProxyStateManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared proxy state (can be cloned cheaply)
pub type SharedProxyState = Arc<ProxyStateManager>;
