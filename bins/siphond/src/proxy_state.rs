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
use tokio::sync::mpsc;

/// Information about a proxied transaction
#[derive(Clone, Debug)]
pub struct ProxyTransaction {
    /// Branch ID we added in our Via header
    pub branch: String,

    /// Original sender's address (where to forward responses)
    #[allow(dead_code)]
    pub sender_addr: SocketAddr,

    /// Transport to use for response
    #[allow(dead_code)]
    pub sender_transport: TransportKind,

    /// Optional stream writer for connection-oriented transports
    #[allow(dead_code)]
    pub sender_stream: Option<mpsc::Sender<bytes::Bytes>>,

    /// Optional WS/WSS target URI
    #[allow(dead_code)]
    pub sender_ws_uri: Option<String>,

    /// Call-ID for logging
    #[allow(dead_code)]
    pub call_id: String,

    /// When this transaction was created
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn find_transaction(&self, branch: &str) -> Option<ProxyTransaction> {
        self.transactions.get(branch).map(|entry| entry.clone())
    }

    /// Remove a transaction (after final response)
    #[allow(dead_code)]
    pub fn remove_transaction(&self, branch: &str) {
        self.transactions.remove(branch);
    }

    /// Clean up old transactions (older than 5 minutes)
    #[allow(dead_code)]
    pub fn cleanup_old(&self, max_age: Duration) {
        let now = Instant::now();
        self.transactions
            .retain(|_, tx| now.duration_since(tx.created_at) < max_age);
    }

    /// Get count of active transactions
    #[allow(dead_code)]
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
#[allow(dead_code)]
pub type SharedProxyState = Arc<ProxyStateManager>;
