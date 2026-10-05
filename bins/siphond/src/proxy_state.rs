// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

/// An INVITE this proxy forwarded and has not seen finish: what a CANCEL
/// for it is built from and where it goes (RFC 3261 §16.10).
#[derive(Clone, Debug)]
pub struct ForwardedInvite {
    /// The INVITE as sent, with this proxy's Via on top.
    pub request: sip_core::Request,
    pub target: SocketAddr,
    pub transport: TransportKind,
    /// The host a TLS connection names.
    pub host: String,
    pub created_at: Instant,
}

/// Proxy state manager for tracking transactions
pub struct ProxyStateManager {
    /// Map branch ID → transaction info
    transactions: DashMap<String, ProxyTransaction>,
    /// The caller's branch → the INVITE forwarded for it.
    forwarded_invites: DashMap<String, ForwardedInvite>,
}

impl ProxyStateManager {
    /// Create a new proxy state manager
    pub fn new() -> Self {
        Self {
            transactions: DashMap::new(),
            forwarded_invites: DashMap::new(),
        }
    }

    /// Store a proxy transaction for response correlation
    pub fn store_transaction(&self, tx: ProxyTransaction) {
        self.transactions.insert(tx.branch.clone(), tx);
    }

    /// Remember an INVITE forwarded for the caller's `branch`.
    pub fn store_forwarded_invite(&self, branch: String, invite: ForwardedInvite) {
        self.forwarded_invites.insert(branch, invite);
    }

    /// The INVITE forwarded for the caller's `branch`, once.
    pub fn take_forwarded_invite(&self, branch: &str) -> Option<ForwardedInvite> {
        self.forwarded_invites
            .remove(branch)
            .map(|(_, invite)| invite)
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
        self.forwarded_invites
            .retain(|_, invite| invite.created_at.elapsed() < max_age);
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
