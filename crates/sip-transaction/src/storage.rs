// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{ClientTransactionState, ServerTransactionState, TransactionKey, TransportContext};
use async_trait::async_trait;

/// Persisted client transaction snapshot (minimal fields for reconstruction).
/// Fields are private to protect transaction state.
#[derive(Debug, Clone)]
pub struct ClientTransactionRecord {
    key: TransactionKey,
    state: ClientTransactionState,
    ctx: TransportContext,
}

impl ClientTransactionRecord {
    /// Creates a new client transaction record.
    pub fn new(key: TransactionKey, state: ClientTransactionState, ctx: TransportContext) -> Self {
        Self { key, state, ctx }
    }

    /// Returns the transaction key.
    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns the transaction state.
    pub fn state(&self) -> ClientTransactionState {
        self.state
    }

    /// Returns the transport context.
    pub fn ctx(&self) -> &TransportContext {
        &self.ctx
    }
}

/// Persisted server transaction snapshot (minimal fields for reconstruction).
/// Fields are private to protect transaction state.
#[derive(Debug, Clone)]
pub struct ServerTransactionRecord {
    key: TransactionKey,
    state: ServerTransactionState,
    ctx: TransportContext,
}

impl ServerTransactionRecord {
    /// Creates a new server transaction record.
    pub fn new(key: TransactionKey, state: ServerTransactionState, ctx: TransportContext) -> Self {
        Self { key, state, ctx }
    }

    /// Returns the transaction key.
    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns the transaction state.
    pub fn state(&self) -> ServerTransactionState {
        self.state
    }

    /// Returns the transport context.
    pub fn ctx(&self) -> &TransportContext {
        &self.ctx
    }
}

/// Transaction store trait. Default implementation is in-memory; apps can plug their own backend.
#[async_trait]
pub trait TransactionStore: Send + Sync + 'static {
    async fn put_client(&self, record: ClientTransactionRecord);
    async fn get_client(&self, key: &TransactionKey) -> Option<ClientTransactionRecord>;
    async fn remove_client(&self, key: &TransactionKey);

    async fn put_server(&self, record: ServerTransactionRecord);
    async fn get_server(&self, key: &TransactionKey) -> Option<ServerTransactionRecord>;
    async fn remove_server(&self, key: &TransactionKey);
}

/// In-memory transaction store (default).
#[derive(Default)]
pub struct InMemoryTransactionStore {
    client: dashmap::DashMap<TransactionKey, ClientTransactionRecord>,
    server: dashmap::DashMap<TransactionKey, ServerTransactionRecord>,
}

#[async_trait]
impl TransactionStore for InMemoryTransactionStore {
    async fn put_client(&self, record: ClientTransactionRecord) {
        self.client.insert(record.key().clone(), record);
    }

    async fn get_client(&self, key: &TransactionKey) -> Option<ClientTransactionRecord> {
        self.client.get(key).map(|r| r.clone())
    }

    async fn remove_client(&self, key: &TransactionKey) {
        self.client.remove(key);
    }

    async fn put_server(&self, record: ServerTransactionRecord) {
        self.server.insert(record.key().clone(), record);
    }

    async fn get_server(&self, key: &TransactionKey) -> Option<ServerTransactionRecord> {
        self.server.get(key).map(|r| r.clone())
    }

    async fn remove_server(&self, key: &TransactionKey) {
        self.server.remove(key);
    }
}
