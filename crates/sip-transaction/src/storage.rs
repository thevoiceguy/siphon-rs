use crate::{ClientTransactionState, ServerTransactionState, TransactionKey, TransportContext};
use async_trait::async_trait;

/// Persisted client transaction snapshot (minimal fields for reconstruction).
#[derive(Debug, Clone)]
pub struct ClientTransactionRecord {
    pub key: TransactionKey,
    pub state: ClientTransactionState,
    pub ctx: TransportContext,
}

/// Persisted server transaction snapshot (minimal fields for reconstruction).
#[derive(Debug, Clone)]
pub struct ServerTransactionRecord {
    pub key: TransactionKey,
    pub state: ServerTransactionState,
    pub ctx: TransportContext,
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
        self.client.insert(record.key.clone(), record);
    }

    async fn get_client(&self, key: &TransactionKey) -> Option<ClientTransactionRecord> {
        self.client.get(key).map(|r| r.clone())
    }

    async fn remove_client(&self, key: &TransactionKey) {
        self.client.remove(key);
    }

    async fn put_server(&self, record: ServerTransactionRecord) {
        self.server.insert(record.key.clone(), record);
    }

    async fn get_server(&self, key: &TransactionKey) -> Option<ServerTransactionRecord> {
        self.server.get(key).map(|r| r.clone())
    }

    async fn remove_server(&self, key: &TransactionKey) {
        self.server.remove(key);
    }
}
