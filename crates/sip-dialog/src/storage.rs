use crate::{Dialog, DialogId};
use async_trait::async_trait;
use smol_str::SmolStr;

/// Dialog storage backend trait. Default impl is in-memory; apps can plug their own (Redis, DB).
#[async_trait]
pub trait DialogStore: Send + Sync + 'static {
    async fn get(&self, id: &DialogId) -> Option<Dialog>;
    async fn put(&self, dialog: Dialog);
    async fn remove(&self, id: &DialogId);
    async fn list_by_call_id(&self, call_id: &SmolStr) -> Vec<Dialog>;
}

/// In-memory dialog store (default).
#[derive(Default)]
pub struct InMemoryDialogStore {
    inner: dashmap::DashMap<DialogId, Dialog>,
}

#[async_trait]
impl DialogStore for InMemoryDialogStore {
    async fn get(&self, id: &DialogId) -> Option<Dialog> {
        self.inner.get(id).map(|d| d.clone())
    }

    async fn put(&self, dialog: Dialog) {
        self.inner.insert(dialog.id.clone(), dialog);
    }

    async fn remove(&self, id: &DialogId) {
        self.inner.remove(id);
    }

    async fn list_by_call_id(&self, call_id: &SmolStr) -> Vec<Dialog> {
        self.inner
            .iter()
            .filter(|d| d.key().call_id == *call_id)
            .map(|d| d.value().clone())
            .collect()
    }
}
