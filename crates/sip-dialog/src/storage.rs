// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{Dialog, DialogId};
use async_trait::async_trait;
use smol_str::SmolStr;

/// Maximum number of dialogs in the in-memory store to prevent memory exhaustion.
const MAX_DIALOGS: usize = 100_000;

/// Dialog storage backend trait. Default impl is in-memory; apps can plug their own (Redis, DB).
#[async_trait]
pub trait DialogStore: Send + Sync + 'static {
    async fn get(&self, id: &DialogId) -> Option<Dialog>;
    async fn put(&self, dialog: Dialog);
    async fn remove(&self, id: &DialogId);
    async fn list_by_call_id(&self, call_id: &SmolStr) -> Vec<Dialog>;
    /// Returns the number of stored dialogs.
    async fn len(&self) -> usize;
    /// Returns true if the store is empty.
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// In-memory dialog store (default).
#[derive(Default)]
pub struct InMemoryDialogStore {
    inner: dashmap::DashMap<DialogId, Dialog>,
}

impl InMemoryDialogStore {
    /// Returns the current number of stored dialogs.
    pub fn count(&self) -> usize {
        self.inner.len()
    }
}

#[async_trait]
impl DialogStore for InMemoryDialogStore {
    async fn get(&self, id: &DialogId) -> Option<Dialog> {
        self.inner.get(id).map(|d| d.clone())
    }

    async fn put(&self, dialog: Dialog) {
        // Enforce size limit to prevent memory exhaustion
        if self.inner.len() >= MAX_DIALOGS && !self.inner.contains_key(&dialog.id) {
            tracing::warn!(
                count = self.inner.len(),
                max = MAX_DIALOGS,
                "dialog store at capacity; rejecting new dialog"
            );
            return;
        }
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

    async fn len(&self) -> usize {
        self.inner.len()
    }
}
