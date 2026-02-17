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
///
/// Uses a secondary index on Call-ID for efficient `list_by_call_id` lookups
/// (O(k) where k = dialogs sharing the Call-ID, instead of O(n) full scan).
#[derive(Default)]
pub struct InMemoryDialogStore {
    inner: dashmap::DashMap<DialogId, Dialog>,
    /// Secondary index: Call-ID → set of DialogIds sharing that Call-ID.
    by_call_id: dashmap::DashMap<SmolStr, Vec<DialogId>>,
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
        let call_id = dialog.id.call_id.clone();
        let dialog_id = dialog.id.clone();
        self.inner.insert(dialog.id.clone(), dialog);
        // Update secondary index
        self.by_call_id
            .entry(call_id)
            .or_default()
            .push(dialog_id);
    }

    async fn remove(&self, id: &DialogId) {
        self.inner.remove(id);
        // Update secondary index
        if let Some(mut ids) = self.by_call_id.get_mut(&id.call_id) {
            ids.retain(|did| did != id);
            if ids.is_empty() {
                drop(ids);
                self.by_call_id.remove(&id.call_id);
            }
        }
    }

    async fn list_by_call_id(&self, call_id: &SmolStr) -> Vec<Dialog> {
        if let Some(ids) = self.by_call_id.get(call_id) {
            ids.iter()
                .filter_map(|id| self.inner.get(id).map(|d| d.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    async fn len(&self) -> usize {
        self.inner.len()
    }
}
