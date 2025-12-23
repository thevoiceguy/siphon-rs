/// Invite state manager for tracking pending INVITE transactions.
///
/// This allows the CANCEL handler to send 487 Request Terminated responses
/// to the original INVITE transaction when a CANCEL is received.
use dashmap::DashMap;
use sip_core::Request;
use sip_parse::header;
use sip_transaction::branch_from_via;
use smol_str::SmolStr;
use sip_transaction::ServerTransactionHandle;

/// Pending INVITE transaction information.
#[derive(Clone)]
pub struct PendingInvite {
    /// Server transaction handle for sending the 487 response
    pub handle: ServerTransactionHandle,
    /// Cached Via header for 487 response
    pub via: SmolStr,
    /// Cached From header for 487 response
    pub from: SmolStr,
    /// Cached To header for 487 response (updated when To-tag is known)
    pub to: SmolStr,
    /// Cached Call-ID header for 487 response
    pub call_id: SmolStr,
    /// Cached CSeq header for 487 response (INVITE CSeq)
    pub cseq: SmolStr,
}

/// Manager for tracking pending INVITE transactions that can be canceled.
///
/// Maps INVITE identifiers to the server transaction handle and essential headers.
/// When a CANCEL is received, the handler can look up the INVITE transaction
/// and send a 487 Request Terminated response through it.
#[derive(Default)]
pub struct InviteStateManager {
    /// Map of INVITE key -> PendingInvite for pending INVITEs
    pending: DashMap<String, PendingInvite>,
}

impl InviteStateManager {
    /// Create a new invite state manager.
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }

    /// Build a stable key for an INVITE/CANCEL pair using Call-ID, CSeq number, and top Via branch.
    pub fn key_from_request(request: &Request) -> Option<String> {
        let call_id = header(&request.headers, "Call-ID")?;
        let cseq = header(&request.headers, "CSeq")?;
        let cseq_num = cseq.split_whitespace().next()?;
        let via = header(&request.headers, "Via")?;
        let branch = branch_from_via(via.as_str())?;
        Some(format!("{}:{}:{}", call_id, cseq_num, branch))
    }

    /// Store a pending INVITE transaction.
    ///
    /// This should be called when sending a provisional response (100/180/183)
    /// to track the INVITE transaction so it can be canceled later.
    pub fn store_pending_invite(
        &self,
        key: String,
        pending: PendingInvite,
    ) {
        self.pending.insert(key, pending);
    }

    /// Create a PendingInvite from a request and transaction handle.
    pub fn pending_from_request(
        handle: ServerTransactionHandle,
        request: &Request,
    ) -> Option<(String, PendingInvite)> {
        let key = Self::key_from_request(request)?;
        let via = header(&request.headers, "Via")?.clone();
        let from = header(&request.headers, "From")?.clone();
        let to = header(&request.headers, "To")?.clone();
        let call_id = header(&request.headers, "Call-ID")?.clone();
        let cseq = header(&request.headers, "CSeq")?.clone();

        Some((
            key,
            PendingInvite {
                handle,
                via,
                from,
                to,
                call_id,
                cseq,
            },
        ))
    }

    /// Look up a pending INVITE transaction by key.
    ///
    /// Returns the pending invite info if found, allowing the caller to send a 487 response.
    pub fn get_pending_invite(&self, key: &str) -> Option<PendingInvite> {
        self.pending.get(key).map(|entry| entry.value().clone())
    }

    /// Update the To header once a To-tag is generated.
    pub fn update_to_header(&self, key: &str, to: SmolStr) {
        if let Some(mut entry) = self.pending.get_mut(key) {
            entry.to = to;
        }
    }

    /// Remove a pending INVITE transaction.
    ///
    /// This should be called when the INVITE transaction completes (receives
    /// 200 OK, 4xx, 5xx, 6xx, or is canceled).
    pub fn remove_pending_invite(&self, key: &str) -> Option<PendingInvite> {
        self.pending.remove(key).map(|(_, pending)| pending)
    }

    /// Get the count of pending INVITE transactions.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
