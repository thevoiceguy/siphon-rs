use sip_core::Headers;
use smol_str::SmolStr;
use std::hash::{Hash, Hasher};

use crate::TransactionKey;

/// Simple, stable hash for stickiness keys using SipHash.
fn siphash_str(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Compute a sharding key from a Call-ID (common for dialog/transaction stickiness).
pub fn shard_by_call_id(call_id: &str) -> u64 {
    siphash_str(call_id)
}

/// Compute a sharding key from a transaction key (branch + method + direction).
pub fn shard_by_transaction_key(key: &TransactionKey) -> u64 {
    let mut base = siphash_str(key.branch.as_str());
    // Mix method and direction
    base ^= siphash_str(key.method.as_str()) << 32;
    if key.is_server {
        base ^= 0x1;
    }
    base
}

/// Compute a sharding key from dialog identifiers (Call-ID + tags).
pub fn shard_by_dialog_id(call_id: &SmolStr, local_tag: &SmolStr, remote_tag: &SmolStr) -> u64 {
    let mut val = siphash_str(call_id.as_str());
    val ^= siphash_str(local_tag.as_str());
    val ^= siphash_str(remote_tag.as_str());
    val
}

/// Extract Call-ID from headers for sharding; returns None if missing.
pub fn shard_key_from_headers(headers: &Headers) -> Option<u64> {
    headers
        .get("Call-ID")
        .map(|cid| shard_by_call_id(cid.as_str()))
}
