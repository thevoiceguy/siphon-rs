// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! What decides which transaction a message belongs to.
//!
//! A transaction is matched by the branch parameter of the top `Via`, the
//! method, and which side we are (RFC 3261 §17.2.3). All of it is read
//! out of a header a peer wrote, and it is a map key: a message that
//! matches the wrong transaction is answered by the wrong state machine,
//! and one that matches none is a transaction that never completes.

#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sip_transaction::TransactionKey;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 || data.len() > 8192 {
        return;
    }
    let bytes = Bytes::copy_from_slice(data);
    let Some(request) = sip_parse::parse_request(&bytes) else {
        return;
    };

    // Both sides of the same request. A key built as a server must never
    // equal the one built as a client, or a request would match the
    // transaction of its own response.
    let server = TransactionKey::from_request(&request, true);
    let client = TransactionKey::from_request(&request, false);
    if let (Some(server), Some(client)) = (&server, &client) {
        assert_ne!(
            server, client,
            "a server key matched a client key for the same request"
        );
    }

    let Some(key) = server else {
        return;
    };

    // Reading the parts back must be total: they came from the wire.
    let _ = (key.branch(), key.method());

    // The key is a map key, so it has to hash and compare consistently —
    // the same request twice is the same transaction, once.
    let mut transactions: HashMap<TransactionKey, u32> = HashMap::new();
    transactions.insert(key.clone(), 1);
    let again = TransactionKey::from_request(&request, true).expect("built once already");
    assert_eq!(
        key, again,
        "the same request built two different transaction keys"
    );
    *transactions.entry(again).or_insert(0) += 1;
    assert_eq!(
        transactions.len(),
        1,
        "the same request opened two transactions"
    );

    // A key built by hand from the same parts is the same key, which is
    // what lets a response find the transaction its request opened.
    let rebuilt = TransactionKey::new(key.branch(), key.method().clone(), true);
    assert_eq!(key, rebuilt, "a key did not survive being rebuilt");
});
