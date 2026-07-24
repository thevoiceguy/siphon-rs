// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Regression for siphon-ai #341: the client connection pool
//! (`ConnectionPool` / `TlsPool`) — used for every *outbound* SIP
//! connection — emitted no HEP at all, so outbound-originated (UAC)
//! calls had no SIP ladder in Homer while inbound calls did. This drives
//! a real send + reply through the TCP pool with a `sip-hep` emitter
//! installed and asserts both directions produce a `HepPacket`.
//!
//! Its own test binary: `sip_hep::set_emitter` installs a process-global
//! once, so this can't share with `hep_udp.rs`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hep_rs::{HepPacket, HepProtocol, HepSink};
use sip_hep::SipHepEmitter;
use sip_transport::pool::ConnectionPool;
use sip_transport::InboundPacket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Default)]
struct CapturingSink {
    received: Mutex<Vec<HepPacket>>,
}

impl HepSink for CapturingSink {
    fn send(&self, packet: HepPacket) {
        self.received.lock().unwrap().push(packet);
    }
}

#[tokio::test]
async fn tcp_pool_emits_hep_on_outbound_send_and_inbound_reply() {
    let sink = Arc::new(CapturingSink::default());
    let emitter = Arc::new(SipHepEmitter::new(sink.clone() as Arc<dyn HepSink>, 4444));
    assert!(
        sip_hep::set_emitter(emitter),
        "first install of the test emitter should succeed"
    );

    // A stand-in trunk: accept one connection, read the request, and
    // reply so the pool's reader task exercises the inbound HEP path.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind trunk");
    let trunk_addr: SocketAddr = listener.local_addr().unwrap();
    let reply =
        b"SIP/2.0 200 OK\r\nCall-ID: pool-hep-1@host\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let _ = sock.write_all(reply).await;
        // Keep the socket open briefly so the reply isn't RST'd before
        // the pool reads it.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let pool = ConnectionPool::new();
    let (in_tx, mut in_rx) = mpsc::channel::<InboundPacket>(8);
    pool.set_inbound_tx(in_tx).await;

    let invite = Bytes::from_static(
        b"INVITE sip:callee@trunk SIP/2.0\r\nCall-ID: pool-hep-1@host\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
    );
    pool.send_tcp(trunk_addr, invite).await.expect("send_tcp");

    // The reader must deliver the reply back through the inbound pipe —
    // proving the connection is live and its inbound half is wired.
    let got = timeout(Duration::from_secs(2), in_rx.recv())
        .await
        .expect("a reply arrives within 2s")
        .expect("inbound packet");
    assert!(
        got.payload().windows(6).any(|w| w == b"200 OK"),
        "reader delivered the 200 OK"
    );

    // Both legs must have produced a HEP packet: the outbound INVITE and
    // the inbound 200 OK. Direction isn't a HepPacket field — it's
    // encoded by src/dst — so distinguish by the message plus the
    // trunk-facing endpoint. Give the emit calls a beat to land.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let packets = sink.received.lock().unwrap().clone();
    let sip: Vec<_> = packets
        .iter()
        .filter(|p| p.protocol == HepProtocol::Sip)
        .collect();

    let outbound_invite = sip
        .iter()
        .any(|p| p.payload.windows(6).any(|w| w == b"INVITE") && p.dst == trunk_addr);
    let inbound_ok = sip
        .iter()
        .any(|p| p.payload.windows(6).any(|w| w == b"200 OK") && p.src == trunk_addr);
    assert!(
        outbound_invite,
        "outbound INVITE (dst=trunk) must emit HEP; sip packets={sip:?}"
    );
    assert!(
        inbound_ok,
        "inbound 200 OK (src=trunk) must emit HEP; sip packets={sip:?}"
    );
    // Correlation id threads through so Homer can group the ladder.
    assert!(
        sip.iter()
            .all(|p| p.correlation_id.as_deref() == Some("pool-hep-1@host")),
        "every SIP chunk carries the Call-ID correlation"
    );
}
