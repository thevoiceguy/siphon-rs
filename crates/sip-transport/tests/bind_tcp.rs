// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! `bind_tcp` then `serve_tcp`: a peer that connects the moment `bind_tcp`
//! returns — before anything serves the listener — is accepted, and its
//! message delivered once serving starts. A spawned `run_tcp` binds only
//! when its task first runs, so a caller that returned right after
//! spawning it could have its first connection refused.

use std::time::Duration;

use sip_transport::{bind_tcp, serve_tcp, InboundPacket};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn a_peer_connecting_before_serving_starts_is_heard() {
    let listener = bind_tcp("127.0.0.1:0").expect("binds");
    let addr = listener.local_addr().unwrap();

    // Before serve_tcp runs: the kernel holds the connection in the backlog.
    let mut client = TcpStream::connect(addr).await.expect("connects at once");
    let msg: &[u8] = b"OPTIONS sip:probe SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-bind\r\n\
From: <sip:a@127.0.0.1>;tag=1\r\n\
To: <sip:probe@127.0.0.1>\r\n\
Call-ID: bind-1@host\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
    client.write_all(msg).await.unwrap();

    let (tx, mut rx) = mpsc::channel::<InboundPacket>(8);
    tokio::spawn(serve_tcp(listener, tx));
    let packet = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("delivered")
        .expect("a packet");
    assert!(packet.payload().starts_with(b"OPTIONS sip:probe"));
}
