// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Issue #73 (part 3): with a keepalive interval configured, an
//! established inbound stream connection receives periodic CRLF while
//! signaling is quiet, keeping carrier idle timers from firing.
//!
//! Lives in its own test binary because the keepalive interval is a
//! process-global knob read at session start.

use std::net::SocketAddr;
use std::time::Duration;

use sip_transport::{run_tcp, InboundPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn established_connection_receives_crlf_keepalives() {
    sip_transport::set_stream_keepalive_interval(1);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener); // run_tcp re-binds the same port
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(8);
    tokio::spawn(async move {
        let _ = run_tcp(&server_addr.to_string(), tx).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(server_addr).await.expect("connect");

    // Establish: one complete SIP message switches the session out of
    // the Slowloris window; keepalives only run on established
    // connections.
    let msg: &[u8] = b"OPTIONS sip:probe SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-ka\r\n\
From: <sip:trunk@127.0.0.1>;tag=1\r\n\
To: <sip:probe@127.0.0.1>\r\n\
Call-ID: ka-call-1@host\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
    client.write_all(msg).await.unwrap();
    let _ = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("inbound within 1s")
        .expect("recv produces a packet");

    // With no signaling at all, CRLF must show up within a couple of
    // intervals.
    let mut buf = vec![0u8; 64];
    let n = timeout(Duration::from_secs(3), client.read(&mut buf))
        .await
        .expect("keepalive within 3s")
        .expect("read ok");
    assert!(n > 0, "connection closed instead of sending keepalive");
    assert!(
        buf[..n].iter().all(|&b| b == b'\r' || b == b'\n'),
        "expected pure CRLF keepalive, got {:?}",
        &buf[..n]
    );
}
