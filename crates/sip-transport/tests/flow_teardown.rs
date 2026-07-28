// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Issue #73: an inbound stream session must tear its writer down when
//! the peer closes the read side, so (a) the socket is actually shut
//! down instead of parking in CLOSE-WAIT, and (b) long-lived `Flow`
//! clones of the writer channel fail fast instead of buffering
//! in-dialog requests into a half-closed socket until Timer B.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use sip_transport::{run_tcp, InboundPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

const OPTIONS_MSG: &[u8] = b"OPTIONS sip:probe SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-teardown\r\n\
From: <sip:trunk@127.0.0.1>;tag=1\r\n\
To: <sip:probe@127.0.0.1>\r\n\
Call-ID: teardown-call-1@host\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

#[tokio::test]
async fn flow_sender_fails_fast_and_socket_closes_after_peer_fin() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener); // run_tcp re-binds the same port
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(8);
    tokio::spawn(async move {
        let _ = run_tcp(&server_addr.to_string(), tx).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    client.write_all(OPTIONS_MSG).await.unwrap();

    let got = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("inbound within 1s")
        .expect("recv produces a packet");

    // Keep a clone of the writer channel past the packet's lifetime —
    // exactly what a dialog's `Flow` does.
    let flow_sender = got.stream().expect("stream writer").clone();
    drop(got);

    // The connection works while the peer is alive.
    let response = Bytes::from_static(
        b"SIP/2.0 200 OK\r\nCall-ID: teardown-call-1@host\r\nContent-Length: 0\r\n\r\n",
    );
    flow_sender
        .send(response.clone())
        .await
        .expect("send on a live connection succeeds");
    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .expect("response within 1s")
        .expect("read ok");
    assert_eq!(&buf[..n], response.as_ref());

    // Peer idle-closes: FIN our read side, keep its own read open —
    // the silent-FIN carrier-edge shape from issue #73.
    client.shutdown().await.expect("half-close");

    // (a) The session must shut the socket down in response, not park
    // it in CLOSE-WAIT: our FIN arrives as EOF on the client.
    let n = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("server FIN within 2s")
        .expect("read ok");
    assert_eq!(n, 0, "server should close its side after peer FIN");

    // (b) The retained flow sender must start failing fast — before
    // the fix it buffered into the dead socket forever.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if flow_sender.send(response.clone()).await.is_err() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "flow sender still accepting writes 2s after peer FIN"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
