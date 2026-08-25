// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "ws")]

use std::net::TcpListener;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use sip_transport::{
    run_ws, run_ws_with_policy, send_ws, InboundPacket, TransportKind, WsAcceptPolicy,
};
use tokio::sync::mpsc;

/// Reserve an ephemeral port and return its `host:port` string.
fn ephemeral_bind() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("{addr}")
}

/// A tungstenite client request with the `sip` subprotocol and an
/// optional `Origin`.
fn sip_upgrade_request(
    url: &str,
    origin: Option<&str>,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::header::HeaderValue};
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
    if let Some(o) = origin {
        request
            .headers_mut()
            .insert("Origin", HeaderValue::from_str(o).unwrap());
    }
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_roundtrip_delivers_packet() {
    // Pick an ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bind = format!("{}", addr);
    let bind_for_task = bind.clone();

    let (tx, mut rx) = mpsc::channel::<InboundPacket>(1);

    tokio::spawn(async move {
        run_ws(&bind_for_task, tx).await.expect("ws listener");
    });

    // Give listener time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{}", bind);
    let payload = Bytes::from_static(b"OPTIONS sip:example.com SIP/2.0\r\n\r\n");
    send_ws(&url, payload.clone()).await.expect("send ws");

    let packet = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("packet recv timeout")
        .expect("packet recv");

    assert_eq!(packet.transport(), TransportKind::Ws);
    assert_eq!(packet.payload(), &payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_rejects_missing_subprotocol() {
    // Pick an ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bind = format!("{}", addr);
    let bind_for_task = bind.clone();

    let (tx, _rx) = mpsc::channel::<InboundPacket>(1);

    tokio::spawn(async move {
        run_ws(&bind_for_task, tx).await.expect("ws listener");
    });

    // Give listener time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{}", bind);
    let result = tokio_tungstenite::connect_async(url).await;
    assert!(result.is_err(), "server should reject missing subprotocol");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_origin_allow_list_admits_and_refuses() {
    let bind = ephemeral_bind();
    let bind_for_task = bind.clone();
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(1);
    let policy = WsAcceptPolicy {
        allowed_origins: vec!["https://ops.example.com".to_string()],
    };
    tokio::spawn(async move {
        run_ws_with_policy(&bind_for_task, policy, tx)
            .await
            .expect("ws listener");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let url = format!("ws://{bind}");

    // Wrong origin → refused at upgrade (403).
    let bad = sip_upgrade_request(&url, Some("https://evil.example.net"));
    assert!(
        tokio_tungstenite::connect_async(bad).await.is_err(),
        "disallowed origin must be refused"
    );

    // No origin at all → refused when an allow-list is set.
    let none = sip_upgrade_request(&url, None);
    assert!(
        tokio_tungstenite::connect_async(none).await.is_err(),
        "absent origin must be refused when an allow-list is set"
    );

    // Allowed origin (case-insensitive) → upgrade succeeds and a SIP
    // message flows.
    let good = sip_upgrade_request(&url, Some("HTTPS://OPS.EXAMPLE.COM"));
    let (mut client, _) = tokio_tungstenite::connect_async(good)
        .await
        .expect("allowed origin must be admitted");
    client
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            b"OPTIONS sip:example.com SIP/2.0\r\n\r\n".to_vec(),
        ))
        .await
        .expect("send");
    let packet = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("packet recv timeout")
        .expect("packet recv");
    assert_eq!(packet.transport(), TransportKind::Ws);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_reply_goes_down_the_same_connection() {
    // The RFC 7118 §5.2 property browsers depend on: the response to a
    // request received over a WS connection is written back down that
    // connection (InboundPacket::stream), not dialed to the Via/Contact
    // address (which for a browser is unroutable).
    let bind = ephemeral_bind();
    let bind_for_task = bind.clone();
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(1);
    tokio::spawn(async move {
        run_ws(&bind_for_task, tx).await.expect("ws listener");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{bind}");
    let req = sip_upgrade_request(&url, None);
    let (mut client, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("connect");
    client
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            b"OPTIONS sip:example.com SIP/2.0\r\n\r\n".to_vec(),
        ))
        .await
        .expect("send request");

    let packet = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("packet recv timeout")
        .expect("packet recv");
    let reply = Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n");
    packet
        .stream()
        .expect("ws packets must carry the connection writer")
        .send(reply.clone())
        .await
        .expect("reply via connection writer");

    let echoed = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .expect("reply recv timeout")
        .expect("stream open")
        .expect("frame ok");
    match echoed {
        tokio_tungstenite::tungstenite::Message::Binary(data) => {
            assert_eq!(Bytes::from(data), reply);
        }
        other => panic!("expected binary SIP reply frame, got {other:?}"),
    }
}
