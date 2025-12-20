#![cfg(feature = "ws")]

use std::net::TcpListener;
use std::time::Duration;

use bytes::Bytes;
use sip_transport::{run_ws, send_ws, InboundPacket, TransportKind};
use tokio::sync::mpsc;

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

    assert_eq!(packet.transport, TransportKind::Ws);
    assert_eq!(packet.payload, payload);
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
