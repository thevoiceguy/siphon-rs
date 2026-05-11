// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! End-to-end TCP capture test: run_tcp accepts a connection, the
//! sip-hep emitter sees one HEP packet per SIP message in both
//! directions.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hep_rs::{HepPacket, HepProtocol, HepSink, IpProto};
use sip_hep::{Direction, SipHepEmitter};
use sip_transport::{run_tcp, InboundPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
async fn run_tcp_emits_hep_for_inbound_and_outbound_frames() {
    // Install the test emitter once. The OnceCell across the test
    // binary means only one #[test] in this binary may call
    // set_emitter — this is the only one.
    let sink = Arc::new(CapturingSink::default());
    let emitter = Arc::new(SipHepEmitter::new(sink.clone() as Arc<dyn HepSink>, 7777));
    let installed = sip_hep::set_emitter(emitter);
    assert!(
        installed,
        "first install of the test emitter should succeed"
    );

    // Bind the daemon side and spin up the TCP listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener); // run_tcp re-binds the same port
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(8);
    tokio::spawn(async move {
        let _ = run_tcp(&server_addr.to_string(), tx).await;
    });

    // Wait briefly for the listener to come up.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(server_addr).await.expect("connect");
    let _client_local = client.local_addr().unwrap();

    // Send one SIP-shaped message with a Content-Length so the
    // server's framer treats it as a complete frame.
    let inbound_msg = b"OPTIONS sip:probe SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-tcp\r\n\
From: <sip:sipp@127.0.0.1>;tag=1\r\n\
To: <sip:probe@127.0.0.1>\r\n\
Call-ID: tcp-hep-call-1@host\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
    client.write_all(inbound_msg).await.unwrap();

    let got = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("inbound within 1s")
        .expect("recv produces a packet");
    assert_eq!(got.payload().as_ref(), inbound_msg);

    // Echo a response back through the writer channel — exercises
    // the outbound hook in spawn_stream_session.
    let stream_tx = got.stream().expect("stream writer");
    let outbound_msg = Bytes::from(
        b"SIP/2.0 200 OK\r\nCall-ID: tcp-hep-call-1@host\r\nContent-Length: 0\r\n\r\n".to_vec(),
    );
    sip_transport::send_stream(
        sip_transport::TransportKind::Tcp,
        stream_tx,
        outbound_msg.clone(),
    )
    .await
    .expect("send_stream ok");

    // Read the response on the client side so the daemon's writer
    // task actually flushes — without a reader the kernel TCP buffer
    // would happily eat the bytes anyway, but reading verifies the
    // wire flow end-to-end.
    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .expect("response within 1s")
        .expect("read ok");
    buf.truncate(n);
    assert_eq!(buf.as_slice(), outbound_msg.as_ref());

    // Give the HEP capture a moment to land (sink::send is sync
    // here but the writer task is async).
    tokio::time::sleep(Duration::from_millis(50)).await;

    let captured = sink.received.lock().unwrap();
    assert_eq!(
        captured.len(),
        2,
        "expected one inbound + one outbound packet; got {captured:?}"
    );

    let inbound = &captured[0];
    assert_eq!(inbound.protocol, HepProtocol::Sip);
    assert_eq!(inbound.transport, IpProto::Tcp);
    assert_eq!(inbound.dst, server_addr);
    assert_eq!(
        inbound.correlation_id.as_deref(),
        Some("tcp-hep-call-1@host")
    );
    assert_eq!(inbound.payload, inbound_msg);

    let outbound = &captured[1];
    assert_eq!(outbound.protocol, HepProtocol::Sip);
    assert_eq!(outbound.transport, IpProto::Tcp);
    assert_eq!(outbound.src, server_addr);
    assert_eq!(
        outbound.correlation_id.as_deref(),
        Some("tcp-hep-call-1@host")
    );
    assert_eq!(outbound.payload, outbound_msg.as_ref());

    // Direction is bytes-encoded by src/dst — exercise the enum on
    // the public surface so dead-code lints can't shrink it.
    let _: Direction = Direction::Inbound;
}
