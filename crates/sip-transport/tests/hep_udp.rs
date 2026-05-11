// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Drives an end-to-end UDP recv + send through `sip-transport` with
//! a `sip-hep` emitter wired up, and asserts the resulting `HepPacket`s
//! describe both directions of the conversation.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hep_rs::{HepPacket, HepProtocol, HepSink, IpProto};
use sip_hep::{Direction, SipHepEmitter};
use sip_transport::{run_udp, send_udp, InboundPacket};
use tokio::net::UdpSocket;
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
async fn run_udp_and_send_udp_emit_hep_on_both_legs() {
    // One-shot install of the global emitter for this test binary.
    // The whole test relies on running first/only in this process —
    // see the `#[ignore]` reminder at the bottom if anyone adds more
    // emitter-using tests to the same binary.
    let sink = Arc::new(CapturingSink::default());
    let emitter = Arc::new(SipHepEmitter::new(sink.clone() as Arc<dyn HepSink>, 7777));
    let installed = sip_hep::set_emitter(emitter);
    assert!(
        installed,
        "first install of the test emitter should succeed"
    );

    // Bind the daemon side: this is the UAS that run_udp services.
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind server"));
    let server_addr: SocketAddr = server.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel::<InboundPacket>(8);
    tokio::spawn(run_udp(Arc::clone(&server), tx));

    // Bind the peer side: this stands in for the SIP caller.
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr: SocketAddr = peer.local_addr().unwrap();

    // Send an OPTIONS-shaped message into the daemon, then receive
    // it back through run_udp's channel.
    let inbound_msg = b"OPTIONS sip:probe SIP/2.0\r\nCall-ID: probe-call-1@host\r\n\r\n";
    peer.send_to(inbound_msg, server_addr).await.unwrap();
    let got = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("inbound packet within 1s")
        .expect("recv produces a packet");
    assert_eq!(got.payload().as_ref(), inbound_msg);

    // Send a reply via the daemon socket so we exercise send_udp's
    // hook too.
    let outbound_msg = b"SIP/2.0 200 OK\r\nCall-ID: probe-call-1@host\r\n\r\n";
    send_udp(server.as_ref(), &peer_addr, outbound_msg)
        .await
        .expect("send_udp ok");

    // The HEP sink picks both up synchronously (CapturingSink::send
    // is just a Mutex push); give a small yield in case the recv
    // loop is mid-iteration when we read.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let captured = sink.received.lock().unwrap();
    assert_eq!(
        captured.len(),
        2,
        "expected one inbound + one outbound packet; got {captured:?}"
    );

    // Inbound packet: src=peer, dst=server.
    let inbound = &captured[0];
    assert_eq!(inbound.protocol, HepProtocol::Sip);
    assert_eq!(inbound.transport, IpProto::Udp);
    assert_eq!(inbound.src, peer_addr);
    assert_eq!(inbound.dst, server_addr);
    assert_eq!(inbound.correlation_id.as_deref(), Some("probe-call-1@host"));
    assert_eq!(inbound.payload, inbound_msg);
    assert_eq!(inbound.capture_id, 7777);

    // Outbound packet: src=server, dst=peer.
    let outbound = &captured[1];
    assert_eq!(outbound.protocol, HepProtocol::Sip);
    assert_eq!(outbound.transport, IpProto::Udp);
    assert_eq!(outbound.src, server_addr);
    assert_eq!(outbound.dst, peer_addr);
    assert_eq!(
        outbound.correlation_id.as_deref(),
        Some("probe-call-1@host"),
        "outbound also extracts Call-ID for correlation"
    );
    assert_eq!(outbound.payload, outbound_msg);
    // Use Direction for symmetry assertion; the wire packet doesn't
    // carry direction explicitly (src/dst encode it), but exercising
    // the enum keeps it part of the public surface.
    let _: Direction = Direction::Inbound;
}
