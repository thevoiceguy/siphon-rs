// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! HEP3 (Homer Encapsulation Protocol v3) emission for siphon-rs.
//!
//! This crate is the integration glue between siphon-rs's transports
//! (sip-transport's `run_udp` / `send_udp` and friends) and a
//! [`hep_rs::HepSink`] running off-process toward
//! [Homer](https://sipcapture.io/) / HEPIC / HEPlify-Server. When
//! enabled, every inbound *parsed* and every outbound *serialized*
//! SIP message is shipped as a HEP3 packet so the collector can
//! correlate signaling with RTCP, QoS, logs, and CDRs in one call
//! view.
//!
//! # Design — `sip-observe` parallel
//!
//! Mirrors the global-OnceCell pattern of [`sip_observe::TransportMetrics`]:
//! callers install a single [`SipHepEmitter`] at startup via
//! [`set_emitter`], and transport code calls [`emit_inbound_sip`] /
//! [`emit_outbound_sip`] at the natural hook points. Without an
//! emitter installed the calls are a single load + null-check, so
//! deployments that don't want HEP pay essentially nothing.
//!
//! # Correlation
//!
//! The HEP3 correlation ID (chunk `0x0011`) is the most useful field
//! for stitching SIP + RTCP + logs into one call view in Homer. This
//! crate doesn't *parse* the SIP message to extract Call-ID
//! (sip-parse already does that, and re-parsing here would duplicate
//! work on the hot path). Callers supply the correlation ID
//! explicitly; the daemon binary typically extracts Call-ID once at
//! dispatch and threads it through.
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::net::SocketAddr;
//! use hep_rs::{UdpHepSink, UdpHepSinkConfig};
//! use sip_hep::{set_emitter, SipHepEmitter};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let collector: SocketAddr = "127.0.0.1:9060".parse()?;
//! let (sink, _worker) = UdpHepSink::start(UdpHepSinkConfig::new(collector)).await?;
//! let emitter = SipHepEmitter::new(Arc::new(sink), 2001);
//! sip_hep::set_emitter(Arc::new(emitter));
//! # Ok(()) }
//! ```

mod emitter;
mod headers;

pub use emitter::{set_emitter, sip_hep, SipHepEmitter, SipHepHandle};
pub use headers::extract_call_id;

// Re-export the bits of `hep-rs` that callers (`sip-transport` etc.)
// need to construct a packet, so they don't have to declare a
// second dep on `hep-rs` just to name `IpProto::Udp`.
pub use hep_rs::{HepProtocol, HepSink, IpProto};

/// What direction a SIP message is going. The HEP packet itself
/// encodes src and dst, but the direction is convenient for callers
/// that already know it at the hook site and removes guesswork at
/// the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Inbound — parsed from a transport recv path.
    Inbound,
    /// Outbound — about to be sent on a transport.
    Outbound,
}

/// Convenience: emit one HEP3 SIP packet through the globally-installed
/// emitter (if any). Inbound flavour — `peer` is the source, the
/// transport's local address is the destination.
///
/// Zero cost when no emitter is installed (single load + null-check).
pub fn emit_inbound_sip(
    transport: hep_rs::IpProto,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    payload: &[u8],
    correlation_id: Option<&str>,
) {
    if let Some(emitter) = sip_hep() {
        emitter.emit_sip(
            Direction::Inbound,
            transport,
            peer,
            local,
            payload,
            correlation_id,
        );
    }
}

/// Convenience: emit one HEP3 SIP packet through the globally-installed
/// emitter (if any). Outbound flavour — `local` is the source, `peer`
/// is the destination.
///
/// Zero cost when no emitter is installed.
pub fn emit_outbound_sip(
    transport: hep_rs::IpProto,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    payload: &[u8],
    correlation_id: Option<&str>,
) {
    if let Some(emitter) = sip_hep() {
        emitter.emit_sip(
            Direction::Outbound,
            transport,
            local,
            peer,
            payload,
            correlation_id,
        );
    }
}
