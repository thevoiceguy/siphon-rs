// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2026 siphon-rs contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Process-wide `SipHepEmitter` install + access.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use hep_rs::{HepPacket, HepProtocol, HepSink, IpProto};
use once_cell::sync::OnceCell;
use tracing::warn;

use crate::Direction;

/// Shared handle to a [`SipHepEmitter`]. Used by transports that
/// want to look up the global emitter once and call it many times.
pub type SipHepHandle = Arc<SipHepEmitter>;

/// Builds [`HepPacket`]s from per-SIP-message tuples and forwards
/// them to a [`HepSink`] (typically a `hep_rs::UdpHepSink`).
///
/// The emitter holds the deployment-wide `capture_id` and (optional)
/// `capture_password` so each call site only needs the tuple
/// `(direction, transport, src, dst, payload, correlation_id)`.
pub struct SipHepEmitter {
    sink: Arc<dyn HepSink>,
    capture_id: u32,
    capture_password: Option<String>,
}

impl SipHepEmitter {
    /// Construct an emitter from a sink + Homer agent ID.
    pub fn new(sink: Arc<dyn HepSink>, capture_id: u32) -> Self {
        Self {
            sink,
            capture_id,
            capture_password: None,
        }
    }

    /// Sets the HEPlify-Server shared password (chunk `0x000E`).
    /// Required by deployments where the collector enforces it.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.capture_password = Some(password.into());
        self
    }

    /// Emit one HEP3 SIP packet. Non-blocking — the underlying sink's
    /// queue drops on full and surfaces the drop via its own counter.
    pub fn emit_sip(
        &self,
        _direction: Direction,
        transport: IpProto,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
        correlation_id: Option<&str>,
    ) {
        // Defensive: HEP3 chunks are u16-length; payloads larger than
        // ~64 KiB don't round-trip cleanly. SIP MTU is typically <2 KiB
        // and UDP enforces ~65 KiB anyway, but TCP streams could hand
        // us something larger. Truncate with a warning instead of
        // dropping silently — Homer still gets the head of the message
        // which is the important part for triage.
        const MAX_SIP_PAYLOAD: usize = 60 * 1024;
        let payload_vec = if payload.len() > MAX_SIP_PAYLOAD {
            warn!(
                len = payload.len(),
                "SIP payload exceeds HEP packet capacity; truncating to {MAX_SIP_PAYLOAD} bytes"
            );
            payload[..MAX_SIP_PAYLOAD].to_vec()
        } else {
            payload.to_vec()
        };

        let pkt = HepPacket {
            capture_id: self.capture_id,
            capture_password: self.capture_password.clone(),
            protocol: HepProtocol::Sip,
            transport,
            src,
            dst,
            timestamp: SystemTime::now(),
            correlation_id: correlation_id.map(|s| s.to_string()),
            payload: payload_vec,
        };
        self.sink.send(pkt);
    }
}

static SIP_HEP: OnceCell<SipHepHandle> = OnceCell::new();

/// Install the global emitter. Returns `true` on install, `false`
/// when already configured — the second call doesn't replace the
/// first (consistent with `sip-observe::set_transport_metrics`).
#[must_use]
pub fn set_emitter(handle: SipHepHandle) -> bool {
    if SIP_HEP.set(handle).is_ok() {
        true
    } else {
        warn!("sip-hep emitter already configured");
        false
    }
}

/// Look up the global emitter. `None` when no HEP shipping is
/// configured for this process — the recommended `if let Some(...)`
/// guard at call sites makes the check zero-cost.
pub fn sip_hep() -> Option<&'static SipHepHandle> {
    SIP_HEP.get()
}
