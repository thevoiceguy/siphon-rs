// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Observability and metrics integration for SIP transports.
//!
//! Provides tracing integration and transport metrics collection
//! for monitoring packet flow, errors, and latency.
//!
//! # Example
//! ```
//! use sip_observe::{set_transport_metrics, TracingTransportMetrics};
//! set_transport_metrics(TracingTransportMetrics);
//! // Metrics automatically emitted via tracing events
//! ```

use once_cell::sync::OnceCell;
use std::sync::Arc;
use tracing::Level;

/// Metrics sink used by transports to emit observability events.
///
/// Implementations should treat `transport`, `stage`, and `op` as low-cardinality
/// identifiers (e.g., "udp", "accept", "read") and avoid propagating untrusted
/// or high-cardinality data into metrics/logs.
pub trait TransportMetrics: Send + Sync + 'static {
    fn on_packet_received(&self, transport: &str);
    fn on_packet_sent(&self, transport: &str);
    fn on_error(&self, transport: &str, stage: &str);
    fn on_accept(&self, transport: &str);
    fn on_connect(&self, transport: &str);
    fn on_latency(&self, transport: &str, op: &str, nanos: u64);
}

#[derive(Debug, Default)]
struct NoopTransportMetrics;

impl TransportMetrics for NoopTransportMetrics {
    fn on_packet_received(&self, _transport: &str) {}
    fn on_packet_sent(&self, _transport: &str) {}
    fn on_error(&self, _transport: &str, _stage: &str) {}
    fn on_accept(&self, _transport: &str) {}
    fn on_connect(&self, _transport: &str) {}
    fn on_latency(&self, _transport: &str, _op: &str, _nanos: u64) {}
}

static TRANSPORT_METRICS: OnceCell<Arc<dyn TransportMetrics>> = OnceCell::new();
static NOOP_TRANSPORT_METRICS: NoopTransportMetrics = NoopTransportMetrics;

/// Installs the global transport metrics implementation.
///
/// Returns `true` if the metrics sink was installed, or `false` if it was
/// already configured.
pub fn set_transport_metrics(metrics: Arc<dyn TransportMetrics>) -> bool {
    TRANSPORT_METRICS.set(metrics).is_ok()
}

/// Returns the currently configured transport metrics sink.
pub fn transport_metrics() -> &'static dyn TransportMetrics {
    TRANSPORT_METRICS
        .get()
        .map(|arc| arc.as_ref())
        .unwrap_or(&NOOP_TRANSPORT_METRICS)
}

/// Creates a tracing span associated with the given transport operation.
pub fn span_with_transport(name: &'static str, transport: &str) -> tracing::Span {
    tracing::span!(Level::INFO, "transport", op = name, transport = transport)
}

/// Simple metrics implementation that logs via `tracing`.
#[derive(Debug, Default)]
pub struct TracingTransportMetrics;

impl TransportMetrics for TracingTransportMetrics {
    fn on_packet_received(&self, transport: &str) {
        tracing::debug!(transport, "packet received");
    }

    fn on_packet_sent(&self, transport: &str) {
        tracing::debug!(transport, "packet sent");
    }

    fn on_error(&self, transport: &str, stage: &str) {
        tracing::warn!(transport, stage, "transport error");
    }

    fn on_accept(&self, transport: &str) {
        tracing::debug!(transport, "accept");
    }

    fn on_connect(&self, transport: &str) {
        tracing::debug!(transport, "connect");
    }

    fn on_latency(&self, transport: &str, op: &str, nanos: u64) {
        tracing::debug!(transport, op, nanos, "latency");
    }
}
