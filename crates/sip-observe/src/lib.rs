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
//! use sip_observe::{set_transport_metrics, RateLimitedTracingTransportMetrics};
//! use std::sync::Arc;
//! set_transport_metrics(Arc::new(RateLimitedTracingTransportMetrics::default()));
//! // Metrics automatically emitted via tracing events
//! ```

use once_cell::sync::OnceCell;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::Level;

/// Maximum length for transport identifiers emitted via tracing metrics.
pub const MAX_LABEL_LEN: usize = 64;

/// Metrics sink used by transports to emit observability events.
///
/// Implementations should treat `transport`, `stage`, and `op` as low-cardinality
/// identifiers (e.g., "udp", "accept", "read") and avoid propagating untrusted
/// or high-cardinality data into metrics/logs. Prefer the provided label enums,
/// apply length limits, and avoid encoding internal identifiers that could
/// disclose topology or configuration details. Production implementations
/// should also consider sampling or rate limiting to avoid hot loops flooding
/// the metrics backend.
pub trait TransportMetrics: Send + Sync + 'static {
    fn on_packet_received(&self, transport: TransportLabel);
    fn on_packet_sent(&self, transport: TransportLabel);
    fn on_error(&self, transport: TransportLabel, stage: StageLabel);
    fn on_accept(&self, transport: TransportLabel);
    fn on_connect(&self, transport: TransportLabel);
    fn on_latency(&self, transport: TransportLabel, op: OpLabel, nanos: u64);
}

#[derive(Debug, Default)]
struct NoopTransportMetrics;

impl TransportMetrics for NoopTransportMetrics {
    fn on_packet_received(&self, _transport: TransportLabel) {}
    fn on_packet_sent(&self, _transport: TransportLabel) {}
    fn on_error(&self, _transport: TransportLabel, _stage: StageLabel) {}
    fn on_accept(&self, _transport: TransportLabel) {}
    fn on_connect(&self, _transport: TransportLabel) {}
    fn on_latency(&self, _transport: TransportLabel, _op: OpLabel, _nanos: u64) {}
}

static TRANSPORT_METRICS: OnceCell<Arc<dyn TransportMetrics>> = OnceCell::new();
static NOOP_TRANSPORT_METRICS: NoopTransportMetrics = NoopTransportMetrics;

/// Installs the global transport metrics implementation.
///
/// Returns `true` if the metrics sink was installed, or `false` if it was
/// already configured.
#[must_use]
pub fn set_transport_metrics(metrics: Arc<dyn TransportMetrics>) -> bool {
    if TRANSPORT_METRICS.set(metrics).is_ok() {
        true
    } else {
        tracing::warn!("transport metrics already configured");
        false
    }
}

/// Returns the currently configured transport metrics sink.
pub fn transport_metrics() -> &'static dyn TransportMetrics {
    TRANSPORT_METRICS
        .get()
        .map(|arc| arc.as_ref())
        .unwrap_or(&NOOP_TRANSPORT_METRICS)
}

/// Creates a tracing span associated with the given transport operation.
pub fn span_with_transport(name: &'static str, transport: TransportLabel) -> tracing::Span {
    tracing::span!(Level::INFO, "transport", op = name, transport = %transport)
}

/// Simple metrics implementation that logs via `tracing`.
///
/// Prefer `RateLimitedTracingTransportMetrics` in production to avoid flooding
/// log sinks.
#[derive(Debug, Default)]
pub struct TracingTransportMetrics;

impl TransportMetrics for TracingTransportMetrics {
    fn on_packet_received(&self, transport: TransportLabel) {
        tracing::debug!(transport = %transport, "packet received");
    }

    fn on_packet_sent(&self, transport: TransportLabel) {
        tracing::debug!(transport = %transport, "packet sent");
    }

    fn on_error(&self, transport: TransportLabel, stage: StageLabel) {
        tracing::warn!(transport = %transport, stage = %stage, "transport error");
    }

    fn on_accept(&self, transport: TransportLabel) {
        tracing::debug!(transport = %transport, "accept");
    }

    fn on_connect(&self, transport: TransportLabel) {
        tracing::debug!(transport = %transport, "connect");
    }

    fn on_latency(&self, transport: TransportLabel, op: OpLabel, nanos: u64) {
        tracing::debug!(transport = %transport, op = %op, nanos, "latency");
    }
}

/// Rate-limited metrics implementation that emits via `tracing`.
///
/// The default configuration samples every 10th event and enforces a 5ms
/// minimum interval between emissions.
#[derive(Debug)]
pub struct RateLimitedTracingTransportMetrics {
    min_interval: Duration,
    sample_every: NonZeroU64,
    last_emit_ns: AtomicU64,
    counter: AtomicU64,
}

impl RateLimitedTracingTransportMetrics {
    pub fn new(min_interval: Duration, sample_every: NonZeroU64) -> Self {
        Self {
            min_interval,
            sample_every,
            last_emit_ns: AtomicU64::new(0),
            counter: AtomicU64::new(0),
        }
    }

    fn should_emit(&self) -> bool {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        if !count.is_multiple_of(self.sample_every.get()) {
            return false;
        }

        let min_ns = self.min_interval.as_nanos() as u64;
        if min_ns == 0 {
            return true;
        }

        let now_ns = now_unix_ns();
        let mut last = self.last_emit_ns.load(Ordering::Relaxed);
        loop {
            if now_ns.saturating_sub(last) < min_ns {
                return false;
            }
            match self.last_emit_ns.compare_exchange(
                last,
                now_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(updated) => last = updated,
            }
        }
    }
}

impl Default for RateLimitedTracingTransportMetrics {
    fn default() -> Self {
        Self::new(Duration::from_millis(5), NonZeroU64::new(10).expect("non-zero sample rate"))
    }
}

impl TransportMetrics for RateLimitedTracingTransportMetrics {
    fn on_packet_received(&self, transport: TransportLabel) {
        if self.should_emit() {
            tracing::debug!(transport = %transport, "packet received");
        }
    }

    fn on_packet_sent(&self, transport: TransportLabel) {
        if self.should_emit() {
            tracing::debug!(transport = %transport, "packet sent");
        }
    }

    fn on_error(&self, transport: TransportLabel, stage: StageLabel) {
        if self.should_emit() {
            tracing::warn!(transport = %transport, stage = %stage, "transport error");
        }
    }

    fn on_accept(&self, transport: TransportLabel) {
        if self.should_emit() {
            tracing::debug!(transport = %transport, "accept");
        }
    }

    fn on_connect(&self, transport: TransportLabel) {
        if self.should_emit() {
            tracing::debug!(transport = %transport, "connect");
        }
    }

    fn on_latency(&self, transport: TransportLabel, op: OpLabel, nanos: u64) {
        if self.should_emit() {
            tracing::debug!(transport = %transport, op = %op, nanos, "latency");
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum TransportLabel {
    Udp,
    Tcp,
    Tls,
    Sctp,
    TlsSctp,
    Ws,
    Wss,
}

impl TransportLabel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Sctp => "sctp",
            Self::TlsSctp => "tls-sctp",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
}

impl std::fmt::Display for TransportLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for TransportLabel {
    type Error = LabelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_label(value)?;
        match value {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "tls" => Ok(Self::Tls),
            "sctp" => Ok(Self::Sctp),
            "tls-sctp" => Ok(Self::TlsSctp),
            "ws" => Ok(Self::Ws),
            "wss" => Ok(Self::Wss),
            _ => Err(LabelError::UnknownValue(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum StageLabel {
    Accept,
    BufferOverflow,
    Dispatch,
    FramingError,
    Handshake,
    Read,
    Recv,
    SessionLimit,
    Truncate,
    Write,
}

impl StageLabel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::BufferOverflow => "buffer_overflow",
            Self::Dispatch => "dispatch",
            Self::FramingError => "framing_error",
            Self::Handshake => "handshake",
            Self::Read => "read",
            Self::Recv => "recv",
            Self::SessionLimit => "session_limit",
            Self::Truncate => "truncate",
            Self::Write => "write",
        }
    }
}

impl std::fmt::Display for StageLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for StageLabel {
    type Error = LabelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_label(value)?;
        match value {
            "accept" => Ok(Self::Accept),
            "buffer_overflow" => Ok(Self::BufferOverflow),
            "dispatch" => Ok(Self::Dispatch),
            "framing_error" => Ok(Self::FramingError),
            "handshake" => Ok(Self::Handshake),
            "read" => Ok(Self::Read),
            "recv" => Ok(Self::Recv),
            "session_limit" => Ok(Self::SessionLimit),
            "truncate" => Ok(Self::Truncate),
            "write" => Ok(Self::Write),
            _ => Err(LabelError::UnknownValue(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum OpLabel {
    Accept,
    Recv,
}

impl OpLabel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Recv => "recv",
        }
    }
}

impl std::fmt::Display for OpLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for OpLabel {
    type Error = LabelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_label(value)?;
        match value {
            "accept" => Ok(Self::Accept),
            "recv" => Ok(Self::Recv),
            _ => Err(LabelError::UnknownValue(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelError {
    TooLong { len: usize, max: usize },
    InvalidChar { index: usize, byte: u8 },
    UnknownValue(String),
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { len, max } => {
                write!(f, "label length {len} exceeds max {max}")
            }
            Self::InvalidChar { index, byte } => {
                write!(f, "label contains invalid byte {byte} at {index}")
            }
            Self::UnknownValue(value) => write!(f, "label value '{value}' is not recognized"),
        }
    }
}

impl std::error::Error for LabelError {}

fn validate_label(label: &str) -> Result<(), LabelError> {
    let bytes = label.as_bytes();
    if bytes.len() > MAX_LABEL_LEN {
        return Err(LabelError::TooLong {
            len: bytes.len(),
            max: MAX_LABEL_LEN,
        });
    }
    for (index, &byte) in bytes.iter().enumerate() {
        if !is_label_byte_safe(byte) {
            return Err(LabelError::InvalidChar { index, byte });
        }
    }
    Ok(())
}

fn is_label_byte_safe(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.')
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
