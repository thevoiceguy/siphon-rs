// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Prometheus-compatible `/metrics` plus k8s `/health` and `/ready` endpoints.
//!
//! Kept deliberately dependency-free — three HTTP/1.1 GET routes don't
//! warrant pulling in hyper or axum. The server reads until the first
//! `\r\n\r\n`, dispatches on the path, and writes a canned response.
//! Per-connection limits prevent a hostile scraper from holding the
//! socket open forever.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use sip_transaction::metrics::{TransactionMetrics, TransactionOutcome, TransportType};

/// Maximum HTTP request size we'll accept — plenty for `GET /metrics
/// HTTP/1.1\r\nHost: ...\r\n\r\n` plus a few headers.
const MAX_REQUEST_SIZE: usize = 8 * 1024;

/// Hard limit on how long a single client can hog the listener.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared state the metrics server snapshots on every `/metrics` hit.
///
/// Cloning is cheap (arcs + atomics); the server is expected to live
/// for the lifetime of the daemon so we don't worry about shutdown.
#[derive(Clone)]
pub struct MetricsState {
    pub transactions: Arc<TransactionMetrics>,
    /// Flipped to `true` by main() once transports are bound and
    /// handlers registered. `/ready` returns 503 until then so a
    /// load balancer won't route traffic to a half-initialised
    /// instance.
    pub ready: Arc<AtomicBool>,
    pub started_at: Instant,
}

impl MetricsState {
    pub fn new(transactions: Arc<TransactionMetrics>) -> Self {
        Self {
            transactions,
            ready: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
        }
    }

    /// Returns a clone of the readiness flag so the daemon can flip
    /// it atomically from main() without holding a mutable reference.
    pub fn ready_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.ready)
    }
}

/// Spawn the HTTP metrics/health server bound to `addr`. Returns the
/// bound address (useful for tests that pass port 0) and a handle to
/// the accept loop.
pub async fn spawn_metrics_server(
    addr: SocketAddr,
    state: MetricsState,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    info!(%bound, "metrics HTTP server listening");

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &state).await {
                            debug!(%peer, error = %e, "metrics HTTP connection ended with error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "metrics listener accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });

    Ok((bound, handle))
}

async fn handle_connection(mut stream: TcpStream, state: &MetricsState) -> Result<()> {
    let mut buf = Vec::with_capacity(512);
    let read_future = async {
        let mut tmp = [0u8; 1024];
        loop {
            if buf.len() >= MAX_REQUEST_SIZE {
                anyhow::bail!("request too large");
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        anyhow::Ok(())
    };
    tokio::time::timeout(READ_TIMEOUT, read_future).await??;

    let request_line = std::str::from_utf8(&buf)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let (status, content_type, body) = match path {
        // Trim query string — Prometheus sometimes appends `?` params.
        p if p.starts_with("/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_metrics(state),
        ),
        "/health" | "/healthz" | "/livez" => ("200 OK", "text/plain", "ok\n".to_string()),
        "/ready" | "/readyz" => {
            if state.ready.load(Ordering::Acquire) {
                ("200 OK", "text/plain", "ready\n".to_string())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain",
                    "not ready\n".to_string(),
                )
            }
        }
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Render the Prometheus exposition format snapshot. Format spec:
/// <https://prometheus.io/docs/instrumenting/exposition_formats/>.
fn render_metrics(state: &MetricsState) -> String {
    let snap = state.transactions.snapshot();
    let mut out = String::with_capacity(2048);

    // --- process-level ----------------------------------------------------
    out.push_str(
        "# HELP siphond_uptime_seconds Seconds since the daemon started.\n\
         # TYPE siphond_uptime_seconds gauge\n",
    );
    out.push_str(&format!(
        "siphond_uptime_seconds {}\n",
        state.started_at.elapsed().as_secs_f64()
    ));

    out.push_str(
        "# HELP siphond_ready Whether readiness probes should return 200.\n\
         # TYPE siphond_ready gauge\n",
    );
    out.push_str(&format!(
        "siphond_ready {}\n",
        if state.ready.load(Ordering::Acquire) {
            1
        } else {
            0
        }
    ));

    // --- transactions totals ----------------------------------------------
    out.push_str(
        "# HELP siphond_transactions_total Total transactions observed by the manager.\n\
         # TYPE siphond_transactions_total counter\n",
    );
    out.push_str(&format!(
        "siphond_transactions_total {}\n",
        snap.total_transactions
    ));

    // --- starts / completes by transport + method + role -----------------
    out.push_str(
        "# HELP siphond_transaction_starts_total Transactions started.\n\
         # TYPE siphond_transaction_starts_total counter\n",
    );
    for (transport, count) in &snap.starts_by_transport {
        out.push_str(&format!(
            "siphond_transaction_starts_total{{transport=\"{}\"}} {}\n",
            transport_label(*transport),
            count,
        ));
    }

    out.push_str(
        "# HELP siphond_transaction_completes_total Transactions that reached terminal state.\n\
         # TYPE siphond_transaction_completes_total counter\n",
    );
    for (transport, count) in &snap.completes_by_transport {
        out.push_str(&format!(
            "siphond_transaction_completes_total{{transport=\"{}\"}} {}\n",
            transport_label(*transport),
            count,
        ));
    }

    // --- outcomes ---------------------------------------------------------
    out.push_str(
        "# HELP siphond_transaction_outcomes_total Transaction outcomes by transport + outcome.\n\
         # TYPE siphond_transaction_outcomes_total counter\n",
    );
    for (transport, stats) in &snap.by_transport {
        for (outcome, count) in &stats.outcomes {
            out.push_str(&format!(
                "siphond_transaction_outcomes_total{{transport=\"{}\",outcome=\"{}\"}} {}\n",
                transport_label(*transport),
                outcome_label(*outcome),
                count,
            ));
        }
    }

    // --- durations -------------------------------------------------------
    // Prometheus convention: mean is easily derived from _sum / _count.
    out.push_str(
        "# HELP siphond_transaction_duration_seconds Transaction duration observations per transport.\n\
         # TYPE siphond_transaction_duration_seconds summary\n",
    );
    for (transport, stats) in &snap.by_transport {
        let label = transport_label(*transport);
        out.push_str(&format!(
            "siphond_transaction_duration_seconds_count{{transport=\"{label}\"}} {}\n",
            stats.count,
        ));
        out.push_str(&format!(
            "siphond_transaction_duration_seconds_sum{{transport=\"{label}\"}} {}\n",
            stats.total_duration.as_secs_f64(),
        ));
        if let Some(min) = stats.min_duration {
            out.push_str(&format!(
                "siphond_transaction_duration_seconds{{transport=\"{label}\",quantile=\"min\"}} {}\n",
                min.as_secs_f64(),
            ));
        }
        if let Some(max) = stats.max_duration {
            out.push_str(&format!(
                "siphond_transaction_duration_seconds{{transport=\"{label}\",quantile=\"max\"}} {}\n",
                max.as_secs_f64(),
            ));
        }
    }

    // --- retransmissions / auth retries ----------------------------------
    out.push_str(
        "# HELP siphond_retransmissions_total UDP retransmit counts by transport.\n\
         # TYPE siphond_retransmissions_total counter\n",
    );
    for (transport, count) in &snap.retransmissions {
        out.push_str(&format!(
            "siphond_retransmissions_total{{transport=\"{}\"}} {}\n",
            transport_label(*transport),
            count,
        ));
    }

    out.push_str(
        "# HELP siphond_auth_retries_total Client transactions that retried after 401/407.\n\
         # TYPE siphond_auth_retries_total counter\n",
    );
    out.push_str(&format!(
        "siphond_auth_retries_total {}\n",
        snap.auth_retries
    ));

    // --- DoS rejections --------------------------------------------------
    out.push_str(
        "# HELP siphond_transactions_rejected_total Transactions rejected due to per-manager limits.\n\
         # TYPE siphond_transactions_rejected_total counter\n",
    );
    out.push_str(&format!(
        "siphond_transactions_rejected_total{{role=\"server\"}} {}\n",
        snap.server_transactions_rejected
    ));
    out.push_str(&format!(
        "siphond_transactions_rejected_total{{role=\"client\"}} {}\n",
        snap.client_transactions_rejected
    ));

    out
}

fn transport_label(t: TransportType) -> &'static str {
    match t {
        TransportType::Udp => "udp",
        TransportType::Tcp => "tcp",
        TransportType::Tls => "tls",
    }
}

fn outcome_label(o: TransactionOutcome) -> &'static str {
    match o {
        TransactionOutcome::Completed => "completed",
        TransactionOutcome::Timeout => "timeout",
        TransactionOutcome::TransportError => "transport_error",
        TransactionOutcome::Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_transaction::metrics::{TransactionRole, TransportType};

    async fn spawn_test_server() -> (SocketAddr, MetricsState) {
        let metrics = Arc::new(TransactionMetrics::new());
        let state = MetricsState::new(Arc::clone(&metrics));
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (addr, _handle) = spawn_metrics_server(bind, state.clone()).await.unwrap();
        (addr, state)
    }

    async fn scrape(addr: SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status_line = head.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, body.to_string())
    }

    #[tokio::test]
    async fn health_endpoint_returns_200_always() {
        let (addr, _state) = spawn_test_server().await;
        let (status, body) = scrape(addr, "/health").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok\n");
    }

    #[tokio::test]
    async fn ready_returns_503_until_flag_flipped() {
        let (addr, state) = spawn_test_server().await;
        let (status, body) = scrape(addr, "/ready").await;
        assert_eq!(status, 503);
        assert!(body.contains("not ready"));

        state.ready.store(true, Ordering::Release);
        let (status, body) = scrape(addr, "/ready").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ready\n");
    }

    #[tokio::test]
    async fn metrics_endpoint_emits_prometheus_format() {
        let (addr, state) = spawn_test_server().await;
        // Plant some state so the render covers multiple branches.
        state
            .transactions
            .record_start(TransportType::Udp, "INVITE", TransactionRole::Client);
        state.transactions.record_transaction_duration(
            TransportType::Udp,
            "INVITE",
            Duration::from_millis(450),
        );
        state
            .transactions
            .record_transaction_outcome(TransportType::Udp, TransactionOutcome::Completed);

        let (status, body) = scrape(addr, "/metrics").await;
        assert_eq!(status, 200);

        // Must look like Prometheus text format.
        assert!(body.contains("# HELP siphond_uptime_seconds"));
        assert!(body.contains("# TYPE siphond_transaction_starts_total counter"));
        assert!(body.contains("siphond_transaction_starts_total{transport=\"udp\"} 1"));
        assert!(body.contains(
            "siphond_transaction_outcomes_total{transport=\"udp\",outcome=\"completed\"} 1"
        ));
        assert!(body.contains("siphond_transaction_duration_seconds_count{transport=\"udp\"} 1"));
    }

    #[tokio::test]
    async fn metrics_endpoint_handles_query_string() {
        // Some Prometheus scrapers append `?collect=all`.
        let (addr, _state) = spawn_test_server().await;
        let (status, _body) = scrape(addr, "/metrics?collect=all").await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (addr, _state) = spawn_test_server().await;
        let (status, _body) = scrape(addr, "/bogus").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn oversized_request_rejected() {
        // Send > MAX_REQUEST_SIZE without terminating `\r\n\r\n` —
        // the server must close instead of reading forever.
        let (addr, _state) = spawn_test_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let huge = vec![b'X'; MAX_REQUEST_SIZE + 1024];
        let _ = stream.write_all(&huge).await;
        let mut buf = Vec::new();
        // read_to_end returns once the server drops the connection;
        // we just need to prove it eventually does, not time out.
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    }
}
