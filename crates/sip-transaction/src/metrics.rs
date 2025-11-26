//! Transaction performance metrics and monitoring.
//!
//! Provides detailed metrics collection for SIP transaction performance,
//! including transaction durations, timer behavior, and success rates.
//!
//! # Usage
//!
//! ```rust
//! use sip_transaction::metrics::{TransactionMetrics, TransportType};
//! use std::time::Duration;
//!
//! let metrics = TransactionMetrics::new();
//!
//! // Record a completed transaction
//! metrics.record_transaction_duration(
//!     TransportType::Tcp,
//!     "INVITE",
//!     Duration::from_millis(250)
//! );
//!
//! // Get statistics
//! let stats = metrics.get_stats();
//! println!("Average TCP transaction: {:?}", stats.avg_duration_by_transport.get(&TransportType::Tcp));
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use sip_core::Method;

use crate::timers::Transport;
use crate::TransactionTimer;

/// Transport type for metrics grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    Udp,
    Tcp,
    Tls,
}

impl From<Transport> for TransportType {
    fn from(t: Transport) -> Self {
        match t {
            Transport::Udp => TransportType::Udp,
            Transport::Tcp => TransportType::Tcp,
            Transport::Tls => TransportType::Tls,
        }
    }
}

/// Outcome of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionOutcome {
    /// Transaction completed successfully
    Completed,
    /// Transaction timed out (Timer B, F, or H)
    Timeout,
    /// Transport error occurred
    TransportError,
    /// Transaction was cancelled
    Cancelled,
}

/// Statistics for a specific transport type.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total number of transactions
    pub count: u64,
    /// Total duration of all transactions
    pub total_duration: Duration,
    /// Average transaction duration
    pub avg_duration: Duration,
    /// Minimum transaction duration
    pub min_duration: Option<Duration>,
    /// Maximum transaction duration
    pub max_duration: Option<Duration>,
    /// Transaction outcomes by type
    pub outcomes: HashMap<TransactionOutcome, u64>,
}

/// Timer firing statistics.
#[derive(Debug, Clone, Default)]
pub struct TimerStats {
    /// Number of times this timer has fired
    pub fire_count: u64,
    /// Total time spent in timer callbacks (if tracked)
    pub total_callback_time: Duration,
}

/// Aggregated metrics statistics.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// Statistics by transport type
    pub by_transport: HashMap<TransportType, TransportStats>,
    /// Statistics by method
    pub by_method: HashMap<String, TransportStats>,
    /// Timer firing statistics
    pub timer_stats: HashMap<TransactionTimer, TimerStats>,
    /// Total transactions tracked
    pub total_transactions: u64,
    /// Snapshot timestamp
    pub timestamp: Instant,
}

/// Internal metrics storage.
#[derive(Debug, Default)]
struct MetricsData {
    /// Transaction durations by transport
    durations_by_transport: HashMap<TransportType, Vec<Duration>>,
    /// Transaction durations by method
    durations_by_method: HashMap<String, Vec<Duration>>,
    /// Transaction outcomes by transport
    outcomes_by_transport: HashMap<TransportType, HashMap<TransactionOutcome, u64>>,
    /// Timer firing counts
    timer_fire_counts: HashMap<TransactionTimer, u64>,
    /// Total transactions
    total_count: u64,
}

/// Thread-safe transaction metrics collector.
///
/// Collects and aggregates performance metrics for SIP transactions,
/// including durations, timer behavior, and success rates.
#[derive(Debug, Clone)]
pub struct TransactionMetrics {
    data: Arc<RwLock<MetricsData>>,
}

impl TransactionMetrics {
    /// Creates a new metrics collector.
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MetricsData::default())),
        }
    }

    /// Records a transaction duration.
    pub fn record_transaction_duration(
        &self,
        transport: TransportType,
        method: &str,
        duration: Duration,
    ) {
        let mut data = self.data.write();

        // Record by transport
        data.durations_by_transport
            .entry(transport)
            .or_insert_with(Vec::new)
            .push(duration);

        // Record by method
        data.durations_by_method
            .entry(method.to_string())
            .or_insert_with(Vec::new)
            .push(duration);

        data.total_count += 1;
    }

    /// Records a transaction outcome.
    pub fn record_transaction_outcome(
        &self,
        transport: TransportType,
        outcome: TransactionOutcome,
    ) {
        let mut data = self.data.write();

        *data.outcomes_by_transport
            .entry(transport)
            .or_insert_with(HashMap::new)
            .entry(outcome)
            .or_insert(0) += 1;
    }

    /// Records a timer firing.
    pub fn record_timer_fired(&self, timer: TransactionTimer) {
        let mut data = self.data.write();
        *data.timer_fire_counts.entry(timer).or_insert(0) += 1;
    }

    /// Gets the current metrics snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let data = self.data.read();

        let mut by_transport = HashMap::new();
        for (transport, durations) in &data.durations_by_transport {
            by_transport.insert(*transport, calculate_stats(durations));
        }

        // Add outcomes to transport stats
        for (transport, outcomes) in &data.outcomes_by_transport {
            if let Some(stats) = by_transport.get_mut(transport) {
                stats.outcomes = outcomes.clone();
            }
        }

        let mut by_method = HashMap::new();
        for (method, durations) in &data.durations_by_method {
            by_method.insert(method.clone(), calculate_stats(durations));
        }

        let timer_stats = data.timer_fire_counts
            .iter()
            .map(|(timer, count)| {
                (*timer, TimerStats {
                    fire_count: *count,
                    total_callback_time: Duration::ZERO,
                })
            })
            .collect();

        MetricsSnapshot {
            by_transport,
            by_method,
            timer_stats,
            total_transactions: data.total_count,
            timestamp: Instant::now(),
        }
    }

    /// Resets all collected metrics.
    pub fn reset(&self) {
        let mut data = self.data.write();
        *data = MetricsData::default();
    }

    /// Gets average transaction duration for a specific transport.
    pub fn avg_duration_for_transport(&self, transport: TransportType) -> Option<Duration> {
        let data = self.data.read();
        data.durations_by_transport
            .get(&transport)
            .map(|durations| {
                if durations.is_empty() {
                    Duration::ZERO
                } else {
                    let total: Duration = durations.iter().sum();
                    total / durations.len() as u32
                }
            })
    }

    /// Gets the number of times a specific timer has fired.
    pub fn timer_fire_count(&self, timer: TransactionTimer) -> u64 {
        let data = self.data.read();
        data.timer_fire_counts.get(&timer).copied().unwrap_or(0)
    }

    /// Gets total transaction count.
    pub fn total_transactions(&self) -> u64 {
        let data = self.data.read();
        data.total_count
    }
}

impl Default for TransactionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate statistics from a list of durations.
fn calculate_stats(durations: &[Duration]) -> TransportStats {
    if durations.is_empty() {
        return TransportStats::default();
    }

    let count = durations.len() as u64;
    let total_duration: Duration = durations.iter().sum();
    let avg_duration = total_duration / durations.len() as u32;
    let min_duration = durations.iter().min().copied();
    let max_duration = durations.iter().max().copied();

    TransportStats {
        count,
        total_duration,
        avg_duration,
        min_duration,
        max_duration,
        outcomes: HashMap::new(),
    }
}

/// Helper to track a transaction's lifecycle for automatic metrics recording.
pub struct TransactionTracker {
    metrics: TransactionMetrics,
    transport: TransportType,
    method: String,
    start_time: Instant,
}

impl TransactionTracker {
    /// Creates a new transaction tracker.
    pub fn new(metrics: TransactionMetrics, transport: TransportType, method: Method) -> Self {
        Self {
            metrics,
            transport,
            method: format!("{:?}", method),
            start_time: Instant::now(),
        }
    }

    /// Records the transaction completion.
    pub fn complete(self, outcome: TransactionOutcome) {
        let duration = self.start_time.elapsed();
        self.metrics.record_transaction_duration(
            self.transport,
            &self.method,
            duration,
        );
        self.metrics.record_transaction_outcome(self.transport, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_transaction_duration() {
        let metrics = TransactionMetrics::new();

        metrics.record_transaction_duration(
            TransportType::Tcp,
            "INVITE",
            Duration::from_millis(100),
        );
        metrics.record_transaction_duration(
            TransportType::Tcp,
            "INVITE",
            Duration::from_millis(200),
        );

        let avg = metrics.avg_duration_for_transport(TransportType::Tcp).unwrap();
        assert_eq!(avg, Duration::from_millis(150));
    }

    #[test]
    fn records_timer_firings() {
        let metrics = TransactionMetrics::new();

        metrics.record_timer_fired(TransactionTimer::E);
        metrics.record_timer_fired(TransactionTimer::E);
        metrics.record_timer_fired(TransactionTimer::F);

        assert_eq!(metrics.timer_fire_count(TransactionTimer::E), 2);
        assert_eq!(metrics.timer_fire_count(TransactionTimer::F), 1);
        assert_eq!(metrics.timer_fire_count(TransactionTimer::K), 0);
    }

    #[test]
    fn calculates_snapshot_correctly() {
        let metrics = TransactionMetrics::new();

        metrics.record_transaction_duration(
            TransportType::Udp,
            "OPTIONS",
            Duration::from_secs(1),
        );
        metrics.record_transaction_duration(
            TransportType::Tcp,
            "OPTIONS",
            Duration::from_millis(100),
        );
        metrics.record_transaction_outcome(TransportType::Udp, TransactionOutcome::Completed);
        metrics.record_timer_fired(TransactionTimer::K);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.total_transactions, 2);
        assert_eq!(snapshot.by_transport.len(), 2);
        assert_eq!(snapshot.by_method.len(), 1);
        assert_eq!(snapshot.timer_stats.len(), 1);
    }

    #[test]
    fn tracks_min_max_durations() {
        let metrics = TransactionMetrics::new();

        metrics.record_transaction_duration(
            TransportType::Tcp,
            "INVITE",
            Duration::from_millis(50),
        );
        metrics.record_transaction_duration(
            TransportType::Tcp,
            "INVITE",
            Duration::from_millis(300),
        );
        metrics.record_transaction_duration(
            TransportType::Tcp,
            "INVITE",
            Duration::from_millis(150),
        );

        let snapshot = metrics.snapshot();
        let tcp_stats = snapshot.by_transport.get(&TransportType::Tcp).unwrap();

        assert_eq!(tcp_stats.min_duration, Some(Duration::from_millis(50)));
        assert_eq!(tcp_stats.max_duration, Some(Duration::from_millis(300)));
        // Average of 50, 300, 150 = 500/3 = 166.666... ms
        assert!(tcp_stats.avg_duration >= Duration::from_millis(166));
        assert!(tcp_stats.avg_duration < Duration::from_millis(167));
    }

    #[test]
    fn reset_clears_all_metrics() {
        let metrics = TransactionMetrics::new();

        metrics.record_transaction_duration(
            TransportType::Udp,
            "REGISTER",
            Duration::from_secs(1),
        );
        metrics.record_timer_fired(TransactionTimer::E);

        assert_eq!(metrics.total_transactions(), 1);

        metrics.reset();

        assert_eq!(metrics.total_transactions(), 0);
        assert_eq!(metrics.timer_fire_count(TransactionTimer::E), 0);
    }

    #[test]
    fn transaction_tracker_lifecycle() {
        let metrics = TransactionMetrics::new();

        let tracker = TransactionTracker::new(
            metrics.clone(),
            TransportType::Tcp,
            Method::Invite,
        );

        std::thread::sleep(Duration::from_millis(10));
        tracker.complete(TransactionOutcome::Completed);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_transactions, 1);

        let tcp_stats = snapshot.by_transport.get(&TransportType::Tcp).unwrap();
        assert!(tcp_stats.avg_duration >= Duration::from_millis(10));
        assert_eq!(tcp_stats.outcomes.get(&TransactionOutcome::Completed), Some(&1));
    }
}
