use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

/// Dialog-level metrics (creation, confirmation, termination, PRACK, session timers).
#[derive(Debug, Clone, Default)]
pub struct DialogMetrics {
    inner: Arc<RwLock<MetricsData>>,
}

#[derive(Debug, Default)]
struct MetricsData {
    created: u64,
    confirmed: u64,
    terminated: u64,
    prack_events: u64,
    session_timer_started: u64,
    session_timer_refreshed: u64,
    session_timer_expired: u64,
    last_updated: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
pub struct DialogMetricsSnapshot {
    pub created: u64,
    pub confirmed: u64,
    pub terminated: u64,
    pub prack_events: u64,
    pub session_timer_started: u64,
    pub session_timer_refreshed: u64,
    pub session_timer_expired: u64,
    pub last_updated: Option<Instant>,
}

impl DialogMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_created(&self) {
        let mut data = self.inner.write();
        data.created += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn record_confirmed(&self) {
        let mut data = self.inner.write();
        data.confirmed += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn record_terminated(&self) {
        let mut data = self.inner.write();
        data.terminated += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn record_prack(&self) {
        let mut data = self.inner.write();
        data.prack_events += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn record_session_timer_started(&self) {
        let mut data = self.inner.write();
        data.session_timer_started += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn record_session_timer_refreshed(&self) {
        let mut data = self.inner.write();
        data.session_timer_refreshed += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn record_session_timer_expired(&self) {
        let mut data = self.inner.write();
        data.session_timer_expired += 1;
        data.last_updated = Some(Instant::now());
    }

    pub fn snapshot(&self) -> DialogMetricsSnapshot {
        let data = self.inner.read();
        DialogMetricsSnapshot {
            created: data.created,
            confirmed: data.confirmed,
            terminated: data.terminated,
            prack_events: data.prack_events,
            session_timer_started: data.session_timer_started,
            session_timer_refreshed: data.session_timer_refreshed,
            session_timer_expired: data.session_timer_expired,
            last_updated: data.last_updated,
        }
    }
}
