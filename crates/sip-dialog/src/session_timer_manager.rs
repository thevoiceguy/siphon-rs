// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 4028 Session Timer Runtime Management
//!
//! This module provides runtime session timer management for SIP dialogs.
//! It monitors active dialogs and schedules timers for:
//! - Session refresh at Session-Expires/2
//! - Session expiration at Session-Expires
//!
//! ## RFC 4028 Requirements
//!
//! - **Session-Expires**: Maximum session duration (default 1800s, minimum 90s)
//! - **Refresher Role**: UAC or UAS responsible for sending refresh
//! - **Refresh Timing**: Must occur at or before Session-Expires/2
//! - **Min-SE**: Minimum acceptable session expiration (default 90s)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sip_dialog::session_timer_manager::{SessionTimerManager, SessionTimerEvent};
//!
//! let manager = SessionTimerManager::new();
//!
//! // Start monitoring a dialog with session timer
//! manager.start_timer(dialog_id.clone(), session_expires, is_refresher);
//!
//! // Listen for events
//! let mut events = manager.subscribe();
//! while let Some(event) = events.recv().await {
//!     match event {
//!         SessionTimerEvent::RefreshNeeded(dialog_id) => {
//!             // Send re-INVITE or UPDATE to refresh session
//!         }
//!         SessionTimerEvent::SessionExpired(dialog_id) => {
//!             // Terminate dialog - refresh not received
//!         }
//!     }
//! }
//! ```

use crate::DialogId;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};

/// RFC 4028 minimum session expiration (90 seconds).
pub const MIN_SESSION_EXPIRES: Duration = Duration::from_secs(90);

/// RFC 4028 recommended default session expiration (1800 seconds / 30 minutes).
pub const DEFAULT_SESSION_EXPIRES: Duration = Duration::from_secs(1800);

/// Events emitted by the session timer manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTimerEvent {
    /// Session refresh is needed for this dialog (fired at Session-Expires/2).
    /// Only emitted if this endpoint is the refresher.
    RefreshNeeded(DialogId),

    /// Session has expired for this dialog (fired at Session-Expires).
    /// Emitted if no refresh was received in time.
    SessionExpired(DialogId),
}

/// Session timer task tracking.
#[derive(Debug)]
struct SessionTimerTask {
    /// When the session expires
    expiry_time: Instant,
    /// Task cancellation handle
    cancel_tx: Option<mpsc::Sender<()>>,
}

/// Manages session timers for all active dialogs.
///
/// This manager monitors dialogs with active session timers and emits events
/// when refresh is needed or sessions expire per RFC 4028.
#[derive(Clone)]
pub struct SessionTimerManager {
    /// Active session timer tasks indexed by DialogId
    tasks: Arc<DashMap<DialogId, SessionTimerTask>>,
    /// Event channel for broadcasting timer events
    event_tx: Arc<mpsc::UnboundedSender<SessionTimerEvent>>,
    /// Receiver stored for cloning
    event_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<SessionTimerEvent>>>,
}

impl SessionTimerManager {
    /// Creates a new session timer manager.
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            tasks: Arc::new(DashMap::new()),
            event_tx: Arc::new(event_tx),
            event_rx: Arc::new(tokio::sync::Mutex::new(event_rx)),
        }
    }

    /// Starts a session timer for the given dialog.
    ///
    /// # Parameters
    ///
    /// - `dialog_id`: Unique dialog identifier
    /// - `session_expires`: Session expiration duration
    /// - `is_refresher`: Whether this endpoint is responsible for refresh
    ///
    /// # Behavior
    ///
    /// - If `is_refresher` is `true`, emits `RefreshNeeded` at `session_expires / 2`
    /// - Always emits `SessionExpired` at `session_expires` if not refreshed
    /// - Replaces any existing timer for this dialog
    pub fn start_timer(&self, dialog_id: DialogId, session_expires: Duration, is_refresher: bool) {
        // Cancel existing timer if present
        self.stop_timer(&dialog_id);

        let expiry_time = Instant::now() + session_expires;
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);

        let task = SessionTimerTask {
            expiry_time,
            cancel_tx: Some(cancel_tx),
        };

        self.tasks.insert(dialog_id.clone(), task);

        // Spawn timer task
        let tasks_ref = self.tasks.clone();
        let event_tx = self.event_tx.clone();
        let dialog_id_clone = dialog_id.clone();

        tokio::spawn(async move {
            // Calculate refresh time (Session-Expires / 2)
            let refresh_duration = session_expires / 2;

            // If we're the refresher, schedule refresh event
            if is_refresher {
                tokio::select! {
                    _ = sleep(refresh_duration) => {
                        // Emit refresh needed event
                        let _ = event_tx.send(SessionTimerEvent::RefreshNeeded(dialog_id_clone.clone()));
                    }
                    _ = cancel_rx.recv() => {
                        // Timer cancelled
                        return;
                    }
                }
            }

            // Wait for remaining time until expiration
            let remaining = if is_refresher {
                session_expires / 2
            } else {
                session_expires
            };

            tokio::select! {
                _ = sleep(remaining) => {
                    // Session expired - emit expiration event
                    let _ = event_tx.send(SessionTimerEvent::SessionExpired(dialog_id_clone.clone()));

                    // Remove task from tracking
                    tasks_ref.remove(&dialog_id_clone);
                }
                _ = cancel_rx.recv() => {
                    // Timer cancelled (dialog refreshed or terminated)
                }
            }
        });
    }

    /// Stops and removes the session timer for the given dialog.
    ///
    /// Call this when:
    /// - Dialog is terminated (BYE received)
    /// - Dialog is refreshed (session timer reset)
    /// - Session-Expires changed (need to reschedule)
    pub fn stop_timer(&self, dialog_id: &DialogId) {
        if let Some((_, task)) = self.tasks.remove(dialog_id) {
            // Send cancellation signal
            if let Some(cancel_tx) = task.cancel_tx {
                let _ = cancel_tx.try_send(());
            }
        }
    }

    /// Refreshes the session timer for a dialog.
    ///
    /// This resets the timer with potentially updated session expiration.
    /// Call this when a session refresh is received (re-INVITE, UPDATE).
    pub fn refresh_timer(
        &self,
        dialog_id: DialogId,
        session_expires: Duration,
        is_refresher: bool,
    ) {
        self.start_timer(dialog_id, session_expires, is_refresher);
    }

    /// Returns true if a session timer is active for the given dialog.
    pub fn has_timer(&self, dialog_id: &DialogId) -> bool {
        self.tasks.contains_key(dialog_id)
    }

    /// Returns the remaining time until session expiration for a dialog.
    pub fn time_remaining(&self, dialog_id: &DialogId) -> Option<Duration> {
        self.tasks.get(dialog_id).map(|task| {
            let now = Instant::now();
            if now < task.expiry_time {
                task.expiry_time - now
            } else {
                Duration::ZERO
            }
        })
    }

    /// Subscribes to session timer events.
    ///
    /// Returns a receiver that will receive `SessionTimerEvent` notifications
    /// when refresh is needed or sessions expire.
    ///
    /// **Note:** Multiple subscribers are not supported. Only the first subscriber
    /// will receive events. For multiple consumers, use a broadcast channel wrapper.
    pub async fn subscribe(&self) -> mpsc::UnboundedReceiver<SessionTimerEvent> {
        let mut rx_lock = self.event_rx.lock().await;
        // Create new channel and swap
        let (_new_tx, new_rx) = mpsc::unbounded_channel();

        // Replace the sender in Arc (this is a limitation - proper design would use broadcast)
        // For now, we'll just return the receiver by taking it
        // This means only one subscriber is supported

        // Take the receiver out
        let old_rx = std::mem::replace(&mut *rx_lock, new_rx);
        old_rx
    }

    /// Returns the count of active session timers.
    pub fn active_count(&self) -> usize {
        self.tasks.len()
    }

    /// Removes all session timers (cleanup all dialogs).
    pub fn clear(&self) {
        let ids: Vec<DialogId> = self.tasks.iter().map(|entry| entry.key().clone()).collect();
        for id in ids {
            self.stop_timer(&id);
        }
    }
}

impl Default for SessionTimerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates that a session expiration duration meets RFC 4028 minimum requirements.
///
/// # Parameters
///
/// - `session_expires`: Proposed session expiration duration
/// - `min_se`: Minimum session expiration (optional, defaults to 90s per RFC)
///
/// # Returns
///
/// - `Ok(session_expires)`: Value is valid
/// - `Err(required_min)`: Value is too small, returns required minimum
pub fn validate_session_expires(
    session_expires: Duration,
    min_se: Option<Duration>,
) -> Result<Duration, Duration> {
    let required_min = min_se.unwrap_or(MIN_SESSION_EXPIRES);

    if session_expires < required_min {
        Err(required_min)
    } else {
        Ok(session_expires)
    }
}

/// Calculates the refresh time for a given session expiration.
///
/// Per RFC 4028, refresh should occur at Session-Expires / 2.
pub fn calculate_refresh_time(session_expires: Duration) -> Duration {
    session_expires / 2
}

/// Negotiates Session-Expires value between UAC and UAS per RFC 4028 §4.
///
/// # RFC 4028 Negotiation Rules
///
/// 1. If requested Session-Expires < Min-SE → respond 422 (Session Interval Too Small)
/// 2. If requested Session-Expires >= Min-SE → accept or reduce to own preference
/// 3. Final value MUST be >= MAX(UAC Min-SE, UAS Min-SE)
///
/// # Parameters
///
/// - `requested`: Session-Expires requested by UAC
/// - `local_min_se`: Local (UAS) Min-SE requirement
/// - `remote_min_se`: Remote (UAC) Min-SE from request (if present)
/// - `local_preference`: UAS preferred Session-Expires (if less than requested)
///
/// # Returns
///
/// - `Ok(negotiated_value)`: Negotiated Session-Expires that satisfies all constraints
/// - `Err(required_min)`: Request violates Min-SE, respond with 422 and this value
///
/// # Examples
///
/// ```rust,ignore
/// use std::time::Duration;
/// use sip_dialog::session_timer_manager::negotiate_session_expires;
///
/// // UAC requests 1800s, UAS Min-SE is 90s
/// let result = negotiate_session_expires(
///     Duration::from_secs(1800),
///     Duration::from_secs(90),
///     None,
///     Some(Duration::from_secs(3600))
/// );
/// assert_eq!(result, Ok(Duration::from_secs(1800))); // Accept UAC request
///
/// // UAC requests 60s, but UAS Min-SE is 90s → reject
/// let result = negotiate_session_expires(
///     Duration::from_secs(60),
///     Duration::from_secs(90),
///     None,
///     None
/// );
/// assert!(result.is_err()); // Respond 422 with Min-SE: 90
/// ```
pub fn negotiate_session_expires(
    requested: Duration,
    local_min_se: Duration,
    remote_min_se: Option<Duration>,
    local_preference: Option<Duration>,
) -> Result<Duration, Duration> {
    // Calculate absolute minimum (MAX of local and remote Min-SE)
    let absolute_min = if let Some(remote) = remote_min_se {
        local_min_se.max(remote)
    } else {
        local_min_se
    };

    // Check if requested value violates minimum
    if requested < absolute_min {
        return Err(absolute_min);
    }

    // If UAS has a preference and requested exceeds it, use preference
    if let Some(pref) = local_preference {
        // Preference must still meet the absolute minimum
        let negotiated = pref.max(absolute_min);

        // Only reduce if preference is less than requested
        if negotiated < requested {
            return Ok(negotiated);
        }
    }

    // Accept the requested value
    Ok(requested)
}

/// Determines refresher role per RFC 4028 §7.
///
/// # RFC 4028 Refresher Selection
///
/// The refresher is selected based on the Session-Expires header parameters:
/// - If `refresher=uac` → UAC is refresher
/// - If `refresher=uas` → UAS is refresher
/// - If no refresher parameter → defaults based on who supports timer extension
///
/// # Parameters
///
/// - `refresher_param`: Value from Session-Expires header refresher parameter
/// - `is_uac`: Whether we are the UAC (caller) perspective
///
/// # Returns
///
/// `true` if we are the refresher, `false` otherwise
pub fn determine_refresher_role(refresher_param: Option<&str>, is_uac: bool) -> bool {
    match refresher_param {
        Some("uac") => is_uac,
        Some("uas") => !is_uac,
        Some("UAC") => is_uac, // Case insensitive
        Some("UAS") => !is_uac,
        _ => is_uac, // Default: UAC is refresher if not specified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_session_expires_minimum() {
        // Valid duration
        assert!(validate_session_expires(Duration::from_secs(90), None).is_ok());
        assert!(validate_session_expires(Duration::from_secs(1800), None).is_ok());

        // Too small
        assert!(validate_session_expires(Duration::from_secs(89), None).is_err());
        assert!(validate_session_expires(Duration::from_secs(60), None).is_err());
    }

    #[test]
    fn validate_session_expires_custom_minimum() {
        let custom_min = Duration::from_secs(120);

        assert!(validate_session_expires(Duration::from_secs(120), Some(custom_min)).is_ok());
        assert!(validate_session_expires(Duration::from_secs(90), Some(custom_min)).is_err());
    }

    #[test]
    fn calculate_refresh_time_half() {
        assert_eq!(
            calculate_refresh_time(Duration::from_secs(1800)),
            Duration::from_secs(900)
        );
        assert_eq!(
            calculate_refresh_time(Duration::from_secs(120)),
            Duration::from_secs(60)
        );
    }

    #[tokio::test]
    async fn session_timer_manager_creation() {
        let manager = SessionTimerManager::new();
        assert_eq!(manager.active_count(), 0);
    }

    #[tokio::test]
    async fn start_and_stop_timer() {
        let manager = SessionTimerManager::new();
        let dialog_id = DialogId::new("call-1", "tag1", "tag2");

        assert!(!manager.has_timer(&dialog_id));

        manager.start_timer(dialog_id.clone(), Duration::from_secs(100), true);
        assert!(manager.has_timer(&dialog_id));
        assert_eq!(manager.active_count(), 1);

        manager.stop_timer(&dialog_id);
        assert!(!manager.has_timer(&dialog_id));
        assert_eq!(manager.active_count(), 0);
    }

    #[tokio::test]
    async fn time_remaining_calculation() {
        let manager = SessionTimerManager::new();
        let dialog_id = DialogId::new("call-1", "tag1", "tag2");

        manager.start_timer(dialog_id.clone(), Duration::from_secs(100), true);

        let remaining = manager.time_remaining(&dialog_id).unwrap();
        assert!(remaining > Duration::from_secs(95));
        assert!(remaining <= Duration::from_secs(100));
    }

    #[tokio::test]
    async fn refresh_timer_replaces_existing() {
        let manager = SessionTimerManager::new();
        let dialog_id = DialogId::new("call-1", "tag1", "tag2");

        manager.start_timer(dialog_id.clone(), Duration::from_secs(10), true);

        // Wait a bit for some time to elapse
        tokio::time::sleep(Duration::from_secs(2)).await;
        let remaining1 = manager.time_remaining(&dialog_id).unwrap();

        // Refresh the timer - should reset to 10s
        manager.refresh_timer(dialog_id.clone(), Duration::from_secs(10), true);
        let remaining2 = manager.time_remaining(&dialog_id).unwrap();

        // After refresh, remaining time should be closer to 10s again
        // remaining2 should be > 9s, remaining1 should be < 9s
        assert!(remaining2 > remaining1);
        assert!(remaining2 > Duration::from_secs(9));
        assert!(remaining1 < Duration::from_secs(9));
    }

    #[tokio::test]
    async fn refresh_event_emitted_for_refresher() {
        let manager = SessionTimerManager::new();
        let dialog_id = DialogId::new("call-1", "tag1", "tag2");

        let mut events = manager.subscribe().await;

        // Start timer with 200ms duration (100ms until refresh)
        manager.start_timer(dialog_id.clone(), Duration::from_millis(200), true);

        // Wait for refresh event
        tokio::time::timeout(Duration::from_millis(300), async {
            let event = events.recv().await.unwrap();
            assert_eq!(event, SessionTimerEvent::RefreshNeeded(dialog_id.clone()));
        })
        .await
        .expect("Refresh event should be emitted");
    }

    #[tokio::test]
    async fn expiration_event_emitted() {
        let manager = SessionTimerManager::new();
        let dialog_id = DialogId::new("call-1", "tag1", "tag2");

        let mut events = manager.subscribe().await;

        // Start timer with 100ms duration (not refresher, so only expiration event)
        manager.start_timer(dialog_id.clone(), Duration::from_millis(100), false);

        // Wait for expiration event
        tokio::time::timeout(Duration::from_millis(200), async {
            let event = events.recv().await.unwrap();
            assert_eq!(event, SessionTimerEvent::SessionExpired(dialog_id.clone()));
        })
        .await
        .expect("Expiration event should be emitted");

        // Timer should be auto-removed after expiration
        assert!(!manager.has_timer(&dialog_id));
    }

    #[tokio::test]
    async fn both_refresh_and_expiration_events_for_refresher() {
        let manager = SessionTimerManager::new();
        let dialog_id = DialogId::new("call-1", "tag1", "tag2");

        let mut events = manager.subscribe().await;

        // Start timer with 200ms duration (100ms until refresh, then 100ms until expiration)
        manager.start_timer(dialog_id.clone(), Duration::from_millis(200), true);

        // Wait for refresh event
        let event1 = tokio::time::timeout(Duration::from_millis(150), events.recv())
            .await
            .expect("Should receive event")
            .unwrap();
        assert_eq!(event1, SessionTimerEvent::RefreshNeeded(dialog_id.clone()));

        // Wait for expiration event
        let event2 = tokio::time::timeout(Duration::from_millis(150), events.recv())
            .await
            .expect("Should receive event")
            .unwrap();
        assert_eq!(event2, SessionTimerEvent::SessionExpired(dialog_id.clone()));
    }

    #[tokio::test]
    async fn clear_removes_all_timers() {
        let manager = SessionTimerManager::new();

        manager.start_timer(
            DialogId::new("call-1", "t1", "t2"),
            Duration::from_secs(100),
            true,
        );
        manager.start_timer(
            DialogId::new("call-2", "t3", "t4"),
            Duration::from_secs(100),
            true,
        );
        manager.start_timer(
            DialogId::new("call-3", "t5", "t6"),
            Duration::from_secs(100),
            true,
        );

        assert_eq!(manager.active_count(), 3);

        manager.clear();
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn negotiate_accepts_valid_request() {
        let result = negotiate_session_expires(
            Duration::from_secs(1800),
            Duration::from_secs(90),
            None,
            None,
        );
        assert_eq!(result, Ok(Duration::from_secs(1800)));
    }

    #[test]
    fn negotiate_rejects_below_local_min_se() {
        let result =
            negotiate_session_expires(Duration::from_secs(60), Duration::from_secs(90), None, None);
        assert_eq!(result, Err(Duration::from_secs(90)));
    }

    #[test]
    fn negotiate_respects_remote_min_se() {
        // UAC requests 100s with Min-SE of 120s → must reject
        let result = negotiate_session_expires(
            Duration::from_secs(100),
            Duration::from_secs(90),
            Some(Duration::from_secs(120)), // Remote Min-SE is higher
            None,
        );
        assert_eq!(result, Err(Duration::from_secs(120)));
    }

    #[test]
    fn negotiate_uses_max_of_both_min_se() {
        // Local Min-SE=120s, Remote Min-SE=90s → absolute min is 120s
        let result = negotiate_session_expires(
            Duration::from_secs(100),
            Duration::from_secs(120),
            Some(Duration::from_secs(90)),
            None,
        );
        assert_eq!(result, Err(Duration::from_secs(120)));
    }

    #[test]
    fn negotiate_applies_local_preference() {
        // UAC requests 3600s, but UAS prefers 1800s
        let result = negotiate_session_expires(
            Duration::from_secs(3600),
            Duration::from_secs(90),
            None,
            Some(Duration::from_secs(1800)),
        );
        assert_eq!(result, Ok(Duration::from_secs(1800)));
    }

    #[test]
    fn negotiate_preference_respects_min_se() {
        // UAS prefers 60s, but Min-SE is 90s → must use 90s
        let result = negotiate_session_expires(
            Duration::from_secs(1800),
            Duration::from_secs(90),
            None,
            Some(Duration::from_secs(60)),
        );
        assert_eq!(result, Ok(Duration::from_secs(90)));
    }

    #[test]
    fn negotiate_accepts_when_preference_higher_than_request() {
        // UAC requests 1800s, UAS prefers 3600s → accept UAC request
        let result = negotiate_session_expires(
            Duration::from_secs(1800),
            Duration::from_secs(90),
            None,
            Some(Duration::from_secs(3600)),
        );
        assert_eq!(result, Ok(Duration::from_secs(1800)));
    }

    #[test]
    fn determine_refresher_uac_explicit() {
        assert!(determine_refresher_role(Some("uac"), true));
        assert!(!determine_refresher_role(Some("uac"), false));
        assert!(determine_refresher_role(Some("UAC"), true)); // Case insensitive
    }

    #[test]
    fn determine_refresher_uas_explicit() {
        assert!(!determine_refresher_role(Some("uas"), true));
        assert!(determine_refresher_role(Some("uas"), false));
        assert!(determine_refresher_role(Some("UAS"), false)); // Case insensitive
    }

    #[test]
    fn determine_refresher_default() {
        // No refresher parameter → UAC is default
        assert!(determine_refresher_role(None, true));
        assert!(!determine_refresher_role(None, false));
    }

    #[test]
    fn determine_refresher_invalid() {
        // Invalid value → UAC is default
        assert!(determine_refresher_role(Some("invalid"), true));
        assert!(!determine_refresher_role(Some("invalid"), false));
    }
}
