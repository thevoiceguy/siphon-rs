// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Configurable rate limiting for SIP applications
//!
//! This crate provides flexible, configurable rate limiting to protect SIP services
//! from abuse, brute force attacks, and resource exhaustion.
//!
//! # Features
//!
//! - **Token bucket algorithm** - Industry-standard rate limiting with burst capacity
//! - **Per-key tracking** - Rate limit by IP address, user, AOR, etc.
//! - **Configurable limits** - Set capacity, refill rate, and cleanup intervals
//! - **Automatic cleanup** - Removes idle rate limiters to prevent memory leaks
//! - **Thread-safe** - Uses DashMap for concurrent access
//!
//! # Example
//!
//! ```
//! use sip_ratelimit::{RateLimiter, RateLimitConfig};
//!
//! // Configure rate limiter: 10 requests per minute with burst of 20
//! let config = RateLimitConfig::new(10, 60).with_burst_capacity(20).unwrap();
//! let limiter = RateLimiter::new(config);
//!
//! // Check if request is allowed
//! if limiter.check_rate_limit("192.168.1.100") {
//!     println!("Request allowed");
//! } else {
//!     println!("Rate limit exceeded");
//! }
//! ```
//!
//! # Use Cases
//!
//! - Authentication attempts (prevent brute force)
//! - REGISTER requests (prevent registration flooding)
//! - INVITE requests (prevent call flooding)
//! - Transaction creation (prevent resource exhaustion)
//! - Connection establishment (prevent connection exhaustion)

use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

// Cleanup trigger threshold
const CLEANUP_EVERY_CHECKS: u64 = 1024;

// Security constants for DoS prevention
const MAX_KEY_LENGTH: usize = 256;
const MAX_TRACKED_KEYS: usize = 100_000;
const MAX_REQUESTS_PER_WINDOW: u32 = 1_000_000;
const MAX_WINDOW_SECS: u64 = 86400; // 24 hours
const MAX_BURST_CAPACITY: u32 = 10_000;

/// Rate limit validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    /// Key too long (DoS prevention)
    KeyTooLong { max: usize, actual: usize },
    /// Key contains control characters (CRLF injection)
    KeyContainsControlChars,
    /// Too many tracked keys (DoS prevention)
    TooManyKeys { max: usize },
    /// Invalid configuration: max_requests too large
    MaxRequestsTooLarge { max: u32, actual: u32 },
    /// Invalid configuration: window_secs too large
    WindowTooLarge { max: u64, actual: u64 },
    /// Invalid configuration: burst_capacity too large
    BurstCapacityTooLarge { max: u32, actual: u32 },
    /// Invalid configuration: max_requests is zero
    MaxRequestsZero,
    /// Invalid configuration: window_secs is zero
    WindowSecsZero,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::KeyTooLong { max, actual } => {
                write!(f, "key length {} exceeds max {}", actual, max)
            }
            RateLimitError::KeyContainsControlChars => {
                write!(f, "key contains control characters (CRLF injection)")
            }
            RateLimitError::TooManyKeys { max } => {
                write!(f, "too many tracked keys (max {})", max)
            }
            RateLimitError::MaxRequestsTooLarge { max, actual } => {
                write!(f, "max_requests {} exceeds limit {}", actual, max)
            }
            RateLimitError::WindowTooLarge { max, actual } => {
                write!(f, "window_secs {} exceeds limit {}", actual, max)
            }
            RateLimitError::BurstCapacityTooLarge { max, actual } => {
                write!(f, "burst_capacity {} exceeds limit {}", actual, max)
            }
            RateLimitError::MaxRequestsZero => {
                write!(f, "max_requests cannot be zero")
            }
            RateLimitError::WindowSecsZero => {
                write!(f, "window_secs cannot be zero")
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Validates a rate limit key for length and control characters
fn validate_key(key: &str) -> Result<(), RateLimitError> {
    if key.len() > MAX_KEY_LENGTH {
        return Err(RateLimitError::KeyTooLong {
            max: MAX_KEY_LENGTH,
            actual: key.len(),
        });
    }
    if key.chars().any(|c| c.is_control()) {
        return Err(RateLimitError::KeyContainsControlChars);
    }
    Ok(())
}

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed in the time window
    max_requests: u32,

    /// Time window in seconds for max_requests
    window_secs: u64,

    /// Burst capacity (number of tokens that can accumulate)
    /// Defaults to max_requests if not specified
    burst_capacity: u32,

    /// How often to refill tokens (in milliseconds)
    /// Defaults to window_secs * 1000 / max_requests
    refill_interval_ms: u64,

    /// Number of tokens to add per refill
    tokens_per_refill: u32,

    /// How long to keep idle rate limiters before cleanup (seconds)
    idle_timeout_secs: u64,

    /// Whether rate limiting is enabled
    enabled: bool,
}

impl RateLimitConfig {
    /// Create a new rate limit configuration with validation
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests allowed in time window
    /// * `window_secs` - Time window in seconds
    ///
    /// # Example
    ///
    /// ```
    /// use sip_ratelimit::RateLimitConfig;
    ///
    /// // 10 requests per minute
    /// let config = RateLimitConfig::new(10, 60).unwrap();
    /// ```
    pub fn new(max_requests: u32, window_secs: u64) -> Result<Self, RateLimitError> {
        // Validate configuration
        if max_requests == 0 {
            return Err(RateLimitError::MaxRequestsZero);
        }
        if window_secs == 0 {
            return Err(RateLimitError::WindowSecsZero);
        }
        if max_requests > MAX_REQUESTS_PER_WINDOW {
            return Err(RateLimitError::MaxRequestsTooLarge {
                max: MAX_REQUESTS_PER_WINDOW,
                actual: max_requests,
            });
        }
        if window_secs > MAX_WINDOW_SECS {
            return Err(RateLimitError::WindowTooLarge {
                max: MAX_WINDOW_SECS,
                actual: window_secs,
            });
        }

        // Calculate refill interval: distribute tokens evenly across window
        let interval = (window_secs * 1000) / max_requests as u64;
        let refill_interval_ms = if interval == 0 { 1 } else { interval };

        Ok(Self {
            max_requests,
            window_secs,
            burst_capacity: max_requests, // Default: same as max_requests
            refill_interval_ms,
            tokens_per_refill: 1,
            idle_timeout_secs: 300, // 5 minutes default
            enabled: true,
        })
    }

    /// Public accessors
    pub fn max_requests(&self) -> u32 {
        self.max_requests
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    pub fn burst_capacity(&self) -> u32 {
        self.burst_capacity
    }

    pub fn refill_interval_ms(&self) -> u64 {
        self.refill_interval_ms
    }

    pub fn tokens_per_refill(&self) -> u32 {
        self.tokens_per_refill
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Create a disabled rate limiter (allows all requests)
    pub fn disabled() -> Self {
        Self {
            max_requests: 0,
            window_secs: 0,
            burst_capacity: 0,
            refill_interval_ms: 0,
            tokens_per_refill: 0,
            idle_timeout_secs: 0,
            enabled: false,
        }
    }

    /// Set burst capacity (how many tokens can accumulate)
    pub fn with_burst_capacity(mut self, capacity: u32) -> Result<Self, RateLimitError> {
        if capacity > MAX_BURST_CAPACITY {
            return Err(RateLimitError::BurstCapacityTooLarge {
                max: MAX_BURST_CAPACITY,
                actual: capacity,
            });
        }
        self.burst_capacity = capacity;
        Ok(self)
    }

    /// Set idle timeout for cleanup (in seconds)
    pub fn with_idle_timeout(mut self, timeout_secs: u64) -> Self {
        self.idle_timeout_secs = timeout_secs;
        self
    }

    /// Set whether rate limiting is enabled
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Preset: Authentication rate limiting (10 attempts per 5 minutes)
    pub fn auth_preset() -> Self {
        Self::new(10, 300)
            .expect("valid auth preset config")
            .with_burst_capacity(3) // Small burst allowed
            .expect("valid burst capacity")
            .with_idle_timeout(600) // 10 minute cleanup
    }

    /// Preset: Registration rate limiting (60 per hour)
    pub fn register_preset() -> Self {
        Self::new(60, 3600)
            .expect("valid register preset config")
            .with_burst_capacity(10)
            .expect("valid burst capacity")
            .with_idle_timeout(1800) // 30 minute cleanup
    }

    /// Preset: Connection rate limiting (100 per minute)
    pub fn connection_preset() -> Self {
        Self::new(100, 60)
            .expect("valid connection preset config")
            .with_burst_capacity(20)
            .expect("valid burst capacity")
            .with_idle_timeout(300)
    }

    /// Preset: INVITE rate limiting (30 per minute)
    pub fn invite_preset() -> Self {
        Self::new(30, 60)
            .expect("valid invite preset config")
            .with_burst_capacity(10)
            .expect("valid burst capacity")
            .with_idle_timeout(300)
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::new(100, 60).expect("valid default config") // 100 requests per minute
    }
}

/// Token bucket for a single key (IP, user, etc.)
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Available tokens
    tokens: f64,
    /// Last refill time
    last_refill: Instant,
    /// Last access time (for cleanup)
    last_access: Instant,
}

impl TokenBucket {
    fn new(initial_tokens: f64) -> Self {
        let now = Instant::now();
        Self {
            tokens: initial_tokens,
            last_refill: now,
            last_access: now,
        }
    }

    /// Try to consume a token
    fn try_consume(&mut self, config: &RateLimitConfig) -> bool {
        self.refill(config);
        self.last_access = Instant::now();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self, config: &RateLimitConfig) {
        if config.refill_interval_ms == 0
            || config.tokens_per_refill == 0
            || config.burst_capacity == 0
        {
            return;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let refill_interval = Duration::from_millis(config.refill_interval_ms);

        if elapsed >= refill_interval {
            let intervals = elapsed.as_millis() / config.refill_interval_ms as u128;
            let tokens_to_add = (intervals as f64) * (config.tokens_per_refill as f64);
            self.tokens = (self.tokens + tokens_to_add).min(config.burst_capacity as f64);
            self.last_refill = now;
        }
    }

    /// Check if this bucket is idle
    fn is_idle(&self, timeout: Duration) -> bool {
        self.last_access.elapsed() > timeout
    }
}

/// Metrics for rate limiter operations
#[derive(Debug, Default)]
pub struct RateLimitMetrics {
    /// Total number of rate limit checks performed
    total_checks: AtomicU64,
    /// Number of requests that were allowed
    allowed_requests: AtomicU64,
    /// Number of requests that were blocked
    blocked_requests: AtomicU64,
    /// Number of cleanup operations performed
    cleanup_runs: AtomicU64,
}

impl RateLimitMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total checks
    pub fn total_checks(&self) -> u64 {
        self.total_checks.load(Ordering::Relaxed)
    }

    /// Get allowed requests
    pub fn allowed_requests(&self) -> u64 {
        self.allowed_requests.load(Ordering::Relaxed)
    }

    /// Get blocked requests
    pub fn blocked_requests(&self) -> u64 {
        self.blocked_requests.load(Ordering::Relaxed)
    }

    /// Get cleanup runs
    pub fn cleanup_runs(&self) -> u64 {
        self.cleanup_runs.load(Ordering::Relaxed)
    }

    /// Get block rate (percentage of requests blocked)
    pub fn block_rate(&self) -> f64 {
        let total = self.total_checks();
        if total == 0 {
            0.0
        } else {
            (self.blocked_requests() as f64 / total as f64) * 100.0
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.total_checks.store(0, Ordering::Relaxed);
        self.allowed_requests.store(0, Ordering::Relaxed);
        self.blocked_requests.store(0, Ordering::Relaxed);
        self.cleanup_runs.store(0, Ordering::Relaxed);
    }
}

/// Information about rate limit status for a key
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Maximum requests allowed in the time window
    limit: u32,
    /// Remaining tokens available
    remaining: u32,
    /// Unix timestamp when the rate limit resets (tokens fully refilled)
    reset_at: u64,
    /// Seconds until rate limit resets
    retry_after: u64,
}

impl RateLimitInfo {
    /// Returns the maximum requests allowed
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the remaining tokens available
    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Returns the Unix timestamp when the rate limit resets
    pub fn reset_at(&self) -> u64 {
        self.reset_at
    }

    /// Returns seconds until rate limit resets
    pub fn retry_after(&self) -> u64 {
        self.retry_after
    }
}

/// Thread-safe rate limiter with configurable limits
#[derive(Debug, Clone)]
pub struct RateLimiter {
    config: Arc<RateLimitConfig>,
    buckets: Arc<DashMap<String, RwLock<TokenBucket>>>,
    metrics: Arc<RateLimitMetrics>,
}

impl RateLimiter {
    /// Create a new rate limiter with given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(config),
            buckets: Arc::new(DashMap::new()),
            metrics: Arc::new(RateLimitMetrics::new()),
        }
    }

    /// Create a disabled rate limiter (allows all requests)
    pub fn disabled() -> Self {
        Self::new(RateLimitConfig::disabled())
    }

    /// Get metrics for this rate limiter
    pub fn metrics(&self) -> &RateLimitMetrics {
        &self.metrics
    }

    /// Check if a request should be rate limited
    ///
    /// Returns `true` if the request is allowed, `false` if rate limit exceeded
    ///
    /// # Arguments
    ///
    /// * `key` - Identifier for rate limiting (IP address, username, etc.)
    pub fn check_rate_limit(&self, key: &str) -> bool {
        // Validate key for security
        if let Err(e) = validate_key(key) {
            debug!(key, error = %e, "invalid rate limit key");
            // Block invalid keys (fail closed for security)
            self.metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Track total checks
        let check_count = self.metrics.total_checks.fetch_add(1, Ordering::Relaxed) + 1;

        // If disabled, allow all requests
        if !self.config.enabled {
            self.metrics
                .allowed_requests
                .fetch_add(1, Ordering::Relaxed);
            return true;
        }

        if check_count.is_multiple_of(CLEANUP_EVERY_CHECKS) {
            self.cleanup_idle();
        }

        // Check if we've hit the max tracked keys limit
        if !self.buckets.contains_key(key) && self.buckets.len() >= MAX_TRACKED_KEYS {
            debug!(
                key,
                current = self.buckets.len(),
                max = MAX_TRACKED_KEYS,
                "rate limiter at max capacity, rejecting new key"
            );
            self.metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Get or create bucket for this key
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| RwLock::new(TokenBucket::new(self.config.burst_capacity as f64)));

        // Try to consume a token
        let allowed = bucket.write().try_consume(&self.config);

        if allowed {
            self.metrics
                .allowed_requests
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .blocked_requests
                .fetch_add(1, Ordering::Relaxed);
            debug!(key, "rate limit exceeded");
        }

        allowed
    }

    /// Check rate limit by IP address
    pub fn check_by_ip(&self, ip: IpAddr) -> bool {
        self.check_rate_limit(&ip.to_string())
    }

    /// Clean up idle rate limiters
    ///
    /// Removes rate limiters that haven't been accessed within the idle timeout.
    /// Returns the number of rate limiters removed.
    pub fn cleanup_idle(&self) -> usize {
        self.metrics.cleanup_runs.fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            return 0;
        }

        let timeout = Duration::from_secs(self.config.idle_timeout_secs);
        let mut removed = 0;

        self.buckets.retain(|key, bucket| {
            let is_idle = bucket.read().is_idle(timeout);
            if is_idle {
                debug!(key, "removing idle rate limiter");
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            debug!(removed, "cleaned up idle rate limiters");
        }

        removed
    }

    /// Get the number of active rate limiters
    pub fn active_count(&self) -> usize {
        self.buckets.len()
    }

    /// Get remaining tokens for a key
    ///
    /// Returns None if the key doesn't exist yet
    pub fn remaining_tokens(&self, key: &str) -> Option<u32> {
        self.buckets.get(key).map(|bucket| {
            let mut bucket = bucket.write();
            bucket.refill(&self.config);
            bucket.tokens as u32
        })
    }

    /// Reset rate limit for a specific key
    pub fn reset(&self, key: &str) {
        self.buckets.remove(key);
    }

    /// Clear all rate limiters
    pub fn clear(&self) {
        self.buckets.clear();
    }

    /// Get configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Get rate limit information for a specific key
    ///
    /// Returns information about current rate limit status including
    /// remaining tokens and reset time. Useful for adding rate limit
    /// headers to responses.
    ///
    /// Returns `None` if the key doesn't exist yet (hasn't made any requests).
    pub fn get_limit_info(&self, key: &str) -> Option<RateLimitInfo> {
        if !self.config.enabled {
            return None;
        }

        let bucket = self.buckets.get(key)?;
        let mut bucket = bucket.write();
        bucket.refill(&self.config);

        if self.config.refill_interval_ms == 0
            || self.config.tokens_per_refill == 0
            || self.config.burst_capacity == 0
        {
            let reset_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            return Some(RateLimitInfo {
                limit: self.config.max_requests,
                remaining: bucket.tokens as u32,
                reset_at,
                retry_after: 0,
            });
        }

        // Calculate when the bucket will be fully refilled
        let time_to_full = if bucket.tokens < self.config.burst_capacity as f64 {
            let tokens_needed = self.config.burst_capacity as f64 - bucket.tokens;
            let refills_needed = (tokens_needed / self.config.tokens_per_refill as f64).ceil();
            Duration::from_millis(refills_needed as u64 * self.config.refill_interval_ms)
        } else {
            Duration::from_secs(0)
        };

        let reset_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + time_to_full.as_secs();

        Some(RateLimitInfo {
            limit: self.config.max_requests,
            remaining: bucket.tokens as u32,
            reset_at,
            retry_after: time_to_full.as_secs(),
        })
    }
}

/// Collection of rate limiters for different purposes
#[derive(Debug, Clone)]
pub struct RateLimiterSet {
    /// Authentication attempts (per IP)
    auth: RateLimiter,
    /// REGISTER requests (per IP)
    register: RateLimiter,
    /// INVITE requests (per IP)
    invite: RateLimiter,
    /// New connections (per IP)
    connections: RateLimiter,
}

impl RateLimiterSet {
    /// Create a new rate limiter set with default configurations
    pub fn new() -> Self {
        Self {
            auth: RateLimiter::new(RateLimitConfig::auth_preset()),
            register: RateLimiter::new(RateLimitConfig::register_preset()),
            invite: RateLimiter::new(RateLimitConfig::invite_preset()),
            connections: RateLimiter::new(RateLimitConfig::connection_preset()),
        }
    }

    /// Get reference to auth rate limiter
    pub fn auth(&self) -> &RateLimiter {
        &self.auth
    }

    /// Get reference to register rate limiter
    pub fn register(&self) -> &RateLimiter {
        &self.register
    }

    /// Get reference to invite rate limiter
    pub fn invite(&self) -> &RateLimiter {
        &self.invite
    }

    /// Get reference to connections rate limiter
    pub fn connections(&self) -> &RateLimiter {
        &self.connections
    }

    /// Create a rate limiter set with custom configurations
    pub fn with_configs(
        auth: RateLimitConfig,
        register: RateLimitConfig,
        invite: RateLimitConfig,
        connections: RateLimitConfig,
    ) -> Self {
        Self {
            auth: RateLimiter::new(auth),
            register: RateLimiter::new(register),
            invite: RateLimiter::new(invite),
            connections: RateLimiter::new(connections),
        }
    }

    /// Create a disabled rate limiter set (allows all requests)
    pub fn disabled() -> Self {
        Self {
            auth: RateLimiter::disabled(),
            register: RateLimiter::disabled(),
            invite: RateLimiter::disabled(),
            connections: RateLimiter::disabled(),
        }
    }

    /// Clean up idle rate limiters in all categories
    pub fn cleanup_idle(&self) -> usize {
        self.auth.cleanup_idle()
            + self.register.cleanup_idle()
            + self.invite.cleanup_idle()
            + self.connections.cleanup_idle()
    }
}

impl Default for RateLimiterSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn metrics_track_operations() {
        let config = RateLimitConfig::new(5, 60).unwrap();
        let limiter = RateLimiter::new(config);

        // Allowed requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("test-key"));
        }

        // Blocked request
        assert!(!limiter.check_rate_limit("test-key"));

        // Check metrics
        let metrics = limiter.metrics();
        assert_eq!(metrics.total_checks(), 6);
        assert_eq!(metrics.allowed_requests(), 5);
        assert_eq!(metrics.blocked_requests(), 1);
    }

    #[test]
    fn metrics_block_rate() {
        let config = RateLimitConfig::new(2, 60).unwrap();
        let limiter = RateLimiter::new(config);

        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");

        // 2 allowed, 2 blocked = 50% block rate
        let metrics = limiter.metrics();
        assert_eq!(metrics.block_rate(), 50.0);
    }

    #[test]
    fn get_limit_info_returns_correct_values() {
        let config = RateLimitConfig::new(10, 60).unwrap().with_burst_capacity(10).unwrap();
        let limiter = RateLimiter::new(config);

        // No info before first request
        assert!(limiter.get_limit_info("test-key").is_none());

        // Make some requests
        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");

        // Check info
        let info = limiter.get_limit_info("test-key").unwrap();
        assert_eq!(info.limit(), 10);
        assert_eq!(info.remaining(), 7); // 10 - 3
        assert!(info.reset_at() > 0);
    }

    #[test]
    fn metrics_reset() {
        let config = RateLimitConfig::new(5, 60).unwrap();
        let limiter = RateLimiter::new(config);

        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");

        assert_eq!(limiter.metrics().total_checks(), 2);

        limiter.metrics().reset();

        assert_eq!(limiter.metrics().total_checks(), 0);
        assert_eq!(limiter.metrics().allowed_requests(), 0);
    }

    #[test]
    fn cleanup_tracked_in_metrics() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        let limiter = RateLimiter::new(config);

        limiter.check_rate_limit("test-key");

        assert_eq!(limiter.metrics().cleanup_runs(), 0);

        limiter.cleanup_idle();

        assert_eq!(limiter.metrics().cleanup_runs(), 1);
    }

    #[test]
    fn token_bucket_allows_burst() {
        let config = RateLimitConfig::new(10, 60).unwrap().with_burst_capacity(5).unwrap();
        let limiter = RateLimiter::new(config);

        // Should allow burst up to capacity
        for i in 0..5 {
            assert!(
                limiter.check_rate_limit("test-key"),
                "Request {} should be allowed",
                i
            );
        }

        // 6th request should be denied
        assert!(
            !limiter.check_rate_limit("test-key"),
            "Request beyond burst should be denied"
        );
    }

    #[test]
    fn token_bucket_refills_over_time() {
        // 10 requests per second (100ms per token)
        let config = RateLimitConfig::new(10, 1).unwrap().with_burst_capacity(2).unwrap();
        let limiter = RateLimiter::new(config);

        // Consume all tokens
        assert!(limiter.check_rate_limit("test-key"));
        assert!(limiter.check_rate_limit("test-key"));
        assert!(!limiter.check_rate_limit("test-key"));

        // Wait for refill
        thread::sleep(Duration::from_millis(150));

        // Should allow one more request
        assert!(
            limiter.check_rate_limit("test-key"),
            "Should allow request after refill"
        );
    }

    #[test]
    fn different_keys_tracked_separately() {
        let config = RateLimitConfig::new(2, 60).unwrap();
        let limiter = RateLimiter::new(config);

        // Key 1: consume tokens
        assert!(limiter.check_rate_limit("key1"));
        assert!(limiter.check_rate_limit("key1"));
        assert!(!limiter.check_rate_limit("key1"));

        // Key 2: should still have tokens
        assert!(limiter.check_rate_limit("key2"));
        assert!(limiter.check_rate_limit("key2"));
    }

    #[test]
    fn disabled_limiter_allows_all() {
        let limiter = RateLimiter::disabled();

        // Should allow unlimited requests
        for _ in 0..1000 {
            assert!(limiter.check_rate_limit("test-key"));
        }
    }

    #[test]
    fn cleanup_removes_idle_limiters() {
        let config = RateLimitConfig::new(10, 60).unwrap().with_idle_timeout(1); // 1 second timeout
        let limiter = RateLimiter::new(config);

        // Create some rate limiters
        limiter.check_rate_limit("key1");
        limiter.check_rate_limit("key2");
        limiter.check_rate_limit("key3");

        assert_eq!(limiter.active_count(), 3);

        // Wait for idle timeout
        thread::sleep(Duration::from_secs(2));

        // Cleanup should remove all
        let removed = limiter.cleanup_idle();
        assert_eq!(removed, 3);
        assert_eq!(limiter.active_count(), 0);
    }

    #[test]
    fn rate_limiter_set_has_separate_limits() {
        let set = RateLimiterSet::new();

        // Each limiter should track independently
        assert!(set.auth().check_rate_limit("192.168.1.1"));
        assert!(set.register().check_rate_limit("192.168.1.1"));
        assert!(set.invite().check_rate_limit("192.168.1.1"));
        assert!(set.connections().check_rate_limit("192.168.1.1"));
    }

    #[test]
    fn check_by_ip() {
        let config = RateLimitConfig::new(2, 60).unwrap();
        let limiter = RateLimiter::new(config);

        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(limiter.check_by_ip(ip));
        assert!(limiter.check_by_ip(ip));
        assert!(!limiter.check_by_ip(ip));
    }

    #[test]
    fn remaining_tokens() {
        let config = RateLimitConfig::new(5, 60).unwrap();
        let limiter = RateLimiter::new(config);

        assert!(limiter.remaining_tokens("test-key").is_none());

        limiter.check_rate_limit("test-key");
        let remaining = limiter.remaining_tokens("test-key").unwrap();
        assert_eq!(remaining, 4);
    }

    #[test]
    fn reset_clears_specific_key() {
        let config = RateLimitConfig::new(2, 60).unwrap();
        let limiter = RateLimiter::new(config);

        // Exhaust limit
        limiter.check_rate_limit("test-key");
        limiter.check_rate_limit("test-key");
        assert!(!limiter.check_rate_limit("test-key"));

        // Reset
        limiter.reset("test-key");

        // Should work again
        assert!(limiter.check_rate_limit("test-key"));
    }

    // ===========================================
    // Security tests: CRLF injection prevention
    // ===========================================

    #[test]
    fn rejects_key_with_crlf() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        let limiter = RateLimiter::new(config);

        // Should reject key with CRLF
        assert!(!limiter.check_rate_limit("test\r\nkey"));
        assert_eq!(limiter.metrics().blocked_requests(), 1);
    }

    #[test]
    fn rejects_key_with_newline() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        let limiter = RateLimiter::new(config);

        // Should reject key with newline
        assert!(!limiter.check_rate_limit("test\nkey"));
        assert_eq!(limiter.metrics().blocked_requests(), 1);
    }

    #[test]
    fn rejects_key_with_tab() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        let limiter = RateLimiter::new(config);

        // Should reject key with tab
        assert!(!limiter.check_rate_limit("test\tkey"));
        assert_eq!(limiter.metrics().blocked_requests(), 1);
    }

    // ===========================================
    // Security tests: Bounds checking
    // ===========================================

    #[test]
    fn rejects_oversized_key() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        let limiter = RateLimiter::new(config);

        let long_key = "x".repeat(MAX_KEY_LENGTH + 1);
        assert!(!limiter.check_rate_limit(&long_key));
        assert_eq!(limiter.metrics().blocked_requests(), 1);
    }

    #[test]
    fn accepts_max_length_key() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        let limiter = RateLimiter::new(config);

        let max_key = "x".repeat(MAX_KEY_LENGTH);
        assert!(limiter.check_rate_limit(&max_key));
        assert_eq!(limiter.metrics().allowed_requests(), 1);
    }

    #[test]
    fn rejects_config_with_zero_max_requests() {
        let result = RateLimitConfig::new(0, 60);
        assert!(matches!(result, Err(RateLimitError::MaxRequestsZero)));
    }

    #[test]
    fn rejects_config_with_zero_window() {
        let result = RateLimitConfig::new(10, 0);
        assert!(matches!(result, Err(RateLimitError::WindowSecsZero)));
    }

    #[test]
    fn rejects_config_with_excessive_max_requests() {
        let result = RateLimitConfig::new(MAX_REQUESTS_PER_WINDOW + 1, 60);
        assert!(matches!(
            result,
            Err(RateLimitError::MaxRequestsTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_config_with_excessive_window() {
        let result = RateLimitConfig::new(10, MAX_WINDOW_SECS + 1);
        assert!(matches!(result, Err(RateLimitError::WindowTooLarge { .. })));
    }

    #[test]
    fn rejects_excessive_burst_capacity() {
        let result = RateLimitConfig::new(10, 60).unwrap().with_burst_capacity(MAX_BURST_CAPACITY + 1);
        assert!(matches!(
            result,
            Err(RateLimitError::BurstCapacityTooLarge { .. })
        ));
    }

    #[test]
    fn accepts_valid_config() {
        let result = RateLimitConfig::new(100, 60);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_valid_burst_capacity() {
        let result = RateLimitConfig::new(100, 60).unwrap().with_burst_capacity(200);
        assert!(result.is_ok());
    }

    #[test]
    fn config_accessors_work() {
        let config = RateLimitConfig::new(10, 60).unwrap();
        assert_eq!(config.max_requests(), 10);
        assert_eq!(config.window_secs(), 60);
        assert_eq!(config.burst_capacity(), 10); // Default same as max_requests
        assert!(config.refill_interval_ms() > 0);
        assert_eq!(config.tokens_per_refill(), 1);
        assert_eq!(config.idle_timeout_secs(), 300);
        assert!(config.enabled());
    }
}
