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
//! let config = RateLimitConfig::new(10, 60).with_burst_capacity(20);
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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed in the time window
    pub max_requests: u32,

    /// Time window in seconds for max_requests
    pub window_secs: u64,

    /// Burst capacity (number of tokens that can accumulate)
    /// Defaults to max_requests if not specified
    pub burst_capacity: u32,

    /// How often to refill tokens (in milliseconds)
    /// Defaults to window_secs * 1000 / max_requests
    pub refill_interval_ms: u64,

    /// Number of tokens to add per refill
    pub tokens_per_refill: u32,

    /// How long to keep idle rate limiters before cleanup (seconds)
    pub idle_timeout_secs: u64,

    /// Whether rate limiting is enabled
    pub enabled: bool,
}

impl RateLimitConfig {
    /// Create a new rate limit configuration
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
    /// let config = RateLimitConfig::new(10, 60);
    /// ```
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        // Calculate refill interval: distribute tokens evenly across window
        let refill_interval_ms = if max_requests > 0 {
            (window_secs * 1000) / max_requests as u64
        } else {
            1000
        };

        Self {
            max_requests,
            window_secs,
            burst_capacity: max_requests, // Default: same as max_requests
            refill_interval_ms,
            tokens_per_refill: 1,
            idle_timeout_secs: 300, // 5 minutes default
            enabled: true,
        }
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
    pub fn with_burst_capacity(mut self, capacity: u32) -> Self {
        self.burst_capacity = capacity;
        self
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
            .with_burst_capacity(3) // Small burst allowed
            .with_idle_timeout(600) // 10 minute cleanup
    }

    /// Preset: Registration rate limiting (60 per hour)
    pub fn register_preset() -> Self {
        Self::new(60, 3600)
            .with_burst_capacity(10)
            .with_idle_timeout(1800) // 30 minute cleanup
    }

    /// Preset: Connection rate limiting (100 per minute)
    pub fn connection_preset() -> Self {
        Self::new(100, 60)
            .with_burst_capacity(20)
            .with_idle_timeout(300)
    }

    /// Preset: INVITE rate limiting (30 per minute)
    pub fn invite_preset() -> Self {
        Self::new(30, 60)
            .with_burst_capacity(10)
            .with_idle_timeout(300)
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::new(100, 60) // 100 requests per minute
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

/// Thread-safe rate limiter with configurable limits
#[derive(Debug, Clone)]
pub struct RateLimiter {
    config: Arc<RateLimitConfig>,
    buckets: Arc<DashMap<String, RwLock<TokenBucket>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(config),
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Create a disabled rate limiter (allows all requests)
    pub fn disabled() -> Self {
        Self::new(RateLimitConfig::disabled())
    }

    /// Check if a request should be rate limited
    ///
    /// Returns `true` if the request is allowed, `false` if rate limit exceeded
    ///
    /// # Arguments
    ///
    /// * `key` - Identifier for rate limiting (IP address, username, etc.)
    pub fn check_rate_limit(&self, key: &str) -> bool {
        // If disabled, allow all requests
        if !self.config.enabled {
            return true;
        }

        // Get or create bucket for this key
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| RwLock::new(TokenBucket::new(self.config.burst_capacity as f64)));

        // Try to consume a token
        let allowed = bucket.write().try_consume(&self.config);

        if !allowed {
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
        self.buckets
            .get(key)
            .map(|bucket| bucket.read().tokens as u32)
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
}

/// Collection of rate limiters for different purposes
#[derive(Debug, Clone)]
pub struct RateLimiterSet {
    /// Authentication attempts (per IP)
    pub auth: RateLimiter,
    /// REGISTER requests (per IP)
    pub register: RateLimiter,
    /// INVITE requests (per IP)
    pub invite: RateLimiter,
    /// New connections (per IP)
    pub connections: RateLimiter,
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
    fn token_bucket_allows_burst() {
        let config = RateLimitConfig::new(10, 60).with_burst_capacity(5);
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
        let config = RateLimitConfig::new(10, 1).with_burst_capacity(2);
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
        let config = RateLimitConfig::new(2, 60);
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
        let config = RateLimitConfig::new(10, 60).with_idle_timeout(1); // 1 second timeout
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
        assert!(set.auth.check_rate_limit("192.168.1.1"));
        assert!(set.register.check_rate_limit("192.168.1.1"));
        assert!(set.invite.check_rate_limit("192.168.1.1"));
        assert!(set.connections.check_rate_limit("192.168.1.1"));
    }

    #[test]
    fn check_by_ip() {
        let config = RateLimitConfig::new(2, 60);
        let limiter = RateLimiter::new(config);

        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(limiter.check_by_ip(ip));
        assert!(limiter.check_by_ip(ip));
        assert!(!limiter.check_by_ip(ip));
    }

    #[test]
    fn remaining_tokens() {
        let config = RateLimitConfig::new(5, 60);
        let limiter = RateLimiter::new(config);

        assert!(limiter.remaining_tokens("test-key").is_none());

        limiter.check_rate_limit("test-key");
        let remaining = limiter.remaining_tokens("test-key").unwrap();
        assert_eq!(remaining, 4);
    }

    #[test]
    fn reset_clears_specific_key() {
        let config = RateLimitConfig::new(2, 60);
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
}
