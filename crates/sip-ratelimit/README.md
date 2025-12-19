# sip-ratelimit

Configurable rate limiting for SIP applications to prevent abuse and resource exhaustion.

## Features

- **Token Bucket Algorithm** - Industry-standard rate limiting with burst capacity
- **Per-Key Tracking** - Rate limit by IP address, user, AOR, or any identifier
- **Configurable Limits** - Customize capacity, refill rate, and cleanup intervals
- **Automatic Cleanup** - Removes idle rate limiters to prevent memory leaks
- **Thread-Safe** - Uses DashMap for concurrent access without contention
- **Zero-Cost When Disabled** - No overhead if rate limiting is turned off

## Quick Start

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// Configure: 10 requests per minute with burst of 20
let config = RateLimitConfig::new(10, 60).with_burst_capacity(20);
let limiter = RateLimiter::new(config);

// Check if request is allowed
if limiter.check_rate_limit("192.168.1.100") {
    println!("Request allowed");
} else {
    println!("Rate limit exceeded - try again later");
}
```

## Configuration Presets

The crate provides preset configurations for common SIP use cases:

### Authentication Rate Limiting

Prevents brute force authentication attacks:

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// 10 attempts per 5 minutes, burst capacity of 3
let config = RateLimitConfig::auth_preset();
let limiter = RateLimiter::new(config);
```

**Configuration:**
- Max requests: 10 per 5 minutes (300 seconds)
- Burst capacity: 3 requests
- Idle timeout: 10 minutes

**Use case:** Protect authentication endpoints from credential stuffing and brute force attacks.

### Registration Rate Limiting

Prevents registration flooding:

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// 60 registrations per hour
let config = RateLimitConfig::register_preset();
let limiter = RateLimiter::new(config);
```

**Configuration:**
- Max requests: 60 per hour (3600 seconds)
- Burst capacity: 10 requests
- Idle timeout: 30 minutes

**Use case:** Protect REGISTER handlers from registration flooding attacks.

### Connection Rate Limiting

Prevents connection exhaustion:

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// 100 connections per minute
let config = RateLimitConfig::connection_preset();
let limiter = RateLimiter::new(config);
```

**Configuration:**
- Max requests: 100 per minute (60 seconds)
- Burst capacity: 20 requests
- Idle timeout: 5 minutes

**Use case:** Protect transport layer from connection exhaustion attacks.

### INVITE Rate Limiting

Prevents call flooding:

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// 30 INVITE requests per minute
let config = RateLimitConfig::invite_preset();
let limiter = RateLimiter::new(config);
```

**Configuration:**
- Max requests: 30 per minute (60 seconds)
- Burst capacity: 10 requests
- Idle timeout: 5 minutes

**Use case:** Protect call servers from INVITE flooding attacks.

## Custom Configuration

Create custom rate limit configurations for specific needs:

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// Custom: 100 requests per 5 minutes, burst of 50
let config = RateLimitConfig::new(100, 300)
    .with_burst_capacity(50)
    .with_idle_timeout(600) // 10 minutes
    .with_enabled(true);

let limiter = RateLimiter::new(config);
```

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `max_requests` | Maximum requests allowed in time window | Required |
| `window_secs` | Time window in seconds | Required |
| `burst_capacity` | Tokens that can accumulate | `max_requests` |
| `refill_interval_ms` | Token refill interval | Calculated |
| `tokens_per_refill` | Tokens added per refill | 1 |
| `idle_timeout_secs` | Cleanup idle limiters after | 300 (5 min) |
| `enabled` | Whether rate limiting is active | true |

## Integration with SIP Components

### Registrar with Rate Limiting

```rust
use sip_registrar::{BasicRegistrar, MemoryLocationStore};
use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// Create registrar with rate limiting
let store = MemoryLocationStore::new();
let auth_store = MemoryCredentialStore::new();
let auth = DigestAuthenticator::new("example.com", auth_store);

// Configure rate limit: 60 registrations per hour
let rate_config = RateLimitConfig::register_preset();
let rate_limiter = RateLimiter::new(rate_config);

let registrar = BasicRegistrar::new(store, Some(auth))
    .with_rate_limiter(rate_limiter);
```

### Authentication with Rate Limiting

```rust
use sip_auth::{DigestAuthenticator, MemoryCredentialStore};
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// Create authenticator with rate limiting
let store = MemoryCredentialStore::new();

// Configure rate limit: 10 attempts per 5 minutes
let rate_config = RateLimitConfig::auth_preset();
let rate_limiter = RateLimiter::new(rate_config);

let auth = DigestAuthenticator::new("example.com", store)
    .with_rate_limiter(rate_limiter);
```

### Multiple Rate Limiters

Use `RateLimiterSet` to manage different rate limits for different purposes:

```rust
use sip_ratelimit::{RateLimiterSet, RateLimitConfig};

// Create a set with default presets
let limiters = RateLimiterSet::new();

// Check different limits
if !limiters.auth.check_rate_limit("192.168.1.100") {
    // Authentication rate limit exceeded
}

if !limiters.register.check_rate_limit("192.168.1.100") {
    // Registration rate limit exceeded
}

if !limiters.invite.check_rate_limit("192.168.1.100") {
    // INVITE rate limit exceeded
}
```

Or create custom configurations:

```rust
use sip_ratelimit::{RateLimiterSet, RateLimitConfig};

let limiters = RateLimiterSet::with_configs(
    RateLimitConfig::new(5, 60),    // Auth: 5 per minute
    RateLimitConfig::new(30, 3600), // Register: 30 per hour
    RateLimitConfig::new(20, 60),   // INVITE: 20 per minute
    RateLimitConfig::new(50, 60),   // Connections: 50 per minute
);
```

## Cleanup and Maintenance

Rate limiters automatically clean up idle entries to prevent memory leaks:

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

let config = RateLimitConfig::new(100, 60);
let limiter = RateLimiter::new(config);

// Trigger cleanup manually (automatic cleanup runs opportunistically every 1024 checks)
let removed = limiter.cleanup_idle();
println!("Removed {} idle rate limiters", removed);

// Get active limiter count
println!("Active rate limiters: {}", limiter.active_count());
```

## Disabling Rate Limiting

To disable rate limiting (useful for testing or development):

```rust
use sip_ratelimit::{RateLimiter, RateLimitConfig};

// Create disabled rate limiter (allows all requests)
let limiter = RateLimiter::disabled();

// Or use configuration
let config = RateLimitConfig::disabled();
let limiter = RateLimiter::new(config);

// Or disable an existing configuration
let config = RateLimitConfig::new(100, 60).with_enabled(false);
```

## Monitoring and Debugging

Check remaining tokens for a key:

```rust
if let Some(remaining) = limiter.remaining_tokens("192.168.1.100") {
    println!("Remaining tokens: {}", remaining);
}
```

Reset rate limit for a specific key:

```rust
limiter.reset("192.168.1.100");
```

Clear all rate limiters:

```rust
limiter.clear();
```

## Performance Considerations

- **Lock-Free Operations**: Uses DashMap for minimal lock contention
- **Memory Efficient**: Automatic cleanup of idle limiters
- **Fast Path**: Disabled limiters have near-zero overhead
- **Scalability**: Handles thousands of concurrent keys efficiently

## Security Best Practices

1. **Layer Rate Limiting**: Use different limits for authentication, registration, and calls
2. **Per-IP Tracking**: Rate limit by source IP address extracted from Via header
3. **Appropriate Burst Capacity**: Allow small bursts for legitimate retransmissions
4. **Monitor and Alert**: Track rate limit hits to detect attacks
5. **Combine with Authentication**: Rate limiting alone is not sufficient security

## Examples

See `examples/` directory for complete examples:

- `simple_rate_limiter.rs` - Basic usage
- `multi_tier_limiting.rs` - Multiple rate limit tiers
- `sip_integration.rs` - Integration with SIP components

## License

MIT OR Apache-2.0
