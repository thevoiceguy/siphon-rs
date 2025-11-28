# sip-transaction

RFC 3261 compliant SIP transaction layer with transport-aware timers and DoS protection.

## Features

- **Client & Server Transactions** - Full state machine implementations for INVITE and non-INVITE methods
- **Transport-Aware Timers** - Automatic timer optimization for TCP/TLS (RFC 3261 §17.1.2.2)
- **Transaction Limits** - Configurable limits to prevent resource exhaustion attacks
- **Performance Metrics** - Built-in duration tracking and timer statistics
- **Connection Pooling** - Automatic TCP connection reuse per RFC 5923

## Quick Start

```rust
use sip_transaction::{TransactionManager, TransactionLimits, TransportDispatcher};
use std::sync::Arc;

// Create transaction manager with default limits
let dispatcher = Arc::new(MyDispatcher::new());
let manager = TransactionManager::new(dispatcher);

// Or configure custom limits for DoS protection
let limits = TransactionLimits::large(); // 100k transactions
let manager = TransactionManager::with_limits(dispatcher, limits);
```

## Transaction Limits for DoS Protection

Without limits, an attacker can exhaust server memory by creating unlimited transactions with unique branch IDs. The `TransactionLimits` struct provides configurable protection.

### Preset Configurations

```rust
// Small server (1-10 concurrent calls): 1,000 transactions each
let limits = TransactionLimits::small();

// Medium server (10-100 concurrent calls): 10,000 transactions each - DEFAULT
let limits = TransactionLimits::medium();

// Large server (100-1000 concurrent calls): 100,000 transactions each
let limits = TransactionLimits::large();

// Carrier-grade (1000+ concurrent calls): 500,000 transactions each
let limits = TransactionLimits::carrier_grade();

// Unlimited (testing only)
let limits = TransactionLimits::unlimited();
```

### Custom Configuration

```rust
use sip_transaction::TransactionLimits;

let limits = TransactionLimits::new(
    5_000,   // max server transactions (incoming requests)
    10_000,  // max client transactions (outgoing requests)
);

let manager = TransactionManager::with_limits(dispatcher, limits);
```

### How Limits Work

1. **Separate Limits**: Server and client transactions have independent limits
2. **Oldest-First Eviction**: When limit is reached, oldest transaction is evicted
3. **Automatic Cleanup**: Evicted transactions have timers canceled
4. **TU Notification**: Client transactions notify the Transaction User on eviction

### Memory Impact

Each transaction consumes approximately 1-2 KB of memory:

| Limit      | Memory Usage  | Suitable For          |
|------------|---------------|-----------------------|
| 1,000      | ~1-2 MB       | Small servers         |
| 10,000     | ~10-20 MB     | Medium servers        |
| 100,000    | ~100-200 MB   | Large servers         |
| 500,000    | ~500 MB-1 GB  | Carrier-grade systems |

### Tuning Recommendations

**Monitor transaction count** in production:
```rust
let server_count = manager.inner.server.len();
let client_count = manager.inner.client.len();
```

**Adjust limits based on**:
- Peak concurrent calls
- Average call duration
- Available memory
- Attack surface exposure

**General formula**: `max_transactions = peak_concurrent_calls * 10`

This accounts for:
- Multiple transactions per call (INVITE, ACK, BYE, re-INVITE)
- Retransmissions and provisional responses
- Timer expiration delays
- Network latency

### Attack Scenarios Protected Against

1. **Transaction Flood**
   - Attacker: Sends requests with unique branch IDs
   - Without Limits: Memory exhaustion, server crash
   - With Limits: Oldest transactions evicted, service continues

2. **Slowloris-style Transaction Exhaustion**
   - Attacker: Creates transactions and never completes them
   - Without Limits: All resources consumed, legitimate calls blocked
   - With Limits: Oldest incomplete transactions evicted

3. **Distributed Transaction Flood**
   - Attacker: Multiple IPs send flood traffic
   - Rate limiting alone insufficient (different IPs)
   - Transaction limits provide defense-in-depth

## Transport-Aware Timers

Per RFC 3261 §17.1.2.2, timer behavior is automatically optimized based on transport reliability:

**UDP (Unreliable)**:
- Retransmissions enabled (Timer A, E, G)
- Full wait times (Timer K = 5 seconds)

**TCP/TLS (Reliable)**:
- Retransmissions disabled (Timer A, E, G = 0)
- Instant completion (Timer K = 0 seconds)
- **Performance**: Transactions complete 5-37 seconds faster

```rust
// Timers automatically adjusted based on transport
let ctx = TransportContext::new(TransportKind::Tcp, peer_addr, None);
let handle = manager.receive_request(request, ctx).await;
```

## Performance Metrics

Track transaction performance and detect anomalies:

```rust
let metrics = manager.metrics();
let snapshot = metrics.snapshot();

println!("Total transactions: {}", snapshot.total_transactions);
println!("Success rate: {}%",
    snapshot.successful_transactions * 100 / snapshot.total_transactions);

// Per-transport analysis
if let Some(tcp_stats) = snapshot.by_transport.get(&TransportType::Tcp) {
    println!("TCP average: {:?}", tcp_stats.avg_duration);
}
```

## Security Best Practices

1. **Configure Appropriate Limits**
   - Start with `medium()` preset
   - Monitor and adjust based on traffic patterns
   - Never use `unlimited()` in production

2. **Layer Security Controls**
   - Transaction limits (this crate)
   - Rate limiting (per-IP/per-user)
   - Firewall rules
   - SIP authentication

3. **Monitor Transaction Metrics**
   - Track eviction frequency
   - Alert on sustained high transaction counts
   - Correlate with rate limit hits

4. **Log Security Events**
   - Transaction limit reached (automatically logged as WARN)
   - Eviction of transactions
   - Unusual transaction patterns

## Examples

See `examples/` directory:
- `transaction_limits_demo.rs` - DoS protection demonstration
- `metrics_tracking.rs` - Performance monitoring
- `timer_behavior.rs` - Transport-aware timer comparison

## Architecture

```
TransactionManager
├─ server: DashMap<TransactionKey, ServerEntry>  (limited)
├─ client: DashMap<TransactionKey, ClientEntry>  (limited)
├─ limits: TransactionLimits                     (configurable)
└─ metrics: TransactionMetrics                   (monitoring)
```

## License

MIT OR Apache-2.0
