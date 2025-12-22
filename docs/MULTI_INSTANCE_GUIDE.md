# Multi-Instance / State Guide (siphon-rs)

This stack stays infra-neutral. You choose whether state is local or shared; the code exposes hooks to plug your own storage and sharding.

## State surfaces
- Dialogs: `sip-dialog::storage::DialogStore` (default: in-memory).
- Transactions: `sip-transaction::storage::TransactionStore` (default: in-memory).
- Location/registrations: app-level (not mandated here).

## Using custom stores
Implement the store traits and inject your backend (Redis/DB/etc.) in your app wiring. Keep the core crates free of infra deps; put adapters behind feature flags in your app.

```rust
// Example skeleton for a Redis-backed dialog store (pseudocode)
struct RedisDialogStore { pool: redis::Client }
#[async_trait]
impl DialogStore for RedisDialogStore {
    async fn get(&self, id: &DialogId) -> Option<Dialog> { /* ... */ }
    async fn put(&self, dialog: Dialog) { /* ... */ }
    async fn remove(&self, id: &DialogId) { /* ... */ }
    async fn list_by_call_id(&self, call_id: &SmolStr) -> Vec<Dialog> { /* ... */ }
}
```

## Sharding / stickiness
Helpers in `sip-transaction::sharding`:
- `shard_by_call_id(call_id)`
- `shard_by_transaction_key(&TransactionKey)`
- `shard_by_dialog_id(call_id, local_tag, remote_tag)`
- `shard_key_from_headers(headers)`

Use these to derive LB stickiness keys (e.g., hash Call-ID) without hard-coding infra logic.

### LB recommendations
- If state is local: configure LB stickiness on Call-ID/branch/dialog-id hash (where supported) or route via app-side sharding header/cookie.
- If state is shared: stickiness is less critical but still reduces cross-node chatter.

## When to keep state local vs shared
- Local (in-memory): simplest for single instance or sticky routing; lower latency; no external deps. Requires LB stickiness for HA.
- Shared store: needed for active-active without strict stickiness; enables failover at the cost of datastore latency/consistency. Use with care for high-rate transactions; consider caching and batch cleanup.

## Observability
Expose metrics/logs around missing-state events (e.g., transaction not found) to detect stickiness drift or store outages, and decide to retry to a specific shard or return an error.
