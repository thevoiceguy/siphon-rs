# sip-dns

RFC 3263 compliant DNS resolution for SIP URIs.

## Features

- **NAPTR Lookup**: Discovers available transports and their preferences (RFC 3263 §4.1)
- **SRV Lookup**: Finds servers with priority/weight-based selection (RFC 3263 §4.2, RFC 2782)
- **A/AAAA Lookup**: Resolves IP addresses with Happy Eyeballs support (RFC 8305)
- **Transport Selection**: Automatic transport ordering (TLS > TCP > UDP for SIPS)
- **Failover Support**: Priority-based target selection for high availability
- **IPv6 Support**: Dual-stack resolution with preference for IPv6
- **Static Resolver**: Testing-friendly resolver with pre-configured targets

## Resolution Algorithm

Following RFC 3263, resolution proceeds in this order:

1. **Numeric IP**: If URI contains an IP address, use it directly
2. **Explicit Port**: If port is specified, skip SRV and do A/AAAA lookup
3. **NAPTR Lookup**: Query NAPTR records to discover transport preferences
4. **SRV Lookup**: For each transport, query SRV records to find servers
5. **A/AAAA Fallback**: If no SRV records, query A/AAAA with default ports

## Usage

### Basic Resolution

```rust
use sip_core::SipUri;
use sip_dns::{Resolver, SipResolver};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let resolver = SipResolver::from_system()?;
    let uri = SipUri::parse("sip:example.com")?;

    let targets = resolver.resolve(&uri).await?;

    for target in targets {
        println!("{}:{} via {:?}", target.host, target.port, target.transport);
    }

    Ok(())
}
```

### SIPS (Secure SIP)

```rust
let uri = SipUri::parse("sips:secure.example.com")?;
let targets = resolver.resolve(&uri).await?;
// Returns TLS targets on port 5061
```

### Explicit Transport

```rust
let uri = SipUri::parse("sip:server.example.com;transport=tcp")?;
let targets = resolver.resolve(&uri).await?;
// Forces TCP transport
```

### Static Resolver for Testing

```rust
use sip_dns::{StaticResolver, DnsTarget, Transport};

let resolver = StaticResolver::single("testserver.local", 5060, Transport::Udp);
let targets = resolver.resolve(&uri).await?;
```

### Failover Configuration

```rust
let targets = vec![
    DnsTarget::new("primary.example.com", 5060, Transport::Tcp).with_priority(10),
    DnsTarget::new("backup.example.com", 5060, Transport::Tcp).with_priority(20),
];
let resolver = StaticResolver::new(targets);
```

## Transport Selection

Transport is selected based on:

1. **Explicit transport parameter** in URI (`sip:host;transport=tcp`)
2. **SIPS scheme** forces TLS transport
3. **NAPTR records** define transport preference order
4. **Default ordering**: TCP preferred over UDP (RFC 3263 recommendation)

### Transport Types

- `Transport::Udp` - UDP (default for SIP)
- `Transport::Tcp` - TCP with connection management
- `Transport::Tls` - TLS (required for SIPS)
- `Transport::Ws` - WebSocket (RFC 7118)
- `Transport::Wss` - WebSocket Secure

## SRV Priority and Weight

SRV records contain priority and weight fields (RFC 2782):

- **Priority**: Lower values tried first (deterministic ordering)
- **Weight**: Within same priority, higher weights selected more often (probabilistic)

Example SRV records:
```
_sip._tcp.example.com.  SRV  10  60  5060  sip1.example.com.
_sip._tcp.example.com.  SRV  10  40  5060  sip2.example.com.
_sip._tcp.example.com.  SRV  20  100  5060  backup.example.com.
```

Resolution order:
1. Try sip1 or sip2 (priority 10), weighted 60/40 split
2. If both fail, try backup (priority 20)

## Configuration

### System DNS

Uses system DNS configuration (`/etc/resolv.conf` on Unix):

```rust
let resolver = SipResolver::from_system()?;
```

### Custom DNS

Provide custom resolver configuration:

```rust
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

let config = ResolverConfig::google(); // Use Google DNS
let opts = ResolverOpts::default();
let resolver = SipResolver::with_config(config, opts)?;
```

### Disable NAPTR

For networks without NAPTR support:

```rust
let resolver = SipResolver::from_system()?.disable_naptr();
```

## Examples

See `examples/dns_resolution.rs`:

```bash
cargo run --example dns_resolution
```

## Testing

```bash
# Run all tests
cargo test

# Run with DNS queries (requires network)
cargo test --test resolver_tests

# Run unit tests only
cargo test --lib
```

## Performance Considerations

- **Caching**: DNS responses are cached by trust-dns-resolver
- **Parallel Lookups**: A and AAAA queries run concurrently
- **Connection Reuse**: Transport layer should reuse resolved connections
- **Failover**: Higher priority targets tried before lower priority

## RFC Compliance

- ✅ RFC 3263 - Locating SIP Servers
- ✅ RFC 2782 - SRV Records (priority/weight)
- ✅ RFC 3596 - AAAA Records (IPv6)
- ✅ RFC 8305 - Happy Eyeballs (IPv6 preference)
- ✅ RFC 7118 - WebSocket Transport

## Integration

Typically used with `sip-transport`:

```rust
use sip_transport::{send_udp, send_stream};

for target in targets {
    match target.transport {
        Transport::Udp => {
            if let Ok(_) = send_udp(&target.host, target.port, &message).await {
                break; // Success
            }
        },
        Transport::Tcp | Transport::Tls => {
            if let Ok(_) = send_stream(&target.host, target.port, &message, tls).await {
                break; // Success
            }
        },
        _ => continue,
    }
}
```

## Limitations

- NAPTR lookup is optional (can be disabled)
- No built-in retry logic (implement at application layer)
- No connection health checking (implement in transport layer)
- Cache TTL controlled by trust-dns-resolver

## License

MIT
