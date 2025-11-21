# sip-dns

RFC 3263 and RFC 3361 compliant SIP server discovery.

## Features

### DNS-Based Discovery (RFC 3263)
- **NAPTR Lookup**: Discovers available transports and their preferences (RFC 3263 §4.1)
- **SRV Lookup**: Finds servers with priority/weight-based selection (RFC 3263 §4.2, RFC 2782)
- **A/AAAA Lookup**: Resolves IP addresses with Happy Eyeballs support (RFC 8305)
- **Transport Selection**: Automatic transport ordering (TLS > TCP > UDP for SIPS)
- **Failover Support**: Priority-based target selection for high availability
- **IPv6 Support**: Dual-stack resolution with preference for IPv6

### DHCP-Based Discovery (RFC 3361, RFC 2132, RFC 5859)
- **DHCP Option 120**: Discovers SIP servers via DHCP (RFC 3361)
- **DHCP Option 66**: TFTP server name for VoIP configuration (RFC 2132)
- **DHCP Option 150**: TFTP server addresses for VoIP configuration (RFC 5859)
- **Domain Name Support**: Resolves DHCP-provided domain names via DNS
- **IPv4 Address Support**: Uses DHCP-provided IPv4 addresses directly
- **Hybrid Resolution**: Tries DHCP first, falls back to DNS
- **Pluggable DHCP Providers**: Trait-based design for platform-specific DHCP clients

### Testing Support
- **Static Resolver**: Pre-configured DNS targets for testing
- **Static DHCP Provider**: Pre-configured DHCP servers for testing

## Resolution Algorithms

### DNS Resolution (RFC 3263)

1. **Numeric IP**: If URI contains an IP address, use it directly
2. **Explicit Port**: If port is specified, skip SRV and do A/AAAA lookup
3. **NAPTR Lookup**: Query NAPTR records to discover transport preferences
4. **SRV Lookup**: For each transport, query SRV records to find servers
5. **A/AAAA Fallback**: If no SRV records, query A/AAAA with default ports

### DHCP Resolution (RFC 3361)

1. **Query DHCP**: Request Option 120 from DHCP server
2. **Parse Servers**: Extract domain names or IPv4 addresses
3. **Use IPv4 Directly**: If IPv4 addresses provided, use them
4. **Resolve Domains**: If domain names provided, resolve via DNS (RFC 3263)

### Hybrid Resolution (Recommended)

1. **Try DHCP First**: Query DHCP Option 120
2. **Fallback to DNS**: If DHCP unavailable, use DNS resolution (RFC 3263)

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

### DHCP-Based Discovery

```rust
use sip_dns::{HybridResolver, StaticDhcpProvider, SipResolver, DhcpSipServer};
use smol_str::SmolStr;

// Create DHCP provider (use StaticDhcpProvider for testing)
let dhcp = StaticDhcpProvider::new(vec![
    DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
    DhcpSipServer::Ipv4("192.168.1.100".parse().unwrap()),
]);

// Create DNS resolver for fallback
let dns = SipResolver::from_system()?;

// Create hybrid resolver (tries DHCP first, then DNS)
let resolver = HybridResolver::new(dhcp, dns);

let uri = SipUri::parse("sip:user@example.com")?;
let targets = resolver.resolve(&uri).await?;
```

### Parsing DHCP Options

#### Option 120 (SIP Servers)

```rust
use sip_dns::parse_dhcp_option_120;

// Encoding 1: IPv4 addresses
let data = vec![1, 192, 168, 1, 1, 10, 0, 0, 1];
let servers = parse_dhcp_option_120(&data)?;

// Encoding 0: Domain names (RFC 1035 format)
let data = vec![0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
let servers = parse_dhcp_option_120(&data)?;
```

#### Option 66 (TFTP Server Name)

```rust
use sip_dns::parse_dhcp_option_66;

// Hostname or IP as string
let data = b"tftp.example.com";
let server = parse_dhcp_option_66(data)?;
println!("TFTP server: {}", server.as_str());
```

#### Option 150 (TFTP Server Addresses)

```rust
use sip_dns::parse_dhcp_option_150;

// Multiple IPv4 addresses
let data = vec![192, 168, 1, 1, 10, 0, 0, 1];
let servers = parse_dhcp_option_150(&data)?;
for addr in servers {
    println!("TFTP server: {}", addr);
}
```

### Custom DHCP Provider

Implement the `DhcpProvider` trait to integrate with platform-specific DHCP:

```rust
use sip_dns::{DhcpProvider, DhcpSipServer, TftpServerName};
use sip_dns::{parse_dhcp_option_120, parse_dhcp_option_66, parse_dhcp_option_150};
use anyhow::Result;

struct SystemDhcpProvider;

#[async_trait::async_trait]
impl DhcpProvider for SystemDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        // Platform-specific DHCP query for Option 120
        let option_120_data = query_system_dhcp_option(120)?;
        if let Some(data) = option_120_data {
            Ok(Some(parse_dhcp_option_120(&data)?))
        } else {
            Ok(None)
        }
    }

    async fn query_tftp_server_name(&self) -> Result<Option<TftpServerName>> {
        // Platform-specific DHCP query for Option 66
        let option_66_data = query_system_dhcp_option(66)?;
        if let Some(data) = option_66_data {
            Ok(Some(parse_dhcp_option_66(&data)?))
        } else {
            Ok(None)
        }
    }

    async fn query_tftp_server_addresses(&self) -> Result<Option<Vec<std::net::Ipv4Addr>>> {
        // Platform-specific DHCP query for Option 150
        let option_150_data = query_system_dhcp_option(150)?;
        if let Some(data) = option_150_data {
            Ok(Some(parse_dhcp_option_150(&data)?))
        } else {
            Ok(None)
        }
    }
}

// Platform-specific DHCP query helper
fn query_system_dhcp_option(option_code: u8) -> Result<Option<Vec<u8>>> {
    // - Linux: Parse /var/lib/dhcp/dhclient.leases
    // - Windows: Query registry or use ipconfig
    // - macOS: Parse /var/db/dhcpd_leases
    todo!()
}
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

### DNS-Based Discovery
- ✅ RFC 3263 - Locating SIP Servers (DNS)
- ✅ RFC 2782 - SRV Records (priority/weight)
- ✅ RFC 3596 - AAAA Records (IPv6)
- ✅ RFC 8305 - Happy Eyeballs (IPv6 preference)
- ✅ RFC 7118 - WebSocket Transport

### DHCP-Based Discovery
- ✅ RFC 3361 - DHCP Option 120 for SIP Servers
  - ✅ Encoding 0: Domain names (RFC 1035 format)
  - ✅ Encoding 1: IPv4 addresses
  - ✅ Preference-ordered server lists
  - ✅ Integration with DNS resolution for domain names
- ✅ RFC 2132 - DHCP Option 66 for TFTP Server Name
  - ✅ String format (hostname, domain, or IP)
  - ✅ Used for VoIP phone configuration
- ✅ RFC 5859 - DHCP Option 150 for TFTP Server Addresses
  - ✅ Multiple IPv4 addresses
  - ✅ Preference-ordered server lists
  - ✅ Cisco VoIP integration

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

### DNS
- NAPTR lookup is optional (can be disabled)
- Cache TTL controlled by trust-dns-resolver

### DHCP
- No built-in system DHCP client (use `DhcpProvider` trait for platform integration)
- DHCP lease monitoring not included (query once per resolution)
- IPv6 DHCP (DHCPv6) not yet supported

### General
- No built-in retry logic (implement at application layer)
- No connection health checking (implement in transport layer)

## License

MIT
