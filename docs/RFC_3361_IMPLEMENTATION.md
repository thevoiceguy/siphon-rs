# RFC 3361 DHCP Option 120 for SIP Servers - Implementation

**Date:** 2025-01-21
**Status:** ✅ **COMPLETE** - Full RFC 3361 compliance achieved
**Test Results:** ✅ All 32 DHCP-related tests passing (Option 66/120/150 + resolver coverage)

---

## Overview

This document describes the RFC 3361 (DHCP Option for SIP Servers) implementation in SIPHON-RS. This extension provides a DHCP-based mechanism for discovering SIP servers, complementing the DNS-based discovery defined in RFC 3263.

### RFC 3361 Summary

RFC 3361 defines DHCP Option 120 for advertising SIP server addresses:
- **Option Code**: 120
- **Two Encoding Formats**:
  - **Encoding 0**: Domain names in RFC 1035 format (length-prefixed labels)
  - **Encoding 1**: IPv4 addresses (4 bytes each in network byte order)
- **Preference Ordering**: Servers listed in order of preference
- **Integration with DNS**: Domain names resolved via RFC 3263

**Note:** The DHCP helper layer in `sip-dns` also includes Option 66 (TFTP server name)
and Option 150 (TFTP server addresses) parsing and provider hooks. These are not part
of RFC 3361 but share the same provider interface for provisioning workflows.

### Discovery Flow

1. **UAC queries DHCP** for Option 120 during network configuration
2. **DHCP server responds** with SIP server list (domain names or IPv4 addresses)
3. **UAC processes servers** in preference order:
   - IPv4 addresses used directly
   - Domain names resolved via DNS (RFC 3263)
4. **Fallback to DNS**: If DHCP unavailable, use RFC 3263 DNS resolution

---

## Implementation Status

### ✅ Complete Implementation

| Component | Status | Location | Description |
|-----------|--------|----------|-------------|
| **DHCP Option 120 Parsing** | ✅ Complete | `sip-dns/src/lib.rs:852-969` | Encoding 0 & 1 support |
| **DhcpSipServer Enum** | ✅ Complete | `sip-dns/src/lib.rs:806-821` | Domain or IPv4 variant |
| **DhcpProvider Trait** | ✅ Complete | `sip-dns/src/lib.rs:823-848` | Pluggable DHCP backends + TFTP hooks |
| **TftpServerName Type** | ✅ Complete | `sip-dns/src/lib.rs:720-731` | Option 66 wrapper |
| **DHCP Option 66 Parsing** | ✅ Complete | `sip-dns/src/lib.rs:733-754` | TFTP server name parsing |
| **DHCP Option 150 Parsing** | ✅ Complete | `sip-dns/src/lib.rs:756-799` | TFTP server address list |
| **StaticDhcpProvider** | ✅ Complete | `sip-dns/src/lib.rs:971-1038` | Testing support (Options 120/66/150) |
| **DhcpResolver** | ✅ Complete | `sip-dns/src/lib.rs:1040-1133` | DHCP-only resolution |
| **HybridResolver** | ✅ Complete | `sip-dns/src/lib.rs:1135-1214` | DHCP + DNS fallback |
| **Tests** | ✅ Complete | 32 DHCP-related tests | Options 66/120/150 + resolvers |
| **Documentation** | ✅ Complete | Inline docs + README + this document | Usage examples and API docs |

---

## API Reference

### Core Types

#### DhcpSipServer

Represents a SIP server entry from DHCP Option 120:

```rust
pub enum DhcpSipServer {
    /// Domain name that should be resolved via DNS (encoding 0)
    Domain(SmolStr),
    /// IPv4 address to use directly (encoding 1)
    Ipv4(std::net::Ipv4Addr),
}

impl DhcpSipServer {
    /// Returns the server as a string
    pub fn as_str(&self) -> String;
}
```

#### TftpServerName

Wrapper for DHCP Option 66 (TFTP server name):

```rust
pub struct TftpServerName(pub SmolStr);

impl TftpServerName {
    /// Returns the server name as a string
    pub fn as_str(&self) -> &str;
}
```

#### DhcpProvider Trait

Interface for DHCP clients to provide SIP and related DHCP options:

```rust
#[async_trait::async_trait]
pub trait DhcpProvider: Send + Sync {
    /// Queries DHCP for Option 120 (SIP servers)
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>>;

    /// Queries DHCP for Option 66 (TFTP server name)
    async fn query_tftp_server_name(&self) -> Result<Option<TftpServerName>>;

    /// Queries DHCP for Option 150 (TFTP server addresses)
    async fn query_tftp_server_addresses(&self) -> Result<Option<Vec<std::net::Ipv4Addr>>>;
}
```

The Option 66/150 methods default to `Ok(None)` in the trait, so only implement them
when your provider surfaces those options.

### Functions

#### parse_dhcp_option_120

Parses raw DHCP Option 120 data:

```rust
pub fn parse_dhcp_option_120(data: &[u8]) -> Result<Vec<DhcpSipServer>>
```

**Input Format:**
- First byte: Encoding type (0 or 1)
- Remaining bytes: Payload (domain names or IPv4 addresses)

**Encoding 0 (Domain Names):**
```
[0] [len] [label...] [len] [label...] [0] ...
```

**Encoding 1 (IPv4 Addresses):**
```
[1] [ip1_byte1] [ip1_byte2] [ip1_byte3] [ip1_byte4] [ip2_byte1] ...
```

**Example:**
```rust
// Encoding 1: Two IPv4 addresses
let data = vec![1, 192, 168, 1, 1, 10, 0, 0, 1];
let servers = parse_dhcp_option_120(&data)?;
assert_eq!(servers.len(), 2);

// Encoding 0: "example.com"
let data = vec![0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
let servers = parse_dhcp_option_120(&data)?;
assert_eq!(servers.len(), 1);
```

#### parse_dhcp_option_66

Parses DHCP Option 66 (TFTP server name):

```rust
pub fn parse_dhcp_option_66(data: &[u8]) -> Result<TftpServerName>
```

**Example:**
```rust
let data = b"tftp.example.com";
let server = parse_dhcp_option_66(data)?;
assert_eq!(server.as_str(), "tftp.example.com");
```

#### parse_dhcp_option_150

Parses DHCP Option 150 (TFTP server address list):

```rust
pub fn parse_dhcp_option_150(data: &[u8]) -> Result<Vec<std::net::Ipv4Addr>>
```

**Example:**
```rust
let data = vec![192, 168, 1, 1, 10, 0, 0, 1];
let servers = parse_dhcp_option_150(&data)?;
assert_eq!(servers.len(), 2);
```

### Resolvers

#### StaticDhcpProvider

Testing-friendly DHCP provider with pre-configured servers:

```rust
pub struct StaticDhcpProvider { /* ... */ }

impl StaticDhcpProvider {
    /// Creates a provider that returns the given servers
    pub fn new(servers: Vec<DhcpSipServer>) -> Self;

    /// Creates a provider that returns no servers (simulates DHCP without Option 120)
    pub fn empty() -> Self;

    /// Sets the TFTP server name (Option 66)
    pub fn with_tftp_name(self, name: TftpServerName) -> Self;

    /// Sets the TFTP server addresses (Option 150)
    pub fn with_tftp_addresses(self, addresses: Vec<std::net::Ipv4Addr>) -> Self;
}
```

**Example:**
```rust
let provider = StaticDhcpProvider::new(vec![
    DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
    DhcpSipServer::Ipv4("192.168.1.1".parse()?),
]);

let provider = provider
    .with_tftp_name(TftpServerName(SmolStr::new("tftp.example.com".to_owned())))
    .with_tftp_addresses(vec!["10.0.0.1".parse()?]);
```

#### DhcpResolver

DHCP-only resolver (no DNS fallback):

```rust
pub struct DhcpResolver<D: DhcpProvider, R: Resolver> { /* ... */ }

impl<D: DhcpProvider, R: Resolver> DhcpResolver<D, R> {
    /// Creates a new DHCP resolver
    pub fn new(dhcp_provider: D, dns_resolver: R) -> Self;
}
```

**Example:**
```rust
let dhcp = StaticDhcpProvider::new(vec![
    DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
]);
let dns = SipResolver::from_system()?;
let resolver = DhcpResolver::new(dhcp, dns);

let uri = SipUri::parse("sip:user@example.com")?;
let targets = resolver.resolve(&uri).await?;  // Fails if DHCP unavailable
```

#### HybridResolver

Recommended resolver with DHCP → DNS fallback:

```rust
pub struct HybridResolver<D: DhcpProvider, R: Resolver> { /* ... */ }

impl<D: DhcpProvider, R: Resolver> HybridResolver<D, R> {
    /// Creates a new hybrid resolver
    pub fn new(dhcp_provider: D, dns_resolver: R) -> Self;
}
```

**Example:**
```rust
let dhcp = StaticDhcpProvider::empty(); // No DHCP in this example
let dns = SipResolver::from_system()?;
let resolver = HybridResolver::new(dhcp, dns);

let uri = SipUri::parse("sip:user@example.com")?;
// Tries DHCP first, falls back to DNS
let targets = resolver.resolve(&uri).await?;
```

---

## Usage Examples

### Example 1: Static DHCP Configuration for Testing

```rust
use sip_dns::{HybridResolver, StaticDhcpProvider, SipResolver, DhcpSipServer};
use sip_core::SipUri;
use smol_str::SmolStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure DHCP servers (for testing)
    let dhcp = StaticDhcpProvider::new(vec![
        DhcpSipServer::Ipv4("192.168.1.100".parse()?),
        DhcpSipServer::Domain(SmolStr::new("sip.example.com".to_owned())),
    ]);

    // Configure DNS resolver for fallback
    let dns = SipResolver::from_system()?;

    // Create hybrid resolver
    let resolver = HybridResolver::new(dhcp, dns);

    // Resolve SIP URI
    let uri = SipUri::parse("sip:user@example.com")?;
    let targets = resolver.resolve(&uri).await?;

    for target in targets {
        println!("{}:{} via {:?}", target.host, target.port, target.transport);
    }

    Ok(())
}
```

### Example 2: Parsing DHCP Option 120

```rust
use sip_dns::{parse_dhcp_option_120, DhcpSipServer};

fn process_dhcp_option_120(raw_data: &[u8]) -> anyhow::Result<()> {
    let servers = parse_dhcp_option_120(raw_data)?;

    for server in servers {
        match server {
            DhcpSipServer::Domain(name) => {
                println!("Domain: {}", name);
            }
            DhcpSipServer::Ipv4(addr) => {
                println!("IPv4: {}", addr);
            }
        }
    }

    Ok(())
}

// Example: Encoding 1 (IPv4 addresses)
let data = vec![1, 192, 168, 1, 1, 10, 0, 0, 1];
process_dhcp_option_120(&data)?;

// Example: Encoding 0 (domain names)
let data = vec![0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
process_dhcp_option_120(&data)?;
```

### Example 3: Custom DHCP Provider (Platform-Specific)

```rust
use sip_dns::{DhcpProvider, DhcpSipServer, parse_dhcp_option_120};
use anyhow::{Result, anyhow};

/// Linux DHCP provider that reads dhclient.leases
struct LinuxDhcpProvider {
    lease_file: String,
}

impl LinuxDhcpProvider {
    fn new() -> Self {
        Self {
            lease_file: "/var/lib/dhcp/dhclient.leases".to_string(),
        }
    }

    fn parse_lease_file(&self) -> Result<Option<Vec<u8>>> {
        // Read lease file
        let contents = std::fs::read_to_string(&self.lease_file)?;

        // Look for "option sip-servers" (option 120)
        for line in contents.lines() {
            if line.trim().starts_with("option sip-servers") {
                // Extract hex data and parse
                let hex_data = extract_option_data(line)?;
                return Ok(Some(hex_data));
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl DhcpProvider for LinuxDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        match self.parse_lease_file()? {
            Some(data) => Ok(Some(parse_dhcp_option_120(&data)?)),
            None => Ok(None),
        }
    }
}

// Helper function to extract option data from lease file
fn extract_option_data(line: &str) -> Result<Vec<u8>> {
    // Parse DHCP option format from lease file
    // Implementation depends on dhclient.leases format
    unimplemented!("Platform-specific implementation")
}

// Usage
let dhcp = LinuxDhcpProvider::new();
let dns = SipResolver::from_system()?;
let resolver = HybridResolver::new(dhcp, dns);
```

### Example 4: DHCP-Only Resolution (No DNS Fallback)

```rust
use sip_dns::{DhcpResolver, StaticDhcpProvider, SipResolver, DhcpSipServer};
use sip_core::SipUri;
use smol_str::SmolStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dhcp = StaticDhcpProvider::new(vec![
        DhcpSipServer::Ipv4("192.168.1.100".parse()?),
    ]);

    let dns = SipResolver::from_system()?;
    let resolver = DhcpResolver::new(dhcp, dns);

    let uri = SipUri::parse("sip:user@example.com")?;

    match resolver.resolve(&uri).await {
        Ok(targets) => {
            println!("Resolved via DHCP:");
            for target in targets {
                println!("  {}:{}", target.host, target.port);
            }
        }
        Err(e) => {
            eprintln!("DHCP resolution failed: {}", e);
            // No DNS fallback with DhcpResolver
        }
    }

    Ok(())
}
```

### Example 5: Handling Mixed DHCP Responses

```rust
use sip_dns::{HybridResolver, StaticDhcpProvider, SipResolver, DhcpSipServer};
use sip_core::SipUri;
use smol_str::SmolStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // DHCP returns mix of IPv4 and domains
    let dhcp = StaticDhcpProvider::new(vec![
        DhcpSipServer::Ipv4("192.168.1.100".parse()?),    // Primary
        DhcpSipServer::Domain(SmolStr::new("sip1.example.com".to_owned())),  // Backup
        DhcpSipServer::Domain(SmolStr::new("sip2.example.com".to_owned())),  // Backup
    ]);

    let dns = SipResolver::from_system()?;
    let resolver = HybridResolver::new(dhcp, dns);

    let uri = SipUri::parse("sip:user@example.com")?;
    let targets = resolver.resolve(&uri).await?;

    println!("Resolved targets in preference order:");
    for (i, target) in targets.iter().enumerate() {
        println!("  {}. {}:{} via {:?}",
            i + 1, target.host, target.port, target.transport);
    }

    Ok(())
}
```

### Example 6: Testing DHCP Parsing Edge Cases

```rust
use sip_dns::parse_dhcp_option_120;

#[test]
fn test_dhcp_option_120_edge_cases() -> anyhow::Result<()> {
    // Empty data
    assert!(parse_dhcp_option_120(&[]).is_err());

    // Invalid encoding
    assert!(parse_dhcp_option_120(&[2, 192, 168, 1, 1]).is_err());

    // IPv4 with invalid length
    assert!(parse_dhcp_option_120(&[1, 192, 168, 1]).is_err());

    // Domain with invalid label length
    assert!(parse_dhcp_option_120(&[0, 255, b'a', b'b']).is_err());

    // Valid single IPv4
    let result = parse_dhcp_option_120(&[1, 192, 168, 1, 1])?;
    assert_eq!(result.len(), 1);

    // Valid multiple IPv4
    let result = parse_dhcp_option_120(&[1, 192, 168, 1, 1, 10, 0, 0, 1])?;
    assert_eq!(result.len(), 2);

    // Valid domain name
    let result = parse_dhcp_option_120(&[
        0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ])?;
    assert_eq!(result.len(), 1);

    Ok(())
}
```

---

## Integration Patterns

### UAC Integration

A SIP User Agent Client should integrate DHCP discovery as follows:

```rust
use sip_dns::{HybridResolver, DhcpProvider, SipResolver};
use sip_core::SipUri;

pub struct SipUac<D: DhcpProvider> {
    resolver: HybridResolver<D, SipResolver>,
}

impl<D: DhcpProvider> SipUac<D> {
    pub fn new(dhcp_provider: D) -> anyhow::Result<Self> {
        let dns = SipResolver::from_system()?;
        let resolver = HybridResolver::new(dhcp_provider, dns);
        Ok(Self { resolver })
    }

    pub async fn register(&self, uri: &SipUri) -> anyhow::Result<()> {
        // Resolve SIP server (tries DHCP, falls back to DNS)
        let targets = self.resolver.resolve(uri).await?;

        // Try each target until one succeeds
        for target in targets {
            if let Ok(_) = self.send_register(&target).await {
                return Ok(());
            }
        }

        Err(anyhow!("Registration failed on all targets"))
    }

    async fn send_register(&self, target: &DnsTarget) -> anyhow::Result<()> {
        // Send REGISTER request to target
        todo!()
    }
}
```

### Platform-Specific DHCP Providers

#### Linux (dhclient)

```rust
struct LinuxDhcpProvider;

#[async_trait::async_trait]
impl DhcpProvider for LinuxDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        // Parse /var/lib/dhcp/dhclient.leases
        // Look for "option sip-servers"
        todo!()
    }
}
```

#### Windows (Registry)

```rust
struct WindowsDhcpProvider;

#[async_trait::async_trait]
impl DhcpProvider for WindowsDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        // Query Windows Registry:
        // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
        // Look for DhcpSipServers or use ipconfig /all
        todo!()
    }
}
```

#### macOS (dhcpd_leases)

```rust
struct MacOsDhcpProvider;

#[async_trait::async_trait]
impl DhcpProvider for MacOsDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        // Parse /var/db/dhcpd_leases
        // Or use ipconfig getpacket
        todo!()
    }
}
```

---

## Testing

### Unit Tests

All tests are in `sip-dns/src/lib.rs`:

```rust
// DHCP Option 66 parsing tests
#[test] fn parse_dhcp_option_66_hostname()
#[test] fn parse_dhcp_option_66_ip_address()
#[test] fn parse_dhcp_option_66_fqdn()
#[test] fn parse_dhcp_option_66_empty()
#[test] fn parse_dhcp_option_66_with_whitespace()

// DHCP Option 150 parsing tests
#[test] fn parse_dhcp_option_150_single_address()
#[test] fn parse_dhcp_option_150_multiple_addresses()
#[test] fn parse_dhcp_option_150_invalid_length()
#[test] fn parse_dhcp_option_150_empty()
#[test] fn parse_dhcp_option_150_eight_addresses()

// DHCP Option 120 parsing tests
#[test] fn parse_dhcp_option_120_ipv4_single()
#[test] fn parse_dhcp_option_120_ipv4_multiple()
#[test] fn parse_dhcp_option_120_ipv4_invalid_length()
#[test] fn parse_dhcp_option_120_domain_single()
#[test] fn parse_dhcp_option_120_domain_multiple()
#[test] fn parse_dhcp_option_120_domain_invalid_length()
#[test] fn parse_dhcp_option_120_domain_missing_terminator()
#[test] fn parse_dhcp_option_120_domain_label_too_long()
#[test] fn parse_dhcp_option_120_empty()
#[test] fn parse_dhcp_option_120_invalid_encoding()

// DHCP provider tests
#[test] fn static_dhcp_provider_returns_servers()
#[test] fn static_dhcp_provider_empty()
#[test] fn static_dhcp_provider_with_tftp_name()
#[test] fn static_dhcp_provider_with_tftp_addresses()
#[test] fn static_dhcp_provider_with_all_options()

// DHCP resolver tests
#[test] fn dhcp_resolver_with_ipv4()
#[test] fn dhcp_resolver_with_domain()
#[test] fn dhcp_resolver_fails_when_no_option_120()

// Hybrid resolver tests
#[test] fn hybrid_resolver_uses_dhcp_when_available()
#[test] fn hybrid_resolver_falls_back_to_dns()
#[test] fn hybrid_resolver_prefers_dhcp_over_dns()

// Utility tests
#[test] fn dhcp_sip_server_as_str()
```

### Running Tests

```bash
# Run all tests
cargo test --package sip-dns

# Run only DHCP tests
cargo test --package sip-dns dhcp

# Run with output
cargo test --package sip-dns -- --nocapture
```

---

## RFC 3361 Compliance

### ✅ Implemented Requirements

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Option 120 Support** | ✅ | `parse_dhcp_option_120()` |
| **Encoding 0 (Domains)** | ✅ | RFC 1035 label parsing |
| **Encoding 1 (IPv4)** | ✅ | 4-byte address parsing |
| **Preference Ordering** | ✅ | Maintains DHCP server order |
| **DNS Integration** | ✅ | Domain names resolved via RFC 3263 |
| **Error Handling** | ✅ | Validates encoding and length |
| **Mixed Encodings** | ✅ | Rejects per RFC (no mixing in same message) |

### ❌ Not Implemented

| Requirement | Status | Rationale |
|-------------|--------|-----------|
| **IPv6 Addresses** | ❌ | RFC 3361 is IPv4 only; DHCPv6 uses different option |
| **System DHCP Client** | ❌ | Platform-specific; use `DhcpProvider` trait |
| **DHCP Lease Monitoring** | ❌ | Application layer responsibility |
| **DHCP Request Generation** | ❌ | Use existing DHCP client; we only parse responses |

---

## Security Considerations

Per RFC 3361 §5:

### Downgrade Attack Prevention

If an adversary modifies DHCP responses, they could redirect a SIP UA to a rogue server. Mitigations:

1. **Use Secure DHCP** when available (DHCP with authentication)
2. **Verify TLS Certificates** when connecting to servers
3. **Use HybridResolver** to allow DNS fallback if DHCP seems compromised
4. **Log DHCP Sources** for security auditing

### Implementation Notes

```rust
// Example: Validate DHCP-provided servers
impl DhcpProvider for SecureDhcpProvider {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        let servers = self.query_raw_dhcp().await?;

        // Validate servers against whitelist or policy
        let validated = servers
            .into_iter()
            .filter(|s| self.is_trusted_server(s))
            .collect();

        Ok(Some(validated))
    }
}
```

---

## Performance Considerations

### DHCP Query Timing

- **DHCP queries are synchronous** during network configuration
- **Cache DHCP results** to avoid repeated queries
- **DHCP typically provides static info** that changes only on network reconnect

### Implementation Suggestion

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CachedDhcpProvider<D: DhcpProvider> {
    inner: D,
    cache: Arc<RwLock<Option<Vec<DhcpSipServer>>>>,
}

impl<D: DhcpProvider> CachedDhcpProvider<D> {
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn invalidate(&self) {
        *self.cache.write().await = None;
    }
}

#[async_trait::async_trait]
impl<D: DhcpProvider> DhcpProvider for CachedDhcpProvider<D> {
    async fn query_sip_servers(&self) -> Result<Option<Vec<DhcpSipServer>>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if cache.is_some() {
                return Ok(cache.clone());
            }
        }

        // Query DHCP and update cache
        let servers = self.inner.query_sip_servers().await?;
        *self.cache.write().await = servers.clone();
        Ok(servers)
    }
}
```

---

## Comparison: DHCP vs DNS Discovery

| Aspect | DHCP (RFC 3361) | DNS (RFC 3263) |
|--------|-----------------|----------------|
| **Setup** | Automatic during network config | Requires DNS infrastructure |
| **Use Case** | Enterprise networks, plug-and-play | Internet services, federated networks |
| **Scalability** | Limited to local network | Global, distributed |
| **Flexibility** | Static per network | Dynamic, load-balanced |
| **Security** | Vulnerable to DHCP spoofing | Vulnerable to DNS hijacking |
| **Failover** | Single DHCP server (usually) | Multiple DNS servers, SRV priorities |
| **Cache** | Long-lived (until network change) | TTL-based caching |

### When to Use DHCP

- ✅ Enterprise/corporate networks with centralized DHCP
- ✅ IP phones and endpoints needing zero-config
- ✅ Networks without public DNS infrastructure
- ✅ Mobile devices in carrier networks

### When to Use DNS

- ✅ Internet-facing SIP services
- ✅ Multi-tenant SIP platforms
- ✅ Federated SIP networks
- ✅ Services requiring dynamic load balancing

### Best Practice: Use HybridResolver

The `HybridResolver` provides the best of both:
1. Tries DHCP for local/enterprise networks
2. Falls back to DNS for internet services
3. Handles all scenarios automatically

```rust
let resolver = HybridResolver::new(dhcp_provider, dns_resolver);
// Works everywhere!
```

---

## Future Enhancements

### Potential Additions

1. **DHCPv6 Support** (RFC 3319)
   - IPv6 equivalent of Option 120
   - Different option code and format

2. **DHCP Lease Monitoring**
   - Detect DHCP lease renewals
   - Invalidate cache on network changes

3. **Built-in Platform Providers**
   - Linux: Parse dhclient.leases
   - Windows: Query registry
   - macOS: Parse dhcpd_leases

4. **DHCP Request Generation**
   - Generate DHCP DISCOVER/REQUEST messages
   - Full DHCP client implementation

5. **mDNS/Zeroconf Integration**
   - RFC 6763 DNS-SD for local discovery
   - Complement DHCP/DNS with mDNS

---

## Related RFCs

- **RFC 3361** - DHCP Option for SIP Servers (this implementation)
- **RFC 3263** - Locating SIP Servers via DNS (implemented in `sip-dns`)
- **RFC 2131** - DHCP Protocol
- **RFC 2132** - DHCP Options (Option 66)
- **RFC 1035** - DNS Domain Names (label encoding used in Option 120)
- **RFC 5859** - DHCP Option 150 for TFTP
- **RFC 3319** - DHCPv6 Options for SIP Servers (IPv6 equivalent, not implemented)

---

## References

- [RFC 3361](https://datatracker.ietf.org/doc/html/rfc3361) - DHCP-for-IPv4 Option for SIP Servers
- [RFC 3263](https://datatracker.ietf.org/doc/html/rfc3263) - Locating SIP Servers
- [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131) - DHCP Protocol
- [RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132) - DHCP Options
- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - Domain Names - Implementation and Specification
- [RFC 5859](https://datatracker.ietf.org/doc/html/rfc5859) - DHCP Option 150 for TFTP

---

**Implementation Complete** ✅
All RFC 3361 requirements implemented with comprehensive testing and documentation.
