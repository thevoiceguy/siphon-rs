# RFC 3605: RTCP Attribute in SDP - Implementation Guide

## Overview

This document describes the implementation of **RFC 3605: Real Time Control Protocol (RTCP) attribute in Session Description Protocol (SDP)** in the siphon-rs project. RFC 3605 defines the `a=rtcp:` attribute that allows SDP to explicitly specify the port and optional address for RTCP traffic when it doesn't follow the standard convention.

**Status**: ✅ **Fully Implemented**

## What is RFC 3605?

RFC 3605 addresses a critical issue with Network Address Translation (NAT) and RTCP port allocation. Traditionally, RTP uses consecutive port pairs (even for RTP, odd for RTCP), but NAT devices can disrupt this ordering through port mapping, breaking the algorithmic port derivation assumption.

### The Problem

Without RFC 3605:
1. RTCP port assumed to be RTP port + 1 (next odd port)
2. NAT port mapping breaks consecutive port numbering
3. No way to signal the actual RTCP port after NAT translation
4. RTCP traffic fails to reach destination in NAT scenarios

### The Solution

With RFC 3605:
1. **Explicit RTCP port**: SDP declares the actual RTCP port number
2. **Optional address**: Can specify different IP address for RTCP
3. **NAT compatibility**: Works with STUN/TURN to discover external ports
4. **Backward compatible**: Implementations that don't understand the attribute ignore it

## Key Concepts

### RTCP Attribute Syntax

**Format**: `a=rtcp:<port> [<nettype> <addrtype> <connection-address>]`

#### Port Only (Minimum)
```
a=rtcp:53020
```
- Specifies RTCP port only
- Uses same address as RTP media

#### Full Address (Complete)
```
a=rtcp:53020 IN IP4 126.16.64.4
a=rtcp:53020 IN IP6 2001:2345:6789:ABCD:EF01:2345:6789:ABCD
```
- Specifies both RTCP port and address
- Useful when RTCP goes to different IP than RTP

### When to Use

**Use a=rtcp: when**:
- RTCP port is NOT (RTP port + 1)
- RTCP uses a different IP address than RTP
- Behind NAT with port mapping
- Using STUN/TURN for address discovery

**Don't use when**:
- RTCP uses standard consecutive port (RTP port + 1)
- Same address as RTP media
- Default behavior is sufficient

### Media-Level Only

**Important**: RFC 3605 explicitly states the RTCP attribute:
- **MAY** be used as a media-level attribute
- **MUST NOT** be used as a session-level attribute

Each media stream can have its own RTCP port/address.

## Implementation Architecture

### Core Types (in `sdp.rs`)

#### RtcpAttribute Struct

```rust
/// RTCP attribute (a=rtcp:, RFC 3605).
///
/// Specifies the port and optional address for RTCP traffic when it differs
/// from the default (RTP port + 1). Commonly used in NAT traversal scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpAttribute {
    /// RTCP port number
    pub port: u16,
    /// Network type (e.g., "IN"), optional
    pub nettype: Option<String>,
    /// Address type (e.g., "IP4", "IP6"), optional
    pub addrtype: Option<String>,
    /// Connection address, optional
    pub connection_address: Option<String>,
}

impl RtcpAttribute {
    pub fn new(port: u16) -> Self;
    pub fn with_address(port: u16, nettype: String, addrtype: String,
                        connection_address: String) -> Self;
    pub fn parse(value: &str) -> Result<Self, SdpError>;
    pub fn to_string(&self) -> String;
}
```

#### MediaDescription Integration

```rust
pub struct MediaDescription {
    // ... other fields ...

    /// RTCP port and address (a=rtcp:, RFC 3605)
    pub rtcp: Option<RtcpAttribute>,

    // ... other fields ...
}
```

## Parsing and Generation

### Parsing Example

```rust
use sip_core::SdpSession;

// Parse SDP with RTCP attribute (port only)
let sdp = "\
v=0\r\n\
o=alice 123 456 IN IP4 192.0.2.1\r\n\
s=NAT Scenario\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtcp:53020\r\n\
";

let session = SdpSession::parse(sdp)?;

// Access RTCP attribute
if let Some(rtcp) = &session.media[0].rtcp {
    println!("RTCP port: {}", rtcp.port);  // 53020
    if let Some(addr) = &rtcp.connection_address {
        println!("RTCP address: {}", addr);
    }
}

// Parse SDP with full address
let sdp_full = "\
v=0\r\n\
o=bob 789 321 IN IP4 192.0.2.2\r\n\
s=NAT with Different Address\r\n\
c=IN IP4 192.0.2.2\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtcp:53020 IN IP4 126.16.64.4\r\n\
";

let session2 = SdpSession::parse(sdp_full)?;
let rtcp = session2.media[0].rtcp.as_ref().unwrap();
println!("RTCP: {}:{}",
    rtcp.connection_address.as_ref().unwrap(),
    rtcp.port
);  // "126.16.64.4:53020"
```

### Generation Example

```rust
use sip_core::{SdpSession, RtcpAttribute, MediaDescription, Origin, Connection};

// Create session
let mut session = SdpSession::new(
    Origin {
        username: "alice".to_string(),
        sess_id: "123".to_string(),
        sess_version: "456".to_string(),
        nettype: "IN".to_string(),
        addrtype: "IP4".to_string(),
        unicast_address: "192.0.2.1".to_string(),
    },
    "NAT Session".to_string(),
);

session.connection = Some(Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "192.0.2.1".to_string(),
});

// Add media with RTCP port only
session.media.push(MediaDescription {
    media: "audio".to_string(),
    port: 49170,
    port_count: None,
    proto: "RTP/AVP".to_string(),
    fmt: vec!["0".to_string()],
    title: None,
    connection: None,
    bandwidth: Vec::new(),
    encryption_key: None,
    attributes: Vec::new(),
    mid: None,
    rtcp: Some(RtcpAttribute::new(53020)),
    capability_set: None,
});

// Generate SDP
let sdp_string = session.to_string();
// Contains: a=rtcp:53020

// Add media with full RTCP address
session.media.push(MediaDescription {
    media: "video".to_string(),
    port: 49172,
    port_count: None,
    proto: "RTP/AVP".to_string(),
    fmt: vec!["31".to_string()],
    title: None,
    connection: None,
    bandwidth: Vec::new(),
    encryption_key: None,
    attributes: Vec::new(),
    mid: None,
    rtcp: Some(RtcpAttribute::with_address(
        53022,
        "IN".to_string(),
        "IP4".to_string(),
        "126.16.64.5".to_string(),
    )),
    capability_set: None,
});

let sdp_string2 = session.to_string();
// Contains: a=rtcp:53022 IN IP4 126.16.64.5
```

## Common Use Cases

### Use Case 1: Simple NAT Scenario

Client behind NAT discovers external ports via STUN:

```
v=0
o=user 0 0 IN IP4 192.168.1.100
s=Call Behind NAT
c=IN IP4 203.0.113.5
t=0 0
m=audio 49170 RTP/AVP 0
a=rtcp:53020
```

**Interpretation**:
- Internal: RTP on 49170, RTCP on 49171
- External (after NAT): RTP on 49170, RTCP on 53020
- RTCP attribute specifies the external RTCP port

### Use Case 2: Split RTP/RTCP Addresses

RTCP sent to monitoring/QoS server:

```
v=0
o=user 0 0 IN IP4 192.0.2.1
s=Monitored Call
c=IN IP4 192.0.2.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtcp:5000 IN IP4 monitor.example.com
```

**Interpretation**:
- RTP media: 192.0.2.1:49170
- RTCP reports: monitor.example.com:5000
- QoS monitoring separate from media path

### Use Case 3: Multiple Media Streams

Different RTCP ports for each media:

```
v=0
o=user 0 0 IN IP4 192.0.2.1
s=Multi-Media NAT
c=IN IP4 192.0.2.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtcp:53020
m=video 49172 RTP/AVP 31
a=rtcp:53022 IN IP4 126.16.64.5
```

**Interpretation**:
- Audio RTCP: Same address as RTP, port 53020
- Video RTCP: Different address (126.16.64.5), port 53022
- Each media independently configurable

### Use Case 4: IPv6 Support

RTCP over IPv6:

```
v=0
o=user 0 0 IN IP6 2001:db8::1
s=IPv6 Session
c=IN IP6 2001:db8::1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtcp:53020 IN IP6 2001:db8::2
```

**Interpretation**:
- RTP: 2001:db8::1:49170
- RTCP: 2001:db8::2:53020
- Supports IPv4 and IPv6 addresses

## Integration with NAT Traversal

### STUN/TURN Workflow

1. **Discover external address**:
   ```rust
   // Use STUN to discover external IP and ports
   let external_rtp_port = stun_discover_port(local_rtp_port);
   let external_rtcp_port = stun_discover_port(local_rtcp_port);
   ```

2. **Create SDP with discovered ports**:
   ```rust
   let rtcp_attr = if external_rtcp_port != external_rtp_port + 1 {
       // RTCP port doesn't follow convention, include attribute
       Some(RtcpAttribute::new(external_rtcp_port))
   } else {
       // Standard port, no attribute needed
       None
   };
   ```

3. **Include in SDP offer/answer**:
   ```rust
   media.rtcp = rtcp_attr;
   let sdp = session.to_string();
   // Send via SIP signaling
   ```

### Example Implementation

```rust
use sip_core::{SdpSession, RtcpAttribute};

fn create_nat_sdp(
    local_rtp_port: u16,
    external_rtp_port: u16,
    external_rtcp_port: u16,
    external_ip: &str,
) -> SdpSession {
    let mut session = /* ... create session ... */;

    let rtcp_attr = if external_rtcp_port != external_rtp_port + 1 {
        Some(RtcpAttribute::with_address(
            external_rtcp_port,
            "IN".to_string(),
            "IP4".to_string(),
            external_ip.to_string(),
        ))
    } else {
        None
    };

    session.media[0].port = external_rtp_port;
    session.media[0].rtcp = rtcp_attr;

    session
}
```

## Security Considerations

RFC 3605 highlights security concerns:

### Threats

**Malicious RTCP Redirection**:
- Attacker intercepts SDP signaling
- Modifies `a=rtcp:` to redirect RTCP to attacker's server
- RTCP reports leak session information
- Could enable traffic analysis or DoS

### Mitigations

**1. SDP Integrity Protection** (Recommended by RFC):
```
Use S/MIME to sign SDP bodies in SIP
```

**2. Validate RTCP Endpoints**:
```rust
fn validate_rtcp_endpoint(rtcp: &RtcpAttribute, expected_network: &str) -> bool {
    if let Some(addr) = &rtcp.connection_address {
        // Check if address is within expected network range
        is_address_in_network(addr, expected_network)
    } else {
        true  // Using same address as RTP
    }
}
```

**3. Monitor RTCP Traffic**:
- Verify RTCP packets come from declared address
- Alert on unexpected RTCP sources

## Testing

The implementation includes 21 comprehensive tests covering:

### RtcpAttribute Tests (9 tests)
- `rtcp_attribute_new` - Port-only constructor
- `rtcp_attribute_with_address` - Full address constructor
- `rtcp_attribute_parse_port_only` - Parse port-only format
- `rtcp_attribute_parse_with_address_ipv4` - Parse IPv4 address
- `rtcp_attribute_parse_with_address_ipv6` - Parse IPv6 address
- `rtcp_attribute_parse_invalid_port` - Error handling
- `rtcp_attribute_parse_incomplete_address` - Validation
- `rtcp_attribute_to_string_port_only` - Generate port-only
- `rtcp_attribute_to_string_with_address` - Generate with address

### SDP Integration Tests (9 tests)
- `parse_sdp_with_rtcp_port_only` - Parse SDP with port
- `parse_sdp_with_rtcp_full_address` - Parse SDP with address
- `parse_sdp_with_rtcp_ipv6` - IPv6 support
- `parse_sdp_without_rtcp` - Absent attribute handling
- `generate_sdp_with_rtcp_port_only` - Generate SDP with port
- `generate_sdp_with_rtcp_full_address` - Generate SDP with address
- `round_trip_rtcp_port_only` - Parse→Generate→Parse (port)
- `round_trip_rtcp_with_address` - Parse→Generate→Parse (address)
- `multiple_media_with_different_rtcp` - Multiple media streams

### RFC Compliance Tests (3 tests)
- `rfc_3605_example_1` - RFC 3605 Example 1 (port only)
- `rfc_3605_example_2` - RFC 3605 Example 2 (IPv4 address)
- `rfc_3605_example_3` - RFC 3605 Example 3 (IPv6 address)

Run tests with:
```bash
cargo test rtcp_attribute
cargo test rfc_3605
cargo test --lib 2>&1 | grep rtcp
```

## Implementation Status Summary

| Feature | Status | Notes |
|---------|--------|-------|
| **RtcpAttribute struct** | ✅ Complete | Port + optional address |
| **Port-only parsing** | ✅ Complete | a=rtcp:53020 |
| **Full address parsing** | ✅ Complete | a=rtcp:53020 IN IP4 126.16.64.4 |
| **IPv6 support** | ✅ Complete | Works with IPv6 addresses |
| **Generation** | ✅ Complete | Correct formatting |
| **MediaDescription integration** | ✅ Complete | Optional rtcp field |
| **Extraction from attributes** | ✅ Complete | extract_rtcp() method |
| **Display implementation** | ✅ Complete | to_string() method |
| **Round-trip fidelity** | ✅ Complete | Parse→Generate→Parse |
| **Error handling** | ✅ Complete | Invalid port, incomplete address |
| **Backward compatibility** | ✅ Complete | Optional attribute |
| **Test coverage** | ✅ Complete | 21 comprehensive tests |
| **Documentation** | ✅ Complete | This document |

## Code Locations

| Component | File | Lines |
|-----------|------|-------|
| RtcpAttribute struct | `crates/sip-core/src/sdp.rs` | 386-468 |
| MediaDescription.rtcp | `crates/sip-core/src/sdp.rs` | 352-353 |
| extract_rtcp() method | `crates/sip-core/src/sdp.rs` | 1259-1281 |
| Display implementation | `crates/sip-core/src/sdp.rs` | 1733-1736 |
| Tests | `crates/sip-core/src/sdp.rs` | 4116-4487 |
| Exports | `crates/sip-core/src/lib.rs` | 95 |

## References

- **RFC 3605**: Real Time Control Protocol (RTCP) attribute in Session Description Protocol (SDP)
  - https://datatracker.ietf.org/doc/html/rfc3605
  - Section 2: SDP attribute syntax
  - Section 3: Usage examples
  - Section 4: Security considerations

- **RFC 3550**: RTP: A Transport Protocol for Real-Time Applications
  - https://datatracker.ietf.org/doc/html/rfc3550
  - Section 11: RTP and RTCP port conventions

- **RFC 4566**: SDP: Session Description Protocol
  - https://datatracker.ietf.org/doc/html/rfc4566
  - Section 5.13: Attributes

- **RFC 5389**: STUN: Session Traversal Utilities for NAT
  - https://datatracker.ietf.org/doc/html/rfc5389
  - Used for discovering external ports

## Relationship to Other RFCs

```
RFC 3550 (RTP/RTCP)
    ├── Defines: RTP on port N, RTCP on port N+1
    ├── Problem: NAT breaks port numbering
    └── Limitation: No way to signal actual RTCP port

RFC 3605 (This Implementation)
    ├── Extends: SDP with a=rtcp: attribute
    ├── Solves: Explicit RTCP port signaling
    └── Purpose: NAT traversal for RTCP

RFC 5389 (STUN)
    ├── Discovers: External IP and ports after NAT
    ├── Provides: Values for a=rtcp: attribute
    └── Complementary: Used together with RFC 3605

RFC 3556 (RTCP Bandwidth)
    ├── Specifies: RTCP bandwidth allocation
    ├── Complementary: b=RS:/RR: with a=rtcp:
    └── Together: Control both bandwidth and port/address
```

## Future Enhancements

While the current implementation is fully compliant with RFC 3605, potential future work includes:

1. **STUN Integration**: Helper functions to populate RTCP attribute from STUN results
2. **Validation**: Check RTCP address matches expected network topology
3. **Symmetric RTP**: Detect and warn about symmetric RTP requirements
4. **ICE Integration**: Combine with ICE candidates for complete NAT traversal

## Changelog

- **2024-01-21**: Initial implementation of RFC 3605
  - Added RtcpAttribute struct with full IPv4/IPv6 support
  - Added rtcp field to MediaDescription
  - Implemented parsing with extract_rtcp() method
  - Implemented generation in Display trait
  - Added 21 comprehensive tests
  - All 467 tests passing (446 existing + 21 new)
