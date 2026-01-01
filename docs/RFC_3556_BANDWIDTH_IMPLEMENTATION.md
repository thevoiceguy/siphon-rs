# RFC 3556: SDP Bandwidth Modifiers for RTCP Bandwidth - Implementation Guide

## Overview

This document describes the implementation of **RFC 3556: Session Description Protocol (SDP) Bandwidth Modifiers for RTCP Bandwidth** in the siphon-rs project. RFC 3556 defines two new SDP bandwidth modifiers (RS and RR) that allow endpoints to explicitly specify RTCP bandwidth allocation independently from the total session bandwidth.

**Status**: ✅ **Fully Implemented**

## What is RFC 3556?

RFC 3556 extends SDP's bandwidth specification mechanism to provide fine-grained control over RTCP bandwidth allocation in RTP sessions. This enables proper QoS management for control traffic separate from media streams.

### The Problem

Without RFC 3556:
1. RTCP bandwidth is calculated as a fixed fraction (5%) of session bandwidth
2. No way to independently control sender vs. receiver RTCP bandwidth
3. Cannot allocate RTCP bandwidth when AS (Application Specific) modifier is not used
4. Difficult to manage RTCP overhead in asymmetric scenarios

### The Solution

With RFC 3556:
1. **RS modifier**: Explicitly specifies bandwidth for active data senders' RTCP
2. **RR modifier**: Explicitly specifies bandwidth for receivers/non-senders' RTCP
3. Values in bits per second (not kilobits like AS/CT)
4. Provides precise control for QoS reservations

## Key Concepts

### RTCP Bandwidth Modifiers

#### RS (RTCP Senders)
- **Purpose**: Specifies bandwidth allocated for RTCP from active data senders
- **Unit**: Bits per second (bps)
- **Syntax**: `b=RS:<bandwidth-in-bps>`
- **Scope**: Session-level or media-level

#### RR (RTCP Receivers)
- **Purpose**: Specifies bandwidth for RTCP from receivers and inactive senders
- **Unit**: Bits per second (bps)
- **Syntax**: `b=RR:<bandwidth-in-bps>`
- **Scope**: Session-level or media-level

### Bandwidth Allocation Rules

From RFC 3556, at least **RS/(RS+RR)** of the total RTCP bandwidth MUST be allocated to active data senders.

**Example**: If RS=800 and RR=200:
- Total RTCP bandwidth = 1000 bps
- Senders get at least 800/1000 = 80% of RTCP bandwidth
- Receivers/non-senders share remaining 20%

### Units: bps vs kbps

**Critical distinction**:
- **RS/RR**: Values in **bits per second** (bps)
- **AS/CT**: Values in **kilobits per second** (kbps)
- **TIAS**: Values in **bits per second** (bps)

This difference reflects that RTCP bandwidth is typically much smaller than media bandwidth.

## Implementation Architecture

### Core Types (in `sdp.rs`)

#### BandwidthType Enum

```rust
/// Bandwidth modifier type (RFC 4566, RFC 3556, RFC 3890).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthType {
    /// Conference Total (CT) - total bandwidth for all sites
    CT,
    /// Application Specific (AS) - application-specific maximum
    AS,
    /// RTCP bandwidth for active data senders (RFC 3556)
    RS,
    /// RTCP bandwidth for receivers/non-senders (RFC 3556)
    RR,
    /// TIAS - Transport Independent Application Specific
    TIAS,
    /// Other/unregistered bandwidth type
    Other(char),
}

impl BandwidthType {
    pub fn as_str(&self) -> &str;
    pub fn parse(s: &str) -> Self;
    pub fn is_rtcp(&self) -> bool;  // Returns true for RS or RR
}
```

#### Enhanced Bandwidth Struct

```rust
/// Bandwidth line (b=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bandwidth {
    bwtype: String,
    bandwidth: u64,  // kbps for AS/CT, bps for RS/RR/TIAS
}

impl Bandwidth {
    pub fn new(bwtype: impl Into<String>, bandwidth: u64) -> Self;

    // Convenience constructors
    pub fn rtcp_senders(bps: u64) -> Self;       // Creates RS
    pub fn rtcp_receivers(bps: u64) -> Self;     // Creates RR
    pub fn application_specific(kbps: u64) -> Self;  // Creates AS
    pub fn conference_total(kbps: u64) -> Self;      // Creates CT
    pub fn tias(bps: u64) -> Self;                   // Creates TIAS

    // Type checking
    pub fn bandwidth_type(&self) -> BandwidthType;
    pub fn is_rtcp(&self) -> bool;
}
```

Fields are private; use the constructors, `bandwidth_type()`, and `is_rtcp()` for inspection. The
`Display` implementation renders the full `b=` line.

## Parsing and Generation

### Parsing Example

```rust
use sip_core::SdpSession;

let sdp = "\
v=0\r\n\
o=alice 123 456 IN IP4 192.0.2.1\r\n\
s=Audio Conference\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
b=AS:128\r\n\
b=RS:2000\r\n\
b=RR:1500\r\n\
m=audio 49170 RTP/AVP 0\r\n\
";

let session = SdpSession::parse(sdp)?;

// Access bandwidth modifiers
for bw in session.bandwidth() {
    let value = bw
        .to_string()
        .split_once(':')
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .unwrap_or_default();

    println!(
        "{}: {} {}",
        bw.bandwidth_type(),
        value,
        if bw.is_rtcp() { "bps" } else { "kbps" }
    );
}
// Output:
// AS: 128 kbps
// RS: 2000 bps
// RR: 1500 bps

// Check specific modifiers
let rtcp_bandwidth: Vec<_> = session
    .bandwidth()
    .iter()
    .filter(|bw| bw.is_rtcp())
    .collect();

assert_eq!(rtcp_bandwidth.len(), 2);
```

### Generation Example

```rust
use sip_core::Bandwidth;

let bandwidth_lines = [
    Bandwidth::application_specific(128).to_string(), // 128 kbps
    Bandwidth::rtcp_senders(2000).to_string(),        // 2000 bps
    Bandwidth::rtcp_receivers(1500).to_string(),      // 1500 bps
]
.join("\r\n");

let sdp_string = format!(
    "v=0\r\n\
o=alice 123 456 IN IP4 192.0.2.1\r\n\
s=RTCP Bandwidth Example\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
{}\r\n\
m=audio 49170 RTP/AVP 0\r\n",
    bandwidth_lines
);

// Contains:
// b=AS:128
// b=RS:2000
// b=RR:1500
```

You can parse and round-trip the generated SDP if needed:

```rust
use sip_core::SdpSession;

let session = SdpSession::parse(&sdp_string)?;
let round_trip = session.to_string();
// Contains:
// b=AS:128
// b=RS:2000
// b=RR:1500
```

## Common Use Cases

### Use Case 1: Session-Level RTCP Bandwidth

Specify RTCP bandwidth for the entire session:

```
v=0
o=alice 123 456 IN IP4 192.0.2.1
s=Multi-Stream Conference
c=IN IP4 192.0.2.1
t=0 0
b=AS:256
b=RS:4000
b=RR:2000
m=audio 49170 RTP/AVP 0
m=video 49172 RTP/AVP 31
```

**Interpretation**:
- Total application bandwidth: 256 kbps
- RTCP senders bandwidth: 4000 bps (4 kbps)
- RTCP receivers bandwidth: 2000 bps (2 kbps)
- Total RTCP: 6000 bps (6 kbps = ~2.3% of total)
- Applies to all media streams

### Use Case 2: Per-Media RTCP Bandwidth

Different RTCP allocations for different media types:

```
v=0
o=bob 789 321 IN IP4 192.0.2.2
s=AV Conference
c=IN IP4 192.0.2.2
t=0 0
m=audio 49170 RTP/AVP 0
b=AS:64
b=RS:1000
b=RR:500
m=video 49172 RTP/AVP 31
b=AS:512
b=RS:8000
b=RR:4000
```

**Interpretation**:
- Audio stream:
  - Media bandwidth: 64 kbps
  - RTCP senders: 1000 bps
  - RTCP receivers: 500 bps
- Video stream:
  - Media bandwidth: 512 kbps
  - RTCP senders: 8000 bps
  - RTCP receivers: 4000 bps

### Use Case 3: Asymmetric Scenarios

One-way streaming with many receivers:

```
v=0
o=streamer 111 222 IN IP4 192.0.2.3
s=Live Stream
c=IN IP4 233.1.2.3
t=0 0
b=AS:1000
b=RS:5000
b=RR:500
m=video 49170 RTP/AVP 31
```

**Interpretation**:
- Total RTCP: 5500 bps
- Senders (streamer) get 5000 bps (91%)
- Each receiver shares remaining 500 bps
- Optimized for single sender, many receivers

### Use Case 4: Conservative RTCP Allocation

Low-overhead RTCP for bandwidth-constrained links:

```
v=0
o=alice 333 444 IN IP4 192.0.2.4
s=Low Bandwidth Call
c=IN IP4 192.0.2.4
t=0 0
m=audio 49170 RTP/AVP 0
b=AS:32
b=RS:500
b=RR:300
```

**Interpretation**:
- Audio: 32 kbps (narrow-band codec)
- RTCP: 800 bps total (~2.5% of media)
- Minimal RTCP overhead for constrained link

## Bandwidth Calculation Helper

Example function to validate RFC 3556 compliance:

```rust
use sip_core::{Bandwidth, BandwidthType, SdpSession};

fn analyze_rtcp_bandwidth(session: &SdpSession) {
    let mut rs_bandwidth = None;
    let mut rr_bandwidth = None;

    fn bandwidth_value(bw: &Bandwidth) -> Option<u64> {
        bw.to_string()
            .split_once(':')
            .and_then(|(_, value)| value.parse::<u64>().ok())
    }

    for bw in session.bandwidth() {
        if let Some(value) = bandwidth_value(bw) {
            match bw.bandwidth_type() {
                BandwidthType::RS => rs_bandwidth = Some(value),
                BandwidthType::RR => rr_bandwidth = Some(value),
                _ => {}
            }
        }
    }

    if let (Some(rs), Some(rr)) = (rs_bandwidth, rr_bandwidth) {
        let total_rtcp = rs + rr;
        let sender_fraction = rs as f64 / total_rtcp as f64;

        println!("RTCP Bandwidth Analysis:");
        println!("  Senders (RS): {} bps ({:.1}%)", rs, sender_fraction * 100.0);
        println!(
            "  Receivers (RR): {} bps ({:.1}%)",
            rr,
            (1.0 - sender_fraction) * 100.0
        );
        println!("  Total RTCP: {} bps", total_rtcp);
    } else {
        println!("RTCP Bandwidth Analysis: RS/RR modifiers not both present");
    }
}
```

## Interaction with Other RFCs

### RFC 3550 (RTP)
RFC 3556 modifiers control bandwidth allocated for RTCP packets defined in RFC 3550. The default 5% RTCP allocation rule is overridden when RS/RR are present.

### RFC 3551 (RTP/AVP)
RFC 3556 modifiers apply to RTCP traffic for media streams using the RTP/AVP profile.

### RFC 4566 (SDP)
RFC 3556 extends the `b=` line syntax from RFC 4566, adding two new modifier types (RS and RR) alongside existing CT, AS, and TIAS modifiers.

### RFC 3524 (SRF)
RFC 3556 and RFC 3524 are complementary:
- RFC 3524 (SRF): Groups media streams for resource reservation flows
- RFC 3556 (RS/RR): Specifies RTCP bandwidth within those flows

Example combining both:
```
a=group:SRF 1 2
b=RS:4000
b=RR:2000
m=audio 30000 RTP/AVP 0
a=mid:1
m=video 30002 RTP/AVP 31
a=mid:2
```
Both audio and video share one reservation flow with 6000 bps total RTCP.

## Security Considerations

RFC 3556 emphasizes security:

**Threat**: Malicious SDP with inflated RS/RR values could:
- Cause excessive bandwidth reservation
- Waste network resources on RTCP overhead
- Create denial of service conditions

**Mitigation** (as recommended by RFC 3556):
- Use S/MIME or other mechanisms to provide integrity protection for SDP
- Validate RS/RR values against policy limits before reserving resources
- Implement admission control for RTCP bandwidth
- Monitor actual RTCP usage vs. declared bandwidth

The implementation focuses on correct parsing and generation; security policy enforcement is application-level.

## Testing

The implementation includes 14 comprehensive tests covering:

### BandwidthType Tests
- `parse_bandwidth_type_rs` - Parse RS modifier
- `parse_bandwidth_type_rr` - Parse RR modifier
- `parse_bandwidth_type_case_insensitive` - Case handling (RS, rs, Rs)
- `bandwidth_type_display` - String representation
- `bandwidth_type_is_rtcp` - RTCP type detection

### Bandwidth Constructor Tests
- `bandwidth_rtcp_senders_constructor` - RS convenience constructor
- `bandwidth_rtcp_receivers_constructor` - RR convenience constructor
- `bandwidth_application_specific_constructor` - AS constructor
- `bandwidth_conference_total_constructor` - CT constructor

### SDP Integration Tests
- `parse_sdp_with_rtcp_bandwidth` - Parse SDP with RS/RR
- `parse_sdp_with_mixed_bandwidth` - Mixed AS/RS/RR modifiers
- `generate_sdp_with_rtcp_bandwidth` - Generate SDP with RTCP bandwidth
- `round_trip_rtcp_bandwidth` - Parse → Generate → Parse
- `rtcp_bandwidth_media_level` - Per-media RTCP bandwidth

### RFC Compliance Tests
- `rfc_3556_example` - Example from RFC 3556 specification

Run tests with:
```bash
cargo test bandwidth_type
cargo test bandwidth_rtcp
cargo test rtcp_bandwidth
cargo test rfc_3556_example
```

## Implementation Status Summary

| Feature | Status | Notes |
|---------|--------|-------|
| **RS modifier** | ✅ Complete | BandwidthType::RS variant |
| **RR modifier** | ✅ Complete | BandwidthType::RR variant |
| **Parsing** | ✅ Complete | Case-insensitive, integrated with existing bandwidth parsing |
| **Generation** | ✅ Complete | Correct formatting (b=RS:, b=RR:) |
| **Display** | ✅ Complete | as_str() and Display trait |
| **Type checking** | ✅ Complete | is_rtcp() method |
| **Constructors** | ✅ Complete | rtcp_senders(), rtcp_receivers() |
| **Session-level** | ✅ Complete | Works at session level |
| **Media-level** | ✅ Complete | Works at media level |
| **Round-trip fidelity** | ✅ Complete | Parse→Generate→Parse |
| **Test coverage** | ✅ Complete | 14 comprehensive tests |
| **Documentation** | ✅ Complete | This document |

## Code Locations

| Component | File | Lines |
|-----------|------|-------|
| BandwidthType enum | `crates/sip-core/src/sdp.rs` | 386-438 |
| RS variant | `crates/sip-core/src/sdp.rs` | 395-396 |
| RR variant | `crates/sip-core/src/sdp.rs` | 397-398 |
| is_rtcp() method | `crates/sip-core/src/sdp.rs` | 434-437 |
| Bandwidth struct | `crates/sip-core/src/sdp.rs` | 449-519 |
| rtcp_senders() | `crates/sip-core/src/sdp.rs` | 488-493 |
| rtcp_receivers() | `crates/sip-core/src/sdp.rs` | 495-500 |
| Tests | `crates/sip-core/src/sdp.rs` | 4456-4715 |
| Exports | `crates/sip-core/src/lib.rs` | 119 |

## References

- **RFC 3556**: Session Description Protocol (SDP) Bandwidth Modifiers for RTP Control Protocol (RTCP) Bandwidth
  - https://datatracker.ietf.org/doc/html/rfc3556
  - Section 2: SDP extensions (RS and RR)
  - Section 3: Default bandwidth values
  - Section 4: Precedence
  - Section 5: Security considerations

- **RFC 3550**: RTP: A Transport Protocol for Real-Time Applications
  - https://datatracker.ietf.org/doc/html/rfc3550
  - Section 6.2: RTCP transmission interval

- **RFC 4566**: SDP: Session Description Protocol
  - https://datatracker.ietf.org/doc/html/rfc4566
  - Section 5.8: Bandwidth information (b=)

## Relationship to Other RFCs

```
RFC 4566 (SDP Base)
    ├── Defines: b=<bwtype>:<bandwidth>
    ├── Defines: AS and CT modifiers
    └── Units: kilobits per second

RFC 3556 (This Implementation)
    ├── Extends: RFC 4566 bandwidth syntax
    ├── Adds: RS and RR modifiers
    ├── Units: bits per second (not kilobits!)
    └── Purpose: Explicit RTCP bandwidth control

RFC 3550 (RTP/RTCP)
    ├── Defines: RTCP packet types
    ├── Default: 5% of session bandwidth
    └── Overridden by: RFC 3556 RS/RR modifiers
```

## Future Enhancements

While the current implementation is fully compliant with RFC 3556, potential future work includes:

1. **Validation Helpers**: Functions to validate RS/RR ratios against RFC 3556 rules
2. **Bandwidth Calculator**: Utility to suggest RS/RR values based on participant count
3. **RTCP Integration**: Example code showing RTCP packet scheduling with RS/RR
4. **Policy Framework**: Configurable limits for RTCP bandwidth allocation

## Changelog

- **2024-01-21**: Initial implementation of RFC 3556
  - Added RS and RR variants to BandwidthType enum
  - Enhanced Bandwidth struct with convenience constructors
  - Added is_rtcp() methods for type checking
  - Updated parsing and display logic
  - Added 14 comprehensive tests
