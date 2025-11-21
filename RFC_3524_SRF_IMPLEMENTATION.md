# RFC 3524: Mapping of Media Streams to Resource Reservation Flows - Implementation Guide

## Overview

This document describes the implementation of **RFC 3524: Mapping of Media Streams to Resource Reservation Flows** in the siphon-rs project. RFC 3524 extends the SDP grouping framework (RFC 3388) with **SRF (Single Reservation Flow)** semantics, allowing endpoints to specify how multiple media streams should be mapped to resource reservation flows for QoS management.

**Status**: ✅ **Fully Implemented**

## What is SRF?

SRF (Single Reservation Flow) is a grouping semantic that indicates which media streams should share the same resource reservation flow. This is critical for QoS management in multimedia sessions where multiple streams (audio, video, data) may need coordinated resource allocation.

### The Problem

Without SRF:
1. Network has no declarative way to know which streams should share QoS resources
2. Applications must coordinate resource reservation separately from SDP negotiation
3. No standard way to express "audio and video should use one RSVP session"
4. Difficult to optimize resource usage across multiple streams

### The Solution

With SRF:
1. SDP explicitly declares which streams share reservation flows: `a=group:SRF 1 2`
2. Network elements can parse SDP to configure QoS before media flows
3. Flexible mapping: all streams in one flow, each stream separate, or mixed strategies
4. Standard way to express reservation topology

## Key Concepts

### Single Reservation Flow (SRF)

**Definition**: Media lines grouped using SRF semantics SHOULD be mapped into the same resource reservation flow.

**Syntax**: Uses existing SDP grouping framework from RFC 3388
```
a=group:SRF <mid1> <mid2> [<mid3> ...]
```

**Semantics**:
- Media streams in the group share one reservation flow (e.g., one RSVP session)
- Media streams NOT in any group use separate flows
- A group can contain a single media line (isolates that stream)
- Multiple SRF groups create multiple independent reservation flows

### Resource Reservation Flow

A **resource reservation flow** is a network pathway with:
- Assigned QoS parameters (bandwidth, latency, jitter)
- Filtering rules (source/destination IP, ports)
- Maintained by protocols like RSVP or DiffServ

SRF groups declare how to map SDP media descriptions to these flows.

### Relationship to RFC 3388

RFC 3524 is an **extension** to RFC 3388's grouping framework:
- RFC 3388 defined: LS (Lip Synchronization), FID (Flow Identification)
- RFC 3524 adds: SRF (Single Reservation Flow)
- Uses same syntax: `a=group:<semantics> <mids>` and `a=mid:<id>`
- Compatible with other group semantics

## Implementation Architecture

### Core Types (in `sdp.rs`)

The SRF implementation extends the existing `GroupSemantics` enum:

```rust
/// Group semantics for media line grouping (RFC 3388, RFC 3524).
pub enum GroupSemantics {
    /// Lip Synchronization (RFC 3388)
    LS,
    /// Flow Identification (RFC 3388)
    FID,
    /// Single Reservation Flow (RFC 3524)
    SRF,
    /// Other semantics (extensible)
    Other(String),
}

impl GroupSemantics {
    pub fn as_str(&self) -> &str {
        match self {
            GroupSemantics::LS => "LS",
            GroupSemantics::FID => "FID",
            GroupSemantics::SRF => "SRF",
            GroupSemantics::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "LS" => GroupSemantics::LS,
            "FID" => GroupSemantics::FID,
            "SRF" => GroupSemantics::SRF,
            _ => GroupSemantics::Other(s.to_string()),
        }
    }
}
```

### Existing Infrastructure

SRF leverages the complete grouping infrastructure from RFC 3388:

```rust
/// Media group (a=group:) for grouping media lines
pub struct MediaGroup {
    pub semantics: GroupSemantics,  // LS, FID, SRF, or Other
    pub mids: Vec<String>,          // Media IDs
}

pub struct SdpSession {
    // ... other fields ...
    pub groups: Vec<MediaGroup>,    // All group attributes
    pub media: Vec<MediaDescription>,
}

pub struct MediaDescription {
    // ... other fields ...
    pub mid: Option<String>,        // Media ID (a=mid:)
}
```

## Parsing and Generation

### Parsing Example

```rust
use sip_core::SdpSession;

let sdp = "\
v=0\r\n\
o=Laura 289083124 289083124 IN IP4 one.example.com\r\n\
s=SDP Seminar\r\n\
c=IN IP4 192.0.0.1\r\n\
t=0 0\r\n\
a=group:SRF 1 2\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=mid:1\r\n\
m=video 30002 RTP/AVP 31\r\n\
a=mid:2\r\n\
";

let session = SdpSession::parse(sdp)?;

// Access SRF groups
for group in &session.groups {
    if group.semantics == GroupSemantics::SRF {
        println!("SRF group with media IDs: {:?}", group.mids);
        // Output: SRF group with media IDs: ["1", "2"]
    }
}

// Access media with IDs
for media in &session.media {
    if let Some(mid) = &media.mid {
        println!("Media {} on port {}", mid, media.port);
    }
}
```

### Generation Example

```rust
use sip_core::{SdpSession, MediaGroup, GroupSemantics, MediaDescription,
               Origin, Connection};

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
    "Multi-Stream Session".to_string(),
);

session.connection = Some(Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "192.0.2.1".to_string(),
});

// Add SRF group
session.groups.push(MediaGroup {
    semantics: GroupSemantics::SRF,
    mids: vec!["audio".to_string(), "video".to_string()],
});

// Add audio media
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
    mid: Some("audio".to_string()),
    capability_set: None,
});

// Add video media
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
    mid: Some("video".to_string()),
    capability_set: None,
});

// Generate SDP
let sdp_string = session.to_string();
// Contains: a=group:SRF audio video
```

## Common Use Cases

### Use Case 1: Combined Audio/Video Reservation

Map audio and video to a single RSVP session:

```
v=0
o=alice 123 456 IN IP4 192.0.2.1
s=AV Conference
c=IN IP4 192.0.2.1
t=0 0
a=group:SRF 1 2
m=audio 30000 RTP/AVP 0
a=mid:1
m=video 30002 RTP/AVP 31
a=mid:2
```

**Result**: One RSVP session reserves resources for both audio and video streams together.

### Use Case 2: Isolated Stream Reservation

Create a dedicated reservation flow for a single stream:

```
v=0
o=bob 789 321 IN IP4 192.0.2.2
s=Priority Audio
c=IN IP4 192.0.2.2
t=0 0
a=group:SRF 1
m=audio 30000 RTP/AVP 0
a=mid:1
m=video 30002 RTP/AVP 31
a=mid:2
```

**Result**:
- Audio (mid:1) gets dedicated RSVP session
- Video (mid:2) gets separate RSVP session (not in any group)

### Use Case 3: Multiple Independent Flows

Create separate reservation flows for different media groups:

```
v=0
o=carol 111 222 IN IP4 192.0.2.3
s=Multi-Flow Session
c=IN IP4 192.0.2.3
t=0 0
a=group:SRF 1 2
a=group:SRF 3
m=audio 30000 RTP/AVP 0
a=mid:1
m=video 30002 RTP/AVP 31
a=mid:2
m=video 30004 RTP/AVP 32
a=mid:3
```

**Result**:
- Flow 1: Audio (mid:1) + Video (mid:2) in one RSVP session
- Flow 2: Video (mid:3) in separate RSVP session

### Use Case 4: Mixed Semantics

Combine SRF with other group semantics:

```
v=0
o=dave 333 444 IN IP4 192.0.2.4
s=Complex Session
c=IN IP4 192.0.2.4
t=0 0
a=group:LS 1 2
a=group:SRF 1 2 3
m=audio 30000 RTP/AVP 0
a=mid:1
m=video 30002 RTP/AVP 31
a=mid:2
m=application 30004 udp wb
a=mid:3
```

**Interpretation**:
- LS group: Audio and video must be synchronized
- SRF group: Audio, video, and whiteboard share one reservation flow
- Both semantics apply independently

## Security Considerations

RFC 3524 emphasizes security:

**Threat**: Malicious SDP with SRF groups could:
- Cause excessive resource consumption
- Degrade quality of service for legitimate streams
- Create denial of service conditions

**Mitigation** (as recommended by RFC 3524):
- Use S/MIME to provide integrity protection for SDP
- Validate SRF groups against policy before reserving resources
- Implement resource limits and admission control

The implementation focuses on correct parsing and generation; security policy enforcement is application-level.

## Testing

The implementation includes 10 comprehensive tests covering:

### Parsing Tests
- `parse_group_srf_semantics` - Basic SRF group parsing
- `parse_group_srf_case_insensitive` - Case handling (SRF, srf, Srf)
- `parse_sdp_with_srf_group` - Complete SDP with SRF
- `srf_group_single_media` - Single media in SRF group
- `multiple_srf_groups` - Multiple independent SRF groups

### Generation Tests
- `generate_sdp_with_srf_group` - SDP generation with SRF

### Display Tests
- `group_semantics_srf_display` - String representation

### Round-Trip Tests
- `round_trip_srf_group` - Parse → Generate → Parse

### Interaction Tests
- `mixed_group_semantics_with_srf` - SRF with LS/FID

### RFC Compliance Tests
- `rfc_3524_example` - Example from RFC 3524 Section 3

Run tests with:
```bash
cargo test sdp::tests::parse_group_srf
cargo test sdp::tests::srf
cargo test sdp::tests::rfc_3524
```

## Implementation Status Summary

| Feature | Status | Notes |
|---------|--------|-------|
| **SRF group semantics** | ✅ Complete | Added to GroupSemantics enum |
| **Parsing** | ✅ Complete | Case-insensitive, via RFC 3388 framework |
| **Generation** | ✅ Complete | Correct formatting |
| **Display** | ✅ Complete | as_str() and Display trait |
| **Round-trip fidelity** | ✅ Complete | Parse→Generate→Parse |
| **Single media groups** | ✅ Complete | Supports SRF with one mid |
| **Multiple SRF groups** | ✅ Complete | Multiple independent flows |
| **Mixed semantics** | ✅ Complete | SRF + LS/FID combinations |
| **Test coverage** | ✅ Complete | 10 comprehensive tests |
| **Documentation** | ✅ Complete | This document |

## Code Locations

| Component | File | Lines |
|-----------|------|-------|
| GroupSemantics enum | `crates/sip-core/src/sdp.rs` | 283-316 |
| SRF variant | `crates/sip-core/src/sdp.rs` | 293 |
| Parsing logic | `crates/sip-core/src/sdp.rs` | 308-315 |
| Display logic | `crates/sip-core/src/sdp.rs` | 298-316 |
| Tests | `crates/sip-core/src/sdp.rs` | 3367-3606 |

## References

- **RFC 3524**: Mapping of Media Streams to Resource Reservation Flows
  - https://datatracker.ietf.org/doc/html/rfc3524
  - Section 2: SDP syntax and semantics
  - Section 3: Examples
  - Section 4: Security considerations

- **RFC 3388**: Grouping of Media Lines in SDP
  - https://datatracker.ietf.org/doc/html/rfc3388
  - Foundation for SRF extension

- **RFC 2205**: RSVP (Resource ReSerVation Protocol)
  - https://datatracker.ietf.org/doc/html/rfc2205
  - Protocol that benefits from SRF declarations

## Relationship to Other RFCs

```
RFC 3388 (Grouping Framework)
    ├── Defines: a=group:<semantics> <mids>
    ├── Defines: LS and FID semantics
    └── Provides: MediaGroup structure

RFC 3524 (This Implementation)
    ├── Extends: RFC 3388
    ├── Adds: SRF semantics
    └── Purpose: QoS resource mapping

RFC 3312 (Preconditions)
    └── Complementary: Defines WHEN resources are ready
                        (SRF defines HOW to group them)
```

## Future Enhancements

While the current implementation is fully compliant with RFC 3524, potential future work includes:

1. **Helper Methods**: Utilities for finding all media in an SRF group
2. **Validation**: Check that all mids in SRF group reference existing media
3. **RSVP Integration**: Example code showing RSVP session setup from SRF groups
4. **Policy Engine**: Framework for enforcing SRF group resource policies

## Example Integration

Here's how an application might use SRF groups for RSVP setup:

```rust
use sip_core::{SdpSession, GroupSemantics};

fn setup_rsvp_sessions(sdp: &SdpSession) {
    for group in &sdp.groups {
        if group.semantics == GroupSemantics::SRF {
            // Collect all media streams in this group
            let media_in_group: Vec<_> = sdp.media.iter()
                .filter(|m| m.mid.as_ref().map_or(false, |mid| group.mids.contains(mid)))
                .collect();

            // Create one RSVP session for all these streams
            println!("Creating RSVP session for {} streams", media_in_group.len());
            for media in media_in_group {
                println!("  - {} on port {}", media.media, media.port);
                // Setup RSVP filters for this media...
            }
        }
    }

    // Handle media not in any SRF group (each gets separate session)
    for media in &sdp.media {
        let in_srf_group = sdp.groups.iter().any(|g| {
            g.semantics == GroupSemantics::SRF &&
            media.mid.as_ref().map_or(false, |mid| g.mids.contains(mid))
        });

        if !in_srf_group {
            println!("Creating separate RSVP session for {}", media.media);
            // Setup individual RSVP session...
        }
    }
}
```

## Changelog

- **2024-01-21**: Initial implementation of RFC 3524
  - Added SRF variant to GroupSemantics enum
  - Updated parsing and display logic
  - Added 10 comprehensive tests
  - Integrated with existing RFC 3388 framework
  - All 417 tests passing
