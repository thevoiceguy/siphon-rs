# RFC 3407: Session Description Protocol (SDP) Simple Capability Declaration - Implementation Guide

## Overview

This document describes the implementation of **RFC 3407: Session Description Protocol (SDP) Simple Capability Declaration** in the siphon-rs project. RFC 3407 extends SDP with capability declaration attributes that allow endpoints to declare media capabilities beyond what's currently committed to in the session description.

**Status**: ✅ **Fully Implemented**

## What Are Capability Declarations?

Capability declarations address the fundamental distinction between what an endpoint **can support** (capabilities) and what it's **currently using** (session parameters). This enables more sophisticated negotiation scenarios where endpoints can signal alternative capabilities without committing to them immediately.

### The Problem

Without capability declarations:
1. Alice wants to support both PCMU and G.729 codecs
2. Alice can only list what she's currently offering in the m= line
3. If Bob doesn't support the offered codec, negotiation fails
4. No way to signal "I can also support these alternatives"

### The Solution

With capability declarations:
1. Alice sends SDP with current session (m=audio ... RTP/AVP 0)
2. Alice also declares capabilities (a=cdsc:1 audio RTP/AVP 0 18)
3. Bob sees both what's offered AND what's potentially available
4. Future renegotiation can use these declared capabilities

## Key Concepts

### Four Attribute Types

RFC 3407 defines four SDP attributes for capability declaration:

1. **Sequence Number (a=sqn:)**: Version number for capability sets
   ```
   a=sqn:0
   ```
   - Range: 0-255 (modulo 256)
   - Increments when capabilities change
   - REQUIRED when capability descriptions are present

2. **Capability Description (a=cdsc:)**: Declares potential media formats
   ```
   a=cdsc:1 audio RTP/AVP 0 18
   ```
   - Similar to m= line but declares capabilities, not commitments
   - Format: `<cap-num> <media> <transport> <fmt list>`
   - `cap-num` identifies the capability (1-255)

3. **Capability Parameter (a=cpar:)**: General parameters for capabilities
   ```
   a=cpar:a=fmtp:96 annexb=no
   ```
   - Arbitrary SDP attributes associated with capabilities
   - Can specify codec parameters, bandwidth, etc.

4. **Capability Parameter Min/Max (a=cparmin:/a=cparmax:)**: Constraints
   ```
   a=cparmin:b=AS:32
   a=cparmax:b=AS:128
   ```
   - Minimum and maximum values for capability parameters
   - Typically used for bandwidth constraints

### Scope

Capability declarations can appear at two levels:

| Level | Scope |
|-------|-------|
| **Session-level** | Applies to all media streams in the session |
| **Media-level** | Applies only to the specific media description |

### Capability Sets

A **capability set** is the complete collection of:
- One sequence number (a=sqn:)
- Zero or more capability descriptions (a=cdsc:)
- Zero or more capability parameters (a=cpar:/cparmin:/cparmax:)

Important constraints:
- Only ONE capability set per session description
- Sequence number REQUIRED if any capability descriptions present
- Sequence number MUST precede capability descriptions

## Implementation Architecture

### Core Types (in `sdp.rs`)

```rust
/// Capability description (a=cdsc:)
pub struct CapabilityDescription {
    pub cap_num: u8,              // Capability number (1-255)
    pub media: String,            // Media type (audio, video, etc.)
    pub transport: String,        // Transport protocol
    pub formats: Vec<String>,     // Format list (payload types)
}

/// Capability parameter type
pub enum CapabilityParameterType {
    General,   // a=cpar:
    Min,       // a=cparmin:
    Max,       // a=cparmax:
}

/// Capability parameter (a=cpar:/cparmin:/cparmax:)
pub struct CapabilityParameter {
    pub param_type: CapabilityParameterType,
    pub value: String,            // Parameter content
}

/// Capability set (collection with sequence number)
pub struct SdpCapabilitySet {
    pub sequence_number: u8,                    // a=sqn: (0-255)
    pub descriptions: Vec<CapabilityDescription>,  // a=cdsc:
    pub parameters: Vec<CapabilityParameter>,   // a=cpar:/cparmin:/cparmax:
}
```

### SDP Integration

Capability sets are integrated into existing SDP structures:

```rust
pub struct SdpSession {
    // ... existing fields ...
    pub capability_set: Option<SdpCapabilitySet>,  // Session-level capabilities
    pub media: Vec<MediaDescription>,
}

pub struct MediaDescription {
    // ... existing fields ...
    pub capability_set: Option<SdpCapabilitySet>,  // Media-level capabilities
}
```

## Parsing and Generation

### Parsing Example

```rust
use sip_core::SdpSession;

let sdp = "\
v=0\r\n\
o=alice 123 456 IN IP4 192.0.2.1\r\n\
s=Session\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
a=sqn:0\r\n\
a=cdsc:1 audio RTP/AVP 0 18\r\n\
a=cdsc:3 audio RTP/AVP 96\r\n\
a=cpar:a=fmtp:96 annexb=no\r\n\
m=audio 49170 RTP/AVP 0\r\n\
";

let session = SdpSession::parse(sdp)?;

// Access session-level capabilities
if let Some(cap_set) = &session.capability_set {
    println!("Sequence number: {}", cap_set.sequence_number);

    for desc in &cap_set.descriptions {
        println!("Capability {}: {} {}",
            desc.cap_num, desc.media, desc.transport);
    }

    for param in &cap_set.parameters {
        println!("Parameter: {}", param.value);
    }
}
```

### Generation Example

```rust
use sip_core::{SdpSession, SdpCapabilitySet, CapabilityDescription,
               CapabilityParameter, CapabilityParameterType, Origin, Connection};

// Create basic session
let mut session = SdpSession::new(
    Origin {
        username: "alice".to_string(),
        sess_id: "123".to_string(),
        sess_version: "456".to_string(),
        nettype: "IN".to_string(),
        addrtype: "IP4".to_string(),
        unicast_address: "192.0.2.1".to_string(),
    },
    "Capability Demo".to_string(),
);

session.connection = Some(Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "192.0.2.1".to_string(),
});

// Create capability set
let mut cap_set = SdpCapabilitySet::new(0);

// Add capability descriptions
cap_set.descriptions.push(CapabilityDescription {
    cap_num: 1,
    media: "audio".to_string(),
    transport: "RTP/AVP".to_string(),
    formats: vec!["0".to_string(), "18".to_string()],
});

// Add capability parameters
cap_set.parameters.push(CapabilityParameter::parse(
    CapabilityParameterType::General,
    "a=fmtp:18 annexb=yes",
));

cap_set.parameters.push(CapabilityParameter::parse(
    CapabilityParameterType::Min,
    "b=AS:32",
));

session.capability_set = Some(cap_set);

// Generate SDP
let sdp_string = session.to_string();
```

## Common Use Cases

### Use Case 1: Codec Alternatives

Declare multiple codec capabilities while offering one:

```
v=0
o=alice 123 456 IN IP4 192.0.2.1
s=Codec Options
c=IN IP4 192.0.2.1
t=0 0
m=audio 49170 RTP/AVP 0
a=sqn:0
a=cdsc:1 audio RTP/AVP 0 18
a=cdsc:3 audio RTP/AVP 8
```

**Interpretation**:
- Currently offering: PCMU (payload type 0)
- Can also support: PCMU + G.729 (capability 1) or PCMA (capability 3)

### Use Case 2: Bandwidth Constraints

Declare bandwidth requirements for different capabilities:

```
v=0
o=bob 789 321 IN IP4 192.0.2.2
s=Bandwidth Options
c=IN IP4 192.0.2.2
t=0 0
m=video 49172 RTP/AVP 31
a=sqn:1
a=cdsc:1 video RTP/AVP 31 34
a=cparmin:b=AS:128
a=cparmax:b=AS:512
```

**Interpretation**:
- Currently offering: H.261
- Can support H.261 or H.263 (capability 1)
- Requires minimum 128 kbps, maximum 512 kbps

### Use Case 3: Media-Level Capabilities

Declare different capabilities for different media streams:

```
v=0
o=carol 111 222 IN IP4 192.0.2.3
s=Multi-Media
c=IN IP4 192.0.2.3
t=0 0
m=audio 49170 RTP/AVP 0
a=sqn:0
a=cdsc:1 audio RTP/AVP 0 8 18
m=video 49172 RTP/AVP 31
a=sqn:5
a=cdsc:1 video RTP/AVP 31 34
```

**Interpretation**:
- Audio capabilities: PCMU, PCMA, G.729 (sequence 0)
- Video capabilities: H.261, H.263 (sequence 5)

## Validation Rules

The implementation enforces these RFC 3407 validation rules:

1. **Sequence Number Required**: If any a=cdsc: or a=cpar: attributes are present, a=sqn: MUST be present
   ```rust
   // Returns error if capabilities without sequence number
   SdpSession::parse(sdp)?;  // Error: "Capability descriptions require a=sqn"
   ```

2. **Sequence Number Range**: Must be 0-255 (u8)
   ```rust
   let cap_set = SdpCapabilitySet::new(255);  // Valid
   ```

3. **Capability Number Range**: Must be 1-255 (not 0)
   ```rust
   CapabilityDescription { cap_num: 1, ... }  // Valid
   ```

4. **Single Capability Set**: Only one capability set per session description (validated during parsing)

## Offer/Answer Model Integration

While RFC 3407 doesn't define specific offer/answer semantics for capabilities, the implementation preserves capability sets during negotiation:

```rust
// In sdp_offer_answer.rs
impl OfferAnswerEngine {
    pub fn generate_answer(&self, offer: &SdpSession, ...) -> Result<SdpSession, ...> {
        // ...
        Ok(MediaDescription {
            // ... other fields ...
            capability_set: offer_media.capability_set.clone(),  // Preserved
        })
    }
}
```

This ensures:
- Capability sets in offers are maintained in answers
- Future renegotiation can reference declared capabilities
- No capability information is lost during negotiation

## Testing

The implementation includes 18 comprehensive tests covering:

### Parsing Tests
- `parse_capability_description` - Basic capability description parsing
- `parse_capability_description_video` - Video capability parsing
- `parse_capability_parameter_general` - General parameter parsing
- `parse_capability_parameter_min` - Minimum constraint parsing
- `parse_capability_parameter_max` - Maximum constraint parsing
- `parse_sdp_with_session_level_capabilities` - Complete session-level example
- `parse_sdp_with_media_level_capabilities` - Media-level capabilities
- `capability_set_with_multiple_descriptions` - Multiple capability descriptions

### Generation Tests
- `capability_description_display` - Display formatting
- `generate_sdp_with_session_level_capabilities` - Session-level generation
- `generate_sdp_with_media_level_capabilities` - Media-level generation

### Round-Trip Tests
- `round_trip_capabilities` - Parse and regenerate

### Validation Tests
- `capability_descriptions_without_sqn_error` - Missing sequence number
- `capability_parameters_without_sqn_error` - Parameters without sqn
- `sequence_number_modulo_256` - Range validation
- `sdp_without_capabilities` - No capabilities present

### RFC Compliance Tests
- `rfc_3407_example` - Example from RFC 3407 Section 4.1

### Helper Tests
- `capability_parameter_type_as_str` - Type conversion

Run tests with:
```bash
cargo test sdp::tests::parse_capability
cargo test sdp::tests::generate_sdp_with_.*_capabilities
cargo test sdp::tests::rfc_3407
```

## Implementation Status Summary

| Feature | Status | Notes |
|---------|--------|-------|
| **Sequence number (a=sqn:)** | ✅ Complete | Full parsing and generation |
| **Capability description (a=cdsc:)** | ✅ Complete | Supports all media types |
| **Capability parameters (a=cpar:)** | ✅ Complete | General, min, max variants |
| **Session-level capabilities** | ✅ Complete | Applies to all media |
| **Media-level capabilities** | ✅ Complete | Per-media capabilities |
| **Validation** | ✅ Complete | Enforces sqn requirement |
| **Parsing** | ✅ Complete | Full RFC 3407 support |
| **Generation** | ✅ Complete | Correct attribute ordering |
| **Round-trip fidelity** | ✅ Complete | Parse→Generate→Parse |
| **Offer/Answer preservation** | ✅ Complete | Capabilities maintained |
| **Test coverage** | ✅ Complete | 18 comprehensive tests |
| **Documentation** | ✅ Complete | This document |

## Code Locations

| Component | File | Lines |
|-----------|------|-------|
| Core types | `crates/sip-core/src/sdp.rs` | 369-498 |
| Parsing logic | `crates/sip-core/src/sdp.rs` | 1029-1128 |
| Display/Generation | `crates/sip-core/src/sdp.rs` | 1386-1395, 1497-1506 |
| Offer/Answer | `crates/sip-core/src/sdp_offer_answer.rs` | (capability_set preserved) |
| Public API exports | `crates/sip-core/src/lib.rs` | 90-96 |
| Tests | `crates/sip-core/src/sdp.rs` | 2987-3331 |

## References

- **RFC 3407**: Session Description Protocol (SDP) Simple Capability Declaration
  - https://datatracker.ietf.org/doc/html/rfc3407
  - Section 3: Capability attribute definitions
  - Section 4: Examples
  - Section 5: IANA considerations

## Future Enhancements

While the current implementation is fully compliant with RFC 3407, potential future work includes:

1. **RFC 5939 Integration**: SDP Capability Negotiation (builds on RFC 3407)
2. **Capability Matching**: Algorithms for selecting optimal capabilities
3. **Capability Prioritization**: Ordering preferences among alternatives
4. **Helper Methods**: Convenience functions for common capability patterns

## Changelog

- **2024-01-21**: Initial implementation of RFC 3407
  - Added CapabilityDescription, CapabilityParameter, SdpCapabilitySet types
  - Implemented parsing and generation
  - Added 18 comprehensive tests
  - Integrated with offer/answer model
  - All 407 tests passing
