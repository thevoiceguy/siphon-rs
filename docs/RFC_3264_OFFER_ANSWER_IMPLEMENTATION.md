# RFC 3264: SDP Offer/Answer Model - Implementation

## Overview

RFC 3264 defines the offer/answer model used with SDP to negotiate multimedia sessions between two parties. This document describes the comprehensive RFC 3264-compliant implementation in siphon-rs.

**Status**: ✅ **FULLY COMPLIANT** - Complete offer/answer negotiation

**Key Standards**:
- **RFC 3264**: An Offer/Answer Model with the Session Description Protocol (SDP)
- **RFC 4566**: SDP: Session Description Protocol
- **RFC 3261**: SIP (uses offer/answer in INVITE/200 OK)

## What is the Offer/Answer Model?

The offer/answer model enables two agents to negotiate multimedia session parameters:

1. **Offerer** generates an SDP with proposed media streams and codecs
2. **Answerer** responds with an SDP indicating acceptance, rejection, or modification
3. Both parties then communicate using the negotiated parameters

### Example Flow

```text
Alice (Offerer)                Bob (Answerer)
     |                              |
     | INVITE with SDP Offer        |
     |----------------------------->|
     |   Proposes: PCMU, PCMA       |
     |                              |
     |        200 OK with SDP Answer|
     |<-----------------------------|
     |   Accepts: PCMU              |
     |                              |
     | Both use PCMU codec          |
     |<===========================> |
```

## RFC 3264 Compliance

### Core Requirements

✅ **Media Stream Matching** (§5.1):
- Answer MUST have same number of media streams as offer
- Streams matched by position (i-th in offer = i-th in answer)

✅ **Codec Negotiation** (§6):
- Select at least one common codec
- Maintain format preference order from offer
- Use payload types from offer, not answer

✅ **Direction Negotiation** (§6.1):
- sendrecv ↔ sendrecv, sendonly, recvonly, inactive
- sendonly ↔ recvonly, inactive
- recvonly ↔ sendonly, inactive
- inactive ↔ inactive

✅ **Media Rejection** (§6):
- Port 0 indicates rejected stream
- Continue with remaining streams

✅ **Hold/Resume** (§8):
- Hold: sendrecv → sendonly
- Resume: sendonly → sendrecv

## Implementation Architecture

### Core Types

```rust
/// Offer/answer negotiation engine
pub struct OfferAnswerEngine {}

/// Configuration for generating answers
pub struct AnswerOptions {
    // Fields are private; configure via builder methods.
}

impl AnswerOptions {
    pub fn new() -> Self;
    pub fn with_local_address(self, address: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn with_base_port(self, port: u16) -> Self;
    pub fn with_audio_codecs(self, codecs: Vec<CodecInfo>) -> Result<Self, NegotiationError>;
    pub fn with_video_codecs(self, codecs: Vec<CodecInfo>) -> Result<Self, NegotiationError>;
    pub fn with_direction_override(self, direction: Direction) -> Self;
    pub fn with_reject_media(self, reject: Vec<usize>) -> Result<Self, NegotiationError>;
    pub fn with_username(self, username: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn with_session_id(self, session_id: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn with_qos_local_status(self, status: PreconditionDirection) -> Self;
    pub fn with_qos_remote_status(self, status: PreconditionDirection) -> Self;
    pub fn with_upgrade_preconditions(self, upgrade: bool) -> Self;
}

/// Codec information for negotiation
pub struct CodecInfo {
    // Fields are private; configure via builder methods.
}

impl CodecInfo {
    pub fn new(
        name: impl AsRef<str>,
        clock_rate: u32,
        channels: Option<u16>,
    ) -> Result<Self, NegotiationError>;
    pub fn with_fmtp(self, fmtp: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn matches(&self, rtpmap: &RtpMap) -> bool;
}

/// Negotiation errors
pub enum NegotiationError {
    NoCommonCodecs(usize),      // No codecs match for stream
    InvalidSdp(String),         // Invalid SDP structure
    MediaMismatch(String),      // Stream count mismatch
    DirectionConflict(String),  // Invalid direction combination
    ValidationError(String),    // Input validation failure
    TooManyMediaStreams { max: usize, actual: usize },
}
```

## Usage Examples

### Example 1: Basic Offer/Answer Exchange

```rust
use sip_core::sdp::SdpSession;
use sip_core::sdp_offer_answer::{OfferAnswerEngine, AnswerOptions};

// Alice sends INVITE with SDP offer
let offer_sdp = "v=0\r\n\
                 o=alice 2890844526 2890842807 IN IP4 192.0.2.1\r\n\
                 s=Call\r\n\
                 c=IN IP4 192.0.2.1\r\n\
                 t=0 0\r\n\
                 m=audio 49170 RTP/AVP 0 8\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n\
                 a=sendrecv\r\n";

let offer = SdpSession::parse(offer_sdp)?;

// Bob generates answer
let engine = OfferAnswerEngine::new();

let answer_options = AnswerOptions::default()
    .with_local_address("203.0.113.5")
    ?
    .with_base_port(60000)
    .with_username("bob")
    ?
    .with_session_id("9876543210")
    ?;

let answer = engine.generate_answer(&offer, answer_options)?;

// Answer contains:
// - Same media type (audio)
// - Common codec (PCMU or PCMA)
// - Bob's IP and port
// - Negotiated direction

println!("{}", answer);
// v=0
// o=bob 9876543210 0 IN IP4 203.0.113.5
// s=Call
// c=IN IP4 203.0.113.5
// t=0 0
// m=audio 60000 RTP/AVP 0 8
// a=rtpmap:0 PCMU/8000
// a=rtpmap:8 PCMA/8000
// a=sendrecv
```

### Example 2: Codec Negotiation

```rust
use sip_core::sdp::SdpSession;
use sip_core::sdp_offer_answer::{AnswerOptions, CodecInfo, OfferAnswerEngine};

// Offer with 3 codecs
let offer_sdp = "v=0\r\n\
                 o=alice 123 456 IN IP4 192.0.2.1\r\n\
                 s=Call\r\n\
                 c=IN IP4 192.0.2.1\r\n\
                 t=0 0\r\n\
                 m=audio 49170 RTP/AVP 0 8 18\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n\
                 a=rtpmap:18 G729/8000\r\n";

let offer = SdpSession::parse(offer_sdp)?;

// Bob only supports PCMU and PCMA (not G729)
let options = AnswerOptions::default()
    .with_audio_codecs(vec![
        CodecInfo::new("PCMU", 8000, Some(1))?,
        CodecInfo::new("PCMA", 8000, Some(1))?,
        // G729 not included - won't be selected
    ])
    ?;

let engine = OfferAnswerEngine::new();
let answer = engine.generate_answer(&offer, options)?;

// Answer only includes common codecs (PCMU and PCMA)
assert_eq!(answer.media()[0].fmt().len(), 2);
assert!(answer.media()[0].fmt().contains(&"0".to_string())); // PCMU
assert!(answer.media()[0].fmt().contains(&"8".to_string())); // PCMA
```

### Example 3: Rejecting Media Streams

```rust
use sip_core::sdp::SdpSession;
use sip_core::sdp_offer_answer::{AnswerOptions, OfferAnswerEngine};

// Offer with audio and video
let offer_sdp = "v=0\r\n\
                 o=alice 123 456 IN IP4 192.0.2.1\r\n\
                 s=Conference\r\n\
                 c=IN IP4 192.0.2.1\r\n\
                 t=0 0\r\n\
                 m=audio 49170 RTP/AVP 0\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 m=video 51372 RTP/AVP 99\r\n\
                 a=rtpmap:99 H264/90000\r\n";

let offer = SdpSession::parse(offer_sdp)?;

// Bob wants audio only (reject video)
let options = AnswerOptions::default()
    .with_reject_media(vec![1])
    ?; // Reject second media (video)

let engine = OfferAnswerEngine::new();
let answer = engine.generate_answer(&offer, options)?;

// Audio accepted (port != 0)
assert_ne!(answer.media()[0].port(), 0);

// Video rejected (port == 0)
assert_eq!(answer.media()[1].port(), 0);

println!("{}", answer);
// v=0
// o=- 0 0 IN IP4 0.0.0.0
// s=Conference
// c=IN IP4 0.0.0.0
// t=0 0
// m=audio 50000 RTP/AVP 0
// a=rtpmap:0 PCMU/8000
// a=sendrecv
// m=video 0 RTP/AVP 99  ← Port 0 = rejected
```

### Example 4: Direction Negotiation

```rust
use sip_core::sdp::{SdpSession, Direction};
use sip_core::sdp_offer_answer::{OfferAnswerEngine, AnswerOptions};

// ===== Scenario 1: Music on Hold (sendonly) =====

let hold_offer = "v=0\r\n\
                  o=alice 123 456 IN IP4 192.0.2.1\r\n\
                  s=Call\r\n\
                  c=IN IP4 192.0.2.1\r\n\
                  t=0 0\r\n\
                  m=audio 49170 RTP/AVP 0\r\n\
                  a=sendonly\r\n";  // Alice sends music on hold

let offer = SdpSession::parse(hold_offer)?;
let engine = OfferAnswerEngine::new();
let answer = engine.generate_answer(&offer, AnswerOptions::default())?;

// Bob's answer is recvonly (receives music on hold)
let answer_dir = answer.find_direction(Some(0))?;
assert_eq!(answer_dir, Direction::RecvOnly);


// ===== Scenario 2: Broadcast (recvonly) =====

let broadcast_offer = "v=0\r\n\
                       o=server 123 456 IN IP4 192.0.2.1\r\n\
                       s=Live Stream\r\n\
                       c=IN IP4 192.0.2.1\r\n\
                       t=0 0\r\n\
                       m=audio 49170 RTP/AVP 0\r\n\
                       a=recvonly\r\n";  // Server wants to receive (unused)

let offer = SdpSession::parse(broadcast_offer)?;
let answer = engine.generate_answer(&offer, AnswerOptions::default())?;

// Answer is sendonly (client sends to server)
let answer_dir = answer.find_direction(Some(0))?;
assert_eq!(answer_dir, Direction::SendOnly);
```

### Example 5: Hold and Resume

```rust
use sip_core::sdp::{Direction, SdpSession};
use sip_core::sdp_offer_answer::OfferAnswerEngine;

// ===== Initial Active Call =====

let active_sdp = "v=0\r\n\
                  o=alice 123 0 IN IP4 192.0.2.1\r\n\
                  s=Call\r\n\
                  c=IN IP4 192.0.2.1\r\n\
                  t=0 0\r\n\
                  m=audio 49170 RTP/AVP 0\r\n\
                  a=sendrecv\r\n";

let active_session = SdpSession::parse(active_sdp)?;
let engine = OfferAnswerEngine::new();

// ===== Alice Puts Bob on Hold =====

let hold_offer = engine.create_hold_offer(&active_session);

// Direction changed to sendonly (send music on hold)
assert_eq!(hold_offer.find_direction(Some(0))?, Direction::SendOnly);

// Session version incremented
assert_eq!(hold_offer.origin().sess_version(), "1");

// Send re-INVITE with hold offer
println!("Hold offer:\n{}", hold_offer);


// ===== Alice Resumes Call =====

let resume_offer = engine.create_resume_offer(&hold_offer);

// Direction restored to sendrecv
assert_eq!(resume_offer.find_direction(Some(0))?, Direction::SendRecv);

// Session version incremented again
assert_eq!(resume_offer.origin().sess_version(), "2");

println!("Resume offer:\n{}", resume_offer);
```

### Example 6: Static Payload Types

```rust
use sip_core::sdp::SdpSession;
use sip_core::sdp_offer_answer::{AnswerOptions, OfferAnswerEngine};

// Offer without explicit rtpmap (uses static payload types)
let offer_sdp = "v=0\r\n\
                 o=alice 123 456 IN IP4 192.0.2.1\r\n\
                 s=Call\r\n\
                 c=IN IP4 192.0.2.1\r\n\
                 t=0 0\r\n\
                 m=audio 49170 RTP/AVP 0 8\r\n";
                 // No rtpmap lines - uses well-known mappings

let offer = SdpSession::parse(offer_sdp)?;
let engine = OfferAnswerEngine::new();
let answer = engine.generate_answer(&offer, AnswerOptions::default())?;

// Engine recognizes static payload types:
// 0 = PCMU/8000
// 8 = PCMA/8000

assert!(answer.media()[0].fmt().contains(&"0".to_string()));
assert!(answer.media()[0].fmt().contains(&"8".to_string()));

// Answer includes explicit rtpmap
let has_pcmu_rtpmap = answer.media()[0]
    .attributes()
    .iter()
    .any(|a| a.value.as_ref().map_or(false, |v| v.contains("PCMU/8000")));
assert!(has_pcmu_rtpmap);
```

### Example 7: Format Parameters (fmtp)

```rust
use sip_core::sdp::SdpSession;
use sip_core::sdp_offer_answer::{AnswerOptions, OfferAnswerEngine};

// Offer with fmtp for H.264
let offer_sdp = "v=0\r\n\
                 o=alice 123 456 IN IP4 192.0.2.1\r\n\
                 s=Video Call\r\n\
                 c=IN IP4 192.0.2.1\r\n\
                 t=0 0\r\n\
                 m=video 51372 RTP/AVP 99\r\n\
                 a=rtpmap:99 H264/90000\r\n\
                 a=fmtp:99 profile-level-id=42e01f;packetization-mode=1\r\n";

let offer = SdpSession::parse(offer_sdp)?;
let engine = OfferAnswerEngine::new();
let answer = engine.generate_answer(&offer, AnswerOptions::default())?;

// fmtp is copied to answer
let has_fmtp = answer.media()[0]
    .attributes()
    .iter()
    .any(|a| {
        a.name == "fmtp" &&
        a.value.as_ref().map_or(false, |v| v.contains("profile-level-id"))
    });

assert!(has_fmtp);
```

### Example 8: SIP Integration

```rust
use sip_core::{Headers, Method, Request, RequestLine, Response, SipUri, StatusLine};
use sip_core::sdp::SdpSession;
use sip_core::sdp_offer_answer::{OfferAnswerEngine, AnswerOptions};
use bytes::Bytes;
use smol_str::SmolStr;

// ===== Alice sends INVITE with SDP offer =====

let offer_sdp = "v=0\r\n\
                 o=alice 123 456 IN IP4 192.0.2.1\r\n\
                 s=Call\r\n\
                 c=IN IP4 192.0.2.1\r\n\
                 t=0 0\r\n\
                 m=audio 49170 RTP/AVP 0 8\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:8 PCMA/8000\r\n";

let mut invite = Request::new(
    RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com")?),
    Headers::new(),
    Bytes::from(offer_sdp),
)
?;

// Add Content-Type
invite
    .headers_mut()
    .push(
        SmolStr::new("Content-Type"),
        SmolStr::new("application/sdp"),
    )
    ?;


// ===== Bob receives INVITE and generates answer =====

// Parse offer from INVITE body
let offer = SdpSession::parse(std::str::from_utf8(invite.body())?)?;

// Generate answer
let engine = OfferAnswerEngine::new();
let answer_options = AnswerOptions::default()
    .with_local_address("203.0.113.5")
    ?
    .with_username("bob")
    ?;

let answer = engine.generate_answer(&offer, answer_options)?;
let answer_sdp = answer.to_string();


// ===== Bob sends 200 OK with SDP answer =====

let mut ok_response = Response::new(
    StatusLine::new(200, "OK")?,
    invite.headers().clone(),
    Bytes::from(answer_sdp),
)
?;

ok_response
    .headers_mut()
    .push(
        SmolStr::new("Content-Type"),
        SmolStr::new("application/sdp"),
    )
    ?;

// Now both parties can communicate using negotiated parameters
```

## Direction Negotiation Rules (RFC 3264 Table 1)

| Offer Direction | Valid Answer Directions | Selected Result |
|-----------------|------------------------|-----------------|
| sendrecv | sendrecv, sendonly, recvonly, inactive | Bidirectional or restricted |
| sendonly | recvonly, inactive | Offerer sends, answerer receives |
| recvonly | sendonly, inactive | Offerer receives, answerer sends |
| inactive | inactive | No media in either direction |

### Implementation

```rust
impl OfferAnswerEngine {
    fn negotiate_direction(&self, offer_direction: Direction) -> Direction {
        match offer_direction {
            Direction::SendRecv => Direction::SendRecv,  // Accept bidirectional
            Direction::SendOnly => Direction::RecvOnly,  // We receive, they send
            Direction::RecvOnly => Direction::SendOnly,  // We send, they receive
            Direction::Inactive => Direction::Inactive,  // No media
        }
    }
}
```

## Static RTP Payload Types

The engine recognizes well-known static payload types per RFC 3551:

| Payload | Codec | Clock Rate | Description |
|---------|-------|------------|-------------|
| 0 | PCMU | 8000 | G.711 μ-law |
| 8 | PCMA | 8000 | G.711 A-law |
| 3 | GSM | 8000 | GSM Full Rate |
| 4 | G723 | 8000 | G.723.1 |
| 9 | G722 | 8000 | G.722 (16kHz) |
| 18 | G729 | 8000 | G.729 |

Offers can omit rtpmap for these payload types; the engine automatically infers the codec information.

## Hold and Resume Scenarios

### Hold (Active → Hold)

```text
Initial State: sendrecv (bidirectional)
Hold Action:   Change to sendonly (send music on hold)

Before:
m=audio 49170 RTP/AVP 0
a=sendrecv

After:
m=audio 49170 RTP/AVP 0
a=sendonly  ← Changed
```

### Resume (Hold → Active)

```text
Hold State:   sendonly (music on hold)
Resume Action: Change to sendrecv (restore call)

Before:
m=audio 49170 RTP/AVP 0
a=sendonly

After:
m=audio 49170 RTP/AVP 0
a=sendrecv  ← Restored
```

### Implementation

```rust
// Hold
let hold_offer = engine.create_hold_offer(&active_session);

// Resume
let resume_offer = engine.create_resume_offer(&hold_offer);
```

## Testing

Comprehensive test coverage with 16 tests:

```bash
$ cargo test --package sip-core sdp_offer_answer::
running 16 tests
test sdp_offer_answer::tests::generate_basic_answer ... ok
test sdp_offer_answer::tests::codec_negotiation_selects_common ... ok
test sdp_offer_answer::tests::reject_media_with_port_zero ... ok
test sdp_offer_answer::tests::direction_negotiation_sendonly ... ok
test sdp_offer_answer::tests::hold_offer_changes_to_sendonly ... ok
test sdp_offer_answer::tests::resume_offer_restores_sendrecv ... ok
test sdp_offer_answer::tests::static_payload_type_mapping ... ok
test sdp_offer_answer::tests::fmtp_copied_to_answer ... ok
test sdp_offer_answer::tests::reject_oversized_codec_name ... ok
test sdp_offer_answer::tests::reject_empty_codec_name ... ok
test sdp_offer_answer::tests::reject_codec_name_with_control_chars ... ok
test sdp_offer_answer::tests::reject_too_many_audio_codecs ... ok
test sdp_offer_answer::tests::reject_too_many_media_streams ... ok
test sdp_offer_answer::tests::fields_are_private ... ok
test sdp_offer_answer::tests::answer_without_preconditions_in_offer ... ok
test sdp_offer_answer::tests::answer_with_segmented_preconditions ... ok

test result: ok. 16 passed; 0 failed
```

Tests cover:
- ✅ Basic answer generation
- ✅ Codec negotiation (common codec selection)
- ✅ Media rejection (port 0)
- ✅ Direction negotiation (sendonly, recvonly, etc.)
- ✅ Hold offer generation
- ✅ Resume offer generation
- ✅ Static payload type recognition
- ✅ fmtp parameter copying
- ✅ Input validation (codec limits, media stream caps)
- ✅ Preconditions handling (RFC 3312)

## API Reference

### OfferAnswerEngine

```rust
pub struct OfferAnswerEngine {}

impl OfferAnswerEngine {
    /// Creates a new offer/answer engine
    pub fn new() -> Self;

    /// Generates an answer for the given offer
    pub fn generate_answer(
        &self,
        offer: &SdpSession,
        options: AnswerOptions
    ) -> Result<SdpSession, NegotiationError>;

    /// Creates a hold offer from an active session
    pub fn create_hold_offer(&self, session: &SdpSession) -> SdpSession;

    /// Creates a resume offer from a held session
    pub fn create_resume_offer(&self, session: &SdpSession) -> SdpSession;
}
```

### AnswerOptions

```rust
pub struct AnswerOptions {
    // Fields are private; configure via builder methods.
}

impl AnswerOptions {
    pub fn new() -> Self;
    pub fn with_local_address(self, address: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn with_base_port(self, port: u16) -> Self;
    pub fn with_audio_codecs(self, codecs: Vec<CodecInfo>) -> Result<Self, NegotiationError>;
    pub fn with_video_codecs(self, codecs: Vec<CodecInfo>) -> Result<Self, NegotiationError>;
    pub fn with_direction_override(self, direction: Direction) -> Self;
    pub fn with_reject_media(self, reject: Vec<usize>) -> Result<Self, NegotiationError>;
    pub fn with_username(self, username: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn with_session_id(self, session_id: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn with_qos_local_status(self, status: PreconditionDirection) -> Self;
    pub fn with_qos_remote_status(self, status: PreconditionDirection) -> Self;
    pub fn with_upgrade_preconditions(self, upgrade: bool) -> Self;

    pub fn local_address(&self) -> &str;
    pub fn base_port(&self) -> u16;
    pub fn audio_codecs(&self) -> &[CodecInfo];
    pub fn video_codecs(&self) -> &[CodecInfo];
    pub fn direction_override(&self) -> Option<Direction>;
    pub fn reject_media(&self) -> &[usize];
    pub fn username(&self) -> &str;
    pub fn session_id(&self) -> &str;
    pub fn qos_local_status(&self) -> Option<PreconditionDirection>;
    pub fn qos_remote_status(&self) -> Option<PreconditionDirection>;
    pub fn upgrade_preconditions_to_mandatory(&self) -> bool;
}

impl Default for AnswerOptions;
```

`AnswerOptions::default()` builds the hardcoded codec lists with `CodecInfo::new(...).ok()` and
filters invalid entries, so a validation change will drop a default codec instead of panicking.

### CodecInfo

```rust
pub struct CodecInfo {
    // Fields are private; configure via builder methods.
}

impl CodecInfo {
    pub fn new(
        name: impl AsRef<str>,
        clock_rate: u32,
        channels: Option<u16>,
    ) -> Result<Self, NegotiationError>;
    pub fn with_fmtp(self, fmtp: impl AsRef<str>) -> Result<Self, NegotiationError>;
    pub fn name(&self) -> &str;
    pub fn clock_rate(&self) -> u32;
    pub fn channels(&self) -> Option<u16>;
    pub fn fmtp(&self) -> Option<&str>;
    pub fn matches(&self, rtpmap: &RtpMap) -> bool;
}
```

### NegotiationError

```rust
pub enum NegotiationError {
    NoCommonCodecs(usize),      // No matching codecs for media
    InvalidSdp(String),         // SDP structure error
    MediaMismatch(String),      // Stream count mismatch
    DirectionConflict(String),  // Invalid direction combination
    ValidationError(String),    // Input validation failure
    TooManyMediaStreams { max: usize, actual: usize },
}
```

## RFC 3264 Compliance Summary

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Media stream matching by position | ✅ | `generate_answer()` |
| Codec negotiation and selection | ✅ | `negotiate_media()` |
| Direction attribute negotiation | ✅ | `negotiate_direction()` |
| Media rejection (port 0) | ✅ | `create_rejected_media()` |
| Hold/resume procedures | ✅ | `create_hold_offer()`, `create_resume_offer()` |
| Static payload type recognition | ✅ | `get_static_payload_rtpmap()` |
| Format parameter preservation | ✅ | `find_fmtp_for_payload()` |
| Session version incrementing | ✅ | Hold/resume methods |

## Implementation Files

### `crates/sip-core/src/sdp_offer_answer.rs`

**Lines 1-16**: Module documentation and imports
**Lines 27-61**: `NegotiationError` enum
**Lines 63-252**: `AnswerOptions` struct, builder methods, and Default implementation
**Lines 254-329**: `CodecInfo` struct with matching logic
**Lines 436-438**: `OfferAnswerEngine` struct
**Lines 445-511**: `generate_answer()` - Core offer/answer negotiation
**Lines 513-602**: `negotiate_media()` - Per-media stream negotiation
**Lines 604-621**: `create_rejected_media()` - Media rejection helper
**Lines 623-647**: `extract_rtpmaps()` - RTP mapping extraction
**Lines 649-689**: `get_static_payload_rtpmap()` - Static payload recognition
**Lines 692-706**: `find_fmtp_for_payload()` - Format parameter lookup
**Lines 708-718**: `get_media_direction()` - Direction attribute extraction
**Lines 720-728**: `negotiate_direction()` - Direction negotiation logic
**Lines 730-758**: `create_hold_offer()` - Hold offer generation
**Lines 761-790**: `create_resume_offer()` - Resume offer generation
**Lines 792-912**: `handle_preconditions()` - RFC 3312 preconditions
**Lines 921-1237**: Comprehensive test suite (16 tests)

### `crates/sip-core/src/lib.rs`

**Line 60**: Module declaration
**Line 119**: Exported types

## Conclusion

siphon-rs provides **complete RFC 3264 compliance** for SDP offer/answer negotiation:

✅ **Media Stream Matching** - By position per RFC 3264 §5.1
✅ **Codec Negotiation** - Common codec selection with preference
✅ **Direction Negotiation** - All direction combinations supported
✅ **Media Rejection** - Port 0 rejection mechanism
✅ **Hold/Resume** - Complete hold and resume support
✅ **Static Payloads** - Recognition of well-known payload types
✅ **Format Parameters** - fmtp preservation in answers

The implementation provides type-safe, ergonomic APIs for multimedia session negotiation in SIP applications, with full support for the offer/answer model.

---

**References**:
- [RFC 3264: An Offer/Answer Model with SDP](https://www.rfc-editor.org/rfc/rfc3264.html)
- [RFC 4566: SDP](https://www.rfc-editor.org/rfc/rfc4566.html)
- [RFC 3551: RTP Audio/Video Profile](https://www.rfc-editor.org/rfc/rfc3551.html)
- [RFC 3261: SIP §13.2 (SDP in SIP)](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2)
