# RFC 4566: SDP (Session Description Protocol) - Implementation

## Overview

RFC 4566 defines SDP (Session Description Protocol), a textual format for describing multimedia sessions. This document describes the comprehensive RFC 4566-compliant SDP implementation in siphon-rs.

**Status**: ✅ **FULLY COMPLIANT** - Complete parsing, generation, and validation

**Key Standards**:
- **RFC 4566**: SDP: Session Description Protocol
- **RFC 3264**: An Offer/Answer Model with SDP (used with SIP)
- **RFC 3261**: SIP integration (SDP in message bodies)

## What is SDP?

SDP provides a standard way to describe multimedia communication sessions for:
- Session announcement
- Session invitation
- Parameter negotiation

### SDP Structure

An SDP description consists of:
1. **Session-level section**: Applies to entire conference
2. **Media-level sections**: One per media stream (audio, video, etc.)

Format: `<type>=<value>` where type is a single character.

```text
v=0
o=alice 123 456 IN IP4 192.0.2.1          ← Session level
s=Voice Call
c=IN IP4 192.0.2.1
t=0 0
m=audio 49170 RTP/AVP 0 8                 ← Media level
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
m=video 51372 RTP/AVP 99                  ← Another media
a=rtpmap:99 H264/90000
```

## RFC 4566 Compliance

### Supported Session-Level Fields

| Field | Name | Required | Supported |
|-------|------|----------|-----------|
| v= | Protocol Version | ✓ | ✅ Full |
| o= | Origin | ✓ | ✅ Full |
| s= | Session Name | ✓ | ✅ Full |
| i= | Session Information | Optional | ✅ Full |
| u= | URI | Optional | ✅ Full |
| e= | Email | Optional | ✅ Full (multiple) |
| p= | Phone | Optional | ✅ Full (multiple) |
| c= | Connection Data | Optional* | ✅ Full |
| b= | Bandwidth | Optional | ✅ Full (multiple) |
| t= | Timing | ✓ | ✅ Full (multiple) |
| r= | Repeat Times | Optional | ✅ Full |
| z= | Time Zones | Optional | ✅ Full |
| k= | Encryption Key | Optional | ✅ Full |
| a= | Attributes | Optional | ✅ Full (multiple) |

*Required at session level OR in all media descriptions.

### Supported Media-Level Fields

| Field | Name | Required | Supported |
|-------|------|----------|-----------|
| m= | Media Description | ✓ | ✅ Full |
| i= | Media Title | Optional | ✅ Full |
| c= | Connection Data | Optional | ✅ Full |
| b= | Bandwidth | Optional | ✅ Full (multiple) |
| k= | Encryption Key | Optional | ✅ Full |
| a= | Attributes | Optional | ✅ Full (multiple) |

### Parsed Attributes

✅ **Direction attributes** (RFC 4566 §6):
- `a=sendrecv` - Bidirectional media (default)
- `a=sendonly` - Send-only (e.g., music on hold)
- `a=recvonly` - Receive-only (e.g., broadcast)
- `a=inactive` - No media sent or received

✅ **RTP attributes**:
- `a=rtpmap:<payload> <encoding>/<rate>[/<params>]` - RTP payload mapping
- `a=fmtp:<format> <params>` - Format-specific parameters

✅ **Generic attributes**:
- Property form: `a=recvonly`
- Value form: `a=tool:siphon v1.0`

## Implementation Architecture

### Core Types

```rust
/// Complete SDP session description
pub struct SdpSession {
    // Required fields
    pub version: u32,              // v= (always 0)
    pub origin: Origin,            // o=
    pub session_name: String,      // s=

    // Optional session-level fields
    pub session_info: Option<String>,        // i=
    pub uri: Option<String>,                 // u=
    pub emails: Vec<String>,                 // e=
    pub phones: Vec<String>,                 // p=
    pub connection: Option<Connection>,      // c=
    pub bandwidth: Vec<Bandwidth>,           // b=
    pub timing: Vec<Timing>,                 // t= (at least one)
    pub repeat_times: Vec<RepeatTime>,       // r=
    pub time_zones: Vec<TimeZone>,           // z=
    pub encryption_key: Option<EncryptionKey>, // k=
    pub attributes: Vec<Attribute>,          // a=

    // Media descriptions
    pub media: Vec<MediaDescription>,        // m=
}

/// Origin line components (o=)
pub struct Origin {
    pub username: String,          // Login or "-"
    pub sess_id: String,           // Globally unique (NTP timestamp)
    pub sess_version: String,      // Incremented on changes
    pub nettype: String,           // "IN" for Internet
    pub addrtype: String,          // "IP4" or "IP6"
    pub unicast_address: String,   // FQDN or IP
}

/// Media description with attributes
pub struct MediaDescription {
    pub media: String,             // audio, video, text, application, message
    pub port: u16,                 // Transport port
    pub port_count: Option<u16>,   // For m=video 49170/2
    pub proto: String,             // RTP/AVP, RTP/SAVP, udp, etc.
    pub fmt: Vec<String>,          // Payload types / formats

    // Media-level fields
    pub title: Option<String>,              // i=
    pub connection: Option<Connection>,     // c=
    pub bandwidth: Vec<Bandwidth>,          // b=
    pub encryption_key: Option<EncryptionKey>, // k=
    pub attributes: Vec<Attribute>,         // a=
}
```

### Direction Enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,  // Bidirectional (default)
    SendOnly,  // Send-only
    RecvOnly,  // Receive-only
    Inactive,  // No media
}
```

### RTP Attributes

```rust
/// RTP payload mapping (a=rtpmap)
pub struct RtpMap {
    pub payload_type: u8,
    pub encoding_name: String,
    pub clock_rate: u32,
    pub encoding_params: Option<String>,  // Channels for audio
}

/// Format parameters (a=fmtp)
pub struct Fmtp {
    pub format: String,    // Payload type
    pub params: String,    // Codec-specific parameters
}
```

## Usage Examples

### Example 1: Parsing SDP

```rust
use sip_core::sdp::{SdpSession, Direction};

let sdp_text = "v=0\r\n\
                o=alice 2890844526 2890842807 IN IP4 192.0.2.1\r\n\
                s=Voice Call\r\n\
                c=IN IP4 192.0.2.1\r\n\
                t=0 0\r\n\
                m=audio 49170 RTP/AVP 0 8\r\n\
                a=rtpmap:0 PCMU/8000\r\n\
                a=rtpmap:8 PCMA/8000\r\n\
                a=sendrecv\r\n";

// Parse SDP
let session = SdpSession::parse(sdp_text)?;

// Access session-level fields
assert_eq!(session.version, 0);
assert_eq!(session.origin.username, "alice");
assert_eq!(session.session_name, "Voice Call");
assert_eq!(session.connection.as_ref()?.connection_address, "192.0.2.1");

// Access media descriptions
assert_eq!(session.media.len(), 1);
assert_eq!(session.media[0].media, "audio");
assert_eq!(session.media[0].port, 49170);
assert_eq!(session.media[0].proto, "RTP/AVP");
assert_eq!(session.media[0].fmt, vec!["0", "8"]);

// Find direction
let dir = session.find_direction(Some(0))?;
assert_eq!(dir, Direction::SendRecv);

// Find rtpmap attributes
let rtpmaps = session.find_rtpmaps(0);
assert_eq!(rtpmaps.len(), 2);
assert_eq!(rtpmaps[0].payload_type, 0);
assert_eq!(rtpmaps[0].encoding_name, "PCMU");
assert_eq!(rtpmaps[0].clock_rate, 8000);
```

### Example 2: Generating SDP

```rust
use sip_core::sdp::{SdpSession, Origin, Connection, MediaDescription, Attribute, RtpMap};

// Create session
let origin = Origin {
    username: "bob".to_string(),
    sess_id: "1234567890".to_string(),
    sess_version: "1".to_string(),
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    unicast_address: "203.0.113.5".to_string(),
};

let mut session = SdpSession::new(origin, "Video Conference".to_string());

// Add session-level connection
session.connection = Some(Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "203.0.113.5".to_string(),
});

// Add audio media
let mut audio = MediaDescription {
    media: "audio".to_string(),
    port: 49170,
    port_count: None,
    proto: "RTP/AVP".to_string(),
    fmt: vec!["0".to_string(), "8".to_string()],
    title: None,
    connection: None,
    bandwidth: Vec::new(),
    encryption_key: None,
    attributes: vec![
        Attribute {
            name: "rtpmap".to_string(),
            value: Some("0 PCMU/8000".to_string()),
        },
        Attribute {
            name: "rtpmap".to_string(),
            value: Some("8 PCMA/8000".to_string()),
        },
        Attribute {
            name: "sendrecv".to_string(),
            value: None,
        },
    ],
};

session.media.push(audio);

// Generate SDP string
let sdp_string = session.to_string();
println!("{}", sdp_string);

// Output:
// v=0
// o=bob 1234567890 1 IN IP4 203.0.113.5
// s=Video Conference
// c=IN IP4 203.0.113.5
// t=0 0
// m=audio 49170 RTP/AVP 0 8
// a=rtpmap:0 PCMU/8000
// a=rtpmap:8 PCMA/8000
// a=sendrecv
```

### Example 3: SIP INVITE with SDP Offer

```rust
use sip_core::sdp::{SdpSession, Origin, Connection};
use sip_core::{Request, Method, SipUri, RequestLine};

// Create SDP offer
let origin = Origin {
    username: "caller".to_string(),
    sess_id: "1234567890".to_string(),
    sess_version: "0".to_string(),
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    unicast_address: "192.0.2.10".to_string(),
};

let mut session = SdpSession::new(origin, "Call Session".to_string());
session.connection = Some(Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "192.0.2.10".to_string(),
});

// Add audio media with multiple codecs
let mut audio = MediaDescription {
    media: "audio".to_string(),
    port: 8000,
    port_count: None,
    proto: "RTP/AVP".to_string(),
    fmt: vec!["0".to_string(), "8".to_string(), "101".to_string()],
    title: None,
    connection: None,
    bandwidth: Vec::new(),
    encryption_key: None,
    attributes: vec![
        Attribute {
            name: "rtpmap".to_string(),
            value: Some("0 PCMU/8000".to_string()),
        },
        Attribute {
            name: "rtpmap".to_string(),
            value: Some("8 PCMA/8000".to_string()),
        },
        Attribute {
            name: "rtpmap".to_string(),
            value: Some("101 telephone-event/8000".to_string()),
        },
        Attribute {
            name: "fmtp".to_string(),
            value: Some("101 0-15".to_string()),
        },
    ],
};

session.media.push(audio);

// Generate SDP body
let sdp_body = session.to_string();

// Create INVITE with SDP
let mut invite = Request::new(
    RequestLine::new(Method::Invite, SipUri::parse("sip:callee@example.com")?),
    Headers::new(),
    bytes::Bytes::from(sdp_body),
);

// Add Content-Type header
invite.headers.push(
    SmolStr::new("Content-Type"),
    SmolStr::new("application/sdp"),
);
```

### Example 4: Parsing All Field Types

```rust
use sip_core::sdp::SdpSession;

// Complete SDP with all optional fields
let sdp = "v=0\r\n\
           o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
           s=SDP Seminar\r\n\
           i=A Seminar on the session description protocol\r\n\
           u=http://www.example.com/seminars/sdp.pdf\r\n\
           e=j.doe@example.com (Jane Doe)\r\n\
           e=support@example.com\r\n\
           p=+1 617 555-6011\r\n\
           c=IN IP4 224.2.17.12/127\r\n\
           b=CT:1000\r\n\
           b=AS:256\r\n\
           t=2873397496 2873404696\r\n\
           r=604800 3600 0 90000\r\n\
           z=2882844526 -1h 2898848070 0\r\n\
           k=prompt\r\n\
           a=recvonly\r\n\
           a=type:broadcast\r\n\
           m=audio 49170 RTP/AVP 0\r\n\
           m=video 51372 RTP/AVP 99\r\n\
           a=rtpmap:99 h263-1998/90000\r\n";

let session = SdpSession::parse(sdp)?;

// Session-level fields
println!("Version: {}", session.version);
println!("Origin: {:?}", session.origin);
println!("Session Name: {}", session.session_name);
println!("Session Info: {:?}", session.session_info);
println!("URI: {:?}", session.uri);
println!("Emails: {:?}", session.emails);
println!("Phones: {:?}", session.phones);
println!("Connection: {:?}", session.connection);
println!("Bandwidth: {:?}", session.bandwidth);
println!("Timing: {:?}", session.timing);
println!("Repeat Times: {:?}", session.repeat_times);
println!("Time Zones: {:?}", session.time_zones);
println!("Encryption Key: {:?}", session.encryption_key);
println!("Attributes: {:?}", session.attributes);

// Media descriptions
for (i, media) in session.media.iter().enumerate() {
    println!("Media {}: {} port {}", i, media.media, media.port);
    println!("  Proto: {}", media.proto);
    println!("  Formats: {:?}", media.fmt);
    println!("  Attributes: {:?}", media.attributes);
}
```

### Example 5: Video Call with Multiple Codecs

```rust
use sip_core::sdp::{SdpSession, Origin, Connection, MediaDescription, Attribute, Direction};

let origin = Origin {
    username: "-".to_string(),
    sess_id: "1234567890".to_string(),
    sess_version: "2".to_string(),
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    unicast_address: "192.0.2.100".to_string(),
};

let mut session = SdpSession::new(origin, "Video Call".to_string());
session.connection = Some(Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "192.0.2.100".to_string(),
});

// Audio with PCMU, PCMA, and DTMF
let audio = MediaDescription {
    media: "audio".to_string(),
    port: 5004,
    port_count: None,
    proto: "RTP/AVP".to_string(),
    fmt: vec!["0".to_string(), "8".to_string(), "101".to_string()],
    title: Some("Audio Stream".to_string()),
    connection: None,
    bandwidth: Vec::new(),
    encryption_key: None,
    attributes: vec![
        Attribute { name: "rtpmap".to_string(), value: Some("0 PCMU/8000".to_string()) },
        Attribute { name: "rtpmap".to_string(), value: Some("8 PCMA/8000".to_string()) },
        Attribute { name: "rtpmap".to_string(), value: Some("101 telephone-event/8000".to_string()) },
        Attribute { name: "fmtp".to_string(), value: Some("101 0-15".to_string()) },
        Attribute { name: "ptime".to_string(), value: Some("20".to_string()) },
        Attribute { name: "sendrecv".to_string(), value: None },
    ],
};

session.media.push(audio);

// Video with H.264
let video = MediaDescription {
    media: "video".to_string(),
    port: 5006,
    port_count: None,
    proto: "RTP/AVP".to_string(),
    fmt: vec!["99".to_string()],
    title: Some("Video Stream".to_string()),
    connection: None,
    bandwidth: vec![
        Bandwidth { bwtype: "AS".to_string(), bandwidth: 384 },
    ],
    encryption_key: None,
    attributes: vec![
        Attribute { name: "rtpmap".to_string(), value: Some("99 H264/90000".to_string()) },
        Attribute { name: "fmtp".to_string(), value: Some("99 profile-level-id=42e01f;packetization-mode=1".to_string()) },
        Attribute { name: "sendrecv".to_string(), value: None },
    ],
};

session.media.push(video);

let generated = session.to_string();
println!("{}", generated);
```

### Example 6: Hold Scenarios

```rust
use sip_core::sdp::{SdpSession, Direction, Attribute};

// Parsing a hold request (sendonly)
let hold_sdp = "v=0\r\n\
                o=alice 123 456 IN IP4 192.0.2.1\r\n\
                s=Call\r\n\
                c=IN IP4 192.0.2.1\r\n\
                t=0 0\r\n\
                m=audio 49170 RTP/AVP 0\r\n\
                a=sendonly\r\n";

let session = SdpSession::parse(hold_sdp)?;
let dir = session.find_direction(Some(0))?;

match dir {
    Direction::SendOnly => println!("Call on hold (music on hold)"),
    Direction::RecvOnly => println!("Remote party on hold"),
    Direction::Inactive => println!("Both parties on hold"),
    Direction::SendRecv => println!("Active call"),
}

// Generating a hold response
let mut response_session = session.clone();
// Change to recvonly to accept music on hold
response_session.media[0].attributes = vec![
    Attribute { name: "recvonly".to_string(), value: None },
];
```

## Field-by-Field Reference

### v= (Version)

**Format**: `v=0`

**Description**: Protocol version, currently always 0.

**Required**: Yes (must be first line)

```rust
session.version  // u32, always 0
```

### o= (Origin)

**Format**: `o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>`

**Example**: `o=alice 2890844526 2890842807 IN IP4 192.0.2.1`

**Description**: Session originator and session identifier.

**Components**:
- `username`: User's login or "-"
- `sess-id`: Globally unique identifier (often NTP timestamp)
- `sess-version`: Version number, increment on changes
- `nettype`: "IN" for Internet
- `addrtype`: "IP4" or "IP6"
- `unicast-address`: FQDN or IP address

**Required**: Yes

```rust
let origin = Origin {
    username: "alice".to_string(),
    sess_id: "2890844526".to_string(),
    sess_version: "2890842807".to_string(),
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    unicast_address: "192.0.2.1".to_string(),
};
```

### s= (Session Name)

**Format**: `s=<session name>`

**Example**: `s=SIP Call`

**Description**: Human-readable session name. Use `s= ` (space) if no meaningful name.

**Required**: Yes

```rust
session.session_name = "My Conference".to_string();
```

### i= (Information)

**Format**: `i=<session description>`

**Example**: `i=Discussion about next quarter goals`

**Description**: Human-readable information about the session.

**Location**: Session-level or media-level

**Required**: No

```rust
session.session_info = Some("Weekly team meeting".to_string());
media.title = Some("Screen sharing".to_string());
```

### u= (URI)

**Format**: `u=<uri>`

**Example**: `u=http://www.example.com/conference.html`

**Description**: URI pointing to additional information.

**Required**: No

```rust
session.uri = Some("http://example.com/meeting".to_string());
```

### e= (Email) and p= (Phone)

**Format**:
- `e=<email-address>`
- `p=<phone-number>`

**Examples**:
- `e=alice@example.com (Alice Smith)`
- `p=+1 617 555-6011`

**Description**: Contact information. Multiple allowed.

**Required**: No

```rust
session.emails.push("admin@example.com".to_string());
session.phones.push("+1 555 1234".to_string());
```

### c= (Connection Data)

**Format**: `c=<nettype> <addrtype> <connection-address>`

**Examples**:
- `c=IN IP4 192.0.2.1`
- `c=IN IP4 224.2.17.12/127` (multicast with TTL)
- `c=IN IP6 FF15::101`

**Description**: Network connection information.

**Required**: At session level OR in all media descriptions

```rust
let conn = Connection {
    nettype: "IN".to_string(),
    addrtype: "IP4".to_string(),
    connection_address: "192.0.2.1".to_string(),
};

session.connection = Some(conn.clone());
// OR
media.connection = Some(conn);
```

### b= (Bandwidth)

**Format**: `b=<bwtype>:<bandwidth>`

**Examples**:
- `b=CT:1000` (Conference Total: 1000 kbps)
- `b=AS:384` (Application Specific: 384 kbps)

**Description**: Bandwidth limit in kilobits per second.

**Required**: No (multiple allowed)

```rust
session.bandwidth.push(Bandwidth {
    bwtype: "CT".to_string(),
    bandwidth: 1000,
});
```

### t= (Timing)

**Format**: `t=<start-time> <stop-time>`

**Example**: `t=2873397496 2873404696`

**Description**: NTP timestamps for session start/stop times. Use `t=0 0` for unbounded.

**Required**: Yes (at least one)

```rust
session.timing.push(Timing {
    start_time: 0,  // Permanent session
    stop_time: 0,
});
```

### r= (Repeat Times)

**Format**: `r=<repeat interval> <active duration> <offsets from start-time>`

**Examples**:
- `r=604800 3600 0 90000` (weekly, 1 hour, starting immediately and at 25h)
- `r=7d 1h 0 25h` (same, using compact notation)

**Description**: Repeat schedule for recurring sessions.

**Required**: No

```rust
session.repeat_times.push(RepeatTime {
    repeat_interval: "7d".to_string(),
    active_duration: "1h".to_string(),
    offsets: vec!["0".to_string(), "25h".to_string()],
});
```

### z= (Time Zones)

**Format**: `z=<adjustment time> <offset> <adjustment time> <offset> ...`

**Example**: `z=2882844526 -1h 2898848070 0`

**Description**: Daylight saving time adjustments.

**Required**: No

```rust
session.time_zones.push(TimeZone {
    adjustment_time: 2882844526,
    offset: "-1h".to_string(),
});
```

### k= (Encryption Key)

**Format**:
- `k=<method>`
- `k=<method>:<encryption key>`

**Examples**:
- `k=prompt`
- `k=clear:mypassword`
- `k=base64:dGVzdCBwYXNzd29yZA==`
- `k=uri:https://example.com/keys/session123`

**Description**: Encryption key information.

**Security Warning**: Only use over secure channels!

**Required**: No

```rust
session.encryption_key = Some(EncryptionKey {
    method: "prompt".to_string(),
    key: None,
});
```

### a= (Attributes)

**Format**:
- Property: `a=<attribute>`
- Value: `a=<attribute>:<value>`

**Examples**:
- `a=recvonly`
- `a=rtpmap:0 PCMU/8000`
- `a=tool:siphon v1.0`

**Description**: Generic extension mechanism.

**Required**: No (multiple allowed)

```rust
// Property attribute
session.attributes.push(Attribute {
    name: "recvonly".to_string(),
    value: None,
});

// Value attribute
session.attributes.push(Attribute {
    name: "tool".to_string(),
    value: Some("siphon v1.0".to_string()),
});
```

### m= (Media Description)

**Format**: `m=<media> <port> <proto> <fmt> ...`

**Examples**:
- `m=audio 49170 RTP/AVP 0 8`
- `m=video 51372 RTP/AVP 99`
- `m=video 49170/2 RTP/AVP 31` (2 ports: 49170-49173)

**Components**:
- `media`: audio, video, text, application, message
- `port`: Transport port number
- `proto`: RTP/AVP, RTP/SAVP, udp, etc.
- `fmt`: Format list (RTP payload types, etc.)

**Required**: No (zero or more)

```rust
let media = MediaDescription {
    media: "audio".to_string(),
    port: 49170,
    port_count: None,  // Or Some(2) for /2
    proto: "RTP/AVP".to_string(),
    fmt: vec!["0".to_string(), "8".to_string()],
    // ... other fields
};
```

## Direction Attributes

RFC 4566 Section 6 defines four direction attributes:

### a=sendrecv (Default)

**Meaning**: Media sent and received (bidirectional)

**Use**: Normal active call

```rust
media.attributes.push(Attribute {
    name: "sendrecv".to_string(),
    value: None,
});

// Check direction
if session.find_direction(Some(0)) == Some(Direction::SendRecv) {
    println!("Bidirectional media");
}
```

### a=sendonly

**Meaning**: Media sent only, not received

**Use**: Music on hold, announcements

```rust
media.attributes.push(Attribute {
    name: "sendonly".to_string(),
    value: None,
});
```

### a=recvonly

**Meaning**: Media received only, not sent

**Use**: Broadcast reception, listening to hold music

```rust
media.attributes.push(Attribute {
    name: "recvonly".to_string(),
    value: None,
});
```

### a=inactive

**Meaning**: No media sent or received

**Use**: Both sides on hold

```rust
media.attributes.push(Attribute {
    name: "inactive".to_string(),
    value: None,
});
```

## RTP Attributes

### a=rtpmap

**Format**: `a=rtpmap:<payload type> <encoding name>/<clock rate>[/<encoding parameters>]`

**Examples**:
- `a=rtpmap:0 PCMU/8000` (G.711 μ-law, 8kHz)
- `a=rtpmap:8 PCMA/8000` (G.711 A-law, 8kHz)
- `a=rtpmap:98 L16/16000/2` (16-bit linear, 16kHz, stereo)
- `a=rtpmap:99 H264/90000` (H.264 video, 90kHz)

**Components**:
- `payload type`: RTP payload type number
- `encoding name`: Codec name
- `clock rate`: RTP timestamp clock rate in Hz
- `encoding parameters`: Usually channel count for audio

```rust
// Parse rtpmap
let rtpmap = RtpMap::parse("98 L16/16000/2")?;
assert_eq!(rtpmap.payload_type, 98);
assert_eq!(rtpmap.encoding_name, "L16");
assert_eq!(rtpmap.clock_rate, 16000);
assert_eq!(rtpmap.encoding_params, Some("2".to_string()));

// Format rtpmap
let value = rtpmap.to_value();  // "98 L16/16000/2"

// Find all rtpmaps in media
let rtpmaps = session.find_rtpmaps(0);
for rtpmap in rtpmaps {
    println!("Payload {}: {}/{}",
        rtpmap.payload_type,
        rtpmap.encoding_name,
        rtpmap.clock_rate);
}
```

### a=fmtp

**Format**: `a=fmtp:<format> <format specific parameters>`

**Examples**:
- `a=fmtp:98 profile-level-id=42e01f` (H.264 profile)
- `a=fmtp:101 0-15` (DTMF events 0-15)
- `a=fmtp:100 minptime=10;useinbandfec=1` (Opus parameters)

**Description**: Codec-specific configuration parameters.

```rust
// Parse fmtp
let fmtp = Fmtp::parse("98 profile-level-id=42e01f")?;
assert_eq!(fmtp.format, "98");
assert_eq!(fmtp.params, "profile-level-id=42e01f");

// Find all fmtp in media
let fmtps = session.find_fmtps(0);
for fmtp in fmtps {
    println!("Format {}: {}", fmtp.format, fmtp.params);
}
```

## Error Handling

```rust
use sip_core::sdp::{SdpSession, SdpError};

let result = SdpSession::parse(sdp_text);

match result {
    Ok(session) => {
        println!("Parsed successfully");
    }
    Err(SdpError::MissingRequiredField(field)) => {
        println!("Missing required field: {}", field);
    }
    Err(SdpError::InvalidFormat(field)) => {
        println!("Invalid format for field: {}", field);
    }
    Err(SdpError::InvalidOrder(msg)) => {
        println!("Field order error: {}", msg);
    }
    Err(SdpError::InvalidSyntax(msg)) => {
        println!("Syntax error: {}", msg);
    }
    Err(SdpError::UnknownField(c)) => {
        println!("Unknown field type: {}", c);
    }
}
```

## Testing

Comprehensive test coverage with 25 tests:

```bash
$ cargo test --package sip-core sdp::
running 25 tests
test sdp::tests::parse_minimal_sdp ... ok
test sdp::tests::parse_session_info_line ... ok
test sdp::tests::parse_email_line ... ok
test sdp::tests::parse_phone_line ... ok
test sdp::tests::parse_bandwidth_line ... ok
test sdp::tests::parse_timing_line ... ok
test sdp::tests::parse_repeat_time_line ... ok
test sdp::tests::parse_time_zone_line ... ok
test sdp::tests::parse_encryption_key_line ... ok
test sdp::tests::parse_generic_attributes ... ok
test sdp::tests::parse_all_direction_attributes ... ok
test sdp::tests::parse_rtpmap_variations ... ok
test sdp::tests::parse_fmtp_variations ... ok
test sdp::tests::parse_media_with_multiple_ports ... ok
test sdp::tests::parse_media_level_fields ... ok
test sdp::tests::parse_complete_rfc_example ... ok
test sdp::tests::generate_sdp ... ok
test sdp::tests::generate_complete_sdp ... ok
test sdp::tests::round_trip_sdp ... ok
test sdp::tests::validate_connection_requirement ... ok
test sdp::tests::validate_connection_in_media ... ok
# ... all pass
```

## Performance Characteristics

- **Parsing**: O(n) where n = number of lines
- **Generation**: O(n) where n = number of fields
- **Memory**: Minimal allocations, uses `String` for fields
- **Zero-copy**: Not applicable (SDP is textual, needs parsing)

## Integration with SIP

SDP is typically used in SIP message bodies:

```rust
use sip_core::{Request, Response, Method};
use sip_core::sdp::SdpSession;

// INVITE with SDP offer
let invite = /* ... */;
if let Some(body) = invite.body {
    if let Ok(session) = SdpSession::parse(std::str::from_utf8(&body)?) {
        println!("SDP offer received");
        println!("Media count: {}", session.media.len());
    }
}

// 200 OK with SDP answer
let response = /* ... */;
if let Ok(session) = SdpSession::parse(std::str::from_utf8(&response.body)?) {
    println!("SDP answer received");
    // Negotiate codecs, ports, etc.
}
```

## RFC 4566 Compliance Summary

✅ **Complete compliance** with RFC 4566:

| Feature | Status |
|---------|--------|
| All session-level fields | ✅ Fully supported |
| All media-level fields | ✅ Fully supported |
| Field ordering validation | ✅ Enforced |
| Connection requirement | ✅ Validated |
| Direction attributes | ✅ Parsed and generated |
| RTP attributes (rtpmap, fmtp) | ✅ Specialized parsing |
| Generic attributes | ✅ Property and value forms |
| Error handling | ✅ Comprehensive |
| Parsing | ✅ Complete |
| Generation | ✅ Complete |
| Round-trip | ✅ Tested |

## Implementation Files

### `crates/sip-core/src/sdp.rs`

**Lines 1-61**: Module documentation and RFC 4566 compliance summary
**Lines 62-92**: Error types (`SdpError`)
**Lines 94-135**: Core `SdpSession` struct
**Lines 137-274**: Supporting structs (Origin, Connection, Bandwidth, etc.)
**Lines 276-498**: `SdpSession` implementation (parsing, generation, helpers)
**Lines 500-555**: Display implementation for generation
**Lines 557-644**: Media description parsing and display
**Lines 646-715**: Display implementations for all types
**Lines 717-784**: RTP attribute parsing (`RtpMap`, `Fmtp`)
**Lines 786-955**: Parsing helper functions
**Lines 957-1495**: Comprehensive test suite (25 tests)

### `crates/sip-core/src/lib.rs`

**Lines 89-92**: Exported SDP types

## Conclusion

siphon-rs provides **complete RFC 4566 compliance** for SDP:

✅ **All field types** - v=, o=, s=, i=, u=, e=, p=, c=, b=, t=, r=, z=, k=, a=, m=
✅ **Parsing** - Comprehensive with error handling
✅ **Generation** - Complete via Display trait
✅ **Validation** - Field ordering, connection requirements
✅ **Direction attributes** - sendrecv, sendonly, recvonly, inactive
✅ **RTP attributes** - rtpmap and fmtp with specialized parsing
✅ **Generic attributes** - Property and value forms
✅ **Testing** - 25 comprehensive tests covering all features

The implementation provides type-safe, ergonomic APIs for working with SDP in SIP applications, with full support for multimedia session description and negotiation.

---

**References**:
- [RFC 4566: SDP: Session Description Protocol](https://www.rfc-editor.org/rfc/rfc4566.html)
- [RFC 3264: An Offer/Answer Model with SDP](https://www.rfc-editor.org/rfc/rfc3264.html)
- [RFC 3261: SIP §13.2 (SDP Bodies)](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2)
