# RFC 3891 Replaces Header Implementation

## Overview

This document describes the implementation of RFC 3891 ("The 'Replaces' Header Field in the Session Initiation Protocol (SIP)") in the sip-core crate.

## RFC Implemented

- **RFC 3891**: The "Replaces" Header Field in the Session Initiation Protocol (SIP)

## Purpose

The Replaces header enables distributed peer-to-peer call control by allowing one SIP dialog to logically replace another. This supports advanced telephony features without requiring centralized control:

1. **Attended Transfer**: Transfer a call after consulting with the transfer target
2. **Call Pickup**: Answer a ringing call from a different device
3. **Call Park and Retrieval**: Park a call and retrieve it from another location
4. **Dialog Migration**: Move an active call to a different device

## Key Concepts

### Dialog Replacement

The Replaces header identifies an existing dialog that should be replaced by the new dialog being established. The existing dialog is terminated, and the new dialog takes its place.

### Dialog Identification

A SIP dialog is uniquely identified by three components:
- **Call-ID**: Shared by both parties in the dialog
- **Local Tag**: Tag in the To header (from the perspective of the UA being replaced)
- **Remote Tag**: Tag in the From header (from the perspective of the UA being replaced)

### Early-Only Flag

The optional `early-only` parameter prevents replacement of confirmed (established) dialogs. This is useful for:
- Avoiding race conditions during call pickup
- Ensuring the target dialog is still ringing
- Preventing accidental replacement of active calls

## Header Format

### Syntax

```
Replaces: call-id; to-tag=value; from-tag=value [; early-only]
```

### Components

- **call-id** (required): The Call-ID of the dialog to replace
- **to-tag** (required): The local tag from the dialog being replaced
- **from-tag** (required): The remote tag from the dialog being replaced
- **early-only** (optional): Flag restricting replacement to early dialogs only

### Examples

**Basic Replaces:**
```
Replaces: 425928@bobster.example.org;to-tag=7743;from-tag=6472
```

**With early-only flag:**
```
Replaces: 98asjd8@test.com;to-tag=12345;from-tag=67890;early-only
```

## Implementation Structure

### `ReplacesHeader`

The main structure representing a Replaces header:

```rust
pub struct ReplacesHeader {
    // fields are private; use accessors
}
```

**Fields:**
- `call_id`: Call-ID of the dialog to replace
- `to_tag`: Local tag (to-tag) of the dialog to replace
- `from_tag`: Remote tag (from-tag) of the dialog to replace
- `early_only`: If true, only allows replacement of early dialogs

**Methods:**
- `new(call_id: &str, to_tag: &str, from_tag: &str)` - Creates a new Replaces header
- `with_early_only(early_only: bool)` - Sets the early-only flag
- `is_early_only()` - Returns true if early-only flag is set
- `parse(input: &str)` - Parses a Replaces header from a string

## Usage Examples

### Creating a Replaces Header

```rust
use sip_core::ReplacesHeader;

// Basic Replaces header
let replaces = ReplacesHeader::new(
    "425928@bobster.example.org",
    "7743",
    "6472"
);

assert_eq!(replaces.call_id(), "425928@bobster.example.org");
assert_eq!(replaces.to_tag(), "7743");
assert_eq!(replaces.from_tag(), "6472");
assert!(!replaces.is_early_only());

// Format as string
println!("{}", replaces);
// Output: 425928@bobster.example.org;to-tag=7743;from-tag=6472
```

### With Early-Only Flag

```rust
use sip_core::ReplacesHeader;

let replaces = ReplacesHeader::new(
    "call123@example.com",
    "tag1",
    "tag2"
).with_early_only(true);

assert!(replaces.is_early_only());

println!("{}", replaces);
// Output: call123@example.com;to-tag=tag1;from-tag=tag2;early-only
```

### Parsing Replaces Headers

```rust
use sip_core::ReplacesHeader;

// Parse basic header
let input = "425928@bobster.example.org;to-tag=7743;from-tag=6472";
let replaces = ReplacesHeader::parse(input)?;

assert_eq!(replaces.call_id(), "425928@bobster.example.org");
assert_eq!(replaces.to_tag(), "7743");
assert_eq!(replaces.from_tag(), "6472");

// Parse with early-only
let input = "98asjd8@test.com;to-tag=12345;from-tag=67890;early-only";
let replaces = ReplacesHeader::parse(input)?;

assert!(replaces.is_early_only());
```

## Use Cases

### 1. Attended Transfer

The most common use case for the Replaces header is attended (supervised) transfer.

**Scenario:**
1. Alice calls Bob (Call A: Alice ↔ Bob)
2. Bob puts Alice on hold
3. Bob calls Charlie (Call B: Bob ↔ Charlie) - consultation call
4. Bob talks to Charlie about the transfer
5. Bob sends REFER to Alice with a Refer-To header containing Charlie's URI and a Replaces header pointing to Call B
6. Alice sends INVITE to Charlie with the Replaces header
7. Charlie's phone replaces Call B (Bob ↔ Charlie) with the new call from Alice
8. Bob hangs up both calls

**Result:** Alice and Charlie are connected, Bob is out of the picture.

**Example REFER from Bob to Alice:**
```
REFER sip:alice@example.com SIP/2.0
Via: SIP/2.0/UDP bob.example.com;branch=z9hG4bK776asdhds
From: Bob <sip:bob@example.com>;tag=1234
To: Alice <sip:alice@example.com>;tag=5678
Call-ID: call-a@bob.example.com
CSeq: 1 REFER
Refer-To: <sip:charlie@example.com?Replaces=call-b%40bob.example.com%3Bto-tag%3D9999%3Bfrom-tag%3D8888>
```

Note: The Replaces header is URL-encoded in the Refer-To URI.

**Example INVITE from Alice to Charlie:**
```
INVITE sip:charlie@example.com SIP/2.0
Via: SIP/2.0/UDP alice.example.com;branch=z9hG4bK87asdks7
From: Alice <sip:alice@example.com>;tag=abcd
To: Charlie <sip:charlie@example.com>
Call-ID: new-call@alice.example.com
CSeq: 1 INVITE
Replaces: call-b@bob.example.com;to-tag=9999;from-tag=8888
```

**Rust Implementation:**
```rust
use sip_core::{Request, Method, ReplacesHeader};

// Charlie receives the INVITE and extracts the Replaces header
let replaces_value = request.headers().get("Replaces")?;
let replaces = ReplacesHeader::parse(replaces_value)?;

// Charlie's phone finds the matching dialog (Call B with Bob)
if let Some(dialog) = find_dialog(replaces.call_id(), replaces.to_tag(), replaces.from_tag()) {
    // Terminate the existing dialog with Bob
    dialog.send_bye();

    // Accept the new dialog with Alice
    let response = Response::new(200, "OK");
    // ... send response and establish media with Alice
}
```

### 2. Call Pickup

Call pickup allows answering a ringing call from a different device.

**Scenario:**
1. Alice calls Bob's desk phone (ringing - early dialog)
2. Bob is in the lab and sees the notification
3. Bob's lab phone sends INVITE with Replaces header (with early-only flag)
4. The desk phone call is replaced by the lab phone
5. Alice is now connected to Bob at his lab

**Example INVITE from Bob's lab phone:**
```
INVITE sip:bob-desk@example.com SIP/2.0
Via: SIP/2.0/UDP lab.example.com;branch=z9hG4bK87asdks7
From: Bob <sip:bob-lab@example.com>;tag=xyz
To: Bob <sip:bob-desk@example.com>
Call-ID: pickup-call@lab.example.com
CSeq: 1 INVITE
Replaces: desk-call@example.com;to-tag=desk-tag;from-tag=alice-tag;early-only
```

**Rust Implementation:**
```rust
use sip_core::ReplacesHeader;

// Create Replaces header for call pickup
let replaces = ReplacesHeader::new(
    "desk-call@example.com",
    "desk-tag",
    "alice-tag"
).with_early_only(true);  // Only pick up if still ringing

// Add to INVITE
request.headers_mut().set("Replaces", &replaces.to_string());

// The desk phone will:
// - Cancel the ringing call with Alice
// - Alice's call will be redirected to the lab phone
```

### 3. Call Park and Retrieval

Call parking allows placing a call in a temporary holding location and retrieving it from another device.

**Scenario:**
1. Bob is on a call with Alice at his office phone
2. Bob needs to leave the office
3. Bob transfers the call to a "parking" extension (e.g., *99)
4. Bob walks to the lab
5. Bob dials the retrieval code from his lab phone
6. The system sends INVITE with Replaces to retrieve the parked call
7. Bob's lab phone picks up the call with Alice

**Rust Implementation:**
```rust
use sip_core::ReplacesHeader;

// When Bob parks the call, the parking server stores the dialog info
let parked_dialog = ParkingSlot {
    call_id: "alice-bob@example.com",
    to_tag: "bob-tag",
    from_tag: "alice-tag",
    slot: "*99",
};

// When Bob retrieves from his lab phone
let replaces = ReplacesHeader::new(
    &parked_dialog.call_id,
    &parked_dialog.to_tag,
    &parked_dialog.from_tag
);

// Send INVITE to the parking location
let mut request = Request::new(
    Method::INVITE,
    format!("sip:{}@park.example.com", parked_dialog.slot).parse()?
);
request.headers_mut().set("Replaces", &replaces.to_string());
```

### 4. Dialog Migration

Moving an active call from one device to another.

**Scenario:**
1. Bob is on a mobile call with Alice
2. Bob arrives at the office and wants to move the call to his desk phone
3. Bob's desk phone sends INVITE with Replaces
4. The call migrates from mobile to desk phone

**Rust Implementation:**
```rust
use sip_core::ReplacesHeader;

// Extract dialog info from mobile call
let mobile_dialog = current_call.dialog();

// Create Replaces header
let replaces = ReplacesHeader::new(
    &mobile_dialog.call_id,
    &mobile_dialog.local_tag,
    &mobile_dialog.remote_tag
);

// Send INVITE from desk phone
let mut request = Request::new(
    Method::INVITE,
    alice_uri
);
request.headers_mut().set("Replaces", &replaces.to_string());

// Mobile phone will terminate when desk phone confirms
```

## Response Codes

When a UA receives a request with a Replaces header, it should respond according to RFC 3891:

| Condition | Response Code | Reason |
|-----------|---------------|--------|
| **Success** | 200 OK | Dialog matched and replaced successfully |
| **No Matching Dialog** | 481 Call/Transaction Does Not Exist | The specified dialog was not found |
| **Authorization Failed** | 403 Forbidden | Not authorized to replace this dialog |
| **Malformed Header** | 400 Bad Request | Replaces header is malformed or invalid |
| **Confirmed Dialog with early-only** | 486 Busy Here | Dialog is confirmed but early-only flag was set |
| **Dialog Terminated** | 603 Decline | The target dialog has already terminated |
| **Multiple Matches** | 400 Bad Request | Ambiguous - multiple dialogs match |

**Example Response Handling:**
```rust
use sip_core::ReplacesHeader;

fn handle_invite_with_replaces(request: &Request) -> Response {
    if let Some(replaces_value) = request.headers().get("Replaces") {
        let replaces = match ReplacesHeader::parse(replaces_value) {
            Some(r) => r,
            None => return Response::new(400, "Bad Request"), // Malformed
        };

        // Find the matching dialog
        let dialog = match find_dialog(replaces.call_id(), replaces.to_tag(), replaces.from_tag()) {
            Some(d) => d,
            None => return Response::new(481, "Call/Transaction Does Not Exist"),
        };

        // Check authorization
        if !is_authorized_to_replace(&dialog, &request) {
            return Response::new(403, "Forbidden");
        }

        // Check early-only flag
        if replaces.is_early_only() && dialog.is_confirmed() {
            return Response::new(486, "Busy Here");
        }

        // Check if already terminated
        if dialog.is_terminated() {
            return Response::new(603, "Decline");
        }

        // Replace the dialog
        dialog.terminate();
        Response::new(200, "OK")
    } else {
        // Handle as normal INVITE
        Response::new(200, "OK")
    }
}
```

## Security Considerations

### Authentication and Authorization

RFC 3891 requires strict security measures:

1. **Authentication**: The sender of a Replaces request MUST be authenticated
   - Use SIP Digest Authentication
   - Or S/MIME signatures
   - Or other cryptographic means

2. **Authorization**: The UA must verify the sender is authorized to replace the dialog
   - Shared credentials with the dialog participant
   - Referred-By mechanism (RFC 3892)
   - Local policy (e.g., same user, trusted domain)

3. **Privacy**: Dialog information should be protected
   - Use TLS for transport
   - Encrypt dialog parameters when transmitted
   - Avoid exposing dialog info in logs

**Example Authorization Check:**
```rust
fn is_authorized_to_replace(dialog: &Dialog, request: &Request) -> bool {
    // Check if authenticated
    if !is_authenticated(request) {
        return false;
    }

    // Check if same user
    let from_uri = request.from_uri();
    if from_uri.user() == dialog.remote_uri().user() {
        return true;
    }

    // Check Referred-By header (RFC 3892)
    if let Some(referred_by) = request.headers().get("Referred-By") {
        if referred_by.contains(&dialog.remote_uri().to_string()) {
            return true;
        }
    }

    // Check local policy
    if is_trusted_domain(from_uri.host()) {
        return true;
    }

    false
}
```

### Replay Attacks

To prevent replay attacks:
- Use nonces in authentication
- Validate timestamps
- Track replaced dialogs to prevent re-replacement
- Use TLS to protect headers in transit

### Information Disclosure

The Replaces header exposes dialog information (Call-ID and tags). To mitigate:
- Only send Replaces to trusted parties
- Use TLS/SIPS to encrypt signaling
- Avoid logging Replaces header values
- Implement dialog-level access control

## Integration with Other RFCs

### RFC 3515: REFER Method

The REFER method often uses Replaces in the Refer-To header:

```
Refer-To: <sip:target@example.com?Replaces=call-id%3Bto-tag%3Dtag1%3Bfrom-tag%3Dtag2>
```

**Encoding:**
```rust
use sip_core::ReplacesHeader;

let replaces = ReplacesHeader::new("call-id", "tag1", "tag2");
let encoded = urlencoding::encode(&replaces.to_string());

let refer_to = format!("<sip:target@example.com?Replaces={}>", encoded);
```

### RFC 3892: Referred-By

The Referred-By header provides authentication for Replaces requests:

```
Referred-By: <sip:bob@example.com>
```

This allows the recipient to verify that Bob initiated the transfer.

### RFC 4579: Conference URIs

Replaces can be used to join conferences by replacing a conference focus dialog.

## Testing

The implementation includes 14 comprehensive tests covering:

1. **Basic Operations**
   - Creating Replaces headers
   - Setting early-only flag
   - Formatting as string

2. **Parsing**
   - Basic header parsing
   - Parsing with early-only flag
   - Whitespace handling
   - Case-insensitive parameter names
   - Missing required parameters
   - Malformed headers

3. **Round-Trip**
   - Format → Parse → Format consistency
   - With and without early-only flag

### Running Tests

```bash
cargo test --package sip-core replaces
```

All 14 tests pass successfully.

## Complete Examples

### Attended Transfer Implementation

```rust
use sip_core::{Request, Response, Method, ReplacesHeader};

struct AttendedTransfer {
    // Call A: Alice ↔ Bob
    call_a_id: String,
    alice_tag: String,
    bob_tag_a: String,

    // Call B: Bob ↔ Charlie
    call_b_id: String,
    bob_tag_b: String,
    charlie_tag: String,
}

impl AttendedTransfer {
    fn execute_transfer(&self) {
        // Bob sends REFER to Alice
        let replaces = ReplacesHeader::new(
            &self.call_b_id,
            &self.charlie_tag,  // Charlie's tag
            &self.bob_tag_b,    // Bob's tag in Call B
        );

        // Encode Replaces for Refer-To
        let replaces_str = replaces.to_string();
        let encoded = urlencoding::encode(&replaces_str);

        // Build Refer-To header
        let refer_to = format!(
            "<sip:charlie@example.com?Replaces={}>",
            encoded
        );

        // Send REFER to Alice
        let mut refer = Request::new(
            Method::REFER,
            "sip:alice@example.com".parse()?
        );
        refer.headers_mut().set("Refer-To", &refer_to);

        // Alice will send INVITE to Charlie with Replaces header
    }
}

fn handle_invite_from_alice(request: &Request) {
    // Charlie receives INVITE with Replaces
    if let Some(replaces_str) = request.headers().get("Replaces") {
        let replaces = ReplacesHeader::parse(replaces_str)?;

        // Find Call B with Bob
        let dialog_b = find_dialog(
            replaces.call_id(),
            replaces.to_tag(),
            replaces.from_tag()
        )?;

        // Send BYE to Bob on Call B
        dialog_b.send_bye();

        // Accept INVITE from Alice
        let response = Response::new(200, "OK");
        // Establish media with Alice
    }
}
```

### Call Pickup Implementation

```rust
use sip_core::{Request, ReplacesHeader};

struct CallPickupService {
    ringing_calls: HashMap<String, DialogInfo>,
}

impl CallPickupService {
    fn pickup_call(&self, target_extension: &str) -> Request {
        // Find the ringing call
        let dialog = self.ringing_calls.get(target_extension)?;

        // Create Replaces header with early-only
        let replaces = ReplacesHeader::new(
            &dialog.call_id,
            &dialog.local_tag,
            &dialog.remote_tag
        ).with_early_only(true);

        // Create INVITE to pick up the call
        let mut request = Request::new(
            Method::INVITE,
            dialog.target_uri.clone()
        );
        request.headers_mut().set("Replaces", &replaces.to_string());

        request
    }

    fn handle_pickup_invite(&mut self, request: &Request) -> Response {
        let replaces_str = request.headers().get("Replaces")?;
        let replaces = ReplacesHeader::parse(replaces_str)?;

        // Find the ringing call
        let dialog = match self.find_dialog_by_replaces(&replaces) {
            Some(d) => d,
            None => return Response::new(481, "Call/Transaction Does Not Exist"),
        };

        // Verify early-only constraint
        if replaces.is_early_only() && dialog.state != DialogState::Early {
            return Response::new(486, "Busy Here");
        }

        // Cancel the original ringing call
        dialog.send_cancel();

        // Accept the pickup INVITE
        Response::new(200, "OK")
    }
}
```

## File Locations

- **Implementation**: `/home/siphon/siphon-rs/crates/sip-core/src/replaces.rs`
- **Tests**: Included in the same file (14 unit tests)
- **Exports**: `/home/siphon/siphon-rs/crates/sip-core/src/lib.rs`

## Module Exports

The following type is exported from sip-core:

```rust
pub use replaces::ReplacesHeader;
```

## References

- [RFC 3891: The "Replaces" Header Field in SIP](https://www.rfc-editor.org/rfc/rfc3891.html)
- [RFC 3515: The Session Initiation Protocol (SIP) Refer Method](https://www.rfc-editor.org/rfc/rfc3515.html)
- [RFC 3892: The Session Initiation Protocol (SIP) Referred-By Mechanism](https://www.rfc-editor.org/rfc/rfc3892.html)
- [RFC 5359: Session Initiation Protocol Service Examples](https://www.rfc-editor.org/rfc/rfc5359.html)

## Future Enhancements

Potential improvements for future versions:

1. **Dialog Matching Helper**: Utility function to match Replaces against a dialog set
2. **URL Encoding**: Built-in URL encoding for use in Refer-To headers
3. **Validation**: Stricter validation of Call-ID and tag formats
4. **Authorization Framework**: Pluggable authorization policies
5. **Logging**: Structured logging for replacement operations
6. **Metrics**: Track replacement success/failure rates

## Compliance

This implementation complies with:
- RFC 3891 (Replaces Header Field)
- RFC 3261 (SIP base specification)

## Status

✅ **Implementation Complete**
- ReplacesHeader type implemented
- All required and optional parameters supported
- Parsing and formatting working
- All tests passing (14/14)
- Documentation complete
