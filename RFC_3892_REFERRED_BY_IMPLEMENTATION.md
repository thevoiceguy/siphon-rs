# RFC 3892 Referred-By Header Implementation

## Overview

This document describes the implementation of RFC 3892 ("The Session Initiation Protocol (SIP) Referred-By Mechanism") in the sip-core crate.

## RFC Implemented

- **RFC 3892**: The Session Initiation Protocol (SIP) Referred-By Mechanism

## Purpose

The Referred-By header provides authenticated identity information about the party that initiated a call transfer or referral. It enables:

1. **Identity Verification**: Know who initiated the transfer
2. **Authorization Decisions**: Make policy decisions based on referrer identity
3. **Authenticated Transfers**: Cryptographically verify referrer identity with S/MIME
4. **Non-Repudiation**: Prevent referrers from denying they initiated transfers
5. **User Experience**: Display who transferred the call to the recipient

## Key Concepts

### Referral Flow

The Referred-By header appears in two places during a referral:

1. **REFER Request**: The referrer (e.g., Bob) sends a REFER to the referee (e.g., Alice)
   - Includes: `Referred-By: <sip:bob@example.com>`

2. **Triggered INVITE**: The referee (Alice) sends INVITE to the refer target (Charlie)
   - Copies the Referred-By header unchanged
   - Charlie sees: `Referred-By: <sip:bob@example.com>`

### Roles

- **Referrer**: The party initiating the transfer (Bob)
- **Referee**: The party being asked to make a new request (Alice)
- **Refer Target**: The party receiving the triggered request (Charlie)

### Authentication with S/MIME

When the `cid` parameter is present, it references a MIME body part containing an Authenticated Identity Body (AIB):

- **AIB**: S/MIME signed message fragment
- **Contains**: Date, Refer-To, Referred-By headers (timestamp prevents replay)
- **Protects**: Integrity and authenticity of the referral

## Header Format

### Syntax

```
Referred-By: name-addr [;cid="content-id"] [;param=value]*
```

**Name-Addr Formats:**
```
<sip:uri>
"Display Name" <sip:uri>
```

### Components

- **URI** (required): The referrer's SIP address-of-record
- **cid parameter** (optional): Content-ID referencing S/MIME signature
- **Additional parameters** (optional): Extension parameters

### Examples

**Basic:**
```
Referred-By: <sip:bob@example.com>
```

**With Display Name:**
```
Referred-By: "Bob Smith" <sip:bob@example.com>
```

**With Signature:**
```
Referred-By: <sip:bob@example.com>;cid="signature123@example.com"
```

**With All Features:**
```
Referred-By: "Bob Smith" <sip:bob@example.com>;cid="sig123@example.com";tag=abc
```

### Compact Form

The compact form is `b`:
```
b: <sip:bob@example.com>
```

## Implementation Structure

### `ReferredByHeader`

The main structure representing a Referred-By header:

```rust
pub struct ReferredByHeader {
    pub name_addr: NameAddr,
    pub cid: Option<SmolStr>,
    pub params: BTreeMap<SmolStr, SmolStr>,
}
```

**Fields:**
- `name_addr`: The referrer's address (display name + URI)
- `cid`: Optional Content-ID referencing an S/MIME signature
- `params`: Additional extension parameters

**Methods:**
- `new(uri: &str)` - Creates a new header with URI only
- `with_name(display_name: &str, uri: &str)` - Creates with display name
- `with_cid(cid: &str)` - Sets the Content-ID parameter
- `with_param(name: &str, value: &str)` - Adds a parameter
- `has_signature()` - Returns true if cid parameter is present
- `get_cid()` - Gets the Content-ID value
- `get_param(name: &str)` - Gets a parameter value
- `parse(input: &str)` - Parses from a string

## Usage Examples

### Creating Referred-By Headers

```rust
use sip_core::ReferredByHeader;

// Basic header with URI only
let referred_by = ReferredByHeader::new("sip:bob@example.com");

println!("{}", referred_by);
// Output: <sip:bob@example.com>
```

### With Display Name

```rust
use sip_core::ReferredByHeader;

let referred_by = ReferredByHeader::with_name(
    "Bob Smith",
    "sip:bob@example.com"
);

println!("{}", referred_by);
// Output: "Bob Smith" <sip:bob@example.com>
```

### With S/MIME Signature Reference

```rust
use sip_core::ReferredByHeader;

let referred_by = ReferredByHeader::new("sip:bob@example.com")
    .with_cid("signature123@example.com");

assert!(referred_by.has_signature());
assert_eq!(referred_by.get_cid(), Some("signature123@example.com"));

println!("{}", referred_by);
// Output: <sip:bob@example.com>;cid="signature123@example.com"
```

### With Custom Parameters

```rust
use sip_core::ReferredByHeader;

let referred_by = ReferredByHeader::new("sip:bob@example.com")
    .with_param("tag", "abc123")
    .with_param("custom", "value");

assert_eq!(referred_by.get_param("tag"), Some("abc123"));
assert_eq!(referred_by.get_param("custom"), Some("value"));
```

### Parsing Referred-By Headers

```rust
use sip_core::ReferredByHeader;

// Parse basic header
let header = ReferredByHeader::parse(
    "<sip:bob@example.com>"
).unwrap();

// Parse with display name
let header = ReferredByHeader::parse(
    r#""Bob Smith" <sip:bob@example.com>"#
).unwrap();

assert_eq!(header.name_addr.display_name.as_deref(), Some("Bob Smith"));

// Parse with signature
let header = ReferredByHeader::parse(
    r#"<sip:bob@example.com>;cid="sig123@example.com""#
).unwrap();

assert_eq!(header.get_cid(), Some("sig123@example.com"));
```

## Use Cases

### 1. Basic Call Transfer

The most common use case: Bob transfers Alice to Charlie.

**Scenario:**
1. Alice calls Bob
2. Bob decides to transfer Alice to Charlie
3. Bob sends REFER to Alice with `Refer-To: <sip:charlie@example.com>`
4. Bob includes `Referred-By: <sip:bob@example.com>`
5. Alice sends INVITE to Charlie with the Referred-By header
6. Charlie sees that Bob initiated the transfer

**REFER from Bob to Alice:**
```
REFER sip:alice@example.com SIP/2.0
From: Bob <sip:bob@example.com>;tag=1234
To: Alice <sip:alice@example.com>;tag=5678
Refer-To: <sip:charlie@example.com>
Referred-By: <sip:bob@example.com>
```

**INVITE from Alice to Charlie:**
```
INVITE sip:charlie@example.com SIP/2.0
From: Alice <sip:alice@example.com>;tag=9999
To: Charlie <sip:charlie@example.com>
Referred-By: <sip:bob@example.com>
```

**Rust Implementation:**
```rust
use sip_core::{Request, Method, ReferredByHeader};

// Bob sends REFER to Alice
let mut refer = Request::new(
    Method::REFER,
    "sip:alice@example.com".parse().unwrap()
);

let referred_by = ReferredByHeader::new("sip:bob@example.com");
refer.headers_mut().set("Referred-By", &referred_by.to_string());
refer.headers_mut().set("Refer-To", "<sip:charlie@example.com>");

// Alice receives REFER and extracts Referred-By
let referred_by_value = refer.headers().get("Referred-By").unwrap();
let referred_by = ReferredByHeader::parse(referred_by_value).unwrap();

// Alice creates INVITE to Charlie with same Referred-By
let mut invite = Request::new(
    Method::INVITE,
    "sip:charlie@example.com".parse().unwrap()
);
invite.headers_mut().set("Referred-By", &referred_by.to_string());
```

### 2. Authenticated Transfer with S/MIME

Using cryptographic signatures to verify referrer identity.

**Scenario:**
1. Bob sends REFER with S/MIME signed AIB
2. REFER includes multipart body with signature
3. Alice copies both header and body to INVITE
4. Charlie verifies Bob's signature

**REFER with S/MIME:**
```
REFER sip:alice@example.com SIP/2.0
From: Bob <sip:bob@example.com>;tag=1234
To: Alice <sip:alice@example.com>;tag=5678
Referred-By: <sip:bob@example.com>;cid="aib123@example.com"
Content-Type: multipart/signed; boundary="boundary123"

--boundary123
Content-Type: message/sipfrag
Content-ID: <aib123@example.com>

Date: Mon, 15 Jan 2024 10:30:00 GMT
Refer-To: <sip:charlie@example.com>
Referred-By: <sip:bob@example.com>

--boundary123
Content-Type: application/pkcs7-signature

[S/MIME signature data]
--boundary123--
```

**Rust Implementation:**
```rust
use sip_core::ReferredByHeader;

// Create Referred-By with signature reference
let referred_by = ReferredByHeader::new("sip:bob@example.com")
    .with_cid("aib123@example.com");

// Add to REFER
refer.headers_mut().set("Referred-By", &referred_by.to_string());
refer.headers_mut().set(
    "Content-Type",
    "multipart/signed; boundary=\"boundary123\""
);

// Set multipart body with AIB and signature
// ... add multipart body parts ...

// On receiving side, verify signature
if referred_by.has_signature() {
    let cid = referred_by.get_cid().unwrap();
    // Extract MIME part with matching Content-ID
    // Verify S/MIME signature
    // If valid, trust the referrer identity
}
```

### 3. Authorization Based on Referrer

Make policy decisions based on who initiated the transfer.

**Scenario:**
- Charlie's phone has a whitelist of trusted referrers
- Only accepts transfers from known users
- Rejects transfers from unknown sources

**Rust Implementation:**
```rust
use sip_core::ReferredByHeader;

struct TransferPolicy {
    trusted_referrers: Vec<String>,
}

impl TransferPolicy {
    fn should_accept_transfer(&self, invite: &Request) -> bool {
        // Extract Referred-By header
        let referred_by_value = match invite.headers().get("Referred-By") {
            Some(val) => val,
            None => {
                // No Referred-By header - reject for security
                return false;
            }
        };

        let referred_by = match ReferredByHeader::parse(referred_by_value) {
            Some(rb) => rb,
            None => return false,
        };

        // Check if referrer is trusted
        let referrer_uri = referred_by.name_addr.uri.raw.to_string();
        self.trusted_referrers.contains(&referrer_uri)
    }
}

// Usage
let policy = TransferPolicy {
    trusted_referrers: vec![
        "sip:bob@example.com".to_string(),
        "sip:admin@example.com".to_string(),
    ],
};

if policy.should_accept_transfer(&invite) {
    // Accept the transfer
    let response = Response::new(200, "OK");
} else {
    // Reject the transfer
    let response = Response::new(403, "Forbidden");
}
```

### 4. Call Center Transfer Tracking

Track which agent transferred a call for audit and quality purposes.

**Scenario:**
- Call center with multiple agents
- Track transfer chains for quality assurance
- Log who transferred calls to whom

**Rust Implementation:**
```rust
use sip_core::ReferredByHeader;

struct TransferLog {
    timestamp: String,
    referrer: String,
    referee: String,
    target: String,
}

fn log_transfer(invite: &Request) -> Option<TransferLog> {
    let referred_by_value = invite.headers().get("Referred-By")?;
    let referred_by = ReferredByHeader::parse(referred_by_value)?;

    let referrer = if let Some(ref name) = referred_by.name_addr.display_name {
        format!("{} <{}>", name, referred_by.name_addr.uri.raw)
    } else {
        referred_by.name_addr.uri.raw.to_string()
    };

    Some(TransferLog {
        timestamp: chrono::Utc::now().to_rfc3339(),
        referrer,
        referee: invite.from_uri().to_string(),
        target: invite.to_uri().to_string(),
    })
}

// Usage
if let Some(log) = log_transfer(&invite) {
    println!("Transfer: {} transferred call from {} to {}",
        log.referrer, log.referee, log.target);

    // Store in database for reporting
    store_transfer_log(log);
}
```

### 5. Error Handling: Missing Referred-By

Handle cases where Referred-By is required but missing.

**Scenario:**
- Server requires authenticated referrals
- Client sends INVITE without Referred-By
- Server responds with 429 "Provide Referrer Identity"

**Rust Implementation:**
```rust
use sip_core::{Request, Response, ReferredByHeader};

fn handle_invite(invite: &Request) -> Response {
    // Check if this is a referred request (has Replaces header)
    if invite.headers().get("Replaces").is_some() {
        // This is a transfer - Referred-By should be present
        match invite.headers().get("Referred-By") {
            None => {
                // Missing Referred-By - ask client to provide it
                let mut response = Response::new(
                    429,
                    "Provide Referrer Identity"
                );
                response.headers_mut().set(
                    "Warning",
                    "399 example.com \"Referred-By header required for transfers\""
                );
                return response;
            }
            Some(value) => {
                // Parse and validate
                let referred_by = match ReferredByHeader::parse(value) {
                    Some(rb) => rb,
                    None => {
                        return Response::new(400, "Bad Request");
                    }
                };

                // Check if signature is required
                if !referred_by.has_signature() && requires_signature() {
                    return Response::new(
                        428,
                        "Use Identity Header"
                    );
                }

                // Validate signature if present
                if referred_by.has_signature() {
                    if !verify_signature(&referred_by, invite) {
                        return Response::new(403, "Forbidden");
                    }
                }
            }
        }
    }

    // Accept the INVITE
    Response::new(200, "OK")
}
```

## Integration with Other RFCs

### RFC 3515: REFER Method

The Referred-By header is typically used with REFER requests:

```rust
use sip_core::{Request, Method, ReferredByHeader};

// Create REFER request
let mut refer = Request::new(
    Method::REFER,
    "sip:alice@example.com".parse().unwrap()
);

// Add Refer-To and Referred-By
refer.headers_mut().set("Refer-To", "<sip:charlie@example.com>");

let referred_by = ReferredByHeader::with_name(
    "Bob Smith",
    "sip:bob@example.com"
);
refer.headers_mut().set("Referred-By", &referred_by.to_string());
```

### RFC 3891: Replaces Header

Referred-By and Replaces work together in attended transfers:

```rust
use sip_core::{ReferredByHeader, ReplacesHeader};

// Bob sends REFER to Alice with Replaces in Refer-To
let replaces = ReplacesHeader::new(
    "call-b@example.com",
    "charlie-tag",
    "bob-tag"
);

let replaces_encoded = urlencoding::encode(&replaces.to_string());
let refer_to = format!("<sip:charlie@example.com?Replaces={}>", replaces_encoded);

refer.headers_mut().set("Refer-To", &refer_to);

// Add Referred-By so Charlie knows Bob initiated this
let referred_by = ReferredByHeader::new("sip:bob@example.com");
refer.headers_mut().set("Referred-By", &referred_by.to_string());

// Alice sends INVITE to Charlie with both headers
invite.headers_mut().set("Replaces", &replaces.to_string());
invite.headers_mut().set("Referred-By", &referred_by.to_string());
```

### S/MIME (RFC 5750)

For authenticated transfers using Authenticated Identity Body (AIB):

```rust
use sip_core::ReferredByHeader;

// Create Referred-By with signature reference
let referred_by = ReferredByHeader::new("sip:bob@example.com")
    .with_cid("aib-signature@example.com");

// The AIB contains signed headers
let aib_content = r#"Date: Mon, 15 Jan 2024 10:30:00 GMT
Refer-To: <sip:charlie@example.com>
Referred-By: <sip:bob@example.com>"#;

// Sign the AIB with S/MIME
// let signed_aib = sign_with_smime(aib_content, bob_certificate);

// Create multipart body
request.headers_mut().set(
    "Content-Type",
    "multipart/signed; protocol=\"application/pkcs7-signature\""
);

// Add body parts:
// 1. message/sipfrag with Content-ID matching cid parameter
// 2. application/pkcs7-signature with the signature
```

## Security Considerations

### Authentication Requirements

RFC 3892 requires authentication of the referrer:

1. **SIP Digest Authentication**: Verify REFER sender identity
2. **S/MIME Signatures**: Cryptographic proof via AIB
3. **TLS/SIPS**: Protect headers in transit

**Example:**
```rust
fn verify_referrer(refer: &Request, referred_by: &ReferredByHeader) -> bool {
    // Check SIP authentication
    if !is_authenticated(refer) {
        return false;
    }

    // Verify From header matches Referred-By
    let from_uri = refer.from_uri();
    if from_uri.to_string() != referred_by.name_addr.uri.raw.to_string() {
        return false;
    }

    // If signature present, verify it
    if referred_by.has_signature() {
        return verify_aib_signature(refer, referred_by);
    }

    true
}
```

### Authorization Policies

Implement policies to control who can transfer calls:

```rust
enum TransferPolicy {
    AllowAll,
    WhitelistOnly(Vec<String>),
    SamedomainOnly,
    RequireSignature,
}

impl TransferPolicy {
    fn allows(&self, referred_by: &ReferredByHeader, target_domain: &str) -> bool {
        match self {
            Self::AllowAll => true,

            Self::WhitelistOnly(list) => {
                list.contains(&referred_by.name_addr.uri.raw.to_string())
            }

            Self::SameDomainOnly => {
                let referrer_domain = referred_by.name_addr.uri.host.as_str();
                referrer_domain == target_domain
            }

            Self::RequireSignature => {
                referred_by.has_signature()
            }
        }
    }
}
```

### Privacy Protection

Protect referrer identity information:

1. **Encryption**: Use TLS/SIPS for transport
2. **Logging**: Avoid logging Referred-By headers in plaintext
3. **Disclosure**: Only send to trusted parties
4. **User Consent**: Inform users their identity will be disclosed

### Replay Attack Prevention

The timestamp in the AIB prevents replay attacks:

```rust
fn verify_aib_timestamp(aib_date: &str) -> bool {
    use chrono::{DateTime, Utc, Duration};

    let aib_time = DateTime::parse_from_rfc2822(aib_date).ok()?;
    let now = Utc::now();
    let age = now.signed_duration_since(aib_time.with_timezone(&Utc));

    // Reject if older than 5 minutes
    age < Duration::minutes(5)
}
```

## Testing

The implementation includes 17 comprehensive tests covering:

1. **Header Creation**
   - Basic header with URI only
   - With display name
   - With CID parameter
   - With custom parameters

2. **Formatting**
   - Basic format
   - With display name
   - With CID
   - With all features

3. **Parsing**
   - Basic header
   - With display name
   - With CID parameter
   - With all features
   - Case-insensitive parameters
   - Whitespace tolerance
   - Empty string handling

4. **Round-Trip**
   - Format → Parse → Format consistency
   - With and without CID
   - With and without display name

### Running Tests

```bash
cargo test --package sip-core referred_by
```

All 17 tests pass successfully.

## Complete Example: Attended Transfer

Here's a complete example of an attended transfer using Referred-By:

```rust
use sip_core::{Request, Response, Method, ReferredByHeader, ReplacesHeader};

// Step 1: Alice calls Bob (Call A)
// ... call established ...

// Step 2: Bob calls Charlie (Call B - consultation call)
let call_b_dialog = establish_call_to_charlie();

// Step 3: Bob sends REFER to Alice
let mut refer = Request::new(
    Method::REFER,
    alice_uri.clone()
);

// Create Replaces header for Call B
let replaces = ReplacesHeader::new(
    &call_b_dialog.call_id,
    &call_b_dialog.remote_tag,  // Charlie's tag
    &call_b_dialog.local_tag,   // Bob's tag
);

// Encode Replaces for Refer-To URI
let replaces_encoded = urlencoding::encode(&replaces.to_string());
let refer_to = format!(
    "<sip:charlie@example.com?Replaces={}>",
    replaces_encoded
);

refer.headers_mut().set("Refer-To", &refer_to);

// Add Referred-By
let referred_by = ReferredByHeader::with_name(
    "Bob Smith",
    "sip:bob@example.com"
);
refer.headers_mut().set("Referred-By", &referred_by.to_string());

// Send REFER to Alice
send_request(refer);

// Step 4: Alice receives REFER
fn handle_refer(refer: &Request) -> Response {
    // Extract headers
    let refer_to = refer.headers().get("Refer-To").unwrap();
    let referred_by_value = refer.headers().get("Referred-By").unwrap();

    let referred_by = ReferredByHeader::parse(referred_by_value).unwrap();

    // Parse Refer-To to extract target and Replaces
    // ... parse URI and Replaces parameter ...

    // Accept the REFER
    let response = Response::new(202, "Accepted");

    // Send NOTIFY about progress
    send_notify("SIP/2.0 100 Trying");

    // Step 5: Alice sends INVITE to Charlie
    let mut invite = Request::new(
        Method::INVITE,
        charlie_uri
    );

    // Copy Referred-By unchanged
    invite.headers_mut().set("Referred-By", referred_by_value);

    // Add Replaces from Refer-To
    invite.headers_mut().set("Replaces", &replaces.to_string());

    // Send INVITE
    send_request(invite);

    response
}

// Step 6: Charlie receives INVITE
fn handle_invite_with_replaces(invite: &Request) -> Response {
    // Extract Referred-By
    let referred_by_value = invite.headers().get("Referred-By").unwrap();
    let referred_by = ReferredByHeader::parse(referred_by_value).unwrap();

    println!("Call transferred by: {}",
        referred_by.name_addr.display_name
            .as_deref()
            .unwrap_or("Unknown"));

    // Extract and process Replaces
    let replaces_value = invite.headers().get("Replaces").unwrap();
    let replaces = ReplacesHeader::parse(replaces_value).unwrap();

    // Find Call B with Bob
    let call_b = find_dialog(&replaces.call_id, &replaces.to_tag, &replaces.from_tag);

    // Terminate Call B
    call_b.send_bye();

    // Accept new call with Alice
    Response::new(200, "OK")
}

// Step 7: Bob hangs up both calls (already done via BYE in step 6)
// Result: Alice and Charlie are connected
```

## File Locations

- **Implementation**: `/home/siphon/siphon-rs/crates/sip-core/src/referred_by.rs`
- **Tests**: Included in the same file (17 unit tests)
- **Exports**: `/home/siphon/siphon-rs/crates/sip-core/src/lib.rs`

## Module Exports

The following type is exported from sip-core:

```rust
pub use referred_by::ReferredByHeader;
```

## References

- [RFC 3892: The SIP Referred-By Mechanism](https://www.rfc-editor.org/rfc/rfc3892.html)
- [RFC 3515: The Session Initiation Protocol (SIP) Refer Method](https://www.rfc-editor.org/rfc/rfc3515.html)
- [RFC 3891: The "Replaces" Header Field in SIP](https://www.rfc-editor.org/rfc/rfc3891.html)
- [RFC 5750: Secure/Multipurpose Internet Mail Extensions (S/MIME) for SIP](https://www.rfc-editor.org/rfc/rfc5750.html)

## Compliance

This implementation complies with:
- RFC 3892 (Referred-By Mechanism)
- RFC 3261 (SIP base specification)
- Name-addr format from RFC 3261

## Status

✅ **Implementation Complete**
- ReferredByHeader type implemented
- All required and optional parameters supported
- Name-addr parsing and formatting working
- S/MIME CID parameter support
- All tests passing (17/17)
- Documentation complete
