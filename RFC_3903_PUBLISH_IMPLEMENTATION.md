# RFC 3903 PUBLISH Method Implementation

## Overview

This document describes the implementation of RFC 3903 ("Session Initiation Protocol (SIP) Extension for Event State Publication") in the sip-core crate.

## RFC Implemented

- **RFC 3903**: Session Initiation Protocol (SIP) Extension for Event State Publication

## Purpose

The PUBLISH method enables SIP user agents to publish event state information to an Event State Compositor (ESC). This is primarily used for:

1. **Presence Publication**: Users publish their availability status
2. **Event State Management**: Maintain soft-state information with defined lifetimes
3. **State Aggregation**: ESC aggregates state from multiple sources
4. **State Distribution**: ESC distributes aggregated state via NOTIFY to subscribers

## Key Concepts

### Roles

- **Event Publication Agent (EPA)**: The UAC that sends PUBLISH requests
- **Event State Compositor (ESC)**: The UAS that receives PUBLISH requests, maintains state, and distributes notifications

### Soft-State Model

Publications are temporary with defined lifetimes:
- Each publication has an expiration time
- Must be refreshed before expiration
- Automatically expires if not refreshed
- Can be explicitly removed

### Entity Tags

Publications are identified by entity-tags:
- **SIP-ETag**: Server-assigned identifier returned in responses
- **SIP-If-Match**: Client-provided identifier for operations on existing publications

### Four Operations

Based on presence of body and SIP-If-Match header:

| Body | SIP-If-Match | Expires | Operation |
|------|--------------|---------|-----------|
| Yes  | No           | > 0     | **Initial**: Create new publication |
| No   | Yes          | > 0     | **Refresh**: Extend lifetime |
| Yes  | Yes          | > 0     | **Modify**: Update content |
| No   | Yes          | = 0     | **Remove**: Delete publication |

## Implementation Structure

### `SipETagHeader`

Server-assigned entity tag identifying a publication:

```rust
pub struct SipETagHeader {
    pub value: SmolStr,
}
```

**Methods:**
- `new(value: &str)` - Creates a new SIP-ETag
- `parse(input: &str)` - Parses from a string
- `to_string()` - Formats as string

### `SipIfMatchHeader`

Client-provided entity tag for conditional operations:

```rust
pub struct SipIfMatchHeader {
    pub value: SmolStr,
}
```

**Methods:**
- `new(value: &str)` - Creates a new SIP-If-Match
- `parse(input: &str)` - Parses from a string
- `to_string()` - Formats as string

### `Method::Publish`

The PUBLISH method is defined in the `Method` enum:

```rust
pub enum Method {
    // ... other methods
    Publish,
}
```

## Usage Examples

### 1. Initial Publication

Client publishes presence for the first time.

**Request:**
```
PUBLISH sip:alice@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds7
To: Alice <sip:alice@example.com>
From: Alice <sip:alice@example.com>;tag=123
Call-ID: pub-123@client.example.com
CSeq: 1 PUBLISH
Event: presence
Expires: 3600
Content-Type: application/pidf+xml
Content-Length: [body size]

<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf"
          entity="sip:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@client.example.com</contact>
  </tuple>
</presence>
```

**Response:**
```
SIP/2.0 200 OK
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds7
To: Alice <sip:alice@example.com>;tag=xyz
From: Alice <sip:alice@example.com>;tag=123
Call-ID: pub-123@client.example.com
CSeq: 1 PUBLISH
SIP-ETag: dx200xyz
Expires: 1800
Content-Length: 0
```

**Rust Implementation:**
```rust
use sip_core::{Request, Method, EventHeader, PresenceDocument, SipETagHeader};

// Create PUBLISH request
let mut publish = Request::new(
    Method::Publish,
    "sip:alice@example.com".parse().unwrap()
);

// Set headers
publish.headers_mut().set("Event", "presence");
publish.headers_mut().set("Expires", "3600");
publish.headers_mut().set("Content-Type", "application/pidf+xml");

// Create presence document
let mut presence = PresenceDocument::new("sip:alice@example.com");
presence.add_tuple(
    Tuple::new("t1", BasicStatus::Open)
        .with_contact("sip:alice@client.example.com")
);

// Set body
publish.set_body(presence.to_xml().into_bytes());

// Send request
let response = send_request(publish).await;

// Extract SIP-ETag from response
if response.status_code() == 200 {
    let etag_value = response.headers().get("SIP-ETag").unwrap();
    let etag = SipETagHeader::parse(etag_value).unwrap();

    // Store entity-tag for future operations
    store_entity_tag("alice@example.com", etag);
}
```

### 2. Refresh Publication

Extend the lifetime of an existing publication without changing content.

**Request:**
```
PUBLISH sip:alice@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bKnashd89
To: Alice <sip:alice@example.com>
From: Alice <sip:alice@example.com>;tag=123
Call-ID: pub-123@client.example.com
CSeq: 2 PUBLISH
SIP-If-Match: dx200xyz
Expires: 3600
Content-Length: 0
```

**Response:**
```
SIP/2.0 200 OK
SIP-ETag: dx200xyz
Expires: 1800
```

**Rust Implementation:**
```rust
use sip_core::{Request, Method, SipIfMatchHeader};

// Retrieve stored entity-tag
let etag = retrieve_entity_tag("alice@example.com");

// Create refresh PUBLISH
let mut publish = Request::new(
    Method::Publish,
    "sip:alice@example.com".parse().unwrap()
);

// Add SIP-If-Match with previous entity-tag
let if_match = SipIfMatchHeader::new(&etag.value);
publish.headers_mut().set("SIP-If-Match", &if_match.to_string());
publish.headers_mut().set("Expires", "3600");

// No body for refresh
publish.set_body(vec![]);

// Send request
let response = send_request(publish).await;
```

### 3. Modify Publication

Update the content of an existing publication.

**Request:**
```
PUBLISH sip:alice@example.com SIP/2.0
SIP-If-Match: dx200xyz
Event: presence
Expires: 3600
Content-Type: application/pidf+xml

<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf"
          entity="sip:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>closed</basic>
    </status>
  </tuple>
</presence>
```

**Response:**
```
SIP/2.0 200 OK
SIP-ETag: kwj449x
Expires: 1800
```

**Rust Implementation:**
```rust
use sip_core::{Request, Method, SipIfMatchHeader, PresenceDocument, BasicStatus, Tuple};

// Retrieve stored entity-tag
let etag = retrieve_entity_tag("alice@example.com");

// Create modify PUBLISH
let mut publish = Request::new(
    Method::Publish,
    "sip:alice@example.com".parse().unwrap()
);

// Add SIP-If-Match
let if_match = SipIfMatchHeader::new(&etag.value);
publish.headers_mut().set("SIP-If-Match", &if_match.to_string());
publish.headers_mut().set("Event", "presence");
publish.headers_mut().set("Expires", "3600");
publish.headers_mut().set("Content-Type", "application/pidf+xml");

// Create updated presence (now closed/unavailable)
let mut presence = PresenceDocument::new("sip:alice@example.com");
presence.add_tuple(
    Tuple::new("t1", BasicStatus::Closed)
);

// Set body
publish.set_body(presence.to_xml().into_bytes());

// Send request
let response = send_request(publish).await;

// Update stored entity-tag with new value
if response.status_code() == 200 {
    let new_etag_value = response.headers().get("SIP-ETag").unwrap();
    let new_etag = SipETagHeader::parse(new_etag_value).unwrap();
    store_entity_tag("alice@example.com", new_etag);
}
```

### 4. Remove Publication

Explicitly delete a publication.

**Request:**
```
PUBLISH sip:alice@example.com SIP/2.0
SIP-If-Match: kwj449x
Expires: 0
Content-Length: 0
```

**Response:**
```
SIP/2.0 200 OK
SIP-ETag: kwj449x
Expires: 0
```

**Rust Implementation:**
```rust
use sip_core::{Request, Method, SipIfMatchHeader};

// Retrieve stored entity-tag
let etag = retrieve_entity_tag("alice@example.com");

// Create remove PUBLISH
let mut publish = Request::new(
    Method::Publish,
    "sip:alice@example.com".parse().unwrap()
);

// Add SIP-If-Match and set Expires to 0
let if_match = SipIfMatchHeader::new(&etag.value);
publish.headers_mut().set("SIP-If-Match", &if_match.to_string());
publish.headers_mut().set("Expires", "0");

// No body for removal
publish.set_body(vec![]);

// Send request
let response = send_request(publish).await;

// Remove stored entity-tag
if response.status_code() == 200 {
    remove_entity_tag("alice@example.com");
}
```

## Response Codes

### Success Responses

**200 OK**: Publication successful
- **Required headers**: SIP-ETag, Expires
- **SIP-ETag**: Entity-tag identifying this publication
- **Expires**: Actual expiration time granted by server (may differ from requested)

### Error Responses

**400 Bad Request**: Malformed request
- Missing required Event header
- Invalid message format

**404 Not Found**: Request-URI doesn't identify a valid publication target
- The presentity doesn't exist
- The ESC doesn't support this Request-URI

**412 Conditional Request Failed**: Entity-tag mismatch or expired
- SIP-If-Match doesn't match any current publication
- Referenced publication has expired
- Client should retry with initial publication

**423 Interval Too Brief**: Requested Expires value too small
- **Required header**: Min-Expires
- Client should retry with larger Expires value

**Example 412 Response:**
```
SIP/2.0 412 Conditional Request Failed
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bKnashd89
To: Alice <sip:alice@example.com>;tag=xyz
From: Alice <sip:alice@example.com>;tag=123
Call-ID: pub-123@client.example.com
CSeq: 3 PUBLISH
Content-Length: 0
```

**Example 423 Response:**
```
SIP/2.0 423 Interval Too Brief
Min-Expires: 1800
Content-Length: 0
```

## Server-Side Implementation

### Event State Compositor (ESC)

```rust
use sip_core::{Request, Response, Method, SipETagHeader, SipIfMatchHeader};
use std::collections::HashMap;

struct Publication {
    entity_tag: String,
    event_package: String,
    content_type: String,
    body: Vec<u8>,
    expires_at: Instant,
}

struct EventStateCompositor {
    publications: HashMap<String, Publication>,
    min_expires: u32,
    max_expires: u32,
}

impl EventStateCompositor {
    fn handle_publish(&mut self, request: &Request) -> Response {
        // Validate Event header
        let event = match request.headers().get("Event") {
            Some(e) => e,
            None => return Response::new(400, "Bad Request"),
        };

        // Get requested expires
        let requested_expires = request.headers()
            .get("Expires")
            .and_then(|e| e.parse::<u32>().ok())
            .unwrap_or(3600);

        // Check SIP-If-Match header
        let if_match = request.headers()
            .get("SIP-If-Match")
            .and_then(|v| SipIfMatchHeader::parse(v));

        // Determine operation
        let has_body = !request.body().is_empty();
        let expires_zero = requested_expires == 0;

        match (has_body, if_match.as_ref(), expires_zero) {
            // Initial publication
            (true, None, false) => self.handle_initial(request, event, requested_expires),

            // Refresh
            (false, Some(etag), false) => self.handle_refresh(request, etag, requested_expires),

            // Modify
            (true, Some(etag), false) => self.handle_modify(request, etag, requested_expires),

            // Remove
            (false, Some(etag), true) => self.handle_remove(request, etag),

            // Invalid combination
            _ => Response::new(400, "Bad Request"),
        }
    }

    fn handle_initial(&mut self, request: &Request, event: &str, expires: u32) -> Response {
        // Validate expires
        if expires < self.min_expires {
            let mut response = Response::new(423, "Interval Too Brief");
            response.headers_mut().set("Min-Expires", &self.min_expires.to_string());
            return response;
        }

        let actual_expires = expires.min(self.max_expires);

        // Generate entity-tag
        let entity_tag = generate_entity_tag();

        // Create publication
        let publication = Publication {
            entity_tag: entity_tag.clone(),
            event_package: event.to_string(),
            content_type: request.headers()
                .get("Content-Type")
                .unwrap_or("application/octet-stream")
                .to_string(),
            body: request.body().to_vec(),
            expires_at: Instant::now() + Duration::from_secs(actual_expires as u64),
        };

        // Store publication
        let presentity = extract_presentity(request.request_uri());
        self.publications.insert(presentity, publication);

        // Build response
        let mut response = Response::new(200, "OK");
        let etag = SipETagHeader::new(&entity_tag);
        response.headers_mut().set("SIP-ETag", &etag.to_string());
        response.headers_mut().set("Expires", &actual_expires.to_string());

        response
    }

    fn handle_refresh(&mut self, request: &Request, if_match: &SipIfMatchHeader, expires: u32) -> Response {
        let presentity = extract_presentity(request.request_uri());

        // Find publication
        let publication = match self.publications.get_mut(&presentity) {
            Some(pub_) if pub_.entity_tag == if_match.value.as_str() => pub_,
            _ => return Response::new(412, "Conditional Request Failed"),
        };

        // Update expiration
        let actual_expires = expires.min(self.max_expires);
        publication.expires_at = Instant::now() + Duration::from_secs(actual_expires as u64);

        // Build response
        let mut response = Response::new(200, "OK");
        let etag = SipETagHeader::new(&publication.entity_tag);
        response.headers_mut().set("SIP-ETag", &etag.to_string());
        response.headers_mut().set("Expires", &actual_expires.to_string());

        response
    }

    fn handle_modify(&mut self, request: &Request, if_match: &SipIfMatchHeader, expires: u32) -> Response {
        let presentity = extract_presentity(request.request_uri());

        // Find publication
        let publication = match self.publications.get_mut(&presentity) {
            Some(pub_) if pub_.entity_tag == if_match.value.as_str() => pub_,
            _ => return Response::new(412, "Conditional Request Failed"),
        };

        // Generate new entity-tag
        let new_entity_tag = generate_entity_tag();

        // Update publication
        publication.entity_tag = new_entity_tag.clone();
        publication.content_type = request.headers()
            .get("Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();
        publication.body = request.body().to_vec();

        let actual_expires = expires.min(self.max_expires);
        publication.expires_at = Instant::now() + Duration::from_secs(actual_expires as u64);

        // Build response
        let mut response = Response::new(200, "OK");
        let etag = SipETagHeader::new(&new_entity_tag);
        response.headers_mut().set("SIP-ETag", &etag.to_string());
        response.headers_mut().set("Expires", &actual_expires.to_string());

        response
    }

    fn handle_remove(&mut self, request: &Request, if_match: &SipIfMatchHeader) -> Response {
        let presentity = extract_presentity(request.request_uri());

        // Find and remove publication
        match self.publications.get(&presentity) {
            Some(pub_) if pub_.entity_tag == if_match.value.as_str() => {
                let entity_tag = pub_.entity_tag.clone();
                self.publications.remove(&presentity);

                let mut response = Response::new(200, "OK");
                let etag = SipETagHeader::new(&entity_tag);
                response.headers_mut().set("SIP-ETag", &etag.to_string());
                response.headers_mut().set("Expires", "0");
                response
            }
            _ => Response::new(412, "Conditional Request Failed"),
        }
    }
}

fn generate_entity_tag() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:x}", rng.gen::<u64>())
}

fn extract_presentity(uri: &Uri) -> String {
    uri.to_string()
}
```

## Integration with SIP Events (RFC 3265)

PUBLISH works with the SIP Events framework:

```rust
use sip_core::{EventHeader, SubscriptionState};

// When state changes via PUBLISH, notify subscribers
fn notify_subscribers(presentity: &str, publication: &Publication) {
    let subscribers = get_subscribers(presentity, &publication.event_package);

    for subscriber in subscribers {
        let mut notify = Request::new(
            Method::Notify,
            subscriber.contact.clone()
        );

        // Set Event header
        let event = EventHeader::new(&publication.event_package);
        notify.headers_mut().set("Event", &event.to_string());

        // Set Subscription-State
        notify.headers_mut().set("Subscription-State", "active");

        // Copy publication content
        notify.headers_mut().set("Content-Type", &publication.content_type);
        notify.set_body(publication.body.clone());

        send_request(notify);
    }
}
```

## Security Considerations

### Authentication

RFC 3903 requires authentication:

```rust
fn handle_publish(&self, request: &Request) -> Response {
    // Verify authentication
    if !is_authenticated(request) {
        return Response::new(401, "Unauthorized")
            .with_header("WWW-Authenticate", "Digest realm=\"example.com\"");
    }

    // Verify authorization
    let presentity = extract_presentity(request.request_uri());
    let from_uri = request.from_uri();

    if !is_authorized(from_uri, &presentity) {
        return Response::new(403, "Forbidden");
    }

    // Process PUBLISH
    self.process_publish(request)
}
```

### Privacy

Protect sensitive information:

```rust
// Use TLS for transport
let sips_uri = "sips:alice@example.com".parse().unwrap();

// Avoid logging sensitive headers
fn log_request(request: &Request) {
    let sanitized = sanitize_headers(request.headers());
    log::info!("PUBLISH from {} to {}",
        request.from_uri(),
        request.request_uri());
}
```

### Replay Attack Prevention

Use proper timestamps and nonces:

```rust
// Include timestamp in published state
let presence = PresenceDocument::new("sip:alice@example.com")
    .with_tuple(
        Tuple::new("t1", BasicStatus::Open)
            .with_timestamp(&Utc::now().to_rfc3339())
    );
```

## Testing

The implementation includes 13 comprehensive tests covering:

1. **SIP-ETag Tests**
   - Basic creation
   - Formatting
   - Parsing
   - Whitespace handling
   - Empty string handling
   - Round-trip conversion

2. **SIP-If-Match Tests**
   - Basic creation
   - Formatting
   - Parsing
   - Whitespace handling
   - Empty string handling
   - Round-trip conversion

3. **Integration Test**
   - Matching SIP-ETag and SIP-If-Match values

### Running Tests

```bash
cargo test --package sip-core sip_etag
```

All 13 tests pass successfully.

## Complete Example: Presence Publication Flow

```rust
use sip_core::{Request, Response, Method, EventHeader, PresenceDocument, BasicStatus, Tuple};
use sip_core::{SipETagHeader, SipIfMatchHeader};

struct PresenceAgent {
    entity_tag: Option<SipETagHeader>,
}

impl PresenceAgent {
    async fn publish_presence(&mut self, status: BasicStatus) {
        match &self.entity_tag {
            None => self.initial_publish(status).await,
            Some(_) => self.modify_publish(status).await,
        }
    }

    async fn initial_publish(&mut self, status: BasicStatus) {
        // Create presence document
        let mut presence = PresenceDocument::new("sip:alice@example.com");
        presence.add_tuple(
            Tuple::new("device1", status)
                .with_contact("sip:alice@192.168.1.100:5060")
        );

        // Create PUBLISH request
        let mut publish = Request::new(
            Method::Publish,
            "sip:alice@example.com".parse().unwrap()
        );

        publish.headers_mut().set("Event", "presence");
        publish.headers_mut().set("Expires", "3600");
        publish.headers_mut().set("Content-Type", "application/pidf+xml");
        publish.set_body(presence.to_xml().into_bytes());

        // Send and handle response
        let response = send_request(publish).await;

        if response.status_code() == 200 {
            let etag_value = response.headers().get("SIP-ETag").unwrap();
            self.entity_tag = SipETagHeader::parse(etag_value);
            println!("Initial publish successful, ETag: {}", etag_value);
        }
    }

    async fn modify_publish(&mut self, status: BasicStatus) {
        let etag = self.entity_tag.as_ref().unwrap();

        // Create updated presence
        let mut presence = PresenceDocument::new("sip:alice@example.com");
        presence.add_tuple(
            Tuple::new("device1", status)
                .with_contact("sip:alice@192.168.1.100:5060")
        );

        // Create PUBLISH request
        let mut publish = Request::new(
            Method::Publish,
            "sip:alice@example.com".parse().unwrap()
        );

        let if_match = SipIfMatchHeader::new(&etag.value);
        publish.headers_mut().set("SIP-If-Match", &if_match.to_string());
        publish.headers_mut().set("Event", "presence");
        publish.headers_mut().set("Expires", "3600");
        publish.headers_mut().set("Content-Type", "application/pidf+xml");
        publish.set_body(presence.to_xml().into_bytes());

        // Send and handle response
        let response = send_request(publish).await;

        match response.status_code() {
            200 => {
                let etag_value = response.headers().get("SIP-ETag").unwrap();
                self.entity_tag = SipETagHeader::parse(etag_value);
                println!("Modify publish successful, new ETag: {}", etag_value);
            }
            412 => {
                println!("Publication expired or invalid, doing initial publish");
                self.entity_tag = None;
                self.initial_publish(status).await;
            }
            _ => {
                println!("Publish failed: {}", response.status_code());
            }
        }
    }

    async fn refresh_publish(&mut self) {
        if let Some(etag) = &self.entity_tag {
            let mut publish = Request::new(
                Method::Publish,
                "sip:alice@example.com".parse().unwrap()
            );

            let if_match = SipIfMatchHeader::new(&etag.value);
            publish.headers_mut().set("SIP-If-Match", &if_match.to_string());
            publish.headers_mut().set("Expires", "3600");
            publish.set_body(vec![]);

            let response = send_request(publish).await;

            if response.status_code() == 200 {
                println!("Refresh successful");
            } else if response.status_code() == 412 {
                println!("Publication expired, need to re-publish");
                self.entity_tag = None;
            }
        }
    }

    async fn remove_publish(&mut self) {
        if let Some(etag) = &self.entity_tag {
            let mut publish = Request::new(
                Method::Publish,
                "sip:alice@example.com".parse().unwrap()
            );

            let if_match = SipIfMatchHeader::new(&etag.value);
            publish.headers_mut().set("SIP-If-Match", &if_match.to_string());
            publish.headers_mut().set("Expires", "0");
            publish.set_body(vec![]);

            let response = send_request(publish).await;

            if response.status_code() == 200 {
                println!("Publication removed");
                self.entity_tag = None;
            }
        }
    }
}

// Usage
#[tokio::main]
async fn main() {
    let mut agent = PresenceAgent {
        entity_tag: None,
    };

    // Publish available
    agent.publish_presence(BasicStatus::Open).await;

    // Change to busy
    agent.publish_presence(BasicStatus::Closed).await;

    // Refresh periodically
    tokio::time::sleep(Duration::from_secs(1800)).await;
    agent.refresh_publish().await;

    // Remove when shutting down
    agent.remove_publish().await;
}
```

## File Locations

- **Implementation**: `/home/siphon/siphon-rs/crates/sip-core/src/sip_etag.rs`
- **Method**: `/home/siphon/siphon-rs/crates/sip-core/src/method.rs` (Method::Publish)
- **Tests**: Included in sip_etag.rs (13 unit tests)
- **Exports**: `/home/siphon/siphon-rs/crates/sip-core/src/lib.rs`

## Module Exports

The following types are exported from sip-core:

```rust
pub use sip_etag::{SipETagHeader, SipIfMatchHeader};
pub use method::Method; // includes Method::Publish
```

## References

- [RFC 3903: Session Initiation Protocol (SIP) Extension for Event State Publication](https://www.rfc-editor.org/rfc/rfc3903.html)
- [RFC 3265: Session Initiation Protocol (SIP)-Specific Event Notification](https://www.rfc-editor.org/rfc/rfc3265.html)
- [RFC 3856: A Presence Event Package for the Session Initiation Protocol (SIP)](https://www.rfc-editor.org/rfc/rfc3856.html)
- [RFC 3863: Presence Information Data Format (PIDF)](https://www.rfc-editor.org/rfc/rfc3863.html)

## Compliance

This implementation complies with:
- RFC 3903 (PUBLISH Method)
- RFC 3261 (SIP base specification)
- Entity-tag format requirements

## Status

✅ **Implementation Complete**
- SipETagHeader implemented with parsing and formatting
- SipIfMatchHeader implemented with parsing and formatting
- Method::Publish already defined
- All tests passing (13/13)
- Documentation complete
