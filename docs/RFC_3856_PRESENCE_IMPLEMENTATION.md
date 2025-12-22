# RFC 3856/3859/3863: Presence Implementation

## Overview

This document describes the implementation of SIP presence support in the siphon-rs codebase, covering:
- **RFC 3856**: Presence Event Package for SIP
- **RFC 3859**: Common Profile for Presence (CPP)
- **RFC 3863**: Presence Information Data Format (PIDF)

Presence represents the willingness and ability of a user to communicate with other users on the network, going beyond simple online/offline indicators to provide rich status information.

## RFC Summary

### RFC 3856 - Presence Event Package

**Event Package**: "presence"
**MIME Type**: application/pidf+xml
**Default Subscription Duration**: 3600 seconds (1 hour)

Defines how SIP is used for presence subscriptions and notifications. Uses SIP's SUBSCRIBE/NOTIFY mechanism to convey presence information.

### RFC 3859 - Common Profile for Presence (CPP)

Defines common semantics and operations for presence protocols to enable interoperability between different presence systems through gateways. Establishes standard terminology:
- **Presentity**: Entity whose presence is reported
- **Watcher**: Entity requesting presence updates
- **PRES URI**: Identifier format (e.g., "pres:alice@example.com")

### RFC 3863 - Presence Information Data Format (PIDF)

Defines the XML-based format for conveying presence information. Key structures:
- **Presence Document**: Root element containing entity and tuples
- **Tuple**: Represents a communication endpoint with status
- **Basic Status**: "open" or "closed"
- **Optional Elements**: contact, note, timestamp

## Implementation Location

The presence implementation is located in:
- **Module**: `crates/sip-core/src/presence.rs`
- **Exports**: Through `crates/sip-core/src/lib.rs`

## API Reference

### Types

#### `PresenceDocument`

RFC 3863 PIDF Presence Document representing complete presence information for a presentity.

**Fields:**
- `entity: SmolStr` - The entity URI (presentity)
- `tuples: Vec<Tuple>` - List of presence tuples
- `notes: Vec<SmolStr>` - Optional notes about the presentity

**Methods:**

##### `new(entity: impl Into<SmolStr>) -> Self`

Creates a new presence document for the given entity.

**Example:**
```rust
use sip_core::PresenceDocument;

let doc = PresenceDocument::new("pres:alice@example.com");
```

---

##### `add_tuple(&mut self, tuple: Tuple)`

Adds a tuple to the presence document.

**Example:**
```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com");

let tuple = Tuple::new("t1")
    .with_status(BasicStatus::Open)
    .with_contact("sip:alice@192.168.1.100");

doc.add_tuple(tuple);
```

---

##### `add_note(&mut self, note: impl Into<SmolStr>)`

Adds a note to the presence document.

---

##### `is_empty(&self) -> bool`

Returns true if there are no tuples.

---

##### `basic_status(&self) -> Option<BasicStatus>`

Returns the basic status from the first tuple, if any.

**Example:**
```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com");
doc.add_tuple(Tuple::new("t1").with_status(BasicStatus::Open));

assert_eq!(doc.basic_status(), Some(BasicStatus::Open));
```

---

##### `to_xml(&self) -> String`

Formats the presence document as application/pidf+xml.

**Example:**
```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com");
doc.add_tuple(
    Tuple::new("t1")
        .with_status(BasicStatus::Open)
        .with_contact("sip:alice@192.168.1.100")
        .with_note("Available")
);

let xml = doc.to_xml();
// <?xml version="1.0" encoding="UTF-8"?>
// <presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
//   <tuple id="t1">
//     <status>
//       <basic>open</basic>
//     </status>
//     <contact>sip:alice@192.168.1.100</contact>
//     <note>Available</note>
//   </tuple>
// </presence>
```

---

#### `Tuple`

RFC 3863 Presence Tuple representing a single communication endpoint or aspect of presence.

**Fields:**
- `id: SmolStr` - Tuple identifier (must be unique within document)
- `status: Option<BasicStatus>` - Basic status (open or closed)
- `contact: Option<SmolStr>` - Contact URI for this tuple
- `notes: Vec<SmolStr>` - Optional notes about this tuple
- `timestamp: Option<SmolStr>` - Optional timestamp

**Methods:**

##### `new(id: impl Into<SmolStr>) -> Self`

Creates a new tuple with the given ID.

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1");
```

---

##### `with_status(self, status: BasicStatus) -> Self`

Sets the basic status (builder pattern).

**Example:**
```rust
use sip_core::{Tuple, BasicStatus};

let tuple = Tuple::new("t1")
    .with_status(BasicStatus::Open);
```

---

##### `with_contact(self, contact: impl Into<SmolStr>) -> Self`

Sets the contact URI (builder pattern).

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")
    .with_contact("sip:alice@192.168.1.100");
```

---

##### `with_note(self, note: impl Into<SmolStr>) -> Self`

Adds a note (builder pattern).

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")
    .with_note("Available")
    .with_note("Happy to chat");
```

---

##### `with_timestamp(self, timestamp: impl Into<SmolStr>) -> Self`

Sets the timestamp (builder pattern).

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")
    .with_timestamp("2023-11-21T12:00:00Z");
```

---

#### `BasicStatus`

RFC 3863 Basic Presence Status indicating availability for communication.

**Variants:**
- `Open` - The presentity is available for communication
- `Closed` - The presentity is not available for communication

**Methods:**

##### `as_str(&self) -> &str`

Returns the string representation for XML.

**Example:**
```rust
use sip_core::BasicStatus;

assert_eq!(BasicStatus::Open.as_str(), "open");
assert_eq!(BasicStatus::Closed.as_str(), "closed");
```

---

##### `from_str(s: &str) -> Option<Self>`

Parses a basic status from a string (case-insensitive).

**Example:**
```rust
use sip_core::BasicStatus;

assert_eq!(BasicStatus::from_str("open"), Some(BasicStatus::Open));
assert_eq!(BasicStatus::from_str("CLOSED"), Some(BasicStatus::Closed));
assert_eq!(BasicStatus::from_str("invalid"), None);
```

---

### Functions

#### `parse_pidf`

```rust
pub fn parse_pidf(xml: &str) -> Option<PresenceDocument>
```

Parses a PIDF presence document from XML.

**Parameters:**
- `xml` - The PIDF XML document

**Returns:**
- `Some(PresenceDocument)` if valid
- `None` if invalid or malformed

**Example:**
```rust
use sip_core::parse_pidf;

let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@192.168.1.100</contact>
    <note>Available</note>
  </tuple>
</presence>"#;

let doc = parse_pidf(xml).unwrap();
assert_eq!(doc.entity, "pres:alice@example.com");
```

**Note:** The current implementation uses basic string parsing. A production implementation should use a proper XML parser library.

---

## Usage Patterns

### Basic Presence Document

Create a simple presence document:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com");

let tuple = Tuple::new("t1")
    .with_status(BasicStatus::Open)
    .with_contact("sip:alice@192.168.1.100")
    .with_note("Available");

doc.add_tuple(tuple);

// Send in NOTIFY body with Content-Type: application/pidf+xml
let xml = doc.to_xml();
```

Output:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@192.168.1.100</contact>
    <note>Available</note>
  </tuple>
</presence>
```

### Multiple Endpoints

Report presence for multiple devices:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com");

// Desktop - open
doc.add_tuple(
    Tuple::new("desktop")
        .with_status(BasicStatus::Open)
        .with_contact("sip:alice@work.example.com")
        .with_note("At my desk")
);

// Mobile - open
doc.add_tuple(
    Tuple::new("mobile")
        .with_status(BasicStatus::Open)
        .with_contact("sip:alice@mobile.example.com")
        .with_note("On the go")
);

// Home phone - closed
doc.add_tuple(
    Tuple::new("home")
        .with_status(BasicStatus::Closed)
        .with_contact("sip:alice@home.example.com")
);

let xml = doc.to_xml();
```

### Away Status

Indicate availability with notes:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:bob@example.com");

doc.add_tuple(
    Tuple::new("t1")
        .with_status(BasicStatus::Open)
        .with_contact("sip:bob@example.com")
        .with_note("In a meeting until 3pm")
);

let xml = doc.to_xml();
```

### Offline Status

Report offline/unavailable:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:carol@example.com");

doc.add_tuple(
    Tuple::new("t1")
        .with_status(BasicStatus::Closed)
);

let xml = doc.to_xml();
```

### With Timestamps

Include temporal information:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:dave@example.com");

doc.add_tuple(
    Tuple::new("t1")
        .with_status(BasicStatus::Open)
        .with_contact("sip:dave@example.com")
        .with_note("Available")
        .with_timestamp("2023-11-21T12:00:00Z")
);

let xml = doc.to_xml();
```

### Parsing Received Presence

Parse a NOTIFY body:

```rust
use sip_core::{parse_pidf, BasicStatus};

let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@192.168.1.100</contact>
    <note>Available</note>
  </tuple>
</presence>"#;

let doc = parse_pidf(xml).unwrap();

// Check overall status
if let Some(status) = doc.basic_status() {
    match status {
        BasicStatus::Open => println!("Alice is available"),
        BasicStatus::Closed => println!("Alice is unavailable"),
    }
}

// Check each tuple
for tuple in &doc.tuples {
    if let Some(contact) = &tuple.contact {
        println!("Contact: {}", contact);
    }
    for note in &tuple.notes {
        println!("Note: {}", note);
    }
}
```

## Integration with Other Components

### With SIP SUBSCRIBE/NOTIFY

Subscribe to presence events:

```
SUBSCRIBE sip:alice@example.com SIP/2.0
Via: SIP/2.0/UDP watcher.example.com:5060;branch=z9hG4bKnashds8
Max-Forwards: 70
To: <sip:alice@example.com>
From: <sip:bob@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 SUBSCRIBE
Event: presence
Accept: application/pidf+xml
Expires: 3600
Contact: <sip:bob@watcher.example.com:5060>
Content-Length: 0
```

Send NOTIFY with presence:

```
NOTIFY sip:bob@watcher.example.com:5060 SIP/2.0
Via: SIP/2.0/UDP presence.example.com:5060;branch=z9hG4bK77ef4c2312983.1
To: <sip:bob@example.com>;tag=1928301774
From: <sip:alice@example.com>;tag=456248
Call-ID: a84b4c76e66710
CSeq: 1 NOTIFY
Event: presence
Subscription-State: active;expires=3599
Content-Type: application/pidf+xml
Content-Length: 312

<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
  <tuple id="t1">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@192.168.1.100</contact>
    <note>Available</note>
  </tuple>
</presence>
```

### With Presence Agent

Presence agent implementation:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};
use std::collections::HashMap;

struct PresenceAgent {
    presence_info: HashMap<String, PresenceDocument>,
}

impl PresenceAgent {
    fn update_presence(&mut self, entity: &str, status: BasicStatus, note: &str) {
        let mut doc = PresenceDocument::new(entity);

        doc.add_tuple(
            Tuple::new("default")
                .with_status(status)
                .with_note(note)
        );

        self.presence_info.insert(entity.to_string(), doc);
    }

    fn get_presence(&self, entity: &str) -> Option<String> {
        self.presence_info.get(entity).map(|doc| doc.to_xml())
    }

    fn notify_watchers(&self, entity: &str) {
        if let Some(xml) = self.get_presence(entity) {
            // Send NOTIFY to all watchers subscribed to this entity
            // with Content-Type: application/pidf+xml and body = xml
        }
    }
}
```

### With User Agent

UA updating presence:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

struct UserAgent {
    entity: String,
}

impl UserAgent {
    fn publish_presence(&self, status: BasicStatus, note: &str) -> String {
        let mut doc = PresenceDocument::new(&self.entity);

        doc.add_tuple(
            Tuple::new("ua1")
                .with_status(status)
                .with_contact(format!("sip:{}@192.168.1.100", self.entity))
                .with_note(note)
        );

        doc.to_xml()
    }

    fn set_available(&self) -> String {
        self.publish_presence(BasicStatus::Open, "Available")
    }

    fn set_away(&self) -> String {
        self.publish_presence(BasicStatus::Open, "Away from desk")
    }

    fn set_offline(&self) -> String {
        self.publish_presence(BasicStatus::Closed, "Offline")
    }
}
```

### Watcher Application

Application watching presence:

```rust
use sip_core::{parse_pidf, BasicStatus};

struct PresenceWatcher {
    watched_entities: Vec<String>,
}

impl PresenceWatcher {
    fn handle_notify(&self, body: &str) {
        if let Some(doc) = parse_pidf(body) {
            println!("Presence update for: {}", doc.entity);

            match doc.basic_status() {
                Some(BasicStatus::Open) => {
                    // Show user as online/available
                    self.update_ui_online(&doc.entity);

                    // Display notes if any
                    for tuple in &doc.tuples {
                        for note in &tuple.notes {
                            self.display_status_message(&doc.entity, note);
                        }
                    }
                }
                Some(BasicStatus::Closed) => {
                    // Show user as offline/unavailable
                    self.update_ui_offline(&doc.entity);
                }
                None => {
                    // Unknown status
                    self.update_ui_unknown(&doc.entity);
                }
            }
        }
    }

    fn update_ui_online(&self, entity: &str) {
        // Update UI to show green/online indicator
    }

    fn update_ui_offline(&self, entity: &str) {
        // Update UI to show gray/offline indicator
    }

    fn update_ui_unknown(&self, entity: &str) {
        // Update UI to show unknown status
    }

    fn display_status_message(&self, entity: &str, message: &str) {
        // Show status message in UI
    }
}
```

## Test Coverage

The presence implementation includes 11 comprehensive unit tests:

### PresenceDocument Tests

1. **presence_document_creation**: Basic creation and properties
2. **presence_document_xml_output**: XML formatting
3. **presence_document_multiple_tuples**: Multiple tuples support
4. **presence_document_with_notes**: Document-level notes
5. **basic_status_from_first_tuple**: Status extraction

### Tuple Tests

6. **tuple_creation**: Basic tuple creation with builder pattern
7. **tuple_with_timestamp**: Timestamp support

### BasicStatus Tests

8. **basic_status_values**: Status string representation and parsing

### Utility Tests

9. **xml_escaping**: XML special character escaping

### Parsing Tests

10. **parse_simple_pidf**: Basic PIDF parsing
11. **round_trip_pidf**: Format and parse round-trip consistency

### Running Tests

```bash
# Run all presence tests
cargo test --package sip-core presence

# Run specific test
cargo test --package sip-core presence_document_creation

# Run with output
cargo test --package sip-core presence -- --nocapture
```

## Limitations and Future Work

### Current Limitations

1. **Basic XML Parsing**: Uses simple string parsing instead of a proper XML parser library

2. **No Rich Presence**: RFC 4480 (RPID) rich presence extensions not implemented

3. **No Person Element**: PIDF person element for presentity information not implemented

4. **No Device Element**: Device information not supported

5. **No Service Element**: Service-specific presence not implemented

6. **No Extensions**: Custom XML namespaces and extensions not supported

7. **No SUBSCRIBE/NOTIFY**: Event package mechanics not implemented (data structures only)

### Future Enhancements

1. **Proper XML Parser**
   - Use roxmltree, quick-xml, or similar library
   - Proper namespace handling
   - Schema validation

2. **RFC 4480 (RPID) Support**
   - Activity elements (meeting, meal, travel, etc.)
   - Mood elements
   - Place-type elements
   - Privacy elements

3. **Extended PIDF Elements**
   - Person element for presentity info
   - Device element for device details
   - Service element for service-specific presence

4. **PIDF-LO (Location)**
   - RFC 4119 location information
   - Civic and geodetic location

5. **Presence Authorization**
   - Watcher information
   - Authorization policies
   - Privacy rules

6. **Complete Event Package**
   - SUBSCRIBE handling
   - NOTIFY generation
   - Subscription state management

7. **Presence Lists**
   - RFC 4662 resource lists
   - Batch subscriptions
   - Efficient multi-presence handling

8. **Partial Presence**
   - RFC 5262 partial PIDF
   - Delta notifications
   - Bandwidth optimization

## Related RFCs

- **RFC 3856**: A Presence Event Package for the Session Initiation Protocol (SIP)
- **RFC 3859**: Common Profile for Presence (CPP)
- **RFC 3863**: Presence Information Data Format (PIDF)
- **RFC 3265**: SIP-Specific Event Notification
- **RFC 4480**: RPID: Rich Presence Extensions to PIDF
- **RFC 4119**: PIDF-LO: A Presence-based GEOPRIV Location Object Format
- **RFC 4662**: A Session Initiation Protocol (SIP) Event Notification Extension for Resource Lists
- **RFC 5262**: Presence Information Data Format (PIDF) Extension for Partial Presence

## Examples

### Complete NOTIFY with Presence

```
NOTIFY sip:bob@watcher.example.com:5060 SIP/2.0
Via: SIP/2.0/UDP presence.example.com:5060;branch=z9hG4bK77ef4c2312983.1
To: <sip:bob@example.com>;tag=1928301774
From: <sip:alice@example.com>;tag=456248
Call-ID: a84b4c76e66710
CSeq: 1 NOTIFY
Event: presence
Subscription-State: active;expires=3599
Content-Type: application/pidf+xml
Content-Length: 448

<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="pres:alice@example.com">
  <tuple id="desktop">
    <status>
      <basic>open</basic>
    </status>
    <contact>sip:alice@work.example.com</contact>
    <note>At my desk</note>
    <timestamp>2023-11-21T14:30:00Z</timestamp>
  </tuple>
  <tuple id="mobile">
    <status>
      <basic>closed</basic>
    </status>
    <contact>sip:alice@mobile.example.com</contact>
  </tuple>
</presence>
```

## Version History

- **Initial Implementation** (Current): Complete PIDF structure, basic status, tuple support, XML formatting, and basic parsing

