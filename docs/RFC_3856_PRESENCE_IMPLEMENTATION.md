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

#### `PresenceError`

Error type for presence validation and parsing.

**Variants:**
- `EntityTooLong { max, actual }` - Entity length exceeds `MAX_ENTITY_LENGTH`
- `IdTooLong { max, actual }` - Tuple ID length exceeds `MAX_ID_LENGTH`
- `ContactTooLong { max, actual }` - Contact length exceeds `MAX_CONTACT_LENGTH`
- `NoteTooLong { max, actual }` - Note length exceeds `MAX_NOTE_LENGTH`
- `TimestampTooLong { max, actual }` - Timestamp length exceeds `MAX_TIMESTAMP_LENGTH`
- `TooManyTuples { max, actual }` - Tuple count exceeds `MAX_TUPLES`
- `TooManyNotes { max, actual }` - Notes count exceeds `MAX_NOTES_PER_TUPLE` or `MAX_NOTES_PER_DOC`
- `InvalidEntity(String)` - Entity contains invalid data
- `InvalidId(String)` - Tuple ID contains invalid data
- `InvalidContact(String)` - Contact contains invalid data
- `InvalidNote(String)` - Note contains invalid data
- `InvalidTimestamp(String)` - Timestamp contains invalid data
- `EmptyEntity` - Entity is empty
- `EmptyId` - Tuple ID is empty
- `ParseError(String)` - Parsing failed (missing or invalid fields)
- `InputTooLarge { max, actual }` - Input exceeds `MAX_PARSE_SIZE`

**Validation Limits:**
- `MAX_ENTITY_LENGTH`: 512
- `MAX_ID_LENGTH`: 128
- `MAX_CONTACT_LENGTH`: 512
- `MAX_NOTE_LENGTH`: 512
- `MAX_TIMESTAMP_LENGTH`: 64
- `MAX_TUPLES`: 50
- `MAX_NOTES_PER_TUPLE`: 10
- `MAX_NOTES_PER_DOC`: 20
- `MAX_PARSE_SIZE`: 1048576 bytes

---

#### `PresenceDocument`

RFC 3863 PIDF Presence Document representing complete presence information for a presentity.

**Fields:**
- `entity: SmolStr` - The entity URI (presentity) (private, use accessors)
- `tuples: Vec<Tuple>` - List of presence tuples (private, use accessors)
- `notes: Vec<SmolStr>` - Optional notes about the presentity (private, use accessors)

**Methods:**

##### `new(entity: impl AsRef<str>) -> Result<Self, PresenceError>`

Creates a new presence document for the given entity.

**Example:**
```rust
use sip_core::PresenceDocument;

let doc = PresenceDocument::new("pres:alice@example.com")?;
```

---

##### `add_tuple(&mut self, tuple: Tuple) -> Result<(), PresenceError>`

Adds a tuple to the presence document.
Returns an error if adding would exceed `MAX_TUPLES`.

**Example:**
```rust
use sip_core::{PresenceDocument, PresenceError, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com")?;

let tuple = Tuple::new("t1")?
    .with_status(BasicStatus::Open)
    .with_contact("sip:alice@192.168.1.100")?;

doc.add_tuple(tuple)?;
```

---

##### `add_note(&mut self, note: impl AsRef<str>) -> Result<(), PresenceError>`

Adds a note to the presence document.
Returns an error if the note is invalid or exceeds `MAX_NOTES_PER_DOC`.

**Example:**
```rust
use sip_core::PresenceDocument;

let mut doc = PresenceDocument::new("pres:alice@example.com")?;
doc.add_note("Available")?;
```

---

##### `entity(&self) -> &str`

Returns the entity URI.

---

##### `tuples(&self) -> impl Iterator<Item = &Tuple>`

Returns an iterator over tuples.

---

##### `notes(&self) -> impl Iterator<Item = &str>`

Returns an iterator over document notes.

---

##### `len(&self) -> usize`

Returns the number of tuples.

---

##### `is_empty(&self) -> bool`

Returns true if there are no tuples.

---

##### `basic_status(&self) -> Option<BasicStatus>`

Returns the basic status from the first tuple, if any.

**Example:**
```rust
use sip_core::{PresenceDocument, PresenceError, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com")?;
doc.add_tuple(Tuple::new("t1")?.with_status(BasicStatus::Open))?;

assert_eq!(doc.basic_status(), Some(BasicStatus::Open));
```

---

##### `to_xml(&self) -> String`

Formats the presence document as application/pidf+xml.

**Example:**
```rust
use sip_core::{PresenceDocument, PresenceError, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com")?;
doc.add_tuple(
    Tuple::new("t1")?
        .with_status(BasicStatus::Open)
        .with_contact("sip:alice@192.168.1.100")?
        .with_note("Available")?
)?;

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
- `id: SmolStr` - Tuple identifier (must be unique within document) (private)
- `status: Option<BasicStatus>` - Basic status (open or closed) (private)
- `contact: Option<SmolStr>` - Contact URI for this tuple (private)
- `notes: Vec<SmolStr>` - Optional notes about this tuple (private)
- `timestamp: Option<SmolStr>` - Optional timestamp (private)

**Methods:**

##### `new(id: impl AsRef<str>) -> Result<Self, PresenceError>`

Creates a new tuple with the given ID.

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")?;
```

---

##### `with_status(self, status: BasicStatus) -> Self`

Sets the basic status (builder pattern).

**Example:**
```rust
use sip_core::{Tuple, BasicStatus};

let tuple = Tuple::new("t1")?
    .with_status(BasicStatus::Open);
```

---

##### `with_contact(self, contact: impl AsRef<str>) -> Result<Self, PresenceError>`

Sets the contact URI (builder pattern).

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")?
    .with_contact("sip:alice@192.168.1.100")?;
```

---

##### `with_note(self, note: impl AsRef<str>) -> Result<Self, PresenceError>`

Adds a note (builder pattern).

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")?
    .with_note("Available")?
    .with_note("Happy to chat")?;
```

---

##### `with_timestamp(self, timestamp: impl AsRef<str>) -> Result<Self, PresenceError>`

Sets the timestamp (builder pattern).

**Example:**
```rust
use sip_core::Tuple;

let tuple = Tuple::new("t1")?
    .with_timestamp("2023-11-21T12:00:00Z")?;
```

---

##### `id(&self) -> &str`

Returns the tuple ID.

---

##### `status(&self) -> Option<BasicStatus>`

Returns the status.

---

##### `contact(&self) -> Option<&str>`

Returns the contact URI.

---

##### `notes(&self) -> impl Iterator<Item = &str>`

Returns an iterator over tuple notes.

---

##### `timestamp(&self) -> Option<&str>`

Returns the timestamp.
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

##### `parse(s: &str) -> Option<Self>`

Parses a basic status from a string (case-insensitive).

**Example:**
```rust
use sip_core::BasicStatus;

assert_eq!(BasicStatus::parse("open"), Some(BasicStatus::Open));
assert_eq!(BasicStatus::parse("CLOSED"), Some(BasicStatus::Closed));
assert_eq!(BasicStatus::parse("invalid"), None);
```

---

### Functions

#### `parse_pidf`

```rust
pub fn parse_pidf(xml: &str) -> Result<PresenceDocument, PresenceError>
```

Parses a PIDF presence document from XML.
Input is capped at `MAX_PARSE_SIZE` (1MB).

**Parameters:**
- `xml` - The PIDF XML document

**Returns:**
- `Ok(PresenceDocument)` if valid
- `Err(PresenceError)` if invalid, malformed, or exceeds size limits

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

let doc = parse_pidf(xml)?;
assert_eq!(doc.entity(), "pres:alice@example.com");
```

**Note:** The current implementation uses basic string parsing. A production implementation should use a proper XML parser library.

---

## Usage Patterns

### Basic Presence Document

Create a simple presence document:

```rust
use sip_core::{PresenceDocument, PresenceError, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:alice@example.com")?;

let tuple = Tuple::new("t1")?
    .with_status(BasicStatus::Open)
    .with_contact("sip:alice@192.168.1.100")?
    .with_note("Available")?;

doc.add_tuple(tuple)?;

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

let mut doc = PresenceDocument::new("pres:alice@example.com")?;

// Desktop - open
doc.add_tuple(
    Tuple::new("desktop")?
        .with_status(BasicStatus::Open)
        .with_contact("sip:alice@work.example.com")?
        .with_note("At my desk")?
)?;

// Mobile - open
doc.add_tuple(
    Tuple::new("mobile")?
        .with_status(BasicStatus::Open)
        .with_contact("sip:alice@mobile.example.com")?
        .with_note("On the go")?
)?;

// Home phone - closed
doc.add_tuple(
    Tuple::new("home")?
        .with_status(BasicStatus::Closed)
        .with_contact("sip:alice@home.example.com")?
)?;

let xml = doc.to_xml();
```

### Away Status

Indicate availability with notes:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:bob@example.com")?;

doc.add_tuple(
    Tuple::new("t1")?
        .with_status(BasicStatus::Open)
        .with_contact("sip:bob@example.com")?
        .with_note("In a meeting until 3pm")?
)?;

let xml = doc.to_xml();
```

### Offline Status

Report offline/unavailable:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:carol@example.com")?;

doc.add_tuple(
    Tuple::new("t1")?
        .with_status(BasicStatus::Closed)
)?;

let xml = doc.to_xml();
```

### With Timestamps

Include temporal information:

```rust
use sip_core::{PresenceDocument, Tuple, BasicStatus};

let mut doc = PresenceDocument::new("pres:dave@example.com")?;

doc.add_tuple(
    Tuple::new("t1")?
        .with_status(BasicStatus::Open)
        .with_contact("sip:dave@example.com")?
        .with_note("Available")?
        .with_timestamp("2023-11-21T12:00:00Z")?
)?;

let xml = doc.to_xml();
```

### Parsing Received Presence

Parse a NOTIFY body:

```rust
use sip_core::{parse_pidf, BasicStatus, PresenceError};

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

let doc = parse_pidf(xml)?;

// Check overall status
if let Some(status) = doc.basic_status() {
    match status {
        BasicStatus::Open => println!("Alice is available"),
        BasicStatus::Closed => println!("Alice is unavailable"),
    }
}

// Check each tuple
for tuple in doc.tuples() {
    if let Some(contact) = tuple.contact() {
        println!("Contact: {}", contact);
    }
    for note in tuple.notes() {
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
    fn update_presence(
        &mut self,
        entity: &str,
        status: BasicStatus,
        note: &str,
    ) -> Result<(), PresenceError> {
        let mut doc = PresenceDocument::new(entity)?;

        doc.add_tuple(
            Tuple::new("default")?
                .with_status(status)
                .with_note(note)?
        )?;

        self.presence_info.insert(entity.to_string(), doc);
        Ok(())
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
    fn publish_presence(&self, status: BasicStatus, note: &str) -> Result<String, PresenceError> {
        let mut doc = PresenceDocument::new(&self.entity)?;

        doc.add_tuple(
            Tuple::new("ua1")?
                .with_status(status)
                .with_contact(format!("sip:{}@192.168.1.100", self.entity))?
                .with_note(note)?
        )?;

        Ok(doc.to_xml())
    }

    fn set_available(&self) -> Result<String, PresenceError> {
        self.publish_presence(BasicStatus::Open, "Available")
    }

    fn set_away(&self) -> Result<String, PresenceError> {
        self.publish_presence(BasicStatus::Open, "Away from desk")
    }

    fn set_offline(&self) -> Result<String, PresenceError> {
        self.publish_presence(BasicStatus::Closed, "Offline")
    }
}
```

### Watcher Application

Application watching presence:

```rust
use sip_core::{parse_pidf, BasicStatus, PresenceError};

struct PresenceWatcher {
    watched_entities: Vec<String>,
}

impl PresenceWatcher {
    fn handle_notify(&self, body: &str) -> Result<(), PresenceError> {
        let doc = parse_pidf(body)?;
        println!("Presence update for: {}", doc.entity());

        match doc.basic_status() {
            Some(BasicStatus::Open) => {
                // Show user as online/available
                self.update_ui_online(doc.entity());

                // Display notes if any
                for tuple in doc.tuples() {
                    for note in tuple.notes() {
                        self.display_status_message(doc.entity(), note);
                    }
                }
            }
            Some(BasicStatus::Closed) => {
                // Show user as offline/unavailable
                self.update_ui_offline(doc.entity());
            }
            None => {
                // Unknown status
                self.update_ui_unknown(doc.entity());
            }
        }

        Ok(())
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

The presence implementation includes 19 comprehensive unit tests:

### PresenceDocument Tests

1. **presence_document_creation**: Basic creation and properties
2. **presence_document_xml_output**: XML formatting
3. **round_trip_pidf**: Format and parse round-trip consistency
4. **fields_are_private**: Ensures field access is via accessors

### Validation Tests

5. **reject_empty_entity**: Rejects empty entity
6. **reject_oversized_entity**: Enforces entity length limit
7. **reject_crlf_in_entity**: Rejects control characters in entity
8. **reject_empty_tuple_id**: Rejects empty tuple ID
9. **reject_crlf_in_tuple_id**: Rejects control characters in tuple ID
10. **reject_crlf_in_contact**: Rejects control characters in contact
11. **reject_crlf_in_note**: Rejects control characters in notes
12. **reject_too_many_tuples**: Enforces tuple count limit
13. **reject_too_many_notes**: Enforces note count limit per tuple
14. **reject_oversized_parse_input**: Enforces parse size limit
15. **parse_validates_entity**: Validates entity during parsing
16. **parse_rejects_invalid_basic_status**: Rejects invalid basic status values

### Tuple Tests

17. **tuple_creation**: Basic tuple creation with builder pattern

### Utility Tests

18. **xml_escaping**: XML special character escaping
19. **parse_preserves_document_notes_and_unescapes**: Preserves document notes and unescapes XML

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
