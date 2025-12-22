# RFC 3842: Message Waiting Indication Implementation

## Overview

This document describes the implementation of RFC 3842 (A Message Summary and Message Waiting Indication Event Package for the Session Initiation Protocol) in the siphon-rs codebase. RFC 3842 defines a SIP event package for message waiting indications (MWI), allowing messaging systems to notify users about pending messages.

## RFC 3842 Summary

**RFC 3842** defines the "message-summary" event package for SIP, enabling voicemail and messaging systems to send message waiting notifications. Key concepts:

- **Event Package**: "message-summary"
- **MIME Type**: application/simple-message-summary
- **Default Subscription Duration**: 3600 seconds (1 hour)
- **Message Classes**: voice, fax, pager, multimedia, text, none
- **Status Tracking**: new/old messages, urgent/non-urgent counts
- **Optional Details**: RFC 2822 headers for specific messages

### Message-Summary Format

The body format is intentionally simple (text-based) to avoid burdening low-end devices:

```
Messages-Waiting: yes
Message-Account: sip:alice@vmail.example.com
Voice-Message: 2/8 (0/2)
Fax-Message: 1/3
```

Format breakdown:
- **Status line**: `Messages-Waiting: yes/no` (mandatory)
- **Account**: `Message-Account: URI` (conditional - required for group subscriptions)
- **Counts**: `<Class>-Message: new/old (urgent_new/urgent_old)` (optional)
- **Headers**: RFC 2822 headers for message details (optional)

### Message Classes

Six message context classes are defined:
- **voice-message**: Voice messages
- **fax-message**: Fax messages
- **pager-message**: Pager messages
- **multimedia-message**: Multimedia messages
- **text-message**: Text messages
- **none-message**: Unclassified messages

### Count Format

Message counts follow the format: `new/old (urgent_new/urgent_old)`
- `new/old`: Total new and old messages
- `(urgent_new/urgent_old)`: Urgent message counts (optional, only if > 0)
- Maximum value: 2^32-1

### Optional Message Headers

For newly received messages, RFC 2822 headers can be included:
- To
- From
- Subject
- Date
- Priority
- Message-ID
- Message-Context

**Important**: Initial NOTIFYs should exclude these to prevent unbounded sizes. Subsequent NOTIFYs include headers only for newly added messages.

## Implementation Location

The RFC 3842 implementation is located in:
- **Module**: `crates/sip-core/src/message_waiting.rs`
- **Exports**: Through `crates/sip-core/src/lib.rs`

## API Reference

### Types

#### `MessageSummary`

RFC 3842 Message Summary representing complete message waiting indication.

**Fields:**
- `messages_waiting: bool` - Whether messages are waiting (mandatory)
- `account: Option<SmolStr>` - Message account URI (conditional)
- `messages: BTreeMap<MessageContextClass, MessageCounts>` - Message counts by class
- `message_headers: Vec<MessageHeader>` - Optional message details

**Methods:**

##### `new(messages_waiting: bool) -> Self`

Creates a new message summary.

**Example:**
```rust
use sip_core::MessageSummary;

let summary = MessageSummary::new(true);
```

---

##### `set_account(&mut self, account: impl Into<SmolStr>)`

Sets the message account URI.

**Example:**
```rust
use sip_core::MessageSummary;

let mut summary = MessageSummary::new(true);
summary.set_account("sip:alice@vmail.example.com");
```

---

##### `add_message_class(&mut self, class: MessageContextClass, counts: MessageCounts)`

Adds message counts for a context class.

**Example:**
```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts};

let mut summary = MessageSummary::new(true);
summary.add_message_class(
    MessageContextClass::Voice,
    MessageCounts::new(2, 8)
);
```

---

##### `add_message_header(&mut self, header: MessageHeader)`

Adds a message header for message details.

---

##### `is_empty(&self) -> bool`

Returns true if there are no message counts.

---

##### `total_new(&self) -> u32`

Returns the total number of new messages across all classes.

**Example:**
```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts};

let mut summary = MessageSummary::new(true);
summary.add_message_class(MessageContextClass::Voice, MessageCounts::new(2, 5));
summary.add_message_class(MessageContextClass::Fax, MessageCounts::new(1, 3));

assert_eq!(summary.total_new(), 3); // 2 + 1
```

---

##### `total_old(&self) -> u32`

Returns the total number of old messages across all classes.

---

##### `has_urgent(&self) -> bool`

Returns true if any messages are urgent.

---

##### `to_string(&self) -> String` (via Display trait)

Formats the message summary as application/simple-message-summary.

**Example:**
```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts};

let mut summary = MessageSummary::new(true);
summary.set_account("sip:alice@vmail.example.com");
summary.add_message_class(
    MessageContextClass::Voice,
    MessageCounts::new(2, 8).with_urgent(0, 2)
);

let body = summary.to_string();
// Output:
// Messages-Waiting: yes
// Message-Account: sip:alice@vmail.example.com
// Voice-Message: 2/8 (0/2)
```

---

#### `MessageContextClass`

RFC 3842 Message Context Class defining the type of message.

**Variants:**
- `Voice` - Voice messages
- `Fax` - Fax messages
- `Pager` - Pager messages
- `Multimedia` - Multimedia messages
- `Text` - Text messages
- `None` - No specific context

**Methods:**

##### `header_name(&self) -> &str`

Returns the header name for this context class.

**Example:**
```rust
use sip_core::MessageContextClass;

assert_eq!(MessageContextClass::Voice.header_name(), "Voice-Message");
assert_eq!(MessageContextClass::Fax.header_name(), "Fax-Message");
```

---

##### `from_header_name(name: &str) -> Option<Self>`

Parses a context class from a header name.

**Example:**
```rust
use sip_core::MessageContextClass;

assert_eq!(
    MessageContextClass::from_header_name("Voice-Message"),
    Some(MessageContextClass::Voice)
);
```

---

##### `as_str(&self) -> &str`

Returns the context class identifier.

**Example:**
```rust
use sip_core::MessageContextClass;

assert_eq!(MessageContextClass::Voice.as_str(), "voice");
assert_eq!(MessageContextClass::Multimedia.as_str(), "multimedia");
```

---

#### `MessageCounts`

Message counts for a context class, separated by new/old status and urgent/non-urgent priority.

**Fields:**
- `new: u32` - Number of new messages
- `old: u32` - Number of old messages
- `urgent_new: u32` - Number of urgent new messages
- `urgent_old: u32` - Number of urgent old messages

**Methods:**

##### `new(new: u32, old: u32) -> Self`

Creates new message counts with new and old totals.

**Example:**
```rust
use sip_core::MessageCounts;

let counts = MessageCounts::new(3, 5);
assert_eq!(counts.new, 3);
assert_eq!(counts.old, 5);
```

---

##### `with_urgent(self, urgent_new: u32, urgent_old: u32) -> Self`

Sets the urgent message counts (builder pattern).

**Example:**
```rust
use sip_core::MessageCounts;

let counts = MessageCounts::new(2, 8)
    .with_urgent(0, 2);

assert_eq!(counts.urgent_new, 0);
assert_eq!(counts.urgent_old, 2);
```

---

##### `total(&self) -> u32`

Returns the total number of messages (new + old).

---

##### `total_urgent(&self) -> u32`

Returns the total number of urgent messages.

---

##### `has_new(&self) -> bool`

Returns true if there are any new messages.

---

##### `has_urgent(&self) -> bool`

Returns true if there are any urgent messages.

---

#### `MessageHeader`

Optional message headers for newly received messages providing details about specific messages.

**Fields:**
- `to: Option<SmolStr>` - To header
- `from: Option<SmolStr>` - From header
- `subject: Option<SmolStr>` - Subject header
- `date: Option<SmolStr>` - Date header
- `priority: Option<SmolStr>` - Priority header
- `message_id: Option<SmolStr>` - Message-ID header
- `message_context: Option<SmolStr>` - Message-Context header

**Methods:**

##### `new() -> Self`

Creates a new empty message header.

---

##### `with_to(self, to: impl Into<SmolStr>) -> Self`

Sets the To header (builder pattern).

**Example:**
```rust
use sip_core::MessageHeader;

let header = MessageHeader::new()
    .with_to("alice@example.com")
    .with_from("bob@example.com")
    .with_subject("Meeting reminder");
```

---

##### `with_from(self, from: impl Into<SmolStr>) -> Self`

Sets the From header.

---

##### `with_subject(self, subject: impl Into<SmolStr>) -> Self`

Sets the Subject header.

---

##### `with_date(self, date: impl Into<SmolStr>) -> Self`

Sets the Date header.

---

##### `with_priority(self, priority: impl Into<SmolStr>) -> Self`

Sets the Priority header.

---

##### `with_message_id(self, message_id: impl Into<SmolStr>) -> Self`

Sets the Message-ID header.

---

##### `with_message_context(self, message_context: impl Into<SmolStr>) -> Self`

Sets the Message-Context header.

---

### Functions

#### `parse_message_summary`

```rust
pub fn parse_message_summary(body: &str) -> Option<MessageSummary>
```

Parses a message summary from application/simple-message-summary format.

**Parameters:**
- `body` - The message summary body text

**Returns:**
- `Some(MessageSummary)` if valid
- `None` if invalid or missing mandatory status line

**Example:**
```rust
use sip_core::parse_message_summary;

let body = "Messages-Waiting: yes\n\
            Message-Account: sip:alice@vmail.example.com\n\
            Voice-Message: 2/8 (0/2)\n";

let summary = parse_message_summary(body).unwrap();
assert!(summary.messages_waiting);
assert_eq!(summary.total_new(), 2);
```

---

## Usage Patterns

### Basic Message Waiting Notification

Send a simple MWI notification:

```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts};

let mut summary = MessageSummary::new(true);
summary.set_account("sip:alice@vmail.example.com");
summary.add_message_class(
    MessageContextClass::Voice,
    MessageCounts::new(2, 8)
);

// Send in NOTIFY body with Content-Type: application/simple-message-summary
let body = summary.to_string();
```

Output:
```
Messages-Waiting: yes
Message-Account: sip:alice@vmail.example.com
Voice-Message: 2/8
```

### Multiple Message Types

Report multiple message types:

```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts};

let mut summary = MessageSummary::new(true);
summary.set_account("sip:alice@vmail.example.com");

summary.add_message_class(
    MessageContextClass::Voice,
    MessageCounts::new(2, 8).with_urgent(0, 2)
);

summary.add_message_class(
    MessageContextClass::Fax,
    MessageCounts::new(1, 3)
);

summary.add_message_class(
    MessageContextClass::Text,
    MessageCounts::new(5, 10).with_urgent(2, 0)
);

let body = summary.to_string();
```

Output:
```
Messages-Waiting: yes
Message-Account: sip:alice@vmail.example.com
Voice-Message: 2/8 (0/2)
Fax-Message: 1/3
Text-Message: 5/10 (2/0)
```

### No Messages Waiting

Clear message waiting indicator:

```rust
use sip_core::MessageSummary;

let summary = MessageSummary::new(false);
let body = summary.to_string();
```

Output:
```
Messages-Waiting: no
```

### With Message Headers

Include details about new messages (for incremental updates):

```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts, MessageHeader};

let mut summary = MessageSummary::new(true);
summary.add_message_class(
    MessageContextClass::Voice,
    MessageCounts::new(4, 8).with_urgent(1, 2)
);

// Add header for newly received message
let header = MessageHeader::new()
    .with_to("alice@atlanta.example.com")
    .with_from("bob@biloxi.example.com")
    .with_subject("carpool tomorrow?");

summary.add_message_header(header);

let body = summary.to_string();
```

Output:
```
Messages-Waiting: yes
Voice-Message: 4/8 (1/2)
To: alice@atlanta.example.com
From: bob@biloxi.example.com
Subject: carpool tomorrow?
```

### Parsing Received Notifications

Parse a NOTIFY body:

```rust
use sip_core::{parse_message_summary, MessageContextClass};

let body = "Messages-Waiting: yes\n\
            Message-Account: sip:alice@vmail.example.com\n\
            Voice-Message: 2/8 (0/2)\n\
            Fax-Message: 1/3\n";

let summary = parse_message_summary(body).unwrap();

// Check status
if summary.messages_waiting {
    println!("You have {} new messages", summary.total_new());

    // Check voice messages
    if let Some(voice) = summary.messages.get(&MessageContextClass::Voice) {
        println!("Voice: {} new, {} old", voice.new, voice.old);
        if voice.has_urgent() {
            println!("  {} urgent messages", voice.total_urgent());
        }
    }
}
```

## Integration with Other Components

### With SIP SUBSCRIBE/NOTIFY

Subscribe to message-summary events:

```
SUBSCRIBE sip:alice@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKnashds8
Max-Forwards: 70
To: <sip:alice@example.com>
From: <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 SUBSCRIBE
Event: message-summary
Expires: 3600
Contact: <sip:alice@192.168.1.100:5060>
Content-Length: 0
```

Send NOTIFY with message summary:

```
NOTIFY sip:alice@192.168.1.100:5060 SIP/2.0
Via: SIP/2.0/UDP vmail.example.com:5060;branch=z9hG4bK77ef4c2312983.1
To: <sip:alice@example.com>;tag=1928301774
From: <sip:alice@example.com>;tag=456248
Call-ID: a84b4c76e66710
CSeq: 1 NOTIFY
Event: message-summary
Subscription-State: active;expires=3599
Content-Type: application/simple-message-summary
Content-Length: 94

Messages-Waiting: yes
Message-Account: sip:alice@vmail.example.com
Voice-Message: 2/8 (0/2)
```

### With Voicemail System

Voicemail system implementation:

```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts};

struct VoicemailBox {
    owner: String,
    messages: Vec<VoiceMessage>,
}

struct VoiceMessage {
    is_new: bool,
    is_urgent: bool,
    from: String,
    subject: String,
    date: String,
}

impl VoicemailBox {
    fn generate_mwi(&self) -> MessageSummary {
        let new = self.messages.iter().filter(|m| m.is_new && !m.is_urgent).count() as u32;
        let old = self.messages.iter().filter(|m| !m.is_new && !m.is_urgent).count() as u32;
        let urgent_new = self.messages.iter().filter(|m| m.is_new && m.is_urgent).count() as u32;
        let urgent_old = self.messages.iter().filter(|m| !m.is_new && m.is_urgent).count() as u32;

        let mut summary = MessageSummary::new(new > 0 || urgent_new > 0);
        summary.set_account(format!("sip:{}@vmail.example.com", self.owner));

        if new > 0 || old > 0 || urgent_new > 0 || urgent_old > 0 {
            summary.add_message_class(
                MessageContextClass::Voice,
                MessageCounts::new(new, old).with_urgent(urgent_new, urgent_old)
            );
        }

        summary
    }
}
```

### With User Agent

UA handling MWI notifications:

```rust
use sip_core::{parse_message_summary, MessageContextClass};

fn handle_mwi_notify(body: &str) {
    if let Some(summary) = parse_message_summary(body) {
        if summary.messages_waiting {
            // Light up MWI LED
            turn_on_mwi_indicator();

            // Update display
            if let Some(voice) = summary.messages.get(&MessageContextClass::Voice) {
                update_display(format!("{} new voice messages", voice.new));
            }

            // Play stutter dial tone if urgent
            if summary.has_urgent() {
                enable_stutter_dial_tone();
            }
        } else {
            // Turn off MWI LED
            turn_off_mwi_indicator();
            disable_stutter_dial_tone();
        }
    }
}
```

### Incremental Updates

Send incremental updates with only new message details:

```rust
use sip_core::{MessageSummary, MessageContextClass, MessageCounts, MessageHeader};

struct MwiNotifier {
    last_count: u32,
}

impl MwiNotifier {
    fn send_update(&mut self, new_messages: &[VoiceMessage]) -> MessageSummary {
        let current_new = new_messages.len() as u32;

        let mut summary = MessageSummary::new(true);
        summary.add_message_class(
            MessageContextClass::Voice,
            MessageCounts::new(current_new, 10) // 10 old messages
        );

        // Only include headers for messages received since last notification
        if current_new > self.last_count {
            for msg in &new_messages[(self.last_count as usize)..] {
                let header = MessageHeader::new()
                    .with_from(&msg.from)
                    .with_subject(&msg.subject)
                    .with_date(&msg.date);
                summary.add_message_header(header);
            }
        }

        self.last_count = current_new;
        summary
    }
}
```

## Test Coverage

The message waiting implementation includes 14 comprehensive unit tests:

### MessageSummary Tests

1. **message_summary_basic**: Basic creation and properties
2. **message_summary_output**: Formatting to application/simple-message-summary

### MessageContextClass Tests

3. **message_context_class_header_names**: Header name generation
4. **message_context_class_from_header**: Parsing from header names

### MessageCounts Tests

5. **message_counts_basic**: Basic count creation and totals
6. **message_counts_with_urgent**: Urgent count handling

### MessageHeader Tests

7. **message_header_builder**: Builder pattern for headers

### Parsing Tests

8. **parse_simple_summary**: Basic summary parsing
9. **parse_summary_with_headers**: Parsing with message headers
10. **parse_no_messages**: Parsing no-messages notification
11. **parse_multiple_classes**: Multiple message classes
12. **parse_message_counts_basic**: Count format parsing
13. **parse_message_counts_with_urgent**: Urgent count parsing

### Integration Tests

14. **round_trip**: Format and parse round-trip consistency

### Running Tests

```bash
# Run all message waiting tests
cargo test --package sip-core message_waiting

# Run specific test
cargo test --package sip-core message_summary_basic

# Run with output
cargo test --package sip-core message_waiting -- --nocapture
```

## Limitations and Future Work

### Current Limitations

1. **No SUBSCRIBE/NOTIFY Implementation**: Only data structures and formatting provided; subscription handling not implemented

2. **No Event State Management**: Subscription state tracking not implemented

3. **No Message-Context Extension**: Custom message contexts beyond the six standard types not supported

4. **No Extended Format**: Only supports simple count format; extended formats with additional metadata not supported

5. **No Parsing Validation**: Minimal validation of parsed URIs and header values

6. **No Binary Format**: Only text-based application/simple-message-summary supported

### Future Enhancements

1. **Complete Event Package Implementation**
   - SUBSCRIBE request handling
   - NOTIFY generation and sending
   - Subscription state management
   - Expiration and refresh handling

2. **Enhanced Parsing**
   - Strict URI validation
   - RFC 2822 header validation
   - Error reporting with specific failure reasons

3. **Extended Message Types**
   - Custom message-context-class support
   - Extension mechanism for vendor-specific types

4. **Advanced Features**
   - Message detail URIs (links to retrieve full messages)
   - Message preview text
   - Caller-ID information in headers
   - Attachment metadata

5. **Performance Optimizations**
   - Efficient diff computation for incremental updates
   - Message header caching
   - Batch notification generation

6. **Integration Features**
   - Automatic subscription renewal
   - Fallback to unsolicited NOTIFY
   - Multi-account aggregation
   - Priority-based notification delivery

7. **RFC 6068 Support**
   - Extended message summary format
   - Additional optional fields
   - Backwards compatibility

## Related RFCs

- **RFC 3842**: A Message Summary and Message Waiting Indication Event Package for the Session Initiation Protocol (SIP) [this document]
- **RFC 3265**: Session Initiation Protocol (SIP)-Specific Event Notification (event notification framework)
- **RFC 3680**: A Session Initiation Protocol (SIP) Event Package for Registrations
- **RFC 6068**: Media Feature Tag for Media Streaming (message-context extension)
- **RFC 2822**: Internet Message Format (header format)

## Examples

### Complete SUBSCRIBE Request

```
SUBSCRIBE sip:alice@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKnashds8
Max-Forwards: 70
To: <sip:alice@example.com>
From: <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 SUBSCRIBE
Event: message-summary
Accept: application/simple-message-summary
Expires: 3600
Contact: <sip:alice@192.168.1.100:5060>
Content-Length: 0
```

### Complete NOTIFY Response

```
NOTIFY sip:alice@192.168.1.100:5060 SIP/2.0
Via: SIP/2.0/UDP vmail.example.com:5060;branch=z9hG4bK77ef4c2312983.1
To: <sip:alice@example.com>;tag=1928301774
From: <sip:alice@example.com>;tag=456248
Call-ID: a84b4c76e66710
CSeq: 1 NOTIFY
Event: message-summary
Subscription-State: active;expires=3599
Content-Type: application/simple-message-summary
Content-Length: 189

Messages-Waiting: yes
Message-Account: sip:alice@vmail.example.com
Voice-Message: 4/8 (1/2)
To: alice@atlanta.example.com
From: bob@biloxi.example.com
Subject: carpool tomorrow?
Date: Mon, 02 Jun 2003 13:02:03 GMT
```

### Terminating Subscription

```
NOTIFY sip:alice@192.168.1.100:5060 SIP/2.0
...
Event: message-summary
Subscription-State: terminated;reason=timeout
Content-Type: application/simple-message-summary
Content-Length: 22

Messages-Waiting: no
```

## Version History

- **Initial Implementation** (Current): Complete MessageSummary, MessageContextClass, MessageCounts, MessageHeader types, parsing, and formatting
