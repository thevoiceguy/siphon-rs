# RFC 3841: Caller Preferences Implementation

## Overview

This document describes the implementation of RFC 3841 (Caller Preferences for the Session Initiation Protocol) in the siphon-rs codebase. RFC 3841 allows SIP callers to express preferences about request handling and routing by including Accept-Contact, Reject-Contact, and Request-Disposition headers in their requests.

## RFC 3841 Summary

**RFC 3841** defines mechanisms for callers to express preferences about which user agents should receive their requests and how proxies should handle them. Key concepts:

- **Accept-Contact**: Specifies desired UA capabilities (prefer or require)
- **Reject-Contact**: Specifies undesired UA capabilities (reject if explicitly advertised)
- **Request-Disposition**: Controls proxy behavior (forking, cancellation, recursion, etc.)
- **Q-value Scoring (Qa)**: Computes caller preference scores for routing decisions
- **Modifiers**: `require` and `explicit` modify matching behavior

### Accept-Contact and Reject-Contact

**Accept-Contact** contains feature preferences describing UAs the caller would like to reach:
```
Accept-Contact: *;audio;video;methods="INVITE,BYE"
```

**Reject-Contact** contains feature sets which, if matched, indicate the request should not be routed to that UA:
```
Reject-Contact: *;actor="msg-taker";automata
```

### Modifiers

- **require**: Non-matching contacts are discarded
- **explicit**: Only explicitly advertised features count toward matching

### Request-Disposition

Controls proxy behavior with six directive types:
- **proxy/redirect**: Server operation mode
- **fork/no-fork**: Contact all addresses or only best
- **cancel/no-cancel**: Automatic CANCEL on 2xx or caller handles
- **recurse/no-recurse**: Follow 3xx responses or forward upstream
- **parallel/sequential**: Simultaneous or sequential attempts
- **queue/no-queue**: Wait if busy or immediate rejection

### Q-value Scoring (Qa)

The proxy computes a caller preference score (Qa) for each contact:
1. For each Accept-Contact with N features, assign 1/N points per matched feature
2. Average scores from multiple Accept-Contact headers
3. Sort contacts by callee q-value (primary), then by Qa (secondary)

## Implementation Location

The RFC 3841 implementation is located in:
- **Module**: `crates/sip-core/src/caller_preferences.rs`
- **Exports**: Through `crates/sip-core/src/lib.rs`
- **Dependencies**: Builds on RFC 3840 capabilities in `crates/sip-core/src/capabilities.rs`

## API Reference

### Types

#### `AcceptContact`

RFC 3841 Accept-Contact header field.

Contains feature preferences that describe UAs the caller would like to reach. Multiple Accept-Contact values can appear in a request.

**Fields:**
- `features: BTreeMap<FeatureTag, FeatureValue>` - Desired capabilities
- `require: bool` - If true, non-matching contacts are discarded
- `explicit: bool` - If true, only explicitly advertised features count
- `q: Option<f64>` - Q-value for this preference (0.0 to 1.0)

**Methods:**

##### `new() -> Self`

Creates a new Accept-Contact header.

**Example:**
```rust
use sip_core::AcceptContact;

let accept = AcceptContact::new();
```

---

##### `with_feature(self, tag: FeatureTag, value: FeatureValue) -> Result<Self, CallerPrefsError>`

Adds a feature preference (builder pattern) with validation and limits.

**Example:**
```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap();
```

---

##### `with_require(self) -> Self`

Sets the require modifier (non-matching contacts are discarded).

**Example:**
```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap()
    .with_require();
// Non-matching contacts will be discarded
```

---

##### `with_explicit(self) -> Self`

Sets the explicit modifier (only explicitly advertised features count).

**Example:**
```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap()
    .with_explicit();
// Only contacts that explicitly advertised video support will match
```

---

##### `with_q(self, q: f64) -> Result<Self, CallerPrefsError>`

Sets the q-value for this preference (validated and clamped to 0.0-1.0).

**Example:**
```rust
use sip_core::AcceptContact;

let accept = AcceptContact::new().with_q(0.8).unwrap();
```

---

##### `add_feature(&mut self, tag: FeatureTag, value: FeatureValue) -> Result<(), CallerPrefsError>`

Adds a feature to this Accept-Contact (mutable) with validation and limits.

---

##### `is_empty(&self) -> bool`

Returns true if this Accept-Contact has no features.

---

##### `feature_count(&self) -> usize`

Returns the number of feature parameters.

---

##### `matches(&self, capabilities: &CapabilitySet, has_explicit_features: bool) -> f64`

Checks if a capability set matches this Accept-Contact predicate.

Returns a score between 0.0 and 1.0 indicating match quality:
- Score is 1/N for each of N features that match
- Returns 0.0 if `require` is set and any feature doesn't match
- Returns 0.0 if `explicit` is set and contact didn't advertise features

**Example:**
```rust
use sip_core::{AcceptContact, CapabilitySet, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap();

let mut caps = CapabilitySet::new();
caps.add_boolean(FeatureTag::Audio, true).unwrap();

let score = accept.matches(&caps, true);
assert_eq!(score, 1.0); // Perfect match
```

---

#### `RejectContact`

RFC 3841 Reject-Contact header field.

Contains feature sets which, if matched by a UA, indicate that the request should not be routed to that UA. Per RFC 3841, Reject-Contact only discards contacts that explicitly advertised matching features.

**Fields:**
- `features: BTreeMap<FeatureTag, FeatureValue>` - Rejected capabilities

**Methods:**

##### `new() -> Self`

Creates a new Reject-Contact header.

**Example:**
```rust
use sip_core::RejectContact;

let reject = RejectContact::new();
```

---

##### `with_feature(self, tag: FeatureTag, value: FeatureValue) -> Result<Self, CallerPrefsError>`

Adds a feature to reject (builder pattern) with validation and limits.

**Example:**
```rust
use sip_core::{RejectContact, FeatureTag, FeatureValue};

let reject = RejectContact::new()
    .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
    .unwrap()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap();
// Reject UAs that are automata with video
```

---

##### `add_feature(&mut self, tag: FeatureTag, value: FeatureValue) -> Result<(), CallerPrefsError>`

Adds a feature to this Reject-Contact (mutable) with validation and limits.

---

##### `is_empty(&self) -> bool`

Returns true if this Reject-Contact has no features.

---

##### `matches(&self, capabilities: &CapabilitySet, has_explicit_features: bool) -> bool`

Checks if a capability set should be rejected.

Returns true if the contact explicitly advertised features matching this Reject-Contact predicate. Per RFC 3841, contacts without explicit features are never rejected.

**Example:**
```rust
use sip_core::{RejectContact, CapabilitySet, FeatureTag, FeatureValue};

let reject = RejectContact::new()
    .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
    .unwrap();

let mut caps = CapabilitySet::new();
caps.add_boolean(FeatureTag::Automata, true).unwrap();

// Should reject (contact advertised automata)
assert!(reject.matches(&caps, true));

// Should not reject (no explicit features)
assert!(!reject.matches(&caps, false));
```

---

#### `RequestDisposition`

RFC 3841 Request-Disposition header directives.

Specifies caller preferences for request handling by proxies. Contains directives controlling proxy/redirect behavior, forking, cancellation, recursion, parallelism, and queuing.

**Fields:**
- `proxy: Option<ProxyDirective>` - Proxy or redirect mode
- `fork: Option<ForkDirective>` - Forking behavior
- `cancel: Option<CancelDirective>` - Cancellation behavior
- `recurse: Option<RecurseDirective>` - Recursion behavior (follow 3xx)
- `parallel: Option<ParallelDirective>` - Parallel or sequential forking
- `queue: Option<QueueDirective>` - Queuing behavior when busy

**Methods:**

##### `new() -> Self`

Creates a new Request-Disposition with default (empty) values.

**Example:**
```rust
use sip_core::RequestDisposition;

let rd = RequestDisposition::new();
```

---

##### `with_proxy(self, directive: ProxyDirective) -> Self`

Sets the proxy directive (builder pattern).

**Example:**
```rust
use sip_core::{RequestDisposition, ProxyDirective};

let rd = RequestDisposition::new()
    .with_proxy(ProxyDirective::Proxy);
```

---

##### `with_fork(self, directive: ForkDirective) -> Self`

Sets the fork directive.

---

##### `with_cancel(self, directive: CancelDirective) -> Self`

Sets the cancel directive.

---

##### `with_recurse(self, directive: RecurseDirective) -> Self`

Sets the recurse directive.

---

##### `with_parallel(self, directive: ParallelDirective) -> Self`

Sets the parallel directive.

---

##### `with_queue(self, directive: QueueDirective) -> Self`

Sets the queue directive.

---

##### `is_empty(&self) -> bool`

Returns true if all directives are None.

---

##### `parse(s: &str) -> Option<Self>`

Parses a Request-Disposition from a comma-separated list of directives.

**Example:**
```rust
use sip_core::{RequestDisposition, ProxyDirective, RecurseDirective, ParallelDirective};

let rd = RequestDisposition::parse("proxy, recurse, parallel").unwrap();

assert_eq!(rd.proxy, Some(ProxyDirective::Proxy));
assert_eq!(rd.recurse, Some(RecurseDirective::Recurse));
assert_eq!(rd.parallel, Some(ParallelDirective::Parallel));
```

---

#### Directive Enums

##### `ProxyDirective`

Proxy directive: proxy or redirect mode.

**Variants:**
- `Proxy` - Server should operate in proxy mode
- `Redirect` - Server should operate in redirect mode

**Methods:**
- `as_str(&self) -> &str` - Returns "proxy" or "redirect"

---

##### `ForkDirective`

Fork directive: fork or no-fork.

**Variants:**
- `Fork` - Contact all addresses (default)
- `NoFork` - Contact only best address

**Methods:**
- `as_str(&self) -> &str` - Returns "fork" or "no-fork"

---

##### `CancelDirective`

Cancel directive: cancel or no-cancel.

**Variants:**
- `Cancel` - Send CANCEL on 2xx from another branch (default)
- `NoCancel` - Caller will handle CANCEL

**Methods:**
- `as_str(&self) -> &str` - Returns "cancel" or "no-cancel"

---

##### `RecurseDirective`

Recurse directive: recurse or no-recurse.

**Variants:**
- `Recurse` - Follow 3xx responses (default)
- `NoRecurse` - Forward 3xx responses upstream

**Methods:**
- `as_str(&self) -> &str` - Returns "recurse" or "no-recurse"

---

##### `ParallelDirective`

Parallel directive: parallel or sequential.

**Variants:**
- `Parallel` - Try all branches simultaneously (default)
- `Sequential` - Try branches sequentially

**Methods:**
- `as_str(&self) -> &str` - Returns "parallel" or "sequential"

---

##### `QueueDirective`

Queue directive: queue or no-queue.

**Variants:**
- `Queue` - Wait if busy (receive 182 Queued)
- `NoQueue` - Immediate rejection if unavailable

**Methods:**
- `as_str(&self) -> &str` - Returns "queue" or "no-queue"

---

#### `ScoredContact`

Represents a contact with its callee q-value and computed caller preference score (Qa).

Used for preference-based routing per RFC 3841.

**Fields:**
- `uri: SmolStr` - Contact URI
- `callee_q: f64` - Callee preference (q-value from Contact)
- `caller_qa: f64` - Caller preference score (Qa, 0.0 to 1.0)
- `has_explicit_features: bool` - Whether contact has explicit feature parameters

**Methods:**

##### `new(uri: impl Into<SmolStr>, callee_q: f64) -> Result<Self, CallerPrefsError>`

Creates a new scored contact.

**Example:**
```rust
use sip_core::ScoredContact;

let contact = ScoredContact::new("sip:alice@example.com", 1.0).unwrap();
```

---

##### `with_explicit_features(self, has_features: bool) -> Self`

Sets whether this contact has explicit feature parameters.

---

##### `with_caller_qa(self, qa: f64) -> Result<Self, CallerPrefsError>`

Sets the caller preference score (Qa).

---

### Functions

#### `score_contacts`

```rust
pub fn score_contacts(
    contacts: Vec<ScoredContact>,
    accept_headers: &[AcceptContact],
    reject_headers: &[RejectContact],
    capabilities: &[CapabilitySet],
) -> Result<Vec<ScoredContact>, CallerPrefsError>
```

Computes caller preference scores for contacts based on Accept-Contact headers.

Per RFC 3841, the Qa score is computed by:
1. For each Accept-Contact predicate with N terms, assign 1/N points per matched feature
2. Average scores from multiple Accept-Contact predicates
3. Contacts without explicit features (immune) get Qa = 1.0

Returns contacts sorted by callee q-value (descending), then caller Qa (descending).

**Parameters:**
- `contacts` - List of contacts with callee q-values
- `accept_headers` - Accept-Contact preferences
- `reject_headers` - Reject-Contact filters
- `capabilities` - Capability sets for each contact (must match contact count)

**Returns:**
- Filtered and sorted list of contacts (or an error)

**Example:**
```rust
use sip_core::{
    ScoredContact, AcceptContact, RejectContact,
    CapabilitySet, FeatureTag, FeatureValue
};

let contacts = vec![
    ScoredContact::new("sip:c1@example.com", 1.0)
        .unwrap()
        .with_explicit_features(true),
    ScoredContact::new("sip:c2@example.com", 1.0)
        .unwrap()
        .with_explicit_features(true),
];

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap();

let mut caps1 = CapabilitySet::new();
caps1.add_boolean(FeatureTag::Audio, true).unwrap();

let mut caps2 = CapabilitySet::new();
caps2.add_boolean(FeatureTag::Video, true).unwrap();

let scored = score_contacts(contacts, &[accept], &[], &[caps1, caps2]).unwrap();

// c1 should rank higher (has audio)
assert_eq!(scored[0].uri, "sip:c1@example.com");
```

---

## Usage Patterns

### Basic Caller Preferences

Express preference for video-capable UAs:

```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap();

// Include in INVITE:
// Accept-Contact: *;audio;video
```

### Require Capabilities

Require audio support (discard non-audio UAs):

```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap()
    .with_require();

// Include in INVITE:
// Accept-Contact: *;audio;require
```

### Reject Capabilities

Avoid voicemail systems:

```rust
use sip_core::{RejectContact, FeatureTag, FeatureValue};
use smol_str::SmolStr;

let reject = RejectContact::new()
    .with_feature(FeatureTag::Actor, FeatureValue::Token(SmolStr::new("msg-taker")))
    .unwrap()
    .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
    .unwrap();

// Include in INVITE:
// Reject-Contact: *;actor="msg-taker";automata
```

### Multiple Accept-Contact Headers

Express multiple preferences:

```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};
use smol_str::SmolStr;

// Prefer video
let accept_video = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap();

// Require audio
let accept_audio = AcceptContact::new()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap()
    .with_require();

// Prefer business class
let accept_business = AcceptContact::new()
    .with_feature(FeatureTag::Class, FeatureValue::Token(SmolStr::new("business")))
    .unwrap();

// Include all in INVITE:
// Accept-Contact: *;video
// Accept-Contact: *;audio;require
// Accept-Contact: *;class="business"
```

### Request-Disposition Usage

Control proxy behavior:

```rust
use sip_core::{RequestDisposition, ProxyDirective, RecurseDirective, ParallelDirective};

let rd = RequestDisposition::new()
    .with_proxy(ProxyDirective::Proxy)
    .with_recurse(RecurseDirective::Recurse)
    .with_parallel(ParallelDirective::Parallel);

// Include in INVITE:
// Request-Disposition: proxy, recurse, parallel
```

### No Forking

Call only the best contact:

```rust
use sip_core::{RequestDisposition, ForkDirective};

let rd = RequestDisposition::new()
    .with_fork(ForkDirective::NoFork);

// Include in INVITE:
// Request-Disposition: no-fork
```

### Proxy Routing with Preferences

Complete proxy routing example:

```rust
use sip_core::{
    ScoredContact, AcceptContact, RejectContact,
    CapabilitySet, FeatureTag, FeatureValue,
    score_contacts
};
use smol_str::SmolStr;

// Caller preferences
let accept = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap()
    .with_feature(FeatureTag::Audio, FeatureValue::Boolean(true))
    .unwrap();

let reject = RejectContact::new()
    .with_feature(FeatureTag::Automata, FeatureValue::Boolean(true))
    .unwrap();

// Registered contacts
let contacts = vec![
    ScoredContact::new("sip:alice@192.168.1.100", 1.0)
        .unwrap()
        .with_explicit_features(true),
    ScoredContact::new("sip:alice@10.0.0.50", 0.8)
        .unwrap()
        .with_explicit_features(true),
    ScoredContact::new("sip:voicemail@example.com", 0.5)
        .unwrap()
        .with_explicit_features(true),
];

// Contact capabilities
let mut caps1 = CapabilitySet::new();
caps1.add_boolean(FeatureTag::Audio, true).unwrap();
caps1.add_boolean(FeatureTag::Video, true).unwrap();

let mut caps2 = CapabilitySet::new();
caps2.add_boolean(FeatureTag::Audio, true).unwrap();

let mut caps3 = CapabilitySet::new();
caps3.add_boolean(FeatureTag::Audio, true).unwrap();
caps3.add_boolean(FeatureTag::Automata, true).unwrap();

// Score and filter contacts
let scored = score_contacts(
    contacts,
    &[accept],
    &[reject],
    &[caps1, caps2, caps3]
).unwrap();

// Result:
// 1. alice@192.168.1.100 (q=1.0, Qa=1.0 - has audio+video)
// 2. alice@10.0.0.50 (q=0.8, Qa=0.5 - has audio only)
// voicemail rejected (automata)

for contact in scored {
    println!("Try {}: q={}, Qa={}", contact.uri, contact.callee_q, contact.caller_qa);
}
```

### Explicit Modifier Usage

Only consider UAs that explicitly advertised features:

```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap()
    .with_explicit();

// Only UAs that explicitly advertised video support will match
// UAs without explicit features get score 0.0
```

### Combined require and explicit

Most restrictive matching:

```rust
use sip_core::{AcceptContact, FeatureTag, FeatureValue};

let accept = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap()
    .with_require()
    .with_explicit();

// Only UAs that:
// 1. Explicitly advertised video support, AND
// 2. Actually support video
// All others are discarded
```

## Integration with Other Components

### With RFC 3840 Capabilities

RFC 3841 builds directly on RFC 3840's capability framework:

```rust
use sip_core::{
    CapabilitySet, FeatureTag,
    AcceptContact, FeatureValue
};

// UA advertises capabilities (RFC 3840)
let mut capabilities = CapabilitySet::new();
capabilities.add_boolean(FeatureTag::Audio, true).unwrap();
capabilities.add_boolean(FeatureTag::Video, true).unwrap();

// Caller expresses preferences (RFC 3841)
let accept = AcceptContact::new()
    .with_feature(FeatureTag::Video, FeatureValue::Boolean(true))
    .unwrap();

// Check match
let score = accept.matches(&capabilities, true);
```

### With SIP INVITE

Include preferences in INVITE requests:

```
INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKnashds8
Max-Forwards: 70
To: Bob <sip:bob@example.com>
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 INVITE
Accept-Contact: *;audio;video
Reject-Contact: *;automata;actor="msg-taker"
Request-Disposition: proxy, recurse, parallel
Contact: <sip:alice@192.168.1.100:5060>
Content-Type: application/sdp
Content-Length: ...

[SDP body]
```

### With Proxy Routing

Proxy processing algorithm:

1. Parse Accept-Contact, Reject-Contact, Request-Disposition
2. Retrieve registered contacts from location service
3. Extract capabilities from each contact
4. Apply Reject-Contact filters
5. Compute Qa scores using Accept-Contact
6. Sort by q-value (primary), then Qa (secondary)
7. Fork according to Request-Disposition

```rust
use sip_core::{AcceptContact, RejectContact, score_contacts};

// Parse headers from INVITE
let accept_headers: Vec<AcceptContact> = /* parse from request */;
let reject_headers: Vec<RejectContact> = /* parse from request */;

// Get registered contacts
let contacts = location_service.get_contacts(&aor);

// Extract capabilities
let capabilities: Vec<_> = contacts.iter()
    .map(|c| c.capabilities().unwrap())
    .collect();

// Score and filter
let scored = score_contacts(
    contacts,
    &accept_headers,
    &reject_headers,
    &capabilities
).unwrap();

// Route to contacts in order
for contact in scored {
    // Fork to contact.uri
}
```

### With Request-Disposition

Control forking behavior:

```rust
use sip_core::{RequestDisposition, ForkDirective};

let rd = RequestDisposition::parse(&request_disposition_value)?;

match rd.fork {
    Some(ForkDirective::Fork) => {
        // Fork to all scored contacts
        for contact in scored {
            fork_to(contact.uri);
        }
    }
    Some(ForkDirective::NoFork) => {
        // Try only best contact
        if let Some(best) = scored.first() {
            route_to(best.uri);
        }
    }
    None => {
        // Default: fork to all
        for contact in scored {
            fork_to(contact.uri);
        }
    }
}
```

## Test Coverage

The caller preferences implementation includes 15 comprehensive unit tests:

### Accept-Contact Tests

1. **accept_contact_creation**: Basic creation with modifiers
2. **accept_contact_matching**: Perfect match scoring (1.0)
3. **accept_contact_require_fails**: Required feature missing returns 0.0
4. **accept_contact_explicit_without_features**: Explicit modifier with no features returns 0.0
5. **accept_contact_partial_match**: Partial match returns fractional score (0.5)

### Reject-Contact Tests

6. **reject_contact_creation**: Basic creation
7. **reject_contact_matches**: Matching features triggers rejection
8. **reject_contact_no_explicit_features**: No rejection without explicit features

### Request-Disposition Tests

9. **request_disposition_parse**: Parsing comma-separated directives
10. **request_disposition_display**: Formatting to string

### ScoredContact Tests

11. **scored_contact_creation**: Creating scored contacts with q-values

### Scoring Tests

12. **score_contacts_basic**: Basic Qa scoring with Accept-Contact
13. **score_contacts_with_reject**: Reject-Contact filtering
14. **score_contacts_require_filter**: Required features eliminate contacts
15. **score_contacts_sorting**: Sorting by q-value then Qa

### Running Tests

```bash
# Run all caller preferences tests
cargo test --package sip-core caller_preferences

# Run specific test
cargo test --package sip-core accept_contact_matching

# Run with output
cargo test --package sip-core caller_preferences -- --nocapture
```

## Limitations and Future Work

### Current Limitations

1. **No Header Parsing**: AcceptContact, RejectContact, and RequestDisposition structs are provided but SIP message parsing/serialization is not implemented

2. **No Implicit Preferences**: RFC 3841 Section 9.1 implicit preference inference (from method, Event header) not implemented

3. **No Proxy Implementation**: Routing logic using preferences not implemented (structures only)

4. **No Fallback Logic**: RFC 3841 Section 7.2.4 fallback when all contacts eliminated not implemented

5. **No Feature Parameter Parsing**: Full RFC 2533 predicate parsing (negation, numeric ranges, etc.) not implemented

6. **No Compact Forms**: Compact form headers ("a" for Accept-Contact, "j" for Reject-Contact) recognized but not generated

### Future Enhancements

1. **Header Parsing and Serialization**
   - Parse Accept-Contact from SIP messages
   - Parse Reject-Contact from SIP messages
   - Parse Request-Disposition from SIP messages
   - Serialize to SIP header format

2. **Complete RFC 2533 Support**
   - Negation (!) operators
   - Numeric comparisons (#>=, #<=, #=)
   - Numeric ranges
   - Complex disjunctions

3. **Implicit Preferences**
   - Infer capabilities from request method
   - Infer capabilities from Event header
   - Apply implicit preferences when explicit ones absent

4. **Proxy Routing Implementation**
   - Complete routing algorithm
   - Fallback logic when all contacts eliminated
   - Response handling (405, 489)

5. **Request-Disposition Processing**
   - Implement all directive behaviors
   - Fork/no-fork logic
   - Sequential vs. parallel forking
   - Queue handling (182 Queued)

6. **Optimization**
   - Cache parsed Accept-Contact predicates
   - Optimize scoring for large contact lists
   - Parallel capability matching

7. **Q-value Extensions**
   - Support q-values in Accept-Contact headers
   - Weight preferences by q-values
   - Complex scoring algorithms

8. **RFC 4596 Guidelines**
   - Implement best practices from RFC 4596
   - Usage guidelines for specific scenarios

## Related RFCs

- **RFC 3841**: Caller Preferences for the Session Initiation Protocol (SIP) [this document]
- **RFC 3840**: Indicating User Agent Capabilities in the Session Initiation Protocol (SIP) [foundation]
- **RFC 2533**: A Syntax for Describing Media Feature Sets
- **RFC 4596**: Guidelines for Usage of the Session Initiation Protocol (SIP) Caller Preferences Extension
- **RFC 3261**: SIP: Session Initiation Protocol

## Examples

### Complete INVITE with Caller Preferences

```
INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKnashds8
Max-Forwards: 70
To: Bob <sip:bob@example.com>
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 INVITE
Accept-Contact: *;audio;require
Accept-Contact: *;video;explicit
Accept-Contact: *;methods="BYE";class="business";q=1.0
Reject-Contact: *;actor="msg-taker";video
Request-Disposition: proxy, recurse, parallel
Contact: <sip:alice@192.168.1.100:5060>;audio;video
Content-Type: application/sdp
Content-Length: 247

[SDP body]
```

### Compact Form

```
INVITE sip:bob@example.com SIP/2.0
...
a: *;audio;video
j: *;automata
d: proxy, no-fork
...
```

## Version History

- **Initial Implementation** (Current): Complete Accept-Contact, Reject-Contact, Request-Disposition types, Q-value scoring logic, and preference matching
