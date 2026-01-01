# RFC 3840: Callee Capabilities Implementation

## Overview

This document describes the implementation of RFC 3840 (Indicating User Agent Capabilities in the Session Initiation Protocol) in the siphon-rs codebase. RFC 3840 provides mechanisms for SIP user agents to communicate their capabilities and characteristics through feature tags conveyed as Contact header parameters.

## RFC 3840 Summary

**RFC 3840** defines how SIP user agents indicate their capabilities to other UAs and registrars. Key concepts:

- **Feature Tags**: Identifiers representing specific UA properties or capabilities
- **Contact Parameters**: Capabilities encoded as Contact header field parameters
- **Registration**: Capabilities registered with REGISTER requests
- **Discovery**: Capabilities queried via OPTIONS requests
- **Intelligent Routing**: Enables preference-based call routing based on UA capabilities

### Feature Tag Categories

1. **Media Types**: Audio, video, application, data, control, text streaming support
2. **Protocol Support**: Supported methods, extensions, URI schemes, event packages
3. **Device Properties**: Automata, class, duplex, mobility
4. **Descriptive**: Human-readable descriptions, languages

### Contact Header Encoding

Feature tags are encoded as Contact header parameters with the "sip." prefix stripped:

```
Contact: <sip:alice@192.168.1.100:5060>;audio;video;methods="INVITE,BYE"
```

In this example:
- `audio` = sip.audio feature tag (boolean, true)
- `video` = sip.video feature tag (boolean, true)
- `methods="INVITE,BYE"` = sip.methods feature tag (token list)

## Implementation Location

The RFC 3840 implementation is located in:
- **Module**: `crates/sip-core/src/capabilities.rs`
- **Exports**: Through `crates/sip-core/src/lib.rs`
- **Contact Integration**: Enhanced `ContactHeader` in `crates/sip-core/src/contact.rs`

## API Reference

### Enums and Types

#### `FeatureTag`

Enumeration of RFC 3840 feature tags for indicating UA capabilities.

**Variants:**

**Media Type Tags:**
- `Audio` - Audio media streaming support (sip.audio)
- `Video` - Video media streaming support (sip.video)
- `Application` - Application media streaming support (sip.application)
- `Data` - Data media streaming support (sip.data)
- `Control` - Control media streaming support (sip.control)
- `Text` - Text media streaming support (sip.text)

**Device Property Tags:**
- `Automata` - Whether the UA is an automaton vs. human (sip.automata)
- `Class` - Device class: business or personal (sip.class)
- `Duplex` - Duplex mode: full, half, send-only, receive-only (sip.duplex)
- `Mobility` - Mobility: fixed or mobile (sip.mobility)
- `Description` - Human-readable description (sip.description)

**Protocol Support Tags:**
- `Events` - Supported event packages (sip.events)
- `Priority` - Supported priority values (sip.priority)
- `Methods` - Supported SIP methods (sip.methods)
- `Schemes` - Supported URI schemes (sip.schemes)
- `Extensions` - Supported SIP extensions (sip.extensions)

**Special Tags:**
- `IsFocus` - Whether UA is a conference focus (sip.isfocus)
- `Actor` - Actor type: principal, attendant, msg-taker, information (sip.actor)
- `Language` - Supported languages (sip.language)

**Methods:**

##### `as_str(&self) -> &str`

Returns the feature tag name with "sip." prefix (as used in RFC 3840).

**Examples:**
```rust
use sip_core::FeatureTag;

assert_eq!(FeatureTag::Audio.as_str(), "sip.audio");
assert_eq!(FeatureTag::Methods.as_str(), "sip.methods");
```

---

##### `param_name(&self) -> &str`

Returns the Contact header parameter name (without "sip." prefix).

Per RFC 3840, the "sip." prefix is stripped when encoding as Contact parameters.

**Examples:**
```rust
use sip_core::FeatureTag;

assert_eq!(FeatureTag::Audio.param_name(), "audio");
assert_eq!(FeatureTag::IsFocus.param_name(), "isfocus");
```

---

##### `from_param_name(name: &str) -> Option<FeatureTag>`

Parses a feature tag from a parameter name (without "sip." prefix).

**Examples:**
```rust
use sip_core::FeatureTag;

assert_eq!(FeatureTag::from_param_name("audio"), Some(FeatureTag::Audio));
assert_eq!(FeatureTag::from_param_name("VIDEO"), Some(FeatureTag::Video));
assert_eq!(FeatureTag::from_param_name("unknown"), None);
```

---

##### `is_media_type(&self) -> bool`

Returns true if this feature tag represents a media type capability.

**Examples:**
```rust
use sip_core::FeatureTag;

assert!(FeatureTag::Audio.is_media_type());
assert!(FeatureTag::Video.is_media_type());
assert!(!FeatureTag::Methods.is_media_type());
```

---

##### `is_list_valued(&self) -> bool`

Returns true if this feature tag represents a list-valued capability.

**Examples:**
```rust
use sip_core::FeatureTag;

assert!(FeatureTag::Methods.is_list_valued());
assert!(FeatureTag::Events.is_list_valued());
assert!(!FeatureTag::Audio.is_list_valued());
```

---

#### `FeatureValue`

Enumeration of feature tag value types per RFC 3840.

**Variants:**

- `Boolean(bool)` - Boolean value (parameter presence = true)
- `Token(SmolStr)` - Single token value (e.g., "fixed", "mobile")
- `TokenList(Vec<SmolStr>)` - List of token values (e.g., ["INVITE", "BYE"])
- `String(SmolStr)` - String value (quoted)
- `Numeric(f64)` - Numeric value

**Methods:**

##### `is_true(&self) -> bool`

Returns true if this is a boolean true value.

---

##### `is_false(&self) -> bool`

Returns true if this is a boolean false value.

---

##### `as_token(&self) -> Option<&SmolStr>`

Returns the token value if this is a Token variant.

---

##### `as_token_list(&self) -> Option<&[SmolStr]>`

Returns the token list if this is a TokenList variant.

---

##### `as_string(&self) -> Option<&SmolStr>`

Returns the string value if this is a String variant.

---

##### `as_numeric(&self) -> Option<f64>`

Returns the numeric value if this is a Numeric variant.

---

##### `to_param_value(&self) -> Result<Option<SmolStr>, CapabilityError>`

Converts this feature value to a Contact header parameter value.

**Encoding Rules (per RFC 3840):**
- Boolean true: no value (parameter name only)
- Boolean false: not included in Contact
- Token: unquoted value
- TokenList: comma-separated quoted values
- String: quoted value
- Numeric: unquoted numeric value

**Examples:**
```rust
use sip_core::FeatureValue;
use smol_str::SmolStr;

let bool_val = FeatureValue::Boolean(true);
assert_eq!(bool_val.to_param_value()?, None); // No value for boolean

let token_val = FeatureValue::Token(SmolStr::new("fixed"));
assert_eq!(token_val.to_param_value()?, Some(SmolStr::new("fixed")));

let list_val = FeatureValue::TokenList(vec![
    SmolStr::new("INVITE"),
    SmolStr::new("BYE")
]);
assert_eq!(
    list_val.to_param_value()?,
    Some(SmolStr::new("\"INVITE,BYE\""))
);
```

---

##### `from_param_value(tag: FeatureTag, value: Option<&str>) -> Result<FeatureValue, CapabilityError>`

Parses a feature value from a Contact header parameter value.

The tag is needed to determine the expected value type.

**Examples:**
```rust
use sip_core::{FeatureTag, FeatureValue};
use smol_str::SmolStr;

// Boolean (no value)
let val = FeatureValue::from_param_value(FeatureTag::Audio, None)?;
assert_eq!(val, FeatureValue::Boolean(true));

// Token
let val = FeatureValue::from_param_value(FeatureTag::Mobility, Some("fixed"))?;
assert_eq!(val, FeatureValue::Token(SmolStr::new("fixed")));

// Token list
let val = FeatureValue::from_param_value(FeatureTag::Methods, Some("\"INVITE,BYE\""))?;
assert_eq!(
    val,
    FeatureValue::TokenList(vec![SmolStr::new("INVITE"), SmolStr::new("BYE")])
);
```

---

#### `Capability`

Represents a single capability (feature tag + value).

**Fields:**
- `tag: FeatureTag` - The feature tag (private, use accessors)
- `value: FeatureValue` - The feature value (private, use accessors)

**Methods:**

##### `new(tag: FeatureTag, value: FeatureValue) -> Result<Self, CapabilityError>`

Creates a new capability.

---

##### `boolean(tag: FeatureTag, value: bool) -> Result<Self, CapabilityError>`

Creates a boolean capability.

**Example:**
```rust
use sip_core::{Capability, FeatureTag};

let cap = Capability::boolean(FeatureTag::Audio, true)?;
```

---

##### `token(tag: FeatureTag, value: impl Into<SmolStr>) -> Result<Self, CapabilityError>`

Creates a token capability.

**Example:**
```rust
use sip_core::{Capability, FeatureTag};

let cap = Capability::token(FeatureTag::Mobility, "mobile")?;
```

---

##### `token_list(tag: FeatureTag, values: Vec<SmolStr>) -> Result<Self, CapabilityError>`

Creates a token list capability.

**Example:**
```rust
use sip_core::{Capability, FeatureTag};
use smol_str::SmolStr;

let cap = Capability::token_list(
    FeatureTag::Methods,
    vec![SmolStr::new("INVITE"), SmolStr::new("BYE")]
)
?;
```

---

##### `string(tag: FeatureTag, value: impl Into<SmolStr>) -> Result<Self, CapabilityError>`

Creates a string capability.

**Example:**
```rust
use sip_core::{Capability, FeatureTag};

let cap = Capability::string(FeatureTag::Description, "Alice's Phone")?;
```

---

##### `numeric(tag: FeatureTag, value: f64) -> Result<Self, CapabilityError>`

Creates a numeric capability.

---

##### `param_name(&self) -> &str`

Returns the Contact header parameter name for this capability.

---

##### `param_value(&self) -> Result<Option<SmolStr>, CapabilityError>`

Returns the Contact header parameter value for this capability.

---

##### `to_param(&self) -> Result<(SmolStr, Option<SmolStr>), CapabilityError>`

Converts this capability to a (name, value) pair for Contact parameters.

---

#### `CapabilitySet`

A set of UA capabilities (RFC 3840).

This represents the complete capability set of a user agent, typically
conveyed in the Contact header of REGISTER or OPTIONS messages.

**Methods:**

##### `new() -> Self`

Creates a new empty capability set.

**Example:**
```rust
use sip_core::CapabilitySet;

let mut capabilities = CapabilitySet::new();
```

---

##### `add(&mut self, capability: Capability) -> Result<(), CapabilityError>`

Adds a capability to the set.

**Example:**
```rust
use sip_core::{CapabilitySet, Capability, FeatureTag};

let mut set = CapabilitySet::new();
set.add(Capability::boolean(FeatureTag::Audio, true)?)?;
```

---

##### `add_boolean(&mut self, tag: FeatureTag, value: bool) -> Result<(), CapabilityError>`

Adds a boolean capability.

**Example:**
```rust
use sip_core::{CapabilitySet, FeatureTag};

let mut set = CapabilitySet::new();
set.add_boolean(FeatureTag::Audio, true)?;
set.add_boolean(FeatureTag::Video, true)?;
```

---

##### `add_token(&mut self, tag: FeatureTag, value: impl Into<SmolStr>) -> Result<(), CapabilityError>`

Adds a token capability.

---

##### `add_token_list(&mut self, tag: FeatureTag, values: Vec<SmolStr>) -> Result<(), CapabilityError>`

Adds a token list capability.

---

##### `add_string(&mut self, tag: FeatureTag, value: impl Into<SmolStr>) -> Result<(), CapabilityError>`

Adds a string capability.

---

##### `add_numeric(&mut self, tag: FeatureTag, value: f64) -> Result<(), CapabilityError>`

Adds a numeric capability.

---

##### `get(&self, tag: FeatureTag) -> Option<&FeatureValue>`

Gets a capability value by tag.

**Example:**
```rust
use sip_core::{CapabilitySet, FeatureTag};

let mut set = CapabilitySet::new();
set.add_boolean(FeatureTag::Audio, true)?;

assert!(set.get(FeatureTag::Audio).is_some());
assert!(set.get(FeatureTag::Video).is_none());
```

---

##### `has(&self, tag: FeatureTag) -> bool`

Returns true if the set contains the given capability tag.

---

##### `iter(&self) -> impl Iterator<Item = Capability>`

Returns an iterator over all capabilities.

---

##### `len(&self) -> usize`

Returns the number of capabilities in the set.

---

##### `is_empty(&self) -> bool`

Returns true if the set is empty.

---

##### `to_params(&self) -> Result<BTreeMap<SmolStr, Option<SmolStr>>, CapabilityError>`

Converts the capability set to Contact header parameters.

Returns a map of parameter names to optional values suitable for
inclusion in a Contact header.

**Example:**
```rust
use sip_core::{CapabilitySet, FeatureTag};
use smol_str::SmolStr;

let mut set = CapabilitySet::new();
set.add_boolean(FeatureTag::Audio, true)?;
set.add_token(FeatureTag::Mobility, "fixed")?;

let params = set.to_params()?;
assert_eq!(params.get(&SmolStr::new("audio")), Some(&None));
assert_eq!(params.get(&SmolStr::new("mobility")), Some(&Some(SmolStr::new("fixed"))));
```

---

##### `from_params(params: &BTreeMap<SmolStr, Option<SmolStr>>) -> Result<Self, CapabilityError>`

Parses a capability set from Contact header parameters.

**Example:**
```rust
use sip_core::{CapabilitySet, FeatureTag};
use smol_str::SmolStr;
use std::collections::BTreeMap;

let mut params = BTreeMap::new();
params.insert(SmolStr::new("audio"), None);
params.insert(SmolStr::new("video"), None);

let set = CapabilitySet::from_params(&params)?;
assert!(set.has(FeatureTag::Audio));
assert!(set.has(FeatureTag::Video));
```

---

##### `matches(&self, required: &CapabilitySet) -> bool`

Checks if this capability set matches the given requirements.

A capability set matches if:
- For boolean: required capability is present and true
- For token: values match (case-insensitive)
- For token list: all required tokens are present in the list
- For string: strings match exactly
- For numeric: values match (within floating-point epsilon)

**Example:**
```rust
use sip_core::{CapabilitySet, FeatureTag};

let mut available = CapabilitySet::new();
available.add_boolean(FeatureTag::Audio, true)?;
available.add_boolean(FeatureTag::Video, true)?;

let mut required = CapabilitySet::new();
required.add_boolean(FeatureTag::Audio, true)?;

assert!(available.matches(&required));

// Require text (not available)
required.add_boolean(FeatureTag::Text, true)?;
assert!(!available.matches(&required));
```

---

### ContactHeader Integration

#### `ContactHeader::capabilities(&self) -> Result<CapabilitySet, CapabilityError>`

Extracts RFC 3840 capabilities from Contact header parameters.

This parses capability feature tags (like audio, video, methods, etc.)
from the Contact header parameters and returns them as a CapabilitySet.

**Example:**
```rust
use sip_core::{ContactHeader, NameAddr, SipUri, Uri, FeatureTag};
use std::collections::BTreeMap;
use smol_str::SmolStr;

let mut params = BTreeMap::new();
params.insert(SmolStr::new("audio"), None);
params.insert(SmolStr::new("video"), None);

let name_addr = NameAddr::new(
    None,
    Uri::from(SipUri::parse("sip:alice@example.com")?),
    params,
)
?;

let contact = ContactHeader::new(name_addr);
let capabilities = contact.capabilities()?;

assert!(capabilities.has(FeatureTag::Audio));
assert!(capabilities.has(FeatureTag::Video));
```

## Usage Patterns

### Registering Capabilities

When a UA registers, it should include its capabilities as Contact parameters:

```rust
use sip_core::{CapabilitySet, FeatureTag};
use smol_str::SmolStr;

// Build capability set
let mut capabilities = CapabilitySet::new();
capabilities.add_boolean(FeatureTag::Audio, true)?;
capabilities.add_boolean(FeatureTag::Video, true)?;
capabilities.add_token(FeatureTag::Mobility, "mobile")?;
capabilities.add_token_list(
    FeatureTag::Methods,
    vec![
        SmolStr::new("INVITE"),
        SmolStr::new("ACK"),
        SmolStr::new("BYE"),
        SmolStr::new("CANCEL"),
    ]
)
?;

// Convert to Contact parameters
let params = capabilities.to_params()?;

// Add to Contact header when building REGISTER request
// Contact: <sip:alice@192.168.1.100:5060>;audio;video;mobility=mobile;methods="INVITE,ACK,BYE,CANCEL"
```

### Querying Capabilities (OPTIONS)

When responding to OPTIONS, include capabilities:

```rust
use sip_core::{CapabilitySet, FeatureTag};

let mut capabilities = CapabilitySet::new();
capabilities.add_boolean(FeatureTag::Audio, true)?;
capabilities.add_boolean(FeatureTag::Video, true)?;
capabilities.add_boolean(FeatureTag::IsFocus, false)?; // Not a conference server

let params = capabilities.to_params()?;
// Include in 200 OK Contact header
```

### Parsing Received Capabilities

When receiving a Contact with capabilities:

```rust
use sip_core::{ContactHeader, FeatureTag};
use std::collections::BTreeMap;
use smol_str::SmolStr;

// Parse Contact header (example)
// Contact: <sip:bob@10.0.0.5:5060>;audio;video;methods="INVITE,BYE"

// Extract capabilities
let contact: ContactHeader = /* parsed from message */;
let capabilities = contact.capabilities()?;

// Check what the UA supports
if capabilities.has(FeatureTag::Audio) {
    println!("UA supports audio");
}

if capabilities.has(FeatureTag::Video) {
    println!("UA supports video");
}

if let Some(methods) = capabilities.get(FeatureTag::Methods) {
    if let Some(method_list) = methods.as_token_list() {
        println!("Supported methods: {:?}", method_list);
    }
}
```

### Capability Matching

Check if a UA meets requirements:

```rust
use sip_core::{CapabilitySet, FeatureTag};
use smol_str::SmolStr;

// UA's advertised capabilities
let mut available = CapabilitySet::new();
available.add_boolean(FeatureTag::Audio, true)?;
available.add_boolean(FeatureTag::Video, true)?;
available.add_token_list(
    FeatureTag::Methods,
    vec![
        SmolStr::new("INVITE"),
        SmolStr::new("ACK"),
        SmolStr::new("BYE"),
        SmolStr::new("CANCEL"),
        SmolStr::new("OPTIONS"),
    ]
)
?;

// Requirements for a video call
let mut required = CapabilitySet::new();
required.add_boolean(FeatureTag::Audio, true)?;
required.add_boolean(FeatureTag::Video, true)?;
required.add_token_list(
    FeatureTag::Methods,
    vec![SmolStr::new("INVITE"), SmolStr::new("BYE")]
)
?;

if available.matches(&required) {
    println!("UA meets requirements for video call");
    // Route call to this UA
} else {
    println!("UA does not meet requirements");
    // Try another UA or fallback
}
```

### Building Full Capability Profile

Complete example of building a comprehensive UA capability profile:

```rust
use sip_core::{CapabilitySet, FeatureTag};
use smol_str::SmolStr;

let mut capabilities = CapabilitySet::new();

// Media capabilities
capabilities.add_boolean(FeatureTag::Audio, true)?;
capabilities.add_boolean(FeatureTag::Video, true)?;
capabilities.add_boolean(FeatureTag::Text, true)?;

// Device properties
capabilities.add_boolean(FeatureTag::Automata, false)?; // Human-operated
capabilities.add_token(FeatureTag::Class, "personal")?;
capabilities.add_token(FeatureTag::Duplex, "full")?;
capabilities.add_token(FeatureTag::Mobility, "mobile")?;

// Descriptive information
capabilities.add_string(FeatureTag::Description, "iPhone 15 Pro")?;
capabilities.add_string(FeatureTag::Language, "en")?;

// Protocol support
capabilities.add_token_list(
    FeatureTag::Methods,
    vec![
        SmolStr::new("INVITE"),
        SmolStr::new("ACK"),
        SmolStr::new("BYE"),
        SmolStr::new("CANCEL"),
        SmolStr::new("OPTIONS"),
        SmolStr::new("REGISTER"),
        SmolStr::new("SUBSCRIBE"),
        SmolStr::new("NOTIFY"),
        SmolStr::new("MESSAGE"),
    ]
)
?;

capabilities.add_token_list(
    FeatureTag::Events,
    vec![
        SmolStr::new("presence"),
        SmolStr::new("message-summary"),
        SmolStr::new("reg"),
    ]
)
?;

capabilities.add_token_list(
    FeatureTag::Schemes,
    vec![
        SmolStr::new("sip"),
        SmolStr::new("sips"),
        SmolStr::new("tel"),
    ]
)
?;

// Conference capabilities
capabilities.add_boolean(FeatureTag::IsFocus, false)?;

// Actor type
capabilities.add_token(FeatureTag::Actor, "principal")?;

// Convert to params for Contact header
let params = capabilities.to_params()?;
```

## Integration with Other Components

### With SIP REGISTER

When sending REGISTER:

```rust
// Build REGISTER request with capabilities in Contact
let mut capabilities = CapabilitySet::new();
capabilities.add_boolean(FeatureTag::Audio, true)?;
capabilities.add_boolean(FeatureTag::Video, true)?;

let params = capabilities.to_params()?;

// Create NameAddr with capabilities
let name_addr = NameAddr::new(
    Some(SmolStr::new("Alice")),
    contact_uri,
    params, // Include capability parameters
)
?;

let contact = ContactHeader::new(name_addr);
// Add contact to REGISTER request
```

### With SIP OPTIONS

When responding to OPTIONS:

```rust
// Parse OPTIONS request
// Build 200 OK response with capabilities

let mut capabilities = CapabilitySet::new();
// ... add capabilities ...

let params = capabilities.to_params()?;

// Include in Contact header of 200 OK response
```

### With Caller Preferences (RFC 3841)

RFC 3840 capabilities are used by RFC 3841 (Caller Preferences) for intelligent routing. Capabilities advertised by UAs can be matched against caller preferences to route calls optimally.

**Example: Route to video-capable UAs**
```rust
// Caller preferences require video
let mut required_caps = CapabilitySet::new();
required_caps.add_boolean(FeatureTag::Video, true)?;

// Check each registered contact
for contact in registered_contacts {
    let ua_caps = contact.capabilities()?;
    if ua_caps.matches(&required_caps) {
        // This UA can handle video calls
        // Add to routing list
    }
}
```

### With Proxy/Registrar

A SIP proxy or registrar should:

1. Store capabilities from REGISTER Contact headers
2. Use capabilities for intelligent routing decisions
3. Return capabilities in location service queries

```rust
// Store registration with capabilities
struct Registration {
    aor: String,
    contact_uri: SipUri,
    capabilities: CapabilitySet,
    expires: u32,
}

// When routing a call, match against requirements
fn find_best_contact(
    registrations: &[Registration],
    required_caps: &CapabilitySet
) -> Option<&Registration> {
    registrations
        .iter()
        .find(|reg| reg.capabilities.matches(required_caps))
}
```

## Test Coverage

The capabilities implementation includes 24 comprehensive unit tests:

### Feature Tag Tests

1. **feature_tag_names**: Verifies feature tag names with "sip." prefix
2. **feature_tag_param_names**: Verifies parameter names without "sip." prefix
3. **feature_tag_from_param_name**: Tests parsing from parameter names
4. **feature_tag_is_media_type**: Tests media type classification
5. **feature_tag_is_list_valued**: Tests list-valued tag identification

### Feature Value Tests

6. **boolean_feature_value**: Boolean value creation and encoding
7. **token_feature_value**: Token value creation and encoding
8. **token_list_feature_value**: Token list creation and encoding
9. **string_feature_value**: String value creation and encoding
10. **numeric_feature_value**: Numeric value creation and encoding
11. **parse_feature_value_boolean**: Parsing boolean from parameters
12. **parse_feature_value_token**: Parsing token from parameters
13. **parse_feature_value_token_list**: Parsing token list from parameters
14. **parse_feature_value_string**: Parsing string from parameters
15. **parse_token_list_with_spaces**: Token list parsing with whitespace

### Capability Tests

16. **capability_creation**: Basic capability construction
17. **capability_to_param**: Conversion to Contact parameters

### CapabilitySet Tests

18. **capability_set_add_and_get**: Adding and retrieving capabilities
19. **capability_set_to_params**: Converting set to Contact parameters
20. **capability_set_from_params**: Parsing set from Contact parameters
21. **capability_set_matching_boolean**: Boolean capability matching
22. **capability_set_matching_token**: Token capability matching
23. **capability_set_matching_token_list**: Token list matching (subset check)
24. **capability_set_iteration**: Iterating over capability set

### Running Tests

```bash
# Run all capabilities tests
cargo test --package sip-core capabilities

# Run specific test
cargo test --package sip-core boolean_feature_value

# Run with output
cargo test --package sip-core capabilities -- --nocapture
```

## Limitations and Future Work

### Current Limitations

1. **No Accept-Contact/Reject-Contact**: RFC 3841 (Caller Preferences) headers not yet implemented

2. **No Proxy Routing Logic**: Capability-based routing logic for proxies not implemented

3. **No Extension Feature Tags**: Only standard RFC 3840 feature tags supported; custom extension tags (with "+" prefix) not implemented

4. **No Capability Negotiation**: No automatic capability negotiation between UAs

5. **No GRUU Integration**: RFC 5627 (GRUU) integration with capabilities not implemented

### Future Enhancements

1. **RFC 3841 Implementation (Caller Preferences)**
   - Implement Accept-Contact header
   - Implement Reject-Contact header
   - Implement Request-Disposition header
   - Add preference matching logic

2. **Extension Feature Tags**
   - Support custom feature tags with "+" prefix
   - Vendor-specific capabilities

3. **Capability-Based Routing**
   - Implement routing logic for proxies
   - Score contacts based on capability matching
   - Parallel forking based on capabilities

4. **Capability Negotiation**
   - Automatic capability exchange
   - Fallback mechanisms (e.g., video to audio)

5. **GRUU Integration**
   - Associate capabilities with GRUUs
   - Capability-specific routing to GRUUs

6. **Capability Update Notifications**
   - Notify subscribers when capabilities change
   - Integration with presence (RFC 3856)

7. **Validation and Constraints**
   - Validate capability combinations
   - Enforce constraints (e.g., video requires audio)

8. **Performance Optimizations**
   - Cache capability sets
   - Optimize matching algorithms for large contact lists

9. **Additional Value Types**
   - Numeric ranges (RFC 2533)
   - Complex expressions with operators

## Related RFCs

- **RFC 3840**: Indicating User Agent Capabilities in the Session Initiation Protocol (SIP) [this document]
- **RFC 3841**: Caller Preferences for the Session Initiation Protocol (SIP) [future work]
- **RFC 2533**: A Syntax for Describing Media Feature Sets (basis for feature tags)
- **RFC 5627**: Obtaining and Using Globally Routable User Agent URIs (GRUUs) in the Session Initiation Protocol (SIP)
- **RFC 3261**: SIP: Session Initiation Protocol

## Examples

### Complete REGISTER with Capabilities

```
REGISTER sip:example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Alice <sip:alice@example.com>
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 1 REGISTER
Contact: <sip:alice@192.168.1.100:5060>;audio;video;mobility=mobile;methods="INVITE,ACK,BYE,CANCEL,OPTIONS";events="presence,message-summary";description="Alice's iPhone"
Expires: 3600
Content-Length: 0
```

### Complete OPTIONS Response with Capabilities

```
SIP/2.0 200 OK
Via: SIP/2.0/UDP client.example.com:5060;branch=z9hG4bKnashds8
To: Bob <sip:bob@example.com>;tag=1928301774
From: Alice <sip:alice@example.com>;tag=2398402
Call-ID: a84b4c76e66710
CSeq: 1 OPTIONS
Contact: <sip:bob@192.168.1.200:5060>;audio;video;text;isfocus;methods="INVITE,ACK,BYE,CANCEL,OPTIONS,SUBSCRIBE,NOTIFY";events="presence,conference";description="Conference Server"
Accept: application/sdp, application/reginfo+xml
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, MESSAGE
Supported: replaces, timer, gruu
Content-Length: 0
```

## Version History

- **Initial Implementation** (Current): Complete RFC 3840 feature tag system, capability sets, Contact header integration, and capability matching logic
