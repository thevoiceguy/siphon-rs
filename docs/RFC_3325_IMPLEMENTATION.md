# RFC 3325 P-Asserted-Identity Implementation

**Date:** 2025-01-21
**Status:** ✅ **COMPLETE** - Full RFC 3325 compliance achieved
**Test Results:** ✅ All P-header tests passing (13 core tests, 4 UAC tests)

---

## Overview

This document describes the RFC 3325 (Private Extensions to SIP for Asserted Identity within Trusted Networks) implementation in SIPHON-RS. This extension defines the P-Asserted-Identity and P-Preferred-Identity headers used within trusted network domains to assert and prefer user identities.

### RFC 3325 Summary

RFC 3325 defines:
- **P-Asserted-Identity**: Header used by trusted proxies to assert the identity of the originator within a trust domain
- **P-Preferred-Identity**: Header used by UACs to indicate their preferred identity to trusted proxies
- **Trust Domains**: Network segments where P-Asserted-Identity can be trusted
- **Multiple Identities**: Support for both SIP URIs and Tel URIs in the same header
- **Privacy Interaction**: P-Asserted-Identity should be removed when Privacy:id is requested

---

## Implementation Status

### ✅ Complete Implementation

| Component | Status | Location | Description |
|-----------|--------|----------|-------------|
| **PHeaderError Type** | ✅ Complete | `sip-core/src/p_headers.rs:22-62` | Validation and parsing errors |
| **PIdentity Type** | ✅ Complete | `sip-core/src/p_headers.rs:64-162` | Generic identity with Uri enum |
| **PAssertedIdentityHeader** | ✅ Complete | `sip-core/src/p_headers.rs:326-469` | P-Asserted-Identity header type |
| **PPreferredIdentityHeader** | ✅ Complete | `sip-core/src/p_headers.rs:472-609` | P-Preferred-Identity header type |
| **Builder Methods** | ✅ Complete | Multiple methods | single_sip(), single_tel(), sip_and_tel() |
| **Query Methods** | ✅ Complete | Multiple methods | has_tel_identity(), sip_identity(), etc. |
| **Display Implementation** | ✅ Complete | Both header types | Formats as "<uri>" or "Name" <uri> |
| **Parsing** | ✅ Complete | `sip-core/src/p_headers.rs:612-703` | Parses both SIP and Tel URIs |
| **UAC APIs** | ✅ Complete | `sip-uac/src/lib.rs:1601-1718` | add_p_preferred_identity_header(), etc. |
| **Tests** | ✅ Complete | 13 core tests + 4 UAC tests | Comprehensive coverage |
| **Documentation** | ✅ Complete | Inline docs + this document | Usage examples and API docs |

---

## API Reference

### Core P-Header Types

**Location:** `crates/sip-core/src/p_headers.rs`

#### PHeaderError Type

```rust
pub enum PHeaderError {
    DisplayNameTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    TooManyIdentities { max: usize, actual: usize },
    TooManyNetworkIds { max: usize, actual: usize },
    NetworkIdTooLong { max: usize, actual: usize },
    AccessTypeTooLong { max: usize, actual: usize },
    InvalidDisplayName(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    InvalidAccessType(String),
    InvalidNetworkId(String),
    DuplicateParam(String),
    EmptyIdentities,
    EmptyNetworkIds,
    InvalidTelUri(String),
    ParseError(String),
}
```

#### PIdentity Struct

Generic identity structure that can hold both SIP and Tel URIs.

```rust
pub struct PIdentity {
    // fields are private
}
```

**Methods:**
- `from_uri(uri: Uri)` - Create identity from URI with no display name
- `with_display_name(name: &str) -> Result<Self, PHeaderError>` - Add display name
- `with_param(name: &str, value: Option<&str>) -> Result<Self, PHeaderError>` - Add param
- `display_name()` / `uri()` / `params()` / `get_param()` - Accessors
- **Display trait** - Formats as `"Name" <uri>;param=value` or `<uri>`

#### PAssertedIdentityHeader

Used by trusted proxies to assert the identity of the originator within a trust domain.

```rust
pub struct PAssertedIdentityHeader {
    // identities are private
}
```

**Constructor Methods:**
- `single_sip(uri: SipUri)` - Create with single SIP URI identity
- `single_tel(number: &str) -> Result<Self, PHeaderError>` - Create with single Tel URI identity
- `sip_and_tel(sip_uri: SipUri, tel_number: &str) -> Result<Self, PHeaderError>` - Create with both SIP and Tel URIs
- `new(identities: Vec<PIdentity>) -> Result<Self, PHeaderError>` - Create with custom identity list

**Query Methods:**
- `has_tel_identity()` - Returns true if header contains at least one Tel URI
- `has_sip_identity()` - Returns true if header contains at least one SIP URI
- `sip_identity()` - Returns first SIP URI as string slice
- `tel_identity()` - Returns first Tel URI as string slice
- `is_empty()` - Returns true if no identities
- `len()` - Returns number of identities

**Display:**
- `to_string()` - Formats as comma-separated list: `<sip:alice@example.com>, <tel:+15551234567>`

#### PPreferredIdentityHeader

Used by UACs to express a preference about which identity should be asserted by a trusted proxy.

```rust
pub struct PPreferredIdentityHeader {
    // identities are private
}
```

**Constructor Methods:**
- `single_sip(uri: SipUri)` - Create with single SIP URI identity
- `single_tel(number: &str) -> Result<Self, PHeaderError>` - Create with single Tel URI identity
- `sip_and_tel(sip_uri: SipUri, tel_number: &str) -> Result<Self, PHeaderError>` - Create with both SIP and Tel URIs
- `new(identities: Vec<PIdentity>) -> Result<Self, PHeaderError>` - Create with custom identity list

**Query Methods:**
- Same as PAssertedIdentityHeader: `has_tel_identity()`, `has_sip_identity()`, `sip_identity()`, `tel_identity()`, `is_empty()`, `len()`

**Display:**
- Same format as PAssertedIdentityHeader

#### Helper Functions

```rust
pub fn parse_p_asserted_identity(headers: &Headers) -> Result<Option<PAssertedIdentityHeader>, PHeaderError>
pub fn parse_p_preferred_identity(headers: &Headers) -> Result<Option<PPreferredIdentityHeader>, PHeaderError>
```

Parse P-header values from SIP message headers, supporting both SIP and Tel URIs.

---

### UAC P-Header APIs

**Location:** `crates/sip-uac/src/lib.rs:1601-1718`

#### add_p_preferred_identity_header()

Adds a P-Preferred-Identity header to an existing request (in-place modification).

```rust
pub fn add_p_preferred_identity_header(
    request: &mut Request,
    header: PPreferredIdentityHeader
)
```

**Example:**
```rust
use sip_core::{PPreferredIdentityHeader, SipUri};
use sip_uac::UserAgentClient;

let uac = UserAgentClient::new(local_uri, contact_uri);
let mut invite = uac.create_invite(&remote_uri, Some(sdp));

// Prefer specific SIP identity
let preferred_uri = SipUri::parse("sip:alice.smith@company.com")?;
let ppi = PPreferredIdentityHeader::single_sip(preferred_uri);
UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);
```

#### with_p_preferred_identity()

Creates a new request with P-Preferred-Identity header added (takes ownership).

```rust
pub fn with_p_preferred_identity(
    request: Request,
    header: PPreferredIdentityHeader
) -> Request
```

**Example:**
```rust
use sip_core::{PPreferredIdentityHeader, SipUri};
use sip_uac::UserAgentClient;

let uac = UserAgentClient::new(local_uri, contact_uri);
let invite = uac.create_invite(&remote_uri, Some(sdp));

// Create invite with preferred identity
let preferred_uri = SipUri::parse("sip:alice.smith@company.com")?;
let ppi = PPreferredIdentityHeader::single_sip(preferred_uri);
let invite = UserAgentClient::with_p_preferred_identity(invite, ppi);
```

#### add_p_asserted_identity_header()

Adds a P-Asserted-Identity header to a request. **IMPORTANT**: This should typically only be used by trusted proxies, not UACs.

```rust
pub fn add_p_asserted_identity_header(
    request: &mut Request,
    header: PAssertedIdentityHeader
)
```

**Trust Domain Warning:** P-Asserted-Identity should only be added by trusted proxies within a trust domain. UACs should use P-Preferred-Identity instead. This method is provided for testing and special cases where the UAC is acting as a trusted element.

**Example:**
```rust
use sip_core::{PAssertedIdentityHeader, SipUri};
use sip_uac::UserAgentClient;

let uac = UserAgentClient::new(local_uri, contact_uri);
let mut invite = uac.create_invite(&remote_uri, Some(sdp));

// Assert identity (typically done by proxy, not UAC)
let asserted_uri = SipUri::parse("sip:alice@example.com")?;
let pai = PAssertedIdentityHeader::sip_and_tel(asserted_uri, "+15551234567")?;
UserAgentClient::add_p_asserted_identity_header(&mut invite, pai);
```

---

## Usage Examples

### Example 1: UAC with P-Preferred-Identity (SIP URI)

A user agent client with multiple identities expressing a preference:

```rust
use sip_core::{PPreferredIdentityHeader, SipUri};
use sip_uac::UserAgentClient;

// UAC has multiple identities, prefer work identity
let local_uri = SipUri::parse("sip:alice@example.com")?;
let contact_uri = SipUri::parse("sip:alice@192.168.1.100:5060")?;
let remote_uri = SipUri::parse("sip:bob@company.com")?;

let uac = UserAgentClient::new(local_uri, contact_uri);
let mut invite = uac.create_invite(&remote_uri, None);

// Express preference for work identity
let work_uri = SipUri::parse("sip:alice.smith@company.com")?;
let ppi = PPreferredIdentityHeader::single_sip(work_uri);
UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);

// Result: P-Preferred-Identity: <sip:alice.smith@company.com>
```

### Example 2: UAC with P-Preferred-Identity (Tel URI)

Expressing preference for a telephone number identity:

```rust
use sip_core::PPreferredIdentityHeader;
use sip_uac::UserAgentClient;

let uac = UserAgentClient::new(local_uri, contact_uri);
let mut invite = uac.create_invite(&remote_uri, None);

// Prefer telephone number identity
let ppi = PPreferredIdentityHeader::single_tel("+15551234567")?;
UserAgentClient::add_p_preferred_identity_header(&mut invite, ppi);

// Result: P-Preferred-Identity: <tel:+15551234567>
```

### Example 3: Proxy Asserting Identity (Both SIP and Tel)

A trusted proxy asserting both SIP and telephone identities:

```rust
use sip_core::{parse_p_preferred_identity, PAssertedIdentityHeader, SipUri};
use smol_str::SmolStr;

// Parse incoming P-Preferred-Identity from UAC
let ppi = parse_p_preferred_identity(request.headers())?;

// Proxy validates and asserts identity
let sip_uri = SipUri::parse("sip:alice@example.com")?;
let pai = PAssertedIdentityHeader::sip_and_tel(sip_uri, "+15551234567")?;

// Add to forwarded request
request
    .headers_mut()
    .push(
        SmolStr::new("P-Asserted-Identity"),
        SmolStr::new(pai.to_string()),
    )
    ?;

// Remove P-Preferred-Identity at trust domain boundary
request.headers_mut().remove("P-Preferred-Identity");

// Result: P-Asserted-Identity: <sip:alice@example.com>, <tel:+15551234567>
```

### Example 4: Querying Identity Information

Extracting identity information from P-Asserted-Identity:

```rust
use sip_core::parse_p_asserted_identity;

// Parse P-Asserted-Identity from incoming request
if let Some(pai) = parse_p_asserted_identity(request.headers())? {
    // Check what types of identities are present
    if pai.has_sip_identity() {
        println!("SIP identity: {}", pai.sip_identity()?);
    }

    if pai.has_tel_identity() {
        println!("Tel identity: {}", pai.tel_identity()?);
    }

    // Check if multiple identities
    if pai.len() > 1 {
        println!("Multiple identities asserted");
    }
}
```

### Example 5: Privacy Interaction

Respecting Privacy header when handling P-Asserted-Identity:

```rust
use sip_core::{enforce_privacy, parse_privacy_header};

// Check if privacy is requested
if let Some(privacy) = parse_privacy_header(request.headers()) {
    // Removes P-Asserted-Identity/P-Preferred-Identity and anonymizes identity headers.
    enforce_privacy(request.headers_mut(), &privacy)?;
}
```

### Example 6: Trust Domain Boundary Handling

Removing P-Asserted-Identity at trust domain boundaries:

```rust
// Function called at trust domain boundary
fn sanitize_at_trust_boundary(request: &mut Request) {
    // P-Asserted-Identity MUST be removed
    request.headers_mut().remove("P-Asserted-Identity");

    // P-Preferred-Identity can be kept or removed based on policy
    // (typically removed for privacy)
    request.headers_mut().remove("P-Preferred-Identity");
}
```

### Example 7: Multiple Identities

Creating P-Asserted-Identity with multiple identities:

```rust
use sip_core::{PIdentity, PAssertedIdentityHeader, SipUri, Uri};

// Create multiple identity entries
let sip_uri = SipUri::parse("sip:alice@example.com")?;
let sip_identity = PIdentity::from_uri(Uri::Sip(sip_uri))
    .with_display_name("Alice Smith")?;

let tel_uri = Uri::parse("tel:+15551234567")?;
let tel_identity = PIdentity::from_uri(tel_uri);

let pai = PAssertedIdentityHeader::new(vec![sip_identity, tel_identity])?;

// Result: P-Asserted-Identity: "Alice Smith" <sip:alice@example.com>, <tel:+15551234567>
```

### Example 8: Parsing and Validation

Parsing P-Preferred-Identity and validating before asserting:

```rust
use sip_core::{parse_p_preferred_identity, PAssertedIdentityHeader, SipUri};

// Parse P-Preferred-Identity from UAC request
if let Some(ppi) = parse_p_preferred_identity(request.headers())? {
    // Validate that the UAC is authorized for this identity
    if let Some(sip_id) = ppi.sip_identity() {
        if is_authorized_for_identity(&uac_credentials, sip_id) {
            // Convert preferred to asserted
            let sip_uri = SipUri::parse(sip_id)?;
            let pai = PAssertedIdentityHeader::single_sip(sip_uri);

            // Add P-Asserted-Identity
            UserAgentClient::add_p_asserted_identity_header(&mut request, pai);

            // Remove P-Preferred-Identity
            request.headers_mut().remove("P-Preferred-Identity");
        } else {
            // Not authorized - reject or use default identity
            println!("UAC not authorized for preferred identity");
        }
    }
}
```

---

## Trust Domain Considerations

### What is a Trust Domain?

A trust domain is a set of network elements (proxies, B2BUAs, etc.) that trust each other for the purposes of asserting user identity. Within a trust domain:
- P-Asserted-Identity can be trusted as accurate
- Elements can add, modify, or remove P-Asserted-Identity headers
- Privacy requirements must be respected

### Trust Domain Boundaries

At the boundary between trust domains or when leaving a trust domain:
- **MUST** remove P-Asserted-Identity headers
- **SHOULD** remove P-Preferred-Identity headers
- **MUST** respect Privacy header requirements
- **MAY** assert a new P-Asserted-Identity based on local policy

### UAC Behavior

User Agent Clients (UACs):
- **SHOULD** use P-Preferred-Identity to express identity preferences
- **MUST NOT** add P-Asserted-Identity (except in testing/special cases)
- **MAY** receive P-Asserted-Identity within a trust domain
- **MUST** ignore P-Asserted-Identity from untrusted sources

### Proxy Behavior

Trusted proxies within a trust domain:
- **MAY** add P-Asserted-Identity based on authenticated identity
- **MAY** honor P-Preferred-Identity if UAC is authorized
- **MUST** remove P-Asserted-Identity at trust domain boundaries
- **MUST** respect Privacy:id requests
- **MUST** validate identity before asserting

---

## Interaction with Other RFCs

### RFC 3323: Privacy Mechanism

When Privacy:id or Privacy:user is requested:
- Proxies **MUST** remove P-Asserted-Identity at trust domain boundaries
- Proxies **SHOULD** remove P-Preferred-Identity
- From/Contact headers should be anonymized (per RFC 3323)

The `enforce_privacy()` helper removes P-Asserted-Identity/P-Preferred-Identity and anonymizes From/Contact when Privacy:id or Privacy:user is present.

Example:
```rust
use sip_core::{PrivacyHeader, PrivacyValue};

// UAC requests identity privacy
let privacy = PrivacyHeader::new(vec![PrivacyValue::Id, PrivacyValue::Critical]);
UserAgentClient::add_privacy_header(&mut invite, vec![PrivacyValue::Id, PrivacyValue::Critical]);

// Proxy MUST remove P-Asserted-Identity when forwarding outside trust domain
// and anonymize From/Contact per RFC 3323
```

### RFC 3261: Basic SIP

P-Asserted-Identity and P-Preferred-Identity are **optional** extensions:
- Do not affect basic SIP call flow
- Can be safely ignored by elements that don't understand them
- Should not cause call failures if missing

### RFC 3966: Tel URIs

Both headers support Tel URIs per RFC 3966:
- Global numbers: `tel:+15551234567`
- Local numbers with context: `tel:5551234567;phone-context=example.com`

---

## Implementation Architecture

### Type Hierarchy

```
PIdentity
├── display_name: Option<SmolStr>
├── uri: Uri
│   ├── Uri::Sip(SipUri)    // sip:/sips: URIs
│   └── Uri::Tel(TelUri)     // tel: URIs
└── params: BTreeMap<SmolStr, Option<SmolStr>>

PAssertedIdentityHeader
└── identities: Vec<PIdentity>

PPreferredIdentityHeader
└── identities: Vec<PIdentity>
```

### Design Decisions

1. **Separate PIdentity type**: Created `PIdentity` instead of reusing `NameAddr` because:
   - `NameAddr` only supports SipUri (not Tel URIs)
   - P-headers need to support both SIP and Tel URIs
   - Cleaner separation of concerns

2. **Uri enum usage**: Used the `Uri` enum to support both SIP and Tel URIs:
   - Type-safe handling of both URI types
   - Existing parsing infrastructure
   - Consistent with tel URI support elsewhere

3. **Builder pattern**: Provided convenience builders:
   - `single_sip()` for common single SIP identity case
   - `single_tel()` for telephone number identities
   - `sip_and_tel()` for enterprise scenarios with both
   - `new()` for custom identity lists

4. **Query methods**: Added query methods for common operations:
   - `has_tel_identity()`, `has_sip_identity()` for presence checks
   - `sip_identity()`, `tel_identity()` for extracting first identity
   - Avoids need for manual iteration in common cases

---

## Test Coverage

### Core P-Header Tests (13 tests)

**Location:** `crates/sip-core/src/p_headers.rs` (lines 911-1040)

- ✅ `p_asserted_identity_single_sip` - Single SIP identity creation
- ✅ `p_asserted_identity_single_tel` - Single Tel identity creation
- ✅ `reject_crlf_in_display_name` - Rejects CRLF injection in display name
- ✅ `reject_oversized_display_name` - Enforces display name limits
- ✅ `reject_too_many_identities` - Enforces identity count limits
- ✅ `reject_empty_identities` - Rejects empty identity list
- ✅ `reject_too_many_params` - Enforces parameter limits
- ✅ `fields_are_private` - Confirms accessor-only API
- ✅ `parse_p_identity_with_display` - Parsing with display name
- ✅ `parse_p_identity_with_angle_in_display` - Parsing with angle brackets in display
- ✅ `parse_p_identity_with_params` - Parsing with parameters
- ✅ `parse_p_identity_list_with_commas` - Parsing multiple identities
- ✅ `reject_invalid_parse_input` - Rejects malformed inputs

### UAC P-Header Tests (4 tests)

**Location:** `crates/sip-uac/src/lib.rs` (lines 3911-3997)

- ✅ `adds_p_preferred_identity_sip` - Adding SIP P-Preferred-Identity
- ✅ `adds_p_preferred_identity_tel` - Adding Tel P-Preferred-Identity
- ✅ `with_p_preferred_identity` - Builder pattern with P-Preferred-Identity
- ✅ `adds_p_asserted_identity` - Adding P-Asserted-Identity (both SIP and Tel)

---

## Compliance Checklist

### RFC 3325 Requirements

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| P-Asserted-Identity header support | ✅ | PAssertedIdentityHeader type |
| P-Preferred-Identity header support | ✅ | PPreferredIdentityHeader type |
| SIP URI support in P-headers | ✅ | Uri::Sip variant |
| Tel URI support in P-headers | ✅ | Uri::Tel variant |
| Multiple identities per header | ✅ | Vec<PIdentity> |
| Display name support | ✅ | PIdentity.display_name |
| Trust domain awareness (docs) | ✅ | Documentation and warnings |
| Privacy interaction (RFC 3323) | ✅ | Enforced via `enforce_privacy()` removing P-headers |
| Parsing of P-headers | ✅ | parse_p_asserted_identity(), parse_p_preferred_identity() |
| Formatting of P-headers | ✅ | Display trait implementations |

### Best Practices

| Practice | Status | Notes |
|----------|--------|-------|
| UACs use P-Preferred-Identity | ✅ | UAC APIs provided |
| Proxies use P-Asserted-Identity | ✅ | Static method with warnings |
| Remove at trust boundaries | ⚠️ | Documented; `enforce_privacy()` covers Privacy:id/user cases |
| Validate before asserting | ⚠️ | Left to application logic |
| Respect Privacy header | ✅ | `enforce_privacy()` applies Privacy header policies |

**Legend:**
- ✅ Fully implemented
- ⚠️ Documented but requires application-level implementation

---

## Future Enhancements

### Potential Improvements

1. **Trust Domain Enforcement**
   - Add trust domain configuration
   - Automatic P-Asserted-Identity removal at boundaries
   - Trust validation framework

2. **Privacy Integration**
   - Proxy integration for `enforce_privacy()` in forwarding paths
   - Session privacy helpers (SDP scrubbing)
   - Privacy-aware proxy APIs

3. **Validation Framework**
   - Identity authorization checking
   - Certificate/credential validation
   - Policy-based identity assertion

4. **Additional P-Headers**
   - P-Charging-Vector (RFC 3455)
   - P-Charging-Function-Addresses (RFC 3455)
   - P-Called-Party-ID (RFC 3455)

---

## References

- **RFC 3325**: Private Extensions to the Session Initiation Protocol (SIP) for Asserted Identity within Trusted Networks
- **RFC 3261**: SIP: Session Initiation Protocol
- **RFC 3323**: A Privacy Mechanism for the Session Initiation Protocol (SIP)
- **RFC 3966**: The tel URI for Telephone Numbers

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2025-01-21 | 1.0 | Initial RFC 3325 implementation complete |
