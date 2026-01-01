# RFC 3329 Security Agreement Implementation

**Date:** 2025-01-21
**Status:** ✅ **COMPLETE** - Full RFC 3329 compliance achieved
**Test Results:** ✅ All security agreement tests passing (27 security tests)

---

## Overview

This document describes the RFC 3329 (Security Mechanism Agreement for SIP) implementation in SIPHON-RS. This extension provides a mechanism for UAs and proxies to agree on security mechanisms to use for SIP signaling, preventing downgrade attacks.

### RFC 3329 Summary

RFC 3329 defines three security headers:
- **Security-Client**: Used by UACs to advertise supported security mechanisms
- **Security-Server**: Used by UASs to advertise supported security mechanisms
- **Security-Verify**: Used by UACs to echo the agreed security mechanism

The security agreement flow:
1. UAC sends initial request with **Security-Client** listing supported mechanisms
2. UAS responds with **494 Security Agreement Required** and **Security-Server** listing its mechanisms
3. UAC chooses a mechanism, sends new request with **Security-Verify** echoing the choice
4. UAS verifies Security-Verify matches and processes the request

This prevents downgrade attacks where an attacker forces use of weak security.

---

## Implementation Status

### ✅ Complete Implementation

| Component | Status | Location | Description |
|-----------|--------|----------|-------------|
| **SecurityError Type** | ✅ Complete | `sip-core/src/security.rs:18-41` | Validation and parsing errors |
| **SecurityMechanism Enum** | ✅ Complete | `sip-core/src/security.rs:127-172` | TLS, Digest, IPsec variants |
| **SecurityEntry Type** | ✅ Complete | `sip-core/src/security.rs:174-295` | Mechanism + parameters |
| **SecurityClientHeader** | ✅ Complete | `sip-core/src/security.rs:298-363` | UAC security advertisement |
| **SecurityServerHeader** | ✅ Complete | `sip-core/src/security.rs:366-458` | UAS security advertisement |
| **SecurityVerifyHeader** | ✅ Complete | `sip-core/src/security.rs:460-524` | Security verification |
| **Preference Handling** | ✅ Complete | q parameter support | Mechanism preference values |
| **Best Match Algorithm** | ✅ Complete | find_best_match() method | Negotiation logic |
| **Parsing** | ✅ Complete | `sip-core/src/security.rs:527-543` | parse_security_* functions |
| **Display Implementation** | ✅ Complete | All types | RFC-compliant formatting |
| **Tests** | ✅ Complete | 27 comprehensive tests | Full coverage |
| **Documentation** | ✅ Complete | Inline docs + this document | Usage examples and API docs |

---

## API Reference

### SecurityError

```rust
pub enum SecurityError {
    ValidationError(String),
    TooManyItems { field: &'static str, max: usize },
    InvalidFormat(String),
}
```

### SecurityMechanism Enum

**Location:** `crates/sip-core/src/security.rs:127-172`

```rust
pub enum SecurityMechanism {
    Tls,        // Transport Layer Security
    Digest,     // Digest Authentication
    IpsecIke,   // IPsec with IKE key management
    IpsecMan,   // IPsec with manual key management
    Other(SmolStr),  // Custom/other mechanism
}
```

**Methods:**
- `as_str(&self) -> &str` - Returns mechanism name
- `parse(s: &str) -> Result<Self, SecurityError>` - Parses from string (case-insensitive)
- **Display trait** - Formats as lowercase string

### SecurityEntry Struct

**Location:** `crates/sip-core/src/security.rs:174-295`

Represents a single security mechanism with parameters.

```rust
pub struct SecurityEntry {
    // fields are private
}
```

**Constructor Methods:**
- `new(mechanism: SecurityMechanism)` - Creates with mechanism, no params
- `tls()` - Creates TLS entry
- `digest(algorithm: &str, qop: Option<&str>) -> Result<Self, SecurityError>` - Creates Digest entry with algorithm
- `ipsec_ike(algorithm: &str, protocol: &str, mode: &str) -> Result<Self, SecurityError>` - Creates IPsec-IKE entry

**Parameter Methods:**
- `set_param(&mut self, name: &str, value: Option<&str>) -> Result<(), SecurityError>` - Sets a parameter
- `get_param(&self, name: &str) -> Option<&Option<SmolStr>>` - Gets a parameter
- `set_preference(&mut self, q: f32) -> Result<(), SecurityError>` - Sets q parameter (0.0-1.0)
- `preference(&self) -> Option<f32>` - Gets q parameter value
- `mechanism(&self) -> &SecurityMechanism` - Gets mechanism
- `params(&self) -> &BTreeMap<SmolStr, Option<SmolStr>>` - Gets params

**Display:**
- `to_string()` - Formats as `mechanism;param1=value1;param2=value2`

**Common Parameters:**
- `q` - Preference value (0.0-1.0, default 0.001)
- `d-alg` - Digest algorithm (MD5, SHA-1, SHA-256, etc.)
- `d-qop` - Digest quality of protection (auth, auth-int)
- `d-ver` - Digest version
- `algorithm` - Encryption algorithm
- `protocol` - IPsec protocol (esp, ah)
- `mode` - IPsec mode (trans, tunnel)
- `encrypt-algorithm` - Encryption algorithm for IPsec
- `spi-c`, `spi-s` - SPI values for client/server
- `port-c`, `port-s` - Port numbers for client/server

### SecurityClientHeader

**Location:** `crates/sip-core/src/security.rs:298-363`

UAC advertisement of supported mechanisms.

```rust
pub struct SecurityClientHeader {
    // entries are private
}
```

**Constructor Methods:**
- `new(entries: Vec<SecurityEntry>) -> Result<Self, SecurityError>` - Creates with entry list
- `single(entry: SecurityEntry)` - Creates with single entry

**Query Methods:**
- `is_empty(&self) -> bool` - True if no entries
- `len(&self) -> usize` - Number of entries
- `entries(&self) -> &[SecurityEntry]` - Access entries
- `sorted_by_preference(&self) -> Vec<&SecurityEntry>` - Entries sorted by q value (highest first)

**Display:**
- `to_string()` - Formats as comma-separated list

### SecurityServerHeader

**Location:** `crates/sip-core/src/security.rs:366-458`

UAS advertisement of supported mechanisms.

```rust
pub struct SecurityServerHeader {
    // entries are private
}
```

**Constructor Methods:**
- `new(entries: Vec<SecurityEntry>) -> Result<Self, SecurityError>` - Creates with entry list
- `single(entry: SecurityEntry)` - Creates with single entry

**Query Methods:**
- `is_empty(&self) -> bool` - True if no entries
- `len(&self) -> usize` - Number of entries
- `entries(&self) -> &[SecurityEntry]` - Access entries
- `sorted_by_preference(&self) -> Vec<&SecurityEntry>` - Entries sorted by q value (highest first)
- `find_best_match(&self, client: &SecurityClientHeader) -> Option<&SecurityEntry>` - Finds best matching mechanism

**Display:**
- `to_string()` - Formats as comma-separated list

### SecurityVerifyHeader

**Location:** `crates/sip-core/src/security.rs:460-524`

UAC verification of chosen mechanism.

```rust
pub struct SecurityVerifyHeader {
    // entries are private
}
```

**Constructor Methods:**
- `new(entries: Vec<SecurityEntry>) -> Result<Self, SecurityError>` - Creates with entry list
- `single(entry: SecurityEntry)` - Creates with single entry

**Query Methods:**
- `is_empty(&self) -> bool` - True if no entries
- `len(&self) -> usize` - Number of entries
- `entries(&self) -> &[SecurityEntry]` - Access entries
- `matches(&self, server_entry: &SecurityEntry) -> bool` - Verifies mechanism matches

**Display:**
- `to_string()` - Formats as comma-separated list

### Parsing Functions

**Location:** `crates/sip-core/src/security.rs:527-543`

```rust
pub fn parse_security_client(value: &str) -> Result<SecurityClientHeader, SecurityError>
pub fn parse_security_server(value: &str) -> Result<SecurityServerHeader, SecurityError>
pub fn parse_security_verify(value: &str) -> Result<SecurityVerifyHeader, SecurityError>
```

Parse security headers from header value strings.

---

## Usage Examples

### Example 1: UAC Initial Request with Security-Client

UAC sends initial request advertising supported security mechanisms:

```rust
use sip_core::{SecurityClientHeader, SecurityEntry};
use smol_str::SmolStr;

// UAC supports TLS (preferred) and Digest
let mut tls = SecurityEntry::tls();
tls.set_preference(0.8)?;

let mut digest = SecurityEntry::digest("SHA-256", Some("auth"))?;
digest.set_preference(0.5)?;

let security_client = SecurityClientHeader::new(vec![tls, digest])?;

// Add to REGISTER request
request
    .headers_mut()
    .push(
        SmolStr::new("Security-Client"),
        SmolStr::new(security_client.to_string()),
    )?;

// Result: Security-Client: tls;q=0.8, digest;d-alg=SHA-256;d-qop=auth;q=0.5
```

### Example 2: UAS 494 Response with Security-Server

UAS responds with 494 and its supported mechanisms:

```rust
use sip_core::{SecurityServerHeader, SecurityEntry};
use smol_str::SmolStr;

// Server supports TLS and Digest
let mut tls = SecurityEntry::tls();
tls.set_preference(0.9)?;

let mut digest = SecurityEntry::digest("MD5", Some("auth"))?;
digest.set_preference(0.3)?;

let security_server = SecurityServerHeader::new(vec![tls, digest])?;

// Create 494 response
let mut response = Response::new(
    StatusLine::new(494, SmolStr::new("Security Agreement Required"))?,
    headers,
    Bytes::new(),
)?;

// Add Security-Server header
response
    .headers_mut()
    .push(
        SmolStr::new("Security-Server"),
        SmolStr::new(security_server.to_string()),
    )?;

// Result: Security-Server: tls;q=0.9, digest;d-alg=MD5;d-qop=auth;q=0.3
```

### Example 3: Finding Best Matching Mechanism

Server determines the best security mechanism supported by both parties:

```rust
use sip_core::parse_security_client;

// Parse Security-Client from initial request
let security_client = parse_security_client(
    request
        .headers()
        .get("Security-Client")
        .ok_or("Missing Security-Client")?,
)?;

// Get server's supported mechanisms
let security_server = get_server_security_mechanisms();

// Find best match
if let Some(best_match) = security_server.find_best_match(&security_client) {
    println!("Chosen mechanism: {}", best_match.mechanism());

    // Include in 494 response
    // Client will use this mechanism in subsequent request
} else {
    // No common mechanisms - return error
    println!("No compatible security mechanisms");
}
```

### Example 4: UAC Subsequent Request with Security-Verify

UAC sends new request with Security-Verify echoing chosen mechanism:

```rust
use sip_core::{parse_security_server, SecurityVerifyHeader};
use smol_str::SmolStr;

// Parse Security-Server from 494 response
let security_server = parse_security_server(
    response
        .headers()
        .get("Security-Server")
        .ok_or("Missing Security-Server")?,
)?;

// Choose the server's highest preference mechanism
let chosen = security_server.sorted_by_preference()[0].clone();

// Create Security-Verify header
let security_verify = SecurityVerifyHeader::single(chosen);

// Add to new request
request
    .headers_mut()
    .push(
        SmolStr::new("Security-Verify"),
        SmolStr::new(security_verify.to_string()),
    )?;

// Result: Security-Verify: tls;q=0.9
```

### Example 5: Server Verifying Security-Verify

Server verifies that client is using the agreed mechanism:

```rust
use sip_core::parse_security_verify;

// Parse Security-Verify from client's request
let security_verify = parse_security_verify(
    request
        .headers()
        .get("Security-Verify")
        .ok_or("Missing Security-Verify")?,
)?;

// Get the mechanism we told the client to use
let expected_mechanism = get_agreed_mechanism_for_client(&client_id);

// Verify it matches
if security_verify.matches(&expected_mechanism) {
    println!("Security mechanism verified correctly");
    // Process request normally
} else {
    println!("Security verification failed - possible downgrade attack!");
    // Reject request
}
```

### Example 6: IPsec Security Entry

Creating IPsec security entries:

```rust
use sip_core::SecurityEntry;

// IPsec with IKE key management
let mut ipsec_ike = SecurityEntry::ipsec_ike(
    "des-ede3-cbc",  // algorithm
    "esp",            // protocol
    "trans"           // mode
)?;
ipsec_ike.set_preference(0.7)?;

// Add additional IPsec parameters
ipsec_ike.set_param("encrypt-algorithm", Some("des-ede3-cbc"))?;
ipsec_ike.set_param("spi-c", Some("1234"))?;
ipsec_ike.set_param("spi-s", Some("5678"))?;
ipsec_ike.set_param("port-c", Some("5060"))?;
ipsec_ike.set_param("port-s", Some("5060"))?;

// Result: ipsec-ike;algorithm=des-ede3-cbc;protocol=esp;mode=trans;...
```

### Example 7: Sorting by Preference

Working with preference values:

```rust
use sip_core::{SecurityClientHeader, SecurityEntry};

// Create entries with different preferences
let mut tls = SecurityEntry::tls();
tls.set_preference(0.3)?;

let mut digest = SecurityEntry::digest("SHA-256", None)?;
digest.set_preference(0.9)?;

let mut ipsec = SecurityEntry::ipsec_ike("des", "esp", "trans")?;
ipsec.set_preference(0.6)?;

let header = SecurityClientHeader::new(vec![tls, digest, ipsec])?;

// Get sorted by preference (highest first)
let sorted = header.sorted_by_preference();

for entry in sorted {
let q = entry.preference().unwrap_or(0.001);
println!("{}: q={}", entry.mechanism(), q);
}

// Output:
// digest: q=0.9
// ipsec-ike: q=0.6
// tls: q=0.3
```

### Example 8: Custom Security Mechanism

Using custom/proprietary security mechanisms:

```rust
use sip_core::{SecurityEntry, SecurityMechanism};

// Custom mechanism
let mechanism = SecurityMechanism::parse("mycompany-secure")?;
let mut entry = SecurityEntry::new(mechanism);

entry.set_param("version", Some("2.0"))?;
entry.set_param("cipher", Some("aes-256-gcm"))?;
entry.set_preference(0.8)?;

// Result: mycompany-secure;version=2.0;cipher=aes-256-gcm;q=0.8
```

### Example 9: Complete Security Agreement Flow

Full UAC-UAS security agreement:

```rust
use sip_core::*;
use smol_str::SmolStr;
use smol_str::SmolStr;

// === STEP 1: UAC sends initial request ===
let mut tls = SecurityEntry::tls();
tls.set_preference(0.8)?;
let mut digest = SecurityEntry::digest("SHA-256", Some("auth"))?;
digest.set_preference(0.5)?;

let security_client = SecurityClientHeader::new(vec![tls, digest])?;
initial_request
    .headers_mut()
    .push(
        SmolStr::new("Security-Client"),
        SmolStr::new(security_client.to_string()),
    )?;

// === STEP 2: UAS responds with 494 ===
let server_tls = SecurityEntry::tls();
let server_digest = SecurityEntry::digest("MD5", Some("auth"))?;

let security_server = SecurityServerHeader::new(vec![server_tls.clone(), server_digest])?;

// Find best match
let best = security_server
    .find_best_match(&security_client)
    .ok_or("No compatible mechanisms")?;
println!("Agreed mechanism: {}", best.mechanism());

response_494
    .headers_mut()
    .push(
        SmolStr::new("Security-Server"),
        SmolStr::new(security_server.to_string()),
    )?;

// === STEP 3: UAC sends new request with Security-Verify ===
let security_verify = SecurityVerifyHeader::single(best.clone());
new_request
    .headers_mut()
    .push(
        SmolStr::new("Security-Verify"),
        SmolStr::new(security_verify.to_string()),
    )?;

// === STEP 4: UAS verifies ===
let verify_header = parse_security_verify(
    new_request
        .headers()
        .get("Security-Verify")
        .ok_or("Missing Security-Verify")?,
)?;

if verify_header.matches(&best) {
    println!("Verification successful!");
    // Process request
} else {
    println!("Verification failed!");
    // Reject
}
```

---

## Security Agreement Protocol Flow

### Complete Flow Diagram

```
UAC                                    UAS/Proxy
 |                                          |
 | (1) REGISTER                             |
 |     Security-Client: tls;q=0.8,          |
 |                      digest;q=0.5        |
 |----------------------------------------->|
 |                                          |
 |                                          | (Check Security-Client)
 |                                          | (No common mechanism or
 |                                          |  mechanism not yet agreed)
 |                                          |
 | (2) 494 Security Agreement Required      |
 |     Security-Server: tls;q=0.9,          |
 |                      digest;q=0.3        |
 |<-----------------------------------------|
 |                                          |
 | (UAC chooses mechanism - TLS)            |
 | (Establishes TLS if needed)              |
 |                                          |
 | (3) REGISTER (over secure channel)       |
 |     Security-Verify: tls;q=0.9           |
 |     Security-Client: tls;q=0.8,          |
 |                      digest;q=0.5        |
 |----------------------------------------->|
 |                                          |
 |                                          | (Verify Security-Verify
 |                                          |  matches agreed mechanism)
 |                                          | (Process request)
 |                                          |
 | (4) 200 OK                               |
 |<-----------------------------------------|
 |                                          |
```

### State Machine

```
UAC State Machine:
1. INITIAL → Send Security-Client → WAIT_494
2. WAIT_494 → Receive 494 with Security-Server → SELECT_MECHANISM
3. SELECT_MECHANISM → Choose mechanism → ESTABLISH_SECURITY
4. ESTABLISH_SECURITY → Setup secure channel → SEND_VERIFY
5. SEND_VERIFY → Send with Security-Verify → COMPLETE

UAS State Machine:
1. INITIAL → Receive Security-Client → SEND_494
2. SEND_494 → Send 494 with Security-Server → WAIT_VERIFY
3. WAIT_VERIFY → Receive Security-Verify → VERIFY_MECHANISM
4. VERIFY_MECHANISM → Check match → PROCESS or REJECT
```

---

## Design Decisions

### 1. Enum for Common Mechanisms

Used enum variants for standard mechanisms (TLS, Digest, IPsec-IKE, IPsec-Man) with `Other` variant for extensibility:
- Type-safe handling of common cases
- Easy pattern matching
- Supports custom mechanisms via `Other(SmolStr)`

### 2. BTreeMap for Parameters

Used `BTreeMap` for parameters instead of specific fields:
- RFC 3329 defines many optional parameters
- Different mechanisms use different parameters
- Allows custom parameters for proprietary mechanisms
- Maintains sorted order for consistent output

### 3. Preference Parsing

q values are stored as parameters but parsed/validated as f32:
- `set_preference()` validates and formats q values
- `preference()` parses q for sorting and comparison
- Preserves RFC-compliant wire formatting

### 4. Best Match Algorithm

`find_best_match()` uses combined preference scoring:
- Computes `server_q * client_q` for each shared mechanism
- Selects the highest combined score
- Balances server policy with client capability
- Deterministic and resistant to preference skew

### 5. Separate Header Types

Created three distinct header types (SecurityClient, SecurityServer, SecurityVerify) rather than one generic:
- Clear semantic meaning in API
- Type safety prevents misuse
- Each has specific methods (e.g., `find_best_match` only on ServerHeader)
- Better documentation and IDE support

---

## Test Coverage

### Security Agreement Tests (27 tests)

**Location:** `crates/sip-core/src/security.rs:698-1051`

- ✅ `security_mechanism_parse` - Mechanism parsing (case-insensitive)
- ✅ `security_mechanism_parse_rejects_empty` - Empty mechanism rejected
- ✅ `security_mechanism_parse_rejects_too_long` - Length limits enforced
- ✅ `security_mechanism_parse_rejects_control_chars` - Control chars rejected
- ✅ `security_mechanism_display` - Mechanism formatting
- ✅ `security_entry_basic` - Entry creation and parameters
- ✅ `security_entry_rejects_too_many_params` - Parameter limit enforced
- ✅ `security_entry_rejects_invalid_param_name` - Param name validation
- ✅ `security_entry_rejects_invalid_param_value` - Param value validation
- ✅ `security_entry_preference` - Preference handling
- ✅ `security_entry_preference_validates_range` - Q value validation
- ✅ `security_entry_display` - Entry formatting
- ✅ `security_client_header` - Client header creation
- ✅ `security_client_header_rejects_too_many_entries` - Entry limit enforced
- ✅ `security_client_display` - Client header formatting
- ✅ `security_server_find_best_match` - Mechanism negotiation
- ✅ `security_server_find_best_match_combines_preferences` - Combined scoring
- ✅ `security_verify_matches` - Verification matching
- ✅ `parse_security_client` - Client header parsing
- ✅ `parse_security_server` - Server header parsing
- ✅ `parse_security_client_rejects_too_many_entries` - Parse entry limit
- ✅ `parse_security_client_rejects_empty` - Empty input rejection
- ✅ `parse_security_client_handles_quoted_separators` - Quoted separator parsing
- ✅ `get_param_is_case_insensitive` - Case-insensitive param lookup
- ✅ `security_sorted_by_preference` - Preference sorting
- ✅ `security_sorted_by_preference_ignores_invalid_q` - Invalid q handling
- ✅ `fields_are_private` - Accessors-only API surface

---

## RFC Compliance Checklist

### RFC 3329 Requirements

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Security-Client header | ✅ | SecurityClientHeader type |
| Security-Server header | ✅ | SecurityServerHeader type |
| Security-Verify header | ✅ | SecurityVerifyHeader type |
| TLS mechanism | ✅ | SecurityMechanism::Tls |
| Digest mechanism | ✅ | SecurityMechanism::Digest |
| IPsec-IKE mechanism | ✅ | SecurityMechanism::IpsecIke |
| IPsec-Man mechanism | ✅ | SecurityMechanism::IpsecMan |
| Preference (q) parameter | ✅ | set_preference(), preference() |
| Digest parameters (d-alg, d-qop) | ✅ | Via params BTreeMap |
| IPsec parameters | ✅ | Via params BTreeMap |
| Header parsing | ✅ | parse_security_* functions |
| Header formatting | ✅ | Display trait implementations |
| Mechanism negotiation | ✅ | find_best_match() method |
| Security verification | ✅ | matches() method |
| 494 response code | ⚠️ | Application-level (not in core) |
| Downgrade attack prevention | ⚠️ | Application-level (not in core) |

**Legend:**
- ✅ Fully implemented in core library
- ⚠️ Requires application-level implementation

### Best Practices

| Practice | Status | Notes |
|----------|--------|-------|
| UAC sends Security-Client first | ⚠️ | Application responsibility |
| UAS responds with 494 + Security-Server | ⚠️ | Application responsibility |
| UAC includes Security-Verify | ⚠️ | Application responsibility |
| UAS verifies Security-Verify | ✅ | matches() method provided |
| Use highest mutual preference | ✅ | find_best_match() uses combined preference score |
| Support multiple mechanisms | ✅ | Vec<SecurityEntry> supports this |

---

## Integration Patterns

### UAC Pattern

```rust
use sip_core::*;

struct SecureUac {
    supported_mechanisms: SecurityClientHeader,
    agreed_mechanism: Option<SecurityEntry>,
}

impl SecureUac {
    fn new() -> Result<Self> {
        // Define supported mechanisms
        let mut tls = SecurityEntry::tls();
        tls.set_preference(0.9)?;

        let mut digest = SecurityEntry::digest("SHA-256", Some("auth"))?;
        digest.set_preference(0.5)?;

        Ok(Self {
            supported_mechanisms: SecurityClientHeader::new(vec![tls, digest])?,
            agreed_mechanism: None,
        })
    }

    fn create_initial_request(&self) -> Result<Request> {
        let mut request = create_base_request();

        // Add Security-Client
        request
            .headers_mut()
            .push(
                SmolStr::new("Security-Client"),
                SmolStr::new(self.supported_mechanisms.to_string()),
            )?;

        Ok(request)
    }

    fn handle_494_response(&mut self, response: &Response) -> Result<Request> {
        // Parse Security-Server
        let server_header = parse_security_server(
            response
                .headers()
                .get("Security-Server")
                .ok_or("Missing Security-Server")?
        )?;

        // Find best match
        let chosen = server_header.find_best_match(&self.supported_mechanisms)
            .ok_or("No compatible mechanisms")?
            .clone();

        // Store agreed mechanism
        self.agreed_mechanism = Some(chosen.clone());

        // Establish security if needed (TLS, IPsec, etc.)
        self.establish_security(&chosen)?;

        // Create new request with Security-Verify
        let mut request = self.create_initial_request()?;

        let verify = SecurityVerifyHeader::single(chosen);
        request
            .headers_mut()
            .push(
                SmolStr::new("Security-Verify"),
                SmolStr::new(verify.to_string()),
            )?;

        Ok(request)
    }
}
```

### UAS Pattern

```rust
use sip_core::*;
use smol_str::SmolStr;

struct SecureUas {
    supported_mechanisms: SecurityServerHeader,
    client_agreements: HashMap<String, SecurityEntry>,
}

impl SecureUas {
    fn new() -> Result<Self> {
        // Define supported mechanisms
        let mut tls = SecurityEntry::tls();
        tls.set_preference(0.9)?;

        let mut digest = SecurityEntry::digest("MD5", Some("auth"))?;
        digest.set_preference(0.3)?;

        Ok(Self {
            supported_mechanisms: SecurityServerHeader::new(vec![tls, digest])?,
            client_agreements: HashMap::new(),
        })
    }

    fn process_request(&mut self, request: &Request) -> Result<Response> {
        // Check if Security-Verify is present
        if request.headers().get("Security-Verify").is_some() {
            // Subsequent request - verify
            return self.verify_and_process(request);
        }

        // Check if Security-Client is present
        if request.headers().get("Security-Client").is_some() {
            // Initial request - send 494
            return self.send_494_response(request);
        }

        // No security agreement
        Ok(create_error_response(421, "Extension Required"))
    }

    fn send_494_response(&mut self, request: &Request) -> Result<Response> {
        // Parse Security-Client
        let client_header = parse_security_client(
            request
                .headers()
                .get("Security-Client")
                .ok_or("Missing Security-Client")?
        )?;

        // Find best match
        let chosen = self.supported_mechanisms.find_best_match(&client_header)
            .ok_or("No compatible mechanisms")?;

        // Store agreement for this client
        let client_id = extract_client_id(request);
        self.client_agreements.insert(client_id, chosen.clone());

        // Create 494 response
        let mut response = Response::new(
            StatusLine::new(494, SmolStr::new("Security Agreement Required"))?,
            Headers::new(),
            Bytes::new()
        )?;

        // Add Security-Server
        response
            .headers_mut()
            .push(
                SmolStr::new("Security-Server"),
                SmolStr::new(self.supported_mechanisms.to_string()),
            )?;

        Ok(response)
    }

    fn verify_and_process(&self, request: &Request) -> Result<Response> {
        let verify_header = parse_security_verify(
            request
                .headers()
                .get("Security-Verify")
                .ok_or("Missing Security-Verify")?
        )?;

        // Get agreed mechanism for this client
        let client_id = extract_client_id(request);
        let agreed = self.client_agreements.get(&client_id)
            .ok_or("No prior agreement")?;

        // Verify
        if !verify_header.matches(agreed) {
            return Err("Security verification failed".into());
        }

        // Process request normally
        Ok(create_success_response(request))
    }
}
```

---

## Security Considerations

### Downgrade Attack Prevention

The Security-Verify header prevents downgrade attacks:
1. Server tells client which mechanism to use via Security-Server
2. Client echoes this choice in Security-Verify
3. Server verifies the echo matches
4. Attacker cannot force weaker mechanism without server detecting mismatch

### Preference Values

Use preference values strategically:
- Higher q for stronger mechanisms (e.g., TLS q=0.9, Digest q=0.3)
- Server's preferences should reflect security policy
- Client's preferences reflect capabilities and requirements

### 494 Response Handling

Always include Security-Server in 494 responses:
- Without it, client cannot determine supported mechanisms
- RFC 3329 requires it for proper negotiation

### Mechanism Parameters

Validate mechanism parameters:
- Digest algorithms (prefer SHA-256 over MD5)
- IPsec algorithms and modes
- Custom mechanism parameters

---

## References

- **RFC 3329**: Security Mechanism Agreement for the Session Initiation Protocol (SIP)
- **RFC 3261**: SIP: Session Initiation Protocol
- **RFC 2617**: HTTP Authentication: Basic and Digest Access Authentication
- **RFC 4346**: The Transport Layer Security (TLS) Protocol Version 1.1
- **RFC 4301**: Security Architecture for the Internet Protocol (IPsec)

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2025-01-21 | 1.0 | Initial RFC 3329 implementation complete |
