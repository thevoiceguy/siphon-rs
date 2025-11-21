# RFC 3824: ENUM Implementation

## Overview

This document describes the implementation of RFC 3824 (Using E.164 numbers with the Session Initiation Protocol) in the siphon-rs codebase. ENUM (E.164 Number Mapping) uses DNS to translate telephone numbers to URIs, particularly SIP URIs.

## RFC 3824 Summary

**RFC 3824** defines how to use E.164 telephone numbers with SIP, specifically through ENUM (RFC 3761). Key concepts:

- **ENUM**: E.164 Number Mapping, a DNS-based system for translating telephone numbers to URIs
- **E.164 Numbers**: International telephone numbering format (e.g., +12025332600)
- **e164.arpa Domain**: DNS domain used for ENUM lookups
- **NAPTR Records**: DNS Naming Authority Pointer records contain URI mappings
- **Service Field**: "E2U+sip" indicates SIP address-of-record mapping
- **Regular Expressions**: NAPTR regexp field maps numbers to URIs
- **Order and Preference**: Lower values indicate higher priority for record selection

### ENUM Process

1. Convert E.164 number to ENUM domain (reverse dotted decimal)
   - Example: `+12025332600` → `0.0.6.2.3.3.5.2.0.2.1.e164.arpa`

2. Query DNS for NAPTR records

3. Filter records by service field (e.g., "E2U+sip")

4. Sort by order (ascending), then preference (ascending)

5. Extract URI from regexp field of highest priority record

## Implementation Location

The ENUM implementation is located in:
- **Module**: `crates/sip-dns/src/enum_lookup.rs`
- **Exports**: Through `crates/sip-dns/src/lib.rs`

## API Reference

### Functions

#### `enum_to_domain(e164_number: &str) -> Option<String>`

Converts an E.164 telephone number to an ENUM domain name for DNS lookup.

**Algorithm (per RFC 3761):**
1. Remove the leading '+'
2. Validate that only digits remain
3. Reverse the digits
4. Separate digits with dots
5. Append ".e164.arpa"

**Parameters:**
- `e164_number`: E.164 number (must start with '+')

**Returns:**
- `Some(String)`: ENUM domain name for DNS lookup
- `None`: If invalid E.164 number

**Examples:**
```rust
use sip_dns::enum_to_domain;

// Standard E.164 conversion
let domain = enum_to_domain("+12025332600").unwrap();
assert_eq!(domain, "0.0.6.2.3.3.5.2.0.2.1.e164.arpa");

// UK number
let domain = enum_to_domain("+442079460123").unwrap();
assert_eq!(domain, "3.2.1.0.6.4.9.7.0.2.4.4.e164.arpa");

// Invalid inputs return None
assert_eq!(enum_to_domain("12025332600"), None);     // Missing '+'
assert_eq!(enum_to_domain("+1-202-533-2600"), None); // Contains non-digits
assert_eq!(enum_to_domain("+"), None);                // Empty after '+'
```

**Validation Rules:**
- Must start with '+'
- Must not be empty after stripping '+'
- Must contain only ASCII digits

---

#### `tel_uri_to_enum_domain(tel_uri: &TelUri) -> Option<String>`

Converts a TelUri to an ENUM domain name. Only works for global (E.164) tel URIs.

**Parameters:**
- `tel_uri`: TelUri to convert

**Returns:**
- `Some(String)`: ENUM domain name
- `None`: If not a global number

**Examples:**
```rust
use sip_core::TelUri;
use sip_dns::tel_uri_to_enum_domain;

// Global number - works
let tel = TelUri::parse("tel:+1-555-123-4567").unwrap();
let domain = tel_uri_to_enum_domain(&tel).unwrap();
assert_eq!(domain, "7.6.5.4.3.2.1.5.5.5.1.e164.arpa");

// Local number - returns None
let tel = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
assert_eq!(tel_uri_to_enum_domain(&tel), None);
```

---

#### `sort_enum_records(records: &mut [EnumNaptrRecord])`

Sorts ENUM NAPTR records by priority according to RFC 3824.

**Sorting Order:**
1. By `order` field (ascending - lower order = higher priority)
2. By `preference` field (ascending - lower preference = higher priority)

**Note:** Per RFC 3824, if multiple records have the same order and preference, clients SHOULD randomly select one, though local policy MAY apply. This implementation does not perform randomization.

**Parameters:**
- `records`: Mutable slice of ENUM NAPTR records to sort in-place

**Examples:**
```rust
use sip_dns::{EnumNaptrRecord, sort_enum_records};

let mut records = vec![
    EnumNaptrRecord::new(200, 10, "u", "E2U+sip", "!^.*$!sip:d@example.com!", ""),
    EnumNaptrRecord::new(100, 20, "u", "E2U+sip", "!^.*$!sip:b@example.com!", ""),
    EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:a@example.com!", ""),
];

sort_enum_records(&mut records);

// After sorting: order 100 comes first, then sorted by preference
assert_eq!(records[0].order, 100);
assert_eq!(records[0].preference, 10);
assert_eq!(records[1].order, 100);
assert_eq!(records[1].preference, 20);
assert_eq!(records[2].order, 200);
```

---

#### `filter_sip_records(records: &[EnumNaptrRecord]) -> Vec<EnumNaptrRecord>`

Filters ENUM NAPTR records to return only SIP service records.

**Filter Criteria:**
- Service field equals "E2U+sip" (case-insensitive)

**Parameters:**
- `records`: Slice of ENUM NAPTR records

**Returns:**
- Vector containing only SIP service records

**Examples:**
```rust
use sip_dns::{EnumNaptrRecord, filter_sip_records};

let records = vec![
    EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", ""),
    EnumNaptrRecord::new(100, 20, "u", "E2U+mailto", "!^.*$!mailto:info@example.com!", ""),
    EnumNaptrRecord::new(100, 30, "u", "E2U+sip", "!^.*$!sip:bob@example.com!", ""),
];

let sip_records = filter_sip_records(&records);
assert_eq!(sip_records.len(), 2);
assert!(sip_records[0].is_sip_service());
assert!(sip_records[1].is_sip_service());
```

---

#### `select_best_sip_record(records: &[EnumNaptrRecord]) -> Option<EnumNaptrRecord>`

Selects the best ENUM NAPTR record for SIP by filtering for SIP services, sorting by priority, and returning the highest priority record.

**Algorithm:**
1. Filter records for SIP services ("E2U+sip")
2. Sort by order and preference
3. Return first (highest priority) record

**Parameters:**
- `records`: Slice of ENUM NAPTR records

**Returns:**
- `Some(EnumNaptrRecord)`: Best SIP record
- `None`: If no SIP records found

**Examples:**
```rust
use sip_dns::{EnumNaptrRecord, select_best_sip_record};

let records = vec![
    EnumNaptrRecord::new(100, 30, "u", "E2U+sip", "!^.*$!sip:c@example.com!", ""),
    EnumNaptrRecord::new(100, 20, "u", "E2U+mailto", "!^.*$!mailto:info@example.com!", ""),
    EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:best@example.com!", ""),
];

let best = select_best_sip_record(&records).unwrap();
assert_eq!(best.preference, 10);
assert_eq!(best.extract_uri(), Some("sip:best@example.com".to_string()));
```

---

### Types

#### `EnumNaptrRecord`

Represents an ENUM NAPTR (Naming Authority Pointer) record per RFC 3761.

**Fields:**
- `order: u16` - Order field (lower = higher priority for ordering)
- `preference: u16` - Preference field (lower = higher priority within same order)
- `flags: String` - Flags (typically "u" for terminal rule)
- `service: String` - Service field (e.g., "E2U+sip", "E2U+mailto")
- `regexp: String` - Regular expression for URI construction
- `replacement: String` - Replacement (typically empty for terminal rules)

**Methods:**

##### `new(order: u16, preference: u16, flags: impl Into<String>, service: impl Into<String>, regexp: impl Into<String>, replacement: impl Into<String>) -> Self`

Creates a new ENUM NAPTR record.

**Example:**
```rust
use sip_dns::EnumNaptrRecord;

let record = EnumNaptrRecord::new(
    100,
    10,
    "u",
    "E2U+sip",
    "!^.*$!sip:user@example.com!",
    ""
);
```

---

##### `is_sip_service(&self) -> bool`

Returns true if this is a SIP service record (service field is "E2U+sip", case-insensitive).

**Example:**
```rust
use sip_dns::EnumNaptrRecord;

let sip_record = EnumNaptrRecord::new(
    100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", ""
);
assert!(sip_record.is_sip_service());

let mailto_record = EnumNaptrRecord::new(
    100, 20, "u", "E2U+mailto", "!^.*$!mailto:info@example.com!", ""
);
assert!(!mailto_record.is_sip_service());
```

---

##### `is_terminal(&self) -> bool`

Returns true if this is a terminal rule (flags field contains 'u' or 'U').

**Example:**
```rust
use sip_dns::EnumNaptrRecord;

let record = EnumNaptrRecord::new(
    100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", ""
);
assert!(record.is_terminal());
```

---

##### `extract_uri(&self) -> Option<String>`

Extracts the URI from the regexp field.

ENUM regexps typically follow the format: `!pattern!replacement!flags`
This method extracts the replacement part (the consequent/URI).

**Regexp Format:**
- First character is the delimiter (typically '!' but can be '|', '#', etc.)
- Format: `delimiter` `pattern` `delimiter` `replacement` `delimiter` `[flags]`
- Returns the replacement part

**Returns:**
- `Some(String)`: URI extracted from regexp
- `None`: If regexp format is invalid or empty

**Examples:**
```rust
use sip_dns::EnumNaptrRecord;

// Standard regexp with '!' delimiter
let record = EnumNaptrRecord::new(
    100, 10, "u", "E2U+sip",
    "!^.*$!sip:user@example.com!",
    ""
);
assert_eq!(record.extract_uri(), Some("sip:user@example.com".to_string()));

// Different delimiter
let record2 = EnumNaptrRecord::new(
    100, 10, "u", "E2U+sip",
    "|^.*$|sip:bob@example.net|",
    ""
);
assert_eq!(record2.extract_uri(), Some("sip:bob@example.net".to_string()));

// Regexp with substitution pattern
let record3 = EnumNaptrRecord::new(
    100, 10, "u", "E2U+sip",
    "!^\\+1([0-9]{10})$!sip:\\1@example.com!",
    ""
);
// Returns the template (actual substitution would require regex engine)
assert_eq!(record3.extract_uri(), Some("sip:\\1@example.com".to_string()));
```

**Note:** This method extracts the URI template from the regexp but does not perform actual regex substitution. A full ENUM implementation would need to apply the pattern to the original E.164 number to produce the final URI.

---

## Usage Patterns

### Basic ENUM Lookup Flow

```rust
use sip_dns::{enum_to_domain, EnumNaptrRecord, select_best_sip_record};

// 1. Convert E.164 number to ENUM domain
let e164 = "+12025551234";
let domain = enum_to_domain(e164).expect("Invalid E.164 number");
// domain = "4.3.2.1.5.5.5.2.0.2.1.e164.arpa"

// 2. Query DNS for NAPTR records (actual DNS query not shown)
// let naptr_records = query_dns_naptr(domain);

// 3. Parse NAPTR records from DNS response (example)
let records = vec![
    EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:alice@example.com!", ""),
    EnumNaptrRecord::new(100, 20, "u", "E2U+mailto", "!^.*$!mailto:alice@example.com!", ""),
    EnumNaptrRecord::new(200, 10, "u", "E2U+sip", "!^.*$!sip:alice@backup.example.com!", ""),
];

// 4. Select best SIP record
let best_record = select_best_sip_record(&records).expect("No SIP records found");

// 5. Extract URI
let sip_uri = best_record.extract_uri().expect("Invalid regexp");
// sip_uri = "sip:alice@example.com"
```

### TelUri Integration

```rust
use sip_core::TelUri;
use sip_dns::tel_uri_to_enum_domain;

// Parse tel URI from SIP message
let tel = TelUri::parse("tel:+1-555-123-4567").expect("Invalid tel URI");

// Convert to ENUM domain
if let Some(domain) = tel_uri_to_enum_domain(&tel) {
    println!("ENUM domain: {}", domain);
    // Proceed with DNS lookup
} else {
    println!("Local tel URI, cannot use ENUM");
}
```

### Manual Record Processing

```rust
use sip_dns::{EnumNaptrRecord, sort_enum_records, filter_sip_records};

// Get NAPTR records from DNS
let mut all_records = vec![
    EnumNaptrRecord::new(100, 30, "u", "E2U+sip", "!^.*$!sip:c@example.com!", ""),
    EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:a@example.com!", ""),
    EnumNaptrRecord::new(100, 20, "u", "E2U+h323", "!^.*$!h323:user@example.com!", ""),
];

// Filter for SIP services only
let sip_records = filter_sip_records(&all_records);

// Sort by priority
let mut sorted = sip_records;
sort_enum_records(&mut sorted);

// Process in order
for record in sorted {
    if let Some(uri) = record.extract_uri() {
        println!("Try URI: {} (order={}, pref={})",
                 uri, record.order, record.preference);
    }
}
```

### Multi-Service Handling

```rust
use sip_dns::{EnumNaptrRecord, sort_enum_records};

let mut records = vec![
    EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", ""),
    EnumNaptrRecord::new(100, 20, "u", "E2U+mailto", "!^.*$!mailto:user@example.com!", ""),
    EnumNaptrRecord::new(100, 30, "u", "E2U+web:http", "!^.*$!http://example.com/user!", ""),
];

// Sort all records by priority
sort_enum_records(&mut records);

// Process by service type
for record in records {
    if record.is_sip_service() {
        println!("SIP: {}", record.extract_uri().unwrap());
    } else if record.service == "E2U+mailto" {
        println!("Email: {}", record.extract_uri().unwrap());
    } else {
        println!("Other service: {}", record.service);
    }
}
```

## Integration with Other Components

### With sip-core TelUri

The ENUM implementation integrates with the existing TelUri type from sip-core:

- TelUri already handles E.164 number parsing and normalization
- TelUri removes visual separators (hyphens, spaces) from tel URIs
- `tel_uri_to_enum_domain()` leverages TelUri's number field directly
- Only global tel URIs (is_global = true) can be converted to ENUM

**Example:**
```rust
use sip_core::TelUri;
use sip_dns::tel_uri_to_enum_domain;

// TelUri normalizes the number
let tel = TelUri::parse("tel:+1-555-123-4567").unwrap();
// tel.number = "+15551234567" (visual separators removed)

// ENUM conversion uses normalized number
let domain = tel_uri_to_enum_domain(&tel).unwrap();
assert_eq!(domain, "7.6.5.4.3.2.1.5.5.5.1.e164.arpa");
```

### With sip-dns Resolver

The ENUM module in sip-dns provides the data structures and conversion logic. Integration with DNS resolution would involve:

1. Use `enum_to_domain()` to convert E.164 number to DNS name
2. Query DNS for NAPTR records at that domain
3. Parse DNS response into `EnumNaptrRecord` structs
4. Use `select_best_sip_record()` to find the best match
5. Use `extract_uri()` to get the SIP URI

**Note:** Actual DNS querying is not yet implemented. The module currently provides the data structures and selection logic only.

### Future UAC Integration

In a User Agent Client (UAC) implementation, ENUM would be used to:

1. **Dial-by-Number**: Convert dialed telephone numbers to SIP URIs
   ```rust
   // User dials +1-555-1234
   let domain = enum_to_domain("+15551234")?;
   let records = dns_query_naptr(domain).await?;
   let best = select_best_sip_record(&records)?;
   let sip_uri = best.extract_uri()?;
   // Make SIP call to sip_uri
   ```

2. **Fallback Logic**: Try multiple ENUM records if connections fail
   ```rust
   let mut sip_records = filter_sip_records(&records);
   sort_enum_records(&mut sip_records);

   for record in sip_records {
       if let Some(uri) = record.extract_uri() {
           if try_call(uri).await.is_ok() {
               break;
           }
       }
   }
   ```

3. **tel: URI Resolution**: Handle tel: URIs in SIP messages
   ```rust
   if let Some(tel_uri) = parse_tel_uri(request_uri) {
       if let Some(domain) = tel_uri_to_enum_domain(&tel_uri) {
           // Look up via ENUM
       }
   }
   ```

## Test Coverage

The ENUM implementation includes 12 comprehensive unit tests covering all functionality:

### Conversion Tests

1. **converts_e164_to_enum_domain**: Verifies correct conversion of various E.164 numbers
   - `+12025332600` → `0.0.6.2.3.3.5.2.0.2.1.e164.arpa`
   - `+442079460123` → `3.2.1.0.6.4.9.7.0.2.4.4.e164.arpa`

2. **rejects_invalid_e164**: Validates input rejection
   - Missing '+' prefix
   - Non-digit characters (hyphens, spaces)
   - Empty string after '+'

3. **tel_uri_to_enum**: Tests TelUri integration
   - Global numbers convert successfully
   - Local numbers return None

### NAPTR Record Tests

4. **creates_naptr_record**: Basic record construction

5. **identifies_sip_service**: Service field detection
   - Correctly identifies "E2U+sip"
   - Case-insensitive matching
   - Distinguishes from other services

6. **extracts_uri_from_regexp**: URI extraction from regexp field
   - Standard '!' delimiter
   - Alternative delimiters ('|', '#')
   - Handles empty or invalid regexps

7. **extracts_uri_with_substitution**: Complex regexp patterns
   - Patterns with backreferences (\\1, \\2)
   - Returns template (not substituted)

### Sorting and Selection Tests

8. **sorts_records_by_preference**: Sorts by preference within same order

9. **sorts_records_by_order_then_preference**: Two-level sorting
   - Primary: order (ascending)
   - Secondary: preference (ascending)

10. **filters_sip_records**: Service filtering
    - Filters "E2U+sip" records
    - Excludes other services (mailto, h323, etc.)

11. **selects_best_sip_record**: End-to-end selection
    - Filters for SIP
    - Sorts by priority
    - Returns highest priority record

12. **selects_best_with_no_sip_records**: Edge case handling
    - Returns None when no SIP records exist

### Running Tests

```bash
# Run all ENUM tests
cargo test --package sip-dns enum

# Run specific test
cargo test --package sip-dns converts_e164_to_enum_domain

# Run with output
cargo test --package sip-dns enum -- --nocapture
```

## Limitations and Future Work

### Current Limitations

1. **No Actual DNS Queries**: The implementation provides data structures and conversion logic but does not perform actual DNS NAPTR queries. Integration with a DNS resolver library is needed.

2. **No Regexp Substitution**: The `extract_uri()` method returns the URI template from the regexp but does not perform regex substitution. For regexps like `!^\\+1([0-9]{10})$!sip:\\1@example.com!`, the backreference `\\1` is not replaced with the captured digits.

3. **No Random Selection**: When multiple records have the same order and preference, RFC 3824 recommends random selection. The current implementation returns them in input order.

4. **No Caching**: ENUM DNS responses should be cached according to their TTL. No caching mechanism is implemented.

5. **No DNSSEC Validation**: RFC 4035 (DNSSEC) validation is not implemented, though it's recommended for ENUM to prevent DNS spoofing attacks.

### Future Enhancements

1. **DNS Resolver Integration**
   - Integrate with trust-dns or similar DNS library
   - Implement NAPTR record queries
   - Parse DNS responses into EnumNaptrRecord structs

2. **Regexp Engine Integration**
   - Add regex crate dependency
   - Implement full regexp substitution
   - Support backreferences and captured groups

3. **Random Selection**
   - Implement RFC 3824-compliant random selection for equal-priority records
   - Consider using `rand` crate

4. **Caching Layer**
   - Implement DNS response caching with TTL expiration
   - Consider cache invalidation strategies

5. **DNSSEC Support**
   - Add DNSSEC validation for ENUM lookups
   - Verify RRSIG records

6. **Error Types**
   - Define specific error types for ENUM operations
   - Distinguish between DNS errors, parse errors, and validation errors

7. **Async DNS Queries**
   - Implement async ENUM lookup functions
   - Support timeout and retry logic

8. **ENUM+SIP UAC Integration**
   - Add ENUM lookup to UAC dialing logic
   - Implement fallback to PSTN or other methods if ENUM fails
   - Support tel: URI resolution in INVITE requests

## References

- **RFC 3824**: Using E.164 numbers with the Session Initiation Protocol (SIP)
- **RFC 3761**: The E.164 to Uniform Resource Identifiers (URI) Dynamic Delegation Discovery System (DDDS) Application (ENUM)
- **RFC 3403**: Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database
- **RFC 2915**: The Naming Authority Pointer (NAPTR) DNS Resource Record
- **RFC 3986**: Uniform Resource Identifier (URI): Generic Syntax

## Version History

- **Initial Implementation** (Current): Basic ENUM domain conversion, NAPTR record handling, and service selection
