# sip-parse

Fast and secure SIP message parser using nom combinators with built-in DoS protection.

## Features

- **RFC 3261 Compliant** - Complete SIP message parsing
- **Integer Overflow Protection** - Content-Length bounds checking prevents memory exhaustion
- **Zero-Copy Parsing** - Uses `Bytes` for efficient memory usage
- **Comprehensive Testing** - 30+ tests including security scenarios
- **tel URI Support** - RFC 3966 telephone number URIs

## Quick Start

```rust
use sip_parse::{parse_request, parse_response};
use bytes::Bytes;

// Parse SIP request
let data = Bytes::from("INVITE sip:bob@example.com SIP/2.0\r\n...");
if let Some(request) = parse_request(&data) {
    println!("Method: {:?}", request.start.method);
    println!("Request-URI: {}", request.start.uri);
}

// Parse SIP response
let data = Bytes::from("SIP/2.0 200 OK\r\n...");
if let Some(response) = parse_response(&data) {
    println!("Status: {}", response.start.code);
}
```

## Security Features

### Content-Length Integer Overflow Protection

The parser includes built-in protection against integer overflow attacks via malicious Content-Length headers.

**Maximum Content-Length: 64 MB**

This limit prevents:
- Integer overflow on 32-bit systems
- Memory exhaustion attacks
- Buffer overflow vulnerabilities

#### Attack Scenario (Prevented)

Without bounds checking:
```
Content-Length: 99999999999999999999
```

**Consequences**:
- Integer overflow during parsing
- Attempt to allocate petabytes of memory
- Server crash or OOM kill

**With bounds checking**:
- Parser detects value exceeds 64 MB limit
- Invalid Content-Length is ignored
- Message body is parsed using actual available bytes
- Server continues operating normally

### Limit Rationale

| Content Type | Typical Size | Maximum Allowed |
|--------------|--------------|-----------------|
| SIP request/response | < 1 KB | 64 MB |
| SDP body | < 5 KB | 64 MB |
| SDP with ICE candidates | < 100 KB | 64 MB |
| MIME attachments | Varies | 64 MB |

**Why 64 MB?**
- Typical SIP messages: < 10 KB (99.9% of traffic)
- SDP with many ICE candidates: < 100 KB
- Safety margin for legitimate large messages: 10 MB
- Absolute protection against DoS: 64 MB cap

### Bounds Checking Implementation

```rust
// Maximum allowed Content-Length (64 MB)
const MAX_CONTENT_LENGTH: usize = 64 * 1024 * 1024;

fn content_length(headers: &Headers) -> Option<usize> {
    // 1. Parse to u64 first (prevents 32-bit overflow)
    let value_u64 = headers.get("Content-Length")?.parse::<u64>().ok()?;

    // 2. Check if fits in usize (32-bit safety)
    if value_u64 > usize::MAX as u64 {
        return None;
    }

    // 3. Enforce security limit
    let length = value_u64 as usize;
    if length > MAX_CONTENT_LENGTH {
        return None;
    }

    Some(length)
}
```

### Test Coverage

The parser includes comprehensive security tests:

```rust
#[test]
fn content_length_rejects_overflow_values() {
    // Tests: 99999999999999999999 → None
}

#[test]
fn content_length_rejects_exceeds_max() {
    // Tests: 67108865 (64MB + 1) → None
}

#[test]
fn content_length_accepts_max_value() {
    // Tests: 67108864 (64MB exactly) → Some(67108864)
}
```

## Configuring Limits

The 64 MB limit is **hardcoded by design** for security. If you need larger messages:

### Option 1: Application-Level Chunking (Recommended)
```rust
// Split large content across multiple SIP messages
// Use Session Description Protocol (SDP) fragmentation
```

### Option 2: Out-of-Band Transfer (Recommended)
```rust
// Use SIP to negotiate transfer
// Send large content via HTTP/HTTPS/MSRP
```

### Option 3: Fork and Modify (Not Recommended)
```rust
// Modify MAX_CONTENT_LENGTH constant in lib.rs
// Understand security implications
// Implement additional memory protections
```

## Parser Behavior

### Valid Content-Length
```
Content-Length: 1234

→ Body extracted up to 1234 bytes
→ If body shorter, returns None (incomplete message)
```

### Invalid Content-Length (Ignored)
```
Content-Length: 999999999999  (exceeds 64 MB)

→ Parser ignores invalid value
→ Uses actual body length from buffer
→ Message still parsed successfully
```

### Missing Content-Length
```
(no Content-Length header)

→ Body length determined by message framing
→ TCP: Read until connection close or next message
→ UDP: Use entire datagram after headers
```

## Performance

- **Zero allocations** for header parsing (borrows from input)
- **Single pass** parsing with nom combinators
- **O(n)** complexity where n = message size
- **Optimized** for typical SIP message sizes (< 10 KB)

## Security Best Practices

1. **Always use the parser** - Don't implement custom Content-Length parsing
2. **Validate message sources** - Use TLS and authentication
3. **Rate limit connections** - Prevent flood attacks
4. **Monitor message sizes** - Alert on unusual patterns
5. **Update regularly** - Security patches and improvements

## Attack Mitigation

The parser protects against:

| Attack Type | Protection Mechanism |
|-------------|---------------------|
| Integer overflow | u64 parsing + bounds check |
| Memory exhaustion | 64 MB hard limit |
| Buffer overflow | Length validation before copy |
| Malformed headers | Robust error handling |
| Denial of Service | Resource limits |

## Examples

### Parsing with Security Monitoring

```rust
use sip_parse::parse_request;
use bytes::Bytes;

fn handle_message(data: &Bytes) {
    match parse_request(data) {
        Some(req) => {
            // Check body size
            if req.body.len() > 1_000_000 {
                log::warn!("Large message body: {} bytes", req.body.len());
            }
            // Process request...
        }
        None => {
            log::error!("Failed to parse SIP message");
        }
    }
}
```

### Detecting Attacks

```rust
// Monitor for suspicious Content-Length values
if let Some(cl_header) = headers.get("Content-Length") {
    if cl_header.len() > 10 {  // More than 10 digits
        log::alert!("Suspicious Content-Length: {}", cl_header);
        // Potential attack attempt
    }
}
```

## License

MIT OR Apache-2.0
