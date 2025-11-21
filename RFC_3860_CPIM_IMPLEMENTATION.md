# RFC 3860/3862 CPIM Implementation

## Overview

This document describes the implementation of RFC 3860 ("Common Profile for Instant Messaging") and RFC 3862 ("Common Profile for Instant Messaging (CPIM) Message Format") in the sip-core crate.

## RFCs Implemented

- **RFC 3860**: Defines the Common Profile for Instant Messaging (abstract service model)
- **RFC 3862**: Defines the CPIM message format (Message/CPIM MIME type)

## Purpose

The Common Profile for Instant Messaging (CPIM) provides a standard message format that enables interoperability between different instant messaging systems. It defines:

1. A common message format that can be carried by any IM protocol
2. End-to-end message metadata (From, To, DateTime, Subject)
3. Support for internationalization and extensibility
4. A foundation for gateway services between different IM networks

CPIM messages are typically used in:
- SIP MESSAGE requests (RFC 3428)
- MSRP message transfer (RFC 4975)
- Gateway systems bridging different IM protocols

## Key Concepts

### Message Structure

A CPIM message consists of three distinct sections separated by blank lines:

```
[MIME Headers]
<blank line>
[Message Headers]
<blank line>
[Content Headers]
<blank line>
[Message Body]
```

### 1. MIME Headers

Identifies the message as CPIM format:
```
Content-type: Message/CPIM
```

### 2. Message Headers

End-to-end metadata about the message:
- **From**: Sender identity (URI with optional display name)
- **To**: Recipient(s) - multiple allowed
- **cc**: Courtesy copy recipient(s) - multiple allowed
- **DateTime**: ISO 8601 timestamp
- **Subject**: Message subject (multiple allowed with language tags)
- **NS**: Namespace declarations for extensions
- **Require**: Mandatory features for processing
- Custom headers (via namespace extensions)

### 3. Content Headers

MIME headers for the message body:
- **Content-type**: MIME type of the body (required)
- **Content-ID**: Unique identifier
- **Content-Disposition**: Presentation hints
- Other MIME headers as needed

### 4. Message Body

The actual message content (text, HTML, XML, binary, etc.)

## Implementation Structure

### Core Types

#### `CpimMessage`

The main structure representing a CPIM message:

```rust
pub struct CpimMessage {
    pub headers: BTreeMap<SmolStr, Vec<CpimHeader>>,
    pub content_type: SmolStr,
    pub content_headers: BTreeMap<SmolStr, SmolStr>,
    pub body: Vec<u8>,
}
```

**Fields:**
- `headers`: Message headers (From, To, DateTime, Subject, etc.)
- `content_type`: MIME type of the message body
- `content_headers`: Additional content headers (Content-ID, etc.)
- `body`: Raw message body bytes

**Builder Methods:**
- `new(content_type: &str, body: Vec<u8>)` - Creates a new message
- `with_from(from: &str)` - Sets the From header
- `with_to(to: &str)` - Adds a To recipient
- `with_datetime(datetime: &str)` - Sets the DateTime header
- `with_subject(subject: &str)` - Adds a Subject
- `with_subject_lang(subject: &str, lang: &str)` - Adds Subject with language tag
- `with_cc(cc: &str)` - Adds a cc recipient
- `with_ns(prefix: &str, uri: &str)` - Declares a namespace
- `with_require(feature: &str)` - Adds a required feature
- `with_content_header(name: &str, value: &str)` - Adds a content header

**Access Methods:**
- `get_header(name: &str)` - Gets first value of a header
- `get_header_values(name: &str)` - Gets all values of a header
- `body_as_string()` - Gets body as UTF-8 string if valid
- `to_string()` - Formats as CPIM message string

#### `CpimHeader`

Represents a message header with optional parameters:

```rust
pub struct CpimHeader {
    pub value: SmolStr,
    pub params: BTreeMap<SmolStr, SmolStr>,
}
```

**Fields:**
- `value`: The header value
- `params`: Parameters (e.g., `lang=en` for Subject headers)

**Methods:**
- `new(value: &str)` - Creates a new header
- `with_param(name: &str, value: &str)` - Adds a parameter

## Character Escaping

RFC 3862 requires UTF-8 encoding and defines escape sequences for control characters:

### Escape Sequences

- `\\` - Backslash
- `\"` - Double quote
- `\b` - Backspace (U+0008)
- `\t` - Tab (U+0009)
- `\n` - Line feed (U+000A)
- `\r` - Carriage return (U+000D)
- `\uxxxx` - Unicode codepoint (4 hex digits)

### Functions

- `escape_header_value(value: &str) -> String` - Escapes special characters
- `unescape_header_value(value: &str) -> Option<String>` - Unescapes sequences

## Parsing

### `parse_cpim(input: &str) -> Option<CpimMessage>`

Parses a CPIM message from a string.

**Returns:**
- `Some(CpimMessage)` if parsing succeeds
- `None` if the message is malformed

**Requirements:**
- Must contain "Content-type: Message/CPIM" in first section
- Must have at least 4 sections (MIME headers, message headers, content headers, body)
- Headers must follow "Name: Value" format
- Values with special characters must use escape sequences

## Usage Examples

### Creating a Simple Message

```rust
use sip_core::{CpimMessage, parse_cpim};

let msg = CpimMessage::new("text/plain", b"Hello, Bob!".to_vec())
    .with_from("Alice <im:alice@example.com>")
    .with_to("Bob <im:bob@example.com>")
    .with_datetime("2023-01-15T10:30:00Z")
    .with_subject("Greeting");

// Format as string
let cpim_str = msg.to_string();
println!("{}", cpim_str);
```

Output:
```
Content-type: Message/CPIM

From: Alice <im:alice@example.com>
To: Bob <im:bob@example.com>
DateTime: 2023-01-15T10:30:00Z
Subject: Greeting

Content-type: text/plain

Hello, Bob!
```

### Multiple Recipients

```rust
let mut msg = CpimMessage::new("text/plain", b"Hello everyone!".to_vec())
    .with_from("Alice <im:alice@example.com>");

msg.add_header("To", "Bob <im:bob@example.com>");
msg.add_header("To", "Charlie <im:charlie@example.com>");
msg.add_header("cc", "Dave <im:dave@example.com>");

let recipients = msg.get_header_values("To");
// recipients = ["Bob <im:bob@example.com>", "Charlie <im:charlie@example.com>"]
```

### Multilingual Subject

```rust
let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
    .with_from("Alice <im:alice@example.com>")
    .with_to("Bob <im:bob@example.com>")
    .with_subject_lang("Hello", "en")
    .with_subject_lang("Bonjour", "fr")
    .with_subject_lang("Hola", "es");

// Recipients can display subject in their preferred language
```

### Namespace Extensions

```rust
let msg = CpimMessage::new("text/plain", b"Important message".to_vec())
    .with_from("Alice <im:alice@example.com>")
    .with_to("Bob <im:bob@example.com>")
    .with_ns("MyFeatures", "mid:MessageFeatures@id.foo.com")
    .with_require("MyFeatures.VitalMessageOption");

// Add custom namespaced header
let mut header = CpimHeader::new("Confirmation-requested");
msg.add_header_obj("MyFeatures.VitalMessageOption", header);
```

### Content Headers

```rust
let msg = CpimMessage::new("text/html", b"<html><body>Hello</body></html>".to_vec())
    .with_from("Alice <im:alice@example.com>")
    .with_to("Bob <im:bob@example.com>")
    .with_content_header("Content-ID", "<1234@example.com>")
    .with_content_header("Content-Disposition", "inline");
```

### Parsing Messages

```rust
let cpim_str = r#"Content-type: Message/CPIM

From: Alice <im:alice@example.com>
To: Bob <im:bob@example.com>
DateTime: 2023-01-15T10:30:00Z
Subject: Hello

Content-type: text/plain

Hello, Bob!"#;

let msg = parse_cpim(cpim_str).unwrap();
assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
assert_eq!(msg.get_header("To"), Some("Bob <im:bob@example.com>"));
assert_eq!(msg.body_as_string(), Some("Hello, Bob!".to_string()));
```

### Handling Escaped Characters

```rust
let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
    .with_subject("Line 1\nLine 2\tTabbed");

let cpim_str = msg.to_string();
// Subject will be escaped: "Subject: Line 1\\nLine 2\\tTabbed"

let parsed = parse_cpim(&cpim_str).unwrap();
assert_eq!(parsed.get_header("Subject"), Some("Line 1\nLine 2\tTabbed"));
// Unescaped correctly
```

## Integration with SIP MESSAGE

CPIM is commonly used as the message body in SIP MESSAGE requests:

```rust
use sip_core::{Request, Method, CpimMessage};

// Create CPIM message
let cpim = CpimMessage::new("text/plain", b"Hello!".to_vec())
    .with_from("Alice <im:alice@example.com>")
    .with_to("Bob <im:bob@example.com>")
    .with_datetime("2023-01-15T10:30:00Z");

// Create SIP MESSAGE request
let mut request = Request::new(
    Method::MESSAGE,
    "sip:bob@example.com".parse().unwrap(),
);

// Set Content-Type header to Message/CPIM
request.headers_mut().set(
    "Content-Type",
    "Message/CPIM",
);

// Set body to CPIM message
request.set_body(cpim.to_string().into_bytes());
```

## DateTime Format

The DateTime header uses ISO 8601 format with timezone:

**Valid Formats:**
```
2023-01-15T10:30:00Z              # UTC
2023-01-15T10:30:00-05:00         # EST (UTC-5)
2023-01-15T10:30:00+09:00         # JST (UTC+9)
2023-01-15T10:30:00.123Z          # With milliseconds
```

**Example:**
```rust
use chrono::Utc;

let now = Utc::now().to_rfc3339();
let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
    .with_datetime(&now);
```

## Addressing

CPIM uses the "im:" URI scheme for instant messaging addresses:

**Format:** `im:user@domain`

**Examples:**
```
im:alice@example.com
im:+12125551234@sms.example.com
im:user123@jabber.example.org
```

**With Display Names:**
```
Alice <im:alice@example.com>
Bob Smith <im:bob@example.com>
"Alice in Wonderland" <im:alice@example.com>
```

## Extensibility

### Namespace Declarations

Use the NS header to declare namespaces for custom extensions:

```rust
let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
    .with_ns("Example", "http://example.com/cpim-extensions");

// Add custom headers using the namespace prefix
msg.add_header("Example.Priority", "urgent");
msg.add_header("Example.Category", "business");
```

### Require Header

Use the Require header to indicate mandatory features:

```rust
let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
    .with_ns("Delivery", "http://example.com/delivery")
    .with_require("Delivery.Receipt");

// Processors that don't support Delivery.Receipt should reject the message
```

## Security Considerations

### S/MIME and PGP

CPIM messages can be wrapped in S/MIME or PGP MIME structures for:
- **Signing**: Verify sender authenticity
- **Encryption**: Protect message confidentiality

**Example Structure:**
```
Content-Type: multipart/signed; protocol="application/pkcs7-signature"

--boundary
Content-type: Message/CPIM

From: Alice <im:alice@example.com>
...
--boundary
Content-Type: application/pkcs7-signature

[Signature data]
--boundary--
```

### Immutability

RFC 3862 emphasizes that CPIM message content MUST NOT be modified by intermediaries:
- Gateways must preserve the original CPIM structure
- Only the transport protocol headers should be modified
- End-to-end integrity is critical for security

## Testing

The implementation includes 15 comprehensive tests covering:

1. **Message Creation**
   - Simple messages with basic headers
   - Multiple recipients (To, cc)
   - Language-tagged subjects
   - Namespace extensions
   - Content headers

2. **Character Escaping**
   - Special characters (backslash, quotes)
   - Control characters (tab, newline, carriage return)
   - Unicode escape sequences

3. **Parsing**
   - Simple messages
   - Multiple subjects with language tags
   - Round-trip (format → parse → format)

4. **Header Management**
   - Getting first header value
   - Getting all header values
   - Header parameters

### Running Tests

```bash
cargo test --package sip-core cpim
```

All 15 tests pass successfully.

## Complete Example

Here's a comprehensive example from RFC 3862:

```
Content-type: Message/CPIM

From: MR SANDERS <im:piglet@100akerwood.com>
To: Donkey <im:eeyore@100akerwood.com>
DateTime: 2000-12-13T13:40:00-08:00
Subject: the weather will be fine today
Subject:;lang=fr beau temps prevu pour aujourd'hui
NS: MyFeatures <mid:MessageFeatures@id.foo.com>
Require: MyFeatures.VitalMessageOption
MyFeatures.VitalMessageOption: Confirmation-requested

Content-type: text/xml; charset=utf-8
Content-ID: <1234567890@foo.com>

<body>
Here is the text of my message.
</body>
```

Rust code to create this message:

```rust
let msg = CpimMessage::new(
    "text/xml; charset=utf-8",
    b"<body>\nHere is the text of my message.\n</body>".to_vec()
)
    .with_from("MR SANDERS <im:piglet@100akerwood.com>")
    .with_to("Donkey <im:eeyore@100akerwood.com>")
    .with_datetime("2000-12-13T13:40:00-08:00")
    .with_subject("the weather will be fine today")
    .with_subject_lang("beau temps prevu pour aujourd'hui", "fr")
    .with_ns("MyFeatures", "mid:MessageFeatures@id.foo.com")
    .with_require("MyFeatures.VitalMessageOption")
    .with_content_header("Content-ID", "<1234567890@foo.com>");

// Add custom namespaced header
let mut custom_header = CpimHeader::new("Confirmation-requested");
msg.add_header_obj("MyFeatures.VitalMessageOption", custom_header);

println!("{}", msg.to_string());
```

## File Locations

- **Implementation**: `/home/siphon/siphon-rs/crates/sip-core/src/cpim.rs`
- **Tests**: Included in the same file (15 unit tests)
- **Exports**: `/home/siphon/siphon-rs/crates/sip-core/src/lib.rs`

## Module Exports

The following types are exported from sip-core:

```rust
pub use cpim::{
    parse_cpim,
    CpimHeader,
    CpimMessage,
};
```

## Limitations

### Current Implementation

1. **Basic XML/HTML Support**: The body is treated as raw bytes; no special handling for XML/HTML
2. **No Schema Validation**: Custom namespaces are not validated
3. **Simple Parsing**: The parser is basic and suitable for well-formed messages
4. **No Multipart Support**: Multipart MIME bodies (for S/MIME) must be handled externally

### Recommended Enhancements

For production use, consider:

1. **Robust XML/HTML Parsing**: Use dedicated libraries for structured content
2. **MIME Multipart**: Integrate with a MIME library for S/MIME support
3. **DateTime Parsing**: Use `chrono` for proper datetime handling
4. **URI Validation**: Validate "im:" URIs according to RFC 3861
5. **Namespace Registry**: Maintain a registry of known namespace extensions

## References

- [RFC 3860: Common Profile for Instant Messaging (CPIM)](https://www.rfc-editor.org/rfc/rfc3860.html)
- [RFC 3862: Common Profile for Instant Messaging (CPIM) Message Format](https://www.rfc-editor.org/rfc/rfc3862.html)
- [RFC 3861: Address Resolution for Instant Messaging and Presence](https://www.rfc-editor.org/rfc/rfc3861.html)
- [RFC 3428: Session Initiation Protocol (SIP) Extension for Instant Messaging](https://www.rfc-editor.org/rfc/rfc3428.html)
- [RFC 4975: The Message Session Relay Protocol (MSRP)](https://www.rfc-editor.org/rfc/rfc4975.html)

## Compliance

This implementation complies with:
- RFC 3860 (Common Profile for Instant Messaging)
- RFC 3862 (CPIM Message Format)
- UTF-8 character encoding (RFC 3629)
- ISO 8601 datetime format

## Status

✅ **Implementation Complete**
- All core types implemented
- Character escaping/unescaping working
- Parsing functional
- All tests passing (15/15)
- Documentation complete
