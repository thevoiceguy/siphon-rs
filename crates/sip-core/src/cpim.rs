//! Common Profile for Instant Messaging (CPIM) message format.
//!
//! This module implements RFC 3860 (Common Profile for Instant Messaging) and
//! RFC 3862 (Common Profile for Instant Messaging (CPIM) Message Format).
//!
//! CPIM provides a standard message format for instant messaging that can be used
//! across different IM protocols, enabling interoperability through gateways.
//!
//! # Message Structure
//!
//! A CPIM message consists of three parts:
//! 1. MIME headers (Content-type: Message/CPIM)
//! 2. Message headers (From, To, DateTime, Subject, etc.)
//! 3. Message content (MIME-encapsulated body)
//!
//! # Example
//!
//! ```text
//! Content-type: Message/CPIM
//!
//! From: Alice <im:alice@example.com>
//! To: Bob <im:bob@example.com>
//! DateTime: 2023-01-15T10:30:00Z
//! Subject: Hello
//!
//! Content-type: text/plain
//!
//! Hello, Bob!
//! ```

use std::collections::BTreeMap;
use std::fmt;

use smol_str::SmolStr;

/// A CPIM message containing headers and content.
///
/// CPIM messages are used for instant messaging interoperability and include
/// end-to-end metadata (From, To, DateTime, Subject, etc.) along with the
/// message content.
#[derive(Debug, Clone, PartialEq)]
pub struct CpimMessage {
    /// Message headers (From, To, DateTime, Subject, NS, Require, etc.)
    pub headers: BTreeMap<SmolStr, Vec<CpimHeader>>,
    /// Content type of the message body
    pub content_type: SmolStr,
    /// Additional content headers (Content-ID, Content-Disposition, etc.)
    pub content_headers: BTreeMap<SmolStr, SmolStr>,
    /// The message body
    pub body: Vec<u8>,
}

/// A CPIM message header with optional parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct CpimHeader {
    /// Header value
    pub value: SmolStr,
    /// Header parameters (e.g., lang=en for Subject)
    pub params: BTreeMap<SmolStr, SmolStr>,
}

impl CpimMessage {
    /// Creates a new CPIM message with the given content type and body.
    pub fn new(content_type: &str, body: Vec<u8>) -> Self {
        Self {
            headers: BTreeMap::new(),
            content_type: SmolStr::new(content_type),
            content_headers: BTreeMap::new(),
            body,
        }
    }

    /// Sets the From header.
    pub fn with_from(mut self, from: &str) -> Self {
        self.set_header("From", from);
        self
    }

    /// Sets the To header.
    pub fn with_to(mut self, to: &str) -> Self {
        self.add_header("To", to);
        self
    }

    /// Sets the DateTime header.
    pub fn with_datetime(mut self, datetime: &str) -> Self {
        self.set_header("DateTime", datetime);
        self
    }

    /// Sets the Subject header.
    pub fn with_subject(mut self, subject: &str) -> Self {
        self.add_header("Subject", subject);
        self
    }

    /// Sets the Subject header with a language tag.
    pub fn with_subject_lang(mut self, subject: &str, lang: &str) -> Self {
        let mut header = CpimHeader::new(subject);
        header
            .params
            .insert(SmolStr::new("lang"), SmolStr::new(lang));
        self.add_header_obj("Subject", header);
        self
    }

    /// Adds a cc (courtesy copy) recipient.
    pub fn with_cc(mut self, cc: &str) -> Self {
        self.add_header("cc", cc);
        self
    }

    /// Adds a namespace declaration.
    pub fn with_ns(mut self, prefix: &str, uri: &str) -> Self {
        let value = format!("{} <{}>", prefix, uri);
        self.add_header("NS", &value);
        self
    }

    /// Adds a Require header.
    pub fn with_require(mut self, feature: &str) -> Self {
        self.add_header("Require", feature);
        self
    }

    /// Adds a content header (e.g., Content-ID, Content-Disposition).
    pub fn with_content_header(mut self, name: &str, value: &str) -> Self {
        self.content_headers
            .insert(SmolStr::new(name), SmolStr::new(value));
        self
    }

    /// Sets a header, replacing any existing values.
    pub fn set_header(&mut self, name: &str, value: &str) {
        let header = CpimHeader::new(value);
        self.headers.insert(SmolStr::new(name), vec![header]);
    }

    /// Adds a header value (allows multiple values for the same header).
    pub fn add_header(&mut self, name: &str, value: &str) {
        let header = CpimHeader::new(value);
        self.add_header_obj(name, header);
    }

    /// Adds a header object.
    pub fn add_header_obj(&mut self, name: &str, header: CpimHeader) {
        self.headers
            .entry(SmolStr::new(name))
            .or_default()
            .push(header);
    }

    /// Gets the first value of a header.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|values| values.first())
            .map(|h| h.value.as_str())
    }

    /// Gets all values of a header.
    pub fn get_header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .get(name)
            .map(|values| values.iter().map(|h| h.value.as_str()).collect())
            .unwrap_or_default()
    }

    /// Gets the message body as a UTF-8 string, if valid.
    pub fn body_as_string(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    /// Formats the CPIM message as a string.
    pub fn to_string(&self) -> String {
        let mut result = String::new();

        // MIME header
        result.push_str("Content-type: Message/CPIM\r\n\r\n");

        // Message headers
        for (name, values) in &self.headers {
            for header in values {
                result.push_str(name);
                result.push(':');

                // Add parameters if present
                if !header.params.is_empty() {
                    for (param_name, param_value) in &header.params {
                        result.push(';');
                        result.push_str(param_name);
                        result.push('=');
                        result.push_str(param_value);
                    }
                }

                result.push(' ');
                result.push_str(&escape_header_value(&header.value));
                result.push_str("\r\n");
            }
        }

        // Blank line separating headers from content
        result.push_str("\r\n");

        // Content headers
        result.push_str("Content-type: ");
        result.push_str(&self.content_type);
        result.push_str("\r\n");

        for (name, value) in &self.content_headers {
            result.push_str(name);
            result.push_str(": ");
            result.push_str(value);
            result.push_str("\r\n");
        }

        // Blank line before body
        result.push_str("\r\n");

        // Body
        if let Ok(body_str) = std::str::from_utf8(&self.body) {
            result.push_str(body_str);
        }

        result
    }
}

impl CpimHeader {
    /// Creates a new CPIM header with the given value.
    pub fn new(value: &str) -> Self {
        Self {
            value: SmolStr::new(value),
            params: BTreeMap::new(),
        }
    }

    /// Adds a parameter to the header.
    pub fn with_param(mut self, name: &str, value: &str) -> Self {
        self.params.insert(SmolStr::new(name), SmolStr::new(value));
        self
    }
}

impl fmt::Display for CpimMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Escapes special characters in a header value according to RFC 3862.
///
/// Control characters must be escaped using the following sequences:
/// - `\\` for backslash
/// - `\\"` for quote
/// - `\\b` for backspace
/// - `\\t` for tab
/// - `\\n` for linefeed
/// - `\\r` for carriage return
/// - `\\uxxxx` for Unicode codepoints
fn escape_header_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\x08' => result.push_str("\\b"),
            '\t' => result.push_str("\\t"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result
}

/// Unescapes special characters in a header value according to RFC 3862.
fn unescape_header_value(value: &str) -> Option<String> {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('b') => result.push('\x08'),
                Some('t') => result.push('\t'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('u') => {
                    // Read 4 hex digits
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() == 4 {
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(unicode_char) = char::from_u32(code) {
                                result.push(unicode_char);
                            } else {
                                return None;
                            }
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        } else {
            result.push(ch);
        }
    }

    Some(result)
}

/// Parses a CPIM message from a string.
///
/// Returns `None` if the message is malformed or doesn't follow the CPIM format.
pub fn parse_cpim(input: &str) -> Option<CpimMessage> {
    let input = input.trim();

    // Split into sections by blank lines (CRLF CRLF or LF LF)
    let sections: Vec<&str> = if input.contains("\r\n\r\n") {
        input.split("\r\n\r\n").collect()
    } else {
        input.split("\n\n").collect()
    };

    if sections.len() < 4 {
        return None;
    }

    // First section: MIME headers (should contain Content-type: Message/CPIM)
    let mime_section = sections[0];
    if !mime_section.to_lowercase().contains("message/cpim") {
        return None;
    }

    // Second section: Message headers
    let headers_section = sections[1];
    let headers = parse_headers(headers_section)?;

    // Third section: Content headers
    let content_headers_section = sections[2];

    // Parse content headers
    let mut content_type = SmolStr::new("text/plain");
    let mut content_headers = BTreeMap::new();

    let line_sep = if content_headers_section.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    for line in content_headers_section.split(line_sep) {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("Content-type")
                || name.eq_ignore_ascii_case("Content-Type")
            {
                content_type = SmolStr::new(value);
            } else {
                content_headers.insert(SmolStr::new(name), SmolStr::new(value));
            }
        }
    }

    // Fourth section onwards: Body (join remaining sections in case body contains blank lines)
    let body_str = sections[3..].join("\r\n\r\n");
    let body = body_str.as_bytes().to_vec();

    Some(CpimMessage {
        headers,
        content_type,
        content_headers,
        body,
    })
}

/// Parses CPIM headers from a string.
fn parse_headers(input: &str) -> Option<BTreeMap<SmolStr, Vec<CpimHeader>>> {
    let mut headers = BTreeMap::new();

    let line_sep = if input.contains("\r\n") { "\r\n" } else { "\n" };

    for line in input.split(line_sep) {
        if line.is_empty() {
            continue;
        }

        // Split into name and value
        let (name_with_params, value) = line.split_once(':')?;

        // Parse header name and parameters
        let mut parts = name_with_params.split(';');
        let name = parts.next()?.trim();

        let mut params = BTreeMap::new();
        for param in parts {
            if let Some((param_name, param_value)) = param.split_once('=') {
                params.insert(
                    SmolStr::new(param_name.trim()),
                    SmolStr::new(param_value.trim()),
                );
            }
        }

        // Unescape the value
        let unescaped_value = unescape_header_value(value.trim())?;

        let header = CpimHeader {
            value: SmolStr::new(&unescaped_value),
            params,
        };

        headers
            .entry(SmolStr::new(name))
            .or_insert_with(Vec::new)
            .push(header);
    }

    Some(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_cpim_message() {
        let msg = CpimMessage::new("text/plain", b"Hello, World!".to_vec())
            .with_from("Alice <im:alice@example.com>")
            .with_to("Bob <im:bob@example.com>")
            .with_datetime("2023-01-15T10:30:00Z")
            .with_subject("Greeting");

        assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
        assert_eq!(msg.get_header("To"), Some("Bob <im:bob@example.com>"));
        assert_eq!(msg.get_header("DateTime"), Some("2023-01-15T10:30:00Z"));
        assert_eq!(msg.get_header("Subject"), Some("Greeting"));
        assert_eq!(msg.content_type, "text/plain");
        assert_eq!(msg.body_as_string(), Some("Hello, World!".to_string()));
    }

    #[test]
    fn cpim_with_multiple_recipients() {
        let mut msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .with_from("Alice <im:alice@example.com>");
        msg.add_header("To", "Bob <im:bob@example.com>");
        msg.add_header("To", "Charlie <im:charlie@example.com>");

        let to_values = msg.get_header_values("To");
        assert_eq!(to_values.len(), 2);
        assert_eq!(to_values[0], "Bob <im:bob@example.com>");
        assert_eq!(to_values[1], "Charlie <im:charlie@example.com>");
    }

    #[test]
    fn cpim_with_language_tagged_subject() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .with_subject_lang("Hello", "en")
            .with_subject_lang("Bonjour", "fr");

        let subjects = msg.get_header_values("Subject");
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0], "Hello");
        assert_eq!(subjects[1], "Bonjour");

        // Check parameters
        let subject_headers = msg.headers.get("Subject").unwrap();
        assert_eq!(
            subject_headers[0].params.get("lang"),
            Some(&SmolStr::new("en"))
        );
        assert_eq!(
            subject_headers[1].params.get("lang"),
            Some(&SmolStr::new("fr"))
        );
    }

    #[test]
    fn cpim_with_namespace() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .with_ns("MyFeatures", "mid:MessageFeatures@id.foo.com")
            .with_require("MyFeatures.VitalMessageOption");

        assert_eq!(
            msg.get_header("NS"),
            Some("MyFeatures <mid:MessageFeatures@id.foo.com>")
        );
        assert_eq!(
            msg.get_header("Require"),
            Some("MyFeatures.VitalMessageOption")
        );
    }

    #[test]
    fn cpim_with_cc() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .with_from("Alice <im:alice@example.com>")
            .with_to("Bob <im:bob@example.com>")
            .with_cc("Charlie <im:charlie@example.com>");

        assert_eq!(
            msg.get_header("cc"),
            Some("Charlie <im:charlie@example.com>")
        );
    }

    #[test]
    fn cpim_with_content_headers() {
        let msg = CpimMessage::new("text/plain", b"Hello".to_vec())
            .with_from("Alice <im:alice@example.com>")
            .with_to("Bob <im:bob@example.com>")
            .with_content_header("Content-ID", "<1234567890@example.com>")
            .with_content_header("Content-Disposition", "inline");

        assert_eq!(
            msg.content_headers.get("Content-ID"),
            Some(&SmolStr::new("<1234567890@example.com>"))
        );
        assert_eq!(
            msg.content_headers.get("Content-Disposition"),
            Some(&SmolStr::new("inline"))
        );
    }

    #[test]
    fn escape_special_characters() {
        let escaped = escape_header_value("Hello\nWorld\r\nTab:\t Quote:\" Backslash:\\");
        assert_eq!(
            escaped,
            "Hello\\nWorld\\r\\nTab:\\t Quote:\\\" Backslash:\\\\"
        );
    }

    #[test]
    fn unescape_special_characters() {
        let unescaped =
            unescape_header_value("Hello\\nWorld\\r\\nTab:\\t Quote:\\\" Backslash:\\\\").unwrap();
        assert_eq!(unescaped, "Hello\nWorld\r\nTab:\t Quote:\" Backslash:\\");
    }

    #[test]
    fn escape_unicode() {
        let escaped = escape_header_value("Hello\x01World");
        assert_eq!(escaped, "Hello\\u0001World");
    }

    #[test]
    fn unescape_unicode() {
        let unescaped = unescape_header_value("Hello\\u0001World").unwrap();
        assert_eq!(unescaped, "Hello\x01World");
    }

    #[test]
    fn format_cpim_message() {
        let msg = CpimMessage::new("text/plain", b"Hello, World!".to_vec())
            .with_from("Alice <im:alice@example.com>")
            .with_to("Bob <im:bob@example.com>")
            .with_datetime("2023-01-15T10:30:00Z")
            .with_subject("Greeting");

        let formatted = msg.to_string();
        assert!(formatted.contains("Content-type: Message/CPIM"));
        assert!(formatted.contains("From: Alice <im:alice@example.com>"));
        assert!(formatted.contains("To: Bob <im:bob@example.com>"));
        assert!(formatted.contains("DateTime: 2023-01-15T10:30:00Z"));
        assert!(formatted.contains("Subject: Greeting"));
        assert!(formatted.contains("Content-type: text/plain"));
        assert!(formatted.contains("Hello, World!"));
    }

    #[test]
    fn parse_simple_cpim_message() {
        let input = "Content-type: Message/CPIM\r\n\r\nFrom: Alice <im:alice@example.com>\r\nTo: Bob <im:bob@example.com>\r\nDateTime: 2023-01-15T10:30:00Z\r\nSubject: Greeting\r\n\r\nContent-type: text/plain\r\n\r\nHello, World!";

        let msg = parse_cpim(input).unwrap();
        assert_eq!(msg.get_header("From"), Some("Alice <im:alice@example.com>"));
        assert_eq!(msg.get_header("To"), Some("Bob <im:bob@example.com>"));
        assert_eq!(msg.get_header("DateTime"), Some("2023-01-15T10:30:00Z"));
        assert_eq!(msg.get_header("Subject"), Some("Greeting"));
        assert_eq!(msg.content_type, "text/plain");
        assert_eq!(msg.body_as_string(), Some("Hello, World!".to_string()));
    }

    #[test]
    fn parse_cpim_with_multiple_subjects() {
        let input = "Content-type: Message/CPIM\r\n\r\nFrom: Alice <im:alice@example.com>\r\nTo: Bob <im:bob@example.com>\r\nSubject: Hello\r\nSubject;lang=fr: Bonjour\r\n\r\nContent-type: text/plain\r\n\r\nHello";

        let msg = parse_cpim(input).unwrap();
        let subjects = msg.get_header_values("Subject");
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0], "Hello");
        assert_eq!(subjects[1], "Bonjour");

        let subject_headers = msg.headers.get("Subject").unwrap();
        assert_eq!(
            subject_headers[1].params.get("lang"),
            Some(&SmolStr::new("fr"))
        );
    }

    #[test]
    fn round_trip_cpim() {
        let original = CpimMessage::new("text/plain", b"Test message".to_vec())
            .with_from("Alice <im:alice@example.com>")
            .with_to("Bob <im:bob@example.com>")
            .with_datetime("2023-01-15T10:30:00Z")
            .with_subject("Test");

        let formatted = original.to_string();
        let parsed = parse_cpim(&formatted).unwrap();

        assert_eq!(parsed.get_header("From"), original.get_header("From"));
        assert_eq!(parsed.get_header("To"), original.get_header("To"));
        assert_eq!(
            parsed.get_header("DateTime"),
            original.get_header("DateTime")
        );
        assert_eq!(parsed.get_header("Subject"), original.get_header("Subject"));
        assert_eq!(parsed.body_as_string(), original.body_as_string());
    }

    #[test]
    fn cpim_header_with_params() {
        let header = CpimHeader::new("Hello")
            .with_param("lang", "en")
            .with_param("charset", "utf-8");

        assert_eq!(header.value, "Hello");
        assert_eq!(header.params.get("lang"), Some(&SmolStr::new("en")));
        assert_eq!(header.params.get("charset"), Some(&SmolStr::new("utf-8")));
    }
}
