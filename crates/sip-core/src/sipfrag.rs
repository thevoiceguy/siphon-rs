// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP message fragments (RFC 3420) with security hardening.

use bytes::Bytes;
use smol_str::SmolStr;
use std::fmt;

use crate::{Headers, Method, RequestLine, Response, StatusLine, Uri};

// Security: Size limits
const MAX_SIPFRAG_BODY_SIZE: usize = 65536; // 64 KB

/// Error types for SipFrag operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipFragError {
    /// Body too large
    BodyTooLarge { max: usize },
    /// Invalid header
    InvalidHeader(String),
    /// Other validation error
    ValidationError(String),
}

impl fmt::Display for SipFragError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipFragError::BodyTooLarge { max } => {
                write!(f, "SipFrag body too large (max {} bytes)", max)
            }
            SipFragError::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            SipFragError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for SipFragError {}

/// A SIP message fragment per RFC 3420.
///
/// message/sipfrag can represent partial SIP messages containing:
/// - Optional start line (request or status line)
/// - Zero or more complete header fields
/// - Optional message body (with required Content-* headers if present)
///
/// # Security
///
/// SipFrag enforces:
/// - Maximum body size of 64 KB to prevent DoS attacks
/// - Private fields to prevent validation bypass
/// - Header validation through Headers type
///
/// This is commonly used in NOTIFY messages to report the status of
/// referenced requests (e.g., with REFER method).
///
/// # Builder Pattern Order
///
/// When adding a body, Content-Type and Content-Length headers **must be added first**.
/// Per RFC 3420, if a body is present, appropriate MIME headers must be included:
///
/// ```
/// use sip_core::SipFrag;
/// use smol_str::SmolStr;
///
/// // Correct order: headers before body
/// let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned())).unwrap()
///     .with_header("Content-Type", "text/plain").unwrap()
///     .with_header("Content-Length", "4").unwrap()
///     .with_body("test").unwrap();  // ✓ Headers present
///
/// // Wrong order will fail:
/// // let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned())).unwrap()
/// //     .with_body("test");  // ✗ Error: Content-Type/Length required
/// ```
///
/// # Example
///
/// ```
/// use sip_core::{SipFrag, StatusLine};
/// use smol_str::SmolStr;
///
/// // Status-only fragment (common for REFER notifications)
/// let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned())).unwrap();
/// assert_eq!(frag.to_string(), "SIP/2.0 200 OK\r\n");
///
/// // Complete response fragment
/// let status = StatusLine::new(603, SmolStr::new("Declined".to_owned())).unwrap();
/// let frag = SipFrag::response(status).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipFrag {
    /// Optional start line (request or response)
    start_line: Option<StartLine>,
    /// Header fields (may be empty)
    headers: Headers,
    /// Optional message body
    body: Bytes,
}

/// Start line of a SIP message fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartLine {
    /// Request line (method, URI, version)
    Request(RequestLine),
    /// Status line (version, code, reason)
    Response(StatusLine),
}

impl SipFrag {
    /// Creates an empty sipfrag with no start line, headers, or body.
    pub fn empty() -> Self {
        Self {
            start_line: None,
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    /// Creates a sipfrag containing only a status line (common for REFER notifications).
    ///
    /// # Example
    ///
    /// ```
    /// use sip_core::SipFrag;
    /// use smol_str::SmolStr;
    ///
    /// let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned())).unwrap();
    /// assert!(frag.is_response());
    /// ```
    pub fn status_only(code: u16, reason: SmolStr) -> Result<Self, SipFragError> {
        let status = StatusLine::new(code, reason).map_err(|e| {
            SipFragError::ValidationError(format!("Invalid status line: {}", e))
        })?;
        Ok(Self {
            start_line: Some(StartLine::Response(status)),
            headers: Headers::new(),
            body: Bytes::new(),
        })
    }

    /// Creates a sipfrag from a complete response (status line + headers + body).
    ///
    /// This is useful for creating detailed NOTIFY bodies that include
    /// headers from the referenced request.
    pub fn from_response(response: Response) -> Result<Self, SipFragError> {
        let (status, headers, body) = response.into_parts();

        if body.len() > MAX_SIPFRAG_BODY_SIZE {
            return Err(SipFragError::BodyTooLarge {
                max: MAX_SIPFRAG_BODY_SIZE,
            });
        }
        validate_body_headers(&headers, body.len())?;

        Ok(Self {
            start_line: Some(StartLine::Response(status)),
            headers,
            body,
        })
    }

    /// Creates a sipfrag with a response status line and headers.
    pub fn response(status: StatusLine) -> Result<Self, SipFragError> {
        Ok(Self {
            start_line: Some(StartLine::Response(status)),
            headers: Headers::new(),
            body: Bytes::new(),
        })
    }

    /// Creates a sipfrag with a request line.
    pub fn request(request_line: RequestLine) -> Result<Self, SipFragError> {
        Ok(Self {
            start_line: Some(StartLine::Request(request_line)),
            headers: Headers::new(),
            body: Bytes::new(),
        })
    }

    /// Creates a sipfrag with only headers (no start line or body).
    pub fn headers_only(headers: Headers) -> Self {
        Self {
            start_line: None,
            headers,
            body: Bytes::new(),
        }
    }

    /// Gets the start line.
    pub fn start_line(&self) -> Option<&StartLine> {
        self.start_line.as_ref()
    }

    /// Gets the headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Gets a mutable reference to the headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Gets the body.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Adds a header field to the fragment.
    pub fn with_header(
        mut self,
        name: impl Into<SmolStr>,
        value: impl Into<SmolStr>,
    ) -> Result<Self, SipFragError> {
        let name_str = name.into();
        let value_str = value.into();
        self.headers
            .push(name_str.as_str(), value_str.as_str())
            .map_err(|e| SipFragError::InvalidHeader(e.to_string()))?;
        Ok(self)
    }

    /// Adds a header field (fallible version).
    pub fn add_header(
        &mut self,
        name: impl Into<SmolStr>,
        value: impl Into<SmolStr>,
    ) -> Result<(), SipFragError> {
        let name_str = name.into();
        let value_str = value.into();
        self.headers
            .push(name_str.as_str(), value_str.as_str())
            .map_err(|e| SipFragError::InvalidHeader(e.to_string()))?;
        Ok(())
    }

    /// Sets the message body with size validation.
    ///
    /// **Important**: Content-Type and Content-Length headers must be added
    /// **before** calling this method. Per RFC 3420, if a body is present,
    /// appropriate MIME headers are required.
    ///
    /// # Errors
    ///
    /// Returns `SipFragError` if:
    /// - Body exceeds 64 KB
    /// - Content-Type header is missing
    /// - Content-Length header is missing or doesn't match body size
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Result<Self, SipFragError> {
        let body_bytes = body.into();

        if body_bytes.len() > MAX_SIPFRAG_BODY_SIZE {
            return Err(SipFragError::BodyTooLarge {
                max: MAX_SIPFRAG_BODY_SIZE,
            });
        }

        validate_body_headers(&self.headers, body_bytes.len())?;
        self.body = body_bytes;
        Ok(self)
    }

    /// Sets the message body (fallible version).
    ///
    /// **Important**: Content-Type and Content-Length headers must be present
    /// before calling this method. Per RFC 3420, if a body is present,
    /// appropriate MIME headers are required.
    ///
    /// # Errors
    ///
    /// Returns `SipFragError` if:
    /// - Body exceeds 64 KB
    /// - Content-Type header is missing
    /// - Content-Length header is missing or doesn't match body size
    pub fn set_body(&mut self, body: impl Into<Bytes>) -> Result<(), SipFragError> {
        let body_bytes = body.into();

        if body_bytes.len() > MAX_SIPFRAG_BODY_SIZE {
            return Err(SipFragError::BodyTooLarge {
                max: MAX_SIPFRAG_BODY_SIZE,
            });
        }

        validate_body_headers(&self.headers, body_bytes.len())?;
        self.body = body_bytes;
        Ok(())
    }

    /// Returns true if this fragment represents a response.
    pub fn is_response(&self) -> bool {
        matches!(self.start_line, Some(StartLine::Response(_)))
    }

    /// Returns true if this fragment represents a request.
    pub fn is_request(&self) -> bool {
        matches!(self.start_line, Some(StartLine::Request(_)))
    }

    /// Returns the status code if this is a response fragment.
    pub fn status_code(&self) -> Option<u16> {
        match &self.start_line {
            Some(StartLine::Response(status)) => Some(status.code()),
            _ => None,
        }
    }

    /// Returns the method if this is a request fragment.
    pub fn method(&self) -> Option<&Method> {
        match &self.start_line {
            Some(StartLine::Request(req)) => Some(req.method()),
            _ => None,
        }
    }

    /// Returns the request URI if this is a request fragment.
    pub fn request_uri(&self) -> Option<&Uri> {
        match &self.start_line {
            Some(StartLine::Request(req)) => Some(req.uri()),
            _ => None,
        }
    }
}

impl fmt::Display for SipFrag {
    /// Formats the sipfrag as a message/sipfrag body per RFC 3420.
    ///
    /// Uses CRLF line endings per SIP specification.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Start line (if present)
        if let Some(start_line) = &self.start_line {
            match start_line {
                StartLine::Request(req) => {
                    write!(
                        f,
                        "{} {} {}\r\n",
                        req.method().as_str(),
                        req.uri(),
                        req.version()
                    )?;
                }
                StartLine::Response(status) => {
                    write!(
                        f,
                        "{} {} {}\r\n",
                        status.version(),
                        status.code(),
                        status.reason()
                    )?;
                }
            }
        }

        // Headers
        for header in self.headers.iter() {
            write!(f, "{}: {}\r\n", header.name(), header.value())?;
        }

        // Body (if present, must include blank line separator)
        if !self.body.is_empty() {
            write!(f, "\r\n")?; // Blank line separates headers from body
            let body = std::str::from_utf8(&self.body).map_err(|_| fmt::Error)?;
            f.write_str(body)?;
        }

        Ok(())
    }
}

fn validate_body_headers(headers: &Headers, body_len: usize) -> Result<(), SipFragError> {
    if body_len == 0 {
        return Ok(());
    }

    if headers.get("Content-Type").is_none() {
        return Err(SipFragError::ValidationError(
            "Content-Type required when body is present".to_string(),
        ));
    }

    let content_length = headers.get("Content-Length").ok_or_else(|| {
        SipFragError::ValidationError("Content-Length required when body is present".to_string())
    })?;

    let parsed_len = content_length
        .trim()
        .parse::<usize>()
        .map_err(|_| SipFragError::ValidationError("Invalid Content-Length".to_string()))?;

    if parsed_len != body_len {
        return Err(SipFragError::ValidationError(format!(
            "Content-Length {} does not match body length {}",
            parsed_len, body_len
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sipfrag_empty() {
        let frag = SipFrag::empty();
        assert!(frag.start_line().is_none());
        assert!(frag.headers().is_empty());
        assert!(frag.body().is_empty());
        assert_eq!(frag.to_string(), "");
    }

    #[test]
    fn sipfrag_status_only() {
        let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned())).unwrap();
        assert!(frag.is_response());
        assert_eq!(frag.status_code(), Some(200));
        assert_eq!(frag.to_string(), "SIP/2.0 200 OK\r\n");
    }

    #[test]
    fn sipfrag_status_with_headers() {
        let frag = SipFrag::status_only(486, SmolStr::new("Busy Here".to_owned()))
            .unwrap()
            .with_header("Retry-After", "60")
            .unwrap();

        let output = frag.to_string();
        assert!(output.contains("SIP/2.0 486 Busy Here"));
        assert!(output.contains("Retry-After: 60"));
    }

    #[test]
    fn sipfrag_request_line() {
        let req_line = RequestLine::new(
            Method::Invite,
            Uri::Sip(crate::SipUri::parse("sip:bob@example.com").unwrap()),
        );
        let frag = SipFrag::request(req_line).unwrap();

        assert!(frag.is_request());
        assert_eq!(frag.method(), Some(&Method::Invite));
        assert!(frag
            .to_string()
            .contains("INVITE sip:bob@example.com SIP/2.0"));
    }

    #[test]
    fn sipfrag_headers_only() {
        let mut headers = Headers::new();
        headers
            .push("From", "sip:alice@example.com")
            .unwrap();
        headers
            .push("To", "sip:bob@example.com")
            .unwrap();

        let frag = SipFrag::headers_only(headers);
        assert!(frag.start_line().is_none());
        assert!(!frag.is_request());
        assert!(!frag.is_response());

        let output = frag.to_string();
        assert!(output.contains("From: sip:alice@example.com"));
        assert!(output.contains("To: sip:bob@example.com"));
    }

    #[test]
    fn sipfrag_with_body() {
        let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned()))
            .unwrap()
            .with_header("Content-Type", "text/plain")
            .unwrap()
            .with_header("Content-Length", "11")
            .unwrap()
            .with_body("Hello World")
            .unwrap();

        let output = frag.to_string();
        assert!(output.contains("SIP/2.0 200 OK"));
        assert!(output.contains("Content-Type: text/plain"));
        assert!(output.contains("Content-Length: 11"));
        assert!(output.contains("\r\n\r\nHello World"));
    }

    #[test]
    fn sipfrag_rejects_oversized_body() {
        let large_body = vec![b'x'; MAX_SIPFRAG_BODY_SIZE + 1];
        let result = SipFrag::status_only(200, SmolStr::new("OK".to_owned()))
            .unwrap()
            .with_body(Bytes::from(large_body));

        assert!(matches!(
            result,
            Err(SipFragError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn sipfrag_accepts_max_sized_body() {
        let max_body = vec![b'x'; MAX_SIPFRAG_BODY_SIZE];
        let result = SipFrag::status_only(200, SmolStr::new("OK".to_owned()))
            .unwrap()
            .with_header("Content-Type", "application/octet-stream")
            .unwrap()
            .with_header("Content-Length", MAX_SIPFRAG_BODY_SIZE.to_string())
            .unwrap()
            .with_body(Bytes::from(max_body));

        assert!(result.is_ok());
    }

    #[test]
    fn sipfrag_set_body_validates_size() {
        let mut frag = SipFrag::empty();
        let large_body = vec![b'x'; MAX_SIPFRAG_BODY_SIZE + 1];

        assert!(frag.set_body(Bytes::from(large_body)).is_err());
    }

    #[test]
    fn sipfrag_status_code_extraction() {
        let frag1 = SipFrag::status_only(404, SmolStr::new("Not Found".to_owned())).unwrap();
        assert_eq!(frag1.status_code(), Some(404));

        let frag2 = SipFrag::empty();
        assert_eq!(frag2.status_code(), None);
    }

    #[test]
    fn sipfrag_from_response() {
        let response = Response::new(
            StatusLine::new(603, SmolStr::new("Declined".to_owned())).unwrap(),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid response");

        let frag = SipFrag::from_response(response).unwrap();
        assert!(frag.is_response());
        assert_eq!(frag.status_code(), Some(603));
    }

    #[test]
    fn sipfrag_from_response_validates_body_size() {
        let large_body = vec![b'x'; MAX_SIPFRAG_BODY_SIZE + 1];
        let response = Response::new(
            StatusLine::new(200, SmolStr::new("OK".to_owned())).unwrap(),
            Headers::new(),
            Bytes::from(large_body),
        )
        .expect("valid response");

        let result = SipFrag::from_response(response);
        assert!(matches!(
            result,
            Err(SipFragError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn sipfrag_add_header_method() {
        let mut frag = SipFrag::empty();
        frag.add_header("From", "sip:alice@example.com").unwrap();
        frag.add_header("To", "sip:bob@example.com").unwrap();

        assert_eq!(frag.headers().len(), 2);
    }

    #[test]
    fn fields_are_private() {
        let frag = SipFrag::empty();

        // These should compile (read access via getters)
        let _ = frag.start_line();
        let _ = frag.headers();
        let _ = frag.body();

        // These should NOT compile:
        // frag.start_line = None;                    // ← Does not compile!
        // frag.headers = Headers::new();             // ← Does not compile!
        // frag.body = Bytes::new();                  // ← Does not compile!
    }

    #[test]
    fn sipfrag_getters_work() {
        let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned())).unwrap();

        assert!(frag.start_line().is_some());
        assert!(frag.headers().is_empty());
        assert!(frag.body().is_empty());
    }

    #[test]
    fn sipfrag_builder_pattern_with_results() {
        let result = SipFrag::status_only(200, SmolStr::new("OK".to_owned()))
            .and_then(|f| f.with_header("Content-Type", "text/plain"))
            .and_then(|f| f.with_header("Content-Length", "4"))
            .and_then(|f| f.with_body("test"));

        assert!(result.is_ok());
        let frag = result.unwrap();
        assert_eq!(frag.body().len(), 4);
    }
}
