// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use bytes::Bytes;
use smol_str::SmolStr;

use crate::{
    headers::Headers,
    method::Method,
    uri::{SipUri, Uri},
    version::SipVersion,
};

const MAX_REASON_LENGTH: usize = 256;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    InvalidStatusCode { code: u16 },
    ReasonTooLong { max: usize, actual: usize },
    InvalidReason(String),
    BodyTooLarge { max: usize, actual: usize },
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStatusCode { code } => {
                write!(f, "invalid SIP status code: {} (must be 100-699)", code)
            }
            Self::ReasonTooLong { max, actual } => {
                write!(f, "reason phrase too long (max {}, got {})", max, actual)
            }
            Self::InvalidReason(msg) => write!(f, "invalid reason phrase: {}", msg),
            Self::BodyTooLarge { max, actual } => {
                write!(f, "body too large (max {}, got {})", max, actual)
            }
        }
    }
}

impl std::error::Error for MessageError {}

/// First line of a SIP request.
///
/// Per RFC 3261, the request line has the format:
/// `Method SP Request-URI SP SIP-Version CRLF`
///
/// # Examples
///
/// ```
/// use sip_core::{RequestLine, Method, Uri};
///
/// let uri = Uri::parse("sip:bob@example.com").unwrap();
/// let request_line = RequestLine::new(Method::Invite, uri);
/// assert_eq!(request_line.method(), &Method::Invite);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    method: Method,
    uri: Uri,
    version: SipVersion,
}

impl RequestLine {
    /// Creates a request line for the given method and target URI.
    ///
    /// Defaults to SIP/2.0 as the version.
    pub fn new(method: Method, uri: impl Into<Uri>) -> Self {
        Self {
            method,
            uri: uri.into(),
            version: SipVersion::V2,
        }
    }

    /// Returns the request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URI.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the SIP version.
    pub fn version(&self) -> &SipVersion {
        &self.version
    }

    /// Convenience method to get the URI as a SipUri if it is one.
    ///
    /// Returns None if the URI is a tel URI or other non-SIP scheme.
    pub fn sip_uri(&self) -> Option<&SipUri> {
        self.uri.as_sip()
    }

    /// Sets the request URI.
    pub fn set_uri(&mut self, uri: impl Into<Uri>) {
        self.uri = uri.into();
    }

    /// Consumes self and returns the components.
    pub fn into_parts(self) -> (Method, Uri, SipVersion) {
        (self.method, self.uri, self.version)
    }
}

/// First line of a SIP response.
///
/// Per RFC 3261, the status line has the format:
/// `SIP-Version SP Status-Code SP Reason-Phrase CRLF`
///
/// # Security
///
/// StatusLine validates the status code and reason phrase to prevent:
/// - Invalid status codes outside the SIP range (100-699)
/// - CRLF injection in reason phrases
/// - Excessive length reason phrases
///
/// # Examples
///
/// ```
/// use sip_core::StatusLine;
///
/// let status = StatusLine::new(200, "OK").unwrap();
/// assert_eq!(status.code(), 200);
/// assert_eq!(status.reason(), "OK");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    version: SipVersion,
    code: u16,
    reason: SmolStr,
}

impl StatusLine {
    /// Creates a status line with the provided code and reason phrase.
    ///
    /// Defaults to SIP/2.0 as the version.
    ///
    /// # Security
    ///
    /// Validates that:
    /// - Status code is in valid range (100-699)
    /// - Reason phrase contains no control characters
    /// - Reason phrase is within length limits
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Status code is not in range 100-699
    /// - Reason phrase contains control characters
    /// - Reason phrase exceeds MAX_REASON_LENGTH
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::StatusLine;
    ///
    /// let status = StatusLine::new(200, "OK").unwrap();
    /// assert_eq!(status.code(), 200);
    ///
    /// // Invalid status code
    /// assert!(StatusLine::new(99, "Invalid").is_err());
    ///
    /// // CRLF injection blocked
    /// assert!(StatusLine::new(200, "OK\r\nInjected").is_err());
    /// ```
    pub fn new(code: u16, reason: impl AsRef<str>) -> Result<Self, MessageError> {
        // Validate status code (SIP codes are 100-699)
        if !(100..=699).contains(&code) {
            return Err(MessageError::InvalidStatusCode { code });
        }

        let reason = reason.as_ref();
        validate_reason_phrase(reason)?;

        Ok(Self {
            version: SipVersion::V2,
            code,
            reason: SmolStr::new(reason),
        })
    }

    /// Returns the SIP version.
    pub fn version(&self) -> &SipVersion {
        &self.version
    }

    /// Returns the status code.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Returns the reason phrase.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns true if this is an informational response (1xx).
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.code)
    }

    /// Returns true if this is a success response (2xx).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Returns true if this is a redirection response (3xx).
    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.code)
    }

    /// Returns true if this is a client error response (4xx).
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// Returns true if this is a server error response (5xx).
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// Returns true if this is a global failure response (6xx).
    pub fn is_global_failure(&self) -> bool {
        (600..700).contains(&self.code)
    }

    /// Returns true if this is an error response (4xx, 5xx, or 6xx).
    pub fn is_error(&self) -> bool {
        self.is_client_error() || self.is_server_error() || self.is_global_failure()
    }

    /// Consumes self and returns the components.
    pub fn into_parts(self) -> (SipVersion, u16, SmolStr) {
        (self.version, self.code, self.reason)
    }
}

/// Immutable in-memory representation of a SIP request message.
///
/// Per RFC 3261, a SIP request consists of:
/// - Request-Line (method, URI, version)
/// - Headers
/// - Empty line
/// - Optional message body
///
/// # Security
///
/// Request validates the body size to prevent DoS attacks.
///
/// # Examples
///
/// ```
/// use sip_core::{Request, RequestLine, Method, Uri, Headers};
/// use bytes::Bytes;
///
/// let uri = Uri::parse("sip:bob@example.com").unwrap();
/// let request_line = RequestLine::new(Method::Invite, uri);
/// let headers = Headers::new();
/// let body = Bytes::new();
///
/// let request = Request::new(request_line, headers, body).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    start: RequestLine,
    headers: Headers,
    body: Bytes,
}

impl Request {
    /// Builds a request from its components.
    ///
    /// # Security
    ///
    /// Validates that the body size is within limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds MAX_BODY_SIZE.
    pub fn new(start: RequestLine, headers: Headers, body: Bytes) -> Result<Self, MessageError> {
        validate_body_size(&body)?;

        Ok(Self {
            start,
            headers,
            body,
        })
    }

    /// Returns the request line.
    pub fn start_line(&self) -> &RequestLine {
        &self.start
    }

    /// Returns the request method.
    pub fn method(&self) -> &Method {
        self.start.method()
    }

    /// Returns the request URI.
    pub fn uri(&self) -> &Uri {
        self.start.uri()
    }

    /// Returns the SIP version.
    pub fn version(&self) -> &SipVersion {
        self.start.version()
    }

    /// Returns the headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns a mutable reference to the headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Returns the message body.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns true if the message has a body.
    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }

    /// Returns the body size in bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Sets the request URI.
    pub fn set_uri(&mut self, uri: impl Into<Uri>) {
        self.start.set_uri(uri);
    }

    /// Sets the message body.
    ///
    /// # Errors
    /// Returns an error if the body exceeds MAX_BODY_SIZE.
    pub fn set_body(&mut self, body: Bytes) -> Result<(), MessageError> {
        validate_body_size(&body)?;
        self.body = body;
        Ok(())
    }

    /// Consumes self and returns the components.
    pub fn into_parts(self) -> (RequestLine, Headers, Bytes) {
        (self.start, self.headers, self.body)
    }
}

/// Immutable in-memory representation of a SIP response message.
///
/// Per RFC 3261, a SIP response consists of:
/// - Status-Line (version, code, reason)
/// - Headers
/// - Empty line
/// - Optional message body
///
/// # Security
///
/// Response validates the body size to prevent DoS attacks.
///
/// # Examples
///
/// ```
/// use sip_core::{Response, StatusLine, Headers};
/// use bytes::Bytes;
///
/// let status_line = StatusLine::new(200, "OK").unwrap();
/// let headers = Headers::new();
/// let body = Bytes::new();
///
/// let response = Response::new(status_line, headers, body).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    start: StatusLine,
    headers: Headers,
    body: Bytes,
}

impl Response {
    /// Builds a response from its components.
    ///
    /// # Security
    ///
    /// Validates that the body size is within limits.
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds MAX_BODY_SIZE.
    pub fn new(start: StatusLine, headers: Headers, body: Bytes) -> Result<Self, MessageError> {
        validate_body_size(&body)?;

        Ok(Self {
            start,
            headers,
            body,
        })
    }

    /// Returns the status line.
    pub fn start_line(&self) -> &StatusLine {
        &self.start
    }

    /// Returns the SIP version.
    pub fn version(&self) -> &SipVersion {
        self.start.version()
    }

    /// Returns the status code.
    pub fn code(&self) -> u16 {
        self.start.code()
    }

    /// Returns the reason phrase.
    pub fn reason(&self) -> &str {
        self.start.reason()
    }

    /// Returns the headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns a mutable reference to the headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Returns the message body.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns true if the message has a body.
    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }

    /// Returns the body size in bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Returns true if this is an informational response (1xx).
    pub fn is_informational(&self) -> bool {
        self.start.is_informational()
    }

    /// Returns true if this is a success response (2xx).
    pub fn is_success(&self) -> bool {
        self.start.is_success()
    }

    /// Returns true if this is a redirection response (3xx).
    pub fn is_redirection(&self) -> bool {
        self.start.is_redirection()
    }

    /// Returns true if this is a client error response (4xx).
    pub fn is_client_error(&self) -> bool {
        self.start.is_client_error()
    }

    /// Returns true if this is a server error response (5xx).
    pub fn is_server_error(&self) -> bool {
        self.start.is_server_error()
    }

    /// Returns true if this is a global failure response (6xx).
    pub fn is_global_failure(&self) -> bool {
        self.start.is_global_failure()
    }

    /// Returns true if this is an error response (4xx, 5xx, or 6xx).
    pub fn is_error(&self) -> bool {
        self.start.is_error()
    }

    /// Sets the message body.
    ///
    /// # Errors
    /// Returns an error if the body exceeds MAX_BODY_SIZE.
    pub fn set_body(&mut self, body: Bytes) -> Result<(), MessageError> {
        validate_body_size(&body)?;
        self.body = body;
        Ok(())
    }

    /// Consumes self and returns the components.
    pub fn into_parts(self) -> (StatusLine, Headers, Bytes) {
        (self.start, self.headers, self.body)
    }
}

/// Either a SIP request or response message.
///
/// # Examples
///
/// ```
/// use sip_core::{SipMessage, Request, RequestLine, Method, Uri, Headers};
/// use bytes::Bytes;
///
/// let uri = Uri::parse("sip:bob@example.com").unwrap();
/// let request_line = RequestLine::new(Method::Invite, uri);
/// let request = Request::new(request_line, Headers::new(), Bytes::new()).unwrap();
///
/// let message = SipMessage::Request(request);
/// assert!(message.is_request());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessage {
    Request(Request),
    Response(Response),
}

impl SipMessage {
    /// Returns true if this is a request.
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Returns true if this is a response.
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Returns a reference to the request if this is a request.
    pub fn as_request(&self) -> Option<&Request> {
        match self {
            Self::Request(req) => Some(req),
            _ => None,
        }
    }

    /// Returns a reference to the response if this is a response.
    pub fn as_response(&self) -> Option<&Response> {
        match self {
            Self::Response(res) => Some(res),
            _ => None,
        }
    }

    /// Returns a mutable reference to the request if this is a request.
    pub fn as_request_mut(&mut self) -> Option<&mut Request> {
        match self {
            Self::Request(req) => Some(req),
            _ => None,
        }
    }

    /// Returns a mutable reference to the response if this is a response.
    pub fn as_response_mut(&mut self) -> Option<&mut Response> {
        match self {
            Self::Response(res) => Some(res),
            _ => None,
        }
    }

    /// Returns the headers regardless of message type.
    pub fn headers(&self) -> &Headers {
        match self {
            Self::Request(req) => req.headers(),
            Self::Response(res) => res.headers(),
        }
    }

    /// Returns mutable headers regardless of message type.
    pub fn headers_mut(&mut self) -> &mut Headers {
        match self {
            Self::Request(req) => req.headers_mut(),
            Self::Response(res) => res.headers_mut(),
        }
    }

    /// Returns the body regardless of message type.
    pub fn body(&self) -> &Bytes {
        match self {
            Self::Request(req) => req.body(),
            Self::Response(res) => res.body(),
        }
    }
}

// Validation functions

fn validate_reason_phrase(reason: &str) -> Result<(), MessageError> {
    if reason.len() > MAX_REASON_LENGTH {
        return Err(MessageError::ReasonTooLong {
            max: MAX_REASON_LENGTH,
            actual: reason.len(),
        });
    }

    // Check for control characters (including CRLF)
    // Per RFC 3261, reason phrase is UTF8-TEXT which excludes control characters
    if reason.chars().any(|c| c.is_ascii_control()) {
        return Err(MessageError::InvalidReason(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_body_size(body: &Bytes) -> Result<(), MessageError> {
    if body.len() > MAX_BODY_SIZE {
        return Err(MessageError::BodyTooLarge {
            max: MAX_BODY_SIZE,
            actual: body.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_uri() -> Uri {
        Uri::parse("sip:bob@example.com").expect("failed to parse URI")
    }

    #[test]
    fn create_request_line() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri.clone());

        assert_eq!(request_line.method(), &Method::Invite);
        assert_eq!(request_line.uri(), &uri);
        assert_eq!(request_line.version(), &SipVersion::V2);
    }

    #[test]
    fn create_status_line() {
        let status = StatusLine::new(200, "OK").unwrap();

        assert_eq!(status.code(), 200);
        assert_eq!(status.reason(), "OK");
        assert_eq!(status.version(), &SipVersion::V2);
    }

    #[test]
    fn reject_invalid_status_codes() {
        // Too low
        assert!(StatusLine::new(99, "Invalid").is_err());

        // Too high
        assert!(StatusLine::new(700, "Invalid").is_err());

        // Way out of range
        assert!(StatusLine::new(0, "Invalid").is_err());
        assert!(StatusLine::new(999, "Invalid").is_err());
    }

    #[test]
    fn accept_valid_status_codes() {
        // Boundary values
        assert!(StatusLine::new(100, "Trying").is_ok());
        assert!(StatusLine::new(699, "Unknown").is_ok());

        // Common codes
        assert!(StatusLine::new(200, "OK").is_ok());
        assert!(StatusLine::new(404, "Not Found").is_ok());
        assert!(StatusLine::new(500, "Server Error").is_ok());
    }

    #[test]
    fn reject_crlf_in_reason() {
        let result = StatusLine::new(200, "OK\r\nInjected: evil");
        assert!(result.is_err());
    }

    #[test]
    fn reject_control_chars_in_reason() {
        assert!(StatusLine::new(200, "OK\x00null").is_err());
        assert!(StatusLine::new(200, "OK\ttab").is_err());
    }

    #[test]
    fn reject_oversized_reason() {
        let long_reason = "x".repeat(MAX_REASON_LENGTH + 1);
        let result = StatusLine::new(200, &long_reason);
        assert!(result.is_err());
    }

    #[test]
    fn status_line_predicates() {
        assert!(StatusLine::new(100, "Trying").unwrap().is_informational());
        assert!(StatusLine::new(200, "OK").unwrap().is_success());
        assert!(StatusLine::new(301, "Moved").unwrap().is_redirection());
        assert!(StatusLine::new(404, "Not Found").unwrap().is_client_error());
        assert!(StatusLine::new(500, "Error").unwrap().is_server_error());
        assert!(StatusLine::new(603, "Decline").unwrap().is_global_failure());

        assert!(StatusLine::new(404, "Not Found").unwrap().is_error());
        assert!(!StatusLine::new(200, "OK").unwrap().is_error());
    }

    #[test]
    fn create_request() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri);
        let headers = Headers::new();
        let body = Bytes::new();

        let request = Request::new(request_line, headers, body).unwrap();

        assert_eq!(request.method(), &Method::Invite);
        assert!(!request.has_body());
        assert_eq!(request.body_len(), 0);
    }

    #[test]
    fn reject_oversized_request_body() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri);
        let headers = Headers::new();

        // Create body larger than MAX_BODY_SIZE
        let huge_body = Bytes::from(vec![0u8; MAX_BODY_SIZE + 1]);

        let result = Request::new(request_line, headers, huge_body);
        assert!(result.is_err());
    }

    #[test]
    fn create_response() {
        let status_line = StatusLine::new(200, "OK").unwrap();
        let headers = Headers::new();
        let body = Bytes::new();

        let response = Response::new(status_line, headers, body).unwrap();

        assert_eq!(response.code(), 200);
        assert_eq!(response.reason(), "OK");
        assert!(response.is_success());
        assert!(!response.has_body());
    }

    #[test]
    fn reject_oversized_response_body() {
        let status_line = StatusLine::new(200, "OK").unwrap();
        let headers = Headers::new();

        // Create body larger than MAX_BODY_SIZE
        let huge_body = Bytes::from(vec![0u8; MAX_BODY_SIZE + 1]);

        let result = Response::new(status_line, headers, huge_body);
        assert!(result.is_err());
    }

    #[test]
    fn sip_message_request() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri);
        let request = Request::new(request_line, Headers::new(), Bytes::new()).unwrap();

        let message = SipMessage::Request(request);

        assert!(message.is_request());
        assert!(!message.is_response());
        assert!(message.as_request().is_some());
        assert!(message.as_response().is_none());
    }

    #[test]
    fn sip_message_response() {
        let status_line = StatusLine::new(200, "OK").unwrap();
        let response = Response::new(status_line, Headers::new(), Bytes::new()).unwrap();

        let message = SipMessage::Response(response);

        assert!(!message.is_request());
        assert!(message.is_response());
        assert!(message.as_request().is_none());
        assert!(message.as_response().is_some());
    }

    #[test]
    fn request_with_body() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri);
        let body = Bytes::from("SDP content here");

        let request = Request::new(request_line, Headers::new(), body.clone()).unwrap();

        assert!(request.has_body());
        assert_eq!(request.body_len(), body.len());
        assert_eq!(request.body(), &body);
    }

    #[test]
    fn fields_are_private() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri);
        let status_line = StatusLine::new(200, "OK").unwrap();
        let request = Request::new(request_line.clone(), Headers::new(), Bytes::new()).unwrap();

        // These should compile (read-only access)
        let _ = request_line.method();
        let _ = request_line.uri();
        let _ = status_line.code();
        let _ = status_line.reason();
        let _ = request.method();
        let _ = request.headers();

        // These should NOT compile (no direct field access):
        // request_line.method = Method::Bye;  // ← Does not compile!
        // status_line.code = 404;             // ← Does not compile!
        // request.body = Bytes::new();        // ← Does not compile!
    }

    #[test]
    fn into_parts() {
        let uri = mock_uri();
        let request_line = RequestLine::new(Method::Invite, uri.clone());
        let (method, returned_uri, version) = request_line.into_parts();

        assert_eq!(method, Method::Invite);
        assert_eq!(returned_uri, uri);
        assert_eq!(version, SipVersion::V2);
    }

    #[test]
    fn test_request_line_set_uri() {
        let uri1 = Uri::parse("sip:alice@example.com").unwrap();
        let uri2 = Uri::parse("sip:bob@other.com").unwrap();
        let mut rl = RequestLine::new(Method::Invite, uri1);
        assert_eq!(rl.uri().to_string(), "sip:alice@example.com");

        rl.set_uri(uri2.clone());
        assert_eq!(rl.uri(), &uri2);
    }

    #[test]
    fn test_request_set_uri() {
        let uri1 = Uri::parse("sip:alice@example.com").unwrap();
        let uri2 = Uri::parse("sip:bob@other.com").unwrap();
        let rl = RequestLine::new(Method::Invite, uri1);
        let mut req = Request::new(rl, Headers::new(), Bytes::new()).unwrap();

        req.set_uri(uri2.clone());
        assert_eq!(req.uri(), &uri2);
    }

    #[test]
    fn test_request_set_body() {
        let uri = mock_uri();
        let rl = RequestLine::new(Method::Invite, uri);
        let mut req = Request::new(rl, Headers::new(), Bytes::new()).unwrap();
        assert!(!req.has_body());

        let body = Bytes::from("new body content");
        req.set_body(body.clone()).unwrap();
        assert!(req.has_body());
        assert_eq!(req.body(), &body);
    }

    #[test]
    fn test_response_set_body() {
        let sl = StatusLine::new(200, "OK").unwrap();
        let mut resp = Response::new(sl, Headers::new(), Bytes::new()).unwrap();
        assert!(!resp.has_body());

        let body = Bytes::from("response body");
        resp.set_body(body.clone()).unwrap();
        assert!(resp.has_body());
        assert_eq!(resp.body(), &body);
    }
}
