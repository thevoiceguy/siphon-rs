use bytes::Bytes;
use smol_str::SmolStr;
use std::fmt;

use crate::{Headers, Method, RequestLine, Response, StatusLine, Uri};

/// A SIP message fragment per RFC 3420.
///
/// message/sipfrag can represent partial SIP messages containing:
/// - Optional start line (request or status line)
/// - Zero or more complete header fields
/// - Optional message body (with required Content-* headers if present)
///
/// This is commonly used in NOTIFY messages to report the status of
/// referenced requests (e.g., with REFER method).
///
/// # Example
///
/// ```
/// use sip_core::{SipFrag, StatusLine};
/// use smol_str::SmolStr;
///
/// // Status-only fragment (common for REFER notifications)
/// let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned()));
/// assert_eq!(frag.to_string(), "SIP/2.0 200 OK\r\n");
///
/// // Complete response fragment
/// let status = StatusLine::new(603, SmolStr::new("Declined".to_owned()));
/// let frag = SipFrag::response(status);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipFrag {
    /// Optional start line (request or response)
    pub start_line: Option<StartLine>,
    /// Header fields (may be empty)
    pub headers: Headers,
    /// Optional message body
    pub body: Bytes,
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
    /// let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned()));
    /// assert!(frag.is_response());
    /// ```
    pub fn status_only(code: u16, reason: SmolStr) -> Self {
        Self {
            start_line: Some(StartLine::Response(StatusLine::new(code, reason))),
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    /// Creates a sipfrag from a complete response (status line + headers + body).
    ///
    /// This is useful for creating detailed NOTIFY bodies that include
    /// headers from the referenced request.
    pub fn from_response(response: Response) -> Self {
        Self {
            start_line: Some(StartLine::Response(response.start)),
            headers: response.headers,
            body: response.body,
        }
    }

    /// Creates a sipfrag with a response status line and headers.
    pub fn response(status: StatusLine) -> Self {
        Self {
            start_line: Some(StartLine::Response(status)),
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    /// Creates a sipfrag with a request line.
    pub fn request(request_line: RequestLine) -> Self {
        Self {
            start_line: Some(StartLine::Request(request_line)),
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    /// Creates a sipfrag with only headers (no start line or body).
    pub fn headers_only(headers: Headers) -> Self {
        Self {
            start_line: None,
            headers,
            body: Bytes::new(),
        }
    }

    /// Adds a header field to the fragment.
    pub fn with_header(mut self, name: impl Into<SmolStr>, value: impl Into<SmolStr>) -> Self {
        self.headers.push(name.into(), value.into());
        self
    }

    /// Sets the message body.
    ///
    /// If a body is provided, you should also include appropriate headers
    /// like Content-Type and Content-Length per RFC 3420.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
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
            Some(StartLine::Response(status)) => Some(status.code),
            _ => None,
        }
    }

    /// Returns the method if this is a request fragment.
    pub fn method(&self) -> Option<&Method> {
        match &self.start_line {
            Some(StartLine::Request(req)) => Some(&req.method),
            _ => None,
        }
    }

    /// Returns the request URI if this is a request fragment.
    pub fn request_uri(&self) -> Option<&Uri> {
        match &self.start_line {
            Some(StartLine::Request(req)) => Some(&req.uri),
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
                    write!(f, "{} {} {}\r\n", req.method.as_str(), req.uri, req.version)?;
                }
                StartLine::Response(status) => {
                    write!(
                        f,
                        "{} {} {}\r\n",
                        status.version, status.code, status.reason
                    )?;
                }
            }
        }

        // Headers
        for header in self.headers.iter() {
            write!(f, "{}: {}\r\n", header.name, header.value)?;
        }

        // Body (if present, must include blank line separator)
        if !self.body.is_empty() {
            write!(f, "\r\n")?; // Blank line separates headers from body
            f.write_str(&String::from_utf8_lossy(&self.body))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sipfrag_empty() {
        let frag = SipFrag::empty();
        assert!(frag.start_line.is_none());
        assert!(frag.headers.is_empty());
        assert!(frag.body.is_empty());
        assert_eq!(frag.to_string(), "");
    }

    #[test]
    fn sipfrag_status_only() {
        let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned()));
        assert!(frag.is_response());
        assert_eq!(frag.status_code(), Some(200));
        assert_eq!(frag.to_string(), "SIP/2.0 200 OK\r\n");
    }

    #[test]
    fn sipfrag_status_with_headers() {
        let frag = SipFrag::status_only(486, SmolStr::new("Busy Here".to_owned()))
            .with_header("Retry-After", "60");

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
        let frag = SipFrag::request(req_line);

        assert!(frag.is_request());
        assert_eq!(frag.method(), Some(&Method::Invite));
        assert!(frag
            .to_string()
            .contains("INVITE sip:bob@example.com SIP/2.0"));
    }

    #[test]
    fn sipfrag_headers_only() {
        let mut headers = Headers::new();
        headers.push(
            SmolStr::new("From".to_owned()),
            SmolStr::new("sip:alice@example.com".to_owned()),
        );
        headers.push(
            SmolStr::new("To".to_owned()),
            SmolStr::new("sip:bob@example.com".to_owned()),
        );

        let frag = SipFrag::headers_only(headers);
        assert!(frag.start_line.is_none());
        assert!(!frag.is_request());
        assert!(!frag.is_response());

        let output = frag.to_string();
        assert!(output.contains("From: sip:alice@example.com"));
        assert!(output.contains("To: sip:bob@example.com"));
    }

    #[test]
    fn sipfrag_with_body() {
        let frag = SipFrag::status_only(200, SmolStr::new("OK".to_owned()))
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", "11")
            .with_body("Hello World");

        let output = frag.to_string();
        assert!(output.contains("SIP/2.0 200 OK"));
        assert!(output.contains("Content-Type: text/plain"));
        assert!(output.contains("Content-Length: 11"));
        assert!(output.contains("\r\n\r\nHello World"));
    }

    #[test]
    fn sipfrag_status_code_extraction() {
        let frag1 = SipFrag::status_only(404, SmolStr::new("Not Found".to_owned()));
        assert_eq!(frag1.status_code(), Some(404));

        let frag2 = SipFrag::empty();
        assert_eq!(frag2.status_code(), None);
    }

    #[test]
    fn sipfrag_from_response() {
        let response = Response::new(
            StatusLine::new(603, SmolStr::new("Declined".to_owned())),
            Headers::new(),
            Bytes::new(),
        );

        let frag = SipFrag::from_response(response);
        assert!(frag.is_response());
        assert_eq!(frag.status_code(), Some(603));
    }
}
