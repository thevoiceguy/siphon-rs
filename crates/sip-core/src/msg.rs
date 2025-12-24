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

/// First line of a SIP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    pub method: Method,
    pub uri: Uri,
    pub version: SipVersion,
}

impl RequestLine {
    /// Creates a request line for the given method and target URI (defaults to SIP/2.0).
    pub fn new(method: Method, uri: impl Into<Uri>) -> Self {
        Self {
            method,
            uri: uri.into(),
            version: SipVersion::V2,
        }
    }

    /// Convenience method to get the URI as a SipUri if it is one.
    /// Returns None if the URI is a tel URI.
    pub fn sip_uri(&self) -> Option<&SipUri> {
        self.uri.as_sip()
    }
}

/// First line of a SIP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    pub version: SipVersion,
    pub code: u16,
    pub reason: SmolStr,
}

impl StatusLine {
    /// Creates a status line with the provided code and reason phrase (defaults to SIP/2.0).
    pub fn new(code: u16, reason: SmolStr) -> Self {
        Self {
            version: SipVersion::V2,
            code,
            reason,
        }
    }
}

/// Immutable in-memory representation of a SIP request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub start: RequestLine,
    pub headers: Headers,
    pub body: Bytes,
}

impl Request {
    /// Builds a request from its components.
    pub fn new(start: RequestLine, headers: Headers, body: Bytes) -> Self {
        Self {
            start,
            headers,
            body,
        }
    }
}

/// Immutable in-memory representation of a SIP response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub start: StatusLine,
    pub headers: Headers,
    pub body: Bytes,
}

impl Response {
    /// Builds a response from its components.
    pub fn new(start: StatusLine, headers: Headers, body: Bytes) -> Self {
        Self {
            start,
            headers,
            body,
        }
    }
}

/// Either a SIP request or response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessage {
    Request(Request),
    Response(Response),
}
