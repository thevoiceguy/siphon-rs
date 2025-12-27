// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SIP proxy helper primitives for RFC 3261 §16 proxy operations.
//!
//! Provides Via insertion, Record-Route handling, Max-Forwards checking, and
//! Request-URI modification for building stateful and stateless proxies.
//!
//! # Example
//! ```
//! use sip_proxy::ProxyHelpers;
//! # use sip_core::{Request, Headers, RequestLine, Method, SipUri};
//! # use bytes::Bytes;
//! # let mut req = Request::new(RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()), Headers::new(), Bytes::new());
//! let branch = ProxyHelpers::add_via(&mut req, "proxy.example.com", "UDP");
//! let proxy_uri = SipUri::parse("sip:proxy.example.com;lr").unwrap();
//! ProxyHelpers::add_record_route(&mut req, &proxy_uri);
//! ```

pub mod cancel_ack;
pub mod service;
pub mod stateful;

use anyhow::{anyhow, Result};
use sip_core::{decrement_max_forwards, Header, Headers, Request, SipUri};
use sip_transaction::generate_branch_id;

/// Stateless proxy helpers for RFC 3261 proxy operations.
///
/// These are simple helpers that perform the mechanical operations required
/// by RFC 3261 for proxying requests. The application is responsible for:
/// - Deciding where to forward requests (routing logic)
/// - Looking up registered users (location service)
/// - Authentication and authorization
/// - Policy decisions
pub struct ProxyHelpers;

impl ProxyHelpers {
    /// Prepends a Via header to the request with a new branch parameter.
    ///
    /// RFC 3261 §16.6 step 1: The proxy MUST insert a Via header field value
    /// into the copy before the existing Via header field values.
    ///
    /// # Arguments
    /// * `request` - The request to modify
    /// * `host` - The proxy's hostname or IP address
    /// * `transport` - Transport protocol (UDP, TCP, TLS)
    ///
    /// # Returns
    /// The generated branch ID for transaction correlation
    pub fn add_via(request: &mut Request, host: &str, transport: &str) -> String {
        let branch = generate_branch_id();
        let via_value = format!("SIP/2.0/{} {};branch={};rport", transport, host, branch);

        // Prepend to existing Via headers
        let mut new_headers = Vec::new();
        new_headers.push(Header {
            name: "Via".into(),
            value: via_value.into(),
        });
        new_headers.extend(request.headers.clone());
        request.headers = Headers::from_vec(new_headers);

        branch.to_string()
    }

    /// Inserts a Record-Route header for dialog routing.
    ///
    /// RFC 3261 §16.6 step 4: The proxy MAY insert a Record-Route header
    /// field value in order to remain on the signaling path for future requests.
    ///
    /// # Arguments
    /// * `request` - The request to modify
    /// * `proxy_uri` - The proxy's SIP URI (will be in Route headers of future requests)
    pub fn add_record_route(request: &mut Request, proxy_uri: &SipUri) {
        let rr_value = format!("<{}>", proxy_uri.as_str());
        request.headers.push("Record-Route".into(), rr_value.into());
    }

    /// Decrements Max-Forwards header and checks for loop.
    ///
    /// RFC 3261 §16.6 step 3: The proxy MUST decrement the Max-Forwards value
    /// by one. If the Max-Forwards value reaches 0, the proxy MUST NOT forward
    /// the request and MUST respond with 483 (Too Many Hops).
    ///
    /// # Arguments
    /// * `request` - The request to check and modify
    ///
    /// # Returns
    /// * `Ok(())` - Max-Forwards was decremented successfully
    /// * `Err(_)` - Max-Forwards exhausted (respond with 483)
    pub fn check_max_forwards(request: &mut Request) -> Result<()> {
        decrement_max_forwards(&mut request.headers)
            .map(|_| ())
            .map_err(|_| anyhow!("Max-Forwards exhausted - respond with 483 Too Many Hops"))
    }

    /// Removes the top Via header from a response before forwarding upstream.
    ///
    /// RFC 3261 §16.7 step 3: The proxy MUST remove the topmost Via header
    /// field value from the response.
    ///
    /// # Arguments
    /// * `headers` - The response headers to modify
    pub fn remove_top_via(headers: &mut Headers) {
        // Find and remove the first Via header
        let mut found_index = None;
        for (i, header) in headers.iter().enumerate() {
            if header.name.as_str().eq_ignore_ascii_case("Via") {
                found_index = Some(i);
                break;
            }
        }

        if let Some(index) = found_index {
            let mut new_headers = Vec::new();
            for (i, header) in headers.clone().into_iter().enumerate() {
                if i != index {
                    new_headers.push(header);
                }
            }
            *headers = Headers::from_vec(new_headers);
        }
    }

    /// Updates the Request-URI to point to the target.
    ///
    /// RFC 3261 §16.6 step 5: The proxy MUST place the Request-URI into
    /// the Request-URI of the forwarded request.
    ///
    /// # Arguments
    /// * `request` - The request to modify
    /// * `target_uri` - The URI to forward to (usually from location service)
    pub fn set_request_uri(request: &mut Request, target_uri: SipUri) {
        request.start.uri = target_uri.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Method, RequestLine};

    #[test]
    fn adds_via_header() {
        let mut headers = Headers::new();
        headers.push("Via".into(), "SIP/2.0/UDP old;branch=z9hG4bK123".into());
        headers.push("Max-Forwards".into(), "70".into());

        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        );

        let branch = ProxyHelpers::add_via(&mut req, "proxy.example.com", "UDP");

        // Via should be prepended
        let vias: Vec<_> = req.headers.iter().filter(|h| h.name == "Via").collect();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].value.contains("proxy.example.com"));
        assert!(vias[0].value.contains(&branch));
        assert!(vias[1].value.contains("old"));
    }

    #[test]
    fn adds_record_route() {
        let mut headers = Headers::new();
        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        );

        let proxy_uri = SipUri::parse("sip:proxy.example.com").unwrap();
        ProxyHelpers::add_record_route(&mut req, &proxy_uri);

        let rr = req.headers.get("Record-Route").unwrap();
        assert!(rr.contains("sip:proxy.example.com"));
    }

    #[test]
    fn decrements_max_forwards() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards".into(), "70".into());

        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        );

        assert!(ProxyHelpers::check_max_forwards(&mut req).is_ok());
        assert_eq!(req.headers.get("Max-Forwards").unwrap(), "69");
    }

    #[test]
    fn rejects_zero_max_forwards() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards".into(), "0".into());

        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        );

        assert!(ProxyHelpers::check_max_forwards(&mut req).is_err());
    }

    #[test]
    fn removes_top_via() {
        let mut headers = Headers::new();
        headers.push("Via".into(), "SIP/2.0/UDP proxy;branch=z9hG4bK456".into());
        headers.push("Via".into(), "SIP/2.0/UDP client;branch=z9hG4bK123".into());
        headers.push("From".into(), "<sip:alice@example.com>".into());

        ProxyHelpers::remove_top_via(&mut headers);

        let vias: Vec<_> = headers.iter().filter(|h| h.name == "Via").collect();
        assert_eq!(vias.len(), 1);
        assert!(vias[0].value.contains("client"));
        assert!(!vias[0].value.contains("proxy"));
    }

    #[test]
    fn updates_request_uri() {
        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:alice@example.com").unwrap(),
            ),
            Headers::new(),
            Bytes::new(),
        );

        let target = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        ProxyHelpers::set_request_uri(&mut req, target.clone());

        assert_eq!(req.start.uri.as_sip().unwrap().as_str(), target.as_str());
    }
}
