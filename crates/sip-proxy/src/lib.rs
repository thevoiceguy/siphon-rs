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
//! # let mut req = Request::new(RequestLine::new(Method::Invite, SipUri::parse("sip:bob@example.com").unwrap()), Headers::new(), Bytes::new()).unwrap();
//! let branch = ProxyHelpers::add_via(&mut req, "proxy.example.com", "UDP".into());
//! let proxy_uri = SipUri::parse("sip:proxy.example.com;lr").unwrap();
//! ProxyHelpers::add_record_route(&mut req, &proxy_uri);
//! ```

pub mod cancel_ack;
pub mod service;
pub mod stateful;

use anyhow::{anyhow, Result};
use sip_core::{decrement_max_forwards, Header, Headers, Request, RequestLine, SipUri};
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

/// Maximum number of Via hops before assuming a routing loop.
/// Most deployments have < 10 hops; 70 matches the default Max-Forwards.
const MAX_VIA_HOPS: usize = 70;

/// RFC 3261 branch magic cookie (§8.1.1.7).
const BRANCH_MAGIC: &str = "z9hG4bK";

/// Computes the loop-detection branch for a request per RFC 3261 §16.6
/// step 8. SHA-256 over `(To, From, Call-ID, CSeq-number, Request-URI,
/// proxy-sent-by)`, truncated to 16 bytes (32 hex chars) for compactness,
/// prefixed with the magic cookie. Fields that are missing from the
/// incoming message contribute the empty string — still deterministic
/// for a given tuple so the same request hashes identically on re-entry.
fn compute_loop_branch(request: &Request, proxy_host: &str) -> String {
    use sha2::{Digest, Sha256};

    let headers = request.headers();
    let to = headers.get("To").unwrap_or("");
    let from = headers.get("From").unwrap_or("");
    let call_id = headers.get("Call-ID").unwrap_or("");
    // Only the numeric portion of CSeq goes into the hash — the method
    // is redundant here (branch is per-transaction) and would change
    // between CANCEL/INVITE pairs that should hash to the same value.
    let cseq_num = headers
        .get("CSeq")
        .and_then(|v| v.split_whitespace().next())
        .unwrap_or("");
    let request_uri = request.uri().as_str();

    let mut hasher = Sha256::new();
    // Separator is ASCII 0x1F (unit separator), forbidden in header
    // values, so the concatenation is unambiguous.
    hasher.update(to.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(from.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(call_id.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(cseq_num.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(request_uri.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(proxy_host.as_bytes());
    let digest = hasher.finalize();
    format!("{}{}", BRANCH_MAGIC, hex::encode(&digest[..16]))
}

/// Extracts the `sent-by` (host[:port]) from a Via header value.
fn extract_via_sent_by(value: &str) -> Option<&str> {
    let after_proto = value.split_whitespace().nth(1)?;
    Some(after_proto.split(';').next().unwrap_or(after_proto))
}

/// Returns true if a Via `sent-by` references `proxy_host`. Matches
/// `host` or `host:port` case-insensitively.
fn sent_by_matches_host(sent_by: &str, proxy_host: &str) -> bool {
    let host = sent_by.split(':').next().unwrap_or(sent_by);
    host.eq_ignore_ascii_case(proxy_host)
}

/// Extracts the `branch` parameter from a Via header value, if any.
fn extract_via_branch(value: &str) -> Option<&str> {
    value
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("branch="))
}

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
        new_headers.push(Header::new("Via", via_value).expect("via header should be valid"));
        new_headers.extend(request.headers().clone());
        *request.headers_mut() =
            Headers::from_vec(new_headers).expect("via header list should be within limits");

        branch.to_string()
    }

    /// Inserts a Record-Route header for dialog routing.
    ///
    /// RFC 3261 §16.6 step 4: The proxy MAY insert a Record-Route header
    /// field value in order to remain on the signaling path for future requests.
    ///
    /// The URI is emitted with the `;lr` parameter (RFC 3261 §16.4 / §19.1.1)
    /// so downstream UAs and proxies use loose routing. Without it, peers will
    /// treat the next-hop as a strict router and rewrite the Request-URI,
    /// breaking the dialog.
    ///
    /// # Arguments
    /// * `request` - The request to modify
    /// * `proxy_uri` - The proxy's SIP URI (will be in Route headers of future requests)
    pub fn add_record_route(request: &mut Request, proxy_uri: &SipUri) {
        let has_lr = proxy_uri
            .params()
            .keys()
            .any(|k| k.eq_ignore_ascii_case("lr"));
        let rr_value = if has_lr {
            format!("<{}>", proxy_uri.as_str())
        } else {
            format!("<{};lr>", proxy_uri.as_str())
        };
        request
            .headers_mut()
            .push("Record-Route", rr_value)
            .unwrap();
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
        decrement_max_forwards(request.headers_mut())
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
            if header.name().eq_ignore_ascii_case("Via") {
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
            *headers =
                Headers::from_vec(new_headers).expect("via header list should be within limits");
        }
    }

    /// Prepends a Via header whose branch embeds a hash of request
    /// identity (RFC 3261 §16.6 step 8). When the same logical request
    /// re-arrives at this proxy (because some downstream forwarded it
    /// back), the topmost Via will carry the same branch with our
    /// sent-by and [`detect_loop_hashed`] will reject it with 482.
    ///
    /// Returns the branch ID for transaction correlation.
    pub fn add_via_with_loop_detection(
        request: &mut Request,
        host: &str,
        transport: &str,
    ) -> String {
        let branch = compute_loop_branch(request, host);
        let via_value = format!("SIP/2.0/{} {};branch={};rport", transport, host, branch);

        let mut new_headers = Vec::new();
        new_headers.push(Header::new("Via", via_value).expect("via header should be valid"));
        new_headers.extend(request.headers().clone());
        *request.headers_mut() =
            Headers::from_vec(new_headers).expect("via header list should be within limits");

        branch
    }

    /// Loop-check using the hashed-branch mechanism (RFC 3261 §16.3).
    ///
    /// Recomputes the branch hash for this request and scans every Via
    /// already on the message. If any Via's sent-by matches this proxy
    /// AND its branch parameter equals our computed hash, the request
    /// has already traversed us — respond 482.
    ///
    /// Stricter than [`detect_loop`] which only caught cases where the
    /// proxy's host literal appeared in any Via for any reason.
    pub fn detect_loop_hashed(request: &Request, proxy_host: &str) -> Result<()> {
        let expected_branch = compute_loop_branch(request, proxy_host);
        for header in request.headers().iter() {
            if !header.name().eq_ignore_ascii_case("Via")
                && !header.name().eq_ignore_ascii_case("v")
            {
                continue;
            }
            let value = header.value();
            let Some(sent_by) = extract_via_sent_by(value) else {
                continue;
            };
            if !sent_by_matches_host(sent_by, proxy_host) {
                continue;
            }
            if let Some(branch) = extract_via_branch(value) {
                if branch == expected_branch {
                    return Err(anyhow!(
                        "Via sent-by={} branch={} matches our hash — routing loop detected (482)",
                        proxy_host,
                        branch
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks for routing loops by inspecting Via headers.
    ///
    /// RFC 3261 §16.3: A proxy MUST detect if it is the target of a loop. A
    /// proxy can detect this by checking if any existing Via header contains
    /// the proxy's own address and branch parameter.
    ///
    /// This method checks:
    /// 1. Whether the number of Via hops exceeds a sane limit (loop indicator)
    /// 2. Whether any existing Via header matches the proxy's own host
    ///
    /// # Arguments
    /// * `request` - The request to check
    /// * `proxy_host` - The proxy's own hostname or IP address
    ///
    /// # Returns
    /// * `Ok(())` - No loop detected
    /// * `Err(_)` - Loop detected (respond with 482 Loop Detected)
    pub fn detect_loop(request: &Request, proxy_host: &str) -> Result<()> {
        let mut via_count = 0;
        for header in request.headers().iter() {
            if header.name().eq_ignore_ascii_case("Via") || header.name().eq_ignore_ascii_case("v")
            {
                via_count += 1;
                if via_count > MAX_VIA_HOPS {
                    return Err(anyhow!(
                        "Via hop count {} exceeds maximum {} - possible routing loop",
                        via_count,
                        MAX_VIA_HOPS
                    ));
                }
                // Check if this Via contains our own host
                let value = header.value();
                // Via format: SIP/2.0/TRANSPORT host[:port];params
                if let Some(host_part) = value.split_whitespace().nth(1) {
                    let host = host_part.split(';').next().unwrap_or(host_part);
                    let host = host.split(':').next().unwrap_or(host);
                    if host.eq_ignore_ascii_case(proxy_host) {
                        return Err(anyhow!(
                            "Via header contains proxy host {} - routing loop detected (482)",
                            proxy_host
                        ));
                    }
                }
            }
        }
        Ok(())
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
        let method = request.method().clone();
        let headers = request.headers().clone();
        let body = request.body().clone();
        *request = Request::new(RequestLine::new(method, target_uri), headers, body)
            .expect("valid request");
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
        headers
            .push("Via", "SIP/2.0/UDP old;branch=z9hG4bK123")
            .unwrap();
        headers.push("Max-Forwards", "70").unwrap();

        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let branch = ProxyHelpers::add_via(&mut req, "proxy.example.com", "UDP".into());

        // Via should be prepended
        let vias: Vec<_> = req.headers().iter().filter(|h| h.name() == "Via").collect();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].value().contains("proxy.example.com"));
        assert!(vias[0].value().contains(&branch));
        assert!(vias[1].value().contains("old"));
    }

    #[test]
    fn adds_record_route() {
        let headers = Headers::new();
        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        let proxy_uri = SipUri::parse("sip:proxy.example.com").unwrap();
        ProxyHelpers::add_record_route(&mut req, &proxy_uri);

        let rr = req.headers().get("Record-Route").unwrap();
        assert!(rr.contains("sip:proxy.example.com"));
        // RFC 3261 §16.4 / §19.1.1: Record-Route URI MUST carry ;lr so peers
        // use loose routing.
        assert!(rr.contains(";lr"), "missing ;lr in Record-Route: {rr}");
    }

    #[test]
    fn record_route_does_not_double_lr() {
        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            Headers::new(),
            Bytes::new(),
        )
        .expect("valid request");

        let proxy_uri = SipUri::parse("sip:proxy.example.com;lr").unwrap();
        ProxyHelpers::add_record_route(&mut req, &proxy_uri);

        let rr = req.headers().get("Record-Route").unwrap();
        assert_eq!(
            rr.matches(";lr").count(),
            1,
            "Record-Route should not duplicate ;lr: {rr}"
        );
    }

    fn make_request_with_identity() -> Request {
        let mut headers = Headers::new();
        headers.push("To", "<sip:bob@example.com>").unwrap();
        headers
            .push("From", "<sip:alice@example.com>;tag=a1b2")
            .unwrap();
        headers.push("Call-ID", "abc123@client").unwrap();
        headers.push("CSeq", "1 INVITE").unwrap();
        Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request")
    }

    #[test]
    fn hashed_branch_is_deterministic() {
        let r1 = make_request_with_identity();
        let r2 = make_request_with_identity();
        let b1 = compute_loop_branch(&r1, "proxy.example.com");
        let b2 = compute_loop_branch(&r2, "proxy.example.com");
        assert_eq!(b1, b2, "same identity → same branch");
        assert!(b1.starts_with("z9hG4bK"), "branch must carry magic cookie: {b1}");
    }

    #[test]
    fn hashed_branch_differs_per_proxy_host() {
        let req = make_request_with_identity();
        let b_a = compute_loop_branch(&req, "proxy-a.example.com");
        let b_b = compute_loop_branch(&req, "proxy-b.example.com");
        assert_ne!(b_a, b_b);
    }

    #[test]
    fn detect_loop_hashed_catches_self_inserted_via() {
        let mut req = make_request_with_identity();
        ProxyHelpers::add_via_with_loop_detection(&mut req, "proxy.example.com", "UDP");
        // Simulate re-arrival: another hop prepends its own Via on top.
        ProxyHelpers::add_via(&mut req, "other-hop.example.net", "UDP");
        let result = ProxyHelpers::detect_loop_hashed(&req, "proxy.example.com");
        assert!(
            result.is_err(),
            "detect_loop_hashed must 482 when our prior hash is in the Via chain"
        );
    }

    #[test]
    fn detect_loop_hashed_ignores_unrelated_vias() {
        let mut req = make_request_with_identity();
        ProxyHelpers::add_via(&mut req, "upstream.example.net", "UDP");
        ProxyHelpers::add_via(&mut req, "another.example.net", "UDP");
        assert!(ProxyHelpers::detect_loop_hashed(&req, "proxy.example.com").is_ok());
    }

    #[test]
    fn detect_loop_hashed_ignores_matching_host_with_different_branch() {
        // Only the exact hash match counts as a loop; a random branch on
        // our hostname is not us-having-seen-this-request-before.
        let mut req = make_request_with_identity();
        ProxyHelpers::add_via(&mut req, "proxy.example.com", "UDP");
        assert!(ProxyHelpers::detect_loop_hashed(&req, "proxy.example.com").is_ok());
    }

    #[test]
    fn hashed_branch_changes_when_request_uri_changes() {
        let r1 = make_request_with_identity();
        let mut r2 = make_request_with_identity();
        ProxyHelpers::set_request_uri(
            &mut r2,
            SipUri::parse("sip:carol@example.net").unwrap(),
        );
        let b1 = compute_loop_branch(&r1, "proxy.example.com");
        let b2 = compute_loop_branch(&r2, "proxy.example.com");
        assert_ne!(b1, b2);
    }

    #[test]
    fn decrements_max_forwards() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "70").unwrap();

        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(ProxyHelpers::check_max_forwards(&mut req).is_ok());
        assert_eq!(req.headers().get("Max-Forwards").unwrap(), "69");
    }

    #[test]
    fn rejects_zero_max_forwards() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards", "0").unwrap();

        let mut req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        assert!(ProxyHelpers::check_max_forwards(&mut req).is_err());
    }

    #[test]
    fn removes_top_via() {
        let mut headers = Headers::new();
        headers
            .push("Via", "SIP/2.0/UDP proxy;branch=z9hG4bK456")
            .unwrap();
        headers
            .push("Via", "SIP/2.0/UDP client;branch=z9hG4bK123")
            .unwrap();
        headers.push("From", "<sip:alice@example.com>").unwrap();

        ProxyHelpers::remove_top_via(&mut headers);

        let vias: Vec<_> = headers.iter().filter(|h| h.name() == "Via").collect();
        assert_eq!(vias.len(), 1);
        assert!(vias[0].value().contains("client"));
        assert!(!vias[0].value().contains("proxy"));
    }

    #[test]
    fn detects_loop_when_proxy_host_in_via() {
        let mut headers = Headers::new();
        headers
            .push("Via", "SIP/2.0/UDP proxy.example.com;branch=z9hG4bK123")
            .unwrap();
        headers
            .push("Via", "SIP/2.0/UDP client.example.com;branch=z9hG4bK456")
            .unwrap();
        headers.push("Max-Forwards", "70").unwrap();

        let req = Request::new(
            RequestLine::new(
                Method::Invite,
                SipUri::parse("sip:bob@example.com").unwrap(),
            ),
            headers,
            Bytes::new(),
        )
        .expect("valid request");

        // Proxy host matches an existing Via
        assert!(ProxyHelpers::detect_loop(&req, "proxy.example.com").is_err());

        // Different host - no loop
        assert!(ProxyHelpers::detect_loop(&req, "other.example.com").is_ok());
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
        )
        .expect("valid request");

        let target = SipUri::parse("sip:alice@192.168.1.100:5060").unwrap();
        ProxyHelpers::set_request_uri(&mut req, target.clone());

        assert_eq!(req.uri().as_sip().unwrap().as_str(), target.as_str());
    }
}
