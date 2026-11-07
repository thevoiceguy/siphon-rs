//! The Via of a response, as the server that sends it fills it.
//!
//! [`crate::TransactionManager`] applies [`stamp_via`] to every response a
//! server transaction sends, so a UA answering through the handle with a
//! response it built itself gets `rport=` and `received=` as one using
//! `sip-uas`'s `IntegratedUAS` always did (thevoiceguy/siphon-rs#164).
//! It changes nothing it has already filled, so applying it twice is safe.

use sip_core::{Response, ViaHeader};
use std::net::SocketAddr;

/// Fill the topmost Via of `response` as RFC 3261 §18.2.1 and RFC 3581 §4
/// have a server do, for a request that came from `source`. The topmost Via was copied verbatim
/// from the request; this fills `rport=<src_port>` when it was
/// present without a value and adds `received=<src_ip>` whenever
/// the sent-by host differs from the actual packet source OR the
/// bare `rport` triggered a rewrite.
///
/// The unconditional `received=` on `rport` rewrites follows the
/// RFC 3581 §4 RECOMMENDATION: clients implementing symmetric
/// response routing want a single place to read the public
/// reflection of their address back from, even when the sent-by
/// IP happens to match the packet source. Adding it costs nothing
/// and short-circuits a class of NAT-tracking bugs in clients
/// that only inspect `received`.
///
/// Silently no-ops if the Via doesn't parse — we never want a
/// malformed inbound Via to abort the response.
pub fn stamp_via(response: &mut Response, source: SocketAddr) {
    let Some(top_via) = response.headers().get("Via") else {
        return;
    };
    let top_via = top_via.to_string();
    let Ok(mut via) = ViaHeader::parse(&top_via) else {
        return;
    };

    let mut changed = false;
    let mut rport_filled = false;

    // RFC 3581 §4: an inbound request with a bare `;rport` must
    // have it rewritten to the actual source port on the response.
    if matches!(via.param("rport"), Some(None))
        && via
            .set_param("rport", Some(source.port().to_string()))
            .is_ok()
    {
        changed = true;
        rport_filled = true;
    }

    // RFC 3261 §18.2.1: when the sent-by host doesn't match the
    // packet source IP, the server MUST add `received=<src_ip>`.
    // Extract the host portion from the sent-by ("host" or
    // "host:port", with IPv6 bracketed); compare against the
    // source IP. Done as strings to sidestep DNS — the requirement
    // is exact-bytes comparison per the RFC, not name resolution.
    //
    // RFC 3581 §4 additionally RECOMMENDS adding `received=` even
    // when sent-by matches src IP, provided we're also filling
    // `rport`. We honour that recommendation by piggy-backing on
    // `rport_filled` — the client asked for symmetric response
    // routing, so it gets the full pair.
    let sent_by_host = sent_by_host(via.sent_by());
    let src_ip = source.ip().to_string();
    if (sent_by_host != src_ip || rport_filled)
        && via.param("received").is_none()
        && via.set_param("received", Some(src_ip.as_str())).is_ok()
    {
        changed = true;
    }

    if changed {
        // `set_or_push` replaces just the first occurrence — exactly
        // the topmost Via, which is what we want. Subsequent Via
        // headers (if any) are response-routing artefacts and
        // mustn't be touched.
        let _ = response.headers_mut().set_or_push("Via", via.to_string());
    }
}

/// Strip the optional `:port` from a `sent-by` value, leaving the
/// host. Handles bracketed IPv6 (`[2001:db8::1]:5060` → `2001:db8::1`).
pub(crate) fn sent_by_host(sent_by: &str) -> &str {
    let s = sent_by.trim();
    if let Some(stripped) = s.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return &stripped[..end];
        }
    }
    s.rsplit_once(':').map(|(host, _)| host).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, StatusLine};
    use smol_str::SmolStr;

    #[test]
    fn sent_by_host_strips_port() {
        assert_eq!(sent_by_host("194.195.208.34:5080"), "194.195.208.34");
        assert_eq!(sent_by_host("194.195.208.34"), "194.195.208.34");
        assert_eq!(sent_by_host("example.com:5060"), "example.com");
        assert_eq!(sent_by_host("[2001:db8::1]:5060"), "2001:db8::1");
        assert_eq!(sent_by_host("[::1]"), "::1");
    }

    #[test]
    fn stamping_twice_changes_nothing_more() {
        let mut headers = Headers::new();
        headers
            .push(
                SmolStr::new("Via"),
                SmolStr::new("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK1;rport"),
            )
            .unwrap();
        let mut response =
            Response::new(StatusLine::new(200, "OK").unwrap(), headers, Bytes::new()).unwrap();
        let source: SocketAddr = "198.51.100.4:61185".parse().unwrap();
        stamp_via(&mut response, source);
        let once = response.headers().get("Via").unwrap().to_string();
        assert!(
            once.contains("rport=61185") && once.contains("received=198.51.100.4"),
            "{once}"
        );
        stamp_via(&mut response, source);
        assert_eq!(response.headers().get("Via").unwrap(), once);
    }
}
