//! CANCEL and ACK forwarding for stateful proxies per RFC 3261 §16
//!
//! Handles special cases for CANCEL and ACK forwarding which require
//! different processing than regular request forwarding.

use anyhow::{anyhow, Result};
use sip_core::{Method, Request, SipUri};
use tracing::{debug, warn};

/// CANCEL forwarding per RFC 3261 §16.10
///
/// A stateful proxy MUST forward CANCEL requests only if it has forwarded
/// the corresponding INVITE request. The CANCEL is forwarded to the same
/// destination(s) as the INVITE.
pub struct CancelForwarder;

impl CancelForwarder {
    /// Check if a CANCEL matches an existing INVITE transaction
    ///
    /// Per RFC 3261 §9.2, CANCEL matches INVITE if:
    /// - Request-URI matches
    /// - From tag matches
    /// - Call-ID matches
    /// - CSeq number matches (but method is CANCEL not INVITE)
    ///
    /// Returns the CSeq number of the INVITE being cancelled
    pub fn extract_invite_cseq(cancel: &Request) -> Result<u32> {
        let cseq_header = cancel
            .headers
            .get("CSeq")
            .ok_or_else(|| anyhow!("CANCEL missing CSeq header"))?;

        // Parse "123 CANCEL" → 123
        let parts: Vec<&str> = cseq_header.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid CSeq format: {}", cseq_header));
        }

        parts[0]
            .parse::<u32>()
            .map_err(|e| anyhow!("Failed to parse CSeq number: {}", e))
    }

    /// Prepare CANCEL for forwarding to a specific branch
    ///
    /// The proxy MUST:
    /// 1. Copy Request-URI from the CANCEL request
    /// 2. Copy the To header from the CANCEL request
    /// 3. Copy the From header from the CANCEL request
    /// 4. Copy the Call-ID from the CANCEL request
    /// 5. Copy the CSeq from the CANCEL request
    /// 6. Add a new Via header
    /// 7. Copy Route headers
    ///
    /// Note: The CANCEL will have the same branch parameter as the
    /// original INVITE to this target (for transaction matching).
    pub fn prepare_cancel(original_cancel: &Request, target_branch: &str) -> Result<Request> {
        let mut cancel = original_cancel.clone();

        // Update Via header with target branch
        // The branch parameter MUST match the INVITE branch for this target
        debug!("Preparing CANCEL with branch {} for forwarding", target_branch);

        // In a real implementation, we'd update the Via header here
        // For now, we just return the cloned request
        // TODO: Update Via header branch parameter

        Ok(cancel)
    }

    /// Determine if CANCEL should be forwarded to a branch
    ///
    /// Per RFC 3261 §16.10, a stateful proxy should forward CANCEL to
    /// a branch only if:
    /// - The INVITE has been forwarded to that branch
    /// - A final response has not yet been received on that branch
    ///
    /// Returns true if CANCEL should be forwarded to this branch
    pub fn should_forward_to_branch(branch_state: &crate::stateful::BranchState) -> bool {
        match branch_state {
            crate::stateful::BranchState::Trying | crate::stateful::BranchState::Proceeding => {
                // INVITE sent but no final response yet - forward CANCEL
                true
            }
            crate::stateful::BranchState::Completed
            | crate::stateful::BranchState::Cancelled
            | crate::stateful::BranchState::TimedOut => {
                // Branch already finished - no need to CANCEL
                false
            }
        }
    }
}

/// ACK forwarding per RFC 3261 §16.11
///
/// ACK handling differs between 2xx and non-2xx responses:
/// - ACK for 2xx: Creates a new transaction, forward like any request
/// - ACK for non-2xx: Part of INVITE transaction, proxy must forward statefully
pub struct AckForwarder;

impl AckForwarder {
    /// Determine the type of ACK based on CSeq and response
    pub fn ack_type(ack: &Request) -> AckType {
        // In a real implementation, we'd check if this ACK is for a 2xx
        // response by looking at the transaction state
        // For now, we default to assuming it's for a non-2xx
        AckType::Non2xx
    }

    /// Prepare ACK for forwarding
    ///
    /// For ACK to 2xx responses (RFC 3261 §16.11):
    /// - Treated as a new request
    /// - Uses Route headers to determine destination
    /// - May need to resolve Request-URI if no Route headers
    ///
    /// For ACK to non-2xx responses:
    /// - Forwarded hop-by-hop within INVITE transaction
    /// - Destination determined from INVITE forwarding
    pub fn prepare_ack(original_ack: &Request, _ack_type: AckType) -> Result<Request> {
        // Clone the ACK
        let ack = original_ack.clone();

        // In a real implementation, we'd:
        // 1. Process Route headers (for 2xx ACK)
        // 2. Update Request-URI (for 2xx ACK)
        // 3. Add Via header
        // 4. Forward to appropriate destination

        Ok(ack)
    }

    /// Check if ACK contains SDP (late offer scenario)
    ///
    /// In a late offer flow:
    /// - INVITE has no SDP
    /// - 200 OK contains SDP offer
    /// - ACK contains SDP answer
    ///
    /// Proxies should forward this ACK with the SDP body intact
    pub fn has_sdp(ack: &Request) -> bool {
        !ack.body.is_empty()
            && ack
                .headers
                .get("Content-Type")
                .map(|ct| ct.contains("application/sdp"))
                .unwrap_or(false)
    }
}

/// Type of ACK being forwarded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckType {
    /// ACK for 2xx response (creates new transaction)
    For2xx,

    /// ACK for non-2xx response (part of INVITE transaction)
    Non2xx,
}

/// Route header processing per RFC 3261 §16.4 and §16.6
pub struct RouteProcessor;

impl RouteProcessor {
    /// Extract Route headers and determine next hop
    ///
    /// RFC 3261 §16.6 step 2: Route Information Preprocessing
    ///
    /// If the Request-URI contains a value this proxy previously placed
    /// into a Record-Route header, the proxy MUST:
    /// 1. Replace Request-URI with last Route header value
    /// 2. Remove that Route header
    pub fn process_route_set(request: &mut Request, proxy_uris: &[SipUri]) -> Result<Option<SipUri>> {
        // Check if Request-URI is one of our Record-Route URIs
        let request_uri = request.start.uri.as_sip()
            .ok_or_else(|| anyhow!("Request-URI is not a SIP URI"))?;

        let is_our_uri = proxy_uris
            .iter()
            .any(|uri| uri.as_str() == request_uri.as_str());

        if is_our_uri {
            debug!("Request-URI matches our Record-Route - processing Route headers");

            // Get the last Route header value
            let route_values: Vec<_> = request
                .headers
                .iter()
                .filter(|h| h.name.as_str().eq_ignore_ascii_case("Route"))
                .map(|h| h.value.clone())
                .collect();

            if let Some(last_route) = route_values.last() {
                // Extract URI from Route header (remove angle brackets)
                let route_uri_str = last_route
                    .as_str()
                    .trim_matches(|c| c == '<' || c == '>');

                if let Some(route_uri) = SipUri::parse(route_uri_str) {
                    debug!("Moving Route header to Request-URI: {}", route_uri.as_str());

                    // Update Request-URI
                    crate::ProxyHelpers::set_request_uri(request, route_uri.clone());

                    // Remove the last Route header
                    // TODO: Actually remove the Route header

                    return Ok(Some(route_uri));
                }
            }
        }

        Ok(None)
    }

    /// Get next hop from Route header or Request-URI
    ///
    /// Returns the destination to forward the request to
    pub fn get_next_hop(request: &Request) -> Result<SipUri> {
        // Check for Route headers
        if let Some(route) = request.headers.get("Route") {
            // Extract URI from Route header
            let uri_str = route.as_str().trim_matches(|c| c == '<' || c == '>');
            SipUri::parse(uri_str).ok_or_else(|| anyhow!("Invalid Route header URI"))
        } else {
            // Use Request-URI
            request
                .start
                .uri
                .as_sip()
                .cloned()
                .ok_or_else(|| anyhow!("Request-URI is not a SIP URI"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{Headers, RequestLine};

    fn make_cancel() -> Request {
        let mut headers = Headers::new();
        headers.push("Call-ID".into(), "test-123".into());
        headers.push("CSeq".into(), "1 CANCEL".into());
        headers.push("From".into(), "<sip:alice@example.com>;tag=abc".into());
        headers.push("To".into(), "<sip:bob@example.com>".into());

        Request::new(
            RequestLine::new(Method::Cancel, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
    }

    fn make_ack() -> Request {
        let mut headers = Headers::new();
        headers.push("Call-ID".into(), "test-123".into());
        headers.push("CSeq".into(), "1 ACK".into());

        Request::new(
            RequestLine::new(Method::Ack, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        )
    }

    #[test]
    fn extracts_invite_cseq_from_cancel() {
        let cancel = make_cancel();
        let cseq = CancelForwarder::extract_invite_cseq(&cancel).unwrap();
        assert_eq!(cseq, 1);
    }

    #[test]
    fn should_forward_cancel_to_trying_branch() {
        let state = crate::stateful::BranchState::Trying;
        assert!(CancelForwarder::should_forward_to_branch(&state));
    }

    #[test]
    fn should_not_forward_cancel_to_completed_branch() {
        let state = crate::stateful::BranchState::Completed;
        assert!(!CancelForwarder::should_forward_to_branch(&state));
    }

    #[test]
    fn detects_ack_with_sdp() {
        let mut ack = make_ack();
        ack.headers.push("Content-Type".into(), "application/sdp".into());
        ack.body = Bytes::from("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n");

        assert!(AckForwarder::has_sdp(&ack));
    }

    #[test]
    fn detects_ack_without_sdp() {
        let ack = make_ack();
        assert!(!AckForwarder::has_sdp(&ack));
    }

    #[test]
    fn gets_next_hop_from_request_uri() {
        let request = make_ack();
        let next_hop = RouteProcessor::get_next_hop(&request).unwrap();
        assert_eq!(next_hop.as_str(), "sip:bob@example.com");
    }
}
