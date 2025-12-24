// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3262 PRACK (Reliable Provisional Response) validation.
//!
//! Provides comprehensive RAck/RSeq validation for reliable provisional responses.
//! Ensures proper sequencing and matching per RFC 3262.

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use sip_core::{Headers, Method, Request, Response};
use std::sync::Arc;
use tracing::debug;

/// Parse Method from string
fn parse_method(s: &str) -> Option<Method> {
    match s.to_uppercase().as_str() {
        "INVITE" => Some(Method::Invite),
        "ACK" => Some(Method::Ack),
        "BYE" => Some(Method::Bye),
        "CANCEL" => Some(Method::Cancel),
        "REGISTER" => Some(Method::Register),
        "OPTIONS" => Some(Method::Options),
        "INFO" => Some(Method::Info),
        "UPDATE" => Some(Method::Update),
        "MESSAGE" => Some(Method::Message),
        "PRACK" => Some(Method::Prack),
        "REFER" => Some(Method::Refer),
        "SUBSCRIBE" => Some(Method::Subscribe),
        "NOTIFY" => Some(Method::Notify),
        "PUBLISH" => Some(Method::Publish),
        _ => None,
    }
}

/// RAck header components per RFC 3262 §7.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAck {
    /// RSeq number from the provisional response being acknowledged
    pub rseq: u32,

    /// CSeq number from the provisional response being acknowledged
    pub cseq: u32,

    /// Method from the provisional response being acknowledged
    pub method: Method,
}

impl RAck {
    /// Parse RAck header value
    ///
    /// Format: RAck: <rseq> <cseq> <method>
    /// Example: RAck: 1776 314159 INVITE
    pub fn parse(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(anyhow!(
                "Invalid RAck format: expected 'rseq cseq method', got '{}'",
                value
            ));
        }

        let rseq = parts[0]
            .parse::<u32>()
            .map_err(|e| anyhow!("Invalid RSeq in RAck: {}", e))?;

        let cseq = parts[1]
            .parse::<u32>()
            .map_err(|e| anyhow!("Invalid CSeq in RAck: {}", e))?;

        let method = parse_method(parts[2])
            .ok_or_else(|| anyhow!("Invalid method in RAck: {}", parts[2]))?;

        Ok(Self { rseq, cseq, method })
    }

    /// Format RAck header value
    pub fn to_string(&self) -> String {
        format!("{} {} {}", self.rseq, self.cseq, self.method.as_str())
    }
}

/// Tracks reliable provisional responses that are awaiting PRACK
#[derive(Debug, Clone)]
struct PendingReliable {
    /// RSeq number of the reliable provisional
    rseq: u32,

    /// CSeq number from the original request
    cseq: u32,

    /// Method from the original request
    method: Method,

    /// Response code (180, 183, etc.)
    code: u16,

    /// Whether PRACK has been received for this response
    pracked: bool,
}

/// PRACK validator for ensuring proper RAck/RSeq sequencing
pub struct PrackValidator {
    /// Dialog ID → list of pending reliable provisionals
    pending: Arc<DashMap<String, Vec<PendingReliable>>>,
}

impl PrackValidator {
    /// Create a new PRACK validator
    pub fn new() -> Self {
        Self {
            pending: Arc::new(DashMap::new()),
        }
    }

    /// Register a reliable provisional response that was sent
    ///
    /// Call this when sending a reliable provisional (180/183 with RSeq header)
    pub fn register_reliable_provisional(
        &self,
        dialog_id: &str,
        rseq: u32,
        cseq: u32,
        method: Method,
        code: u16,
    ) {
        debug!(
            "Registering reliable provisional: dialog={}, rseq={}, cseq={}, method={:?}, code={}",
            dialog_id, rseq, cseq, method, code
        );

        let pending = PendingReliable {
            rseq,
            cseq,
            method,
            code,
            pracked: false,
        };

        self.pending
            .entry(dialog_id.to_string())
            .or_insert_with(Vec::new)
            .push(pending);
    }

    /// Validate an incoming PRACK request
    ///
    /// Returns Ok(()) if the PRACK is valid, Err otherwise
    ///
    /// # Validation Rules (RFC 3262 §4)
    ///
    /// 1. RAck header must be present
    /// 2. RAck RSeq must match a pending reliable provisional
    /// 3. RAck CSeq must match the provisional's CSeq
    /// 4. RAck method must match the provisional's method
    /// 5. PRACK must not be received twice for same RSeq
    pub fn validate_prack(&self, dialog_id: &str, prack: &Request) -> Result<RAck> {
        // Extract RAck header
        let rack_value = prack
            .headers
            .get("RAck")
            .ok_or_else(|| anyhow!("PRACK missing RAck header"))?;

        let rack = RAck::parse(rack_value.as_str())?;

        // Find matching pending reliable provisional
        let mut pending_list = self
            .pending
            .get_mut(dialog_id)
            .ok_or_else(|| anyhow!("No pending reliable provisionals for dialog {}", dialog_id))?;

        let pending_idx = pending_list
            .iter()
            .position(|p| p.rseq == rack.rseq)
            .ok_or_else(|| {
                anyhow!(
                    "RAck RSeq {} does not match any pending reliable provisional",
                    rack.rseq
                )
            })?;

        let pending = &mut pending_list[pending_idx];

        // Validate CSeq matches
        if pending.cseq != rack.cseq {
            return Err(anyhow!(
                "RAck CSeq {} does not match provisional CSeq {}",
                rack.cseq,
                pending.cseq
            ));
        }

        // Validate method matches
        if pending.method != rack.method {
            return Err(anyhow!(
                "RAck method {:?} does not match provisional method {:?}",
                rack.method,
                pending.method
            ));
        }

        // Check if already PRACKed
        if pending.pracked {
            return Err(anyhow!(
                "Duplicate PRACK for RSeq {} (already acknowledged)",
                rack.rseq
            ));
        }

        // Mark as PRACKed
        pending.pracked = true;

        debug!(
            "Valid PRACK received: dialog={}, rseq={}, cseq={}, method={:?}",
            dialog_id, rack.rseq, rack.cseq, rack.method
        );

        Ok(rack)
    }

    /// Check if a reliable provisional has been PRACKed
    pub fn is_pracked(&self, dialog_id: &str, rseq: u32) -> bool {
        if let Some(pending_list) = self.pending.get(dialog_id) {
            pending_list
                .iter()
                .find(|p| p.rseq == rseq)
                .map(|p| p.pracked)
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Get all pending (not yet PRACKed) reliable provisionals for a dialog
    pub fn get_pending(&self, dialog_id: &str) -> Vec<(u32, u16)> {
        if let Some(pending_list) = self.pending.get(dialog_id) {
            pending_list
                .iter()
                .filter(|p| !p.pracked)
                .map(|p| (p.rseq, p.code))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Remove all tracking for a dialog (call when dialog terminates)
    pub fn remove_dialog(&self, dialog_id: &str) {
        self.pending.remove(dialog_id);
    }

    /// Remove a specific PRACKed reliable provisional (cleanup after 200 OK)
    pub fn remove_pracked(&self, dialog_id: &str, rseq: u32) {
        if let Some(mut pending_list) = self.pending.get_mut(dialog_id) {
            pending_list.retain(|p| p.rseq != rseq || !p.pracked);
        }
    }
}

impl Default for PrackValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract RSeq from a response
pub fn extract_rseq(response: &Response) -> Option<u32> {
    response
        .headers
        .get("RSeq")
        .and_then(|v| v.as_str().parse::<u32>().ok())
}

/// Extract CSeq number from headers
pub fn extract_cseq_number(headers: &Headers) -> Option<u32> {
    headers.get("CSeq").and_then(|v| {
        let parts: Vec<&str> = v.split_whitespace().collect();
        parts.first()?.parse::<u32>().ok()
    })
}

/// Extract method from CSeq header
pub fn extract_cseq_method(headers: &Headers) -> Option<Method> {
    headers.get("CSeq").and_then(|v| {
        let parts: Vec<&str> = v.split_whitespace().collect();
        parse_method(parts.get(1)?)
    })
}

/// Check if a response is a reliable provisional (1xx with RSeq header)
pub fn is_reliable_provisional(response: &Response) -> bool {
    response.start.code >= 100
        && response.start.code < 200
        && response.start.code != 100 // 100 Trying is never reliable
        && response.headers.get("RSeq").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sip_core::{RequestLine, SipUri, StatusLine};

    #[test]
    fn parse_rack_header() {
        let rack = RAck::parse("1776 314159 INVITE").unwrap();
        assert_eq!(rack.rseq, 1776);
        assert_eq!(rack.cseq, 314159);
        assert_eq!(rack.method, Method::Invite);
    }

    #[test]
    fn parse_invalid_rack() {
        assert!(RAck::parse("invalid").is_err());
        assert!(RAck::parse("1776 314159").is_err());
        assert!(RAck::parse("abc 123 INVITE").is_err());
    }

    #[test]
    fn rack_to_string() {
        let rack = RAck {
            rseq: 1776,
            cseq: 314159,
            method: Method::Invite,
        };
        assert_eq!(rack.to_string(), "1776 314159 INVITE");
    }

    #[test]
    fn register_and_validate_prack() {
        let validator = PrackValidator::new();
        let dialog_id = "call-123";

        // Register a reliable provisional
        validator.register_reliable_provisional(dialog_id, 1, 100, Method::Invite, 180);

        // Create PRACK request
        let mut headers = Headers::new();
        headers.push("RAck".into(), "1 100 INVITE".into());

        let prack = Request::new(
            RequestLine::new(Method::Prack, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        // Validate PRACK
        let rack = validator.validate_prack(dialog_id, &prack).unwrap();
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq, 100);

        // Should now be marked as PRACKed
        assert!(validator.is_pracked(dialog_id, 1));
    }

    #[test]
    fn reject_duplicate_prack() {
        let validator = PrackValidator::new();
        let dialog_id = "call-123";

        validator.register_reliable_provisional(dialog_id, 1, 100, Method::Invite, 180);

        let mut headers = Headers::new();
        headers.push("RAck".into(), "1 100 INVITE".into());

        let prack = Request::new(
            RequestLine::new(Method::Prack, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        // First PRACK - should succeed
        assert!(validator.validate_prack(dialog_id, &prack).is_ok());

        // Second PRACK - should fail
        assert!(validator.validate_prack(dialog_id, &prack).is_err());
    }

    #[test]
    fn reject_mismatched_cseq() {
        let validator = PrackValidator::new();
        let dialog_id = "call-123";

        validator.register_reliable_provisional(dialog_id, 1, 100, Method::Invite, 180);

        let mut headers = Headers::new();
        headers.push("RAck".into(), "1 999 INVITE".into()); // Wrong CSeq

        let prack = Request::new(
            RequestLine::new(Method::Prack, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(validator.validate_prack(dialog_id, &prack).is_err());
    }

    #[test]
    fn reject_mismatched_method() {
        let validator = PrackValidator::new();
        let dialog_id = "call-123";

        validator.register_reliable_provisional(dialog_id, 1, 100, Method::Invite, 180);

        let mut headers = Headers::new();
        headers.push("RAck".into(), "1 100 UPDATE".into()); // Wrong method

        let prack = Request::new(
            RequestLine::new(Method::Prack, SipUri::parse("sip:bob@example.com").unwrap()),
            headers,
            Bytes::new(),
        );

        assert!(validator.validate_prack(dialog_id, &prack).is_err());
    }

    #[test]
    fn get_pending_provisionals() {
        let validator = PrackValidator::new();
        let dialog_id = "call-123";

        validator.register_reliable_provisional(dialog_id, 1, 100, Method::Invite, 180);
        validator.register_reliable_provisional(dialog_id, 2, 100, Method::Invite, 183);

        let pending = validator.get_pending(dialog_id);
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&(1, 180)));
        assert!(pending.contains(&(2, 183)));
    }

    #[test]
    fn is_reliable_provisional_detection() {
        let mut headers = Headers::new();
        headers.push("RSeq".into(), "1".into());

        let response_180 = Response::new(
            StatusLine::new(180, "Ringing".into()),
            headers.clone(),
            Bytes::new(),
        );

        let response_100 = Response::new(
            StatusLine::new(100, "Trying".into()),
            headers.clone(),
            Bytes::new(),
        );

        let response_200 = Response::new(
            StatusLine::new(200, "OK".into()),
            headers.clone(),
            Bytes::new(),
        );

        assert!(is_reliable_provisional(&response_180)); // 180 with RSeq
        assert!(!is_reliable_provisional(&response_100)); // 100 never reliable
        assert!(!is_reliable_provisional(&response_200)); // 200 is not provisional
    }
}
