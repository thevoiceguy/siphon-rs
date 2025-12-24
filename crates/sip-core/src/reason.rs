// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;

/// RFC 3326 Reason header.
///
/// The Reason header provides information about the reason for terminating
/// a SIP request or indicating why a proxy/server took a particular action.
///
/// # Examples
///
/// ```
/// use sip_core::{ReasonHeader, Q850Cause};
///
/// // Create with Q.850 cause code
/// let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing);
/// assert_eq!(reason.to_string(), "Q.850;cause=16;text=\"Normal Call Clearing\"");
///
/// // Create with SIP response code
/// let reason = ReasonHeader::sip(480, None);
/// assert_eq!(reason.to_string(), "SIP;cause=480;text=\"Temporarily Unavailable\"");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonHeader {
    pub protocol: SmolStr,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// RFC 3326 protocol values for Reason header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonProtocol {
    /// SIP response codes (RFC 3261)
    Sip,
    /// Q.850 ISDN cause codes
    Q850,
    /// SDP negotiation failures
    Sdp,
}

impl ReasonProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReasonProtocol::Sip => "SIP",
            ReasonProtocol::Q850 => "Q.850",
            ReasonProtocol::Sdp => "SDP",
        }
    }
}

impl fmt::Display for ReasonProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Q.850 ISDN cause codes commonly used in SIP.
///
/// These cause codes provide standardized reasons for call termination
/// that are understood across different telephony systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Q850Cause {
    /// Cause 1 - Unallocated (unassigned) number
    UnallocatedNumber = 1,
    /// Cause 2 - No route to specified transit network
    NoRouteToTransitNetwork = 2,
    /// Cause 3 - No route to destination
    NoRouteToDestination = 3,
    /// Cause 16 - Normal call clearing
    NormalCallClearing = 16,
    /// Cause 17 - User busy
    UserBusy = 17,
    /// Cause 18 - No user responding
    NoUserResponding = 18,
    /// Cause 19 - No answer from user (user alerted)
    NoAnswer = 19,
    /// Cause 20 - Subscriber absent
    SubscriberAbsent = 20,
    /// Cause 21 - Call rejected
    CallRejected = 21,
    /// Cause 22 - Number changed
    NumberChanged = 22,
    /// Cause 27 - Destination out of order
    DestinationOutOfOrder = 27,
    /// Cause 28 - Invalid number format (address incomplete)
    InvalidNumberFormat = 28,
    /// Cause 29 - Facility rejected
    FacilityRejected = 29,
    /// Cause 31 - Normal, unspecified
    NormalUnspecified = 31,
    /// Cause 34 - No circuit/channel available
    NoCircuitAvailable = 34,
    /// Cause 38 - Network out of order
    NetworkOutOfOrder = 38,
    /// Cause 41 - Temporary failure
    TemporaryFailure = 41,
    /// Cause 42 - Switching equipment congestion
    SwitchingEquipmentCongestion = 42,
    /// Cause 47 - Resource unavailable, unspecified
    ResourceUnavailable = 47,
    /// Cause 55 - Incoming calls barred within CUG
    IncomingCallsBarred = 55,
    /// Cause 57 - Bearer capability not authorized
    BearerCapabilityNotAuthorized = 57,
    /// Cause 58 - Bearer capability not presently available
    BearerCapabilityNotAvailable = 58,
    /// Cause 63 - Service or option not available, unspecified
    ServiceNotAvailable = 63,
    /// Cause 65 - Bearer capability not implemented
    BearerCapabilityNotImplemented = 65,
    /// Cause 79 - Service or option not implemented, unspecified
    ServiceNotImplemented = 79,
    /// Cause 87 - User not member of CUG
    UserNotMemberOfCUG = 87,
    /// Cause 88 - Incompatible destination
    IncompatibleDestination = 88,
    /// Cause 102 - Recovery on timer expiry
    RecoveryOnTimerExpiry = 102,
    /// Cause 111 - Protocol error, unspecified
    ProtocolError = 111,
    /// Cause 127 - Interworking, unspecified
    InterworkingUnspecified = 127,
}

impl Q850Cause {
    /// Returns the numeric cause code.
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Returns the textual description of the cause.
    pub fn text(&self) -> &'static str {
        match self {
            Q850Cause::UnallocatedNumber => "Unallocated Number",
            Q850Cause::NoRouteToTransitNetwork => "No Route to Transit Network",
            Q850Cause::NoRouteToDestination => "No Route to Destination",
            Q850Cause::NormalCallClearing => "Normal Call Clearing",
            Q850Cause::UserBusy => "User Busy",
            Q850Cause::NoUserResponding => "No User Responding",
            Q850Cause::NoAnswer => "No Answer",
            Q850Cause::SubscriberAbsent => "Subscriber Absent",
            Q850Cause::CallRejected => "Call Rejected",
            Q850Cause::NumberChanged => "Number Changed",
            Q850Cause::DestinationOutOfOrder => "Destination Out of Order",
            Q850Cause::InvalidNumberFormat => "Invalid Number Format",
            Q850Cause::FacilityRejected => "Facility Rejected",
            Q850Cause::NormalUnspecified => "Normal Unspecified",
            Q850Cause::NoCircuitAvailable => "No Circuit Available",
            Q850Cause::NetworkOutOfOrder => "Network Out of Order",
            Q850Cause::TemporaryFailure => "Temporary Failure",
            Q850Cause::SwitchingEquipmentCongestion => "Switching Equipment Congestion",
            Q850Cause::ResourceUnavailable => "Resource Unavailable",
            Q850Cause::IncomingCallsBarred => "Incoming Calls Barred",
            Q850Cause::BearerCapabilityNotAuthorized => "Bearer Capability Not Authorized",
            Q850Cause::BearerCapabilityNotAvailable => "Bearer Capability Not Available",
            Q850Cause::ServiceNotAvailable => "Service Not Available",
            Q850Cause::BearerCapabilityNotImplemented => "Bearer Capability Not Implemented",
            Q850Cause::ServiceNotImplemented => "Service Not Implemented",
            Q850Cause::UserNotMemberOfCUG => "User Not Member of CUG",
            Q850Cause::IncompatibleDestination => "Incompatible Destination",
            Q850Cause::RecoveryOnTimerExpiry => "Recovery on Timer Expiry",
            Q850Cause::ProtocolError => "Protocol Error",
            Q850Cause::InterworkingUnspecified => "Interworking Unspecified",
        }
    }

    /// Creates a Q850Cause from a numeric code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Q850Cause::UnallocatedNumber),
            2 => Some(Q850Cause::NoRouteToTransitNetwork),
            3 => Some(Q850Cause::NoRouteToDestination),
            16 => Some(Q850Cause::NormalCallClearing),
            17 => Some(Q850Cause::UserBusy),
            18 => Some(Q850Cause::NoUserResponding),
            19 => Some(Q850Cause::NoAnswer),
            20 => Some(Q850Cause::SubscriberAbsent),
            21 => Some(Q850Cause::CallRejected),
            22 => Some(Q850Cause::NumberChanged),
            27 => Some(Q850Cause::DestinationOutOfOrder),
            28 => Some(Q850Cause::InvalidNumberFormat),
            29 => Some(Q850Cause::FacilityRejected),
            31 => Some(Q850Cause::NormalUnspecified),
            34 => Some(Q850Cause::NoCircuitAvailable),
            38 => Some(Q850Cause::NetworkOutOfOrder),
            41 => Some(Q850Cause::TemporaryFailure),
            42 => Some(Q850Cause::SwitchingEquipmentCongestion),
            47 => Some(Q850Cause::ResourceUnavailable),
            55 => Some(Q850Cause::IncomingCallsBarred),
            57 => Some(Q850Cause::BearerCapabilityNotAuthorized),
            58 => Some(Q850Cause::BearerCapabilityNotAvailable),
            63 => Some(Q850Cause::ServiceNotAvailable),
            65 => Some(Q850Cause::BearerCapabilityNotImplemented),
            79 => Some(Q850Cause::ServiceNotImplemented),
            87 => Some(Q850Cause::UserNotMemberOfCUG),
            88 => Some(Q850Cause::IncompatibleDestination),
            102 => Some(Q850Cause::RecoveryOnTimerExpiry),
            111 => Some(Q850Cause::ProtocolError),
            127 => Some(Q850Cause::InterworkingUnspecified),
            _ => None,
        }
    }
}

impl fmt::Display for Q850Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text())
    }
}

impl ReasonHeader {
    /// Creates a Reason header with Q.850 protocol and cause code.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::{ReasonHeader, Q850Cause};
    ///
    /// let reason = ReasonHeader::q850(Q850Cause::UserBusy);
    /// assert_eq!(reason.protocol.as_str(), "Q.850");
    /// ```
    pub fn q850(cause: Q850Cause) -> Self {
        let mut params = BTreeMap::new();
        params.insert(
            SmolStr::new("cause"),
            Some(SmolStr::new(cause.code().to_string())),
        );
        params.insert(
            SmolStr::new("text"),
            Some(SmolStr::new(cause.text().to_owned())),
        );

        Self {
            protocol: SmolStr::new(ReasonProtocol::Q850.as_str().to_owned()),
            params,
        }
    }

    /// Creates a Reason header with SIP protocol and response code.
    ///
    /// The text parameter is optional. If not provided, a default text
    /// for common SIP response codes will be used.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReasonHeader;
    ///
    /// // With default text
    /// let reason = ReasonHeader::sip(480, None);
    /// assert_eq!(reason.protocol.as_str(), "SIP");
    ///
    /// // With custom text
    /// let reason = ReasonHeader::sip(600, Some("Custom Busy"));
    /// ```
    pub fn sip(code: u16, text: Option<&str>) -> Self {
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("cause"), Some(SmolStr::new(code.to_string())));

        let default_text = sip_response_text(code);
        let text = text.unwrap_or(default_text);
        params.insert(SmolStr::new("text"), Some(SmolStr::new(text.to_owned())));

        Self {
            protocol: SmolStr::new(ReasonProtocol::Sip.as_str().to_owned()),
            params,
        }
    }

    /// Creates a Reason header with custom protocol and parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::ReasonHeader;
    /// use std::collections::BTreeMap;
    /// use smol_str::SmolStr;
    ///
    /// let mut params = BTreeMap::new();
    /// params.insert(SmolStr::new("cause"), Some(SmolStr::new("42")));
    ///
    /// let reason = ReasonHeader::new("SDP", params);
    /// assert_eq!(reason.protocol.as_str(), "SDP");
    /// ```
    pub fn new(protocol: &str, params: BTreeMap<SmolStr, Option<SmolStr>>) -> Self {
        Self {
            protocol: SmolStr::new(protocol.to_owned()),
            params,
        }
    }

    /// Returns the cause code as a u16 if present and valid.
    pub fn cause_code(&self) -> Option<u16> {
        self.params
            .get("cause")
            .and_then(|v| v.as_ref())
            .and_then(|s| s.parse().ok())
    }

    /// Returns the text parameter if present.
    pub fn text(&self) -> Option<&str> {
        self.params
            .get("text")
            .and_then(|v| v.as_ref())
            .map(|s| s.as_str())
    }

    /// Checks if this is a Q.850 reason.
    pub fn is_q850(&self) -> bool {
        self.protocol.eq_ignore_ascii_case("Q.850")
    }

    /// Checks if this is a SIP reason.
    pub fn is_sip(&self) -> bool {
        self.protocol.eq_ignore_ascii_case("SIP")
    }

    /// Returns the Q850Cause if this is a Q.850 reason with a recognized code.
    pub fn as_q850_cause(&self) -> Option<Q850Cause> {
        if self.is_q850() {
            self.cause_code().and_then(Q850Cause::from_code)
        } else {
            None
        }
    }
}

impl fmt::Display for ReasonHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.protocol)?;

        for (key, value) in &self.params {
            write!(f, ";{}", key)?;
            if let Some(val) = value {
                // Quote the value if it contains special characters or is the text parameter
                if key == "text" || val.contains(|c: char| c.is_whitespace() || c == ';') {
                    write!(f, "=\"{}\"", val)?;
                } else {
                    write!(f, "={}", val)?;
                }
            }
        }

        Ok(())
    }
}

/// Returns default text for common SIP response codes.
fn sip_response_text(code: u16) -> &'static str {
    match code {
        // 1xx Provisional
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",
        // 2xx Success
        200 => "OK",
        202 => "Accepted",
        // 3xx Redirection
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",
        // 4xx Client Error
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        420 => "Bad Extension",
        421 => "Extension Required",
        423 => "Interval Too Brief",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        493 => "Undecipherable",
        // 5xx Server Error
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
        // 6xx Global Failure
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",
        _ => "Unknown",
    }
}

/// Helper function to parse Reason header from headers.
pub fn parse_reason_header(headers: &crate::Headers) -> Option<ReasonHeader> {
    let header_value = headers.get("Reason")?;
    Some(parse_reason_from_string(header_value.as_str()))
}

/// Parses a Reason header value string.
fn parse_reason_from_string(value: &str) -> ReasonHeader {
    let mut parts = value.split(';');
    let protocol = SmolStr::new(parts.next().unwrap_or("").trim().to_owned());
    let mut params = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            params.insert(
                SmolStr::new(name.to_ascii_lowercase()),
                Some(SmolStr::new(val.trim().trim_matches('"').to_owned())),
            );
        } else {
            params.insert(SmolStr::new(part.to_ascii_lowercase()), None);
        }
    }
    ReasonHeader { protocol, params }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_protocol_as_str() {
        assert_eq!(ReasonProtocol::Sip.as_str(), "SIP");
        assert_eq!(ReasonProtocol::Q850.as_str(), "Q.850");
        assert_eq!(ReasonProtocol::Sdp.as_str(), "SDP");
    }

    #[test]
    fn q850_cause_code_and_text() {
        assert_eq!(Q850Cause::NormalCallClearing.code(), 16);
        assert_eq!(Q850Cause::NormalCallClearing.text(), "Normal Call Clearing");

        assert_eq!(Q850Cause::UserBusy.code(), 17);
        assert_eq!(Q850Cause::UserBusy.text(), "User Busy");

        assert_eq!(Q850Cause::NoAnswer.code(), 19);
        assert_eq!(Q850Cause::NoAnswer.text(), "No Answer");
    }

    #[test]
    fn q850_from_code() {
        assert_eq!(
            Q850Cause::from_code(16),
            Some(Q850Cause::NormalCallClearing)
        );
        assert_eq!(Q850Cause::from_code(17), Some(Q850Cause::UserBusy));
        assert_eq!(Q850Cause::from_code(19), Some(Q850Cause::NoAnswer));
        assert_eq!(Q850Cause::from_code(999), None);
    }

    #[test]
    fn reason_header_q850() {
        let reason = ReasonHeader::q850(Q850Cause::UserBusy);
        assert_eq!(reason.protocol.as_str(), "Q.850");
        assert_eq!(reason.cause_code(), Some(17));
        assert_eq!(reason.text(), Some("User Busy"));
        assert!(reason.is_q850());
        assert!(!reason.is_sip());
    }

    #[test]
    fn reason_header_sip_with_default_text() {
        let reason = ReasonHeader::sip(480, None);
        assert_eq!(reason.protocol.as_str(), "SIP");
        assert_eq!(reason.cause_code(), Some(480));
        assert_eq!(reason.text(), Some("Temporarily Unavailable"));
        assert!(reason.is_sip());
        assert!(!reason.is_q850());
    }

    #[test]
    fn reason_header_sip_with_custom_text() {
        let reason = ReasonHeader::sip(600, Some("Custom Busy"));
        assert_eq!(reason.protocol.as_str(), "SIP");
        assert_eq!(reason.cause_code(), Some(600));
        assert_eq!(reason.text(), Some("Custom Busy"));
    }

    #[test]
    fn reason_header_display_q850() {
        let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing);
        assert_eq!(
            reason.to_string(),
            "Q.850;cause=16;text=\"Normal Call Clearing\""
        );
    }

    #[test]
    fn reason_header_display_sip() {
        let reason = ReasonHeader::sip(486, None);
        assert_eq!(reason.to_string(), "SIP;cause=486;text=\"Busy Here\"");
    }

    #[test]
    fn reason_header_as_q850_cause() {
        let reason = ReasonHeader::q850(Q850Cause::CallRejected);
        assert_eq!(reason.as_q850_cause(), Some(Q850Cause::CallRejected));

        let sip_reason = ReasonHeader::sip(480, None);
        assert_eq!(sip_reason.as_q850_cause(), None);
    }

    #[test]
    fn parse_reason_q850() {
        let value = "Q.850;cause=16;text=\"Normal Call Clearing\"";
        let reason = parse_reason_from_string(value);
        assert_eq!(reason.protocol.as_str(), "Q.850");
        assert_eq!(reason.cause_code(), Some(16));
        assert_eq!(reason.text(), Some("Normal Call Clearing"));
    }

    #[test]
    fn parse_reason_sip() {
        let value = "SIP;cause=480;text=\"Temporarily Unavailable\"";
        let reason = parse_reason_from_string(value);
        assert_eq!(reason.protocol.as_str(), "SIP");
        assert_eq!(reason.cause_code(), Some(480));
        assert_eq!(reason.text(), Some("Temporarily Unavailable"));
    }

    #[test]
    fn parse_reason_without_quotes() {
        let value = "SIP;cause=200;text=OK";
        let reason = parse_reason_from_string(value);
        assert_eq!(reason.protocol.as_str(), "SIP");
        assert_eq!(reason.cause_code(), Some(200));
        assert_eq!(reason.text(), Some("OK"));
    }

    #[test]
    fn parse_reason_minimal() {
        let value = "Q.850;cause=16";
        let reason = parse_reason_from_string(value);
        assert_eq!(reason.protocol.as_str(), "Q.850");
        assert_eq!(reason.cause_code(), Some(16));
        assert_eq!(reason.text(), None);
    }

    #[test]
    fn sip_response_text_common_codes() {
        assert_eq!(sip_response_text(100), "Trying");
        assert_eq!(sip_response_text(180), "Ringing");
        assert_eq!(sip_response_text(200), "OK");
        assert_eq!(sip_response_text(404), "Not Found");
        assert_eq!(sip_response_text(480), "Temporarily Unavailable");
        assert_eq!(sip_response_text(486), "Busy Here");
        assert_eq!(sip_response_text(487), "Request Terminated");
        assert_eq!(sip_response_text(500), "Server Internal Error");
        assert_eq!(sip_response_text(600), "Busy Everywhere");
    }

    #[test]
    fn reason_header_new_custom() {
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("cause"), Some(SmolStr::new("42")));
        params.insert(SmolStr::new("text"), Some(SmolStr::new("Custom")));

        let reason = ReasonHeader::new("SDP", params);
        assert_eq!(reason.protocol.as_str(), "SDP");
        assert_eq!(reason.cause_code(), Some(42));
        assert_eq!(reason.text(), Some("Custom"));
    }
}
