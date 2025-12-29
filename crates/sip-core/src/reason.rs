// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

const MAX_PROTOCOL_LENGTH: usize = 32;
const MAX_PARAM_NAME_LENGTH: usize = 64;
const MAX_PARAM_VALUE_LENGTH: usize = 256;
const MAX_PARAMS: usize = 20;
const MAX_PARSE_INPUT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReasonError {
    ProtocolTooLong { max: usize, actual: usize },
    ParamNameTooLong { max: usize, actual: usize },
    ParamValueTooLong { max: usize, actual: usize },
    TooManyParams { max: usize, actual: usize },
    InvalidProtocol(String),
    InvalidParamName(String),
    InvalidParamValue(String),
    EmptyProtocol,
    DuplicateParam(String),
    InputTooLarge { max: usize, actual: usize },
    ParseError(String),
}

impl std::fmt::Display for ReasonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolTooLong { max, actual } =>
                write!(f, "protocol too long (max {}, got {})", max, actual),
            Self::ParamNameTooLong { max, actual } =>
                write!(f, "param name too long (max {}, got {})", max, actual),
            Self::ParamValueTooLong { max, actual } =>
                write!(f, "param value too long (max {}, got {})", max, actual),
            Self::TooManyParams { max, actual } =>
                write!(f, "too many params (max {}, got {})", max, actual),
            Self::InvalidProtocol(msg) =>
                write!(f, "invalid protocol: {}", msg),
            Self::EmptyProtocol =>
                write!(f, "protocol cannot be empty"),
            Self::DuplicateParam(name) =>
                write!(f, "duplicate parameter: {}", name),
            Self::InputTooLarge { max, actual } =>
                write!(f, "input too large (max {}, got {})", max, actual),
            Self::ParseError(msg) =>
                write!(f, "parse error: {}", msg),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::error::Error for ReasonError {}

/// RFC 3326 Reason header.
///
/// The Reason header provides information about the reason for terminating
/// a SIP request or indicating why a proxy/server took a particular action.
///
/// # Security
///
/// ReasonHeader validates all fields to prevent injection attacks.
///
/// # Examples
///
/// ```
/// use sip_core::{ReasonHeader, Q850Cause};
///
/// // Create with Q.850 cause code
/// let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing).unwrap();
/// assert_eq!(reason.to_string(), "Q.850;cause=16;text=\"Normal Call Clearing\"");
///
/// // Create with SIP response code
/// let reason = ReasonHeader::sip(480, None).unwrap();
/// assert_eq!(reason.to_string(), "SIP;cause=480;text=\"Temporarily Unavailable\"");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonHeader {
    protocol: SmolStr,
    params: BTreeMap<SmolStr, Option<SmolStr>>,
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
            Self::Sip => "SIP",
            Self::Q850 => "Q.850",
            Self::Sdp => "SDP",
        }
    }
}

impl std::str::FromStr for ReasonProtocol {
    type Err = ReasonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sip" => Ok(Self::Sip),
            "q.850" => Ok(Self::Q850),
            "sdp" => Ok(Self::Sdp),
            _ => Err(ReasonError::InvalidProtocol(s.to_string())),
        }
    }
}

impl fmt::Display for ReasonProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Q.850 ISDN cause codes commonly used in SIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Q850Cause {
    UnallocatedNumber = 1,
    NoRouteToTransitNetwork = 2,
    NoRouteToDestination = 3,
    NormalCallClearing = 16,
    UserBusy = 17,
    NoUserResponding = 18,
    NoAnswer = 19,
    SubscriberAbsent = 20,
    CallRejected = 21,
    NumberChanged = 22,
    DestinationOutOfOrder = 27,
    InvalidNumberFormat = 28,
    FacilityRejected = 29,
    NormalUnspecified = 31,
    NoCircuitAvailable = 34,
    NetworkOutOfOrder = 38,
    TemporaryFailure = 41,
    SwitchingEquipmentCongestion = 42,
    ResourceUnavailable = 47,
    IncomingCallsBarred = 55,
    BearerCapabilityNotAuthorized = 57,
    BearerCapabilityNotAvailable = 58,
    ServiceNotAvailable = 63,
    BearerCapabilityNotImplemented = 65,
    ServiceNotImplemented = 79,
    UserNotMemberOfCUG = 87,
    IncompatibleDestination = 88,
    RecoveryOnTimerExpiry = 102,
    ProtocolError = 111,
    InterworkingUnspecified = 127,
}

impl Q850Cause {
    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn text(&self) -> &'static str {
        match self {
            Self::UnallocatedNumber => "Unallocated Number",
            Self::NoRouteToTransitNetwork => "No Route to Transit Network",
            Self::NoRouteToDestination => "No Route to Destination",
            Self::NormalCallClearing => "Normal Call Clearing",
            Self::UserBusy => "User Busy",
            Self::NoUserResponding => "No User Responding",
            Self::NoAnswer => "No Answer",
            Self::SubscriberAbsent => "Subscriber Absent",
            Self::CallRejected => "Call Rejected",
            Self::NumberChanged => "Number Changed",
            Self::DestinationOutOfOrder => "Destination Out of Order",
            Self::InvalidNumberFormat => "Invalid Number Format",
            Self::FacilityRejected => "Facility Rejected",
            Self::NormalUnspecified => "Normal Unspecified",
            Self::NoCircuitAvailable => "No Circuit Available",
            Self::NetworkOutOfOrder => "Network Out of Order",
            Self::TemporaryFailure => "Temporary Failure",
            Self::SwitchingEquipmentCongestion => "Switching Equipment Congestion",
            Self::ResourceUnavailable => "Resource Unavailable",
            Self::IncomingCallsBarred => "Incoming Calls Barred",
            Self::BearerCapabilityNotAuthorized => "Bearer Capability Not Authorized",
            Self::BearerCapabilityNotAvailable => "Bearer Capability Not Available",
            Self::ServiceNotAvailable => "Service Not Available",
            Self::BearerCapabilityNotImplemented => "Bearer Capability Not Implemented",
            Self::ServiceNotImplemented => "Service Not Implemented",
            Self::UserNotMemberOfCUG => "User Not Member of CUG",
            Self::IncompatibleDestination => "Incompatible Destination",
            Self::RecoveryOnTimerExpiry => "Recovery on Timer Expiry",
            Self::ProtocolError => "Protocol Error",
            Self::InterworkingUnspecified => "Interworking Unspecified",
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::UnallocatedNumber),
            2 => Some(Self::NoRouteToTransitNetwork),
            3 => Some(Self::NoRouteToDestination),
            16 => Some(Self::NormalCallClearing),
            17 => Some(Self::UserBusy),
            18 => Some(Self::NoUserResponding),
            19 => Some(Self::NoAnswer),
            20 => Some(Self::SubscriberAbsent),
            21 => Some(Self::CallRejected),
            22 => Some(Self::NumberChanged),
            27 => Some(Self::DestinationOutOfOrder),
            28 => Some(Self::InvalidNumberFormat),
            29 => Some(Self::FacilityRejected),
            31 => Some(Self::NormalUnspecified),
            34 => Some(Self::NoCircuitAvailable),
            38 => Some(Self::NetworkOutOfOrder),
            41 => Some(Self::TemporaryFailure),
            42 => Some(Self::SwitchingEquipmentCongestion),
            47 => Some(Self::ResourceUnavailable),
            55 => Some(Self::IncomingCallsBarred),
            57 => Some(Self::BearerCapabilityNotAuthorized),
            58 => Some(Self::BearerCapabilityNotAvailable),
            63 => Some(Self::ServiceNotAvailable),
            65 => Some(Self::BearerCapabilityNotImplemented),
            79 => Some(Self::ServiceNotImplemented),
            87 => Some(Self::UserNotMemberOfCUG),
            88 => Some(Self::IncompatibleDestination),
            102 => Some(Self::RecoveryOnTimerExpiry),
            111 => Some(Self::ProtocolError),
            127 => Some(Self::InterworkingUnspecified),
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
    pub fn q850(cause: Q850Cause) -> Result<Self, ReasonError> {
        let mut params = BTreeMap::new();
        params.insert(
            SmolStr::new("cause"),
            Some(SmolStr::new(cause.code().to_string())),
        );
        params.insert(SmolStr::new("text"), Some(SmolStr::new(cause.text())));

        Ok(Self {
            protocol: SmolStr::new(ReasonProtocol::Q850.as_str()),
            params,
        })
    }

    /// Creates a Reason header with SIP protocol and response code.
    pub fn sip(code: u16, text: Option<&str>) -> Result<Self, ReasonError> {
        let mut params = BTreeMap::new();
        params.insert(SmolStr::new("cause"), Some(SmolStr::new(code.to_string())));

        let default_text = sip_response_text(code);
        let text_value = text.unwrap_or(default_text);
        
        validate_param_value(text_value)?;
        params.insert(SmolStr::new("text"), Some(SmolStr::new(text_value)));

        Ok(Self {
            protocol: SmolStr::new(ReasonProtocol::Sip.as_str()),
            params,
        })
    }

    /// Creates a Reason header with custom protocol and parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if protocol or parameters are invalid.
    pub fn new(
        protocol: impl AsRef<str>,
        params: BTreeMap<SmolStr, Option<SmolStr>>,
    ) -> Result<Self, ReasonError> {
        validate_protocol(protocol.as_ref())?;

        if params.len() > MAX_PARAMS {
            return Err(ReasonError::TooManyParams {
                max: MAX_PARAMS,
                actual: params.len(),
            });
        }

        let mut normalized = BTreeMap::new();
        for (name, value) in params {
            let name_lower = name.as_str().to_ascii_lowercase();
            validate_param_name(&name_lower)?;
            if let Some(v) = &value {
                validate_param_value(v)?;
            }

            if normalized.contains_key(&SmolStr::new(&name_lower)) {
                return Err(ReasonError::DuplicateParam(name_lower));
            }

            normalized.insert(SmolStr::new(&name_lower), value);
        }

        let canonical_protocol = match ReasonProtocol::from_str(protocol.as_ref()) {
            Ok(p) => SmolStr::new(p.as_str()),
            Err(_) => SmolStr::new(protocol.as_ref()),
        };

        Ok(Self {
            protocol: canonical_protocol,
            params: normalized,
        })
    }

    /// Returns the protocol.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Returns an iterator over parameters.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params.iter().map(|(k, v)| {
            (k.as_str(), v.as_ref().map(|s| s.as_str()))
        })
    }

    /// Gets a parameter value by name (case-insensitive).
    pub fn get_param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(&name.to_ascii_lowercase()))
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

// Validation functions

fn validate_protocol(protocol: &str) -> Result<(), ReasonError> {
    if protocol.is_empty() {
        return Err(ReasonError::EmptyProtocol);
    }

    if protocol.len() > MAX_PROTOCOL_LENGTH {
        return Err(ReasonError::ProtocolTooLong {
            max: MAX_PROTOCOL_LENGTH,
            actual: protocol.len(),
        });
    }

    if protocol.chars().any(|c| c.is_ascii_control()) {
        return Err(ReasonError::InvalidProtocol(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_name(name: &str) -> Result<(), ReasonError> {
    if name.is_empty() {
        return Err(ReasonError::InvalidParamName("empty name".to_string()));
    }

    if name.len() > MAX_PARAM_NAME_LENGTH {
        return Err(ReasonError::ParamNameTooLong {
            max: MAX_PARAM_NAME_LENGTH,
            actual: name.len(),
        });
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(ReasonError::InvalidParamName(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_param_value(value: &str) -> Result<(), ReasonError> {
    if value.len() > MAX_PARAM_VALUE_LENGTH {
        return Err(ReasonError::ParamValueTooLong {
            max: MAX_PARAM_VALUE_LENGTH,
            actual: value.len(),
        });
    }

    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(ReasonError::InvalidParamValue(
            "contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Returns default text for common SIP response codes.
fn sip_response_text(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",
        200 => "OK",
        202 => "Accepted",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",
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
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
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
    parse_reason_from_string(header_value).ok()
}

/// Parses a Reason header value string.
pub fn parse_reason_from_string(value: &str) -> Result<ReasonHeader, ReasonError> {
    if value.len() > MAX_PARSE_INPUT {
        return Err(ReasonError::InputTooLarge {
            max: MAX_PARSE_INPUT,
            actual: value.len(),
        });
    }

    let mut parts = value.split(';');
    let protocol = parts.next().unwrap_or("").trim();
    
    validate_protocol(protocol)?;

    let mut params = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if params.len() >= MAX_PARAMS {
            return Err(ReasonError::TooManyParams {
                max: MAX_PARAMS,
                actual: params.len() + 1,
            });
        }

        if let Some((name, val)) = part.split_once('=') {
            let name_lower = name.trim().to_ascii_lowercase();
            let raw_val = val.trim();
            let val_trimmed = if raw_val.starts_with('"') && raw_val.ends_with('"') && raw_val.len() >= 2 {
                unescape_quoted_string(&raw_val[1..raw_val.len() - 1])?
            } else {
                raw_val.to_string()
            };
            
            validate_param_name(&name_lower)?;
            validate_param_value(&val_trimmed)?;

            if params.contains_key(&SmolStr::new(&name_lower)) {
                return Err(ReasonError::DuplicateParam(name_lower));
            }

            params.insert(
                SmolStr::new(&name_lower),
                Some(SmolStr::new(val_trimmed)),
            );
        } else {
            let name_lower = part.to_ascii_lowercase();
            validate_param_name(&name_lower)?;

            if params.contains_key(&SmolStr::new(&name_lower)) {
                return Err(ReasonError::DuplicateParam(name_lower));
            }

            params.insert(SmolStr::new(&name_lower), None);
        }
    }

    let canonical_protocol = match ReasonProtocol::from_str(protocol) {
        Ok(p) => SmolStr::new(p.as_str()),
        Err(_) => SmolStr::new(protocol),
    };

    Ok(ReasonHeader {
        protocol: canonical_protocol,
        params,
    })
}

fn unescape_quoted_string(input: &str) -> Result<String, ReasonError> {
    let mut out = String::new();
    let mut escape = false;
    for ch in input.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch.is_ascii_control() {
            return Err(ReasonError::InvalidParamValue(
                "contains control characters".to_string(),
            ));
        }
        out.push(ch);
    }
    if escape {
        return Err(ReasonError::ParseError(
            "unterminated escape sequence".to_string(),
        ));
    }
    Ok(out)
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
    fn reason_protocol_parse() {
        assert_eq!("sip".parse::<ReasonProtocol>().unwrap(), ReasonProtocol::Sip);
        assert_eq!("Q.850".parse::<ReasonProtocol>().unwrap(), ReasonProtocol::Q850);
        assert!("unknown".parse::<ReasonProtocol>().is_err());
    }

    #[test]
    fn q850_cause_code_and_text() {
        assert_eq!(Q850Cause::NormalCallClearing.code(), 16);
        assert_eq!(Q850Cause::NormalCallClearing.text(), "Normal Call Clearing");
        assert_eq!(Q850Cause::UserBusy.code(), 17);
        assert_eq!(Q850Cause::UserBusy.text(), "User Busy");
    }

    #[test]
    fn q850_from_code() {
        assert_eq!(Q850Cause::from_code(16), Some(Q850Cause::NormalCallClearing));
        assert_eq!(Q850Cause::from_code(17), Some(Q850Cause::UserBusy));
        assert_eq!(Q850Cause::from_code(999), None);
    }

    #[test]
    fn reason_header_q850() {
        let reason = ReasonHeader::q850(Q850Cause::UserBusy).unwrap();
        assert_eq!(reason.protocol(), "Q.850");
        assert_eq!(reason.cause_code(), Some(17));
        assert_eq!(reason.text(), Some("User Busy"));
        assert!(reason.is_q850());
        assert!(!reason.is_sip());
    }

    #[test]
    fn reason_header_sip_with_default_text() {
        let reason = ReasonHeader::sip(480, None).unwrap();
        assert_eq!(reason.protocol(), "SIP");
        assert_eq!(reason.cause_code(), Some(480));
        assert_eq!(reason.text(), Some("Temporarily Unavailable"));
        assert!(reason.is_sip());
    }

    #[test]
    fn reason_header_sip_with_custom_text() {
        let reason = ReasonHeader::sip(600, Some("Custom Busy")).unwrap();
        assert_eq!(reason.cause_code(), Some(600));
        assert_eq!(reason.text(), Some("Custom Busy"));
    }

    #[test]
    fn reason_header_display_q850() {
        let reason = ReasonHeader::q850(Q850Cause::NormalCallClearing).unwrap();
        assert_eq!(reason.to_string(), "Q.850;cause=16;text=\"Normal Call Clearing\"");
    }

    #[test]
    fn reason_header_display_sip() {
        let reason = ReasonHeader::sip(486, None).unwrap();
        assert_eq!(reason.to_string(), "SIP;cause=486;text=\"Busy Here\"");
    }

    #[test]
    fn parse_reason_q850() {
        let value = "Q.850;cause=16;text=\"Normal Call Clearing\"";
        let reason = parse_reason_from_string(value).unwrap();
        assert_eq!(reason.protocol(), "Q.850");
        assert_eq!(reason.cause_code(), Some(16));
        assert_eq!(reason.text(), Some("Normal Call Clearing"));
    }

    #[test]
    fn parse_reason_sip() {
        let value = "SIP;cause=480;text=\"Temporarily Unavailable\"";
        let reason = parse_reason_from_string(value).unwrap();
        assert_eq!(reason.protocol(), "SIP");
        assert_eq!(reason.cause_code(), Some(480));
    }

    #[test]
    fn parse_reason_text_with_escaped_quotes() {
        let value = r#"SIP;cause=480;text="Busy \"Now\"""#;
        let reason = parse_reason_from_string(value).unwrap();
        assert_eq!(reason.text(), Some(r#"Busy "Now""#));
    }

    #[test]
    fn sip_response_text_common_codes() {
        assert_eq!(sip_response_text(100), "Trying");
        assert_eq!(sip_response_text(200), "OK");
        assert_eq!(sip_response_text(404), "Not Found");
        assert_eq!(sip_response_text(486), "Busy Here");
    }

    // Security tests

    #[test]
    fn reject_empty_protocol() {
        let result = ReasonHeader::new("", BTreeMap::new());
        assert!(matches!(result, Err(ReasonError::EmptyProtocol)));
    }

    #[test]
    fn reject_crlf_in_protocol() {
        let result = ReasonHeader::new("SIP\r\nInjected", BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn reject_crlf_in_param_value() {
        let result = ReasonHeader::sip(480, Some("text\r\ninjected"));
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_protocol() {
        let long_protocol = "x".repeat(MAX_PROTOCOL_LENGTH + 1);
        let result = ReasonHeader::new(&long_protocol, BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_param_value() {
        let long_text = "x".repeat(MAX_PARAM_VALUE_LENGTH + 1);
        let result = ReasonHeader::sip(480, Some(&long_text));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_params() {
        let mut params = BTreeMap::new();
        for i in 0..=MAX_PARAMS {
            params.insert(
                SmolStr::new(&format!("p{}", i)),
                Some(SmolStr::new("value")),
            );
        }
        let result = ReasonHeader::new("SIP", params);
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_parse_input() {
        let huge = format!("SIP;{}", "param=value;".repeat(200));
        let result = parse_reason_from_string(&huge);
        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_params_in_parse() {
        let value = "SIP;cause=480;cause=486";
        let result = parse_reason_from_string(value);
        assert!(result.is_err());
    }

    #[test]
    fn fields_are_private() {
        let reason = ReasonHeader::q850(Q850Cause::UserBusy).unwrap();
        
        // These should compile
        let _ = reason.protocol();
        let _ = reason.cause_code();
        let _ = reason.params();
        
        // These should NOT compile:
        // reason.protocol = SmolStr::new("evil");  // ← Does not compile!
        // reason.params.clear();                    // ← Does not compile!
    }
}
