// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SDP (Session Description Protocol) implementation per RFC 4566.
//!
//! This module provides comprehensive support for parsing, generating, and
//! manipulating SDP session descriptions.
//!
//! # RFC 4566 Compliance
//!
//! This implementation supports all RFC 4566 fields:
//!
//! ## Session-Level Fields
//! - v= (version) - Required
//! - o= (origin) - Required
//! - s= (session name) - Required
//! - i= (session information) - Optional
//! - u= (URI) - Optional
//! - e= (email) - Optional, multiple allowed
//! - p= (phone) - Optional, multiple allowed
//! - c= (connection) - Optional (required if not in media)
//! - b= (bandwidth) - Optional, multiple allowed
//! - t= (timing) - Required, at least one
//! - r= (repeat times) - Optional
//! - z= (time zones) - Optional
//! - k= (encryption key) - Optional
//! - a= (attributes) - Optional, multiple allowed
//!
//! ## Media-Level Fields
//! - m= (media description) - Optional, multiple allowed
//! - i= (media title) - Optional
//! - c= (connection) - Optional
//! - b= (bandwidth) - Optional, multiple allowed
//! - k= (encryption key) - Optional
//! - a= (attributes) - Optional, multiple allowed
//!
//! ## Parsed Attributes
//! - a=sendrecv, sendonly, recvonly, inactive (direction)
//! - a=rtpmap (RTP payload mapping)
//! - a=fmtp (format parameters)
//! - Generic attributes (property and value forms)
//!
//! # Examples
//!
//! ```
//! use sip_core::sdp::{SdpSession, Origin, Connection, MediaDescription};
//!
//! // Parse SDP
//! let sdp_text = "v=0\r\n\
//!                 o=alice 123 456 IN IP4 192.0.2.1\r\n\
//!                 s=Example Session\r\n\
//!                 c=IN IP4 192.0.2.1\r\n\
//!                 t=0 0\r\n\
//!                 m=audio 49170 RTP/AVP 0\r\n";
//!
//! let session = SdpSession::parse(sdp_text).unwrap();
//! assert_eq!(session.version, 0);
//! assert_eq!(session.session_name, "Example Session");
//! assert_eq!(session.media.len(), 1);
//!
//! // Generate SDP
//! let generated = session.to_string();
//! ```

use std::fmt;

/// Error types for SDP parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpError {
    /// Missing required field
    MissingRequiredField(&'static str),
    /// Invalid field format
    InvalidFormat(&'static str),
    /// Invalid field order
    InvalidOrder(String),
    /// Unknown field type
    UnknownField(char),
    /// Invalid line syntax
    InvalidSyntax(String),
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpError::MissingRequiredField(field) => write!(f, "Missing required field: {}", field),
            SdpError::InvalidFormat(field) => write!(f, "Invalid format for field: {}", field),
            SdpError::InvalidOrder(msg) => write!(f, "Invalid field order: {}", msg),
            SdpError::UnknownField(c) => write!(f, "Unknown field type: {}", c),
            SdpError::InvalidSyntax(msg) => write!(f, "Invalid syntax: {}", msg),
        }
    }
}

impl std::error::Error for SdpError {}

/// SDP session description (RFC 4566).
///
/// Represents a complete SDP session with session-level fields and
/// zero or more media descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpSession {
    // Required session-level fields
    /// Protocol version (v=), currently always 0
    pub version: u32,
    /// Session originator and identifier (o=)
    pub origin: Origin,
    /// Session name (s=)
    pub session_name: String,

    // Optional session-level fields
    /// Session information (i=)
    pub session_info: Option<String>,
    /// URI of additional information (u=)
    pub uri: Option<String>,
    /// Email addresses (e=, multiple allowed)
    pub emails: Vec<String>,
    /// Phone numbers (p=, multiple allowed)
    pub phones: Vec<String>,
    /// Connection information (c=)
    pub connection: Option<Connection>,
    /// Bandwidth information (b=, multiple allowed)
    pub bandwidth: Vec<Bandwidth>,
    /// Timing information (t=, at least one required)
    pub timing: Vec<Timing>,
    /// Repeat times (r=)
    pub repeat_times: Vec<RepeatTime>,
    /// Time zone adjustments (z=)
    pub time_zones: Vec<TimeZone>,
    /// Encryption key (k=)
    pub encryption_key: Option<EncryptionKey>,
    /// Session-level attributes (a=)
    pub attributes: Vec<Attribute>,
    /// Media groups (a=group:, RFC 3388)
    pub groups: Vec<MediaGroup>,
    /// Capability set (a=sqn/cdsc/cpar, RFC 3407)
    pub capability_set: Option<SdpCapabilitySet>,

    // Media descriptions
    /// Media descriptions (m=, zero or more)
    pub media: Vec<MediaDescription>,
}

/// Origin line (o=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub username: String,
    pub sess_id: String,
    pub sess_version: String,
    pub nettype: String,
    pub addrtype: String,
    pub unicast_address: String,
}

/// Connection line (c=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub nettype: String,
    pub addrtype: String,
    pub connection_address: String,
}

/// Bandwidth modifier type.
///
/// Defines the interpretation of the bandwidth value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthType {
    /// Conference Total (CT) - total bandwidth for all sites (RFC 4566)
    CT,
    /// Application Specific (AS) - application-specific maximum (RFC 4566)
    AS,
    /// RTCP bandwidth for active data senders (RFC 3556)
    RS,
    /// RTCP bandwidth for receivers/non-senders (RFC 3556)
    RR,
    /// TIAS - Transport Independent Application Specific (RFC 3890)
    TIAS,
    /// Other/unregistered bandwidth type
    Other(char),
}

impl BandwidthType {
    pub fn as_str(&self) -> &str {
        match self {
            BandwidthType::CT => "CT",
            BandwidthType::AS => "AS",
            BandwidthType::RS => "RS",
            BandwidthType::RR => "RR",
            BandwidthType::TIAS => "TIAS",
            BandwidthType::Other(_) => "X",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CT" => BandwidthType::CT,
            "AS" => BandwidthType::AS,
            "RS" => BandwidthType::RS,
            "RR" => BandwidthType::RR,
            "TIAS" => BandwidthType::TIAS,
            other => {
                if let Some(ch) = other.chars().next() {
                    BandwidthType::Other(ch)
                } else {
                    BandwidthType::Other('X')
                }
            }
        }
    }

    /// Returns true if this is an RTCP bandwidth modifier (RS or RR).
    pub fn is_rtcp(&self) -> bool {
        matches!(self, BandwidthType::RS | BandwidthType::RR)
    }
}

impl fmt::Display for BandwidthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BandwidthType::Other(ch) => write!(f, "{}", ch),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

/// Bandwidth line (b=) components.
///
/// Specifies bandwidth requirements or limits for a session or media stream.
/// RFC 4566 defines CT and AS, RFC 3556 adds RS and RR for RTCP,
/// RFC 3890 adds TIAS for transport-independent bandwidth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bandwidth {
    /// Bandwidth modifier type (e.g., "AS", "CT", "RS", "RR", "TIAS")
    pub bwtype: String,
    /// Bandwidth value
    ///
    /// - For AS, CT: kilobits per second (kbps)
    /// - For RS, RR, TIAS: bits per second (bps)
    pub bandwidth: u64,
}

impl Bandwidth {
    /// Creates a new bandwidth specification.
    pub fn new(bwtype: impl Into<String>, bandwidth: u64) -> Self {
        Bandwidth {
            bwtype: bwtype.into(),
            bandwidth,
        }
    }

    /// Creates a bandwidth specification for Application Specific maximum (RFC 4566).
    ///
    /// Value is in kilobits per second.
    pub fn application_specific(kbps: u64) -> Self {
        Bandwidth::new("AS", kbps)
    }

    /// Creates a bandwidth specification for Conference Total (RFC 4566).
    ///
    /// Value is in kilobits per second.
    pub fn conference_total(kbps: u64) -> Self {
        Bandwidth::new("CT", kbps)
    }

    /// Creates a bandwidth specification for RTCP senders (RFC 3556).
    ///
    /// Value is in bits per second (not kilobits).
    pub fn rtcp_senders(bps: u64) -> Self {
        Bandwidth::new("RS", bps)
    }

    /// Creates a bandwidth specification for RTCP receivers (RFC 3556).
    ///
    /// Value is in bits per second (not kilobits).
    pub fn rtcp_receivers(bps: u64) -> Self {
        Bandwidth::new("RR", bps)
    }

    /// Creates a bandwidth specification for Transport Independent Application Specific (RFC 3890).
    ///
    /// Value is in bits per second (not kilobits). TIAS specifies application bandwidth
    /// excluding transport overhead (IP/UDP/TCP headers).
    pub fn tias(bps: u64) -> Self {
        Bandwidth::new("TIAS", bps)
    }

    /// Returns the parsed bandwidth type.
    pub fn bandwidth_type(&self) -> BandwidthType {
        BandwidthType::parse(&self.bwtype)
    }

    /// Returns true if this is an RTCP bandwidth modifier (RS or RR).
    pub fn is_rtcp(&self) -> bool {
        self.bandwidth_type().is_rtcp()
    }
}

/// Timing line (t=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    pub start_time: u64,
    pub stop_time: u64,
}

/// Repeat time line (r=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatTime {
    pub repeat_interval: String,
    pub active_duration: String,
    pub offsets: Vec<String>,
}

/// Time zone adjustment (z=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeZone {
    pub adjustment_time: u64,
    pub offset: String,
}

/// Encryption key (k=) components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey {
    pub method: String,
    pub key: Option<String>,
}

/// Generic attribute (a=).
///
/// Attributes come in two forms:
/// - Property: `a=recvonly` (no value)
/// - Value: `a=rtpmap:99 h263/90000` (has value)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
}

/// Media description (m=) with associated fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDescription {
    /// Media type (audio, video, text, application, message)
    pub media: String,
    /// Transport port
    pub port: u16,
    /// Number of ports (for m=video 49170/2)
    pub port_count: Option<u16>,
    /// Transport protocol (RTP/AVP, RTP/SAVP, udp, etc.)
    pub proto: String,
    /// Format list (payload types for RTP, etc.)
    pub fmt: Vec<String>,

    // Media-level optional fields
    /// Media title (i=)
    pub title: Option<String>,
    /// Connection information (c=)
    pub connection: Option<Connection>,
    /// Bandwidth information (b=, multiple allowed)
    pub bandwidth: Vec<Bandwidth>,
    /// Encryption key (k=)
    pub encryption_key: Option<EncryptionKey>,
    /// Media-level attributes (a=)
    pub attributes: Vec<Attribute>,
    /// Media identification tag (a=mid:, RFC 3388)
    pub mid: Option<String>,
    /// RTCP port and address (a=rtcp:, RFC 3605)
    pub rtcp: Option<RtcpAttribute>,
    /// Capability set (a=sqn/cdsc/cpar, RFC 3407)
    pub capability_set: Option<SdpCapabilitySet>,
}

/// Direction attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sendrecv" => Some(Direction::SendRecv),
            "sendonly" => Some(Direction::SendOnly),
            "recvonly" => Some(Direction::RecvOnly),
            "inactive" => Some(Direction::Inactive),
            _ => None,
        }
    }
}

/// RTCP attribute (a=rtcp:, RFC 3605).
///
/// Specifies the port and optional address for RTCP traffic when it differs
/// from the default (RTP port + 1). Commonly used in NAT traversal scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpAttribute {
    /// RTCP port number
    pub port: u16,
    /// Network type (e.g., "IN"), optional
    pub nettype: Option<String>,
    /// Address type (e.g., "IP4", "IP6"), optional
    pub addrtype: Option<String>,
    /// Connection address, optional
    pub connection_address: Option<String>,
}

impl RtcpAttribute {
    /// Creates a new RTCP attribute with just a port.
    pub fn new(port: u16) -> Self {
        RtcpAttribute {
            port,
            nettype: None,
            addrtype: None,
            connection_address: None,
        }
    }

    /// Creates a new RTCP attribute with full address information.
    pub fn with_address(
        port: u16,
        nettype: String,
        addrtype: String,
        connection_address: String,
    ) -> Self {
        RtcpAttribute {
            port,
            nettype: Some(nettype),
            addrtype: Some(addrtype),
            connection_address: Some(connection_address),
        }
    }

    /// Parses an RTCP attribute value.
    ///
    /// Format: <port> [<nettype> <addrtype> <connection-address>]
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();

        if parts.is_empty() {
            return Err(SdpError::InvalidFormat("a=rtcp requires port"));
        }

        let port = parts[0]
            .parse::<u16>()
            .map_err(|_| SdpError::InvalidFormat("Invalid RTCP port"))?;

        if parts.len() == 1 {
            Ok(RtcpAttribute::new(port))
        } else if parts.len() == 4 {
            Ok(RtcpAttribute::with_address(
                port,
                parts[1].to_string(),
                parts[2].to_string(),
                parts[3].to_string(),
            ))
        } else {
            Err(SdpError::InvalidFormat(
                "a=rtcp must have either 1 or 4 components",
            ))
        }
    }

    /// Converts the RTCP attribute to its SDP string representation.
    pub fn to_string(&self) -> String {
        if let (Some(nettype), Some(addrtype), Some(addr)) =
            (&self.nettype, &self.addrtype, &self.connection_address)
        {
            format!("{} {} {} {}", self.port, nettype, addrtype, addr)
        } else {
            self.port.to_string()
        }
    }
}

/// RTP map attribute (a=rtpmap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpMap {
    pub payload_type: u8,
    pub encoding_name: String,
    pub clock_rate: u32,
    pub encoding_params: Option<String>,
}

/// Format parameters attribute (a=fmtp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fmtp {
    pub format: String,
    pub params: String,
}

/// Group semantics for media line grouping (RFC 3388, RFC 3524).
///
/// Defines the relationship type between grouped media streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupSemantics {
    /// Lip Synchronization - streams must be synchronized for playout (RFC 3388)
    LS,
    /// Flow Identification - multiple lines represent alternatives for single logical flow (RFC 3388)
    FID,
    /// Single Reservation Flow - streams mapped to same resource reservation flow (RFC 3524)
    SRF,
    /// Other semantics (extensible for future IANA-registered types)
    Other(String),
}

impl GroupSemantics {
    pub fn as_str(&self) -> &str {
        match self {
            GroupSemantics::LS => "LS",
            GroupSemantics::FID => "FID",
            GroupSemantics::SRF => "SRF",
            GroupSemantics::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "LS" => GroupSemantics::LS,
            "FID" => GroupSemantics::FID,
            "SRF" => GroupSemantics::SRF,
            _ => GroupSemantics::Other(s.to_string()),
        }
    }
}

impl fmt::Display for GroupSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Media group (a=group:) for grouping media lines (RFC 3388).
///
/// Groups media streams to express relationships like synchronization
/// or alternatives.
///
/// Format: a=group:<semantics> <mid1> <mid2> ...
/// Example: a=group:LS 1 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaGroup {
    /// Semantics of the group (LS, FID, etc.)
    pub semantics: GroupSemantics,
    /// Media identification tags (references to a=mid: values)
    pub mids: Vec<String>,
}

impl MediaGroup {
    /// Parses a media group from the attribute value.
    ///
    /// Expected format: "<semantics> <mid1> <mid2> ..."
    /// Example: "LS 1 2"
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.is_empty() {
            return Err(SdpError::InvalidFormat("a=group"));
        }

        let semantics = GroupSemantics::parse(parts[0]);
        let mids: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        if mids.is_empty() {
            return Err(SdpError::InvalidSyntax(
                "a=group must have at least one mid".to_string(),
            ));
        }

        Ok(MediaGroup { semantics, mids })
    }
}

impl fmt::Display for MediaGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.semantics)?;
        for mid in &self.mids {
            write!(f, " {}", mid)?;
        }
        Ok(())
    }
}

/// Capability description (a=cdsc:) for declaring media capabilities (RFC 3407).
///
/// Describes media formats an endpoint can support without committing to use them.
/// Similar structure to m= line but represents potential rather than actual session.
///
/// Format: a=cdsc:<cap-num> <media> <transport> <fmt list>
/// Example: a=cdsc:1 audio RTP/AVP 0 18
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescription {
    /// Capability number (1-255, increments by format count)
    pub cap_num: u8,
    /// Media type (audio, video, etc.)
    pub media: String,
    /// Transport protocol
    pub transport: String,
    /// Format list (payload types, etc.)
    pub formats: Vec<String>,
}

impl CapabilityDescription {
    /// Parses a capability description from the attribute value.
    ///
    /// Expected format: "<cap-num> <media> <transport> <fmt> [<fmt>...]"
    /// Example: "1 audio RTP/AVP 0 18"
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(SdpError::InvalidFormat("a=cdsc"));
        }

        let cap_num = parts[0]
            .parse::<u8>()
            .map_err(|_| SdpError::InvalidFormat("a=cdsc cap-num"))?;
        let media = parts[1].to_string();
        let transport = parts[2].to_string();
        let formats: Vec<String> = parts[3..].iter().map(|s| s.to_string()).collect();

        Ok(CapabilityDescription {
            cap_num,
            media,
            transport,
            formats,
        })
    }
}

impl fmt::Display for CapabilityDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.cap_num, self.media, self.transport)?;
        for fmt in &self.formats {
            write!(f, " {}", fmt)?;
        }
        Ok(())
    }
}

/// Capability parameter type (RFC 3407).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityParameterType {
    /// General parameter (a=cpar:)
    General,
    /// Minimum value constraint (a=cparmin:)
    Min,
    /// Maximum value constraint (a=cparmax:)
    Max,
}

impl CapabilityParameterType {
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityParameterType::General => "cpar",
            CapabilityParameterType::Min => "cparmin",
            CapabilityParameterType::Max => "cparmax",
        }
    }
}

/// Capability parameter (a=cpar/cparmin/cparmax:) (RFC 3407).
///
/// Parameters associated with capability descriptions.
/// Can specify bandwidth, fmtp values, or other SDP attributes.
///
/// Format: a=cpar:<parameters> or a=cparmin:<parameters> or a=cparmax:<parameters>
/// Example: a=cpar:a=fmtp:96 0-16,32-35
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityParameter {
    /// Parameter type (general, min, or max)
    pub param_type: CapabilityParameterType,
    /// Parameter content (e.g., "a=fmtp:96 0-16,32-35")
    pub value: String,
}

impl CapabilityParameter {
    pub fn parse(param_type: CapabilityParameterType, value: &str) -> Self {
        CapabilityParameter {
            param_type,
            value: value.to_string(),
        }
    }
}

impl fmt::Display for CapabilityParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Capability set (RFC 3407).
///
/// A collection of capability descriptions with sequence number for versioning.
/// Represents what an endpoint can support without committing to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpCapabilitySet {
    /// Sequence number (0-255, increments modulo 256)
    pub sequence_number: u8,
    /// Capability descriptions
    pub descriptions: Vec<CapabilityDescription>,
    /// Capability parameters
    pub parameters: Vec<CapabilityParameter>,
}

impl SdpCapabilitySet {
    pub fn new(sequence_number: u8) -> Self {
        SdpCapabilitySet {
            sequence_number,
            descriptions: Vec::new(),
            parameters: Vec::new(),
        }
    }
}

/// Precondition type (RFC 3312).
///
/// Defines the type of precondition to be met before session establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreconditionType {
    /// Quality of Service precondition
    Qos,
    /// Other precondition types (extensible)
    Other(String),
}

impl PreconditionType {
    pub fn as_str(&self) -> &str {
        match self {
            PreconditionType::Qos => "qos",
            PreconditionType::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "qos" => PreconditionType::Qos,
            _ => PreconditionType::Other(s.to_string()),
        }
    }
}

impl fmt::Display for PreconditionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Strength tag for desired preconditions (RFC 3312).
///
/// Indicates how strictly the precondition must be enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthTag {
    /// Resources must be reserved; session establishment fails otherwise
    Mandatory,
    /// User agents should attempt reservation but may proceed without it
    Optional,
    /// No reservation needed
    None,
    /// Indicates rejection due to unmet preconditions
    Failure,
    /// Signals rejection due to unsupported precondition types
    Unknown,
}

impl StrengthTag {
    pub fn as_str(self) -> &'static str {
        match self {
            StrengthTag::Mandatory => "mandatory",
            StrengthTag::Optional => "optional",
            StrengthTag::None => "none",
            StrengthTag::Failure => "failure",
            StrengthTag::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mandatory" => Some(StrengthTag::Mandatory),
            "optional" => Some(StrengthTag::Optional),
            "none" => Some(StrengthTag::None),
            "failure" => Some(StrengthTag::Failure),
            "unknown" => Some(StrengthTag::Unknown),
            _ => None,
        }
    }
}

impl fmt::Display for StrengthTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Status type for preconditions (RFC 3312).
///
/// Indicates whether the status applies to end-to-end path,
/// local access network, or remote access network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusType {
    /// End-to-end (entire path)
    E2E,
    /// Local access network
    Local,
    /// Remote access network
    Remote,
}

impl StatusType {
    pub fn as_str(self) -> &'static str {
        match self {
            StatusType::E2E => "e2e",
            StatusType::Local => "local",
            StatusType::Remote => "remote",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "e2e" => Some(StatusType::E2E),
            "local" => Some(StatusType::Local),
            "remote" => Some(StatusType::Remote),
            _ => None,
        }
    }

    /// Inverts the status type for offer/answer (local <-> remote).
    pub fn invert(self) -> Self {
        match self {
            StatusType::E2E => StatusType::E2E,
            StatusType::Local => StatusType::Remote,
            StatusType::Remote => StatusType::Local,
        }
    }
}

impl fmt::Display for StatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Direction for preconditions (RFC 3312).
///
/// Similar to media direction but used in precondition context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionDirection {
    /// Send direction
    Send,
    /// Receive direction
    Recv,
    /// Both send and receive
    SendRecv,
    /// No direction
    None,
}

impl PreconditionDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            PreconditionDirection::Send => "send",
            PreconditionDirection::Recv => "recv",
            PreconditionDirection::SendRecv => "sendrecv",
            PreconditionDirection::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "send" => Some(PreconditionDirection::Send),
            "recv" => Some(PreconditionDirection::Recv),
            "sendrecv" => Some(PreconditionDirection::SendRecv),
            "none" => Some(PreconditionDirection::None),
            _ => None,
        }
    }

    /// Inverts the direction for offer/answer (send <-> recv).
    pub fn invert(self) -> Self {
        match self {
            PreconditionDirection::Send => PreconditionDirection::Recv,
            PreconditionDirection::Recv => PreconditionDirection::Send,
            PreconditionDirection::SendRecv => PreconditionDirection::SendRecv,
            PreconditionDirection::None => PreconditionDirection::None,
        }
    }
}

impl fmt::Display for PreconditionDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Current status attribute (a=curr:) (RFC 3312).
///
/// Reflects the actual reservation state of network resources
/// for a media stream in a given direction.
///
/// Format: a=curr:<precondition-type> <status-type> <direction>
/// Example: a=curr:qos e2e sendrecv
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentStatus {
    pub precondition_type: PreconditionType,
    pub status_type: StatusType,
    pub direction: PreconditionDirection,
}

impl CurrentStatus {
    /// Parses a current status from the attribute value.
    ///
    /// Expected format: "<precondition-type> <status-type> <direction>"
    /// Example: "qos e2e sendrecv"
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(SdpError::InvalidFormat("a=curr"));
        }

        let precondition_type = PreconditionType::parse(parts[0]);
        let status_type = StatusType::parse(parts[1])
            .ok_or_else(|| SdpError::InvalidFormat("a=curr status-type"))?;
        let direction = PreconditionDirection::parse(parts[2])
            .ok_or_else(|| SdpError::InvalidFormat("a=curr direction"))?;

        Ok(CurrentStatus {
            precondition_type,
            status_type,
            direction,
        })
    }
}

impl fmt::Display for CurrentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.precondition_type, self.status_type, self.direction
        )
    }
}

/// Desired status attribute (a=des:) (RFC 3312).
///
/// Specifies the preconditions required for session establishment.
/// Session proceeds only when current status meets or exceeds the desired threshold.
///
/// Format: a=des:<precondition-type> <strength-tag> <status-type> <direction>
/// Example: a=des:qos mandatory e2e sendrecv
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredStatus {
    pub precondition_type: PreconditionType,
    pub strength: StrengthTag,
    pub status_type: StatusType,
    pub direction: PreconditionDirection,
}

impl DesiredStatus {
    /// Parses a desired status from the attribute value.
    ///
    /// Expected format: "<precondition-type> <strength-tag> <status-type> <direction>"
    /// Example: "qos mandatory e2e sendrecv"
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 4 {
            return Err(SdpError::InvalidFormat("a=des"));
        }

        let precondition_type = PreconditionType::parse(parts[0]);
        let strength = StrengthTag::parse(parts[1])
            .ok_or_else(|| SdpError::InvalidFormat("a=des strength-tag"))?;
        let status_type = StatusType::parse(parts[2])
            .ok_or_else(|| SdpError::InvalidFormat("a=des status-type"))?;
        let direction = PreconditionDirection::parse(parts[3])
            .ok_or_else(|| SdpError::InvalidFormat("a=des direction"))?;

        Ok(DesiredStatus {
            precondition_type,
            strength,
            status_type,
            direction,
        })
    }
}

impl fmt::Display for DesiredStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.precondition_type, self.strength, self.status_type, self.direction
        )
    }
}

/// Confirm status attribute (a=conf:) (RFC 3312).
///
/// Indicates threshold conditions triggering peer notifications.
/// When thresholds are reached, the peer must send updated status.
///
/// Format: a=conf:<precondition-type> <status-type> <direction>
/// Example: a=conf:qos e2e recv
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmStatus {
    pub precondition_type: PreconditionType,
    pub status_type: StatusType,
    pub direction: PreconditionDirection,
}

impl ConfirmStatus {
    /// Parses a confirm status from the attribute value.
    ///
    /// Expected format: "<precondition-type> <status-type> <direction>"
    /// Example: "qos e2e recv"
    pub fn parse(value: &str) -> Result<Self, SdpError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(SdpError::InvalidFormat("a=conf"));
        }

        let precondition_type = PreconditionType::parse(parts[0]);
        let status_type = StatusType::parse(parts[1])
            .ok_or_else(|| SdpError::InvalidFormat("a=conf status-type"))?;
        let direction = PreconditionDirection::parse(parts[2])
            .ok_or_else(|| SdpError::InvalidFormat("a=conf direction"))?;

        Ok(ConfirmStatus {
            precondition_type,
            status_type,
            direction,
        })
    }
}

impl fmt::Display for ConfirmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.precondition_type, self.status_type, self.direction
        )
    }
}

impl SdpSession {
    /// Creates a new SDP session with required fields.
    pub fn new(origin: Origin, session_name: String) -> Self {
        Self {
            version: 0,
            origin,
            session_name,
            session_info: None,
            uri: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            bandwidth: Vec::new(),
            timing: vec![Timing {
                start_time: 0,
                stop_time: 0,
            }],
            repeat_times: Vec::new(),
            time_zones: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            groups: Vec::new(),
            capability_set: None,
            media: Vec::new(),
        }
    }

    /// Parses an SDP session description from a string.
    pub fn parse(input: &str) -> Result<Self, SdpError> {
        let lines: Vec<&str> = input
            .lines()
            .map(|line| line.trim_end_matches('\r'))
            .filter(|line| !line.is_empty())
            .collect();

        if lines.is_empty() {
            return Err(SdpError::MissingRequiredField("v="));
        }

        let mut session = Self {
            version: 0,
            origin: Origin {
                username: String::new(),
                sess_id: String::new(),
                sess_version: String::new(),
                nettype: String::new(),
                addrtype: String::new(),
                unicast_address: String::new(),
            },
            session_name: String::new(),
            session_info: None,
            uri: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            bandwidth: Vec::new(),
            timing: Vec::new(),
            repeat_times: Vec::new(),
            time_zones: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            groups: Vec::new(),
            capability_set: None,
            media: Vec::new(),
        };

        let mut idx = 0;

        // Parse session-level fields
        idx = session.parse_session_level(&lines, idx)?;

        // Parse media descriptions
        while idx < lines.len() {
            let media = MediaDescription::parse(&lines, &mut idx)?;
            session.media.push(media);
        }

        // Extract groups and mids from attributes (RFC 3388)
        session.extract_groups_and_mids()?;

        // Extract capability sets from attributes (RFC 3407)
        session.extract_capabilities()?;

        // Extract RTCP attributes from media (RFC 3605)
        session.extract_rtcp()?;

        // Validate
        session.validate()?;

        Ok(session)
    }

    fn parse_session_level(&mut self, lines: &[&str], mut idx: usize) -> Result<usize, SdpError> {
        // v= (required, must be first)
        if idx >= lines.len() || !lines[idx].starts_with("v=") {
            return Err(SdpError::MissingRequiredField("v="));
        }
        self.version = parse_version(lines[idx])?;
        idx += 1;

        // o= (required)
        if idx >= lines.len() || !lines[idx].starts_with("o=") {
            return Err(SdpError::MissingRequiredField("o="));
        }
        self.origin = parse_origin(lines[idx])?;
        idx += 1;

        // s= (required)
        if idx >= lines.len() || !lines[idx].starts_with("s=") {
            return Err(SdpError::MissingRequiredField("s="));
        }
        self.session_name = lines[idx][2..].to_string();
        idx += 1;

        // Optional fields in order
        while idx < lines.len() && !lines[idx].starts_with("m=") {
            let line = lines[idx];
            if line.len() < 2 || line.chars().nth(1) != Some('=') {
                return Err(SdpError::InvalidSyntax(format!("Invalid line: {}", line)));
            }

            // Safety: We know line.len() >= 2 from check above, so next() must return Some
            let Some(field_type) = line.chars().next() else {
                return Err(SdpError::InvalidSyntax(format!("Empty line")));
            };
            match field_type {
                'i' => self.session_info = Some(line[2..].to_string()),
                'u' => self.uri = Some(line[2..].to_string()),
                'e' => self.emails.push(line[2..].to_string()),
                'p' => self.phones.push(line[2..].to_string()),
                'c' => self.connection = Some(parse_connection(line)?),
                'b' => self.bandwidth.push(parse_bandwidth(line)?),
                't' => {
                    self.timing.push(parse_timing(line)?);
                    // Check for following r= lines
                    while idx + 1 < lines.len() && lines[idx + 1].starts_with("r=") {
                        idx += 1;
                        self.repeat_times.push(parse_repeat_time(lines[idx])?);
                    }
                }
                'r' => return Err(SdpError::InvalidOrder("r= must follow t= line".to_string())),
                'z' => {
                    let zones = parse_time_zones(line)?;
                    self.time_zones.extend(zones);
                }
                'k' => self.encryption_key = Some(parse_encryption_key(line)?),
                'a' => self.attributes.push(parse_attribute(line)?),
                _ => {
                    // Unknown field - ignore per RFC 4566
                }
            }
            idx += 1;
        }

        Ok(idx)
    }

    /// Extracts group and mid attributes from the parsed attributes (RFC 3388).
    ///
    /// This method processes session-level a=group: attributes and media-level
    /// a=mid: attributes, moving them from the generic attributes vectors to
    /// the dedicated groups and mid fields.
    fn extract_groups_and_mids(&mut self) -> Result<(), SdpError> {
        // Extract session-level group attributes
        let mut remaining_attrs = Vec::new();
        for attr in self.attributes.drain(..) {
            if attr.name == "group" {
                if let Some(value) = &attr.value {
                    match MediaGroup::parse(value) {
                        Ok(group) => self.groups.push(group),
                        Err(e) => return Err(e),
                    }
                } else {
                    return Err(SdpError::InvalidFormat("a=group requires value"));
                }
            } else {
                remaining_attrs.push(attr);
            }
        }
        self.attributes = remaining_attrs;

        // Extract media-level mid attributes
        for media in &mut self.media {
            let mut remaining_attrs = Vec::new();
            for attr in media.attributes.drain(..) {
                if attr.name == "mid" {
                    if let Some(value) = &attr.value {
                        media.mid = Some(value.clone());
                    } else {
                        return Err(SdpError::InvalidFormat("a=mid requires value"));
                    }
                } else {
                    remaining_attrs.push(attr);
                }
            }
            media.attributes = remaining_attrs;
        }

        Ok(())
    }

    /// Extracts capability attributes from the parsed attributes (RFC 3407).
    ///
    /// This method processes session-level and media-level capability attributes
    /// (sqn, cdsc, cpar, cparmin, cparmax), moving them from the generic
    /// attributes vectors to the dedicated capability_set fields.
    fn extract_capabilities(&mut self) -> Result<(), SdpError> {
        // Extract session-level capabilities
        self.capability_set = Self::extract_capability_set_from_attributes(&mut self.attributes)?;

        // Extract media-level capabilities
        for media in &mut self.media {
            media.capability_set =
                Self::extract_capability_set_from_attributes(&mut media.attributes)?;
        }

        Ok(())
    }

    /// Extracts RTCP attributes from media-level attributes (RFC 3605).
    ///
    /// This method processes media-level a=rtcp: attributes, moving them from
    /// the generic attributes vectors to the dedicated rtcp field.
    fn extract_rtcp(&mut self) -> Result<(), SdpError> {
        for media in &mut self.media {
            let mut remaining_attrs = Vec::new();
            for attr in media.attributes.drain(..) {
                if attr.name == "rtcp" {
                    if let Some(value) = &attr.value {
                        media.rtcp = Some(RtcpAttribute::parse(value)?);
                    } else {
                        return Err(SdpError::InvalidFormat("a=rtcp requires value"));
                    }
                } else {
                    remaining_attrs.push(attr);
                }
            }
            media.attributes = remaining_attrs;
        }

        Ok(())
    }

    /// Extracts a capability set from a list of attributes.
    fn extract_capability_set_from_attributes(
        attributes: &mut Vec<Attribute>,
    ) -> Result<Option<SdpCapabilitySet>, SdpError> {
        let mut sqn: Option<u8> = None;
        let mut descriptions = Vec::new();
        let mut parameters = Vec::new();
        let mut remaining_attrs = Vec::new();

        for attr in attributes.drain(..) {
            match attr.name.as_str() {
                "sqn" => {
                    if let Some(value) = &attr.value {
                        sqn = Some(
                            value
                                .parse::<u8>()
                                .map_err(|_| SdpError::InvalidFormat("a=sqn"))?,
                        );
                    } else {
                        return Err(SdpError::InvalidFormat("a=sqn requires value"));
                    }
                }
                "cdsc" => {
                    if let Some(value) = &attr.value {
                        descriptions.push(CapabilityDescription::parse(value)?);
                    } else {
                        return Err(SdpError::InvalidFormat("a=cdsc requires value"));
                    }
                }
                "cpar" => {
                    if let Some(value) = &attr.value {
                        parameters.push(CapabilityParameter::parse(
                            CapabilityParameterType::General,
                            value,
                        ));
                    } else {
                        return Err(SdpError::InvalidFormat("a=cpar requires value"));
                    }
                }
                "cparmin" => {
                    if let Some(value) = &attr.value {
                        parameters.push(CapabilityParameter::parse(
                            CapabilityParameterType::Min,
                            value,
                        ));
                    } else {
                        return Err(SdpError::InvalidFormat("a=cparmin requires value"));
                    }
                }
                "cparmax" => {
                    if let Some(value) = &attr.value {
                        parameters.push(CapabilityParameter::parse(
                            CapabilityParameterType::Max,
                            value,
                        ));
                    } else {
                        return Err(SdpError::InvalidFormat("a=cparmax requires value"));
                    }
                }
                _ => remaining_attrs.push(attr),
            }
        }

        *attributes = remaining_attrs;

        // If we found capability attributes, create a capability set
        if let Some(sequence_number) = sqn {
            Ok(Some(SdpCapabilitySet {
                sequence_number,
                descriptions,
                parameters,
            }))
        } else if !descriptions.is_empty() || !parameters.is_empty() {
            // Has capability descriptions but no sqn - error
            Err(SdpError::InvalidSyntax(
                "Capability descriptions require a=sqn".to_string(),
            ))
        } else {
            Ok(None)
        }
    }

    fn validate(&self) -> Result<(), SdpError> {
        // Must have at least one timing line
        if self.timing.is_empty() {
            return Err(SdpError::MissingRequiredField("t="));
        }

        // Must have connection at session or in all media
        if self.connection.is_none() {
            for media in &self.media {
                if media.connection.is_none() {
                    return Err(SdpError::MissingRequiredField("c= (session or all media)"));
                }
            }
        }

        Ok(())
    }

    /// Finds a direction attribute in session or media attributes.
    pub fn find_direction(&self, media_idx: Option<usize>) -> Option<Direction> {
        let attrs = if let Some(idx) = media_idx {
            &self.media.get(idx)?.attributes
        } else {
            &self.attributes
        };

        for attr in attrs {
            if attr.value.is_none() {
                if let Some(dir) = Direction::parse(&attr.name) {
                    return Some(dir);
                }
            }
        }
        None
    }

    /// Finds all rtpmap attributes in a media description.
    pub fn find_rtpmaps(&self, media_idx: usize) -> Vec<RtpMap> {
        let media = match self.media.get(media_idx) {
            Some(m) => m,
            None => return Vec::new(),
        };

        media
            .attributes
            .iter()
            .filter_map(|attr| {
                if attr.name == "rtpmap" {
                    attr.value.as_ref().and_then(|v| RtpMap::parse(v))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Finds all fmtp attributes in a media description.
    pub fn find_fmtps(&self, media_idx: usize) -> Vec<Fmtp> {
        let media = match self.media.get(media_idx) {
            Some(m) => m,
            None => return Vec::new(),
        };

        media
            .attributes
            .iter()
            .filter_map(|attr| {
                if attr.name == "fmtp" {
                    attr.value.as_ref().and_then(|v| Fmtp::parse(v))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Finds all current status (a=curr:) attributes in a media description (RFC 3312).
    pub fn find_current_status(&self, media_idx: usize) -> Vec<CurrentStatus> {
        let media = match self.media.get(media_idx) {
            Some(m) => m,
            None => return Vec::new(),
        };

        media
            .attributes
            .iter()
            .filter_map(|attr| {
                if attr.name == "curr" {
                    attr.value
                        .as_ref()
                        .and_then(|v| CurrentStatus::parse(v).ok())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Finds all desired status (a=des:) attributes in a media description (RFC 3312).
    pub fn find_desired_status(&self, media_idx: usize) -> Vec<DesiredStatus> {
        let media = match self.media.get(media_idx) {
            Some(m) => m,
            None => return Vec::new(),
        };

        media
            .attributes
            .iter()
            .filter_map(|attr| {
                if attr.name == "des" {
                    attr.value
                        .as_ref()
                        .and_then(|v| DesiredStatus::parse(v).ok())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Finds all confirm status (a=conf:) attributes in a media description (RFC 3312).
    pub fn find_confirm_status(&self, media_idx: usize) -> Vec<ConfirmStatus> {
        let media = match self.media.get(media_idx) {
            Some(m) => m,
            None => return Vec::new(),
        };

        media
            .attributes
            .iter()
            .filter_map(|attr| {
                if attr.name == "conf" {
                    attr.value
                        .as_ref()
                        .and_then(|v| ConfirmStatus::parse(v).ok())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Checks if all mandatory preconditions are met for a media stream (RFC 3312).
    ///
    /// Returns true if for each mandatory desired status, there exists a matching
    /// current status that meets or exceeds the desired direction.
    pub fn are_preconditions_met(&self, media_idx: usize) -> bool {
        let desired = self.find_desired_status(media_idx);
        let current = self.find_current_status(media_idx);

        // No desired preconditions means preconditions are met
        if desired.is_empty() {
            return true;
        }

        // Check each mandatory desired precondition
        for des in &desired {
            // Skip non-mandatory preconditions
            if !matches!(des.strength, StrengthTag::Mandatory) {
                continue;
            }

            // Find matching current status
            let matching_curr = current.iter().find(|curr| {
                curr.precondition_type == des.precondition_type
                    && curr.status_type == des.status_type
            });

            match matching_curr {
                Some(curr) => {
                    // Check if current direction meets desired direction
                    if !direction_meets_requirement(curr.direction, des.direction) {
                        return false;
                    }
                }
                None => {
                    // No matching current status means precondition not met
                    return false;
                }
            }
        }

        true
    }
}

/// Checks if a current direction meets the desired direction requirement.
fn direction_meets_requirement(
    current: PreconditionDirection,
    desired: PreconditionDirection,
) -> bool {
    match desired {
        PreconditionDirection::None => true,
        PreconditionDirection::Send => matches!(
            current,
            PreconditionDirection::Send | PreconditionDirection::SendRecv
        ),
        PreconditionDirection::Recv => matches!(
            current,
            PreconditionDirection::Recv | PreconditionDirection::SendRecv
        ),
        PreconditionDirection::SendRecv => {
            matches!(current, PreconditionDirection::SendRecv)
        }
    }
}

impl fmt::Display for SdpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Session-level fields (in required order)
        writeln!(f, "v={}", self.version)?;
        writeln!(f, "{}", self.origin)?;
        writeln!(f, "s={}", self.session_name)?;

        if let Some(ref info) = self.session_info {
            writeln!(f, "i={}", info)?;
        }
        if let Some(ref uri) = self.uri {
            writeln!(f, "u={}", uri)?;
        }
        for email in &self.emails {
            writeln!(f, "e={}", email)?;
        }
        for phone in &self.phones {
            writeln!(f, "p={}", phone)?;
        }
        if let Some(ref conn) = self.connection {
            writeln!(f, "{}", conn)?;
        }
        for bw in &self.bandwidth {
            writeln!(f, "{}", bw)?;
        }
        for timing in &self.timing {
            writeln!(f, "{}", timing)?;
        }
        for repeat in &self.repeat_times {
            writeln!(f, "{}", repeat)?;
        }
        if !self.time_zones.is_empty() {
            write!(f, "z=")?;
            for (i, tz) in self.time_zones.iter().enumerate() {
                if i > 0 {
                    write!(f, " ")?;
                }
                write!(f, "{} {}", tz.adjustment_time, tz.offset)?;
            }
            writeln!(f)?;
        }
        if let Some(ref key) = self.encryption_key {
            writeln!(f, "{}", key)?;
        }
        for attr in &self.attributes {
            writeln!(f, "{}", attr)?;
        }
        // Write capability set (RFC 3407)
        if let Some(ref cap_set) = self.capability_set {
            writeln!(f, "a=sqn:{}", cap_set.sequence_number)?;
            for cdsc in &cap_set.descriptions {
                writeln!(f, "a=cdsc:{}", cdsc)?;
            }
            for cpar in &cap_set.parameters {
                writeln!(f, "a={}:{}", cpar.param_type.as_str(), cpar)?;
            }
        }
        // Write group attributes (RFC 3388)
        for group in &self.groups {
            writeln!(f, "a=group:{}", group)?;
        }

        // Media descriptions
        for media in &self.media {
            write!(f, "{}", media)?;
        }

        Ok(())
    }
}

impl MediaDescription {
    fn parse(lines: &[&str], idx: &mut usize) -> Result<Self, SdpError> {
        if *idx >= lines.len() || !lines[*idx].starts_with("m=") {
            return Err(SdpError::MissingRequiredField("m="));
        }

        let m_line = lines[*idx];
        *idx += 1;

        let (media, port, port_count, proto, fmt) = parse_media_line(m_line)?;

        let mut desc = MediaDescription {
            media,
            port,
            port_count,
            proto,
            fmt,
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: None,
            capability_set: None,
        };

        // Parse media-level fields
        while *idx < lines.len() && !lines[*idx].starts_with("m=") {
            let line = lines[*idx];
            if line.len() < 2 || line.chars().nth(1) != Some('=') {
                return Err(SdpError::InvalidSyntax(format!("Invalid line: {}", line)));
            }

            // Safety: We know line.len() >= 2 from check above, so next() must return Some
            let Some(field_type) = line.chars().next() else {
                return Err(SdpError::InvalidSyntax(format!("Empty line")));
            };
            match field_type {
                'i' => desc.title = Some(line[2..].to_string()),
                'c' => desc.connection = Some(parse_connection(line)?),
                'b' => desc.bandwidth.push(parse_bandwidth(line)?),
                'k' => desc.encryption_key = Some(parse_encryption_key(line)?),
                'a' => desc.attributes.push(parse_attribute(line)?),
                _ => {
                    // Unknown or out-of-order field
                    return Err(SdpError::InvalidOrder(format!(
                        "Unexpected field in media: {}",
                        field_type
                    )));
                }
            }
            *idx += 1;
        }

        Ok(desc)
    }
}

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m={} {}", self.media, self.port)?;
        if let Some(count) = self.port_count {
            write!(f, "/{}", count)?;
        }
        write!(f, " {}", self.proto)?;
        for (i, fmt) in self.fmt.iter().enumerate() {
            if i == 0 {
                write!(f, " {}", fmt)?;
            } else {
                write!(f, " {}", fmt)?;
            }
        }
        writeln!(f)?;

        if let Some(ref title) = self.title {
            writeln!(f, "i={}", title)?;
        }
        if let Some(ref conn) = self.connection {
            writeln!(f, "{}", conn)?;
        }
        for bw in &self.bandwidth {
            writeln!(f, "{}", bw)?;
        }
        if let Some(ref key) = self.encryption_key {
            writeln!(f, "{}", key)?;
        }
        // Write mid attribute (RFC 3388)
        if let Some(ref mid) = self.mid {
            writeln!(f, "a=mid:{}", mid)?;
        }
        // Write rtcp attribute (RFC 3605)
        if let Some(ref rtcp) = self.rtcp {
            writeln!(f, "a=rtcp:{}", rtcp.to_string())?;
        }
        // Write capability set (RFC 3407)
        if let Some(ref cap_set) = self.capability_set {
            writeln!(f, "a=sqn:{}", cap_set.sequence_number)?;
            for cdsc in &cap_set.descriptions {
                writeln!(f, "a=cdsc:{}", cdsc)?;
            }
            for cpar in &cap_set.parameters {
                writeln!(f, "a={}:{}", cpar.param_type.as_str(), cpar)?;
            }
        }
        for attr in &self.attributes {
            writeln!(f, "{}", attr)?;
        }

        Ok(())
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "o={} {} {} {} {} {}",
            self.username,
            self.sess_id,
            self.sess_version,
            self.nettype,
            self.addrtype,
            self.unicast_address
        )
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "c={} {} {}",
            self.nettype, self.addrtype, self.connection_address
        )
    }
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b={}:{}", self.bwtype, self.bandwidth)
    }
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} {}", self.start_time, self.stop_time)
    }
}

impl fmt::Display for RepeatTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r={} {}", self.repeat_interval, self.active_duration)?;
        for offset in &self.offsets {
            write!(f, " {}", offset)?;
        }
        Ok(())
    }
}

impl fmt::Display for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref key) = self.key {
            write!(f, "k={}:{}", self.method, key)
        } else {
            write!(f, "k={}", self.method)
        }
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref value) = self.value {
            write!(f, "a={}:{}", self.name, value)
        } else {
            write!(f, "a={}", self.name)
        }
    }
}

impl RtpMap {
    /// Parses an rtpmap attribute value.
    ///
    /// Format: `<payload> <encoding>/<rate>[/<params>]`
    /// Example: `98 L16/16000/2`
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return None;
        }

        let payload_type = parts[0].parse().ok()?;
        let encoding_parts: Vec<&str> = parts[1].split('/').collect();

        if encoding_parts.len() < 2 {
            return None;
        }

        let encoding_name = encoding_parts[0].to_string();
        let clock_rate = encoding_parts[1].parse().ok()?;
        let encoding_params = encoding_parts.get(2).map(|s| s.to_string());

        Some(RtpMap {
            payload_type,
            encoding_name,
            clock_rate,
            encoding_params,
        })
    }

    /// Formats as attribute value.
    pub fn to_value(&self) -> String {
        if let Some(ref params) = self.encoding_params {
            format!(
                "{} {}/{}/{}",
                self.payload_type, self.encoding_name, self.clock_rate, params
            )
        } else {
            format!(
                "{} {}/{}",
                self.payload_type, self.encoding_name, self.clock_rate
            )
        }
    }
}

impl Fmtp {
    /// Parses an fmtp attribute value.
    ///
    /// Format: `<format> <params>`
    /// Example: `98 profile-level-id=42e01f`
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return None;
        }

        Some(Fmtp {
            format: parts[0].to_string(),
            params: parts[1].to_string(),
        })
    }

    /// Formats as attribute value.
    pub fn to_value(&self) -> String {
        format!("{} {}", self.format, self.params)
    }
}

// Parsing helper functions

fn parse_version(line: &str) -> Result<u32, SdpError> {
    line[2..].parse().map_err(|_| SdpError::InvalidFormat("v="))
}

fn parse_origin(line: &str) -> Result<Origin, SdpError> {
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if parts.len() != 6 {
        return Err(SdpError::InvalidFormat("o="));
    }

    Ok(Origin {
        username: parts[0].to_string(),
        sess_id: parts[1].to_string(),
        sess_version: parts[2].to_string(),
        nettype: parts[3].to_string(),
        addrtype: parts[4].to_string(),
        unicast_address: parts[5].to_string(),
    })
}

fn parse_connection(line: &str) -> Result<Connection, SdpError> {
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if parts.len() != 3 {
        return Err(SdpError::InvalidFormat("c="));
    }

    Ok(Connection {
        nettype: parts[0].to_string(),
        addrtype: parts[1].to_string(),
        connection_address: parts[2].to_string(),
    })
}

fn parse_bandwidth(line: &str) -> Result<Bandwidth, SdpError> {
    let value = &line[2..];
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 2 {
        return Err(SdpError::InvalidFormat("b="));
    }

    let bandwidth = parts[1]
        .parse()
        .map_err(|_| SdpError::InvalidFormat("b="))?;

    Ok(Bandwidth {
        bwtype: parts[0].to_string(),
        bandwidth,
    })
}

fn parse_timing(line: &str) -> Result<Timing, SdpError> {
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if parts.len() != 2 {
        return Err(SdpError::InvalidFormat("t="));
    }

    let start_time = parts[0]
        .parse()
        .map_err(|_| SdpError::InvalidFormat("t="))?;
    let stop_time = parts[1]
        .parse()
        .map_err(|_| SdpError::InvalidFormat("t="))?;

    Ok(Timing {
        start_time,
        stop_time,
    })
}

fn parse_repeat_time(line: &str) -> Result<RepeatTime, SdpError> {
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if parts.len() < 3 {
        return Err(SdpError::InvalidFormat("r="));
    }

    Ok(RepeatTime {
        repeat_interval: parts[0].to_string(),
        active_duration: parts[1].to_string(),
        offsets: parts[2..].iter().map(|s| s.to_string()).collect(),
    })
}

fn parse_time_zones(line: &str) -> Result<Vec<TimeZone>, SdpError> {
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if parts.len() % 2 != 0 {
        return Err(SdpError::InvalidFormat("z="));
    }

    let mut zones = Vec::new();
    for chunk in parts.chunks(2) {
        let adjustment_time = chunk[0]
            .parse()
            .map_err(|_| SdpError::InvalidFormat("z="))?;
        zones.push(TimeZone {
            adjustment_time,
            offset: chunk[1].to_string(),
        });
    }

    Ok(zones)
}

fn parse_encryption_key(line: &str) -> Result<EncryptionKey, SdpError> {
    let value = &line[2..];
    let parts: Vec<&str> = value.splitn(2, ':').collect();

    if parts.len() == 1 {
        Ok(EncryptionKey {
            method: parts[0].to_string(),
            key: None,
        })
    } else {
        Ok(EncryptionKey {
            method: parts[0].to_string(),
            key: Some(parts[1].to_string()),
        })
    }
}

fn parse_attribute(line: &str) -> Result<Attribute, SdpError> {
    let value = &line[2..];
    let parts: Vec<&str> = value.splitn(2, ':').collect();

    if parts.len() == 1 {
        Ok(Attribute {
            name: parts[0].to_string(),
            value: None,
        })
    } else {
        Ok(Attribute {
            name: parts[0].to_string(),
            value: Some(parts[1].to_string()),
        })
    }
}

fn parse_media_line(
    line: &str,
) -> Result<(String, u16, Option<u16>, String, Vec<String>), SdpError> {
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if parts.len() < 4 {
        return Err(SdpError::InvalidFormat("m="));
    }

    let media = parts[0].to_string();

    // Parse port and optional port count
    let port_parts: Vec<&str> = parts[1].split('/').collect();
    let port = port_parts[0]
        .parse()
        .map_err(|_| SdpError::InvalidFormat("m="))?;
    let port_count = if port_parts.len() > 1 {
        Some(
            port_parts[1]
                .parse()
                .map_err(|_| SdpError::InvalidFormat("m="))?,
        )
    } else {
        None
    };

    let proto = parts[2].to_string();
    let fmt = parts[3..].iter().map(|s| s.to_string()).collect();

    Ok((media, port, port_count, proto, fmt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_sdp() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Test Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.version, 0);
        assert_eq!(session.origin.username, "alice");
        assert_eq!(session.session_name, "Test Session");
        assert!(session.connection.is_some());
        assert_eq!(session.timing.len(), 1);
    }

    #[test]
    fn parse_sdp_with_media() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   m=video 51372 RTP/AVP 99\r\n\
                   a=rtpmap:99 h263-1998/90000\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].media, "audio");
        assert_eq!(session.media[0].port, 49170);
        assert_eq!(session.media[1].media, "video");
    }

    #[test]
    fn parse_direction_attributes() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 0.0.0.0\r\n\
                   s=-\r\n\
                   c=IN IP4 0.0.0.0\r\n\
                   t=0 0\r\n\
                   m=audio 9 RTP/AVP 0\r\n\
                   a=sendonly\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let dir = session.find_direction(Some(0)).unwrap();
        assert_eq!(dir, Direction::SendOnly);
    }

    #[test]
    fn parse_rtpmap() {
        let rtpmap = RtpMap::parse("98 L16/16000/2").unwrap();
        assert_eq!(rtpmap.payload_type, 98);
        assert_eq!(rtpmap.encoding_name, "L16");
        assert_eq!(rtpmap.clock_rate, 16000);
        assert_eq!(rtpmap.encoding_params, Some("2".to_string()));
    }

    #[test]
    fn parse_fmtp() {
        let fmtp = Fmtp::parse("98 profile-level-id=42e01f").unwrap();
        assert_eq!(fmtp.format, "98");
        assert_eq!(fmtp.params, "profile-level-id=42e01f");
    }

    #[test]
    fn generate_sdp() {
        let origin = Origin {
            username: "alice".to_string(),
            sess_id: "123".to_string(),
            sess_version: "456".to_string(),
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            unicast_address: "192.0.2.1".to_string(),
        };

        let mut session = SdpSession::new(origin, "Test".to_string());
        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        let sdp_str = session.to_string();
        assert!(sdp_str.contains("v=0"));
        assert!(sdp_str.contains("o=alice"));
        assert!(sdp_str.contains("s=Test"));
        assert!(sdp_str.contains("c=IN IP4 192.0.2.1"));
        assert!(sdp_str.contains("t=0 0"));
    }

    #[test]
    fn round_trip_sdp() {
        let original = "v=0\r\n\
                        o=alice 123 456 IN IP4 192.0.2.1\r\n\
                        s=Session\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(original).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        assert_eq!(session, reparsed);
    }

    // Test all RFC 4566 fields mentioned in requirements

    #[test]
    fn parse_session_info_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session Name\r\n\
                   i=Session Information\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(
            session.session_info,
            Some("Session Information".to_string())
        );
    }

    #[test]
    fn parse_email_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   e=alice@example.com (Alice Smith)\r\n\
                   e=bob@example.com\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.emails.len(), 2);
        assert_eq!(session.emails[0], "alice@example.com (Alice Smith)");
        assert_eq!(session.emails[1], "bob@example.com");
    }

    #[test]
    fn parse_phone_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   p=+1 617 555-6011\r\n\
                   p=+44 20 7946 0958\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.phones.len(), 2);
        assert_eq!(session.phones[0], "+1 617 555-6011");
        assert_eq!(session.phones[1], "+44 20 7946 0958");
    }

    #[test]
    fn parse_bandwidth_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   b=CT:1000\r\n\
                   b=AS:256\r\n\
                   t=0 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.bandwidth.len(), 2);
        assert_eq!(session.bandwidth[0].bwtype, "CT");
        assert_eq!(session.bandwidth[0].bandwidth, 1000);
        assert_eq!(session.bandwidth[1].bwtype, "AS");
        assert_eq!(session.bandwidth[1].bandwidth, 256);
    }

    #[test]
    fn parse_timing_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=2873397496 2873404696\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.timing.len(), 1);
        assert_eq!(session.timing[0].start_time, 2873397496);
        assert_eq!(session.timing[0].stop_time, 2873404696);
    }

    #[test]
    fn parse_repeat_time_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=2873397496 2873404696\r\n\
                   r=604800 3600 0 90000\r\n\
                   r=7d 1h 0 25h\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.repeat_times.len(), 2);
        assert_eq!(session.repeat_times[0].repeat_interval, "604800");
        assert_eq!(session.repeat_times[0].active_duration, "3600");
        assert_eq!(session.repeat_times[0].offsets, vec!["0", "90000"]);
        assert_eq!(session.repeat_times[1].repeat_interval, "7d");
        assert_eq!(session.repeat_times[1].active_duration, "1h");
        assert_eq!(session.repeat_times[1].offsets, vec!["0", "25h"]);
    }

    #[test]
    fn parse_time_zone_line() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=2873397496 2873404696\r\n\
                   z=2882844526 -1h 2898848070 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.time_zones.len(), 2);
        assert_eq!(session.time_zones[0].adjustment_time, 2882844526);
        assert_eq!(session.time_zones[0].offset, "-1h");
        assert_eq!(session.time_zones[1].adjustment_time, 2898848070);
        assert_eq!(session.time_zones[1].offset, "0");
    }

    #[test]
    fn parse_encryption_key_line() {
        let sdp1 = "v=0\r\n\
                    o=alice 123 456 IN IP4 192.0.2.1\r\n\
                    s=Session\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    k=prompt\r\n";

        let session1 = SdpSession::parse(sdp1).unwrap();
        assert_eq!(session1.encryption_key.as_ref().unwrap().method, "prompt");
        assert_eq!(session1.encryption_key.as_ref().unwrap().key, None);

        let sdp2 = "v=0\r\n\
                    o=alice 123 456 IN IP4 192.0.2.1\r\n\
                    s=Session\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    k=clear:mypassword\r\n";

        let session2 = SdpSession::parse(sdp2).unwrap();
        assert_eq!(session2.encryption_key.as_ref().unwrap().method, "clear");
        assert_eq!(
            session2.encryption_key.as_ref().unwrap().key,
            Some("mypassword".to_string())
        );
    }

    #[test]
    fn parse_generic_attributes() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=recvonly\r\n\
                   a=tool:siphon v1.0\r\n\
                   a=type:broadcast\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.attributes.len(), 3);

        // Property attribute (no value)
        assert_eq!(session.attributes[0].name, "recvonly");
        assert_eq!(session.attributes[0].value, None);

        // Value attributes
        assert_eq!(session.attributes[1].name, "tool");
        assert_eq!(session.attributes[1].value, Some("siphon v1.0".to_string()));
        assert_eq!(session.attributes[2].name, "type");
        assert_eq!(session.attributes[2].value, Some("broadcast".to_string()));
    }

    #[test]
    fn parse_all_direction_attributes() {
        // sendrecv
        let sdp1 = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 RTP/AVP 0\r\na=sendrecv\r\n";
        let session1 = SdpSession::parse(sdp1).unwrap();
        assert_eq!(session1.find_direction(Some(0)), Some(Direction::SendRecv));

        // sendonly
        let sdp2 = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 RTP/AVP 0\r\na=sendonly\r\n";
        let session2 = SdpSession::parse(sdp2).unwrap();
        assert_eq!(session2.find_direction(Some(0)), Some(Direction::SendOnly));

        // recvonly
        let sdp3 = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 RTP/AVP 0\r\na=recvonly\r\n";
        let session3 = SdpSession::parse(sdp3).unwrap();
        assert_eq!(session3.find_direction(Some(0)), Some(Direction::RecvOnly));

        // inactive
        let sdp4 = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 RTP/AVP 0\r\na=inactive\r\n";
        let session4 = SdpSession::parse(sdp4).unwrap();
        assert_eq!(session4.find_direction(Some(0)), Some(Direction::Inactive));
    }

    #[test]
    fn parse_rtpmap_variations() {
        // Without encoding params
        let rtpmap1 = RtpMap::parse("0 PCMU/8000").unwrap();
        assert_eq!(rtpmap1.payload_type, 0);
        assert_eq!(rtpmap1.encoding_name, "PCMU");
        assert_eq!(rtpmap1.clock_rate, 8000);
        assert_eq!(rtpmap1.encoding_params, None);

        // With encoding params (channels)
        let rtpmap2 = RtpMap::parse("98 L16/16000/2").unwrap();
        assert_eq!(rtpmap2.payload_type, 98);
        assert_eq!(rtpmap2.encoding_name, "L16");
        assert_eq!(rtpmap2.clock_rate, 16000);
        assert_eq!(rtpmap2.encoding_params, Some("2".to_string()));

        // Video codec
        let rtpmap3 = RtpMap::parse("99 h263-1998/90000").unwrap();
        assert_eq!(rtpmap3.payload_type, 99);
        assert_eq!(rtpmap3.encoding_name, "h263-1998");
        assert_eq!(rtpmap3.clock_rate, 90000);
        assert_eq!(rtpmap3.encoding_params, None);
    }

    #[test]
    fn parse_fmtp_variations() {
        let fmtp1 = Fmtp::parse("98 profile-level-id=42e01f").unwrap();
        assert_eq!(fmtp1.format, "98");
        assert_eq!(fmtp1.params, "profile-level-id=42e01f");

        let fmtp2 = Fmtp::parse("100 minptime=10;useinbandfec=1").unwrap();
        assert_eq!(fmtp2.format, "100");
        assert_eq!(fmtp2.params, "minptime=10;useinbandfec=1");
    }

    #[test]
    fn parse_media_with_multiple_ports() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=video 49170/2 RTP/AVP 31\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.media[0].port, 49170);
        assert_eq!(session.media[0].port_count, Some(2));
    }

    #[test]
    fn parse_media_level_fields() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=video 51372 RTP/AVP 99\r\n\
                   i=Video Stream\r\n\
                   c=IN IP4 192.0.2.99\r\n\
                   b=AS:384\r\n\
                   k=prompt\r\n\
                   a=rtpmap:99 H264/90000\r\n\
                   a=fmtp:99 profile-level-id=42e01f\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let media = &session.media[0];

        assert_eq!(media.title, Some("Video Stream".to_string()));
        assert!(media.connection.is_some());
        assert_eq!(
            media.connection.as_ref().unwrap().connection_address,
            "192.0.2.99"
        );
        assert_eq!(media.bandwidth.len(), 1);
        assert_eq!(media.bandwidth[0].bwtype, "AS");
        assert_eq!(media.bandwidth[0].bandwidth, 384);
        assert!(media.encryption_key.is_some());
        assert_eq!(media.encryption_key.as_ref().unwrap().method, "prompt");
        assert_eq!(media.attributes.len(), 2);
    }

    #[test]
    fn parse_complete_rfc_example() {
        // From RFC 4566 Section 5
        let sdp = "v=0\r\n\
                   o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
                   s=SDP Seminar\r\n\
                   i=A Seminar on the session description protocol\r\n\
                   u=http://www.example.com/seminars/sdp.pdf\r\n\
                   e=j.doe@example.com (Jane Doe)\r\n\
                   c=IN IP4 224.2.17.12/127\r\n\
                   t=2873397496 2873404696\r\n\
                   a=recvonly\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   m=video 51372 RTP/AVP 99\r\n\
                   a=rtpmap:99 h263-1998/90000\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Validate session-level fields
        assert_eq!(session.version, 0);
        assert_eq!(session.origin.username, "jdoe");
        assert_eq!(session.origin.sess_id, "2890844526");
        assert_eq!(session.session_name, "SDP Seminar");
        assert_eq!(
            session.session_info,
            Some("A Seminar on the session description protocol".to_string())
        );
        assert_eq!(
            session.uri,
            Some("http://www.example.com/seminars/sdp.pdf".to_string())
        );
        assert_eq!(session.emails[0], "j.doe@example.com (Jane Doe)");
        assert!(session.connection.is_some());
        assert_eq!(
            session.connection.as_ref().unwrap().connection_address,
            "224.2.17.12/127"
        );
        assert_eq!(session.timing[0].start_time, 2873397496);
        assert_eq!(session.find_direction(None), Some(Direction::RecvOnly));

        // Validate media
        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].media, "audio");
        assert_eq!(session.media[0].port, 49170);
        assert_eq!(session.media[1].media, "video");
        assert_eq!(session.media[1].port, 51372);

        // Validate rtpmap
        let rtpmaps = session.find_rtpmaps(1);
        assert_eq!(rtpmaps.len(), 1);
        assert_eq!(rtpmaps[0].payload_type, 99);
        assert_eq!(rtpmaps[0].encoding_name, "h263-1998");
        assert_eq!(rtpmaps[0].clock_rate, 90000);
    }

    #[test]
    fn generate_complete_sdp() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123456".to_string(),
                sess_version: "789".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "My Session".to_string(),
        );

        session.session_info = Some("Test session info".to_string());
        session.emails.push("user@example.com".to_string());
        session.phones.push("+1 555 1234".to_string());
        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });
        session.bandwidth.push(Bandwidth {
            bwtype: "CT".to_string(),
            bandwidth: 1000,
        });
        session.attributes.push(Attribute {
            name: "sendrecv".to_string(),
            value: None,
        });

        let generated = session.to_string();

        // Verify all lines present
        assert!(generated.contains("v=0"));
        assert!(generated.contains("o=alice 123456 789 IN IP4 192.0.2.1"));
        assert!(generated.contains("s=My Session"));
        assert!(generated.contains("i=Test session info"));
        assert!(generated.contains("e=user@example.com"));
        assert!(generated.contains("p=+1 555 1234"));
        assert!(generated.contains("c=IN IP4 192.0.2.1"));
        assert!(generated.contains("b=CT:1000"));
        assert!(generated.contains("t=0 0"));
        assert!(generated.contains("a=sendrecv"));
    }

    #[test]
    fn validate_connection_requirement() {
        // Missing connection at both session and media level should fail
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let result = SdpSession::parse(sdp);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SdpError::MissingRequiredField(_)
        ));
    }

    #[test]
    fn validate_connection_in_media() {
        // No session-level connection, but media has connection - should succeed
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   c=IN IP4 192.0.2.1\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.connection.is_none());
        assert!(session.media[0].connection.is_some());
    }

    // RFC 3312 Preconditions Tests

    #[test]
    fn parse_current_status() {
        let curr = CurrentStatus::parse("qos e2e sendrecv").unwrap();
        assert_eq!(curr.precondition_type, PreconditionType::Qos);
        assert_eq!(curr.status_type, StatusType::E2E);
        assert_eq!(curr.direction, PreconditionDirection::SendRecv);
    }

    #[test]
    fn parse_current_status_local() {
        let curr = CurrentStatus::parse("qos local send").unwrap();
        assert_eq!(curr.precondition_type, PreconditionType::Qos);
        assert_eq!(curr.status_type, StatusType::Local);
        assert_eq!(curr.direction, PreconditionDirection::Send);
    }

    #[test]
    fn parse_current_status_remote() {
        let curr = CurrentStatus::parse("qos remote recv").unwrap();
        assert_eq!(curr.precondition_type, PreconditionType::Qos);
        assert_eq!(curr.status_type, StatusType::Remote);
        assert_eq!(curr.direction, PreconditionDirection::Recv);
    }

    #[test]
    fn parse_current_status_none() {
        let curr = CurrentStatus::parse("qos e2e none").unwrap();
        assert_eq!(curr.direction, PreconditionDirection::None);
    }

    #[test]
    fn parse_desired_status() {
        let des = DesiredStatus::parse("qos mandatory e2e sendrecv").unwrap();
        assert_eq!(des.precondition_type, PreconditionType::Qos);
        assert_eq!(des.strength, StrengthTag::Mandatory);
        assert_eq!(des.status_type, StatusType::E2E);
        assert_eq!(des.direction, PreconditionDirection::SendRecv);
    }

    #[test]
    fn parse_desired_status_optional() {
        let des = DesiredStatus::parse("qos optional local send").unwrap();
        assert_eq!(des.strength, StrengthTag::Optional);
    }

    #[test]
    fn parse_confirm_status() {
        let conf = ConfirmStatus::parse("qos e2e recv").unwrap();
        assert_eq!(conf.precondition_type, PreconditionType::Qos);
        assert_eq!(conf.status_type, StatusType::E2E);
        assert_eq!(conf.direction, PreconditionDirection::Recv);
    }

    #[test]
    fn display_current_status() {
        let curr = CurrentStatus {
            precondition_type: PreconditionType::Qos,
            status_type: StatusType::E2E,
            direction: PreconditionDirection::SendRecv,
        };
        assert_eq!(curr.to_string(), "qos e2e sendrecv");
    }

    #[test]
    fn display_desired_status() {
        let des = DesiredStatus {
            precondition_type: PreconditionType::Qos,
            strength: StrengthTag::Mandatory,
            status_type: StatusType::Local,
            direction: PreconditionDirection::Send,
        };
        assert_eq!(des.to_string(), "qos mandatory local send");
    }

    #[test]
    fn display_confirm_status() {
        let conf = ConfirmStatus {
            precondition_type: PreconditionType::Qos,
            status_type: StatusType::Remote,
            direction: PreconditionDirection::Recv,
        };
        assert_eq!(conf.to_string(), "qos remote recv");
    }

    #[test]
    fn status_type_invert() {
        assert_eq!(StatusType::E2E.invert(), StatusType::E2E);
        assert_eq!(StatusType::Local.invert(), StatusType::Remote);
        assert_eq!(StatusType::Remote.invert(), StatusType::Local);
    }

    #[test]
    fn precondition_direction_invert() {
        assert_eq!(
            PreconditionDirection::Send.invert(),
            PreconditionDirection::Recv
        );
        assert_eq!(
            PreconditionDirection::Recv.invert(),
            PreconditionDirection::Send
        );
        assert_eq!(
            PreconditionDirection::SendRecv.invert(),
            PreconditionDirection::SendRecv
        );
        assert_eq!(
            PreconditionDirection::None.invert(),
            PreconditionDirection::None
        );
    }

    #[test]
    fn parse_sdp_with_preconditions() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session with Preconditions\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos e2e none\r\n\
                   a=des:qos mandatory e2e sendrecv\r\n\
                   a=conf:qos e2e recv\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(session.media.len(), 1);

        let curr = session.find_current_status(0);
        assert_eq!(curr.len(), 1);
        assert_eq!(curr[0].direction, PreconditionDirection::None);

        let des = session.find_desired_status(0);
        assert_eq!(des.len(), 1);
        assert_eq!(des[0].strength, StrengthTag::Mandatory);
        assert_eq!(des[0].direction, PreconditionDirection::SendRecv);

        let conf = session.find_confirm_status(0);
        assert_eq!(conf.len(), 1);
        assert_eq!(conf[0].direction, PreconditionDirection::Recv);
    }

    #[test]
    fn parse_sdp_with_segmented_preconditions() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos local sendrecv\r\n\
                   a=curr:qos remote none\r\n\
                   a=des:qos mandatory local sendrecv\r\n\
                   a=des:qos mandatory remote sendrecv\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        let curr = session.find_current_status(0);
        assert_eq!(curr.len(), 2);
        assert_eq!(curr[0].status_type, StatusType::Local);
        assert_eq!(curr[0].direction, PreconditionDirection::SendRecv);
        assert_eq!(curr[1].status_type, StatusType::Remote);
        assert_eq!(curr[1].direction, PreconditionDirection::None);

        let des = session.find_desired_status(0);
        assert_eq!(des.len(), 2);
        assert_eq!(des[0].status_type, StatusType::Local);
        assert_eq!(des[1].status_type, StatusType::Remote);
    }

    #[test]
    fn preconditions_not_met_when_current_is_none() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos e2e none\r\n\
                   a=des:qos mandatory e2e sendrecv\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(!session.are_preconditions_met(0));
    }

    #[test]
    fn preconditions_met_when_current_matches_desired() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos e2e sendrecv\r\n\
                   a=des:qos mandatory e2e sendrecv\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.are_preconditions_met(0));
    }

    #[test]
    fn preconditions_met_when_current_exceeds_desired() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos e2e sendrecv\r\n\
                   a=des:qos mandatory e2e send\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.are_preconditions_met(0));
    }

    #[test]
    fn preconditions_met_when_no_mandatory() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos e2e none\r\n\
                   a=des:qos optional e2e sendrecv\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.are_preconditions_met(0));
    }

    #[test]
    fn preconditions_met_when_no_preconditions() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.are_preconditions_met(0));
    }

    #[test]
    fn preconditions_not_met_segmented() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos local sendrecv\r\n\
                   a=curr:qos remote none\r\n\
                   a=des:qos mandatory local sendrecv\r\n\
                   a=des:qos mandatory remote sendrecv\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        // Local is met, but remote is not
        assert!(!session.are_preconditions_met(0));
    }

    #[test]
    fn preconditions_met_segmented() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=curr:qos local sendrecv\r\n\
                   a=curr:qos remote sendrecv\r\n\
                   a=des:qos mandatory local sendrecv\r\n\
                   a=des:qos mandatory remote sendrecv\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.are_preconditions_met(0));
    }

    #[test]
    fn strength_tag_parsing() {
        assert_eq!(
            StrengthTag::parse("mandatory"),
            Some(StrengthTag::Mandatory)
        );
        assert_eq!(StrengthTag::parse("optional"), Some(StrengthTag::Optional));
        assert_eq!(StrengthTag::parse("none"), Some(StrengthTag::None));
        assert_eq!(StrengthTag::parse("failure"), Some(StrengthTag::Failure));
        assert_eq!(StrengthTag::parse("unknown"), Some(StrengthTag::Unknown));
        assert_eq!(StrengthTag::parse("invalid"), None);
    }

    #[test]
    fn precondition_type_extensibility() {
        let other = PreconditionType::parse("custom");
        match other {
            PreconditionType::Other(s) => assert_eq!(s, "custom"),
            _ => panic!("Expected Other variant"),
        }
    }

    #[test]
    fn round_trip_preconditions() {
        let curr = CurrentStatus {
            precondition_type: PreconditionType::Qos,
            status_type: StatusType::E2E,
            direction: PreconditionDirection::SendRecv,
        };
        let parsed = CurrentStatus::parse(&curr.to_string()).unwrap();
        assert_eq!(curr, parsed);

        let des = DesiredStatus {
            precondition_type: PreconditionType::Qos,
            strength: StrengthTag::Mandatory,
            status_type: StatusType::Local,
            direction: PreconditionDirection::Send,
        };
        let parsed = DesiredStatus::parse(&des.to_string()).unwrap();
        assert_eq!(des, parsed);

        let conf = ConfirmStatus {
            precondition_type: PreconditionType::Qos,
            status_type: StatusType::Remote,
            direction: PreconditionDirection::Recv,
        };
        let parsed = ConfirmStatus::parse(&conf.to_string()).unwrap();
        assert_eq!(conf, parsed);
    }

    // RFC 3388 Media Grouping Tests

    #[test]
    fn parse_group_ls_semantics() {
        let group = MediaGroup::parse("LS 1 2").unwrap();
        assert_eq!(group.semantics, GroupSemantics::LS);
        assert_eq!(group.mids, vec!["1", "2"]);
    }

    #[test]
    fn parse_group_fid_semantics() {
        let group = MediaGroup::parse("FID 1 2").unwrap();
        assert_eq!(group.semantics, GroupSemantics::FID);
        assert_eq!(group.mids, vec!["1", "2"]);
    }

    #[test]
    fn parse_group_custom_semantics() {
        let group = MediaGroup::parse("CUSTOM 1 2 3").unwrap();
        match group.semantics {
            GroupSemantics::Other(ref s) => assert_eq!(s, "CUSTOM"),
            _ => panic!("Expected Other variant"),
        }
        assert_eq!(group.mids, vec!["1", "2", "3"]);
    }

    #[test]
    fn parse_group_case_insensitive() {
        let group = MediaGroup::parse("ls 1 2").unwrap();
        assert_eq!(group.semantics, GroupSemantics::LS);

        let group = MediaGroup::parse("fid 3 4").unwrap();
        assert_eq!(group.semantics, GroupSemantics::FID);
    }

    #[test]
    fn parse_group_missing_mids() {
        let result = MediaGroup::parse("LS");
        assert!(result.is_err());
    }

    #[test]
    fn display_group() {
        let group = MediaGroup {
            semantics: GroupSemantics::LS,
            mids: vec!["1".to_string(), "2".to_string()],
        };
        assert_eq!(group.to_string(), "LS 1 2");

        let group = MediaGroup {
            semantics: GroupSemantics::FID,
            mids: vec!["audio".to_string(), "video".to_string()],
        };
        assert_eq!(group.to_string(), "FID audio video");
    }

    #[test]
    fn parse_sdp_with_group_and_mid() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session with Grouping\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:LS 1 2\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 51372 RTP/AVP 99\r\n\
                   a=mid:2\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Check groups
        assert_eq!(session.groups.len(), 1);
        assert_eq!(session.groups[0].semantics, GroupSemantics::LS);
        assert_eq!(session.groups[0].mids, vec!["1", "2"]);

        // Check mids
        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].mid, Some("1".to_string()));
        assert_eq!(session.media[1].mid, Some("2".to_string()));

        // Verify group and mid attributes were extracted from attributes
        assert!(session.attributes.iter().all(|attr| attr.name != "group"));
        assert!(session.media[0]
            .attributes
            .iter()
            .all(|attr| attr.name != "mid"));
        assert!(session.media[1]
            .attributes
            .iter()
            .all(|attr| attr.name != "mid"));
    }

    #[test]
    fn parse_sdp_with_multiple_groups() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:LS 1 2\r\n\
                   a=group:FID 3 4\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 51372 RTP/AVP 99\r\n\
                   a=mid:2\r\n\
                   m=audio 49174 RTP/AVP 0\r\n\
                   a=mid:3\r\n\
                   m=audio 49176 RTP/AVP 8\r\n\
                   a=mid:4\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 2);
        assert_eq!(session.groups[0].semantics, GroupSemantics::LS);
        assert_eq!(session.groups[0].mids, vec!["1", "2"]);
        assert_eq!(session.groups[1].semantics, GroupSemantics::FID);
        assert_eq!(session.groups[1].mids, vec!["3", "4"]);

        assert_eq!(session.media.len(), 4);
        assert_eq!(session.media[0].mid, Some("1".to_string()));
        assert_eq!(session.media[1].mid, Some("2".to_string()));
        assert_eq!(session.media[2].mid, Some("3".to_string()));
        assert_eq!(session.media[3].mid, Some("4".to_string()));
    }

    #[test]
    fn generate_sdp_with_group_and_mid() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "Grouped Session".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        session.groups.push(MediaGroup {
            semantics: GroupSemantics::LS,
            mids: vec!["1".to_string(), "2".to_string()],
        });

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: Some("1".to_string()),
            rtcp: None,
            capability_set: None,
        });

        session.media.push(MediaDescription {
            media: "video".to_string(),
            port: 51372,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["99".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: Some("2".to_string()),
            rtcp: None,
            capability_set: None,
        });

        let generated = session.to_string();

        assert!(generated.contains("a=group:LS 1 2"));
        assert!(generated.contains("a=mid:1"));
        assert!(generated.contains("a=mid:2"));
    }

    #[test]
    fn round_trip_group_and_mid() {
        let original_sdp = "v=0\r\n\
                           o=alice 123 456 IN IP4 192.0.2.1\r\n\
                           s=Session\r\n\
                           c=IN IP4 192.0.2.1\r\n\
                           t=0 0\r\n\
                           a=group:LS 1 2\r\n\
                           m=audio 49170 RTP/AVP 0\r\n\
                           a=mid:1\r\n\
                           m=video 51372 RTP/AVP 99\r\n\
                           a=mid:2\r\n";

        let session = SdpSession::parse(original_sdp).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        assert_eq!(session.groups, reparsed.groups);
        assert_eq!(session.media[0].mid, reparsed.media[0].mid);
        assert_eq!(session.media[1].mid, reparsed.media[1].mid);
    }

    #[test]
    fn parse_sdp_with_mid_but_no_group() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 51372 RTP/AVP 99\r\n\
                   a=mid:2\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 0);
        assert_eq!(session.media[0].mid, Some("1".to_string()));
        assert_eq!(session.media[1].mid, Some("2".to_string()));
    }

    #[test]
    fn parse_sdp_without_mid_or_group() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   m=video 51372 RTP/AVP 99\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 0);
        assert_eq!(session.media[0].mid, None);
        assert_eq!(session.media[1].mid, None);
    }

    #[test]
    fn group_semantics_display() {
        assert_eq!(GroupSemantics::LS.to_string(), "LS");
        assert_eq!(GroupSemantics::FID.to_string(), "FID");
        assert_eq!(
            GroupSemantics::Other("CUSTOM".to_string()).to_string(),
            "CUSTOM"
        );
    }

    #[test]
    fn group_with_many_mids() {
        let group = MediaGroup::parse("LS 1 2 3 4 5").unwrap();
        assert_eq!(group.semantics, GroupSemantics::LS);
        assert_eq!(group.mids.len(), 5);
        assert_eq!(group.mids, vec!["1", "2", "3", "4", "5"]);
    }

    #[test]
    fn fid_group_for_codec_alternatives() {
        // RFC 3388 example: FID for codec alternatives
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:FID 1 2\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   m=audio 30002 RTP/AVP 8\r\n\
                   a=mid:2\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 1);
        assert_eq!(session.groups[0].semantics, GroupSemantics::FID);
        assert_eq!(session.groups[0].mids, vec!["1", "2"]);

        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].port, 30000);
        assert_eq!(session.media[1].port, 30002);
    }

    // RFC 3407: Capability Declaration tests

    #[test]
    fn parse_capability_description() {
        let cdsc = CapabilityDescription::parse("1 audio RTP/AVP 0 18").unwrap();
        assert_eq!(cdsc.cap_num, 1);
        assert_eq!(cdsc.media, "audio");
        assert_eq!(cdsc.transport, "RTP/AVP");
        assert_eq!(cdsc.formats, vec!["0", "18"]);
    }

    #[test]
    fn parse_capability_description_video() {
        let cdsc = CapabilityDescription::parse("2 video RTP/AVP 31 32").unwrap();
        assert_eq!(cdsc.cap_num, 2);
        assert_eq!(cdsc.media, "video");
        assert_eq!(cdsc.transport, "RTP/AVP");
        assert_eq!(cdsc.formats, vec!["31", "32"]);
    }

    #[test]
    fn capability_description_display() {
        let cdsc = CapabilityDescription {
            cap_num: 1,
            media: "audio".to_string(),
            transport: "RTP/AVP".to_string(),
            formats: vec!["0".to_string(), "18".to_string()],
        };
        assert_eq!(cdsc.to_string(), "1 audio RTP/AVP 0 18");
    }

    #[test]
    fn parse_capability_parameter_general() {
        let cpar =
            CapabilityParameter::parse(CapabilityParameterType::General, "a=fmtp:96 0-16,32-35");
        assert_eq!(cpar.param_type, CapabilityParameterType::General);
        assert_eq!(cpar.value, "a=fmtp:96 0-16,32-35");
    }

    #[test]
    fn parse_capability_parameter_min() {
        let cpar = CapabilityParameter::parse(CapabilityParameterType::Min, "b=AS:64");
        assert_eq!(cpar.param_type, CapabilityParameterType::Min);
        assert_eq!(cpar.value, "b=AS:64");
    }

    #[test]
    fn parse_capability_parameter_max() {
        let cpar = CapabilityParameter::parse(CapabilityParameterType::Max, "b=AS:128");
        assert_eq!(cpar.param_type, CapabilityParameterType::Max);
        assert_eq!(cpar.value, "b=AS:128");
    }

    #[test]
    fn capability_parameter_type_as_str() {
        assert_eq!(CapabilityParameterType::General.as_str(), "cpar");
        assert_eq!(CapabilityParameterType::Min.as_str(), "cparmin");
        assert_eq!(CapabilityParameterType::Max.as_str(), "cparmax");
    }

    #[test]
    fn parse_sdp_with_session_level_capabilities() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=sqn:0\r\n\
                   a=cdsc:1 audio RTP/AVP 0 18\r\n\
                   a=cdsc:3 audio RTP/AVP 96\r\n\
                   a=cpar:a=fmtp:96 annexb=no\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert!(session.capability_set.is_some());
        let cap_set = session.capability_set.as_ref().unwrap();
        assert_eq!(cap_set.sequence_number, 0);
        assert_eq!(cap_set.descriptions.len(), 2);

        assert_eq!(cap_set.descriptions[0].cap_num, 1);
        assert_eq!(cap_set.descriptions[0].media, "audio");
        assert_eq!(cap_set.descriptions[0].formats, vec!["0", "18"]);

        assert_eq!(cap_set.descriptions[1].cap_num, 3);
        assert_eq!(cap_set.descriptions[1].formats, vec!["96"]);

        assert_eq!(cap_set.parameters.len(), 1);
        assert_eq!(
            cap_set.parameters[0].param_type,
            CapabilityParameterType::General
        );
        assert_eq!(cap_set.parameters[0].value, "a=fmtp:96 annexb=no");
    }

    #[test]
    fn parse_sdp_with_media_level_capabilities() {
        let sdp = "v=0\r\n\
                   o=bob 789 321 IN IP4 192.0.2.2\r\n\
                   s=Media Capabilities\r\n\
                   c=IN IP4 192.0.2.2\r\n\
                   t=0 0\r\n\
                   m=audio 49172 RTP/AVP 0\r\n\
                   a=sqn:1\r\n\
                   a=cdsc:1 audio RTP/AVP 8 96\r\n\
                   a=cpar:a=rtpmap:96 G726-32/8000\r\n\
                   a=cparmin:b=AS:32\r\n\
                   a=cparmax:b=AS:64\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert!(session.capability_set.is_none());
        assert_eq!(session.media.len(), 1);

        let media_cap_set = session.media[0].capability_set.as_ref().unwrap();
        assert_eq!(media_cap_set.sequence_number, 1);
        assert_eq!(media_cap_set.descriptions.len(), 1);
        assert_eq!(media_cap_set.descriptions[0].cap_num, 1);
        assert_eq!(media_cap_set.descriptions[0].formats, vec!["8", "96"]);

        assert_eq!(media_cap_set.parameters.len(), 3);
        assert_eq!(
            media_cap_set.parameters[0].param_type,
            CapabilityParameterType::General
        );
        assert_eq!(
            media_cap_set.parameters[1].param_type,
            CapabilityParameterType::Min
        );
        assert_eq!(
            media_cap_set.parameters[2].param_type,
            CapabilityParameterType::Max
        );
        assert_eq!(media_cap_set.parameters[1].value, "b=AS:32");
        assert_eq!(media_cap_set.parameters[2].value, "b=AS:64");
    }

    #[test]
    fn generate_sdp_with_session_level_capabilities() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "Test".to_string(),
        );
        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        let mut cap_set = SdpCapabilitySet::new(0);
        cap_set.descriptions.push(CapabilityDescription {
            cap_num: 1,
            media: "audio".to_string(),
            transport: "RTP/AVP".to_string(),
            formats: vec!["0".to_string(), "18".to_string()],
        });
        cap_set.parameters.push(CapabilityParameter::parse(
            CapabilityParameterType::General,
            "a=fmtp:18 annexb=yes",
        ));
        session.capability_set = Some(cap_set);

        let generated = session.to_string();

        assert!(generated.contains("a=sqn:0"));
        assert!(generated.contains("a=cdsc:1 audio RTP/AVP 0 18"));
        assert!(generated.contains("a=cpar:a=fmtp:18 annexb=yes"));
    }

    #[test]
    fn generate_sdp_with_media_level_capabilities() {
        let mut session = SdpSession::new(
            Origin {
                username: "bob".to_string(),
                sess_id: "789".to_string(),
                sess_version: "321".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.2".to_string(),
            },
            "Test".to_string(),
        );
        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.2".to_string(),
        });

        let mut media = MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: None,
            capability_set: None,
        };

        let mut cap_set = SdpCapabilitySet::new(5);
        cap_set.descriptions.push(CapabilityDescription {
            cap_num: 1,
            media: "audio".to_string(),
            transport: "RTP/AVP".to_string(),
            formats: vec!["8".to_string()],
        });
        cap_set.parameters.push(CapabilityParameter::parse(
            CapabilityParameterType::Min,
            "b=AS:32",
        ));
        cap_set.parameters.push(CapabilityParameter::parse(
            CapabilityParameterType::Max,
            "b=AS:128",
        ));
        media.capability_set = Some(cap_set);

        session.media.push(media);

        let generated = session.to_string();

        assert!(generated.contains("a=sqn:5"));
        assert!(generated.contains("a=cdsc:1 audio RTP/AVP 8"));
        assert!(generated.contains("a=cparmin:b=AS:32"));
        assert!(generated.contains("a=cparmax:b=AS:128"));
    }

    #[test]
    fn round_trip_capabilities() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Capability Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=sqn:10\r\n\
                   a=cdsc:1 audio RTP/AVP 0 8 18\r\n\
                   a=cdsc:4 video RTP/AVP 31 34\r\n\
                   a=cpar:a=rtpmap:18 G729/8000\r\n\
                   a=cparmin:b=AS:64\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        assert_eq!(
            session.capability_set.as_ref().unwrap().sequence_number,
            reparsed.capability_set.as_ref().unwrap().sequence_number
        );
        assert_eq!(
            session.capability_set.as_ref().unwrap().descriptions.len(),
            reparsed.capability_set.as_ref().unwrap().descriptions.len()
        );
        assert_eq!(
            session.capability_set.as_ref().unwrap().parameters.len(),
            reparsed.capability_set.as_ref().unwrap().parameters.len()
        );
    }

    #[test]
    fn capability_set_with_multiple_descriptions() {
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=Multiple Caps\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=sqn:20\r\n\
                   a=cdsc:1 audio RTP/AVP 0\r\n\
                   a=cdsc:2 audio RTP/AVP 8\r\n\
                   a=cdsc:3 audio RTP/AVP 18\r\n\
                   a=cdsc:4 video RTP/AVP 31\r\n\
                   a=cdsc:5 video RTP/AVP 34\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let cap_set = session.capability_set.as_ref().unwrap();

        assert_eq!(cap_set.sequence_number, 20);
        assert_eq!(cap_set.descriptions.len(), 5);
        assert_eq!(cap_set.descriptions[0].cap_num, 1);
        assert_eq!(cap_set.descriptions[4].cap_num, 5);
        assert_eq!(cap_set.descriptions[3].media, "video");
    }

    #[test]
    fn capability_descriptions_without_sqn_error() {
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=No SQN\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=cdsc:1 audio RTP/AVP 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let result = SdpSession::parse(sdp);
        assert!(result.is_err());
        match result {
            Err(SdpError::InvalidSyntax(msg)) => {
                assert!(msg.contains("require"));
                assert!(msg.contains("sqn"));
            }
            _ => panic!("Expected InvalidSyntax error"),
        }
    }

    #[test]
    fn capability_parameters_without_sqn_error() {
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=No SQN with params\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=cpar:a=fmtp:96 annexb=no\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let result = SdpSession::parse(sdp);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_number_modulo_256() {
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=SQN 255\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=sqn:255\r\n\
                   a=cdsc:1 audio RTP/AVP 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert_eq!(
            session.capability_set.as_ref().unwrap().sequence_number,
            255
        );
    }

    #[test]
    fn sdp_without_capabilities() {
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=No Caps\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        assert!(session.capability_set.is_none());
        assert!(session.media[0].capability_set.is_none());
    }

    #[test]
    fn rfc_3407_example() {
        // Example from RFC 3407 Section 4.1
        let sdp = "v=0\r\n\
                   o=bob 2890844730 2890844730 IN IP4 128.59.19.68\r\n\
                   s=\r\n\
                   c=IN IP4 128.59.19.68\r\n\
                   t=0 0\r\n\
                   m=audio 3456 RTP/AVP 0 18\r\n\
                   a=sqn:0\r\n\
                   a=cdsc:1 audio RTP/AVP 0 18\r\n\
                   a=cdsc:3 audio RTP/AVP 8\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.media.len(), 1);
        let cap_set = session.media[0].capability_set.as_ref().unwrap();
        assert_eq!(cap_set.sequence_number, 0);
        assert_eq!(cap_set.descriptions.len(), 2);

        assert_eq!(cap_set.descriptions[0].cap_num, 1);
        assert_eq!(cap_set.descriptions[0].formats, vec!["0", "18"]);

        assert_eq!(cap_set.descriptions[1].cap_num, 3);
        assert_eq!(cap_set.descriptions[1].formats, vec!["8"]);
    }

    // RFC 3524: SRF (Single Reservation Flow) tests

    #[test]
    fn parse_group_srf_semantics() {
        let group = MediaGroup::parse("SRF 1 2").unwrap();
        assert_eq!(group.semantics, GroupSemantics::SRF);
        assert_eq!(group.mids, vec!["1", "2"]);
    }

    #[test]
    fn parse_group_srf_case_insensitive() {
        let group_lower = MediaGroup::parse("srf 1 2").unwrap();
        let group_upper = MediaGroup::parse("SRF 1 2").unwrap();
        let group_mixed = MediaGroup::parse("Srf 1 2").unwrap();

        assert_eq!(group_lower.semantics, GroupSemantics::SRF);
        assert_eq!(group_upper.semantics, GroupSemantics::SRF);
        assert_eq!(group_mixed.semantics, GroupSemantics::SRF);
    }

    #[test]
    fn group_semantics_srf_display() {
        let semantics = GroupSemantics::SRF;
        assert_eq!(semantics.to_string(), "SRF");
        assert_eq!(semantics.as_str(), "SRF");
    }

    #[test]
    fn parse_sdp_with_srf_group() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=SRF Example\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:SRF 1 2\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   m=video 30002 RTP/AVP 31\r\n\
                   a=mid:2\r\n\
                   a=rtpmap:31 H261/90000\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 1);
        assert_eq!(session.groups[0].semantics, GroupSemantics::SRF);
        assert_eq!(session.groups[0].mids, vec!["1", "2"]);

        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].mid, Some("1".to_string()));
        assert_eq!(session.media[1].mid, Some("2".to_string()));
    }

    #[test]
    fn generate_sdp_with_srf_group() {
        let mut session = SdpSession::new(
            Origin {
                username: "bob".to_string(),
                sess_id: "789".to_string(),
                sess_version: "321".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.2".to_string(),
            },
            "SRF Test".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.2".to_string(),
        });

        session.groups.push(MediaGroup {
            semantics: GroupSemantics::SRF,
            mids: vec!["audio".to_string(), "video".to_string()],
        });

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: Some("audio".to_string()),
            rtcp: None,
            capability_set: None,
        });

        session.media.push(MediaDescription {
            media: "video".to_string(),
            port: 49172,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["31".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: Some("video".to_string()),
            rtcp: None,
            capability_set: None,
        });

        let generated = session.to_string();

        assert!(generated.contains("a=group:SRF audio video"));
        assert!(generated.contains("a=mid:audio"));
        assert!(generated.contains("a=mid:video"));
    }

    #[test]
    fn round_trip_srf_group() {
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:SRF 1 2 3\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   a=mid:2\r\n\
                   m=video 49174 RTP/AVP 32\r\n\
                   a=mid:3\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        assert_eq!(session.groups.len(), reparsed.groups.len());
        assert_eq!(session.groups[0].semantics, reparsed.groups[0].semantics);
        assert_eq!(session.groups[0].mids, reparsed.groups[0].mids);
    }

    #[test]
    fn srf_group_single_media() {
        // RFC 3524: An SRF group can contain a single media line
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Single Stream Reservation\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:SRF 1\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=mid:1\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 1);
        assert_eq!(session.groups[0].semantics, GroupSemantics::SRF);
        assert_eq!(session.groups[0].mids, vec!["1"]);
    }

    #[test]
    fn multiple_srf_groups() {
        // Multiple SRF groups for different reservation flows
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=Multiple Flows\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:SRF 1 2\r\n\
                   a=group:SRF 3\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   a=mid:2\r\n\
                   m=video 49174 RTP/AVP 32\r\n\
                   a=mid:3\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 2);
        assert_eq!(session.groups[0].semantics, GroupSemantics::SRF);
        assert_eq!(session.groups[0].mids, vec!["1", "2"]);
        assert_eq!(session.groups[1].semantics, GroupSemantics::SRF);
        assert_eq!(session.groups[1].mids, vec!["3"]);
    }

    #[test]
    fn mixed_group_semantics_with_srf() {
        // Mixing SRF with other group semantics (LS, FID)
        let sdp = "v=0\r\n\
                   o=test 1 1 IN IP4 192.0.2.1\r\n\
                   s=Mixed Semantics\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   a=group:LS 1 2\r\n\
                   a=group:SRF 1 2 3\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   a=mid:2\r\n\
                   m=video 49174 RTP/AVP 32\r\n\
                   a=mid:3\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.groups.len(), 2);
        assert_eq!(session.groups[0].semantics, GroupSemantics::LS);
        assert_eq!(session.groups[1].semantics, GroupSemantics::SRF);
    }

    #[test]
    fn rfc_3524_example() {
        // Example from RFC 3524 Section 3
        let sdp = "v=0\r\n\
                   o=Laura 289083124 289083124 IN IP4 one.example.com\r\n\
                   s=SDP Seminar\r\n\
                   c=IN IP4 192.0.0.1\r\n\
                   t=0 0\r\n\
                   a=group:SRF 1 2\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=mid:1\r\n\
                   m=video 30002 RTP/AVP 31\r\n\
                   a=mid:2\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify the SRF group
        assert_eq!(session.groups.len(), 1);
        assert_eq!(session.groups[0].semantics, GroupSemantics::SRF);
        assert_eq!(session.groups[0].mids, vec!["1", "2"]);

        // Verify media descriptions
        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].media, "audio");
        assert_eq!(session.media[0].port, 30000);
        assert_eq!(session.media[0].mid, Some("1".to_string()));

        assert_eq!(session.media[1].media, "video");
        assert_eq!(session.media[1].port, 30002);
        assert_eq!(session.media[1].mid, Some("2".to_string()));
    }

    // ===== RFC 3556: RTCP Bandwidth Modifiers Tests =====

    #[test]
    fn parse_bandwidth_type_rs() {
        let bwtype = BandwidthType::parse("RS");
        assert_eq!(bwtype, BandwidthType::RS);
        assert!(bwtype.is_rtcp());
    }

    #[test]
    fn parse_bandwidth_type_rr() {
        let bwtype = BandwidthType::parse("RR");
        assert_eq!(bwtype, BandwidthType::RR);
        assert!(bwtype.is_rtcp());
    }

    #[test]
    fn parse_bandwidth_type_case_insensitive() {
        assert_eq!(BandwidthType::parse("rs"), BandwidthType::RS);
        assert_eq!(BandwidthType::parse("Rs"), BandwidthType::RS);
        assert_eq!(BandwidthType::parse("rr"), BandwidthType::RR);
        assert_eq!(BandwidthType::parse("Rr"), BandwidthType::RR);
        assert_eq!(BandwidthType::parse("as"), BandwidthType::AS);
        assert_eq!(BandwidthType::parse("ct"), BandwidthType::CT);
        assert_eq!(BandwidthType::parse("tias"), BandwidthType::TIAS);
    }

    #[test]
    fn bandwidth_type_display() {
        assert_eq!(BandwidthType::RS.to_string(), "RS");
        assert_eq!(BandwidthType::RR.to_string(), "RR");
        assert_eq!(BandwidthType::AS.to_string(), "AS");
        assert_eq!(BandwidthType::CT.to_string(), "CT");
        assert_eq!(BandwidthType::TIAS.to_string(), "TIAS");
    }

    #[test]
    fn bandwidth_type_is_rtcp() {
        assert!(BandwidthType::RS.is_rtcp());
        assert!(BandwidthType::RR.is_rtcp());
        assert!(!BandwidthType::AS.is_rtcp());
        assert!(!BandwidthType::CT.is_rtcp());
        assert!(!BandwidthType::TIAS.is_rtcp());
    }

    #[test]
    fn bandwidth_rtcp_senders_constructor() {
        let bw = Bandwidth::rtcp_senders(2000);
        assert_eq!(bw.bwtype, "RS");
        assert_eq!(bw.bandwidth, 2000);
        assert!(bw.is_rtcp());
        assert_eq!(bw.bandwidth_type(), BandwidthType::RS);
    }

    #[test]
    fn bandwidth_rtcp_receivers_constructor() {
        let bw = Bandwidth::rtcp_receivers(1500);
        assert_eq!(bw.bwtype, "RR");
        assert_eq!(bw.bandwidth, 1500);
        assert!(bw.is_rtcp());
        assert_eq!(bw.bandwidth_type(), BandwidthType::RR);
    }

    #[test]
    fn bandwidth_application_specific_constructor() {
        let bw = Bandwidth::application_specific(128);
        assert_eq!(bw.bwtype, "AS");
        assert_eq!(bw.bandwidth, 128);
        assert!(!bw.is_rtcp());
        assert_eq!(bw.bandwidth_type(), BandwidthType::AS);
    }

    #[test]
    fn bandwidth_conference_total_constructor() {
        let bw = Bandwidth::conference_total(256);
        assert_eq!(bw.bwtype, "CT");
        assert_eq!(bw.bandwidth, 256);
        assert!(!bw.is_rtcp());
        assert_eq!(bw.bandwidth_type(), BandwidthType::CT);
    }

    #[test]
    fn parse_sdp_with_rtcp_bandwidth() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=RTCP Bandwidth Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   b=RS:2000\r\n\
                   b=RR:1500\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify RTCP bandwidth modifiers
        assert_eq!(session.bandwidth.len(), 2);

        assert_eq!(session.bandwidth[0].bwtype, "RS");
        assert_eq!(session.bandwidth[0].bandwidth, 2000);
        assert!(session.bandwidth[0].is_rtcp());

        assert_eq!(session.bandwidth[1].bwtype, "RR");
        assert_eq!(session.bandwidth[1].bandwidth, 1500);
        assert!(session.bandwidth[1].is_rtcp());
    }

    #[test]
    fn parse_sdp_with_mixed_bandwidth() {
        let sdp = "v=0\r\n\
                   o=bob 789 321 IN IP4 192.0.2.2\r\n\
                   s=Mixed Bandwidth\r\n\
                   c=IN IP4 192.0.2.2\r\n\
                   t=0 0\r\n\
                   b=AS:128\r\n\
                   b=RS:2000\r\n\
                   b=RR:1500\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   b=AS:64\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify session-level bandwidth
        assert_eq!(session.bandwidth.len(), 3);
        assert_eq!(session.bandwidth[0].bwtype, "AS");
        assert_eq!(session.bandwidth[0].bandwidth, 128);
        assert!(!session.bandwidth[0].is_rtcp());

        assert_eq!(session.bandwidth[1].bwtype, "RS");
        assert!(session.bandwidth[1].is_rtcp());

        assert_eq!(session.bandwidth[2].bwtype, "RR");
        assert!(session.bandwidth[2].is_rtcp());

        // Verify media-level bandwidth
        assert_eq!(session.media[0].bandwidth.len(), 1);
        assert_eq!(session.media[0].bandwidth[0].bwtype, "AS");
        assert_eq!(session.media[0].bandwidth[0].bandwidth, 64);
    }

    #[test]
    fn generate_sdp_with_rtcp_bandwidth() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "RTCP Test".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        session.bandwidth.push(Bandwidth::rtcp_senders(2000));
        session.bandwidth.push(Bandwidth::rtcp_receivers(1500));

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: None,
            capability_set: None,
        });

        let sdp_string = session.to_string();

        // Verify RS and RR are present
        assert!(sdp_string.contains("b=RS:2000"));
        assert!(sdp_string.contains("b=RR:1500"));
    }

    #[test]
    fn round_trip_rtcp_bandwidth() {
        let original = "v=0\r\n\
                        o=alice 123 456 IN IP4 192.0.2.1\r\n\
                        s=Round Trip\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        b=RS:2000\r\n\
                        b=RR:1500\r\n\
                        m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(original).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        // Verify bandwidth preserved through round trip
        assert_eq!(reparsed.bandwidth.len(), 2);
        assert_eq!(reparsed.bandwidth[0].bwtype, "RS");
        assert_eq!(reparsed.bandwidth[0].bandwidth, 2000);
        assert_eq!(reparsed.bandwidth[1].bwtype, "RR");
        assert_eq!(reparsed.bandwidth[1].bandwidth, 1500);
    }

    #[test]
    fn rtcp_bandwidth_media_level() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Media Level RTCP\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   b=RS:2000\r\n\
                   b=RR:1500\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   b=RS:4000\r\n\
                   b=RR:3000\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify audio media bandwidth
        assert_eq!(session.media[0].bandwidth.len(), 2);
        assert_eq!(session.media[0].bandwidth[0].bwtype, "RS");
        assert_eq!(session.media[0].bandwidth[0].bandwidth, 2000);
        assert_eq!(session.media[0].bandwidth[1].bwtype, "RR");
        assert_eq!(session.media[0].bandwidth[1].bandwidth, 1500);

        // Verify video media bandwidth
        assert_eq!(session.media[1].bandwidth.len(), 2);
        assert_eq!(session.media[1].bandwidth[0].bwtype, "RS");
        assert_eq!(session.media[1].bandwidth[0].bandwidth, 4000);
        assert_eq!(session.media[1].bandwidth[1].bwtype, "RR");
        assert_eq!(session.media[1].bandwidth[1].bandwidth, 3000);
    }

    #[test]
    fn rfc_3556_example() {
        // Example inspired by RFC 3556
        let sdp = "v=0\r\n\
                   o=Laura 289083124 289083124 IN IP4 one.example.com\r\n\
                   s=SDP Seminar\r\n\
                   c=IN IP4 224.2.17.12/127\r\n\
                   t=2873397496 2873404696\r\n\
                   b=AS:1000\r\n\
                   b=RS:800\r\n\
                   b=RR:200\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify all bandwidth modifiers
        assert_eq!(session.bandwidth.len(), 3);

        // AS modifier (kbps)
        assert_eq!(session.bandwidth[0].bwtype, "AS");
        assert_eq!(session.bandwidth[0].bandwidth, 1000);
        assert!(!session.bandwidth[0].is_rtcp());

        // RS modifier (bps)
        assert_eq!(session.bandwidth[1].bwtype, "RS");
        assert_eq!(session.bandwidth[1].bandwidth, 800);
        assert!(session.bandwidth[1].is_rtcp());

        // RR modifier (bps)
        assert_eq!(session.bandwidth[2].bwtype, "RR");
        assert_eq!(session.bandwidth[2].bandwidth, 200);
        assert!(session.bandwidth[2].is_rtcp());
    }

    // ===== RFC 3605: RTCP Attribute Tests =====

    #[test]
    fn rtcp_attribute_new() {
        let rtcp = RtcpAttribute::new(53020);
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, None);
        assert_eq!(rtcp.addrtype, None);
        assert_eq!(rtcp.connection_address, None);
    }

    #[test]
    fn rtcp_attribute_with_address() {
        let rtcp = RtcpAttribute::with_address(
            53020,
            "IN".to_string(),
            "IP4".to_string(),
            "126.16.64.4".to_string(),
        );
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, Some("IN".to_string()));
        assert_eq!(rtcp.addrtype, Some("IP4".to_string()));
        assert_eq!(rtcp.connection_address, Some("126.16.64.4".to_string()));
    }

    #[test]
    fn rtcp_attribute_parse_port_only() {
        let rtcp = RtcpAttribute::parse("53020").unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, None);
        assert_eq!(rtcp.addrtype, None);
        assert_eq!(rtcp.connection_address, None);
    }

    #[test]
    fn rtcp_attribute_parse_with_address_ipv4() {
        let rtcp = RtcpAttribute::parse("53020 IN IP4 126.16.64.4").unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, Some("IN".to_string()));
        assert_eq!(rtcp.addrtype, Some("IP4".to_string()));
        assert_eq!(rtcp.connection_address, Some("126.16.64.4".to_string()));
    }

    #[test]
    fn rtcp_attribute_parse_with_address_ipv6() {
        let rtcp =
            RtcpAttribute::parse("53020 IN IP6 2001:2345:6789:ABCD:EF01:2345:6789:ABCD").unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, Some("IN".to_string()));
        assert_eq!(rtcp.addrtype, Some("IP6".to_string()));
        assert_eq!(
            rtcp.connection_address,
            Some("2001:2345:6789:ABCD:EF01:2345:6789:ABCD".to_string())
        );
    }

    #[test]
    fn rtcp_attribute_parse_invalid_port() {
        let result = RtcpAttribute::parse("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn rtcp_attribute_parse_incomplete_address() {
        // Should have 1 or 4 components, not 2 or 3
        let result = RtcpAttribute::parse("53020 IN");
        assert!(result.is_err());

        let result = RtcpAttribute::parse("53020 IN IP4");
        assert!(result.is_err());
    }

    #[test]
    fn rtcp_attribute_to_string_port_only() {
        let rtcp = RtcpAttribute::new(53020);
        assert_eq!(rtcp.to_string(), "53020");
    }

    #[test]
    fn rtcp_attribute_to_string_with_address() {
        let rtcp = RtcpAttribute::with_address(
            53020,
            "IN".to_string(),
            "IP4".to_string(),
            "126.16.64.4".to_string(),
        );
        assert_eq!(rtcp.to_string(), "53020 IN IP4 126.16.64.4");
    }

    #[test]
    fn parse_sdp_with_rtcp_port_only() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=RTCP Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.media.len(), 1);
        let rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, None);
        assert_eq!(rtcp.addrtype, None);
        assert_eq!(rtcp.connection_address, None);
    }

    #[test]
    fn parse_sdp_with_rtcp_full_address() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=RTCP Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020 IN IP4 126.16.64.4\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        let rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, Some("IN".to_string()));
        assert_eq!(rtcp.addrtype, Some("IP4".to_string()));
        assert_eq!(rtcp.connection_address, Some("126.16.64.4".to_string()));
    }

    #[test]
    fn parse_sdp_with_rtcp_ipv6() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=RTCP IPv6 Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020 IN IP6 2001:2345:6789:ABCD:EF01:2345:6789:ABCD\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        let rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.addrtype, Some("IP6".to_string()));
        assert_eq!(
            rtcp.connection_address,
            Some("2001:2345:6789:ABCD:EF01:2345:6789:ABCD".to_string())
        );
    }

    #[test]
    fn parse_sdp_without_rtcp() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=No RTCP Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.media[0].rtcp, None);
    }

    #[test]
    fn generate_sdp_with_rtcp_port_only() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "RTCP Test".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: Some(RtcpAttribute::new(53020)),
            capability_set: None,
        });

        let sdp_string = session.to_string();
        assert!(sdp_string.contains("a=rtcp:53020"));
    }

    #[test]
    fn generate_sdp_with_rtcp_full_address() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "RTCP Test".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: Some(RtcpAttribute::with_address(
                53020,
                "IN".to_string(),
                "IP4".to_string(),
                "126.16.64.4".to_string(),
            )),
            capability_set: None,
        });

        let sdp_string = session.to_string();
        assert!(sdp_string.contains("a=rtcp:53020 IN IP4 126.16.64.4"));
    }

    #[test]
    fn round_trip_rtcp_port_only() {
        let original = "v=0\r\n\
                        o=alice 123 456 IN IP4 192.0.2.1\r\n\
                        s=Round Trip\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 49170 RTP/AVP 0\r\n\
                        a=rtcp:53020\r\n";

        let session = SdpSession::parse(original).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        let rtcp = reparsed.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, None);
    }

    #[test]
    fn round_trip_rtcp_with_address() {
        let original = "v=0\r\n\
                        o=alice 123 456 IN IP4 192.0.2.1\r\n\
                        s=Round Trip\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 49170 RTP/AVP 0\r\n\
                        a=rtcp:53020 IN IP4 126.16.64.4\r\n";

        let session = SdpSession::parse(original).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        let rtcp = reparsed.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, Some("IN".to_string()));
        assert_eq!(rtcp.addrtype, Some("IP4".to_string()));
        assert_eq!(rtcp.connection_address, Some("126.16.64.4".to_string()));
    }

    #[test]
    fn multiple_media_with_different_rtcp() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Multi-Media RTCP\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   a=rtcp:53022 IN IP4 126.16.64.5\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Audio rtcp
        let audio_rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(audio_rtcp.port, 53020);
        assert_eq!(audio_rtcp.connection_address, None);

        // Video rtcp
        let video_rtcp = session.media[1].rtcp.as_ref().unwrap();
        assert_eq!(video_rtcp.port, 53022);
        assert_eq!(
            video_rtcp.connection_address,
            Some("126.16.64.5".to_string())
        );
    }

    #[test]
    fn rfc_3605_example_1() {
        // Example 1 from RFC 3605: port only
        let sdp = "v=0\r\n\
                   o=user 0 0 IN IP4 192.0.2.1\r\n\
                   s=Example\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
    }

    #[test]
    fn rfc_3605_example_2() {
        // Example 2 from RFC 3605: with IPv4 address
        let sdp = "v=0\r\n\
                   o=user 0 0 IN IP4 192.0.2.1\r\n\
                   s=Example\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020 IN IP4 126.16.64.4\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.nettype, Some("IN".to_string()));
        assert_eq!(rtcp.addrtype, Some("IP4".to_string()));
        assert_eq!(rtcp.connection_address, Some("126.16.64.4".to_string()));
    }

    #[test]
    fn rfc_3605_example_3() {
        // Example 3 from RFC 3605: with IPv6 address
        let sdp = "v=0\r\n\
                   o=user 0 0 IN IP4 192.0.2.1\r\n\
                   s=Example\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   a=rtcp:53020 IN IP6 2001:2345:6789:ABCD:EF01:2345:6789:ABCD\r\n";

        let session = SdpSession::parse(sdp).unwrap();
        let rtcp = session.media[0].rtcp.as_ref().unwrap();
        assert_eq!(rtcp.port, 53020);
        assert_eq!(rtcp.addrtype, Some("IP6".to_string()));
        assert_eq!(
            rtcp.connection_address,
            Some("2001:2345:6789:ABCD:EF01:2345:6789:ABCD".to_string())
        );
    }

    // ===== RFC 3890: TIAS Bandwidth Modifier Tests =====

    #[test]
    fn bandwidth_type_tias() {
        let bwtype = BandwidthType::parse("TIAS");
        assert_eq!(bwtype, BandwidthType::TIAS);
        assert!(!bwtype.is_rtcp());
    }

    #[test]
    fn bandwidth_type_tias_case_insensitive() {
        assert_eq!(BandwidthType::parse("tias"), BandwidthType::TIAS);
        assert_eq!(BandwidthType::parse("Tias"), BandwidthType::TIAS);
        assert_eq!(BandwidthType::parse("TiAs"), BandwidthType::TIAS);
    }

    #[test]
    fn bandwidth_type_tias_display() {
        assert_eq!(BandwidthType::TIAS.to_string(), "TIAS");
        assert_eq!(BandwidthType::TIAS.as_str(), "TIAS");
    }

    #[test]
    fn bandwidth_tias_constructor() {
        let bw = Bandwidth::tias(50000);
        assert_eq!(bw.bwtype, "TIAS");
        assert_eq!(bw.bandwidth, 50000);
        assert!(!bw.is_rtcp());
        assert_eq!(bw.bandwidth_type(), BandwidthType::TIAS);
    }

    #[test]
    fn parse_sdp_with_tias() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=TIAS Test\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   b=TIAS:50000\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.bandwidth.len(), 1);
        assert_eq!(session.bandwidth[0].bwtype, "TIAS");
        assert_eq!(session.bandwidth[0].bandwidth, 50000);
        assert_eq!(session.bandwidth[0].bandwidth_type(), BandwidthType::TIAS);
    }

    #[test]
    fn parse_sdp_with_tias_and_as() {
        // RFC 3890 recommends including both AS and TIAS for backward compatibility
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=TIAS with AS\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   b=AS:64\r\n\
                   b=TIAS:50000\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.bandwidth.len(), 2);
        assert_eq!(session.bandwidth[0].bwtype, "AS");
        assert_eq!(session.bandwidth[0].bandwidth, 64);
        assert_eq!(session.bandwidth[1].bwtype, "TIAS");
        assert_eq!(session.bandwidth[1].bandwidth, 50000);
    }

    #[test]
    fn parse_sdp_with_tias_media_level() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Media Level TIAS\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   b=TIAS:8480\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   b=TIAS:42300\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify audio TIAS
        assert_eq!(session.media[0].bandwidth.len(), 1);
        assert_eq!(session.media[0].bandwidth[0].bwtype, "TIAS");
        assert_eq!(session.media[0].bandwidth[0].bandwidth, 8480);

        // Verify video TIAS
        assert_eq!(session.media[1].bandwidth.len(), 1);
        assert_eq!(session.media[1].bandwidth[0].bwtype, "TIAS");
        assert_eq!(session.media[1].bandwidth[0].bandwidth, 42300);
    }

    #[test]
    fn generate_sdp_with_tias() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "TIAS Test".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        session.bandwidth.push(Bandwidth::tias(50000));

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: None,
            capability_set: None,
        });

        let sdp_string = session.to_string();
        assert!(sdp_string.contains("b=TIAS:50000"));
    }

    #[test]
    fn generate_sdp_with_tias_and_as() {
        let mut session = SdpSession::new(
            Origin {
                username: "alice".to_string(),
                sess_id: "123".to_string(),
                sess_version: "456".to_string(),
                nettype: "IN".to_string(),
                addrtype: "IP4".to_string(),
                unicast_address: "192.0.2.1".to_string(),
            },
            "TIAS and AS".to_string(),
        );

        session.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: "192.0.2.1".to_string(),
        });

        // Include both AS and TIAS as recommended by RFC 3890
        session.bandwidth.push(Bandwidth::application_specific(64));
        session.bandwidth.push(Bandwidth::tias(50000));

        session.media.push(MediaDescription {
            media: "audio".to_string(),
            port: 49170,
            port_count: None,
            proto: "RTP/AVP".to_string(),
            fmt: vec!["0".to_string()],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: None,
            rtcp: None,
            capability_set: None,
        });

        let sdp_string = session.to_string();
        assert!(sdp_string.contains("b=AS:64"));
        assert!(sdp_string.contains("b=TIAS:50000"));
    }

    #[test]
    fn round_trip_tias() {
        let original = "v=0\r\n\
                        o=alice 123 456 IN IP4 192.0.2.1\r\n\
                        s=Round Trip\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        b=TIAS:50000\r\n\
                        m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(original).unwrap();
        let generated = session.to_string();
        let reparsed = SdpSession::parse(&generated).unwrap();

        assert_eq!(reparsed.bandwidth.len(), 1);
        assert_eq!(reparsed.bandwidth[0].bwtype, "TIAS");
        assert_eq!(reparsed.bandwidth[0].bandwidth, 50000);
    }

    #[test]
    fn tias_session_and_media_level() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Session and Media TIAS\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   b=TIAS:50780\r\n\
                   m=audio 49170 RTP/AVP 0\r\n\
                   b=TIAS:8480\r\n\
                   m=video 49172 RTP/AVP 31\r\n\
                   b=TIAS:42300\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Session-level TIAS
        assert_eq!(session.bandwidth.len(), 1);
        assert_eq!(session.bandwidth[0].bwtype, "TIAS");
        assert_eq!(session.bandwidth[0].bandwidth, 50780);

        // Media-level TIAS
        assert_eq!(session.media[0].bandwidth[0].bandwidth, 8480);
        assert_eq!(session.media[1].bandwidth[0].bandwidth, 42300);
    }

    #[test]
    fn tias_with_multiple_modifiers() {
        let sdp = "v=0\r\n\
                   o=alice 123 456 IN IP4 192.0.2.1\r\n\
                   s=Multiple Modifiers\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   b=AS:64\r\n\
                   b=TIAS:50000\r\n\
                   b=RS:2000\r\n\
                   b=RR:1500\r\n\
                   m=audio 49170 RTP/AVP 0\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        assert_eq!(session.bandwidth.len(), 4);
        assert_eq!(session.bandwidth[0].bwtype, "AS");
        assert_eq!(session.bandwidth[1].bwtype, "TIAS");
        assert_eq!(session.bandwidth[2].bwtype, "RS");
        assert_eq!(session.bandwidth[3].bwtype, "RR");
    }

    #[test]
    fn rfc_3890_streaming_example() {
        // Inspired by RFC 3890 streaming example
        let sdp = "v=0\r\n\
                   o=user 0 0 IN IP4 192.0.2.1\r\n\
                   s=Streaming Session\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   b=TIAS:50780\r\n\
                   m=audio 49170 RTP/AVP 97\r\n\
                   b=AS:12\r\n\
                   b=TIAS:8480\r\n\
                   a=maxprate:10\r\n\
                   m=video 49172 RTP/AVP 98\r\n\
                   b=AS:50\r\n\
                   b=TIAS:42300\r\n\
                   a=maxprate:18\r\n";

        let session = SdpSession::parse(sdp).unwrap();

        // Verify session-level TIAS
        assert_eq!(session.bandwidth.len(), 1);
        assert_eq!(session.bandwidth[0].bandwidth, 50780);

        // Verify audio: AS (backward compat) + TIAS
        assert_eq!(session.media[0].bandwidth.len(), 2);
        assert_eq!(session.media[0].bandwidth[0].bwtype, "AS");
        assert_eq!(session.media[0].bandwidth[0].bandwidth, 12);
        assert_eq!(session.media[0].bandwidth[1].bwtype, "TIAS");
        assert_eq!(session.media[0].bandwidth[1].bandwidth, 8480);

        // Verify video: AS + TIAS
        assert_eq!(session.media[1].bandwidth.len(), 2);
        assert_eq!(session.media[1].bandwidth[0].bwtype, "AS");
        assert_eq!(session.media[1].bandwidth[0].bandwidth, 50);
        assert_eq!(session.media[1].bandwidth[1].bwtype, "TIAS");
        assert_eq!(session.media[1].bandwidth[1].bandwidth, 42300);
    }
}
