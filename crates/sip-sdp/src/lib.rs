// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SDP (Session Description Protocol) implementation per RFC 4566
//!
//! This crate provides:
//! - Complete SDP parsing and serialization (RFC 4566)
//! - RFC 3264 offer/answer model
//! - Media capability negotiation
//! - Configuration profiles for common scenarios
//!
//! # Example
//! ```
//! use sip_sdp::{SessionDescription, MediaDescription, MediaType, RtpMap};
//!
//! // Create an audio-only SDP offer
//! let sdp = SessionDescription::builder()
//!     .origin("alice", "123456", "192.168.1.100").unwrap()
//!     .session_name("VoIP Call").unwrap()
//!     .connection("192.168.1.100").unwrap()
//!     .media(MediaDescription::audio(8000)
//!         .add_format(0).unwrap()  // PCMU
//!         .add_format(8).unwrap()  // PCMA
//!         .add_rtpmap(0, "PCMU", 8000, None).unwrap()
//!         .add_rtpmap(8, "PCMA", 8000, None).unwrap())
//!     .unwrap()
//!     .build();
//! ```

pub mod builder;
pub mod negotiate;
pub mod parse;
pub mod profiles;
pub mod serialize;

use smol_str::SmolStr;
use std::collections::HashMap;

// Security constants for DoS prevention and input validation
const MAX_USERNAME_LENGTH: usize = 256;
const MAX_SESSION_ID_LENGTH: usize = 256;
const MAX_SESSION_NAME_LENGTH: usize = 512;
const MAX_ADDRESS_LENGTH: usize = 256;
const MAX_ENCODING_NAME_LENGTH: usize = 64;
const MAX_ATTRIBUTE_NAME_LENGTH: usize = 128;
const MAX_ATTRIBUTE_VALUE_LENGTH: usize = 1024;

// Collection limits (DoS prevention)
const MAX_MEDIA_DESCRIPTIONS: usize = 20;
const MAX_ATTRIBUTES_PER_DESCRIPTION: usize = 50;
const MAX_FORMATS_PER_MEDIA: usize = 50;
const MAX_TIME_DESCRIPTIONS: usize = 10;
const MAX_TIME_ZONES: usize = 10;
const MAX_RTPMAPS: usize = 50;

// Value limits (removed unused MAX_PORT - ports are just u16, no additional validation needed)
const MIN_CLOCK_RATE: u32 = 1000; // 1 kHz minimum
const MAX_CLOCK_RATE: u32 = 1_000_000_000; // 1 GHz maximum
const MAX_PAYLOAD_TYPE: u8 = 127; // RTP payload type range

/// SDP validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum SdpError {
    /// Field too long (DoS prevention)
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    /// Field contains control characters (CRLF injection)
    FieldContainsControlChars { field: &'static str },
    /// Too many items in collection (DoS prevention)
    TooManyItems {
        collection: &'static str,
        max: usize,
        actual: usize,
    },
    /// Clock rate out of range
    InvalidClockRate { rate: u32, min: u32, max: u32 },
    /// Payload type out of range
    InvalidPayloadType { payload_type: u8, max: u8 },
    /// Empty required field
    EmptyField { field: &'static str },
}

impl std::fmt::Display for SdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdpError::FieldTooLong { field, max, actual } => {
                write!(f, "{} length {} exceeds max {}", field, actual, max)
            }
            SdpError::FieldContainsControlChars { field } => {
                write!(f, "{} contains control characters (CRLF injection)", field)
            }
            SdpError::TooManyItems {
                collection,
                max,
                actual,
            } => {
                write!(
                    f,
                    "too many items in {} ({} exceeds max {})",
                    collection, actual, max
                )
            }
            SdpError::InvalidClockRate { rate, min, max } => {
                write!(
                    f,
                    "clock rate {} out of range ({}-{})",
                    rate, min, max
                )
            }
            SdpError::InvalidPayloadType { payload_type, max } => {
                write!(f, "payload type {} exceeds max {}", payload_type, max)
            }
            SdpError::EmptyField { field } => {
                write!(f, "{} cannot be empty", field)
            }
        }
    }
}

impl std::error::Error for SdpError {}

/// Validates a string field for length and control characters
fn validate_field(
    value: &str,
    field: &'static str,
    max_length: usize,
) -> Result<(), SdpError> {
    if value.is_empty() {
        return Err(SdpError::EmptyField { field });
    }
    if value.len() > max_length {
        return Err(SdpError::FieldTooLong {
            field,
            max: max_length,
            actual: value.len(),
        });
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(SdpError::FieldContainsControlChars { field });
    }
    Ok(())
}

/// Validates a clock rate
fn validate_clock_rate(rate: u32) -> Result<(), SdpError> {
    if rate < MIN_CLOCK_RATE || rate > MAX_CLOCK_RATE {
        return Err(SdpError::InvalidClockRate {
            rate,
            min: MIN_CLOCK_RATE,
            max: MAX_CLOCK_RATE,
        });
    }
    Ok(())
}

/// Validates a payload type
fn validate_payload_type(payload_type: u8) -> Result<(), SdpError> {
    if payload_type > MAX_PAYLOAD_TYPE {
        return Err(SdpError::InvalidPayloadType {
            payload_type,
            max: MAX_PAYLOAD_TYPE,
        });
    }
    Ok(())
}

/// Complete SDP Session Description per RFC 4566
#[derive(Debug, Clone, PartialEq)]
pub struct SessionDescription {
    /// Protocol version (always 0 per RFC 4566)
    pub version: u8,

    /// Origin line: o=username session-id session-version nettype addrtype unicast-address
    pub origin: Origin,

    /// Session name: s=<session name>
    pub session_name: SmolStr,

    /// Session information (optional): i=<session description>
    pub session_info: Option<SmolStr>,

    /// URI (optional): u=<uri>
    pub uri: Option<SmolStr>,

    /// Email contact (optional): e=<email address>
    pub email: Option<SmolStr>,

    /// Phone contact (optional): p=<phone number>
    pub phone: Option<SmolStr>,

    /// Connection information (optional at session level): c=<nettype> <addrtype> <connection-address>
    pub connection: Option<Connection>,

    /// Bandwidth information (optional): b=<bwtype>:<bandwidth>
    pub bandwidth: Vec<Bandwidth>,

    /// Time descriptions: t=<start-time> <stop-time> (one or more)
    pub times: Vec<TimeDescription>,

    /// Time zone adjustments: z=<adjustment-time> <offset> ...
    pub time_zones: Vec<TimeZoneAdjustment>,

    /// Session encryption key (optional): k=<method> or k=<method>:<encryption key>
    pub encryption_key: Option<SmolStr>,

    /// Session attributes: a=<attribute> or a=<attribute>:<value>
    pub attributes: Vec<Attribute>,

    /// Media descriptions: m=<media> <port> <proto> <fmt> ...
    pub media: Vec<MediaDescription>,
}

/// Origin line (o=) per RFC 4566 §5.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub username: SmolStr,
    pub session_id: SmolStr,
    pub session_version: SmolStr,
    pub net_type: NetType,
    pub addr_type: AddrType,
    pub unicast_address: SmolStr,
}

/// Connection information (c=) per RFC 4566 §5.7
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub net_type: NetType,
    pub addr_type: AddrType,
    pub connection_address: SmolStr,
}

/// Time description (t=) per RFC 4566 §5.9
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeDescription {
    pub start_time: u64, // NTP timestamp or 0 for permanent
    pub stop_time: u64,  // NTP timestamp or 0 for unbounded
    pub repeats: Vec<RepeatTime>,
}

/// Repeat time (r=) per RFC 4566 §5.10
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatTime {
    pub repeat_interval: SmolStr,
    pub active_duration: SmolStr,
    pub offsets: Vec<SmolStr>,
}

/// Time zone adjustment (z=) per RFC 4566 §5.11
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeZoneAdjustment {
    pub adjustment_time: SmolStr,
    pub offset: SmolStr,
}
/// Bandwidth specification (b=) per RFC 4566 §5.8
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bandwidth {
    pub bw_type: SmolStr, // "CT", "AS", etc.
    pub bandwidth: u32,   // in kilobits per second
}

/// Media description (m=) per RFC 4566 §5.14
#[derive(Debug, Clone, PartialEq)]
pub struct MediaDescription {
    /// Media type: audio, video, text, application, message
    pub media_type: MediaType,

    /// Transport port
    pub port: u16,

    /// Number of ports (for RTP: usually 1)
    pub num_ports: Option<u16>,

    /// Transport protocol: RTP/AVP, RTP/SAVP, UDP, TCP, etc.
    pub protocol: Protocol,

    /// Format list (RTP payload types or media format descriptions)
    pub formats: Vec<SmolStr>,

    /// Media title (optional): i=<media title>
    pub title: Option<SmolStr>,

    /// Connection information (optional, overrides session-level): c=
    pub connection: Option<Connection>,

    /// Bandwidth (optional): b=
    pub bandwidth: Vec<Bandwidth>,

    /// Encryption key (optional): k=<method> or k=<method>:<encryption key>
    pub encryption_key: Option<SmolStr>,

    /// Media attributes: a=
    pub attributes: Vec<Attribute>,

    /// RTP maps extracted from attributes (for convenience)
    pub rtpmaps: HashMap<u8, RtpMap>,
}

/// Media type per RFC 4566
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
    Text,
    Application,
    Message,
    Other(SmolStr),
}

/// Transport protocol per RFC 4566
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// RTP Profile for Audio and Video Conferences (RFC 3551)
    RtpAvp,
    /// Secure RTP Profile (RFC 3711)
    RtpSavp,
    /// RTP/SAVPF - Secure RTP Profile with RTCP Feedback (RFC 5124)
    RtpSavpf,
    /// UDP/TLS/RTP/SAVPF - WebRTC standard (RFC 5764)
    UdpTlsRtpSavpf,
    /// TCP/TLS/RTP/SAVPF - WebRTC over TCP (RFC 4571 + RFC 5764)
    TcpTlsRtpSavpf,
    /// UDP
    Udp,
    /// TCP
    Tcp,
    /// Other protocol
    Other(SmolStr),
}

/// Network type per RFC 4566
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetType {
    Internet, // "IN"
}

/// Address type per RFC 4566
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrType {
    IPv4, // "IP4"
    IPv6, // "IP6"
}

/// SDP Attribute (a=) per RFC 4566 §5.13
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    /// Property attribute: a=<flag>
    Property(SmolStr),

    /// Value attribute: a=<attribute>:<value>
    Value { name: SmolStr, value: SmolStr },
}

/// RTP Payload Type Mapping (parsed from rtpmap attribute)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpMap {
    /// Payload type (0-127)
    pub payload_type: u8,

    /// Encoding name (e.g., "PCMU", "H264")
    pub encoding_name: SmolStr,

    /// Clock rate in Hz
    pub clock_rate: u32,

    /// Encoding parameters (e.g., number of channels for audio)
    pub encoding_params: Option<SmolStr>,
}

impl Default for SessionDescription {
    fn default() -> Self {
        Self {
            version: 0,
            origin: Origin {
                username: SmolStr::new("-"),
                session_id: SmolStr::new("0"),
                session_version: SmolStr::new("0"),
                net_type: NetType::Internet,
                addr_type: AddrType::IPv4,
                unicast_address: SmolStr::new("0.0.0.0"),
            },
            session_name: SmolStr::new("-"),
            session_info: None,
            uri: None,
            email: None,
            phone: None,
            connection: None,
            bandwidth: Vec::new(),
            times: vec![TimeDescription {
                start_time: 0,
                stop_time: 0,
                repeats: Vec::new(),
            }],
            time_zones: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            media: Vec::new(),
        }
    }
}

impl SessionDescription {
    /// Creates a new builder for constructing SDP
    pub fn builder() -> builder::SessionDescriptionBuilder {
        builder::SessionDescriptionBuilder::new()
    }

    /// Parses SDP from a string
    ///
    /// # Example
    /// ```
    /// use sip_sdp::SessionDescription;
    ///
    /// let sdp_text = "v=0\r\n\
    ///                 o=alice 123456 0 IN IP4 192.168.1.100\r\n\
    ///                 s=VoIP Call\r\n\
    ///                 c=IN IP4 192.168.1.100\r\n\
    ///                 t=0 0\r\n\
    ///                 m=audio 8000 RTP/AVP 0 8\r\n\
    ///                 a=rtpmap:0 PCMU/8000\r\n\
    ///                 a=rtpmap:8 PCMA/8000\r\n";
    ///
    /// let sdp = SessionDescription::parse(sdp_text).unwrap();
    /// assert_eq!(sdp.origin.username.as_str(), "alice");
    /// assert_eq!(sdp.media.len(), 1);
    /// ```
    pub fn parse(sdp: &str) -> Result<Self, parse::ParseError> {
        parse::parse_sdp(sdp)
    }

    /// Serializes SDP to a string
    ///
    /// # Example
    /// ```
    /// use sip_sdp::{SessionDescription, MediaDescription};
    ///
    /// let sdp = SessionDescription::builder()
    ///     .origin("alice", "123456", "192.168.1.100").unwrap()
    ///     .session_name("VoIP Call").unwrap()
    ///     .connection("192.168.1.100").unwrap()
    ///     .media(MediaDescription::audio(8000)
    ///         .add_format(0).unwrap()
    ///         .add_rtpmap(0, "PCMU", 8000, None).unwrap())
    ///     .unwrap()
    ///     .build();
    ///
    /// let sdp_text = sdp.serialize();
    /// assert!(sdp_text.contains("v=0\r\n"));
    /// assert!(sdp_text.contains("m=audio 8000 RTP/AVP 0\r\n"));
    /// ```
    pub fn serialize(&self) -> String {
        serialize::serialize_sdp(self)
    }

    /// Finds a media description by type
    ///
    /// Returns the first media description matching the given type.
    ///
    /// # Example
    /// ```
    /// use sip_sdp::{SessionDescription, MediaDescription, MediaType};
    ///
    /// let sdp = SessionDescription::builder()
    ///     .origin("bob", "456", "10.0.0.1").unwrap()
    ///     .session_name("Conference").unwrap()
    ///     .connection("10.0.0.1").unwrap()
    ///     .media(MediaDescription::audio(9000).add_format(0).unwrap()).unwrap()
    ///     .media(MediaDescription::video(9002).add_format(96).unwrap()).unwrap()
    ///     .build();
    ///
    /// let audio = sdp.find_media(MediaType::Audio).unwrap();
    /// assert_eq!(audio.port, 9000);
    /// ```
    pub fn find_media(&self, media_type: MediaType) -> Option<&MediaDescription> {
        self.media.iter().find(|m| m.media_type == media_type)
    }

    /// Finds all media descriptions of a given type
    ///
    /// Returns all media descriptions matching the given type (useful for multi-stream scenarios).
    ///
    /// # Example
    /// ```
    /// use sip_sdp::{SessionDescription, MediaDescription, MediaType};
    ///
    /// let sdp = SessionDescription::builder()
    ///     .origin("charlie", "789", "172.16.0.1").unwrap()
    ///     .session_name("Multi-Audio").unwrap()
    ///     .connection("172.16.0.1").unwrap()
    ///     .media(MediaDescription::audio(5000).add_format(0).unwrap()).unwrap()
    ///     .media(MediaDescription::audio(5002).add_format(8).unwrap()).unwrap()
    ///     .build();
    ///
    /// let all_audio = sdp.find_all_media(MediaType::Audio);
    /// assert_eq!(all_audio.len(), 2);
    /// assert_eq!(all_audio[0].port, 5000);
    /// assert_eq!(all_audio[1].port, 5002);
    /// ```
    pub fn find_all_media(&self, media_type: MediaType) -> Vec<&MediaDescription> {
        self.media
            .iter()
            .filter(|m| m.media_type == media_type)
            .collect()
    }
}

impl std::fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

impl MediaDescription {
    /// Creates a new audio media description
    pub fn audio(port: u16) -> Self {
        Self {
            media_type: MediaType::Audio,
            port,
            num_ports: None,
            protocol: Protocol::RtpAvp,
            formats: Vec::new(),
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            rtpmaps: HashMap::new(),
        }
    }

    /// Creates a new video media description
    pub fn video(port: u16) -> Self {
        Self {
            media_type: MediaType::Video,
            port,
            num_ports: None,
            protocol: Protocol::RtpAvp,
            formats: Vec::new(),
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            rtpmaps: HashMap::new(),
        }
    }

    /// Adds a format (payload type) with validation
    pub fn add_format(mut self, payload_type: u8) -> Result<Self, SdpError> {
        validate_payload_type(payload_type)?;

        if self.formats.len() >= MAX_FORMATS_PER_MEDIA {
            return Err(SdpError::TooManyItems {
                collection: "formats",
                max: MAX_FORMATS_PER_MEDIA,
                actual: self.formats.len() + 1,
            });
        }

        self.formats.push(SmolStr::new(payload_type.to_string()));
        Ok(self)
    }

    /// Adds a format token (non-RTP or custom) with validation
    pub fn add_format_token(mut self, token: &str) -> Result<Self, SdpError> {
        validate_field(token, "format_token", MAX_ENCODING_NAME_LENGTH)?;

        if self.formats.len() >= MAX_FORMATS_PER_MEDIA {
            return Err(SdpError::TooManyItems {
                collection: "formats",
                max: MAX_FORMATS_PER_MEDIA,
                actual: self.formats.len() + 1,
            });
        }

        self.formats.push(SmolStr::new(token));
        Ok(self)
    }

    /// Adds an RTP map with validation
    pub fn add_rtpmap(
        mut self,
        payload_type: u8,
        encoding_name: &str,
        clock_rate: u32,
        encoding_params: Option<&str>,
    ) -> Result<Self, SdpError> {
        validate_payload_type(payload_type)?;
        validate_field(encoding_name, "encoding_name", MAX_ENCODING_NAME_LENGTH)?;
        validate_clock_rate(clock_rate)?;

        if self.rtpmaps.len() >= MAX_RTPMAPS {
            return Err(SdpError::TooManyItems {
                collection: "rtpmaps",
                max: MAX_RTPMAPS,
                actual: self.rtpmaps.len() + 1,
            });
        }

        if self.attributes.len() >= MAX_ATTRIBUTES_PER_DESCRIPTION {
            return Err(SdpError::TooManyItems {
                collection: "attributes",
                max: MAX_ATTRIBUTES_PER_DESCRIPTION,
                actual: self.attributes.len() + 1,
            });
        }

        let rtpmap = RtpMap {
            payload_type,
            encoding_name: SmolStr::new(encoding_name),
            clock_rate,
            encoding_params: encoding_params.map(SmolStr::new),
        };

        // Add attribute
        let attr_value = if let Some(params) = &rtpmap.encoding_params {
            format!(
                "{} {}/{}/{}",
                payload_type, encoding_name, clock_rate, params
            )
        } else {
            format!("{} {}/{}", payload_type, encoding_name, clock_rate)
        };

        self.attributes.push(Attribute::Value {
            name: SmolStr::new("rtpmap"),
            value: SmolStr::new(&attr_value),
        });

        self.rtpmaps.insert(payload_type, rtpmap);
        Ok(self)
    }

    /// Adds a property attribute with validation
    pub fn add_property(mut self, name: &str) -> Result<Self, SdpError> {
        validate_field(name, "attribute_name", MAX_ATTRIBUTE_NAME_LENGTH)?;

        if self.attributes.len() >= MAX_ATTRIBUTES_PER_DESCRIPTION {
            return Err(SdpError::TooManyItems {
                collection: "attributes",
                max: MAX_ATTRIBUTES_PER_DESCRIPTION,
                actual: self.attributes.len() + 1,
            });
        }

        self.attributes
            .push(Attribute::Property(SmolStr::new(name)));
        Ok(self)
    }

    /// Adds a value attribute with validation
    pub fn add_attribute(mut self, name: &str, value: &str) -> Result<Self, SdpError> {
        validate_field(name, "attribute_name", MAX_ATTRIBUTE_NAME_LENGTH)?;
        validate_field(value, "attribute_value", MAX_ATTRIBUTE_VALUE_LENGTH)?;

        if self.attributes.len() >= MAX_ATTRIBUTES_PER_DESCRIPTION {
            return Err(SdpError::TooManyItems {
                collection: "attributes",
                max: MAX_ATTRIBUTES_PER_DESCRIPTION,
                actual: self.attributes.len() + 1,
            });
        }

        self.attributes.push(Attribute::Value {
            name: SmolStr::new(name),
            value: SmolStr::new(value),
        });
        Ok(self)
    }

    /// Sets the connection for this media with validation
    pub fn connection(mut self, addr: &str) -> Result<Self, SdpError> {
        self.connection = Some(Connection::new(addr)?);
        Ok(self)
    }

    /// Sets the media direction (sendrecv, sendonly, recvonly, inactive)
    pub fn direction(self, dir: &str) -> Result<Self, SdpError> {
        self.add_property(dir)
    }
}

impl Origin {
    /// Creates a new origin line with validation
    pub fn new(username: &str, session_id: &str, addr: &str) -> Result<Self, SdpError> {
        validate_field(username, "username", MAX_USERNAME_LENGTH)?;
        validate_field(session_id, "session_id", MAX_SESSION_ID_LENGTH)?;
        validate_field(addr, "address", MAX_ADDRESS_LENGTH)?;

        Ok(Self {
            username: SmolStr::new(username),
            session_id: SmolStr::new(session_id),
            session_version: SmolStr::new("0"),
            net_type: NetType::Internet,
            addr_type: if addr.contains(':') {
                AddrType::IPv6
            } else {
                AddrType::IPv4
            },
            unicast_address: SmolStr::new(addr),
        })
    }
}

impl Connection {
    /// Creates a new connection line with validation
    pub fn new(addr: &str) -> Result<Self, SdpError> {
        validate_field(addr, "address", MAX_ADDRESS_LENGTH)?;

        Ok(Self {
            net_type: NetType::Internet,
            addr_type: if addr.contains(':') {
                AddrType::IPv6
            } else {
                AddrType::IPv4
            },
            connection_address: SmolStr::new(addr),
        })
    }
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediaType::Audio => write!(f, "audio"),
            MediaType::Video => write!(f, "video"),
            MediaType::Text => write!(f, "text"),
            MediaType::Application => write!(f, "application"),
            MediaType::Message => write!(f, "message"),
            MediaType::Other(name) => write!(f, "{}", name),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::RtpAvp => write!(f, "RTP/AVP"),
            Protocol::RtpSavp => write!(f, "RTP/SAVP"),
            Protocol::RtpSavpf => write!(f, "RTP/SAVPF"),
            Protocol::UdpTlsRtpSavpf => write!(f, "UDP/TLS/RTP/SAVPF"),
            Protocol::TcpTlsRtpSavpf => write!(f, "TCP/TLS/RTP/SAVPF"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::fmt::Display for NetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IN")
    }
}

impl std::fmt::Display for AddrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddrType::IPv4 => write!(f, "IP4"),
            AddrType::IPv6 => write!(f, "IP6"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_audio_media() {
        let media = MediaDescription::audio(8000)
            .add_format(0)
            .unwrap()
            .add_format(8)
            .unwrap()
            .add_rtpmap(0, "PCMU", 8000, None)
            .unwrap()
            .add_rtpmap(8, "PCMA", 8000, None)
            .unwrap();

        assert_eq!(media.media_type, MediaType::Audio);
        assert_eq!(media.port, 8000);
        assert_eq!(
            media.formats.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
            vec!["0", "8"]
        );
        assert_eq!(media.rtpmaps.len(), 2);
    }

    #[test]
    fn builds_basic_sdp() {
        let sdp = SessionDescription::builder()
            .origin("alice", "123456", "192.168.1.100")
            .unwrap()
            .session_name("Test Call")
            .unwrap()
            .connection("192.168.1.100")
            .unwrap()
            .build();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.username.as_str(), "alice");
        assert_eq!(sdp.session_name.as_str(), "Test Call");
    }

    // Security tests: CRLF injection prevention
    #[test]
    fn rejects_crlf_in_username() {
        let result = Origin::new("alice\r\ninjected", "123", "192.168.1.100");
        assert!(matches!(result, Err(SdpError::FieldContainsControlChars { .. })));
    }

    #[test]
    fn rejects_crlf_in_session_id() {
        let result = Origin::new("alice", "123\r\n456", "192.168.1.100");
        assert!(matches!(result, Err(SdpError::FieldContainsControlChars { .. })));
    }

    #[test]
    fn rejects_crlf_in_address() {
        let result = Origin::new("alice", "123", "192.168.1.100\r\n");
        assert!(matches!(result, Err(SdpError::FieldContainsControlChars { .. })));
    }

    #[test]
    fn rejects_crlf_in_session_name() {
        let result = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test\r\nCall");
        assert!(matches!(result, Err(SdpError::FieldContainsControlChars { .. })));
    }

    #[test]
    fn rejects_crlf_in_attribute_name() {
        let result = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap()
            .attribute("send\r\nrecv", None);
        assert!(matches!(result, Err(SdpError::FieldContainsControlChars { .. })));
    }

    #[test]
    fn rejects_crlf_in_attribute_value() {
        let result = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap()
            .attribute("fmtp", Some("101\r\n0-16"));
        assert!(matches!(result, Err(SdpError::FieldContainsControlChars { .. })));
    }

    // Security tests: Field length limits
    #[test]
    fn rejects_oversized_username() {
        let long_username = "x".repeat(MAX_USERNAME_LENGTH + 1);
        let result = Origin::new(&long_username, "123", "192.168.1.100");
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_oversized_session_id() {
        let long_id = "x".repeat(MAX_SESSION_ID_LENGTH + 1);
        let result = Origin::new("alice", &long_id, "192.168.1.100");
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_oversized_address() {
        let long_addr = "x".repeat(MAX_ADDRESS_LENGTH + 1);
        let result = Origin::new("alice", "123", &long_addr);
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_oversized_session_name() {
        let long_name = "x".repeat(MAX_SESSION_NAME_LENGTH + 1);
        let result = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name(&long_name);
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_oversized_attribute_name() {
        let long_name = "x".repeat(MAX_ATTRIBUTE_NAME_LENGTH + 1);
        let result = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap()
            .attribute(&long_name, None);
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_oversized_attribute_value() {
        let long_value = "x".repeat(MAX_ATTRIBUTE_VALUE_LENGTH + 1);
        let result = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap()
            .attribute("test", Some(&long_value));
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    #[test]
    fn rejects_oversized_encoding_name() {
        let long_name = "x".repeat(MAX_ENCODING_NAME_LENGTH + 1);
        let result = MediaDescription::audio(8000).add_rtpmap(96, &long_name, 48000, None);
        assert!(matches!(result, Err(SdpError::FieldTooLong { .. })));
    }

    // Security tests: Collection bounds
    #[test]
    fn rejects_too_many_media_descriptions() {
        let mut builder = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap();

        // Add MAX_MEDIA_DESCRIPTIONS media descriptions
        for i in 0..MAX_MEDIA_DESCRIPTIONS {
            builder = builder
                .media(MediaDescription::audio(8000 + i as u16))
                .unwrap();
        }

        // Try to add one more - should fail
        let result = builder.media(MediaDescription::audio(9000));
        assert!(matches!(result, Err(SdpError::TooManyItems { .. })));
    }

    #[test]
    fn rejects_too_many_attributes() {
        let mut builder = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap();

        // Add MAX_ATTRIBUTES_PER_DESCRIPTION attributes
        for i in 0..MAX_ATTRIBUTES_PER_DESCRIPTION {
            builder = builder.attribute(&format!("attr{}", i), None).unwrap();
        }

        // Try to add one more - should fail
        let result = builder.attribute("overflow", None);
        assert!(matches!(result, Err(SdpError::TooManyItems { .. })));
    }

    #[test]
    fn rejects_too_many_formats() {
        let mut media = MediaDescription::audio(8000);

        // Add MAX_FORMATS_PER_MEDIA formats
        for i in 0..MAX_FORMATS_PER_MEDIA {
            let pt = i as u8;
            if pt > 127 {
                break;
            }
            media = media.add_format(pt).unwrap();
        }

        // Try to add one more - should fail
        let result = media.add_format(100);
        assert!(matches!(result, Err(SdpError::TooManyItems { .. })));
    }

    #[test]
    fn rejects_too_many_rtpmaps() {
        let mut media = MediaDescription::audio(8000);

        // Add MAX_RTPMAPS rtpmaps using payload types 0-49
        for i in 0..MAX_RTPMAPS {
            let pt = i as u8;
            media = media
                .add_format(pt)
                .unwrap()
                .add_rtpmap(pt, "codec", 8000, None)
                .unwrap();
        }

        // Try to add one more - should fail
        let result = media.add_rtpmap(127, "overflow", 8000, None);
        assert!(matches!(result, Err(SdpError::TooManyItems { .. })));
    }

    #[test]
    fn rejects_too_many_time_zones() {
        let mut builder = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap();

        // Add MAX_TIME_ZONES time zones
        for i in 0..MAX_TIME_ZONES {
            builder = builder
                .time_zone_adjustment(&format!("{}", i * 3600), "1h")
                .unwrap();
        }

        // Try to add one more - should fail
        let result = builder.time_zone_adjustment("36000", "1h");
        assert!(matches!(result, Err(SdpError::TooManyItems { .. })));
    }

    #[test]
    fn rejects_too_many_time_descriptions() {
        let mut builder = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Test")
            .unwrap()
            .time(0, 0);

        // Add MAX_TIME_DESCRIPTIONS - 1 more time descriptions (already added one with .time())
        for _ in 1..MAX_TIME_DESCRIPTIONS {
            builder = builder.add_time(0, 0).unwrap();
        }

        // Try to add one more - should fail
        let result = builder.add_time(0, 0);
        assert!(matches!(result, Err(SdpError::TooManyItems { .. })));
    }

    // Security tests: Value range validation
    #[test]
    fn rejects_invalid_payload_type() {
        let result = MediaDescription::audio(8000).add_format(128);
        assert!(matches!(result, Err(SdpError::InvalidPayloadType { .. })));
    }

    #[test]
    fn rejects_clock_rate_too_low() {
        let result = MediaDescription::audio(8000).add_rtpmap(96, "codec", 999, None);
        assert!(matches!(result, Err(SdpError::InvalidClockRate { .. })));
    }

    #[test]
    fn rejects_clock_rate_too_high() {
        let result = MediaDescription::audio(8000).add_rtpmap(96, "codec", 1_000_000_001, None);
        assert!(matches!(result, Err(SdpError::InvalidClockRate { .. })));
    }

    #[test]
    fn accepts_valid_clock_rates() {
        // Min valid clock rate
        let result = MediaDescription::audio(8000).add_rtpmap(96, "codec", MIN_CLOCK_RATE, None);
        assert!(result.is_ok());

        // Max valid clock rate
        let result = MediaDescription::audio(8000).add_rtpmap(96, "codec", MAX_CLOCK_RATE, None);
        assert!(result.is_ok());

        // Common clock rates
        let result = MediaDescription::audio(8000).add_rtpmap(0, "PCMU", 8000, None);
        assert!(result.is_ok());

        let result = MediaDescription::audio(8000).add_rtpmap(96, "opus", 48000, None);
        assert!(result.is_ok());

        let result = MediaDescription::video(8002).add_rtpmap(97, "H264", 90000, None);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_max_valid_payload_type() {
        let result = MediaDescription::audio(8000).add_format(127);
        assert!(result.is_ok());
    }
}
