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
//!     .origin("alice", "123456", "192.168.1.100")
//!     .session_name("VoIP Call")
//!     .connection("192.168.1.100")
//!     .media(MediaDescription::audio(8000)
//!         .add_format(0)  // PCMU
//!         .add_format(8)  // PCMA
//!         .add_rtpmap(0, "PCMU", 8000, None)
//!         .add_rtpmap(8, "PCMA", 8000, None))
//!     .build();
//! ```

pub mod builder;
pub mod negotiate;
pub mod parse;
pub mod profiles;
pub mod serialize;

use smol_str::SmolStr;
use std::collections::HashMap;

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
    ///     .origin("alice", "123456", "192.168.1.100")
    ///     .session_name("VoIP Call")
    ///     .connection("192.168.1.100")
    ///     .media(MediaDescription::audio(8000)
    ///         .add_format(0)
    ///         .add_rtpmap(0, "PCMU", 8000, None))
    ///     .build();
    ///
    /// let sdp_text = sdp.to_string();
    /// assert!(sdp_text.contains("v=0\r\n"));
    /// assert!(sdp_text.contains("m=audio 8000 RTP/AVP 0\r\n"));
    /// ```
    pub fn to_string(&self) -> String {
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
    ///     .origin("bob", "456", "10.0.0.1")
    ///     .session_name("Conference")
    ///     .connection("10.0.0.1")
    ///     .media(MediaDescription::audio(9000).add_format(0))
    ///     .media(MediaDescription::video(9002).add_format(96))
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
    ///     .origin("charlie", "789", "172.16.0.1")
    ///     .session_name("Multi-Audio")
    ///     .connection("172.16.0.1")
    ///     .media(MediaDescription::audio(5000).add_format(0))
    ///     .media(MediaDescription::audio(5002).add_format(8))
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

    /// Adds a format (payload type)
    pub fn add_format(mut self, payload_type: u8) -> Self {
        self.formats.push(SmolStr::new(payload_type.to_string()));
        self
    }

    /// Adds a format token (non-RTP or custom)
    pub fn add_format_token(mut self, token: &str) -> Self {
        self.formats.push(SmolStr::new(token));
        self
    }

    /// Adds an RTP map
    pub fn add_rtpmap(
        mut self,
        payload_type: u8,
        encoding_name: &str,
        clock_rate: u32,
        encoding_params: Option<&str>,
    ) -> Self {
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
        self
    }

    /// Adds a property attribute
    pub fn add_property(mut self, name: &str) -> Self {
        self.attributes
            .push(Attribute::Property(SmolStr::new(name)));
        self
    }

    /// Adds a value attribute
    pub fn add_attribute(mut self, name: &str, value: &str) -> Self {
        self.attributes.push(Attribute::Value {
            name: SmolStr::new(name),
            value: SmolStr::new(value),
        });
        self
    }

    /// Sets the connection for this media
    pub fn connection(mut self, addr: &str) -> Self {
        self.connection = Some(Connection {
            net_type: NetType::Internet,
            addr_type: if addr.contains(':') {
                AddrType::IPv6
            } else {
                AddrType::IPv4
            },
            connection_address: SmolStr::new(addr),
        });
        self
    }

    /// Sets the media direction (sendrecv, sendonly, recvonly, inactive)
    pub fn direction(self, dir: &str) -> Self {
        self.add_property(dir)
    }
}

impl Origin {
    /// Creates a new origin line
    pub fn new(username: &str, session_id: &str, addr: &str) -> Self {
        Self {
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
        }
    }
}

impl Connection {
    /// Creates a new connection line
    pub fn new(addr: &str) -> Self {
        Self {
            net_type: NetType::Internet,
            addr_type: if addr.contains(':') {
                AddrType::IPv6
            } else {
                AddrType::IPv4
            },
            connection_address: SmolStr::new(addr),
        }
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
            .add_format(8)
            .add_rtpmap(0, "PCMU", 8000, None)
            .add_rtpmap(8, "PCMA", 8000, None);

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
            .session_name("Test Call")
            .connection("192.168.1.100")
            .build();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.username.as_str(), "alice");
        assert_eq!(sdp.session_name.as_str(), "Test Call");
    }
}
