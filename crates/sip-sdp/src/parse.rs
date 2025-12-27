// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SDP parser implementing RFC 4566
//!
//! Parses text-based SDP into SessionDescription structures using nom combinators.

use crate::*;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{char, digit1, line_ending, space1},
    combinator::{map, map_res, opt},
    multi::{many0, separated_list0},
    sequence::{preceded, terminated, tuple},
    IResult,
};
use std::collections::HashMap;

/// Error type for SDP parsing failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Missing required field
    MissingField(&'static str),
    /// Invalid field format
    InvalidFormat(&'static str, String),
    /// Parsing failed
    ParseFailed(String),
    /// Invalid protocol version (must be 0)
    InvalidVersion(u8),
    /// Input exceeds configured limits
    LimitExceeded(&'static str, usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::MissingField(field) => write!(f, "Missing required SDP field: {}", field),
            ParseError::InvalidFormat(field, reason) => {
                write!(f, "Invalid format for {}: {}", field, reason)
            }
            ParseError::ParseFailed(msg) => write!(f, "SDP parsing failed: {}", msg),
            ParseError::InvalidVersion(v) => write!(f, "Invalid SDP version: {} (must be 0)", v),
            ParseError::LimitExceeded(what, limit) => {
                write!(f, "SDP input exceeds limit for {}: {}", what, limit)
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses a complete SDP session description
pub fn parse_sdp(input: &str) -> Result<SessionDescription, ParseError> {
    parse_sdp_with_limits(input, ParseLimits::default())
}

/// Limits for parsing SDP input
#[derive(Debug, Clone, Copy)]
pub struct ParseLimits {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub max_line_length: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: 128 * 1024,
            max_lines: 2048,
            max_line_length: 4096,
        }
    }
}

/// Parses a complete SDP session description with limits
pub fn parse_sdp_with_limits(
    input: &str,
    limits: ParseLimits,
) -> Result<SessionDescription, ParseError> {
    if input.len() > limits.max_bytes {
        return Err(ParseError::LimitExceeded("bytes", limits.max_bytes));
    }

    let mut line_count = 0usize;
    for line in input.lines() {
        if line.is_empty() {
            continue;
        }
        line_count += 1;
        if line_count > limits.max_lines {
            return Err(ParseError::LimitExceeded("lines", limits.max_lines));
        }
        if line.len() > limits.max_line_length {
            return Err(ParseError::LimitExceeded("line length", limits.max_line_length));
        }
    }

    // Parse all lines into a structured format first
    let (remaining, lines) =
        parse_sdp_lines(input).map_err(|e| ParseError::ParseFailed(e.to_string()))?;

    // Check if there's unparsed input (should be empty or just whitespace)
    if !remaining.trim().is_empty() {
        return Err(ParseError::ParseFailed(format!(
            "Unparsed input remaining: {}",
            remaining
        )));
    }

    // Build SessionDescription from parsed lines
    build_session_description(lines)
}

/// Represents a parsed SDP line
#[derive(Debug, Clone)]
enum SdpLine {
    Version(u8),
    Origin(Origin),
    SessionName(SmolStr),
    Info(SmolStr),
    Uri(SmolStr),
    Email(SmolStr),
    Phone(SmolStr),
    Connection(Connection),
    Bandwidth(Bandwidth),
    Time(TimeDescription),
    Repeat(RepeatTime),
    TimeZone(Vec<TimeZoneAdjustment>),
    EncryptionKey(SmolStr),
    Attribute(Attribute),
    Media(MediaBlock),
}

/// Media block with its attributes
#[derive(Debug, Clone)]
struct MediaBlock {
    media_type: MediaType,
    port: u16,
    num_ports: Option<u16>,
    protocol: Protocol,
    formats: Vec<SmolStr>,
    title: Option<SmolStr>,
    connection: Option<Connection>,
    bandwidth: Vec<Bandwidth>,
    encryption_key: Option<SmolStr>,
    attributes: Vec<Attribute>,
}

/// Parse all SDP lines
fn parse_sdp_lines(input: &str) -> IResult<&str, Vec<SdpLine>> {
    many0(terminated(parse_line, opt(line_ending)))(input)
}

/// Parse a single SDP line
fn parse_line(input: &str) -> IResult<&str, SdpLine> {
    alt((
        map(parse_v_line, SdpLine::Version),
        map(parse_o_line, SdpLine::Origin),
        map(parse_s_line, SdpLine::SessionName),
        map(parse_i_line, SdpLine::Info),
        map(parse_u_line, SdpLine::Uri),
        map(parse_e_line, SdpLine::Email),
        map(parse_p_line, SdpLine::Phone),
        map(parse_c_line, SdpLine::Connection),
        map(parse_b_line, SdpLine::Bandwidth),
        map(parse_t_line, SdpLine::Time),
        map(parse_r_line, SdpLine::Repeat),
        map(parse_z_line, SdpLine::TimeZone),
        map(parse_k_line, SdpLine::EncryptionKey),
        map(parse_a_line, SdpLine::Attribute),
        map(parse_m_line, SdpLine::Media),
    ))(input)
}

/// Parse version line: v=0
fn parse_v_line(input: &str) -> IResult<&str, u8> {
    preceded(tag("v="), map_res(digit1, |s: &str| s.parse::<u8>()))(input)
}

/// Parse origin line: o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
fn parse_o_line(input: &str) -> IResult<&str, Origin> {
    preceded(
        tag("o="),
        map(
            tuple((
                terminated(take_till(|c| c == ' '), space1),
                terminated(take_till(|c| c == ' '), space1),
                terminated(take_till(|c| c == ' '), space1),
                terminated(parse_nettype, space1),
                terminated(parse_addrtype, space1),
                take_till(|c| c == '\r' || c == '\n'),
            )),
            |(username, sess_id, sess_version, net_type, addr_type, unicast_address)| Origin {
                username: SmolStr::new(username),
                session_id: SmolStr::new(sess_id),
                session_version: SmolStr::new(sess_version),
                net_type,
                addr_type,
                unicast_address: SmolStr::new(unicast_address.trim()),
            },
        ),
    )(input)
}

/// Parse session name line: s=<session name>
fn parse_s_line(input: &str) -> IResult<&str, SmolStr> {
    preceded(
        tag("s="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            SmolStr::new(s.trim())
        }),
    )(input)
}

/// Parse session information line: i=<session description>
fn parse_i_line(input: &str) -> IResult<&str, SmolStr> {
    preceded(
        tag("i="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            SmolStr::new(s.trim())
        }),
    )(input)
}

/// Parse URI line: u=<uri>
fn parse_u_line(input: &str) -> IResult<&str, SmolStr> {
    preceded(
        tag("u="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            SmolStr::new(s.trim())
        }),
    )(input)
}

/// Parse email line: e=<email address>
fn parse_e_line(input: &str) -> IResult<&str, SmolStr> {
    preceded(
        tag("e="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            SmolStr::new(s.trim())
        }),
    )(input)
}

/// Parse phone line: p=<phone number>
fn parse_p_line(input: &str) -> IResult<&str, SmolStr> {
    preceded(
        tag("p="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            SmolStr::new(s.trim())
        }),
    )(input)
}

/// Parse connection line: c=<nettype> <addrtype> <connection-address>
fn parse_c_line(input: &str) -> IResult<&str, Connection> {
    preceded(
        tag("c="),
        map(
            tuple((
                terminated(parse_nettype, space1),
                terminated(parse_addrtype, space1),
                take_till(|c| c == '\r' || c == '\n'),
            )),
            |(net_type, addr_type, connection_address)| Connection {
                net_type,
                addr_type,
                connection_address: SmolStr::new(connection_address.trim()),
            },
        ),
    )(input)
}

/// Parse bandwidth line: b=<bwtype>:<bandwidth>
fn parse_b_line(input: &str) -> IResult<&str, Bandwidth> {
    preceded(
        tag("b="),
        map(
            tuple((
                take_till(|c| c == ':'),
                preceded(char(':'), map_res(digit1, |s: &str| s.parse::<u32>())),
            )),
            |(bw_type, bandwidth)| Bandwidth {
                bw_type: SmolStr::new(bw_type),
                bandwidth,
            },
        ),
    )(input)
}

/// Parse time description line: t=<start-time> <stop-time>
fn parse_t_line(input: &str) -> IResult<&str, TimeDescription> {
    preceded(
        tag("t="),
        map(
            tuple((
                terminated(map_res(digit1, |s: &str| s.parse::<u64>()), space1),
                map_res(digit1, |s: &str| s.parse::<u64>()),
            )),
            |(start_time, stop_time)| TimeDescription {
                start_time,
                stop_time,
                repeats: Vec::new(),
            },
        ),
    )(input)
}

/// Parse repeat time line: r=<repeat interval> <active duration> <offsets...>
fn parse_r_line(input: &str) -> IResult<&str, RepeatTime> {
    preceded(
        tag("r="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            let parts: Vec<&str> = s.split_whitespace().collect();
            let repeat_interval = parts.first().copied().unwrap_or("");
            let active_duration = parts.get(1).copied().unwrap_or("");
            let offsets = parts
                .iter()
                .skip(2)
                .map(|v| SmolStr::new(*v))
                .collect();

            RepeatTime {
                repeat_interval: SmolStr::new(repeat_interval),
                active_duration: SmolStr::new(active_duration),
                offsets,
            }
        }),
    )(input)
}

/// Parse time zone adjustments: z=<adjustment-time> <offset> ...
fn parse_z_line(input: &str) -> IResult<&str, Vec<TimeZoneAdjustment>> {
    preceded(
        tag("z="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            let parts: Vec<&str> = s.split_whitespace().collect();
            let mut adjustments = Vec::new();

            let mut iter = parts.chunks_exact(2);
            for chunk in &mut iter {
                adjustments.push(TimeZoneAdjustment {
                    adjustment_time: SmolStr::new(chunk[0]),
                    offset: SmolStr::new(chunk[1]),
                });
            }
            if !iter.remainder().is_empty() {
                adjustments.push(TimeZoneAdjustment {
                    adjustment_time: SmolStr::new(iter.remainder()[0]),
                    offset: SmolStr::new(""),
                });
            }

            adjustments
        }),
    )(input)
}

/// Parse encryption key line: k=<method> or k=<method>:<key>
fn parse_k_line(input: &str) -> IResult<&str, SmolStr> {
    preceded(
        tag("k="),
        map(take_till(|c| c == '\r' || c == '\n'), |s: &str| {
            SmolStr::new(s.trim())
        }),
    )(input)
}

/// Parse attribute line: a=<attribute> or a=<attribute>:<value>
fn parse_a_line(input: &str) -> IResult<&str, Attribute> {
    preceded(
        tag("a="),
        alt((
            map(
                tuple((
                    take_till(|c| c == ':'),
                    preceded(char(':'), take_till(|c| c == '\r' || c == '\n')),
                )),
                |(name, value): (&str, &str)| Attribute::Value {
                    name: SmolStr::new(name),
                    value: SmolStr::new(value.trim()),
                },
            ),
            map(take_till(|c| c == '\r' || c == '\n'), |name: &str| {
                Attribute::Property(SmolStr::new(name.trim()))
            }),
        )),
    )(input)
}

/// Parse media description line: m=<media> <port> <proto> <fmt> ...
fn parse_m_line(input: &str) -> IResult<&str, MediaBlock> {
    preceded(
        tag("m="),
        map(
            tuple((
                terminated(parse_media_type, space1),
                terminated(parse_port, space1),
                terminated(parse_protocol, space1),
                separated_list0(
                    space1,
                    map(take_till(|c| c == ' ' || c == '\r' || c == '\n'), |s: &str| {
                        SmolStr::new(s)
                    }),
                ),
            )),
            |(media_type, (port, num_ports), protocol, formats)| MediaBlock {
                media_type,
                port,
                num_ports,
                protocol,
                formats,
                title: None,
                connection: None,
                bandwidth: Vec::new(),
                encryption_key: None,
                attributes: Vec::new(),
            },
        ),
    )(input)
}

/// Parse media type: audio, video, text, application, message
fn parse_media_type(input: &str) -> IResult<&str, MediaType> {
    map(
        take_till(|c| c == ' ' || c == '\r' || c == '\n'),
        |name: &str| match name {
            "audio" => MediaType::Audio,
            "video" => MediaType::Video,
            "text" => MediaType::Text,
            "application" => MediaType::Application,
            "message" => MediaType::Message,
            other => MediaType::Other(SmolStr::new(other)),
        },
    )(input)
}

/// Parse port with optional port count: <port> or <port>/<num_ports>
fn parse_port(input: &str) -> IResult<&str, (u16, Option<u16>)> {
    map(
        tuple((
            map_res(digit1, |s: &str| s.parse::<u16>()),
            opt(preceded(
                char('/'),
                map_res(digit1, |s: &str| s.parse::<u16>()),
            )),
        )),
        |(port, num_ports)| (port, num_ports),
    )(input)
}

/// Parse protocol: RTP/AVP, RTP/SAVP, RTP/SAVPF, UDP/TLS/RTP/SAVPF, TCP/TLS/RTP/SAVPF, UDP, TCP, etc.
fn parse_protocol(input: &str) -> IResult<&str, Protocol> {
    alt((
        // WebRTC protocols (longest first to avoid partial matches)
        map(tag("UDP/TLS/RTP/SAVPF"), |_| Protocol::UdpTlsRtpSavpf),
        map(tag("TCP/TLS/RTP/SAVPF"), |_| Protocol::TcpTlsRtpSavpf),
        map(tag("RTP/SAVPF"), |_| Protocol::RtpSavpf),
        // Traditional RTP protocols
        map(tag("RTP/SAVP"), |_| Protocol::RtpSavp),
        map(tag("RTP/AVP"), |_| Protocol::RtpAvp),
        // Basic protocols
        map(tag("UDP"), |_| Protocol::Udp),
        map(tag("TCP"), |_| Protocol::Tcp),
        // Fallback for unknown protocols
        map(
            take_till(|c| c == ' ' || c == '\r' || c == '\n'),
            |s: &str| Protocol::Other(SmolStr::new(s)),
        ),
    ))(input)
}

/// Parse network type: IN (Internet)
fn parse_nettype(input: &str) -> IResult<&str, NetType> {
    map(tag("IN"), |_| NetType::Internet)(input)
}

/// Parse address type: IP4, IP6
fn parse_addrtype(input: &str) -> IResult<&str, AddrType> {
    alt((
        map(tag("IP4"), |_| AddrType::IPv4),
        map(tag("IP6"), |_| AddrType::IPv6),
    ))(input)
}

/// Build SessionDescription from parsed lines
fn build_session_description(lines: Vec<SdpLine>) -> Result<SessionDescription, ParseError> {
    let mut version = None;
    let mut origin = None;
    let mut session_name = None;
    let mut session_info = None;
    let mut uri = None;
    let mut email = None;
    let mut phone = None;
    let mut connection = None;
    let mut bandwidth = Vec::new();
    let mut times = Vec::new();
    let mut current_time: Option<TimeDescription> = None;
    let mut time_zones = Vec::new();
    let mut encryption_key = None;
    let mut attributes = Vec::new();
    let mut media_blocks = Vec::new();
    let mut current_media: Option<MediaBlock> = None;

    for line in lines {
        match line {
            SdpLine::Version(v) => version = Some(v),
            SdpLine::Origin(o) => origin = Some(o),
            SdpLine::SessionName(s) => session_name = Some(s),
            SdpLine::Info(i) => {
                if let Some(ref mut m) = current_media {
                    m.title = Some(i);
                } else {
                    session_info = Some(i);
                }
            }
            SdpLine::Uri(u) => uri = Some(u),
            SdpLine::Email(e) => email = Some(e),
            SdpLine::Phone(p) => phone = Some(p),
            SdpLine::Connection(c) => {
                if let Some(ref mut m) = current_media {
                    m.connection = Some(c);
                } else {
                    connection = Some(c);
                }
            }
            SdpLine::Bandwidth(b) => {
                if let Some(ref mut m) = current_media {
                    m.bandwidth.push(b);
                } else {
                    bandwidth.push(b);
                }
            }
            SdpLine::Time(t) => {
                if let Some(finished) = current_time.take() {
                    times.push(finished);
                }
                current_time = Some(t);
            }
            SdpLine::Repeat(r) => {
                let repeat = normalize_repeat(r)?;
                if let Some(ref mut time) = current_time {
                    time.repeats.push(repeat);
                } else {
                    return Err(ParseError::InvalidFormat(
                        "r=",
                        "repeat without time description".to_string(),
                    ));
                }
            }
            SdpLine::TimeZone(z) => {
                let normalized = normalize_time_zones(z)?;
                time_zones.extend(normalized);
            }
            SdpLine::EncryptionKey(key) => {
                if let Some(ref mut m) = current_media {
                    m.encryption_key = Some(key);
                } else {
                    encryption_key = Some(key);
                }
            }
            SdpLine::Attribute(a) => {
                if let Some(ref mut m) = current_media {
                    m.attributes.push(a);
                } else {
                    attributes.push(a);
                }
            }
            SdpLine::Media(m) => {
                // Finish previous media block if any
                if let Some(finished_media) = current_media.take() {
                    media_blocks.push(finished_media);
                }
                current_media = Some(m);
            }
        }
    }

    // Finish last media block if any
    if let Some(finished_media) = current_media.take() {
        media_blocks.push(finished_media);
    }

    if let Some(finished_time) = current_time.take() {
        times.push(finished_time);
    }

    // Validate required fields
    let version = version.ok_or(ParseError::MissingField("v= (version)"))?;
    if version != 0 {
        return Err(ParseError::InvalidVersion(version));
    }

    let origin = origin.ok_or(ParseError::MissingField("o= (origin)"))?;
    let session_name = session_name.ok_or(ParseError::MissingField("s= (session name)"))?;
    if times.is_empty() {
        return Err(ParseError::MissingField("t= (time)"));
    }

    // Convert media blocks to MediaDescription
    let media = media_blocks
        .into_iter()
        .map(|block| {
            validate_media_formats(&block)?;
            // Extract rtpmaps from attributes
            let mut rtpmaps = HashMap::new();
            for attr in &block.attributes {
                if let Attribute::Value { name, value } = attr {
                    if name.as_str() == "rtpmap" {
                        if let Some(rtpmap) = parse_rtpmap(value.as_str()) {
                            rtpmaps.insert(rtpmap.payload_type, rtpmap);
                        }
                    }
                }
            }

            Ok(MediaDescription {
                media_type: block.media_type,
                port: block.port,
                num_ports: block.num_ports,
                protocol: block.protocol,
                formats: block.formats,
                title: block.title,
                connection: block.connection,
                bandwidth: block.bandwidth,
                encryption_key: block.encryption_key,
                attributes: block.attributes,
                rtpmaps,
            })
        })
        .collect::<Result<Vec<_>, ParseError>>()?;

    Ok(SessionDescription {
        version,
        origin,
        session_name,
        session_info,
        uri,
        email,
        phone,
        connection,
        bandwidth,
        times,
        time_zones,
        encryption_key,
        attributes,
        media,
    })
}

fn normalize_repeat(repeat: RepeatTime) -> Result<RepeatTime, ParseError> {
    if repeat.repeat_interval.is_empty() || repeat.active_duration.is_empty() {
        return Err(ParseError::InvalidFormat(
            "r=",
            "repeat interval or duration missing".to_string(),
        ));
    }
    Ok(repeat)
}

fn normalize_time_zones(
    zones: Vec<TimeZoneAdjustment>,
) -> Result<Vec<TimeZoneAdjustment>, ParseError> {
    if zones.is_empty() {
        return Err(ParseError::InvalidFormat(
            "z=",
            "missing time zone adjustments".to_string(),
        ));
    }
    if zones
        .iter()
        .any(|z| z.adjustment_time.is_empty() || z.offset.is_empty())
    {
        return Err(ParseError::InvalidFormat(
            "z=",
            "invalid time zone adjustment pair".to_string(),
        ));
    }
    Ok(zones)
}

fn validate_media_formats(block: &MediaBlock) -> Result<(), ParseError> {
    if matches!(&block.media_type, MediaType::Other(name) if name.is_empty()) {
        return Err(ParseError::InvalidFormat(
            "m=",
            "missing media type".to_string(),
        ));
    }
    if block.formats.is_empty() {
        return Err(ParseError::InvalidFormat(
            "m=",
            "missing format list".to_string(),
        ));
    }
    if block.formats.iter().any(|f| f.is_empty()) {
        return Err(ParseError::InvalidFormat(
            "m=",
            "empty format token".to_string(),
        ));
    }

    if is_rtp_protocol(&block.protocol) {
        for fmt in &block.formats {
            let token = fmt.as_str();
            let value = token.parse::<u16>().map_err(|_| {
                ParseError::InvalidFormat(
                    "m=",
                    format!("non-numeric RTP payload type: {}", token),
                )
            })?;
            if value > 127 {
                return Err(ParseError::InvalidFormat(
                    "m=",
                    format!("RTP payload type out of range: {}", value),
                ));
            }
        }
    }

    Ok(())
}

fn is_rtp_protocol(protocol: &Protocol) -> bool {
    matches!(
        protocol,
        Protocol::RtpAvp
            | Protocol::RtpSavp
            | Protocol::RtpSavpf
            | Protocol::UdpTlsRtpSavpf
            | Protocol::TcpTlsRtpSavpf
    )
}

/// Parse rtpmap attribute value: <payload> <encoding>/<clock> or <payload> <encoding>/<clock>/<params>
fn parse_rtpmap(value: &str) -> Option<RtpMap> {
    let parts: Vec<&str> = value.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let payload_type = parts[0].parse::<u8>().ok()?;
    let encoding_parts: Vec<&str> = parts[1].split('/').collect();

    if encoding_parts.len() < 2 {
        return None;
    }

    let encoding_name = SmolStr::new(encoding_parts[0]);
    let clock_rate = encoding_parts[1].parse::<u32>().ok()?;
    let encoding_params = encoding_parts.get(2).map(|s| SmolStr::new(*s));

    Some(RtpMap {
        payload_type,
        encoding_name,
        clock_rate,
        encoding_params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_audio_sdp() {
        let sdp = "v=0\r\n\
                   o=alice 123456 0 IN IP4 192.168.1.100\r\n\
                   s=Test Session\r\n\
                   c=IN IP4 192.168.1.100\r\n\
                   t=0 0\r\n\
                   m=audio 8000 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";

        let result = parse_sdp(sdp).unwrap();

        assert_eq!(result.version, 0);
        assert_eq!(result.origin.username.as_str(), "alice");
        assert_eq!(result.origin.session_id.as_str(), "123456");
        assert_eq!(result.session_name.as_str(), "Test Session");
        assert_eq!(result.media.len(), 1);
        assert_eq!(result.media[0].media_type, MediaType::Audio);
        assert_eq!(result.media[0].port, 8000);
        assert_eq!(
            result.media[0]
                .formats
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>(),
            vec!["0", "8"]
        );
        assert_eq!(result.media[0].rtpmaps.len(), 2);
    }

    #[test]
    fn parses_audio_video_sdp() {
        let sdp = "v=0\r\n\
                   o=bob 654321 0 IN IP4 10.0.0.1\r\n\
                   s=Video Call\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 9000 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   m=video 9002 RTP/AVP 96\r\n\
                   a=rtpmap:96 H264/90000\r\n";

        let result = parse_sdp(sdp).unwrap();

        assert_eq!(result.media.len(), 2);
        assert_eq!(result.media[0].media_type, MediaType::Audio);
        assert_eq!(result.media[1].media_type, MediaType::Video);
        assert_eq!(result.media[1].rtpmaps[&96].encoding_name.as_str(), "H264");
    }

    #[test]
    fn parses_optional_fields() {
        let sdp = "v=0\r\n\
                   o=charlie 111 0 IN IP4 172.16.0.1\r\n\
                   s=Full Session\r\n\
                   i=Test session with all fields\r\n\
                   u=http://example.com\r\n\
                   e=charlie@example.com\r\n\
                   p=+1-555-1234\r\n\
                   c=IN IP4 172.16.0.1\r\n\
                   b=AS:256\r\n\
                   t=0 0\r\n\
                   a=sendrecv\r\n\
                   m=audio 5004 RTP/AVP 0\r\n";

        let result = parse_sdp(sdp).unwrap();

        assert_eq!(
            result.session_info.as_ref().unwrap().as_str(),
            "Test session with all fields"
        );
        assert_eq!(result.uri.as_ref().unwrap().as_str(), "http://example.com");
        assert_eq!(
            result.email.as_ref().unwrap().as_str(),
            "charlie@example.com"
        );
        assert_eq!(result.phone.as_ref().unwrap().as_str(), "+1-555-1234");
        assert_eq!(result.bandwidth.len(), 1);
        assert_eq!(result.bandwidth[0].bw_type.as_str(), "AS");
        assert_eq!(result.bandwidth[0].bandwidth, 256);
    }

    #[test]
    fn rejects_missing_required_fields() {
        // Missing origin
        let sdp = "v=0\r\ns=Test\r\nt=0 0\r\n";
        assert!(parse_sdp(sdp).is_err());

        // Missing session name
        let sdp = "v=0\r\no=alice 123 0 IN IP4 1.2.3.4\r\nt=0 0\r\n";
        assert!(parse_sdp(sdp).is_err());

        // Missing time
        let sdp = "v=0\r\no=alice 123 0 IN IP4 1.2.3.4\r\ns=Test\r\n";
        assert!(parse_sdp(sdp).is_err());
    }

    #[test]
    fn rejects_invalid_version() {
        let sdp = "v=1\r\no=alice 123 0 IN IP4 1.2.3.4\r\ns=Test\r\nt=0 0\r\n";
        match parse_sdp(sdp) {
            Err(ParseError::InvalidVersion(1)) => {}
            _ => panic!("Expected InvalidVersion error"),
        }
    }

    #[test]
    fn parses_time_repeat_zones_and_keys() {
        let sdp = "v=0\r\n\
                   o=alice 123 0 IN IP4 192.0.2.1\r\n\
                   s=Test\r\n\
                   t=0 0\r\n\
                   r=7d 1h 0 25h\r\n\
                   z=2882844526 -1h 2898848070 0\r\n\
                   k=clear:secret\r\n\
                   m=audio 5004 RTP/AVP 0\r\n\
                   i=Audio Stream\r\n\
                   k=prompt\r\n";

        let result = parse_sdp(sdp).unwrap();
        assert_eq!(result.times.len(), 1);
        assert_eq!(result.times[0].repeats.len(), 1);
        assert_eq!(result.time_zones.len(), 2);
        assert_eq!(result.encryption_key.as_deref(), Some("clear:secret"));
        assert_eq!(result.media.len(), 1);
        assert_eq!(result.media[0].title.as_deref(), Some("Audio Stream"));
        assert_eq!(result.media[0].encryption_key.as_deref(), Some("prompt"));
    }
}
