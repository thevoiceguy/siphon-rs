//! RFC 3264 Offer/Answer Model implementation
//!
//! Implements SDP offer/answer negotiation for establishing media sessions.
//! Handles codec negotiation, media stream matching, and direction negotiation.

use crate::*;
use std::collections::HashMap;

/// Error type for negotiation failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    /// No common codec found for media stream
    NoCommonCodec(MediaType),
    /// Incompatible media direction
    IncompatibleDirection,
    /// Missing required media stream
    MissingMediaStream(MediaType),
    /// Invalid SDP structure
    InvalidSdp(String),
}

impl std::fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NegotiationError::NoCommonCodec(media_type) => {
                write!(f, "No common codec found for {:?} media", media_type)
            }
            NegotiationError::IncompatibleDirection => {
                write!(f, "Incompatible media direction")
            }
            NegotiationError::MissingMediaStream(media_type) => {
                write!(f, "Missing required {:?} media stream", media_type)
            }
            NegotiationError::InvalidSdp(msg) => write!(f, "Invalid SDP: {}", msg),
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Media direction per RFC 3264
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Can send and receive
    SendRecv,
    /// Can only send
    SendOnly,
    /// Can only receive
    RecvOnly,
    /// Inactive (neither send nor receive)
    Inactive,
}

impl Direction {
    /// Parse direction from SDP attribute
    pub fn from_attribute(attr: &Attribute) -> Option<Self> {
        match attr {
            Attribute::Property(name) => match name.as_str() {
                "sendrecv" => Some(Direction::SendRecv),
                "sendonly" => Some(Direction::SendOnly),
                "recvonly" => Some(Direction::RecvOnly),
                "inactive" => Some(Direction::Inactive),
                _ => None,
            },
            _ => None,
        }
    }

    /// Get the direction from answerer's perspective
    pub fn reverse(&self) -> Self {
        match self {
            Direction::SendRecv => Direction::SendRecv,
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            Direction::Inactive => Direction::Inactive,
        }
    }

    /// Check if this direction is compatible with another
    ///
    /// Two directions are compatible if they can establish media flow:
    /// - Inactive is only compatible with Inactive (no media flow)
    /// - SendRecv is compatible with any active direction
    /// - SendOnly is compatible with RecvOnly (unidirectional flow)
    /// - RecvOnly is compatible with SendOnly (unidirectional flow)
    pub fn is_compatible_with(&self, other: &Direction) -> bool {
        match (self, other) {
            // Inactive is only compatible with Inactive
            (Direction::Inactive, Direction::Inactive) => true,
            (Direction::Inactive, _) | (_, Direction::Inactive) => false,
            // SendRecv is compatible with any active direction
            (Direction::SendRecv, _) | (_, Direction::SendRecv) => true,
            // Unidirectional compatibility
            (Direction::SendOnly, Direction::RecvOnly) => true,
            (Direction::RecvOnly, Direction::SendOnly) => true,
            // Same direction (SendOnly/SendOnly or RecvOnly/RecvOnly) is incompatible
            _ => false,
        }
    }

    /// Negotiate direction between offer and answer
    pub fn negotiate(&self, answer_dir: &Direction) -> Result<Direction, NegotiationError> {
        if !self.is_compatible_with(answer_dir) {
            return Err(NegotiationError::IncompatibleDirection);
        }

        // Result is the more restrictive of the two
        Ok(match (self, answer_dir) {
            (Direction::Inactive, _) | (_, Direction::Inactive) => Direction::Inactive,
            (Direction::SendRecv, d) | (d, Direction::SendRecv) => *d,
            (Direction::SendOnly, Direction::RecvOnly) => Direction::SendOnly,
            (Direction::RecvOnly, Direction::SendOnly) => Direction::RecvOnly,
            (d1, d2) if d1 == d2 => *d1,
            _ => Direction::Inactive,
        })
    }
}

/// Negotiates an SDP answer from an offer
///
/// Implements RFC 3264 offer/answer model:
/// - Match media streams by type
/// - Negotiate common codecs (payload types)
/// - Negotiate media direction
/// - Generate appropriate answer
///
/// # Example
/// ```
/// use sip_sdp::{SessionDescription, MediaDescription, negotiate};
///
/// // Remote offer with PCMU and PCMA
/// let offer = SessionDescription::builder()
///     .origin("alice", "123", "192.168.1.100")
///     .session_name("Call")
///     .connection("192.168.1.100")
///     .media(MediaDescription::audio(8000)
///         .add_format(0)  // PCMU
///         .add_format(8)  // PCMA
///         .add_rtpmap(0, "PCMU", 8000, None)
///         .add_rtpmap(8, "PCMA", 8000, None))
///     .build();
///
/// // Local capabilities (only support PCMU)
/// let local_caps = SessionDescription::builder()
///     .origin("bob", "456", "10.0.0.1")
///     .session_name("Server")
///     .connection("10.0.0.1")
///     .media(MediaDescription::audio(9000)
///         .add_format(0)  // PCMU only
///         .add_rtpmap(0, "PCMU", 8000, None))
///     .build();
///
/// // Negotiate answer
/// let answer = negotiate::negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();
///
/// // Answer should only include PCMU (common codec)
/// assert_eq!(answer.media.len(), 1);
/// assert_eq!(answer.media[0].formats.len(), 1);
/// assert_eq!(answer.media[0].formats[0].as_str(), "0");
/// ```
pub fn negotiate_answer(
    offer: &SessionDescription,
    local_addr: &str,
    local_capabilities: &SessionDescription,
) -> Result<SessionDescription, NegotiationError> {
    let mut answer_builder = SessionDescription::builder()
        .origin(
            &local_capabilities.origin.username,
            &generate_session_id(),
            local_addr,
        )
        .session_name(&local_capabilities.session_name)
        .connection(local_addr)
        .time(0, 0);

    // Process each media stream in the offer
    for offer_media in &offer.media {
        match negotiate_media(offer_media, local_capabilities) {
            Ok(answer_media) => {
                answer_builder = answer_builder.media(answer_media);
            }
            Err(NegotiationError::NoCommonCodec(_))
            | Err(NegotiationError::MissingMediaStream(_)) => {
                // No common codec or unsupported media type - include rejected media (port 0)
                let rejected = create_rejected_media(offer_media);
                answer_builder = answer_builder.media(rejected);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(answer_builder.build())
}

/// Negotiate a single media stream
fn negotiate_media(
    offer_media: &MediaDescription,
    local_capabilities: &SessionDescription,
) -> Result<MediaDescription, NegotiationError> {
    // Find matching media type in local capabilities
    let local_media = local_capabilities
        .find_media(offer_media.media_type.clone())
        .ok_or(NegotiationError::MissingMediaStream(
            offer_media.media_type.clone(),
        ))?;

    if offer_media.protocol != local_media.protocol {
        return Err(NegotiationError::NoCommonCodec(offer_media.media_type.clone()));
    }

    // Find common codecs (payload types)
    let common_formats = find_common_formats(offer_media, local_media);

    if common_formats.is_empty() {
        return Err(NegotiationError::NoCommonCodec(offer_media.media_type.clone()));
    }

    // Get directions
    let offer_dir = extract_direction(&offer_media.attributes).unwrap_or(Direction::SendRecv);
    let local_dir = extract_direction(&local_media.attributes).unwrap_or(Direction::SendRecv);

    // Negotiate direction from answerer's perspective
    let answer_dir = offer_dir.reverse().negotiate(&local_dir)?;

    // Build answer media
    let mut answer_media = base_answer_media(offer_media, local_media.port);

    // Add negotiated formats
    for negotiated in &common_formats {
        answer_media = answer_media.add_format_token(negotiated.offered_format.as_str());
        if let Some(rtpmap) = &negotiated.rtpmap {
            answer_media = answer_media.add_rtpmap(
                rtpmap.payload_type,
                &rtpmap.encoding_name,
                rtpmap.clock_rate,
                rtpmap.encoding_params.as_ref().map(|s| s.as_str()),
            );
        }
    }

    // Set negotiated direction
    answer_media = answer_media.direction(match answer_dir {
        Direction::SendRecv => "sendrecv",
        Direction::SendOnly => "sendonly",
        Direction::RecvOnly => "recvonly",
        Direction::Inactive => "inactive",
    });

    // Copy connection if present
    if let Some(ref conn) = local_media.connection {
        answer_media.connection = Some(conn.clone());
    }

    Ok(answer_media)
}

/// Find common payload types between offer and local capabilities
#[derive(Debug, Clone)]
struct NegotiatedFormat {
    offered_format: SmolStr,
    rtpmap: Option<RtpMap>,
}

fn find_common_formats(
    offer_media: &MediaDescription,
    local_media: &MediaDescription,
) -> Vec<NegotiatedFormat> {
    let mut common = Vec::new();

    if is_rtp_protocol(&offer_media.protocol) {
        for offer_fmt in &offer_media.formats {
            let offer_pt = match parse_payload_type(offer_fmt) {
                Some(pt) => pt,
                None => continue,
            };

            if offer_pt < 96 {
                if local_supports_static_pt(local_media, offer_pt) {
                    common.push(NegotiatedFormat {
                        offered_format: offer_fmt.clone(),
                        rtpmap: local_media.rtpmaps.get(&offer_pt).cloned(),
                    });
                }
                continue;
            }

            let offer_rtpmap = match offer_media.rtpmaps.get(&offer_pt) {
                Some(map) => map,
                None => continue,
            };

            if let Some(local_rtpmap) = find_matching_dynamic_rtpmap(local_media, offer_rtpmap) {
                common.push(NegotiatedFormat {
                    offered_format: offer_fmt.clone(),
                    rtpmap: Some(RtpMap {
                        payload_type: offer_pt,
                        encoding_name: local_rtpmap.encoding_name.clone(),
                        clock_rate: local_rtpmap.clock_rate,
                        encoding_params: local_rtpmap.encoding_params.clone(),
                    }),
                });
            }
        }
    } else {
        for offer_fmt in &offer_media.formats {
            if local_media.formats.iter().any(|f| f == offer_fmt) {
                common.push(NegotiatedFormat {
                    offered_format: offer_fmt.clone(),
                    rtpmap: None,
                });
            }
        }
    }

    common
}

/// Create a rejected media stream (port 0)
fn create_rejected_media(offer_media: &MediaDescription) -> MediaDescription {
    let mut rejected = MediaDescription {
        media_type: offer_media.media_type.clone(),
        port: 0,
        num_ports: offer_media.num_ports,
        protocol: offer_media.protocol.clone(),
        formats: offer_media.formats.clone(),
        title: None,
        connection: None,
        bandwidth: Vec::new(),
        encryption_key: None,
        attributes: Vec::new(),
        rtpmaps: HashMap::new(),
    };
    if rejected.formats.is_empty() {
        rejected = rejected.add_format_token("0");
    }
    rejected
}

/// Extract direction from attributes
fn extract_direction(attributes: &[Attribute]) -> Option<Direction> {
    attributes.iter().find_map(Direction::from_attribute)
}

fn base_answer_media(offer_media: &MediaDescription, port: u16) -> MediaDescription {
    MediaDescription {
        media_type: offer_media.media_type.clone(),
        port,
        num_ports: offer_media.num_ports,
        protocol: offer_media.protocol.clone(),
        formats: Vec::new(),
        title: None,
        connection: None,
        bandwidth: Vec::new(),
        encryption_key: None,
        attributes: Vec::new(),
        rtpmaps: HashMap::new(),
    }
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

fn parse_payload_type(fmt: &SmolStr) -> Option<u8> {
    let value = fmt.as_str().parse::<u16>().ok()?;
    if value > 127 {
        None
    } else {
        Some(value as u8)
    }
}

fn local_supports_static_pt(local_media: &MediaDescription, pt: u8) -> bool {
    local_media
        .formats
        .iter()
        .filter_map(parse_payload_type)
        .any(|local_pt| local_pt == pt)
}

fn find_matching_dynamic_rtpmap(
    local_media: &MediaDescription,
    offer_rtpmap: &RtpMap,
) -> Option<RtpMap> {
    local_media
        .rtpmaps
        .values()
        .find(|local_rtpmap| {
            local_media
                .formats
                .iter()
                .filter_map(parse_payload_type)
                .any(|pt| pt == local_rtpmap.payload_type)
                && offer_rtpmap
                    .encoding_name
                    .eq_ignore_ascii_case(&local_rtpmap.encoding_name)
                && offer_rtpmap.clock_rate == local_rtpmap.clock_rate
                && offer_rtpmap.encoding_params == local_rtpmap.encoding_params
        })
        .cloned()
}

/// Generate session ID
fn generate_session_id() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_reverse() {
        assert_eq!(Direction::SendRecv.reverse(), Direction::SendRecv);
        assert_eq!(Direction::SendOnly.reverse(), Direction::RecvOnly);
        assert_eq!(Direction::RecvOnly.reverse(), Direction::SendOnly);
        assert_eq!(Direction::Inactive.reverse(), Direction::Inactive);
    }

    #[test]
    fn direction_compatibility() {
        assert!(Direction::SendRecv.is_compatible_with(&Direction::SendRecv));
        assert!(Direction::SendRecv.is_compatible_with(&Direction::SendOnly));
        assert!(Direction::SendOnly.is_compatible_with(&Direction::RecvOnly));
        assert!(!Direction::Inactive.is_compatible_with(&Direction::SendRecv));
    }

    #[test]
    fn negotiates_simple_audio_answer() {
        // Offer: audio with PCMU and PCMA
        let offer = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .session_name("Call")
            .connection("192.168.1.100")
            .media(
                MediaDescription::audio(8000)
                    .add_format(0)
                    .add_format(8)
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .add_rtpmap(8, "PCMA", 8000, None)
                    .direction("sendrecv"),
            )
            .build();

        // Local capabilities: support PCMU only
        let local_caps = SessionDescription::builder()
            .origin("bob", "456", "10.0.0.1")
            .session_name("Server")
            .connection("10.0.0.1")
            .media(
                MediaDescription::audio(9000)
                    .add_format(0)
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .direction("sendrecv"),
            )
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();

        assert_eq!(answer.media.len(), 1);
        assert_eq!(answer.media[0].port, 9000);
        assert_eq!(
            answer.media[0]
                .formats
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>(),
            vec!["0"]
        ); // Only PCMU
    }

    #[test]
    fn rejects_media_with_no_common_codec() {
        // Offer: video with H264
        let offer = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .session_name("Call")
            .connection("192.168.1.100")
            .media(
                MediaDescription::video(8002)
                    .add_format(96)
                    .add_rtpmap(96, "H264", 90000, None),
            )
            .build();

        // Local capabilities: no video support
        let local_caps = SessionDescription::builder()
            .origin("bob", "456", "10.0.0.1")
            .session_name("Server")
            .connection("10.0.0.1")
            .media(
                MediaDescription::audio(9000)
                    .add_format(0)
                    .add_rtpmap(0, "PCMU", 8000, None),
            )
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();

        // Should include rejected media (port 0)
        assert_eq!(answer.media.len(), 1);
        assert_eq!(answer.media[0].port, 0); // Rejected
    }

    #[test]
    fn negotiates_direction() {
        let sendrecv = Direction::SendRecv;
        let sendonly = Direction::SendOnly;

        // SendRecv + SendOnly = RecvOnly (from answerer's perspective)
        let result = sendrecv.reverse().negotiate(&sendonly).unwrap();
        assert_eq!(result, Direction::SendOnly);
    }

    #[test]
    fn negotiates_dynamic_payload_by_codec() {
        let offer = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .session_name("Call")
            .connection("192.168.1.100")
            .media(
                MediaDescription::audio(8000)
                    .add_format(96)
                    .add_rtpmap(96, "opus", 48000, Some("2"))
                    .direction("sendrecv"),
            )
            .build();

        let local_caps = SessionDescription::builder()
            .origin("bob", "456", "10.0.0.1")
            .session_name("Server")
            .connection("10.0.0.1")
            .media(
                MediaDescription::audio(9000)
                    .add_format(111)
                    .add_rtpmap(111, "opus", 48000, Some("2"))
                    .direction("sendrecv"),
            )
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();
        assert_eq!(answer.media.len(), 1);
        assert!(answer.media[0].formats.iter().any(|f| f == "96"));
        assert!(answer.media[0].rtpmaps.contains_key(&96));
    }
}
