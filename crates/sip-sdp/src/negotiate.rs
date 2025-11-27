//! RFC 3264 Offer/Answer Model implementation
//!
//! Implements SDP offer/answer negotiation for establishing media sessions.
//! Handles codec negotiation, media stream matching, and direction negotiation.

use crate::*;

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
    pub fn is_compatible_with(&self, other: &Direction) -> bool {
        match (self, other) {
            (Direction::Inactive, _) | (_, Direction::Inactive) => false,
            (Direction::SendRecv, _) | (_, Direction::SendRecv) => true,
            (Direction::SendOnly, Direction::RecvOnly) => true,
            (Direction::RecvOnly, Direction::SendOnly) => true,
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
        .find_media(offer_media.media_type)
        .ok_or(NegotiationError::MissingMediaStream(offer_media.media_type))?;

    // Find common codecs (payload types)
    let common_formats = find_common_formats(offer_media, local_media);

    if common_formats.is_empty() {
        return Err(NegotiationError::NoCommonCodec(offer_media.media_type));
    }

    // Get directions
    let offer_dir = extract_direction(&offer_media.attributes).unwrap_or(Direction::SendRecv);
    let local_dir = extract_direction(&local_media.attributes).unwrap_or(Direction::SendRecv);

    // Negotiate direction from answerer's perspective
    let answer_dir = offer_dir.reverse().negotiate(&local_dir)?;

    // Build answer media
    let mut answer_media = match offer_media.media_type {
        MediaType::Audio => MediaDescription::audio(local_media.port),
        MediaType::Video => MediaDescription::video(local_media.port),
        _ => MediaDescription::audio(local_media.port), // Fallback
    };

    // Add negotiated formats
    for pt in &common_formats {
        answer_media = answer_media.add_format(*pt);

        // Copy rtpmap from local capabilities
        if let Some(rtpmap) = local_media.rtpmaps.get(pt) {
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
fn find_common_formats(offer_media: &MediaDescription, local_media: &MediaDescription) -> Vec<u8> {
    let mut common = Vec::new();

    for offer_pt in &offer_media.formats {
        // Check if we support this payload type
        if local_media.formats.contains(offer_pt) {
            // For dynamic payload types (96-127), also check encoding name
            if *offer_pt >= 96 {
                if let (Some(offer_rtpmap), Some(local_rtpmap)) = (
                    offer_media.rtpmaps.get(offer_pt),
                    local_media.rtpmaps.get(offer_pt),
                ) {
                    // Match by encoding name (case-insensitive)
                    if offer_rtpmap
                        .encoding_name
                        .eq_ignore_ascii_case(&local_rtpmap.encoding_name)
                        && offer_rtpmap.clock_rate == local_rtpmap.clock_rate
                    {
                        common.push(*offer_pt);
                    }
                }
            } else {
                // Static payload types (0-95) are well-defined
                common.push(*offer_pt);
            }
        }
    }

    common
}

/// Create a rejected media stream (port 0)
fn create_rejected_media(offer_media: &MediaDescription) -> MediaDescription {
    match offer_media.media_type {
        MediaType::Audio => MediaDescription::audio(0),
        MediaType::Video => MediaDescription::video(0),
        _ => MediaDescription::audio(0),
    }
    .add_format(if !offer_media.formats.is_empty() {
        offer_media.formats[0]
    } else {
        0
    })
}

/// Extract direction from attributes
fn extract_direction(attributes: &[Attribute]) -> Option<Direction> {
    attributes.iter().find_map(Direction::from_attribute)
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
        assert_eq!(answer.media[0].formats, vec![0]); // Only PCMU
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
}
