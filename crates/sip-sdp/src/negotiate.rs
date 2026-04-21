// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

// Re-export the canonical Direction from `attrs` so callers that do
// `use sip_sdp::negotiate::Direction` continue to compile while the
// type itself lives in one place.
pub use crate::attrs::Direction;

/// Negotiation behaviour layered on top of [`Direction`]. Lives in its
/// own trait so the attribute-only `attrs` module stays free of
/// negotiation-specific decisions.
pub trait DirectionNegotiate {
    /// Get the direction from the answerer's perspective. RFC 3264 §6
    /// step 4: the answerer sees `sendonly` ↔ `recvonly` swapped.
    fn reverse(&self) -> Direction;

    /// True iff the two directions can establish bidirectional or
    /// unidirectional media flow. `Inactive` is only compatible with
    /// itself; `SendRecv` is compatible with any active direction;
    /// `SendOnly` pairs with `RecvOnly` (and vice versa); same-side
    /// directions (e.g. SendOnly/SendOnly) cannot exchange media.
    fn is_compatible_with(&self, other: &Direction) -> bool;

    /// Compute the answerer's direction given an offer direction.
    fn negotiate(&self, answer_dir: &Direction) -> Result<Direction, NegotiationError>;
}

impl DirectionNegotiate for Direction {
    fn reverse(&self) -> Direction {
        match self {
            Direction::SendRecv => Direction::SendRecv,
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            Direction::Inactive => Direction::Inactive,
        }
    }

    fn is_compatible_with(&self, other: &Direction) -> bool {
        match (self, other) {
            // Inactive degrades to Inactive in either direction —
            // it's a valid answer to any offer (the answerer is
            // refusing media flow). Per RFC 3264 §6 the answerer
            // MAY decline to send or receive even when it's
            // technically capable.
            (Direction::Inactive, _) | (_, Direction::Inactive) => true,
            // SendRecv degrades to whatever the other side offered.
            (Direction::SendRecv, _) | (_, Direction::SendRecv) => true,
            // Cross-direction unidirectional pairs flow.
            (Direction::SendOnly, Direction::RecvOnly) => true,
            (Direction::RecvOnly, Direction::SendOnly) => true,
            // Both SendOnly or both RecvOnly: no flow possible
            // (both want to talk, or both want to listen, with no
            // one on the other end).
            _ => false,
        }
    }

    fn negotiate(&self, answer_dir: &Direction) -> Result<Direction, NegotiationError> {
        if !self.is_compatible_with(answer_dir) {
            return Err(NegotiationError::IncompatibleDirection);
        }
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
///     .origin("alice", "123", "192.168.1.100").unwrap()
///     .session_name("Call").unwrap()
///     .connection("192.168.1.100").unwrap()
///     .media(MediaDescription::audio(8000)
///         .add_format(0).unwrap()  // PCMU
///         .add_format(8).unwrap()  // PCMA
///         .add_rtpmap(0, "PCMU", 8000, None).unwrap()
///         .add_rtpmap(8, "PCMA", 8000, None).unwrap())
///     .unwrap()
///     .build();
///
/// // Local capabilities (only support PCMU)
/// let local_caps = SessionDescription::builder()
///     .origin("bob", "456", "10.0.0.1").unwrap()
///     .session_name("Server").unwrap()
///     .connection("10.0.0.1").unwrap()
///     .media(MediaDescription::audio(9000)
///         .add_format(0).unwrap()  // PCMU only
///         .add_rtpmap(0, "PCMU", 8000, None).unwrap())
///     .unwrap()
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
        .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?
        .session_name(&local_capabilities.session_name)
        .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?
        .connection(local_addr)
        .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?
        .time(0, 0);

    // Process each media stream in the offer.
    //
    // RFC 3264 §6 / §8.2: the answer MUST contain the same number of
    // m-lines as the offer, in the same order. An m-line that the
    // answerer wants to reject is signalled by a port value of zero.
    // If the OFFER itself already carries port 0 for a section, that
    // section is permanently rejected — the answer must echo a port-0
    // line back without trying to negotiate codecs (the offerer is
    // explicitly removing or refusing that stream).
    for offer_media in &offer.media {
        if offer_media.port == 0 {
            let echoed = create_rejected_media(offer_media)?;
            answer_builder = answer_builder
                .media(echoed)
                .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;
            continue;
        }
        match negotiate_media(offer_media, local_capabilities) {
            Ok(answer_media) => {
                answer_builder = answer_builder
                    .media(answer_media)
                    .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;
            }
            Err(NegotiationError::NoCommonCodec(_))
            | Err(NegotiationError::MissingMediaStream(_)) => {
                // No common codec or unsupported media type - include rejected media (port 0)
                let rejected = create_rejected_media(offer_media)?;
                answer_builder = answer_builder
                    .media(rejected)
                    .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;
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
        return Err(NegotiationError::NoCommonCodec(
            offer_media.media_type.clone(),
        ));
    }

    // Find common codecs (payload types)
    let common_formats = find_common_formats(offer_media, local_media);

    if common_formats.is_empty() {
        return Err(NegotiationError::NoCommonCodec(
            offer_media.media_type.clone(),
        ));
    }

    // Get directions. Use `effective_direction` so the legacy
    // RFC 2543 hold convention (`c=` line carrying 0.0.0.0) is
    // surfaced as `Inactive`. Without this the offer would look
    // like `sendrecv` and the answerer would happily try to send
    // media to a peer that isn't listening.
    let offer_dir = offer_media.effective_direction();
    let local_dir = local_media.effective_direction();

    // Negotiate direction from answerer's perspective
    let answer_dir = offer_dir.reverse().negotiate(&local_dir)?;

    // Build answer media
    let mut answer_media = base_answer_media(offer_media, local_media.port);

    // Add negotiated formats. For each accepted PT also echo the
    // offerer's fmtp line (RFC 3264 §6.1): the answer SHOULD carry
    // any parameters needed to specify the format. For
    // negotiation-sensitive codecs (opus useinbandfec, telephone-event
    // event ranges, H.264 profile-level-id) this is what real-world
    // peers expect — dropping the fmtp degrades interop silently.
    for negotiated in &common_formats {
        answer_media = answer_media
            .add_format_token(negotiated.offered_format.as_str())
            .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;
        if let Some(rtpmap) = &negotiated.rtpmap {
            answer_media = answer_media
                .add_rtpmap(
                    rtpmap.payload_type,
                    &rtpmap.encoding_name,
                    rtpmap.clock_rate,
                    rtpmap.encoding_params.as_ref().map(|s| s.as_str()),
                )
                .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;
        }
        // Echo offerer's fmtp for this PT, if any.
        if let Some(pt) = parse_payload_type(&negotiated.offered_format) {
            if let Some(fmtp) = offer_media.fmtp_for(pt) {
                answer_media.attributes.push(Attribute::Value {
                    name: SmolStr::new("fmtp"),
                    value: SmolStr::new(format!("{} {}", pt, fmtp.params)),
                });
            }
        }
    }

    // Set negotiated direction
    answer_media = answer_media
        .with_direction(match answer_dir {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        })
        .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;

    // Copy connection if present
    if let Some(ref conn) = local_media.connection {
        answer_media.connection = Some(conn.clone());
    }

    // RFC 5763 §5: when the offer carries an `a=setup:` attribute
    // (DTLS role indicator), the answerer MUST respond with a
    // compatible role. `actpass` invites the answerer to choose;
    // active/passive force the opposite role; `holdconn` is echoed.
    // We only emit setup in the answer if the offer asked for it —
    // injecting it unsolicited would surprise non-DTLS peers.
    if let Some(offer_setup) = offer_media.setup() {
        let answer_setup = crate::attrs::Setup::answer_for(offer_setup);
        answer_media.set_setup(answer_setup);
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
fn create_rejected_media(
    offer_media: &MediaDescription,
) -> Result<MediaDescription, NegotiationError> {
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
        rejected = rejected
            .add_format_token("0")
            .map_err(|e| NegotiationError::InvalidSdp(e.to_string()))?;
    }
    Ok(rejected)
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
        // RFC 3264 §6: Inactive is a valid answer to any offer — the
        // answerer can always degrade to no-media-flow even if it
        // would technically support sendrecv. The negotiated result
        // is Inactive in either direction.
        assert!(Direction::Inactive.is_compatible_with(&Direction::SendRecv));
        assert!(Direction::SendRecv.is_compatible_with(&Direction::Inactive));
        // Same-side directions can't flow: both want to talk, or
        // both want to listen.
        assert!(!Direction::SendOnly.is_compatible_with(&Direction::SendOnly));
        assert!(!Direction::RecvOnly.is_compatible_with(&Direction::RecvOnly));
    }

    #[test]
    fn negotiates_simple_audio_answer() {
        // Offer: audio with PCMU and PCMA
        let offer = SessionDescription::builder()
            .origin("alice", "123", "192.168.1.100")
            .unwrap()
            .session_name("Call")
            .unwrap()
            .connection("192.168.1.100")
            .unwrap()
            .media(
                MediaDescription::audio(8000)
                    .add_format(0)
                    .unwrap()
                    .add_format(8)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap()
                    .add_rtpmap(8, "PCMA", 8000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        // Local capabilities: support PCMU only
        let local_caps = SessionDescription::builder()
            .origin("bob", "456", "10.0.0.1")
            .unwrap()
            .session_name("Server")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(
                MediaDescription::audio(9000)
                    .add_format(0)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
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
            .unwrap()
            .session_name("Call")
            .unwrap()
            .connection("192.168.1.100")
            .unwrap()
            .media(
                MediaDescription::video(8002)
                    .add_format(96)
                    .unwrap()
                    .add_rtpmap(96, "H264", 90000, None)
                    .unwrap(),
            )
            .unwrap()
            .build();

        // Local capabilities: no video support
        let local_caps = SessionDescription::builder()
            .origin("bob", "456", "10.0.0.1")
            .unwrap()
            .session_name("Server")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(
                MediaDescription::audio(9000)
                    .add_format(0)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap(),
            )
            .unwrap()
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
            .unwrap()
            .session_name("Call")
            .unwrap()
            .connection("192.168.1.100")
            .unwrap()
            .media(
                MediaDescription::audio(8000)
                    .add_format(96)
                    .unwrap()
                    .add_rtpmap(96, "opus", 48000, Some("2"))
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let local_caps = SessionDescription::builder()
            .origin("bob", "456", "10.0.0.1")
            .unwrap()
            .session_name("Server")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(
                MediaDescription::audio(9000)
                    .add_format(111)
                    .unwrap()
                    .add_rtpmap(111, "opus", 48000, Some("2"))
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();
        assert_eq!(answer.media.len(), 1);
        assert!(answer.media[0].formats.iter().any(|f| f == "96"));
        assert!(answer.media[0].rtpmaps.contains_key(&96));
    }

    // ---------------------------------------------------------------
    // RFC 3264 §6.1: fmtp preservation
    //
    // When the answerer accepts a PT, the answer SHOULD echo the
    // offerer's fmtp for that PT. Without this, codec-sensitive
    // parameters (opus useinbandfec, H.264 profile-level-id,
    // telephone-event event ranges) silently disagree and calls
    // either go silent or fall back to lowest-common defaults.
    // ---------------------------------------------------------------

    #[test]
    fn answer_echoes_offer_fmtp_for_accepted_pt() {
        let offer = SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("Opus call")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(
                MediaDescription::audio(8000)
                    .add_format(111)
                    .unwrap()
                    .add_format(101)
                    .unwrap()
                    .add_rtpmap(111, "opus", 48000, Some("2"))
                    .unwrap()
                    .add_rtpmap(101, "telephone-event", 8000, None)
                    .unwrap()
                    .add_attribute("fmtp", "111 minptime=10;useinbandfec=1")
                    .unwrap()
                    .add_attribute("fmtp", "101 0-16")
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let local_caps = SessionDescription::builder()
            .origin("bob", "1", "10.0.0.1")
            .unwrap()
            .session_name("Opus caps")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(
                MediaDescription::audio(9000)
                    .add_format(111)
                    .unwrap()
                    .add_format(101)
                    .unwrap()
                    .add_rtpmap(111, "opus", 48000, Some("2"))
                    .unwrap()
                    .add_rtpmap(101, "telephone-event", 8000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();
        let opus = answer.media[0]
            .fmtp_for(111)
            .expect("answer must preserve opus fmtp");
        assert_eq!(opus.params.as_str(), "minptime=10;useinbandfec=1");
        let dtmf = answer.media[0]
            .fmtp_for(101)
            .expect("answer must preserve telephone-event fmtp");
        assert_eq!(dtmf.params.as_str(), "0-16");
    }

    #[test]
    fn answer_only_carries_fmtp_for_accepted_pts() {
        // Offer lists two dynamic codecs (opus PT 111, iSAC PT 103)
        // each with fmtp. Local supports only opus. The answer must
        // carry opus fmtp and MUST NOT carry iSAC fmtp (rejected PT).
        let offer = SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("Mixed codecs")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(
                MediaDescription::audio(8000)
                    .add_format(111)
                    .unwrap()
                    .add_format(103)
                    .unwrap()
                    .add_rtpmap(111, "opus", 48000, Some("2"))
                    .unwrap()
                    .add_rtpmap(103, "ISAC", 16000, None)
                    .unwrap()
                    .add_attribute("fmtp", "111 minptime=10")
                    .unwrap()
                    .add_attribute("fmtp", "103 mode=wide")
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let local_caps = SessionDescription::builder()
            .origin("bob", "1", "10.0.0.1")
            .unwrap()
            .session_name("Opus-only")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(
                MediaDescription::audio(9000)
                    .add_format(111)
                    .unwrap()
                    .add_rtpmap(111, "opus", 48000, Some("2"))
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &local_caps).unwrap();
        assert!(answer.media[0].fmtp_for(111).is_some());
        assert!(
            answer.media[0].fmtp_for(103).is_none(),
            "fmtp for rejected PT MUST NOT appear in answer",
        );
    }

    // ---------------------------------------------------------------
    // RFC 5763 §5: DTLS setup negotiation
    //
    // The DTLS role attribute lets one peer initiate the handshake
    // (active) and the other accept (passive). Negotiation is:
    //   offer active   → answer passive
    //   offer passive  → answer active
    //   offer actpass  → answer active (convention — answerer
    //                                    initiates)
    //   offer holdconn → answer holdconn
    // ---------------------------------------------------------------

    fn dtls_offer(setup: &str) -> SessionDescription {
        let media = MediaDescription {
            media_type: MediaType::Audio,
            port: 9000,
            num_ports: None,
            protocol: Protocol::UdpTlsRtpSavpf,
            formats: vec![SmolStr::new("111")],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: vec![
                Attribute::Value {
                    name: SmolStr::new("rtpmap"),
                    value: SmolStr::new("111 opus/48000/2"),
                },
                Attribute::Value {
                    name: SmolStr::new("setup"),
                    value: SmolStr::new(setup),
                },
                Attribute::Value {
                    name: SmolStr::new("fingerprint"),
                    value: SmolStr::new("sha-256 AB:CD:EF"),
                },
                Attribute::Property(SmolStr::new("sendrecv")),
            ],
            rtpmaps: {
                let mut m = HashMap::new();
                m.insert(
                    111,
                    RtpMap {
                        payload_type: 111,
                        encoding_name: SmolStr::new("opus"),
                        clock_rate: 48000,
                        encoding_params: Some(SmolStr::new("2")),
                    },
                );
                m
            },
        };
        SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("DTLS")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(media)
            .unwrap()
            .build()
    }

    fn dtls_caps() -> SessionDescription {
        let media = MediaDescription {
            media_type: MediaType::Audio,
            port: 9000,
            num_ports: None,
            protocol: Protocol::UdpTlsRtpSavpf,
            formats: vec![SmolStr::new("111")],
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: vec![
                Attribute::Value {
                    name: SmolStr::new("rtpmap"),
                    value: SmolStr::new("111 opus/48000/2"),
                },
                Attribute::Property(SmolStr::new("sendrecv")),
            ],
            rtpmaps: {
                let mut m = HashMap::new();
                m.insert(
                    111,
                    RtpMap {
                        payload_type: 111,
                        encoding_name: SmolStr::new("opus"),
                        clock_rate: 48000,
                        encoding_params: Some(SmolStr::new("2")),
                    },
                );
                m
            },
        };
        SessionDescription::builder()
            .origin("bob", "1", "10.0.0.1")
            .unwrap()
            .session_name("DTLS caps")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(media)
            .unwrap()
            .build()
    }

    #[test]
    fn dtls_setup_actpass_answered_with_active() {
        let offer = dtls_offer("actpass");
        let answer = negotiate_answer(&offer, "10.0.0.1", &dtls_caps()).unwrap();
        assert_eq!(answer.media[0].setup(), Some(crate::attrs::Setup::Active));
    }

    #[test]
    fn dtls_setup_active_answered_with_passive() {
        let offer = dtls_offer("active");
        let answer = negotiate_answer(&offer, "10.0.0.1", &dtls_caps()).unwrap();
        assert_eq!(answer.media[0].setup(), Some(crate::attrs::Setup::Passive));
    }

    #[test]
    fn dtls_setup_passive_answered_with_active() {
        let offer = dtls_offer("passive");
        let answer = negotiate_answer(&offer, "10.0.0.1", &dtls_caps()).unwrap();
        assert_eq!(answer.media[0].setup(), Some(crate::attrs::Setup::Active));
    }

    #[test]
    fn dtls_setup_holdconn_echoed() {
        let offer = dtls_offer("holdconn");
        let answer = negotiate_answer(&offer, "10.0.0.1", &dtls_caps()).unwrap();
        assert_eq!(answer.media[0].setup(), Some(crate::attrs::Setup::HoldConn));
    }

    #[test]
    fn no_setup_in_offer_means_no_setup_in_answer() {
        // Offer without setup (non-DTLS path): answer must NOT inject
        // a spurious setup attribute.
        let offer = audio_offer_with_direction("sendrecv");
        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert!(answer.media[0].setup().is_none());
    }

    // ---------------------------------------------------------------
    // RFC 3264 §6 / §8.2: port-0 preservation
    //
    // An m-line with port=0 in the OFFER is the offerer rejecting (or
    // removing) that media stream. The answer MUST echo a port-0 line
    // back in the same position; we MUST NOT try to negotiate codecs
    // for it. Re-INVITE-driven session modifications rely on this so
    // both sides converge on the same set of active streams.
    // ---------------------------------------------------------------

    fn audio_caps() -> SessionDescription {
        SessionDescription::builder()
            .origin("bob", "1", "10.0.0.1")
            .unwrap()
            .session_name("caps")
            .unwrap()
            .connection("10.0.0.1")
            .unwrap()
            .media(
                MediaDescription::audio(9000)
                    .add_format(0)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build()
    }

    #[test]
    fn offer_port_zero_yields_answer_port_zero() {
        // Offer carries a port-0 audio stream — the offerer is
        // explicitly refusing that media. Answer MUST echo port 0
        // and MUST NOT add the local rtpmap as if it were negotiating.
        let offer = SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("Reject")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(MediaDescription {
                media_type: MediaType::Audio,
                port: 0,
                num_ports: None,
                protocol: Protocol::RtpAvp,
                formats: vec![SmolStr::new("0")],
                title: None,
                connection: None,
                bandwidth: Vec::new(),
                encryption_key: None,
                attributes: Vec::new(),
                rtpmaps: HashMap::new(),
            })
            .unwrap()
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert_eq!(answer.media.len(), 1);
        assert_eq!(answer.media[0].port, 0, "MUST echo port 0");
        // The answerer MUST NOT inject local rtpmaps onto a rejected
        // media stream.
        assert!(answer.media[0].rtpmaps.is_empty());
    }

    // ---------------------------------------------------------------
    // RFC 3264 §8.4 + RFC 2543 hold semantics
    //
    // Modern hold: peer A sends a re-INVITE with a=sendonly (it will
    //   send media — typically music-on-hold — but won't accept any).
    //   Peer B answers with a=recvonly.
    // Modern resume: peer A sends a re-INVITE with a=sendrecv. Peer B
    //   answers with a=sendrecv.
    // Legacy RFC 2543 hold: peer A sends c=IN IP4 0.0.0.0. Per
    //   RFC 3264 §5.1 we MUST treat this as inactive — answer with
    //   a=inactive (no media in either direction).
    // ---------------------------------------------------------------

    fn audio_offer_with_direction(direction: &str) -> SessionDescription {
        SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("Hold")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(
                MediaDescription::audio(8000)
                    .add_format(0)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap()
                    .with_direction(direction)
                    .unwrap(),
            )
            .unwrap()
            .build()
    }

    fn answer_direction(answer: &SessionDescription) -> Direction {
        answer.media[0]
            .direction()
            .expect("answer must carry an explicit direction")
    }

    #[test]
    fn modern_hold_sendonly_answered_with_recvonly() {
        let offer = audio_offer_with_direction("sendonly");
        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert_eq!(answer_direction(&answer), Direction::RecvOnly);
    }

    #[test]
    fn modern_hold_inactive_answered_with_inactive() {
        let offer = audio_offer_with_direction("inactive");
        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert_eq!(answer_direction(&answer), Direction::Inactive);
    }

    #[test]
    fn modern_resume_sendrecv_answered_with_sendrecv() {
        let offer = audio_offer_with_direction("sendrecv");
        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert_eq!(answer_direction(&answer), Direction::SendRecv);
    }

    #[test]
    fn full_hold_resume_round_trip() {
        // Sequence: initial INVITE (sendrecv) → re-INVITE (sendonly =
        // hold) → re-INVITE (sendrecv = resume). Verify the answer at
        // each step is what RFC 3264 §8.4 prescribes.
        for (offer_dir, expected_answer_dir) in [
            ("sendrecv", Direction::SendRecv),
            ("sendonly", Direction::RecvOnly),
            ("sendrecv", Direction::SendRecv),
        ] {
            let offer = audio_offer_with_direction(offer_dir);
            let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
            assert_eq!(
                answer_direction(&answer),
                expected_answer_dir,
                "offer dir {offer_dir} should yield answer {expected_answer_dir:?}",
            );
        }
    }

    #[test]
    fn legacy_rfc2543_hold_via_zero_address_yields_inactive_answer() {
        // Build the offer manually so we can plant `c=IN IP4 0.0.0.0`
        // at the media level. The session-level connection stays
        // valid; it's the per-media c= that signals hold.
        let mut audio_media = MediaDescription::audio(8000)
            .add_format(0)
            .unwrap()
            .add_rtpmap(0, "PCMU", 8000, None)
            .unwrap()
            .with_direction("sendrecv")
            .unwrap();
        audio_media.connection = Some(Connection::new("0.0.0.0").unwrap());

        let offer = SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("Legacy hold")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(audio_media)
            .unwrap()
            .build();

        // Sanity: the offerer is on hold per the helper.
        assert!(offer.media[0].is_held_by_remote());

        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert_eq!(answer_direction(&answer), Direction::Inactive);
    }

    #[test]
    fn answer_preserves_offer_m_line_order_with_port_zero_in_middle() {
        // Three m-lines in the offer: audio (active) → video (port 0,
        // rejected) → audio (active). The answer must contain three
        // m-lines in the same order with port 0 preserved in the
        // middle slot.
        let offer = SessionDescription::builder()
            .origin("alice", "1", "192.0.2.10")
            .unwrap()
            .session_name("Multi")
            .unwrap()
            .connection("192.0.2.10")
            .unwrap()
            .media(
                MediaDescription::audio(8000)
                    .add_format(0)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .media(MediaDescription {
                media_type: MediaType::Video,
                port: 0,
                num_ports: None,
                protocol: Protocol::RtpAvp,
                formats: vec![SmolStr::new("96")],
                title: None,
                connection: None,
                bandwidth: Vec::new(),
                encryption_key: None,
                attributes: Vec::new(),
                rtpmaps: HashMap::new(),
            })
            .unwrap()
            .media(
                MediaDescription::audio(8002)
                    .add_format(0)
                    .unwrap()
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
            .build();

        let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps()).unwrap();
        assert_eq!(answer.media.len(), 3, "m-line count must match offer");
        assert_eq!(answer.media[0].media_type, MediaType::Audio);
        assert!(answer.media[0].port != 0);
        assert_eq!(answer.media[1].media_type, MediaType::Video);
        assert_eq!(answer.media[1].port, 0, "rejected slot must stay rejected");
        assert_eq!(answer.media[2].media_type, MediaType::Audio);
        assert!(answer.media[2].port != 0);
    }
}
