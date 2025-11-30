//! RFC 3264: SDP Offer/Answer Model implementation.
//!
//! This module provides comprehensive support for SDP offer/answer negotiation
//! as defined in RFC 3264.
//!
//! # Key Concepts
//!
//! - **Offer**: SDP proposal from one party (offerer)
//! - **Answer**: SDP response from the other party (answerer)
//! - **Media Matching**: By position (i-th in offer = i-th in answer)
//! - **Codec Negotiation**: Select common codecs from both parties
//! - **Direction Negotiation**: sendrecv, sendonly, recvonly, inactive
//! - **Rejection**: Port 0 indicates rejected media stream
//! - **Hold**: Change direction to sendonly or inactive
//!
//! # Examples
//!
//! ```
//! use sip_core::sdp_offer_answer::{OfferAnswerEngine, AnswerOptions};
//! use sip_core::sdp::SdpSession;
//!
//! // Parse minimal offer with one audio stream
//! let offer = SdpSession::parse(concat!(
//!     "v=0\r\n",
//!     "o=alice 123 456 IN IP4 192.0.2.1\r\n",
//!     "s=Example Session\r\n",
//!     "c=IN IP4 192.0.2.1\r\n",
//!     "t=0 0\r\n",
//!     "m=audio 49170 RTP/AVP 0\r\n",
//!     "a=rtpmap:0 PCMU/8000\r\n",
//! ))
//! .unwrap();
//!
//! // Create negotiation engine
//! let engine = OfferAnswerEngine::new();
//!
//! // Generate answer
//! let answer = engine.generate_answer(&offer, AnswerOptions::default()).unwrap();
//! ```

use crate::sdp::{
    Attribute, ConfirmStatus, Connection, CurrentStatus, DesiredStatus, Direction, Fmtp,
    MediaDescription, Origin, PreconditionDirection, PreconditionType, RtpMap, SdpSession,
    StatusType, StrengthTag,
};
use std::collections::HashMap;
use std::fmt;

/// Errors that can occur during offer/answer negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    /// No common codecs found for a media stream
    NoCommonCodecs(usize),
    /// Invalid SDP structure
    InvalidSdp(String),
    /// Media stream mismatch between offer and answer
    MediaMismatch(String),
    /// Direction attribute conflict
    DirectionConflict(String),
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NegotiationError::NoCommonCodecs(idx) => {
                write!(f, "No common codecs for media stream {}", idx)
            }
            NegotiationError::InvalidSdp(msg) => write!(f, "Invalid SDP: {}", msg),
            NegotiationError::MediaMismatch(msg) => write!(f, "Media mismatch: {}", msg),
            NegotiationError::DirectionConflict(msg) => write!(f, "Direction conflict: {}", msg),
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Configuration for generating answers.
#[derive(Debug, Clone)]
pub struct AnswerOptions {
    /// Local address to use in answer
    pub local_address: String,
    /// Base port for media streams
    pub base_port: u16,
    /// Supported audio codecs (name -> clock rate)
    pub audio_codecs: Vec<CodecInfo>,
    /// Supported video codecs (name -> clock rate)
    pub video_codecs: Vec<CodecInfo>,
    /// Override direction for all media
    pub direction_override: Option<Direction>,
    /// Reject specific media by index
    pub reject_media: Vec<usize>,
    /// Username for origin line
    pub username: String,
    /// Session ID for origin line
    pub session_id: String,
    /// Current QoS status for local segment (RFC 3312)
    pub qos_local_status: Option<PreconditionDirection>,
    /// Current QoS status for remote segment (RFC 3312)
    pub qos_remote_status: Option<PreconditionDirection>,
    /// Upgrade strength tags to mandatory (RFC 3312)
    pub upgrade_preconditions_to_mandatory: bool,
}

impl Default for AnswerOptions {
    fn default() -> Self {
        Self {
            local_address: "0.0.0.0".to_string(),
            base_port: 50000,
            audio_codecs: vec![
                CodecInfo::new("PCMU", 8000, Some(1)),
                CodecInfo::new("PCMA", 8000, Some(1)),
                CodecInfo::new("telephone-event", 8000, Some(1)),
            ],
            video_codecs: vec![
                CodecInfo::new("H264", 90000, None),
                CodecInfo::new("VP8", 90000, None),
            ],
            direction_override: None,
            reject_media: Vec::new(),
            username: "-".to_string(),
            session_id: "0".to_string(),
            qos_local_status: None,
            qos_remote_status: None,
            upgrade_preconditions_to_mandatory: false,
        }
    }
}

/// Codec information for negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecInfo {
    pub name: String,
    pub clock_rate: u32,
    pub channels: Option<u16>,
    pub fmtp: Option<String>,
}

impl CodecInfo {
    pub fn new(name: impl Into<String>, clock_rate: u32, channels: Option<u16>) -> Self {
        Self {
            name: name.into(),
            clock_rate,
            channels,
            fmtp: None,
        }
    }

    pub fn with_fmtp(mut self, fmtp: impl Into<String>) -> Self {
        self.fmtp = Some(fmtp.into());
        self
    }

    /// Check if this codec matches an RtpMap
    pub fn matches(&self, rtpmap: &RtpMap) -> bool {
        self.name.eq_ignore_ascii_case(&rtpmap.encoding_name)
            && self.clock_rate == rtpmap.clock_rate
    }
}

/// RFC 3264 Offer/Answer negotiation engine.
pub struct OfferAnswerEngine {}

impl OfferAnswerEngine {
    /// Creates a new offer/answer engine.
    pub fn new() -> Self {
        Self {}
    }

    /// Generates an answer SDP for the given offer.
    ///
    /// # RFC 3264 Compliance
    ///
    /// - Creates matching media stream for each offer stream
    /// - Selects common codecs from offer
    /// - Negotiates direction attributes
    /// - Can reject streams with port 0
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::sdp::SdpSession;
    /// use sip_core::sdp_offer_answer::{OfferAnswerEngine, AnswerOptions};
    ///
    /// let offer_sdp = "v=0\r\n\
    ///                  o=alice 123 456 IN IP4 192.0.2.1\r\n\
    ///                  s=Call\r\n\
    ///                  c=IN IP4 192.0.2.1\r\n\
    ///                  t=0 0\r\n\
    ///                  m=audio 49170 RTP/AVP 0 8\r\n\
    ///                  a=rtpmap:0 PCMU/8000\r\n\
    ///                  a=rtpmap:8 PCMA/8000\r\n";
    ///
    /// let offer = SdpSession::parse(offer_sdp).unwrap();
    /// let engine = OfferAnswerEngine::new();
    /// let answer = engine.generate_answer(&offer, AnswerOptions::default()).unwrap();
    ///
    /// assert_eq!(answer.media.len(), 1);
    /// assert_eq!(answer.media[0].media, "audio");
    /// ```
    pub fn generate_answer(
        &self,
        offer: &SdpSession,
        options: AnswerOptions,
    ) -> Result<SdpSession, NegotiationError> {
        // Create answer origin
        let answer_origin = Origin {
            username: options.username.clone(),
            sess_id: options.session_id.clone(),
            sess_version: "0".to_string(),
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            unicast_address: options.local_address.clone(),
        };

        let mut answer = SdpSession::new(answer_origin, offer.session_name.clone());

        // Copy timing from offer (RFC 3264: t= line must match)
        answer.timing = offer.timing.clone();

        // Session-level connection
        answer.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: options.local_address.clone(),
        });

        // Process each media stream in order
        let mut current_port = options.base_port;

        for (idx, offer_media) in offer.media.iter().enumerate() {
            // Check if this media should be rejected
            let should_reject = options.reject_media.contains(&idx);

            let answer_media = if should_reject {
                self.create_rejected_media(offer_media)
            } else {
                match self.negotiate_media(offer_media, &options, current_port, idx) {
                    Ok(media) => {
                        current_port += 2; // RTP + RTCP
                        media
                    }
                    Err(_) => {
                        // No common codecs - reject
                        self.create_rejected_media(offer_media)
                    }
                }
            };

            answer.media.push(answer_media);
        }

        Ok(answer)
    }

    /// Negotiates a single media stream.
    fn negotiate_media(
        &self,
        offer_media: &MediaDescription,
        options: &AnswerOptions,
        port: u16,
        media_idx: usize,
    ) -> Result<MediaDescription, NegotiationError> {
        // Get offer's rtpmap attributes
        let offer_rtpmaps = self.extract_rtpmaps(offer_media);

        // Select supported codecs
        let supported_codecs = match offer_media.media.as_str() {
            "audio" => &options.audio_codecs,
            "video" => &options.video_codecs,
            _ => {
                return Err(NegotiationError::NoCommonCodecs(media_idx));
            }
        };

        // Find common codecs
        let mut common_codecs: Vec<(String, &RtpMap)> = Vec::new();

        for (payload, rtpmap) in &offer_rtpmaps {
            for codec in supported_codecs {
                if codec.matches(rtpmap) {
                    common_codecs.push((payload.clone(), rtpmap));
                    break;
                }
            }
        }

        if common_codecs.is_empty() {
            return Err(NegotiationError::NoCommonCodecs(media_idx));
        }

        // Build format list (payload types from offer)
        let fmt: Vec<String> = common_codecs.iter().map(|(pt, _)| pt.clone()).collect();

        // Build attributes (rtpmap + fmtp if present)
        let mut attributes = Vec::new();

        // Add rtpmap for each selected codec
        for (payload, rtpmap) in &common_codecs {
            attributes.push(Attribute {
                name: "rtpmap".to_string(),
                value: Some(rtpmap.to_value()),
            });

            // Copy fmtp if present in offer
            if let Some(fmtp_value) = self.find_fmtp_for_payload(offer_media, payload) {
                attributes.push(Attribute {
                    name: "fmtp".to_string(),
                    value: Some(fmtp_value),
                });
            }
        }

        // Negotiate direction
        let offer_direction = self.get_media_direction(offer_media);
        let answer_direction = if let Some(override_dir) = options.direction_override {
            override_dir
        } else {
            self.negotiate_direction(offer_direction)
        };

        attributes.push(Attribute {
            name: answer_direction.as_str().to_string(),
            value: None,
        });

        // Handle preconditions (RFC 3312)
        self.handle_preconditions(offer_media, options, &mut attributes);

        Ok(MediaDescription {
            media: offer_media.media.clone(),
            port,
            port_count: None,
            proto: offer_media.proto.clone(),
            fmt,
            title: None,
            connection: None, // Use session-level
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes,
            mid: offer_media.mid.clone(), // Preserve mid from offer (RFC 3388)
            rtcp: offer_media.rtcp.clone(), // Preserve rtcp from offer (RFC 3605)
            capability_set: offer_media.capability_set.clone(), // Preserve capabilities from offer (RFC 3407)
        })
    }

    /// Creates a rejected media description (port 0).
    fn create_rejected_media(&self, offer_media: &MediaDescription) -> MediaDescription {
        MediaDescription {
            media: offer_media.media.clone(),
            port: 0, // Port 0 = rejected
            port_count: None,
            proto: offer_media.proto.clone(),
            fmt: offer_media.fmt.clone(), // Copy formats (ignored per RFC 3264)
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: offer_media.mid.clone(), // Preserve mid from offer (RFC 3388)
            rtcp: None,                   // No rtcp for rejected media
            capability_set: offer_media.capability_set.clone(), // Preserve capabilities from offer (RFC 3407)
        }
    }

    /// Extracts rtpmap attributes from media description.
    fn extract_rtpmaps(&self, media: &MediaDescription) -> HashMap<String, RtpMap> {
        let mut rtpmaps = HashMap::new();

        for attr in &media.attributes {
            if attr.name == "rtpmap" {
                if let Some(ref value) = attr.value {
                    if let Some(rtpmap) = RtpMap::parse(value) {
                        rtpmaps.insert(rtpmap.payload_type.to_string(), rtpmap);
                    }
                }
            }
        }

        // Add static payload types if not explicitly mapped
        for fmt in &media.fmt {
            if !rtpmaps.contains_key(fmt) {
                if let Some(rtpmap) = self.get_static_payload_rtpmap(fmt) {
                    rtpmaps.insert(fmt.clone(), rtpmap);
                }
            }
        }

        rtpmaps
    }

    /// Gets static RTP payload mapping for well-known payload types.
    fn get_static_payload_rtpmap(&self, payload: &str) -> Option<RtpMap> {
        match payload {
            "0" => Some(RtpMap {
                payload_type: 0,
                encoding_name: "PCMU".to_string(),
                clock_rate: 8000,
                encoding_params: None,
            }),
            "8" => Some(RtpMap {
                payload_type: 8,
                encoding_name: "PCMA".to_string(),
                clock_rate: 8000,
                encoding_params: None,
            }),
            "3" => Some(RtpMap {
                payload_type: 3,
                encoding_name: "GSM".to_string(),
                clock_rate: 8000,
                encoding_params: None,
            }),
            "4" => Some(RtpMap {
                payload_type: 4,
                encoding_name: "G723".to_string(),
                clock_rate: 8000,
                encoding_params: None,
            }),
            "9" => Some(RtpMap {
                payload_type: 9,
                encoding_name: "G722".to_string(),
                clock_rate: 8000,
                encoding_params: None,
            }),
            "18" => Some(RtpMap {
                payload_type: 18,
                encoding_name: "G729".to_string(),
                clock_rate: 8000,
                encoding_params: None,
            }),
            _ => None,
        }
    }

    /// Finds fmtp attribute value for a specific payload type.
    fn find_fmtp_for_payload(&self, media: &MediaDescription, payload: &str) -> Option<String> {
        for attr in &media.attributes {
            if attr.name == "fmtp" {
                if let Some(ref value) = attr.value {
                    if let Some(fmtp) = Fmtp::parse(value) {
                        if fmtp.format == payload {
                            return Some(value.clone());
                        }
                    }
                }
            }
        }
        None
    }

    /// Gets direction attribute from media description.
    fn get_media_direction(&self, media: &MediaDescription) -> Direction {
        for attr in &media.attributes {
            if attr.value.is_none() {
                if let Some(dir) = Direction::parse(&attr.name) {
                    return dir;
                }
            }
        }
        Direction::SendRecv // Default
    }

    /// Negotiates direction attribute per RFC 3264 Table 1.
    ///
    /// | Offer      | Answer Options               |
    /// |------------|------------------------------|
    /// | sendrecv   | sendrecv, sendonly, recvonly, inactive |
    /// | sendonly   | recvonly, inactive           |
    /// | recvonly   | sendonly, inactive           |
    /// | inactive   | inactive                     |
    fn negotiate_direction(&self, offer_direction: Direction) -> Direction {
        match offer_direction {
            Direction::SendRecv => Direction::SendRecv, // Accept bidirectional
            Direction::SendOnly => Direction::RecvOnly, // We receive, they send
            Direction::RecvOnly => Direction::SendOnly, // We send, they receive
            Direction::Inactive => Direction::Inactive, // No media
        }
    }

    /// Creates a hold offer from an active session.
    ///
    /// # RFC 3264 Hold
    ///
    /// - sendrecv → sendonly (send music on hold)
    /// - recvonly → inactive (no media)
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_core::sdp::SdpSession;
    /// use sip_core::sdp_offer_answer::OfferAnswerEngine;
    ///
    /// let active_session = SdpSession::parse(concat!(
    ///     "v=0\r\n",
    ///     "o=alice 123 456 IN IP4 192.0.2.1\r\n",
    ///     "s=Example Session\r\n",
    ///     "c=IN IP4 192.0.2.1\r\n",
    ///     "t=0 0\r\n",
    ///     "m=audio 49170 RTP/AVP 0\r\n",
    ///     "a=rtpmap:0 PCMU/8000\r\n",
    /// )).unwrap();
    /// let engine = OfferAnswerEngine::new();
    /// let hold_offer = engine.create_hold_offer(&active_session);
    ///
    /// // All media streams now sendonly or inactive
    /// ```
    pub fn create_hold_offer(&self, session: &SdpSession) -> SdpSession {
        let mut hold_session = session.clone();

        // Increment session version
        if let Ok(version) = hold_session.origin.sess_version.parse::<u64>() {
            hold_session.origin.sess_version = (version + 1).to_string();
        }

        // Update direction for each media stream
        for media in &mut hold_session.media {
            let current_dir = self.get_media_direction(media);

            let hold_dir = match current_dir {
                Direction::SendRecv => Direction::SendOnly, // Send music on hold
                Direction::RecvOnly => Direction::Inactive, // No media
                Direction::SendOnly => Direction::SendOnly, // Already hold
                Direction::Inactive => Direction::Inactive, // Already inactive
            };

            // Remove old direction attribute
            media
                .attributes
                .retain(|attr| attr.value.is_some() || Direction::parse(&attr.name).is_none());

            // Add new direction
            media.attributes.push(Attribute {
                name: hold_dir.as_str().to_string(),
                value: None,
            });
        }

        hold_session
    }

    /// Creates a resume offer from a held session.
    ///
    /// # RFC 3264 Resume
    ///
    /// - sendonly → sendrecv (resume bidirectional)
    /// - inactive → recvonly (resume receiving)
    pub fn create_resume_offer(&self, session: &SdpSession) -> SdpSession {
        let mut resume_session = session.clone();

        // Increment session version
        if let Ok(version) = resume_session.origin.sess_version.parse::<u64>() {
            resume_session.origin.sess_version = (version + 1).to_string();
        }

        // Update direction for each media stream
        for media in &mut resume_session.media {
            let current_dir = self.get_media_direction(media);

            let resume_dir = match current_dir {
                Direction::SendOnly => Direction::SendRecv, // Resume bidirectional
                Direction::Inactive => Direction::RecvOnly, // Resume receiving
                Direction::SendRecv => Direction::SendRecv, // Already active
                Direction::RecvOnly => Direction::RecvOnly, // Keep receiving
            };

            // Remove old direction attribute
            media
                .attributes
                .retain(|attr| attr.value.is_some() || Direction::parse(&attr.name).is_none());

            // Add new direction
            media.attributes.push(Attribute {
                name: resume_dir.as_str().to_string(),
                value: None,
            });
        }

        resume_session
    }

    /// Handles preconditions in offer/answer (RFC 3312).
    ///
    /// Processes precondition attributes from the offer and adds appropriate
    /// precondition attributes to the answer according to RFC 3312 rules:
    ///
    /// - Inverts status types (local <-> remote, E2E unchanged)
    /// - Inverts directions (send <-> recv, sendrecv/none unchanged)
    /// - Can upgrade strength tags (but never downgrade)
    /// - Sets current status based on answerer's capabilities
    /// - Copies/upgrades desired status from offer
    /// - Handles confirmation requests
    fn handle_preconditions(
        &self,
        offer_media: &MediaDescription,
        options: &AnswerOptions,
        attributes: &mut Vec<Attribute>,
    ) {
        // Extract preconditions from offer
        let mut offer_curr: Vec<CurrentStatus> = Vec::new();
        let mut offer_des: Vec<DesiredStatus> = Vec::new();
        let mut offer_conf: Vec<ConfirmStatus> = Vec::new();

        for attr in &offer_media.attributes {
            if attr.name == "curr" {
                if let Some(value) = &attr.value {
                    if let Ok(curr) = CurrentStatus::parse(value) {
                        offer_curr.push(curr);
                    }
                }
            } else if attr.name == "des" {
                if let Some(value) = &attr.value {
                    if let Ok(des) = DesiredStatus::parse(value) {
                        offer_des.push(des);
                    }
                }
            } else if attr.name == "conf" {
                if let Some(value) = &attr.value {
                    if let Ok(conf) = ConfirmStatus::parse(value) {
                        offer_conf.push(conf);
                    }
                }
            }
        }

        // If no preconditions in offer, nothing to do
        if offer_curr.is_empty() && offer_des.is_empty() && offer_conf.is_empty() {
            return;
        }

        // Process current status - invert and set based on answerer capabilities
        for offer_c in &offer_curr {
            // Only handle QoS for now
            if !matches!(offer_c.precondition_type, PreconditionType::Qos) {
                continue;
            }

            let inverted_status_type = offer_c.status_type.invert();
            let inverted_direction = offer_c.direction.invert();

            // Determine answer's current status based on options
            let answer_direction = match inverted_status_type {
                StatusType::Local => {
                    // Answer's local = Offer's remote
                    options
                        .qos_local_status
                        .unwrap_or(PreconditionDirection::None)
                }
                StatusType::Remote => {
                    // Answer's remote = Offer's local
                    options
                        .qos_remote_status
                        .unwrap_or(PreconditionDirection::None)
                }
                StatusType::E2E => {
                    // E2E status: use inverted direction if options not set
                    // This allows E2E to be negotiated end-to-end
                    inverted_direction
                }
            };

            attributes.push(Attribute {
                name: "curr".to_string(),
                value: Some(
                    CurrentStatus {
                        precondition_type: offer_c.precondition_type.clone(),
                        status_type: inverted_status_type,
                        direction: answer_direction,
                    }
                    .to_string(),
                ),
            });
        }

        // Process desired status - invert and optionally upgrade
        for offer_d in &offer_des {
            // Only handle QoS for now
            if !matches!(offer_d.precondition_type, PreconditionType::Qos) {
                continue;
            }

            let inverted_status_type = offer_d.status_type.invert();
            let inverted_direction = offer_d.direction.invert();

            // Optionally upgrade strength
            let answer_strength = if options.upgrade_preconditions_to_mandatory
                && offer_d.strength == StrengthTag::Optional
            {
                StrengthTag::Mandatory
            } else {
                offer_d.strength
            };

            attributes.push(Attribute {
                name: "des".to_string(),
                value: Some(
                    DesiredStatus {
                        precondition_type: offer_d.precondition_type.clone(),
                        strength: answer_strength,
                        status_type: inverted_status_type,
                        direction: inverted_direction,
                    }
                    .to_string(),
                ),
            });
        }

        // Process confirm status - invert
        for offer_conf_item in &offer_conf {
            // Only handle QoS for now
            if !matches!(offer_conf_item.precondition_type, PreconditionType::Qos) {
                continue;
            }

            let inverted_status_type = offer_conf_item.status_type.invert();
            let inverted_direction = offer_conf_item.direction.invert();

            attributes.push(Attribute {
                name: "conf".to_string(),
                value: Some(
                    ConfirmStatus {
                        precondition_type: offer_conf_item.precondition_type.clone(),
                        status_type: inverted_status_type,
                        direction: inverted_direction,
                    }
                    .to_string(),
                ),
            });
        }
    }
}

impl Default for OfferAnswerEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_basic_answer() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0 8\r\n\
                         a=rtpmap:0 PCMU/8000\r\n\
                         a=rtpmap:8 PCMA/8000\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        assert_eq!(answer.media.len(), 1);
        assert_eq!(answer.media[0].media, "audio");
        assert_ne!(answer.media[0].port, 0); // Not rejected
        assert!(!answer.media[0].fmt.is_empty()); // Has codecs
    }

    #[test]
    fn codec_negotiation_selects_common() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0 8 18\r\n\
                         a=rtpmap:0 PCMU/8000\r\n\
                         a=rtpmap:8 PCMA/8000\r\n\
                         a=rtpmap:18 G729/8000\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();

        let mut options = AnswerOptions::default();
        options.audio_codecs = vec![
            CodecInfo::new("PCMU", 8000, Some(1)), // Common
            CodecInfo::new("PCMA", 8000, Some(1)), // Common
                                                   // G729 not supported
        ];

        let engine = OfferAnswerEngine::new();
        let answer = engine.generate_answer(&offer, options).unwrap();

        // Should have 2 codecs (PCMU and PCMA)
        assert_eq!(answer.media[0].fmt.len(), 2);
        assert!(answer.media[0].fmt.contains(&"0".to_string())); // PCMU
        assert!(answer.media[0].fmt.contains(&"8".to_string())); // PCMA
    }

    #[test]
    fn reject_media_with_port_zero() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         m=video 51372 RTP/AVP 99\r\n\
                         a=rtpmap:99 H264/90000\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();

        let mut options = AnswerOptions::default();
        options.reject_media = vec![1]; // Reject video

        let engine = OfferAnswerEngine::new();
        let answer = engine.generate_answer(&offer, options).unwrap();

        assert_eq!(answer.media.len(), 2);
        assert_ne!(answer.media[0].port, 0); // Audio accepted
        assert_eq!(answer.media[1].port, 0); // Video rejected
    }

    #[test]
    fn direction_negotiation_sendonly() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=sendonly\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        // Offer is sendonly, answer should be recvonly
        let answer_dir = engine.get_media_direction(&answer.media[0]);
        assert_eq!(answer_dir, Direction::RecvOnly);
    }

    #[test]
    fn hold_offer_changes_to_sendonly() {
        let active_sdp = "v=0\r\n\
                          o=alice 123 0 IN IP4 192.0.2.1\r\n\
                          s=Call\r\n\
                          c=IN IP4 192.0.2.1\r\n\
                          t=0 0\r\n\
                          m=audio 49170 RTP/AVP 0\r\n\
                          a=sendrecv\r\n";

        let active_session = SdpSession::parse(active_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let hold_offer = engine.create_hold_offer(&active_session);

        // Direction should be sendonly
        let hold_dir = engine.get_media_direction(&hold_offer.media[0]);
        assert_eq!(hold_dir, Direction::SendOnly);

        // Version should increment
        assert_eq!(hold_offer.origin.sess_version, "1");
    }

    #[test]
    fn resume_offer_restores_sendrecv() {
        let held_sdp = "v=0\r\n\
                        o=alice 123 1 IN IP4 192.0.2.1\r\n\
                        s=Call\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 49170 RTP/AVP 0\r\n\
                        a=sendonly\r\n";

        let held_session = SdpSession::parse(held_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let resume_offer = engine.create_resume_offer(&held_session);

        // Direction should be sendrecv
        let resume_dir = engine.get_media_direction(&resume_offer.media[0]);
        assert_eq!(resume_dir, Direction::SendRecv);

        // Version should increment
        assert_eq!(resume_offer.origin.sess_version, "2");
    }

    #[test]
    fn static_payload_type_mapping() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0 8\r\n";
        // No explicit rtpmap (uses static payload types)

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        // Should still negotiate PCMU (0) and PCMA (8)
        assert_eq!(answer.media[0].fmt.len(), 2);
        assert!(answer.media[0].fmt.contains(&"0".to_string()));
        assert!(answer.media[0].fmt.contains(&"8".to_string()));
    }

    #[test]
    fn fmtp_copied_to_answer() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 101\r\n\
                         a=rtpmap:101 telephone-event/8000\r\n\
                         a=fmtp:101 0-15\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        // Check that fmtp is present in answer
        let has_fmtp = answer.media[0]
            .attributes
            .iter()
            .any(|attr| attr.name == "fmtp" && attr.value.as_ref().unwrap().starts_with("101"));

        assert!(has_fmtp);
    }

    // RFC 3312 Preconditions Tests

    #[test]
    fn answer_inverts_precondition_status_types() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=curr:qos local sendrecv\r\n\
                         a=curr:qos remote none\r\n\
                         a=des:qos mandatory local sendrecv\r\n\
                         a=des:qos mandatory remote sendrecv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();

        let mut options = AnswerOptions::default();
        options.qos_local_status = Some(PreconditionDirection::SendRecv);

        let answer = engine.generate_answer(&offer, options).unwrap();

        // Check that status types are inverted (local <-> remote)
        let curr_statuses = answer.find_current_status(0);
        assert_eq!(curr_statuses.len(), 2);

        // Offer's local becomes answer's remote
        assert!(curr_statuses
            .iter()
            .any(|c| c.status_type == StatusType::Remote));
        // Offer's remote becomes answer's local
        assert!(curr_statuses
            .iter()
            .any(|c| c.status_type == StatusType::Local));
    }

    #[test]
    fn answer_inverts_precondition_directions() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=curr:qos e2e send\r\n\
                         a=des:qos mandatory e2e recv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        let curr_statuses = answer.find_current_status(0);
        assert_eq!(curr_statuses.len(), 1);
        // Offer's send becomes answer's recv
        assert_eq!(curr_statuses[0].direction, PreconditionDirection::Recv);

        let des_statuses = answer.find_desired_status(0);
        assert_eq!(des_statuses.len(), 1);
        // Offer's recv becomes answer's send
        assert_eq!(des_statuses[0].direction, PreconditionDirection::Send);
    }

    #[test]
    fn answer_e2e_status_unchanged() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=curr:qos e2e none\r\n\
                         a=des:qos mandatory e2e sendrecv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        // E2E status type should remain E2E
        let curr_statuses = answer.find_current_status(0);
        assert_eq!(curr_statuses.len(), 1);
        assert_eq!(curr_statuses[0].status_type, StatusType::E2E);

        let des_statuses = answer.find_desired_status(0);
        assert_eq!(des_statuses.len(), 1);
        assert_eq!(des_statuses[0].status_type, StatusType::E2E);
    }

    #[test]
    fn answer_can_upgrade_strength_tags() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=curr:qos e2e none\r\n\
                         a=des:qos optional e2e sendrecv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();

        let mut options = AnswerOptions::default();
        options.upgrade_preconditions_to_mandatory = true;

        let answer = engine.generate_answer(&offer, options).unwrap();

        let des_statuses = answer.find_desired_status(0);
        assert_eq!(des_statuses.len(), 1);
        // Optional should be upgraded to mandatory
        assert_eq!(des_statuses[0].strength, StrengthTag::Mandatory);
    }

    #[test]
    fn answer_preserves_mandatory_strength() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=des:qos mandatory e2e sendrecv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        let des_statuses = answer.find_desired_status(0);
        assert_eq!(des_statuses.len(), 1);
        assert_eq!(des_statuses[0].strength, StrengthTag::Mandatory);
    }

    #[test]
    fn answer_sets_current_status_from_options() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=curr:qos local sendrecv\r\n\
                         a=curr:qos remote none\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();

        let mut options = AnswerOptions::default();
        options.qos_local_status = Some(PreconditionDirection::SendRecv);
        options.qos_remote_status = Some(PreconditionDirection::None);

        let answer = engine.generate_answer(&offer, options).unwrap();

        let curr_statuses = answer.find_current_status(0);
        assert_eq!(curr_statuses.len(), 2);

        // Answer's local (offer's remote) should be set from qos_local_status
        let local_status = curr_statuses
            .iter()
            .find(|c| c.status_type == StatusType::Local);
        assert!(local_status.is_some());
        assert_eq!(
            local_status.unwrap().direction,
            PreconditionDirection::SendRecv
        );

        // Answer's remote (offer's local) should be set from qos_remote_status
        let remote_status = curr_statuses
            .iter()
            .find(|c| c.status_type == StatusType::Remote);
        assert!(remote_status.is_some());
        assert_eq!(
            remote_status.unwrap().direction,
            PreconditionDirection::None
        );
    }

    #[test]
    fn answer_handles_confirm_status() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=conf:qos e2e recv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        let conf_statuses = answer.find_confirm_status(0);
        assert_eq!(conf_statuses.len(), 1);
        assert_eq!(conf_statuses[0].status_type, StatusType::E2E);
        // Offer's recv becomes answer's send
        assert_eq!(conf_statuses[0].direction, PreconditionDirection::Send);
    }

    #[test]
    fn answer_without_preconditions_in_offer() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        // No preconditions should be added to answer
        let curr_statuses = answer.find_current_status(0);
        assert_eq!(curr_statuses.len(), 0);

        let des_statuses = answer.find_desired_status(0);
        assert_eq!(des_statuses.len(), 0);

        let conf_statuses = answer.find_confirm_status(0);
        assert_eq!(conf_statuses.len(), 0);
    }

    #[test]
    fn answer_with_segmented_preconditions() {
        let offer_sdp = "v=0\r\n\
                         o=alice 123 456 IN IP4 192.0.2.1\r\n\
                         s=Call\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 49170 RTP/AVP 0\r\n\
                         a=curr:qos local sendrecv\r\n\
                         a=curr:qos remote none\r\n\
                         a=des:qos mandatory local sendrecv\r\n\
                         a=des:qos mandatory remote sendrecv\r\n\
                         a=conf:qos local send\r\n\
                         a=conf:qos remote recv\r\n";

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();

        let mut options = AnswerOptions::default();
        options.qos_local_status = Some(PreconditionDirection::SendRecv);

        let answer = engine.generate_answer(&offer, options).unwrap();

        // Verify all precondition types are present and inverted
        let curr_statuses = answer.find_current_status(0);
        assert_eq!(curr_statuses.len(), 2);

        let des_statuses = answer.find_desired_status(0);
        assert_eq!(des_statuses.len(), 2);

        let conf_statuses = answer.find_confirm_status(0);
        assert_eq!(conf_statuses.len(), 2);

        // Verify status type inversion
        assert!(curr_statuses
            .iter()
            .any(|c| c.status_type == StatusType::Local));
        assert!(curr_statuses
            .iter()
            .any(|c| c.status_type == StatusType::Remote));
    }
}
