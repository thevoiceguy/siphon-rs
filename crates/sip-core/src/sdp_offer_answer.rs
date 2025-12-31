// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3264: SDP Offer/Answer Model implementation.
//!
//! This module provides comprehensive support for SDP offer/answer negotiation
//! as defined in RFC 3264.

use crate::sdp::{
    Attribute, ConfirmStatus, Connection, CurrentStatus, DesiredStatus, Direction, Fmtp,
    MediaDescription, Origin, PreconditionDirection, PreconditionType, RtpMap, SdpSession,
    StatusType, StrengthTag,
};
use std::collections::HashMap;
use std::fmt;

const MAX_CODEC_NAME_LENGTH: usize = 64;
const MAX_FMTP_LENGTH: usize = 256;
const MAX_ADDRESS_LENGTH: usize = 256;
const MAX_USERNAME_LENGTH: usize = 128;
const MAX_SESSION_ID_LENGTH: usize = 128;
const MAX_CODECS_PER_TYPE: usize = 50;
const MAX_REJECT_MEDIA: usize = 20;
const MAX_MEDIA_STREAMS: usize = 20;

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
    /// Input validation error
    ValidationError(String),
    /// Too many media streams
    TooManyMediaStreams { max: usize, actual: usize },
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
            NegotiationError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            NegotiationError::TooManyMediaStreams { max, actual } => {
                write!(f, "Too many media streams (max {}, got {})", max, actual)
            }
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Configuration for generating answers.
///
/// # Security
///
/// AnswerOptions validates all string inputs for length to prevent DoS attacks.
/// Collections are bounded to prevent memory exhaustion.
#[derive(Debug, Clone)]
pub struct AnswerOptions {
    local_address: String,
    base_port: u16,
    audio_codecs: Vec<CodecInfo>,
    video_codecs: Vec<CodecInfo>,
    direction_override: Option<Direction>,
    reject_media: Vec<usize>,
    username: String,
    session_id: String,
    qos_local_status: Option<PreconditionDirection>,
    qos_remote_status: Option<PreconditionDirection>,
    upgrade_preconditions_to_mandatory: bool,
}

impl AnswerOptions {
    /// Creates new AnswerOptions with validated inputs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the local address.
    pub fn with_local_address(
        mut self,
        address: impl AsRef<str>,
    ) -> Result<Self, NegotiationError> {
        validate_address(address.as_ref())?;
        self.local_address = address.as_ref().to_string();
        Ok(self)
    }

    /// Sets the base port.
    pub fn with_base_port(mut self, port: u16) -> Self {
        self.base_port = port;
        self
    }

    /// Sets audio codecs.
    pub fn with_audio_codecs(mut self, codecs: Vec<CodecInfo>) -> Result<Self, NegotiationError> {
        if codecs.len() > MAX_CODECS_PER_TYPE {
            return Err(NegotiationError::ValidationError(format!(
                "Too many audio codecs (max {})",
                MAX_CODECS_PER_TYPE
            )));
        }
        self.audio_codecs = codecs;
        Ok(self)
    }

    /// Sets video codecs.
    pub fn with_video_codecs(mut self, codecs: Vec<CodecInfo>) -> Result<Self, NegotiationError> {
        if codecs.len() > MAX_CODECS_PER_TYPE {
            return Err(NegotiationError::ValidationError(format!(
                "Too many video codecs (max {})",
                MAX_CODECS_PER_TYPE
            )));
        }
        self.video_codecs = codecs;
        Ok(self)
    }

    /// Sets direction override.
    pub fn with_direction_override(mut self, direction: Direction) -> Self {
        self.direction_override = Some(direction);
        self
    }

    /// Sets media streams to reject.
    pub fn with_reject_media(mut self, reject: Vec<usize>) -> Result<Self, NegotiationError> {
        if reject.len() > MAX_REJECT_MEDIA {
            return Err(NegotiationError::ValidationError(format!(
                "Too many reject indices (max {})",
                MAX_REJECT_MEDIA
            )));
        }
        self.reject_media = reject;
        Ok(self)
    }

    /// Sets username for origin line.
    pub fn with_username(mut self, username: impl AsRef<str>) -> Result<Self, NegotiationError> {
        validate_username(username.as_ref())?;
        self.username = username.as_ref().to_string();
        Ok(self)
    }

    /// Sets session ID for origin line.
    pub fn with_session_id(
        mut self,
        session_id: impl AsRef<str>,
    ) -> Result<Self, NegotiationError> {
        validate_session_id(session_id.as_ref())?;
        self.session_id = session_id.as_ref().to_string();
        Ok(self)
    }

    /// Sets QoS local status.
    pub fn with_qos_local_status(mut self, status: PreconditionDirection) -> Self {
        self.qos_local_status = Some(status);
        self
    }

    /// Sets QoS remote status.
    pub fn with_qos_remote_status(mut self, status: PreconditionDirection) -> Self {
        self.qos_remote_status = Some(status);
        self
    }

    /// Sets precondition upgrade flag.
    pub fn with_upgrade_preconditions(mut self, upgrade: bool) -> Self {
        self.upgrade_preconditions_to_mandatory = upgrade;
        self
    }

    // Getters
    pub fn local_address(&self) -> &str {
        &self.local_address
    }

    pub fn base_port(&self) -> u16 {
        self.base_port
    }

    pub fn audio_codecs(&self) -> &[CodecInfo] {
        &self.audio_codecs
    }

    pub fn video_codecs(&self) -> &[CodecInfo] {
        &self.video_codecs
    }

    pub fn direction_override(&self) -> Option<Direction> {
        self.direction_override
    }

    pub fn reject_media(&self) -> &[usize] {
        &self.reject_media
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn qos_local_status(&self) -> Option<PreconditionDirection> {
        self.qos_local_status
    }

    pub fn qos_remote_status(&self) -> Option<PreconditionDirection> {
        self.qos_remote_status
    }

    pub fn upgrade_preconditions_to_mandatory(&self) -> bool {
        self.upgrade_preconditions_to_mandatory
    }
}

impl Default for AnswerOptions {
    fn default() -> Self {
        Self {
            local_address: "0.0.0.0".to_string(),
            base_port: 50000,
            audio_codecs: vec![
                CodecInfo::new("PCMU", 8000, Some(1)).ok(),
                CodecInfo::new("PCMA", 8000, Some(1)).ok(),
                CodecInfo::new("telephone-event", 8000, Some(1)).ok(),
            ]
            .into_iter()
            .flatten()
            .collect(),
            video_codecs: vec![
                CodecInfo::new("H264", 90000, None).ok(),
                CodecInfo::new("VP8", 90000, None).ok(),
            ]
            .into_iter()
            .flatten()
            .collect(),
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
///
/// # Security
///
/// CodecInfo validates all string inputs for length and content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecInfo {
    name: String,
    clock_rate: u32,
    channels: Option<u16>,
    fmtp: Option<String>,
}

impl CodecInfo {
    /// Creates a new codec info with validation.
    pub fn new(
        name: impl AsRef<str>,
        clock_rate: u32,
        channels: Option<u16>,
    ) -> Result<Self, NegotiationError> {
        validate_codec_name(name.as_ref())?;

        Ok(Self {
            name: name.as_ref().to_string(),
            clock_rate,
            channels,
            fmtp: None,
        })
    }

    /// Sets the FMTP parameter with validation.
    pub fn with_fmtp(mut self, fmtp: impl AsRef<str>) -> Result<Self, NegotiationError> {
        validate_fmtp(fmtp.as_ref())?;
        self.fmtp = Some(fmtp.as_ref().to_string());
        Ok(self)
    }

    /// Returns the codec name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the clock rate.
    pub fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Returns the number of channels.
    pub fn channels(&self) -> Option<u16> {
        self.channels
    }

    /// Returns the FMTP parameter.
    pub fn fmtp(&self) -> Option<&str> {
        self.fmtp.as_deref()
    }

    /// Check if this codec matches an RtpMap
    pub fn matches(&self, rtpmap: &RtpMap) -> bool {
        if !self.name.eq_ignore_ascii_case(&rtpmap.encoding_name()) {
            return false;
        }
        if self.clock_rate() != rtpmap.clock_rate() {
            return false;
        }

        match (self.channels, rtpmap.encoding_params().as_deref()) {
            (Some(codec_channels), Some(params)) => {
                params.parse::<u16>().ok() == Some(codec_channels)
            }
            (Some(codec_channels), None) => codec_channels == 1,
            (None, Some(_)) => false,
            (None, None) => true,
        }
    }
}

// Validation functions

fn validate_codec_name(name: &str) -> Result<(), NegotiationError> {
    if name.is_empty() {
        return Err(NegotiationError::ValidationError(
            "Codec name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_CODEC_NAME_LENGTH {
        return Err(NegotiationError::ValidationError(format!(
            "Codec name too long (max {})",
            MAX_CODEC_NAME_LENGTH
        )));
    }

    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(NegotiationError::ValidationError(
            "Codec name contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_fmtp(fmtp: &str) -> Result<(), NegotiationError> {
    if fmtp.len() > MAX_FMTP_LENGTH {
        return Err(NegotiationError::ValidationError(format!(
            "FMTP too long (max {})",
            MAX_FMTP_LENGTH
        )));
    }

    if fmtp.chars().any(|c| c.is_ascii_control()) {
        return Err(NegotiationError::ValidationError(
            "FMTP contains invalid control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_address(address: &str) -> Result<(), NegotiationError> {
    if address.is_empty() {
        return Err(NegotiationError::ValidationError(
            "Address cannot be empty".to_string(),
        ));
    }

    if address.len() > MAX_ADDRESS_LENGTH {
        return Err(NegotiationError::ValidationError(format!(
            "Address too long (max {})",
            MAX_ADDRESS_LENGTH
        )));
    }

    if address.chars().any(|c| c.is_ascii_control()) {
        return Err(NegotiationError::ValidationError(
            "Address contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_username(username: &str) -> Result<(), NegotiationError> {
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(NegotiationError::ValidationError(format!(
            "Username too long (max {})",
            MAX_USERNAME_LENGTH
        )));
    }

    if username.chars().any(|c| c.is_ascii_control()) {
        return Err(NegotiationError::ValidationError(
            "Username contains control characters".to_string(),
        ));
    }

    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), NegotiationError> {
    if session_id.is_empty() {
        return Err(NegotiationError::ValidationError(
            "Session ID cannot be empty".to_string(),
        ));
    }

    if session_id.len() > MAX_SESSION_ID_LENGTH {
        return Err(NegotiationError::ValidationError(format!(
            "Session ID too long (max {})",
            MAX_SESSION_ID_LENGTH
        )));
    }

    if session_id.chars().any(|c| c.is_ascii_control()) {
        return Err(NegotiationError::ValidationError(
            "Session ID contains control characters".to_string(),
        ));
    }

    Ok(())
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
    /// # Security
    ///
    /// Validates offer size and structure before processing.
    pub fn generate_answer(
        &self,
        offer: &SdpSession,
        options: AnswerOptions,
    ) -> Result<SdpSession, NegotiationError> {
        // Validate offer size
        if offer.media().len() > MAX_MEDIA_STREAMS {
            return Err(NegotiationError::TooManyMediaStreams {
                max: MAX_MEDIA_STREAMS,
                actual: offer.media().len(),
            });
        }

        // Create answer origin - use getters
        let answer_origin = Origin {
            username: options.username().to_string(),
            sess_id: options.session_id().to_string(),
            sess_version: "0".to_string(),
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            unicast_address: options.local_address().to_string(),
        };

        let mut answer = SdpSession::new(answer_origin, offer.session_name().to_string());

        // Copy timing from offer (RFC 3264: t= line must match)
        answer.timing = offer.timing.clone();

        // Session-level connection - use getter
        answer.connection = Some(Connection {
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            connection_address: options.local_address().to_string(),
        });

        // Process each media stream in order - use getter
        let mut current_port = options.base_port();

        for (idx, offer_media) in offer.media().iter().enumerate() {
            // Check if this media should be rejected - use getter
            let should_reject = options.reject_media().contains(&idx);

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

        // Select supported codecs - use getters
        let supported_codecs = match offer_media.media() {
            "audio" => options.audio_codecs(),
            "video" => options.video_codecs(),
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

        // Negotiate direction - use getter
        let offer_direction = self.get_media_direction(offer_media);
        let answer_direction = if let Some(override_dir) = options.direction_override() {
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
            media: offer_media.media().to_string(),
            port,
            port_count: None,
            proto: offer_media.proto().to_string(),
            fmt,
            title: None,
            connection: None, // Use session-level
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes,
            mid: offer_media.mid().map(String::from),
            rtcp: offer_media.rtcp().cloned(),
            capability_set: offer_media.capability_set().cloned(),
        })
    }

    /// Creates a rejected media description (port 0).
    fn create_rejected_media(&self, offer_media: &MediaDescription) -> MediaDescription {
        MediaDescription {
            media: offer_media.media().to_string(),
            port: 0,
            port_count: None,
            proto: offer_media.proto().to_string(),
            fmt: offer_media.fmt().to_vec(),
            title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            mid: offer_media.mid().map(String::from),
            rtcp: None,
            capability_set: offer_media.capability_set().cloned(),
        }
    }

    /// Extracts rtpmap attributes from media description.
    fn extract_rtpmaps(&self, media: &MediaDescription) -> HashMap<String, RtpMap> {
        let mut rtpmaps = HashMap::new();

        for attr in media.attributes() {
            if attr.name == "rtpmap" {
                if let Some(ref value) = attr.value {
                    if let Some(rtpmap) = RtpMap::parse(value) {
                        rtpmaps.insert(rtpmap.payload_type().to_string(), rtpmap);
                    }
                }
            }
        }

        // Add static payload types if not explicitly mapped
        for fmt in media.fmt() {
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
        for attr in media.attributes() {
            if attr.name == "fmtp" {
                if let Some(ref value) = attr.value {
                    if let Some(fmtp) = Fmtp::parse(value) {
                        if fmtp.format() == payload {
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
        for attr in media.attributes() {
            if attr.value.is_none() {
                if let Some(dir) = Direction::parse(&attr.name) {
                    return dir;
                }
            }
        }
        Direction::SendRecv
    }

    /// Negotiates direction attribute per RFC 3264 Table 1.
    fn negotiate_direction(&self, offer_direction: Direction) -> Direction {
        match offer_direction {
            Direction::SendRecv => Direction::SendRecv,
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            Direction::Inactive => Direction::Inactive,
        }
    }

    /// Creates a hold offer from an active session.
    pub fn create_hold_offer(&self, session: &SdpSession) -> SdpSession {
        let mut hold_session = session.clone();

        if let Ok(version) = hold_session.origin().sess_version().parse::<u64>() {
            hold_session.origin.sess_version = (version + 1).to_string();
        }

        for media in &mut hold_session.media {
            let current_dir = self.get_media_direction(media);

            let hold_dir = match current_dir {
                Direction::SendRecv => Direction::SendOnly,
                Direction::RecvOnly => Direction::Inactive,
                Direction::SendOnly => Direction::SendOnly,
                Direction::Inactive => Direction::Inactive,
            };

            media
                .attributes
                .retain(|attr| attr.value.is_some() || Direction::parse(&attr.name).is_none());

            media.attributes.push(Attribute {
                name: hold_dir.as_str().to_string(),
                value: None,
            });
        }

        hold_session
    }

    /// Creates a resume offer from a held session.
    pub fn create_resume_offer(&self, session: &SdpSession) -> SdpSession {
        let mut resume_session = session.clone();

        if let Ok(version) = resume_session.origin.sess_version.parse::<u64>() {
            resume_session.origin.sess_version = (version + 1).to_string();
        }

        for media in &mut resume_session.media {
            let current_dir = self.get_media_direction(media);

            let resume_dir = match current_dir {
                Direction::SendOnly => Direction::SendRecv,
                Direction::Inactive => Direction::RecvOnly,
                Direction::SendRecv => Direction::SendRecv,
                Direction::RecvOnly => Direction::RecvOnly,
            };

            media
                .attributes
                .retain(|attr| attr.value.is_some() || Direction::parse(&attr.name).is_none());

            media.attributes.push(Attribute {
                name: resume_dir.as_str().to_string(),
                value: None,
            });
        }

        resume_session
    }

    /// Handles preconditions in offer/answer (RFC 3312).
    fn handle_preconditions(
        &self,
        offer_media: &MediaDescription,
        options: &AnswerOptions,
        attributes: &mut Vec<Attribute>,
    ) {
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

        if offer_curr.is_empty() && offer_des.is_empty() && offer_conf.is_empty() {
            return;
        }

        // Use getters for options
        for offer_c in &offer_curr {
            if !matches!(offer_c.precondition_type, PreconditionType::Qos) {
                continue;
            }

            let inverted_status_type = offer_c.status_type.invert();
            let inverted_direction = offer_c.direction.invert();

            let answer_direction = match inverted_status_type {
                StatusType::Local => options
                    .qos_local_status()
                    .unwrap_or(PreconditionDirection::None),
                StatusType::Remote => options
                    .qos_remote_status()
                    .unwrap_or(PreconditionDirection::None),
                StatusType::E2E => inverted_direction,
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

        for offer_d in &offer_des {
            if !matches!(offer_d.precondition_type, PreconditionType::Qos) {
                continue;
            }

            let inverted_status_type = offer_d.status_type.invert();
            let inverted_direction = offer_d.direction.invert();

            // Use getter
            let answer_strength = if options.upgrade_preconditions_to_mandatory()
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

        for offer_conf_item in &offer_conf {
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

        assert_eq!(answer.media().len(), 1);
        assert_eq!(answer.media()[0].media, "audio");
        assert_ne!(answer.media()[0].port, 0);
        assert!(!answer.media()[0].fmt.is_empty());
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

        let options = AnswerOptions::default()
            .with_audio_codecs(vec![
                CodecInfo::new("PCMU", 8000, Some(1)).unwrap(),
                CodecInfo::new("PCMA", 8000, Some(1)).unwrap(),
            ])
            .unwrap();

        let engine = OfferAnswerEngine::new();
        let answer = engine.generate_answer(&offer, options).unwrap();

        assert_eq!(answer.media()[0].fmt.len(), 2);
        assert!(answer.media()[0].fmt.contains(&"0".to_string()));
        assert!(answer.media()[0].fmt.contains(&"8".to_string()));
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

        let options = AnswerOptions::default().with_reject_media(vec![1]).unwrap();

        let engine = OfferAnswerEngine::new();
        let answer = engine.generate_answer(&offer, options).unwrap();

        assert_eq!(answer.media().len(), 2);
        assert_ne!(answer.media()[0].port, 0);
        assert_eq!(answer.media()[1].port, 0);
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

        let answer_dir = engine.get_media_direction(&answer.media()[0]);
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

        let hold_dir = engine.get_media_direction(&hold_offer.media()[0]);
        assert_eq!(hold_dir, Direction::SendOnly);
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

        let resume_dir = engine.get_media_direction(&resume_offer.media()[0]);
        assert_eq!(resume_dir, Direction::SendRecv);
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

        let offer = SdpSession::parse(offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let answer = engine
            .generate_answer(&offer, AnswerOptions::default())
            .unwrap();

        assert_eq!(answer.media()[0].fmt.len(), 2);
        assert!(answer.media()[0].fmt.contains(&"0".to_string()));
        assert!(answer.media()[0].fmt.contains(&"8".to_string()));
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

        let has_fmtp = answer.media()[0]
            .attributes
            .iter()
            .any(|attr| attr.name == "fmtp" && attr.value.as_ref().unwrap().starts_with("101"));

        assert!(has_fmtp);
    }

    // Security tests

    #[test]
    fn reject_oversized_codec_name() {
        let long_name = "x".repeat(MAX_CODEC_NAME_LENGTH + 1);
        let result = CodecInfo::new(&long_name, 8000, Some(1));
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_codec_name() {
        let result = CodecInfo::new("", 8000, Some(1));
        assert!(result.is_err());
    }

    #[test]
    fn reject_codec_name_with_control_chars() {
        let result = CodecInfo::new("PCMU\r\ninjected", 8000, Some(1));
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_audio_codecs() {
        let mut codecs = Vec::new();
        for i in 0..=MAX_CODECS_PER_TYPE {
            codecs.push(CodecInfo::new(&format!("codec{}", i), 8000, Some(1)).unwrap());
        }

        let result = AnswerOptions::default().with_audio_codecs(codecs);
        assert!(result.is_err());
    }

    #[test]
    fn reject_too_many_media_streams() {
        let mut offer_sdp =
            "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n".to_string();

        for i in 0..=MAX_MEDIA_STREAMS {
            offer_sdp.push_str(&format!("m=audio {} RTP/AVP 0\r\n", 10000 + i * 2));
        }

        let offer = SdpSession::parse(&offer_sdp).unwrap();
        let engine = OfferAnswerEngine::new();
        let result = engine.generate_answer(&offer, AnswerOptions::default());

        assert!(matches!(
            result,
            Err(NegotiationError::TooManyMediaStreams { .. })
        ));
    }

    #[test]
    fn fields_are_private() {
        let codec = CodecInfo::new("PCMU", 8000, Some(1)).unwrap();
        let options = AnswerOptions::default();

        // These should compile (read access via getters)
        let _ = codec.name();
        let _ = codec.clock_rate();
        let _ = options.local_address();

        // These should NOT compile:
        // codec.name = "evil".to_string();           // ← Does not compile!
        // options.local_address = "evil".to_string();// ← Does not compile!
    }

    // RFC 3312 Preconditions tests
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
