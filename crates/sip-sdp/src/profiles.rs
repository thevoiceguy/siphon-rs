//! SDP configuration profiles for common scenarios
//!
//! Provides pre-configured SDP templates for typical use cases like audio-only calls,
//! video conferences, etc. These can be used as starting points and customized as needed.

use crate::*;
use std::collections::HashSet;

/// SDP profile type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpProfile {
    /// Audio-only with PCMU/PCMA codecs
    AudioOnly,
    /// Audio + video with common codecs
    AudioVideo,
    /// Custom profile (application-defined)
    Custom,
}

/// Flexible SDP profile builder for custom media/capability sets.
#[derive(Debug, Clone)]
pub struct MediaProfileBuilder {
    audio_codecs: Vec<(u8, String, u32)>,
    video_codecs: Vec<(u8, String, u32)>,
    include_telephone_event: bool,
    direction: &'static str,
    enable_video: bool,
    rtcp_mux: bool,
}

impl MediaProfileBuilder {
    /// Audio-only profile with PCMU/PCMA + telephone-event.
    pub fn audio_only() -> Self {
        Self {
            audio_codecs: vec![(0, "PCMU".to_string(), 8000), (8, "PCMA".to_string(), 8000)],
            video_codecs: Vec::new(),
            include_telephone_event: true,
            direction: "sendrecv",
            enable_video: false,
            rtcp_mux: true,
        }
    }

    /// Audio+video profile with PCMU/PCMA, H264, VP8.
    pub fn audio_video() -> Self {
        Self {
            audio_codecs: vec![(0, "PCMU".to_string(), 8000), (8, "PCMA".to_string(), 8000)],
            video_codecs: vec![
                (96, "H264".to_string(), 90000),
                (97, "VP8".to_string(), 90000),
            ],
            include_telephone_event: true,
            direction: "sendrecv",
            enable_video: true,
            rtcp_mux: true,
        }
    }

    pub fn add_audio_codec<S: Into<String>>(mut self, payload: u8, name: S, rate: u32) -> Self {
        self.audio_codecs.push((payload, name.into(), rate));
        self
    }

    pub fn add_video_codec<S: Into<String>>(mut self, payload: u8, name: S, rate: u32) -> Self {
        self.enable_video = true;
        self.video_codecs.push((payload, name.into(), rate));
        self
    }

    pub fn direction(mut self, dir: &'static str) -> Self {
        self.direction = dir;
        self
    }

    pub fn telephone_event(mut self, enabled: bool) -> Self {
        self.include_telephone_event = enabled;
        self
    }

    pub fn rtcp_mux(mut self, enabled: bool) -> Self {
        self.rtcp_mux = enabled;
        self
    }

    /// Build an SDP offer based on configured capabilities.
    pub fn build(
        &self,
        username: &str,
        addr: &str,
        audio_port: u16,
        video_port: Option<u16>,
    ) -> SessionDescription {
        let session_id = generate_session_id();
        let mut builder = SessionDescription::builder()
            .origin(username, &session_id, addr)
            .session_name("siphon")
            .connection(addr)
            .time(0, 0);

        let mut audio = MediaDescription::audio(audio_port).direction(self.direction);
        for (pt, name, rate) in &self.audio_codecs {
            audio = audio
                .add_format(*pt)
                .add_rtpmap(*pt, name.as_str(), *rate, None);
        }
        if self.include_telephone_event {
            audio = audio
                .add_format(101)
                .add_rtpmap(101, "telephone-event", 8000, None)
                .add_attribute("fmtp", "101 0-16");
        }
        if self.rtcp_mux {
            audio = audio.add_property("rtcp-mux");
        }
        builder = builder.media(audio);

        if self.enable_video {
            let vport = video_port.unwrap_or(audio_port + 2);
            let mut video = MediaDescription::video(vport).direction(self.direction);
            for (pt, name, rate) in &self.video_codecs {
                video = video
                    .add_format(*pt)
                    .add_rtpmap(*pt, name.as_str(), *rate, None);
            }
            if self.rtcp_mux {
                video = video.add_property("rtcp-mux");
            }
            builder = builder.media(video);
        }

        builder.build()
    }
}

/// Creates an SDP session from a profile
///
/// Provides quick SDP generation for common scenarios.
///
/// # Example
/// ```
/// use sip_sdp::profiles::{SdpProfile, create_from_profile};
///
/// // Audio-only call with PCMU, PCMA, and telephone-event
/// let sdp = create_from_profile(
///     SdpProfile::AudioOnly,
///     "alice",
///     "192.168.1.100",
///     8000,
///     None,
/// );
///
/// assert_eq!(sdp.media.len(), 1);
/// assert!(sdp.media[0].formats.iter().any(|f| f == "0"));  // PCMU
/// assert!(sdp.media[0].formats.iter().any(|f| f == "8"));  // PCMA
/// assert!(sdp.media[0].formats.iter().any(|f| f == "101")); // telephone-event
///
/// // Audio+video call
/// let av_sdp = create_from_profile(
///     SdpProfile::AudioVideo,
///     "bob",
///     "10.0.0.1",
///     9000,
///     Some(9002),
/// );
///
/// assert_eq!(av_sdp.media.len(), 2);
/// ```
pub fn create_from_profile(
    profile: SdpProfile,
    local_uri: &str,
    local_addr: &str,
    audio_port: u16,
    video_port: Option<u16>,
) -> SessionDescription {
    match profile {
        SdpProfile::AudioOnly => create_audio_only(local_uri, local_addr, audio_port),
        SdpProfile::AudioVideo => create_audio_video(
            local_uri,
            local_addr,
            audio_port,
            video_port.unwrap_or(audio_port + 2),
        ),
        SdpProfile::Custom => create_audio_only(local_uri, local_addr, audio_port),
    }
}

/// Creates audio-only SDP with PCMU and PCMA codecs
fn create_audio_only(username: &str, addr: &str, port: u16) -> SessionDescription {
    let session_id = generate_session_id();

    SessionDescription::builder()
        .origin(username, &session_id, addr)
        .session_name("VoIP Audio Call")
        .connection(addr)
        .time(0, 0)
        .media(
            MediaDescription::audio(port)
                .add_format(0) // PCMU
                .add_format(8) // PCMA
                .add_format(101) // telephone-event
                .add_rtpmap(0, "PCMU", 8000, None)
                .add_rtpmap(8, "PCMA", 8000, None)
                .add_rtpmap(101, "telephone-event", 8000, None)
                .add_attribute("fmtp", "101 0-16")
                .direction("sendrecv"),
        )
        .build()
}

/// Creates audio+video SDP with common codecs
fn create_audio_video(
    username: &str,
    addr: &str,
    audio_port: u16,
    video_port: u16,
) -> SessionDescription {
    let session_id = generate_session_id();

    SessionDescription::builder()
        .origin(username, &session_id, addr)
        .session_name("Audio/Video Conference")
        .connection(addr)
        .time(0, 0)
        .media(
            MediaDescription::audio(audio_port)
                .add_format(0) // PCMU
                .add_format(8) // PCMA
                .add_format(101) // telephone-event
                .add_rtpmap(0, "PCMU", 8000, None)
                .add_rtpmap(8, "PCMA", 8000, None)
                .add_rtpmap(101, "telephone-event", 8000, None)
                .add_attribute("fmtp", "101 0-16")
                .direction("sendrecv"),
        )
        .media(
            MediaDescription::video(video_port)
                .add_format(96) // H264
                .add_format(97) // VP8
                .add_rtpmap(96, "H264", 90000, None)
                .add_rtpmap(97, "VP8", 90000, None)
                .add_attribute("rtcp-fb", "96 nack")
                .add_attribute("rtcp-fb", "96 nack pli")
                .add_attribute("rtcp-fb", "97 nack")
                .add_attribute("rtcp-fb", "97 nack pli")
                .direction("sendrecv"),
        )
        .build()
}

/// Generates a session ID using current timestamp
fn generate_session_id() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

/// Builds an SDP answer by intersecting codecs in the offer with the desired profile.
pub fn negotiate_answer(
    offer: &SessionDescription,
    profile: &MediaProfileBuilder,
    username: &str,
    addr: &str,
    audio_port: u16,
    video_port: Option<u16>,
) -> SessionDescription {
    let mut builder = MediaProfileBuilder {
        audio_codecs: Vec::new(),
        video_codecs: Vec::new(),
        include_telephone_event: false,
        direction: "sendrecv",
        enable_video: false,
        rtcp_mux: profile.rtcp_mux,
    };

    let desired_audio: HashSet<u8> = profile.audio_codecs.iter().map(|c| c.0).collect();
    let desired_video: HashSet<u8> = profile.video_codecs.iter().map(|c| c.0).collect();

    for m in &offer.media {
        match &m.media_type {
            MediaType::Audio => {
                for fmt in &m.formats {
                    let pt = match parse_payload_type(fmt) {
                        Some(pt) => pt,
                        None => continue,
                    };
                    if desired_audio.contains(&pt) {
                        if let Some(rtp) = m.rtpmaps.get(&pt) {
                            builder = builder.add_audio_codec(
                                pt,
                                rtp.encoding_name.to_string(),
                                rtp.clock_rate,
                            );
                        }
                    }
                    if pt == 101 && profile.include_telephone_event {
                        builder = builder.telephone_event(true);
                    }
                }
            }
            MediaType::Video => {
                // Only enable video if the profile supports it
                if profile.enable_video || !profile.video_codecs.is_empty() {
                    builder.enable_video = true;
                    for fmt in &m.formats {
                        let pt = match parse_payload_type(fmt) {
                            Some(pt) => pt,
                            None => continue,
                        };
                        if desired_video.contains(&pt) {
                            if let Some(rtp) = m.rtpmaps.get(&pt) {
                                builder = builder.add_video_codec(
                                    pt,
                                    rtp.encoding_name.to_string(),
                                    rtp.clock_rate,
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    builder.build(username, addr, audio_port, video_port)
}

fn parse_payload_type(fmt: &SmolStr) -> Option<u8> {
    let value = fmt.as_str().parse::<u16>().ok()?;
    if value > 127 {
        None
    } else {
        Some(value as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_audio_only_profile() {
        let sdp = create_from_profile(SdpProfile::AudioOnly, "alice", "192.168.1.100", 8000, None);

        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert_eq!(sdp.media[0].port, 8000);
        assert!(sdp.media[0].formats.iter().any(|f| f == "0")); // PCMU
        assert!(sdp.media[0].formats.iter().any(|f| f == "8")); // PCMA
    }

    #[test]
    fn creates_audio_video_profile() {
        let sdp = create_from_profile(SdpProfile::AudioVideo, "bob", "10.0.0.1", 9000, Some(9002));

        assert_eq!(sdp.media.len(), 2);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert_eq!(sdp.media[1].media_type, MediaType::Video);
        assert_eq!(sdp.media[0].port, 9000);
        assert_eq!(sdp.media[1].port, 9002);
    }

    #[test]
    fn audio_profile_has_telephone_event() {
        let sdp = create_from_profile(SdpProfile::AudioOnly, "charlie", "172.16.0.1", 5004, None);

        assert!(sdp.media[0].formats.iter().any(|f| f == "101")); // telephone-event
        assert!(sdp.media[0].rtpmaps.contains_key(&101));
        assert_eq!(
            sdp.media[0].rtpmaps[&101].encoding_name.as_str(),
            "telephone-event"
        );
    }

    #[test]
    fn media_profile_builder_builds_audio_video() {
        let builder = MediaProfileBuilder::audio_video().rtcp_mux(true);
        let sdp = builder.build("alice", "192.0.2.1", 5004, Some(5006));
        assert_eq!(sdp.media.len(), 2);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert!(sdp.media[0]
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::Property(name) if name == "rtcp-mux")));
        assert_eq!(sdp.media[1].media_type, MediaType::Video);
        assert!(sdp.media[1]
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::Property(name) if name == "rtcp-mux")));
    }

    #[test]
    fn negotiate_answer_intersects_codecs() {
        let offer = MediaProfileBuilder::audio_video()
            .add_audio_codec(111, "opus", 48000)
            .build("alice", "198.51.100.1", 4000, Some(4002));
        let profile = MediaProfileBuilder::audio_only().add_audio_codec(111, "opus", 48000);
        let answer = negotiate_answer(&offer, &profile, "bob", "203.0.113.1", 7000, None);
        assert_eq!(answer.media.len(), 1);
        assert_eq!(answer.media[0].media_type, MediaType::Audio);
        assert!(answer.media[0].formats.iter().any(|f| f == "111"));
        assert!(answer.media[0].rtpmaps.contains_key(&111));
    }
}
