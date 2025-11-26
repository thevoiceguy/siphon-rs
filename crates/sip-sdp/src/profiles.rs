//! SDP configuration profiles for common scenarios
//!
//! Provides pre-configured SDP templates for typical use cases like audio-only calls,
//! video conferences, etc. These can be used as starting points and customized as needed.

use crate::*;

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

/// Creates an SDP session from a profile
pub fn create_from_profile(
    profile: SdpProfile,
    local_uri: &str,
    local_addr: &str,
    audio_port: u16,
    video_port: Option<u16>,
) -> SessionDescription {
    match profile {
        SdpProfile::AudioOnly => create_audio_only(local_uri, local_addr, audio_port),
        SdpProfile::AudioVideo => {
            create_audio_video(local_uri, local_addr, audio_port, video_port.unwrap_or(audio_port + 2))
        }
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
                .add_format(0)  // PCMU
                .add_format(8)  // PCMA
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
fn create_audio_video(username: &str, addr: &str, audio_port: u16, video_port: u16) -> SessionDescription {
    let session_id = generate_session_id();

    SessionDescription::builder()
        .origin(username, &session_id, addr)
        .session_name("Audio/Video Conference")
        .connection(addr)
        .time(0, 0)
        .media(
            MediaDescription::audio(audio_port)
                .add_format(0)   // PCMU
                .add_format(8)   // PCMA
                .add_format(101) // telephone-event
                .add_rtpmap(0, "PCMU", 8000, None)
                .add_rtpmap(8, "PCMA", 8000, None)
                .add_rtpmap(101, "telephone-event", 8000, None)
                .add_attribute("fmtp", "101 0-16")
                .direction("sendrecv"),
        )
        .media(
            MediaDescription::video(video_port)
                .add_format(96)  // H264
                .add_format(97)  // VP8
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_audio_only_profile() {
        let sdp = create_from_profile(
            SdpProfile::AudioOnly,
            "alice",
            "192.168.1.100",
            8000,
            None,
        );

        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert_eq!(sdp.media[0].port, 8000);
        assert!(sdp.media[0].formats.contains(&0)); // PCMU
        assert!(sdp.media[0].formats.contains(&8)); // PCMA
    }

    #[test]
    fn creates_audio_video_profile() {
        let sdp = create_from_profile(
            SdpProfile::AudioVideo,
            "bob",
            "10.0.0.1",
            9000,
            Some(9002),
        );

        assert_eq!(sdp.media.len(), 2);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert_eq!(sdp.media[1].media_type, MediaType::Video);
        assert_eq!(sdp.media[0].port, 9000);
        assert_eq!(sdp.media[1].port, 9002);
    }

    #[test]
    fn audio_profile_has_telephone_event() {
        let sdp = create_from_profile(
            SdpProfile::AudioOnly,
            "charlie",
            "172.16.0.1",
            5004,
            None,
        );

        assert!(sdp.media[0].formats.contains(&101)); // telephone-event
        assert!(sdp.media[0].rtpmaps.contains_key(&101));
        assert_eq!(sdp.media[0].rtpmaps[&101].encoding_name.as_str(), "telephone-event");
    }
}
