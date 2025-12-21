//! SDP utility functions shared across handlers.
//!
//! This module provides common SDP negotiation and generation functions
//! used by INVITE and REFER handlers.

use anyhow::{anyhow, Result};
use sip_core::SipUri;
use sip_sdp::{
    negotiate as sdp_negotiate, parse as sdp_parse,
    profiles::{create_from_profile, MediaProfileBuilder, SdpProfile as SdpProfileProfile},
    serialize as sdp_serialize,
};
use std::fs;
use std::path::Path;

use crate::config::DaemonConfig;

/// Parse a name-addr format URI (e.g., "Alice <sip:alice@example.com>")
pub fn parse_name_addr_uri(value: &str) -> Option<SipUri> {
    if let Some(start) = value.find('<') {
        let end = value.find('>').unwrap_or(value.len());
        SipUri::parse(&value[start + 1..end])
    } else {
        let uri = value.split(';').next()?.trim();
        SipUri::parse(uri)
    }
}

/// Extract username and host from local_uri configuration
pub fn local_identity(config: &DaemonConfig) -> (String, String) {
    if let Some(uri) = SipUri::parse(&config.local_uri) {
        let username = uri.user.as_deref().unwrap_or("siphond").to_string();
        (username, uri.host.to_string())
    } else {
        ("siphond".to_string(), "127.0.0.1".to_string())
    }
}

/// Load custom SDP from file path
pub fn load_custom_sdp(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path)?;
    if contents.trim().is_empty() {
        return Err(anyhow!("Custom SDP file is empty: {:?}", path));
    }
    Ok(contents)
}

/// Generate SDP offer based on configured profile
pub fn generate_sdp_offer(config: &DaemonConfig) -> Result<String> {
    let (username, local_ip) = local_identity(config);
    let audio_port = config.rtp_audio_port;
    let video_port = config.rtp_video_port;

    match &config.sdp_profile {
        crate::config::SdpProfile::None => {
            Err(anyhow!("SDP not supported in current configuration"))
        }
        crate::config::SdpProfile::AudioOnly => {
            let sdp = create_from_profile(
                SdpProfileProfile::AudioOnly,
                &username,
                &local_ip,
                audio_port,
                None,
            );
            Ok(sdp_serialize::serialize_sdp(&sdp))
        }
        crate::config::SdpProfile::AudioVideo => {
            let sdp = create_from_profile(
                SdpProfileProfile::AudioVideo,
                &username,
                &local_ip,
                audio_port,
                Some(video_port),
            );
            Ok(sdp_serialize::serialize_sdp(&sdp))
        }
        crate::config::SdpProfile::Custom(path) => load_custom_sdp(path),
    }
}

/// Generate SDP answer based on configured profile
pub fn generate_sdp_answer(config: &DaemonConfig, offer: &str) -> Result<String> {
    let offer_sdp =
        sdp_parse::parse_sdp(offer).map_err(|e| anyhow!("Failed to parse SDP offer: {:?}", e))?;

    let (username, local_ip) = local_identity(config);
    let audio_port = config.rtp_audio_port;
    let video_port = config.rtp_video_port;

    let answer = match &config.sdp_profile {
        crate::config::SdpProfile::None => {
            return Err(anyhow!("SDP not supported in current configuration"));
        }
        crate::config::SdpProfile::AudioOnly => {
            let profile = MediaProfileBuilder::audio_only();
            sip_sdp::profiles::negotiate_answer(
                &offer_sdp,
                &profile,
                &username,
                &local_ip,
                audio_port,
                None,
            )
        }
        crate::config::SdpProfile::AudioVideo => {
            let profile = MediaProfileBuilder::audio_video();
            sip_sdp::profiles::negotiate_answer(
                &offer_sdp,
                &profile,
                &username,
                &local_ip,
                audio_port,
                Some(video_port),
            )
        }
        crate::config::SdpProfile::Custom(path) => {
            let custom = load_custom_sdp(path)?;
            let local_caps = sdp_parse::parse_sdp(&custom)
                .map_err(|e| anyhow!("Failed to parse custom SDP: {:?}", e))?;
            sdp_negotiate::negotiate_answer(&offer_sdp, &local_ip, &local_caps)
                .map_err(|e| anyhow!("SDP negotiation failed: {}", e))?
        }
    };

    Ok(sdp_serialize::serialize_sdp(&answer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_addr_with_brackets() {
        let uri = parse_name_addr_uri("Alice <sip:alice@example.com>").unwrap();
        assert_eq!(uri.user.as_deref(), Some("alice"));
        assert_eq!(uri.host.as_str(), "example.com");
    }

    #[test]
    fn parses_name_addr_without_brackets() {
        let uri = parse_name_addr_uri("sip:bob@example.com;tag=123").unwrap();
        assert_eq!(uri.user.as_deref(), Some("bob"));
        assert_eq!(uri.host.as_str(), "example.com");
    }

    #[test]
    fn extracts_local_identity() {
        let mut config = DaemonConfig::default();
        config.local_uri = "sip:test@192.168.1.100".to_string();
        let (username, host) = local_identity(&config);
        assert_eq!(username, "test");
        assert_eq!(host, "192.168.1.100");
    }
}
