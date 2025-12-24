// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SDP serializer implementing RFC 4566
//!
//! Converts SessionDescription structures to text-based SDP format.

use crate::*;

/// Serializes a SessionDescription to RFC 4566 format
pub fn serialize_sdp(sdp: &SessionDescription) -> String {
    let mut output = String::new();

    // Version (required): v=0
    output.push_str(&format!("v={}\r\n", sdp.version));

    // Origin (required): o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    output.push_str(&format!(
        "o={} {} {} {} {} {}\r\n",
        sdp.origin.username,
        sdp.origin.session_id,
        sdp.origin.session_version,
        sdp.origin.net_type,
        sdp.origin.addr_type,
        sdp.origin.unicast_address
    ));

    // Session name (required): s=<session name>
    output.push_str(&format!("s={}\r\n", sdp.session_name));

    // Session information (optional): i=<session description>
    if let Some(ref info) = sdp.session_info {
        output.push_str(&format!("i={}\r\n", info));
    }

    // URI (optional): u=<uri>
    if let Some(ref uri) = sdp.uri {
        output.push_str(&format!("u={}\r\n", uri));
    }

    // Email (optional): e=<email address>
    if let Some(ref email) = sdp.email {
        output.push_str(&format!("e={}\r\n", email));
    }

    // Phone (optional): p=<phone number>
    if let Some(ref phone) = sdp.phone {
        output.push_str(&format!("p={}\r\n", phone));
    }

    // Connection (optional at session level): c=<nettype> <addrtype> <connection-address>
    if let Some(ref conn) = sdp.connection {
        output.push_str(&format!(
            "c={} {} {}\r\n",
            conn.net_type, conn.addr_type, conn.connection_address
        ));
    }

    // Bandwidth (zero or more): b=<bwtype>:<bandwidth>
    for bw in &sdp.bandwidth {
        output.push_str(&format!("b={}:{}\r\n", bw.bw_type, bw.bandwidth));
    }

    // Time (required): t=<start-time> <stop-time>
    if sdp.times.is_empty() {
        output.push_str("t=0 0\r\n");
    }
    for time in &sdp.times {
        output.push_str(&format!("t={} {}\r\n", time.start_time, time.stop_time));
        for repeat in &time.repeats {
            output.push_str(&format!(
                "r={} {}",
                repeat.repeat_interval, repeat.active_duration
            ));
            for offset in &repeat.offsets {
                output.push_str(&format!(" {}", offset));
            }
            output.push_str("\r\n");
        }
    }

    // Time zone adjustments (optional): z=<adjustment-time> <offset> ...
    if !sdp.time_zones.is_empty() {
        output.push_str("z=");
        for (idx, zone) in sdp.time_zones.iter().enumerate() {
            if idx > 0 {
                output.push(' ');
            }
            output.push_str(&format!("{} {}", zone.adjustment_time, zone.offset));
        }
        output.push_str("\r\n");
    }

    // Session encryption key (optional): k=<method>:<encryption key>
    if let Some(ref key) = sdp.encryption_key {
        output.push_str(&format!("k={}\r\n", key));
    }

    // Session-level attributes: a=<attribute> or a=<attribute>:<value>
    for attr in &sdp.attributes {
        serialize_attribute(&mut output, attr);
    }

    // Media descriptions: m=<media> <port> <proto> <fmt> ...
    for media in &sdp.media {
        serialize_media(&mut output, media);
    }

    output
}

/// Serializes a media description
fn serialize_media(output: &mut String, media: &MediaDescription) {
    // Media line: m=<media> <port>/<num_ports> <proto> <fmt> ...
    output.push_str(&format!("m={} ", media.media_type));

    if let Some(num_ports) = media.num_ports {
        output.push_str(&format!("{}/{} ", media.port, num_ports));
    } else {
        output.push_str(&format!("{} ", media.port));
    }

    output.push_str(&format!("{}", media.protocol));

    // Format list (RTP payload types or tokens)
    if media.formats.is_empty() {
        output.push_str(" 0");
    } else {
        for fmt in &media.formats {
            output.push_str(&format!(" {}", fmt));
        }
    }
    output.push_str("\r\n");

    // Media title (optional): i=<media title>
    if let Some(ref title) = media.title {
        output.push_str(&format!("i={}\r\n", title));
    }

    // Connection (optional): c=<nettype> <addrtype> <connection-address>
    if let Some(ref conn) = media.connection {
        output.push_str(&format!(
            "c={} {} {}\r\n",
            conn.net_type, conn.addr_type, conn.connection_address
        ));
    }

    // Bandwidth (zero or more): b=<bwtype>:<bandwidth>
    for bw in &media.bandwidth {
        output.push_str(&format!("b={}:{}\r\n", bw.bw_type, bw.bandwidth));
    }

    // Encryption key (optional): k=<method>:<encryption key>
    if let Some(ref key) = media.encryption_key {
        output.push_str(&format!("k={}\r\n", key));
    }

    // Media-level attributes
    for attr in &media.attributes {
        serialize_attribute(output, attr);
    }
}

/// Serializes an attribute
fn serialize_attribute(output: &mut String, attr: &Attribute) {
    match attr {
        Attribute::Property(name) => {
            output.push_str(&format!("a={}\r\n", name));
        }
        Attribute::Value { name, value } => {
            output.push_str(&format!("a={}:{}\r\n", name, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_simple_audio_sdp() {
        let sdp = SessionDescription::builder()
            .origin("alice", "123456", "192.168.1.100")
            .session_name("Test Call")
            .connection("192.168.1.100")
            .media(
                MediaDescription::audio(8000)
                    .add_format(0)
                    .add_format(8)
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .add_rtpmap(8, "PCMA", 8000, None),
            )
            .build();

        let result = serialize_sdp(&sdp);

        assert!(result.contains("v=0\r\n"));
        assert!(result.contains("o=alice 123456 0 IN IP4 192.168.1.100\r\n"));
        assert!(result.contains("s=Test Call\r\n"));
        assert!(result.contains("c=IN IP4 192.168.1.100\r\n"));
        assert!(result.contains("t=0 0\r\n"));
        assert!(result.contains("m=audio 8000 RTP/AVP 0 8\r\n"));
        assert!(result.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(result.contains("a=rtpmap:8 PCMA/8000\r\n"));
    }

    #[test]
    fn serializes_audio_video_sdp() {
        let sdp = SessionDescription::builder()
            .origin("bob", "654321", "10.0.0.1")
            .session_name("Video Conference")
            .connection("10.0.0.1")
            .media(
                MediaDescription::audio(9000)
                    .add_format(0)
                    .add_rtpmap(0, "PCMU", 8000, None)
                    .direction("sendrecv"),
            )
            .media(
                MediaDescription::video(9002)
                    .add_format(96)
                    .add_rtpmap(96, "H264", 90000, None)
                    .direction("sendrecv"),
            )
            .build();

        let result = serialize_sdp(&sdp);

        assert!(result.contains("m=audio 9000 RTP/AVP 0\r\n"));
        assert!(result.contains("m=video 9002 RTP/AVP 96\r\n"));
        assert!(result.contains("a=rtpmap:96 H264/90000\r\n"));
    }

    #[test]
    fn serializes_optional_fields() {
        let sdp = SessionDescription::builder()
            .origin("charlie", "111", "172.16.0.1")
            .session_name("Full Session")
            .session_info("Test session")
            .connection("172.16.0.1")
            .attribute("sendrecv", None)
            .media(MediaDescription::audio(5004).add_format(0))
            .build();

        let result = serialize_sdp(&sdp);

        assert!(result.contains("i=Test session\r\n"));
        assert!(result.contains("a=sendrecv\r\n"));
    }

    #[test]
    fn round_trip_parse_serialize() {
        let original_sdp = "v=0\r\n\
                            o=alice 123456 0 IN IP4 192.168.1.100\r\n\
                            s=Test Session\r\n\
                            c=IN IP4 192.168.1.100\r\n\
                            t=0 0\r\n\
                            m=audio 8000 RTP/AVP 0 8\r\n\
                            a=rtpmap:0 PCMU/8000\r\n\
                            a=rtpmap:8 PCMA/8000\r\n";

        // Parse
        let parsed = crate::parse::parse_sdp(original_sdp).unwrap();

        // Serialize
        let serialized = serialize_sdp(&parsed);

        // Parse again
        let reparsed = crate::parse::parse_sdp(&serialized).unwrap();

        // Should be identical
        assert_eq!(parsed, reparsed);
    }
}
