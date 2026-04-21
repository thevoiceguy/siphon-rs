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
            .unwrap()
            .session_name("Test Call")
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
                    .unwrap(),
            )
            .unwrap()
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
            .unwrap()
            .session_name("Video Conference")
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
            .media(
                MediaDescription::video(9002)
                    .add_format(96)
                    .unwrap()
                    .add_rtpmap(96, "H264", 90000, None)
                    .unwrap()
                    .with_direction("sendrecv")
                    .unwrap(),
            )
            .unwrap()
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
            .unwrap()
            .session_name("Full Session")
            .unwrap()
            .session_info("Test session")
            .unwrap()
            .connection("172.16.0.1")
            .unwrap()
            .attribute("sendrecv", None)
            .unwrap()
            .media(MediaDescription::audio(5004).add_format(0).unwrap())
            .unwrap()
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

    // ---------------------------------------------------------------
    // Round-trip preservation guarantee
    //
    // Real-world SDP carries a long tail of attributes the parser does
    // not understand (vendor extensions, ICE/DTLS, BUNDLE, RTCP-FB).
    // These tests assert two properties on representative samples
    // gathered from common interop targets:
    //
    //   1. parse → serialize → parse round-trips to an equal value.
    //   2. Every `a=...` line in the original input survives byte-for-byte
    //      in the serialized output.
    //
    // The second property guards against any future parser refactor
    // that silently drops unknown attributes — a regression that would
    // be invisible to (1) because both sides would lose the same data.
    // ---------------------------------------------------------------

    /// Walks every `a=` line in `original` and asserts the serialized
    /// form contains the same `name[:value]` token. Skips empty lines.
    fn assert_attributes_preserved(original: &str, serialized: &str) {
        for line in original.lines() {
            let trimmed = line.trim_end_matches('\r');
            if !trimmed.starts_with("a=") {
                continue;
            }
            assert!(
                serialized.contains(trimmed),
                "attribute dropped by round-trip:\n  original line: {trimmed}\n  serialized:\n{serialized}",
            );
        }
    }

    fn assert_round_trip_preserves(sample: &str) {
        let parsed = crate::parse::parse_sdp(sample).expect("sample must parse");
        let serialized = serialize_sdp(&parsed);
        assert_attributes_preserved(sample, &serialized);
        let reparsed = crate::parse::parse_sdp(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed, "semantic equality across round-trip");
    }

    #[test]
    fn preserves_asterisk_style_offer() {
        let sample = "v=0\r\n\
                      o=- 1234567890 1 IN IP4 192.0.2.10\r\n\
                      s=Asterisk\r\n\
                      c=IN IP4 192.0.2.10\r\n\
                      t=0 0\r\n\
                      m=audio 5004 RTP/AVP 0 8 9 96 97\r\n\
                      a=sendrecv\r\n\
                      a=rtpmap:0 PCMU/8000\r\n\
                      a=rtpmap:8 PCMA/8000\r\n\
                      a=rtpmap:9 G722/8000\r\n\
                      a=rtpmap:96 iLBC/8000\r\n\
                      a=fmtp:96 mode=20\r\n\
                      a=rtpmap:97 telephone-event/8000\r\n\
                      a=fmtp:97 0-16\r\n\
                      a=ptime:20\r\n\
                      a=maxptime:140\r\n";
        assert_round_trip_preserves(sample);
    }

    #[test]
    fn preserves_freeswitch_style_offer_with_unknown_attrs() {
        let sample = "v=0\r\n\
                      o=FreeSWITCH 1729188372 1729188373 IN IP4 198.51.100.5\r\n\
                      s=FreeSWITCH\r\n\
                      c=IN IP4 198.51.100.5\r\n\
                      t=0 0\r\n\
                      m=audio 16384 RTP/AVP 0 101\r\n\
                      a=rtpmap:0 PCMU/8000\r\n\
                      a=rtpmap:101 telephone-event/8000\r\n\
                      a=fmtp:101 0-16\r\n\
                      a=rtcp:16385 IN IP4 198.51.100.5\r\n\
                      a=ptime:20\r\n\
                      a=sendrecv\r\n\
                      a=X-vendor-info:fs-engine=core1;build=1.10.10\r\n";
        assert_round_trip_preserves(sample);
    }

    #[test]
    fn preserves_webrtc_style_offer_with_dtls_ice_bundle() {
        let sample = "v=0\r\n\
                      o=- 4611728142112323737 2 IN IP4 127.0.0.1\r\n\
                      s=-\r\n\
                      t=0 0\r\n\
                      a=group:BUNDLE 0\r\n\
                      a=msid-semantic: WMS stream0\r\n\
                      m=audio 9 UDP/TLS/RTP/SAVPF 111 103 9 0 8 13 110\r\n\
                      c=IN IP4 0.0.0.0\r\n\
                      a=rtcp:9 IN IP4 0.0.0.0\r\n\
                      a=ice-ufrag:abcd\r\n\
                      a=ice-pwd:efghijklmnopqrstuvwxyz0123\r\n\
                      a=ice-options:trickle\r\n\
                      a=fingerprint:sha-256 12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0\r\n\
                      a=setup:actpass\r\n\
                      a=mid:0\r\n\
                      a=sendrecv\r\n\
                      a=rtpmap:111 opus/48000/2\r\n\
                      a=fmtp:111 minptime=10;useinbandfec=1\r\n\
                      a=rtpmap:103 ISAC/16000\r\n\
                      a=rtpmap:9 G722/8000\r\n\
                      a=rtpmap:0 PCMU/8000\r\n\
                      a=rtpmap:8 PCMA/8000\r\n\
                      a=rtpmap:13 CN/8000\r\n\
                      a=rtpmap:110 telephone-event/48000\r\n\
                      a=ssrc:3735928559 cname:user@example.com\r\n\
                      a=ssrc:3735928559 msid:stream0 track0\r\n\
                      a=candidate:1 1 UDP 2130706431 192.168.1.5 52000 typ host generation 0\r\n\
                      a=candidate:2 1 UDP 1694498815 198.51.100.10 52001 typ srflx raddr 192.168.1.5 rport 52000 generation 0\r\n";
        assert_round_trip_preserves(sample);
    }

    #[test]
    fn preserves_audio_video_offer_with_per_media_attrs() {
        let sample = "v=0\r\n\
                      o=alice 1 1 IN IP4 203.0.113.4\r\n\
                      s=A/V Conf\r\n\
                      c=IN IP4 203.0.113.4\r\n\
                      t=0 0\r\n\
                      a=tool:siphon-rs\r\n\
                      m=audio 49170 RTP/AVP 96\r\n\
                      a=rtpmap:96 opus/48000/2\r\n\
                      a=fmtp:96 maxaveragebitrate=64000\r\n\
                      a=sendrecv\r\n\
                      a=ptime:20\r\n\
                      m=video 49180 RTP/AVP 100\r\n\
                      a=rtpmap:100 H264/90000\r\n\
                      a=fmtp:100 profile-level-id=42e01f;packetization-mode=1\r\n\
                      a=sendonly\r\n\
                      a=mid:video0\r\n";
        assert_round_trip_preserves(sample);
    }

    #[test]
    fn preserves_typed_accessor_modifications_across_round_trip() {
        // End-to-end app workflow: parse, mutate via typed accessors,
        // serialize, re-parse. Assert mutations land AND no other
        // attribute is lost (especially the `x-keep-me` extension).
        use crate::attrs::{Direction, Setup};

        let sample = "v=0\r\n\
                      o=- 0 0 IN IP4 198.51.100.1\r\n\
                      s=-\r\n\
                      c=IN IP4 198.51.100.1\r\n\
                      t=0 0\r\n\
                      m=audio 9000 UDP/TLS/RTP/SAVPF 111\r\n\
                      a=sendrecv\r\n\
                      a=rtpmap:111 opus/48000/2\r\n\
                      a=fmtp:111 minptime=10\r\n\
                      a=ptime:20\r\n\
                      a=setup:actpass\r\n\
                      a=fingerprint:sha-256 12:34\r\n\
                      a=mid:audio0\r\n\
                      a=x-keep-me:custom-flag\r\n";

        let mut parsed = crate::parse::parse_sdp(sample).unwrap();
        parsed.media[0].set_direction(Direction::SendOnly);
        parsed.media[0].set_ptime(40);
        parsed.media[0].set_fmtp(111, "minptime=20;useinbandfec=1");
        parsed.media[0].set_setup(Setup::Active);

        let serialized = serialize_sdp(&parsed);

        assert!(serialized.contains("a=sendonly"));
        assert!(serialized.contains("a=ptime:40"));
        assert!(serialized.contains("a=fmtp:111 minptime=20;useinbandfec=1"));
        assert!(serialized.contains("a=setup:active"));
        assert!(!serialized.contains("a=sendrecv"));
        assert!(!serialized.contains("a=ptime:20"));
        assert!(!serialized.contains("a=fmtp:111 minptime=10"));
        assert!(!serialized.contains("a=setup:actpass"));
        assert!(serialized.contains("a=fingerprint:sha-256 12:34"));
        assert!(serialized.contains("a=mid:audio0"));
        assert!(
            serialized.contains("a=x-keep-me:custom-flag"),
            "unknown attribute lost across modify/serialize: {serialized}",
        );
        assert!(serialized.contains("a=rtpmap:111 opus/48000/2"));

        let reparsed = crate::parse::parse_sdp(&serialized).unwrap();
        assert_eq!(parsed, reparsed);
    }
}
