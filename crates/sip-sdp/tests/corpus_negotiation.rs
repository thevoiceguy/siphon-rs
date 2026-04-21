// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Real-corpus offer/answer negotiation tests.
//!
//! Each fixture is a verbatim SDP body representative of a common
//! interop target (Asterisk PJSIP, FreeSWITCH, Linphone, Chrome
//! WebRTC, Microsoft Teams). The body is what those stacks have been
//! observed to send in INVITEs against siphond — keeping them inline
//! makes regressions obvious in code review without forcing reviewers
//! to chase fixture files.
//!
//! For each fixture we run `negotiate_answer` against a representative
//! local capability set and assert RFC 3264 invariants:
//!
//!   * The answer has the same number of m-lines as the offer, in
//!     the same order.
//!   * Each m-line in the answer either negotiates (port != 0) or
//!     rejects (port == 0) — never crashes.
//!   * The negotiated PTs are a subset of the PTs the offer listed
//!     for that section.
//!   * The answer round-trips cleanly through serialize → parse.
//!   * Nothing in the offer triggers a parse panic or a
//!     `NegotiationError::InvalidSdp`.
//!
//! These tests are intentionally tolerant: real-world SDP carries a
//! long tail of attributes that aren't strictly negotiation-relevant
//! (RTCP-FB, msid-semantic, ice-options, x-vendor extensions). We
//! check that they don't break parsing or negotiation, not that we
//! understand or echo them.

use sip_sdp::{
    negotiate::negotiate_answer, MediaDescription, MediaType, Protocol, SessionDescription,
};

// ---------------------------------------------------------------------------
// Local capability profiles
// ---------------------------------------------------------------------------

fn audio_only_caps_pcmu_pcma() -> SessionDescription {
    SessionDescription::builder()
        .origin("siphond", "1", "10.0.0.1")
        .unwrap()
        .session_name("siphond audio caps")
        .unwrap()
        .connection("10.0.0.1")
        .unwrap()
        .media(
            MediaDescription::audio(40000)
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
        .build()
}

fn audio_caps_with_opus() -> SessionDescription {
    SessionDescription::builder()
        .origin("siphond", "1", "10.0.0.1")
        .unwrap()
        .session_name("siphond opus-capable")
        .unwrap()
        .connection("10.0.0.1")
        .unwrap()
        .media(
            MediaDescription::audio(40000)
                .add_format(0)
                .unwrap()
                .add_format(111)
                .unwrap()
                .add_rtpmap(0, "PCMU", 8000, None)
                .unwrap()
                .add_rtpmap(111, "opus", 48000, Some("2"))
                .unwrap()
                .with_direction("sendrecv")
                .unwrap(),
        )
        .unwrap()
        .build()
}

// ---------------------------------------------------------------------------
// Shared invariant checks
// ---------------------------------------------------------------------------

fn assert_answer_invariants(offer: &SessionDescription, answer: &SessionDescription) {
    assert_eq!(
        offer.media.len(),
        answer.media.len(),
        "answer m-line count must equal offer's",
    );

    for (idx, (offer_m, answer_m)) in offer.media.iter().zip(&answer.media).enumerate() {
        // m-line type and protocol are positionally preserved.
        assert_eq!(
            offer_m.media_type, answer_m.media_type,
            "media type mismatch at m-line {idx}",
        );
        assert_eq!(
            offer_m.protocol, answer_m.protocol,
            "protocol mismatch at m-line {idx}",
        );

        if answer_m.port != 0 {
            // For accepted streams, every PT in the answer must
            // appear in the offer's format list. We only enforce
            // this for RTP-based protocols where PTs are numeric.
            if matches!(
                answer_m.protocol,
                Protocol::RtpAvp
                    | Protocol::RtpSavp
                    | Protocol::RtpSavpf
                    | Protocol::UdpTlsRtpSavpf
                    | Protocol::TcpTlsRtpSavpf
            ) {
                for fmt in &answer_m.formats {
                    assert!(
                        offer_m.formats.iter().any(|of| of == fmt),
                        "answer m-line {idx} carries unrequested PT {fmt}",
                    );
                }
            }
        }
    }

    // Final round-trip via serialize.
    let serialized = answer.serialize();
    let reparsed =
        SessionDescription::parse(&serialized).expect("answer must serialize and re-parse cleanly");
    assert_eq!(*answer, reparsed, "answer round-trip mismatch");
}

// ---------------------------------------------------------------------------
// Asterisk PJSIP — typical audio offer with G.711 + telephone-event.
// ---------------------------------------------------------------------------

const ASTERISK_PJSIP_OFFER: &str = "v=0\r\n\
o=- 1734567890 1 IN IP4 192.0.2.5\r\n\
s=Asterisk\r\n\
c=IN IP4 192.0.2.5\r\n\
t=0 0\r\n\
m=audio 14000 RTP/AVP 0 8 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=ptime:20\r\n\
a=maxptime:140\r\n\
a=sendrecv\r\n";

#[test]
fn corpus_asterisk_pjsip_audio_offer() {
    let offer = SessionDescription::parse(ASTERISK_PJSIP_OFFER).expect("parse");
    let answer =
        negotiate_answer(&offer, "10.0.0.1", &audio_only_caps_pcmu_pcma()).expect("negotiate");
    assert_answer_invariants(&offer, &answer);
    // PCMU and PCMA are both supported locally; Asterisk's PT 101
    // (telephone-event) isn't in our caps so it's filtered.
    let pts: Vec<&str> = answer.media[0].formats.iter().map(|f| f.as_str()).collect();
    assert!(pts.contains(&"0"));
    assert!(pts.contains(&"8"));
}

// ---------------------------------------------------------------------------
// FreeSWITCH — adds rtcp + a vendor extension.
// ---------------------------------------------------------------------------

const FREESWITCH_OFFER: &str = "v=0\r\n\
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
a=X-vendor-info:fs-engine=core1\r\n";

#[test]
fn corpus_freeswitch_audio_offer() {
    let offer = SessionDescription::parse(FREESWITCH_OFFER).expect("parse");
    let answer =
        negotiate_answer(&offer, "10.0.0.1", &audio_only_caps_pcmu_pcma()).expect("negotiate");
    assert_answer_invariants(&offer, &answer);
    // The vendor extension on the offer side does NOT need to appear
    // in the answer — the negotiator builds the answer from local
    // capabilities. We just verify negotiation didn't crash.
    assert!(
        answer.media[0].formats.iter().any(|f| f == "0"),
        "PCMU should be negotiated",
    );
}

// ---------------------------------------------------------------------------
// Linphone — opus-first audio offer with multiple fallbacks.
// ---------------------------------------------------------------------------

const LINPHONE_OPUS_OFFER: &str = "v=0\r\n\
o=linphone 12345 67890 IN IP4 203.0.113.20\r\n\
s=Talk\r\n\
c=IN IP4 203.0.113.20\r\n\
t=0 0\r\n\
m=audio 7078 RTP/AVP 96 0 8 101\r\n\
a=rtpmap:96 opus/48000/2\r\n\
a=fmtp:96 useinbandfec=1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n";

#[test]
fn corpus_linphone_opus_audio_offer() {
    let offer = SessionDescription::parse(LINPHONE_OPUS_OFFER).expect("parse");
    // Local supports opus + PCMU. Linphone's opus PT is 96; ours is
    // 111 — negotiation should map by codec/clock/channels and use
    // the offerer's PT in the answer.
    let answer = negotiate_answer(&offer, "10.0.0.1", &audio_caps_with_opus()).expect("negotiate");
    assert_answer_invariants(&offer, &answer);
    // Opus negotiated: answer carries PT 96 (offerer's), encoding
    // params copied from local (still "2" channels), and the
    // offerer's fmtp (useinbandfec=1) is echoed back.
    let opus = answer.media[0]
        .rtpmaps
        .get(&96)
        .expect("opus negotiated under offerer's PT");
    assert_eq!(opus.encoding_name.as_str(), "opus");
    assert_eq!(opus.clock_rate, 48000);
    let opus_fmtp = answer.media[0]
        .fmtp_for(96)
        .expect("opus fmtp echoed in answer");
    assert_eq!(opus_fmtp.params.as_str(), "useinbandfec=1");
}

// ---------------------------------------------------------------------------
// Chrome WebRTC — DTLS, ICE, BUNDLE, SSRC. Negotiation here is
// best-effort: we don't bridge ICE/DTLS, but the SDP layer must not
// reject the offer or crash when constructing the answer.
// ---------------------------------------------------------------------------

const CHROME_WEBRTC_OFFER: &str = "v=0\r\n\
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
a=ssrc:3735928559 msid:stream0 track0\r\n";

fn webrtc_caps() -> SessionDescription {
    // Local-side caps that match Chrome's protocol so negotiation
    // doesn't reject on protocol mismatch.
    let mut media = MediaDescription::audio(40000)
        .add_format(111)
        .unwrap()
        .add_format(0)
        .unwrap()
        .add_rtpmap(111, "opus", 48000, Some("2"))
        .unwrap()
        .add_rtpmap(0, "PCMU", 8000, None)
        .unwrap()
        .with_direction("sendrecv")
        .unwrap();
    media.protocol = Protocol::UdpTlsRtpSavpf;

    SessionDescription::builder()
        .origin("siphond", "1", "10.0.0.1")
        .unwrap()
        .session_name("siphond webrtc caps")
        .unwrap()
        .connection("10.0.0.1")
        .unwrap()
        .media(media)
        .unwrap()
        .build()
}

#[test]
fn corpus_chrome_webrtc_audio_offer() {
    let offer = SessionDescription::parse(CHROME_WEBRTC_OFFER).expect("parse");
    let answer = negotiate_answer(&offer, "10.0.0.1", &webrtc_caps()).expect("negotiate");
    assert_answer_invariants(&offer, &answer);

    // DTLS setup negotiation: offer is `actpass`, answer should pick
    // `active` per RFC 5763 §5 convention.
    use sip_sdp::attrs::Setup;
    assert_eq!(answer.media[0].setup(), Some(Setup::Active));

    // Common codecs: opus and PCMU.
    let pts: Vec<&str> = answer.media[0].formats.iter().map(|f| f.as_str()).collect();
    assert!(pts.contains(&"111"), "opus must be negotiated");
    assert!(pts.contains(&"0"), "PCMU must be negotiated");
}

// ---------------------------------------------------------------------------
// Microsoft Teams Direct Routing — silk + opus + multi-channel rtpmap
// quirks. Teams tends to put a lot of attributes on the audio
// section and uses non-standard cap names; we just verify the
// negotiation doesn't get tripped up.
// ---------------------------------------------------------------------------

const MS_TEAMS_AUDIO_OFFER: &str = "v=0\r\n\
o=- 1234567890 0 IN IP4 52.114.20.5\r\n\
s=session\r\n\
c=IN IP4 52.114.20.5\r\n\
b=AS:117\r\n\
t=0 0\r\n\
m=audio 50000 RTP/SAVP 117 0 13\r\n\
a=rtpmap:117 X-MS-RTA/16000\r\n\
a=fmtp:117 bitrate=29000\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:13 CN/8000\r\n\
a=ptime:20\r\n\
a=maxptime:200\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WG2zUeY3lUTSU4wxL3RZqe1Mh2OHN/4SyD9oC2lj\r\n\
a=sendrecv\r\n\
a=label:audio\r\n";

fn teams_caps() -> SessionDescription {
    let mut media = MediaDescription::audio(40000)
        .add_format(0)
        .unwrap()
        .add_rtpmap(0, "PCMU", 8000, None)
        .unwrap()
        .with_direction("sendrecv")
        .unwrap();
    media.protocol = Protocol::RtpSavp;
    SessionDescription::builder()
        .origin("siphond", "1", "10.0.0.1")
        .unwrap()
        .session_name("siphond teams caps")
        .unwrap()
        .connection("10.0.0.1")
        .unwrap()
        .media(media)
        .unwrap()
        .build()
}

#[test]
fn corpus_microsoft_teams_audio_offer() {
    let offer = SessionDescription::parse(MS_TEAMS_AUDIO_OFFER).expect("parse");
    let answer = negotiate_answer(&offer, "10.0.0.1", &teams_caps()).expect("negotiate");
    assert_answer_invariants(&offer, &answer);
    // We share PCMU only; Teams's X-MS-RTA codec isn't in our caps.
    let pts: Vec<&str> = answer.media[0].formats.iter().map(|f| f.as_str()).collect();
    assert_eq!(pts, vec!["0"], "only PCMU is in common");
}

// ---------------------------------------------------------------------------
// Audio + video offer (Asterisk-style conf bridge), where the
// answerer rejects video.
// ---------------------------------------------------------------------------

const ASTERISK_AUDIO_VIDEO_OFFER: &str = "v=0\r\n\
o=- 1734567890 1 IN IP4 192.0.2.5\r\n\
s=Asterisk\r\n\
c=IN IP4 192.0.2.5\r\n\
t=0 0\r\n\
m=audio 14000 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n\
m=video 14002 RTP/AVP 99\r\n\
a=rtpmap:99 H264/90000\r\n\
a=fmtp:99 profile-level-id=42e01f;packetization-mode=1\r\n\
a=sendrecv\r\n";

#[test]
fn corpus_audio_video_offer_rejects_video_section() {
    let offer = SessionDescription::parse(ASTERISK_AUDIO_VIDEO_OFFER).expect("parse");
    // Local audio-only caps — video must come back rejected (port 0)
    // while audio negotiates successfully.
    let answer =
        negotiate_answer(&offer, "10.0.0.1", &audio_only_caps_pcmu_pcma()).expect("negotiate");
    assert_answer_invariants(&offer, &answer);
    assert_eq!(answer.media.len(), 2);
    assert_eq!(answer.media[0].media_type, MediaType::Audio);
    assert!(answer.media[0].port != 0);
    assert_eq!(answer.media[1].media_type, MediaType::Video);
    assert_eq!(
        answer.media[1].port, 0,
        "video MUST be rejected with port 0",
    );
}
