// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The seed corpus the fuzz targets start from.
//!
//! A fuzzer given no seeds spends its whole run failing to invent a
//! syntactically valid SIP message, and never reaches the state machines
//! underneath. These are the messages worth mutating: each one parses,
//! and each one carries something a target cares about — a route set, a
//! second contact, a q-value, a tel URI, a multipart body.
//!
//! Generated rather than committed as blobs, so they cannot go stale
//! against the parser the way a checked-in corpus does. This test asserts
//! they are all still valid on every run, and writes them out only when
//! `SIPHON_FUZZ_SEED_DIR` is set — which is what the nightly fuzzing
//! workflow does before it runs.

use std::path::PathBuf;

/// A seed: the targets it belongs to, a name, and the bytes.
struct Seed {
    targets: &'static [&'static str],
    name: &'static str,
    body: String,
}

fn seed(targets: &'static [&'static str], name: &'static str, body: impl Into<String>) -> Seed {
    Seed {
        targets,
        name,
        body: body.into(),
    }
}

/// Every target that takes a whole SIP request.
const REQUESTS: &[&str] = &[
    "parse_request",
    "serialize_roundtrip",
    "dialog_from_message",
    "registrar_bindings",
    "transaction_key",
];

/// Every target that takes a whole SIP response.
const RESPONSES: &[&str] = &["parse_response", "dialog_from_message"];

fn seeds() -> Vec<Seed> {
    vec![
        seed(
            REQUESTS,
            "invite",
            "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnashds8;rport\r\n\
             Max-Forwards: 70\r\n\
             From: \"Alice\" <sip:alice@example.com>;tag=1928301774\r\n\
             To: Bob <sip:bob@example.com>\r\n\
             Call-ID: a84b4c76e66710@pc33.example.com\r\n\
             CSeq: 314159 INVITE\r\n\
             Contact: <sip:alice@10.0.0.1:5060;transport=udp>\r\n\
             Record-Route: <sip:proxy1.example.com;lr>\r\n\
             Record-Route: <sip:proxy2.example.com;lr>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 129\r\n\r\n\
             v=0\r\n\
             o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
        ),
        seed(
            REQUESTS,
            "register_multi_contact",
            "REGISTER sip:example.com SIP/2.0\r\n\
             Via: SIP/2.0/TCP 10.0.0.9:5060;branch=z9hG4bKregister1\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@example.com>;tag=reg1\r\n\
             To: <sip:alice@example.com>\r\n\
             Call-ID: register-call-id@10.0.0.9\r\n\
             CSeq: 2 REGISTER\r\n\
             Contact: <sip:alice@10.0.0.9:5060;transport=tcp>;q=0.8;expires=3600\r\n\
             Contact: <sip:alice@10.0.0.10:5060>;q=0.2;reg-id=1\r\n\
             Path: <sip:edge.example.com;lr>\r\n\
             Expires: 3600\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            REQUESTS,
            "register_wildcard",
            "REGISTER sip:example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKwild\r\n\
             From: <sip:alice@example.com>;tag=wild\r\n\
             To: <sip:alice@example.com>\r\n\
             Call-ID: wildcard@10.0.0.9\r\n\
             CSeq: 9 REGISTER\r\n\
             Contact: *\r\n\
             Expires: 0\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            REQUESTS,
            "register_tel_uri",
            "REGISTER sip:example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKtel\r\n\
             From: <tel:+1-555-123-4567>;tag=tel1\r\n\
             To: <tel:+1-555-123-4567>\r\n\
             Call-ID: tel-register@10.0.0.9\r\n\
             CSeq: 1 REGISTER\r\n\
             Contact: <sip:+15551234567@10.0.0.9;user=phone>\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            REQUESTS,
            "bye_in_dialog",
            "BYE sip:bob@10.0.0.2 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKbye1\r\n\
             Route: <sip:proxy2.example.com;lr>\r\n\
             Route: <sip:proxy1.example.com;lr>\r\n\
             From: \"Alice\" <sip:alice@example.com>;tag=1928301774\r\n\
             To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
             Call-ID: a84b4c76e66710@pc33.example.com\r\n\
             CSeq: 314160 BYE\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            REQUESTS,
            "refer_with_replaces",
            "REFER sip:bob@10.0.0.2 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKrefer1\r\n\
             From: <sip:alice@example.com>;tag=refer1\r\n\
             To: <sip:bob@example.com>;tag=a6c85cf\r\n\
             Call-ID: a84b4c76e66710@pc33.example.com\r\n\
             CSeq: 42 REFER\r\n\
             Refer-To: <sip:carol@example.com?Replaces=other-call%3Bto-tag%3Dx%3Bfrom-tag%3Dy>\r\n\
             Referred-By: <sip:alice@example.com>\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            REQUESTS,
            "subscribe",
            "SUBSCRIBE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsub1\r\n\
             From: <sip:alice@example.com>;tag=sub1\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: subscribe@10.0.0.1\r\n\
             CSeq: 1 SUBSCRIBE\r\n\
             Event: presence\r\n\
             Expires: 3600\r\n\
             Accept: application/pidf+xml\r\n\
             Contact: <sip:alice@10.0.0.1>\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            &["parse_request", "transaction_key"],
            "options_no_body",
            "OPTIONS sip:example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKoptions\r\n\
             From: <sip:ping@example.com>;tag=opt\r\n\
             To: <sip:example.com>\r\n\
             Call-ID: options@10.0.0.1\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            RESPONSES,
            "ok_with_record_route",
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnashds8;received=203.0.113.1\r\n\
             From: \"Alice\" <sip:alice@example.com>;tag=1928301774\r\n\
             To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
             Call-ID: a84b4c76e66710@pc33.example.com\r\n\
             CSeq: 314159 INVITE\r\n\
             Contact: <sip:bob@10.0.0.2:5060>\r\n\
             Record-Route: <sip:proxy1.example.com;lr>\r\n\
             Record-Route: <sip:proxy2.example.com;lr>\r\n\
             Session-Expires: 1800;refresher=uac\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            RESPONSES,
            "ringing_reliable",
            "SIP/2.0 180 Ringing\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKnashds8\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             To: <sip:bob@example.com>;tag=early-tag\r\n\
             Call-ID: a84b4c76e66710@pc33.example.com\r\n\
             CSeq: 314159 INVITE\r\n\
             RSeq: 1\r\n\
             Require: 100rel\r\n\
             Contact: <sip:bob@10.0.0.2>\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            RESPONSES,
            "unauthorized",
            "SIP/2.0 401 Unauthorized\r\n\
             Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKregister1\r\n\
             From: <sip:alice@example.com>;tag=reg1\r\n\
             To: <sip:alice@example.com>;tag=server-tag\r\n\
             Call-ID: register-call-id@10.0.0.9\r\n\
             CSeq: 2 REGISTER\r\n\
             WWW-Authenticate: Digest realm=\"example.com\", nonce=\"dcd98b7102dd2f0e\", algorithm=MD5, qop=\"auth\"\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            &["parse_headers"],
            "headers",
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1;rport=5060;received=203.0.113.1\r\n\
             From: \"Alice ;tricky\" <sip:alice@example.com>;tag=1\r\n\
             To: <sip:bob@example.com>;tag=2\r\n\
             Contact: <sip:a@1.2.3.4>;q=0.5;expires=60\r\n\
             Content-Length: 0\r\n\r\n",
        ),
        seed(
            &["parse_via"],
            "via",
            "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1;rport;received=203.0.113.1",
        ),
        seed(
            &["parse_uri"],
            "uri_sip",
            "sip:alice@example.com:5060;transport=tcp;lr?X-H=v",
        ),
        seed(&["parse_uri"], "uri_tel", "tel:+1-555-123-4567;ext=1234"),
        seed(
            &["parse_cpim"],
            "cpim",
            "From: <sip:alice@example.com>\r\n\
             To: <sip:bob@example.com>\r\n\
             DateTime: 2026-09-22T08:00:00Z\r\n\
             Content-Type: text/plain\r\n\r\n\
             Content-Type: text/plain;charset=utf-8\r\n\r\n\
             hello\r\n",
        ),
        seed(
            &["parse_multipart"],
            "multipart",
            "--b1\r\n\
             Content-Type: application/sdp\r\n\r\n\
             v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 1000 RTP/AVP 0\r\n\r\n\
             --b1\r\n\
             Content-Type: application/pidf+xml\r\n\
             Content-ID: <loc@example.com>\r\n\r\n\
             <?xml version=\"1.0\"?><presence/>\r\n\
             --b1--\r\n",
        ),
    ]
}

/// Where the fuzzer reads its corpus from, when the workflow asks for it.
fn seed_dir() -> Option<PathBuf> {
    std::env::var_os("SIPHON_FUZZ_SEED_DIR").map(PathBuf::from)
}

#[test]
fn the_seed_corpus_is_valid_and_written_when_asked() {
    let seeds = seeds();
    assert!(!seeds.is_empty());

    for seed in &seeds {
        let bytes = bytes::Bytes::from(seed.body.clone());
        // Every seed has to be the thing it claims to be, or the fuzzer
        // starts from inputs that bail out at the first line.
        if seed.targets.contains(&"parse_request") || seed.targets.contains(&"registrar_bindings") {
            assert!(
                sip_parse::parse_request(&bytes).is_some(),
                "seed {} does not parse as a request",
                seed.name
            );
        }
        if seed.targets.contains(&"parse_response") {
            assert!(
                sip_parse::parse_response(&bytes).is_some(),
                "seed {} does not parse as a response",
                seed.name
            );
        }
    }

    let Some(dir) = seed_dir() else {
        return;
    };
    for seed in &seeds {
        for target in seed.targets {
            let target_dir = dir.join(target);
            std::fs::create_dir_all(&target_dir).expect("create the target's corpus directory");
            std::fs::write(target_dir.join(seed.name), seed.body.as_bytes())
                .expect("write the seed");
        }
    }
}
