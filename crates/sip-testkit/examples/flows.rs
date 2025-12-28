// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Demonstrates assembling simple SIP call flows with sip-testkit helpers.
use sip_parse::{serialize_request, serialize_response};
use sip_testkit::{
    build_options, build_refer, build_register, build_response, scenario_invite_prack,
};

fn main() {
    // REGISTER flow
    let register = build_register(
        "sip:registrar.example.com",
        "<sip:alice@client.example.com:5060>",
    );
    println!(
        "REGISTER:\n{}",
        String::from_utf8_lossy(&serialize_request(&register))
    );

    // INVITE + PRACK early dialog flow
    let (invite, provisional, prack) = scenario_invite_prack("sip:bob@example.com");
    println!(
        "INVITE:\n{}",
        String::from_utf8_lossy(&serialize_request(&invite))
    );
    println!(
        "180 (with RSeq):\n{}",
        String::from_utf8_lossy(&serialize_response(&provisional))
    );
    println!(
        "PRACK:\n{}",
        String::from_utf8_lossy(&serialize_request(&prack))
    );

    // REFER transfer
    let refer = build_refer(
        "sip:bob@example.com",
        "<sip:carol@example.com>",
        "call-transfer@example.com",
        5,
    );
    println!(
        "REFER:\n{}",
        String::from_utf8_lossy(&serialize_request(&refer))
    );

    // OPTIONS keepalive
    let options = build_options("sip:example.com");
    let ok = build_response(200, "OK");
    println!(
        "OPTIONS:\n{}",
        String::from_utf8_lossy(&serialize_request(&options))
    );
    println!(
        "200 OK:\n{}",
        String::from_utf8_lossy(&serialize_response(&ok))
    );
}
