// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use sip_core::Response;

/// Extract realm value from WWW-Authenticate/Proxy-Authenticate headers.
pub fn extract_realm(response: &Response) -> Option<String> {
    let header_val = response
        .headers
        .get("WWW-Authenticate")
        .or_else(|| response.headers.get("Proxy-Authenticate"))?;
    let header = header_val.trim();
    let header_lower = header.to_ascii_lowercase();
    let digest_pos = header_lower.find("digest")?;
    let params = header[digest_pos + "Digest".len()..].trim_start();

    split_auth_params(params).into_iter().find_map(|part| {
        let trimmed = part.trim();
        let trimmed = trimmed
            .strip_prefix("Digest")
            .unwrap_or(trimmed)
            .trim_start();
        let (key, value) = trimmed.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("realm") {
            let value = value.trim();
            let value = if value.starts_with('"') && value.ends_with('"') {
                &value[1..value.len() - 1]
            } else {
                value
            };
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn split_auth_params(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;

    for (idx, ch) in input.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let part = input[start..idx].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }

    let tail = input[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }

    parts
}
