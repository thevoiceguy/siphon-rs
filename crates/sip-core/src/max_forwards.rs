// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

use crate::Headers;

/// Errors returned when attempting to adjust Max-Forwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaxForwardsError {
    Exhausted,
    Invalid,
}

/// Decrements Max-Forwards per RFC 3261 §8.1.1.6, inserting a default when missing.
pub fn decrement_max_forwards(headers: &mut Headers) -> Result<u32, MaxForwardsError> {
    for header in headers.iter_mut() {
        if header.name.eq_ignore_ascii_case("Max-Forwards") {
            let value = header
                .value
                .as_str()
                .trim()
                .parse::<u32>()
                .map_err(|_| MaxForwardsError::Invalid)?;
            if value == 0 {
                return Err(MaxForwardsError::Exhausted);
            }
            let decremented = value.saturating_sub(1);
            header.value = SmolStr::new(decremented.to_string());
            return Ok(decremented);
        }
    }

    // Insert default 70 -> 69 when missing.
    headers.push(SmolStr::new("Max-Forwards"), SmolStr::new("69"));
    Ok(69)
}

/// Validates a branch parameter including the RFC 3261 magic cookie prefix.
pub fn is_valid_branch(branch: &str) -> bool {
    branch.starts_with("z9hG4bK")
        && branch.is_ascii()
        && branch.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrements_existing_header() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards".into(), "5".into());
        let remaining = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(remaining, 4);
    }

    #[test]
    fn inserts_when_missing() {
        let mut headers = Headers::new();
        let remaining = decrement_max_forwards(&mut headers).unwrap();
        assert_eq!(remaining, 69);
        assert!(headers.get("Max-Forwards").is_some());
    }

    #[test]
    fn returns_error_when_exhausted() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards".into(), "0".into());
        assert_eq!(
            decrement_max_forwards(&mut headers),
            Err(MaxForwardsError::Exhausted)
        );
    }

    #[test]
    fn returns_error_when_invalid() {
        let mut headers = Headers::new();
        headers.push("Max-Forwards".into(), "bogus".into());
        assert_eq!(
            decrement_max_forwards(&mut headers),
            Err(MaxForwardsError::Invalid)
        );
    }

    #[test]
    fn validates_branch_cookie() {
        assert!(is_valid_branch("z9hG4bKabc123"));
        assert!(!is_valid_branch("badbranch"));
    }
}
