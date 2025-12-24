// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use smol_str::SmolStr;

/// Represents a MIME type such as `application/sdp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeType {
    pub top_level: SmolStr,
    pub subtype: SmolStr,
    pub params: BTreeMap<SmolStr, SmolStr>,
}

impl MimeType {
    pub fn as_str(&self) -> String {
        format!("{}/{}", self.top_level, self.subtype)
    }

    pub fn param(&self, name: &str) -> Option<&SmolStr> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }
}
