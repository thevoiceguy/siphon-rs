// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use smol_str::SmolStr;

/// Parsed representation of a Via header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaHeader {
    pub transport: SmolStr,
    pub sent_by: SmolStr,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

impl ViaHeader {
    /// Returns the transport token (e.g. UDP/TCP/TLS) associated with this Via.
    pub fn transport(&self) -> &str {
        self.transport.as_str()
    }

    /// Looks up the provided parameter ignoring ASCII case.
    pub fn param(&self, name: &str) -> Option<&Option<SmolStr>> {
        self.params.get(&SmolStr::new(name.to_ascii_lowercase()))
    }
}
