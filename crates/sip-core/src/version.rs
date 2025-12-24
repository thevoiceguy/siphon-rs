// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt;

/// SIP version supported by the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SipVersion {
    V2,
}

impl SipVersion {
    /// Returns the SIP version string (e.g. `SIP/2.0`).
    pub const fn as_str(self) -> &'static str {
        match self {
            SipVersion::V2 => "SIP/2.0",
        }
    }
}

impl fmt::Display for SipVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
