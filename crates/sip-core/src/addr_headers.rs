// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::name_addr::NameAddr;

/// Typed wrapper for the `From` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromHeader(NameAddr);

impl FromHeader {
    pub fn new(inner: NameAddr) -> Self {
        Self(inner)
    }

    pub fn tag(&self) -> Option<&smol_str::SmolStr> {
        self.0.get_param("tag").and_then(|v| v.as_ref())
    }

    pub fn inner(&self) -> &NameAddr {
        &self.0
    }
}

/// Typed wrapper for the `To` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToHeader(NameAddr);

impl ToHeader {
    pub fn new(inner: NameAddr) -> Self {
        Self(inner)
    }

    pub fn tag(&self) -> Option<&smol_str::SmolStr> {
        self.0.get_param("tag").and_then(|v| v.as_ref())
    }

    pub fn inner(&self) -> &NameAddr {
        &self.0
    }
}

/// Typed wrapper for Call-Info/Reply-To/other name-addr headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddrHeader(NameAddr);

impl NameAddrHeader {
    pub fn new(inner: NameAddr) -> Self {
        Self(inner)
    }

    pub fn inner(&self) -> &NameAddr {
        &self.0
    }
}
