// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

use crate::{name_addr::NameAddr, Uri};

/// Parsed Route/Record-Route header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeader(NameAddr);

impl RouteHeader {
    pub fn new(inner: NameAddr) -> Self {
        Self(inner)
    }

    pub fn uri(&self) -> &Uri {
        self.0.uri()
    }

    pub fn params(&self) -> impl Iterator<Item = (&SmolStr, &Option<SmolStr>)> {
        self.0.params()
    }

    pub fn inner(&self) -> &NameAddr {
        &self.0
    }
}
