// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::Uri;

/// Represents a single Geolocation header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationValue {
    pub uri: Uri,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// Geolocation header (list of values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationHeader {
    pub values: Vec<GeolocationValue>,
}

/// Geolocation-Error header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationErrorHeader {
    pub code: Option<SmolStr>,
    pub description: Option<SmolStr>,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// Geolocation-Routing header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeolocationRoutingHeader {
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}
