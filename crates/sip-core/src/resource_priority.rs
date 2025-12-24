// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

/// Represents a single namespace.priority value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePriorityValue {
    pub namespace: SmolStr,
    pub priority: SmolStr,
}

/// Represents Resource-Priority/Accept-Resource-Priority headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePriorityHeader {
    pub values: Vec<ResourcePriorityValue>,
}
