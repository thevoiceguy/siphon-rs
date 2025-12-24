// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

/// Priority header values defined in RFC 3261.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorityValue {
    Emergency,
    Urgent,
    Normal,
    NonUrgent,
    Unknown(SmolStr),
}

impl PriorityValue {
    pub fn as_str(&self) -> &str {
        match self {
            PriorityValue::Emergency => "emergency",
            PriorityValue::Urgent => "urgent",
            PriorityValue::Normal => "normal",
            PriorityValue::NonUrgent => "non-urgent",
            PriorityValue::Unknown(value) => value.as_str(),
        }
    }
}
