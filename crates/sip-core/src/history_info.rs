// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use smol_str::SmolStr;

use crate::Uri;

/// Represents a single History-Info entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfoEntry {
    pub uri: Uri,
    pub params: BTreeMap<SmolStr, Option<SmolStr>>,
}

/// History-Info header containing ordered entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInfoHeader {
    pub entries: Vec<HistoryInfoEntry>,
}
