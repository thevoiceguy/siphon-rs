// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use smol_str::SmolStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectHeader {
    pub value: SmolStr,
}
