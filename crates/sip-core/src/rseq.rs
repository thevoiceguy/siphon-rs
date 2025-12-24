// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Represents the RSeq header (RFC 3262).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSeqHeader {
    pub sequence: u32,
}

/// Represents the RAck header (RFC 3262).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAckHeader {
    pub rseq: u32,
    pub cseq_number: u32,
    pub cseq_method: crate::Method,
}
