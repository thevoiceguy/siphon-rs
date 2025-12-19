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
