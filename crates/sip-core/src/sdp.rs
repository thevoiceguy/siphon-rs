use smol_str::SmolStr;

/// Lightweight wrapper over an SDP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpSession {
    raw: SmolStr,
}

impl SdpSession {
    pub fn new(raw: SmolStr) -> Self {
        Self { raw }
    }

    pub fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.raw.split('\n').map(|line| line.trim_end_matches('\r'))
    }
}
