use smol_str::SmolStr;

/// Minimal SDP representation sufficient for signalling unit tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDescription {
    pub version: u8,
    pub origin: SmolStr,
    pub session_name: SmolStr,
}

impl SessionDescription {
    /// Creates a new session description with version 0.
    pub fn new(origin: SmolStr, session_name: SmolStr) -> Self {
        Self {
            version: 0,
            origin,
            session_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_basic_sdp() {
        let sdp = SessionDescription::new("alice".into(), "call".into());
        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.as_str(), "alice");
    }
}
