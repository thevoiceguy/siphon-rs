//! Builder pattern for constructing SDP SessionDescription

use crate::*;

/// Builder for SessionDescription
pub struct SessionDescriptionBuilder {
    sdp: SessionDescription,
}

impl SessionDescriptionBuilder {
    pub fn new() -> Self {
        Self {
            sdp: SessionDescription::default(),
        }
    }

    /// Sets the origin line
    pub fn origin(mut self, username: &str, session_id: &str, addr: &str) -> Self {
        self.sdp.origin = Origin::new(username, session_id, addr);
        self
    }

    /// Sets the session name
    pub fn session_name(mut self, name: &str) -> Self {
        self.sdp.session_name = SmolStr::new(name);
        self
    }

    /// Sets session information
    pub fn session_info(mut self, info: &str) -> Self {
        self.sdp.session_info = Some(SmolStr::new(info));
        self
    }

    /// Sets the connection address
    pub fn connection(mut self, addr: &str) -> Self {
        self.sdp.connection = Some(Connection::new(addr));
        self
    }

    /// Adds a session-level attribute
    pub fn attribute(mut self, name: &str, value: Option<&str>) -> Self {
        if let Some(val) = value {
            self.sdp.attributes.push(Attribute::Value {
                name: SmolStr::new(name),
                value: SmolStr::new(val),
            });
        } else {
            self.sdp
                .attributes
                .push(Attribute::Property(SmolStr::new(name)));
        }
        self
    }

    /// Adds a media description
    pub fn media(mut self, media: MediaDescription) -> Self {
        self.sdp.media.push(media);
        self
    }

    /// Sets the time description (default is 0 0 for permanent session)
    pub fn time(mut self, start: u64, stop: u64) -> Self {
        self.sdp.time = TimeDescription {
            start_time: start,
            stop_time: stop,
        };
        self
    }

    /// Builds the SessionDescription
    pub fn build(self) -> SessionDescription {
        self.sdp
    }
}

impl Default for SessionDescriptionBuilder {
    fn default() -> Self {
        Self::new()
    }
}
