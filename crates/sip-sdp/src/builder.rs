// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

    /// Sets the origin line with validation
    pub fn origin(
        mut self,
        username: &str,
        session_id: &str,
        addr: &str,
    ) -> Result<Self, SdpError> {
        self.sdp.origin = Origin::new(username, session_id, addr)?;
        Ok(self)
    }

    /// Sets the session name with validation
    pub fn session_name(mut self, name: &str) -> Result<Self, SdpError> {
        validate_field(name, "session_name", MAX_SESSION_NAME_LENGTH)?;
        self.sdp.session_name = SmolStr::new(name);
        Ok(self)
    }

    /// Sets session information with validation
    pub fn session_info(mut self, info: &str) -> Result<Self, SdpError> {
        validate_field(info, "session_info", MAX_SESSION_NAME_LENGTH)?;
        self.sdp.session_info = Some(SmolStr::new(info));
        Ok(self)
    }

    /// Sets the connection address with validation
    pub fn connection(mut self, addr: &str) -> Result<Self, SdpError> {
        self.sdp.connection = Some(Connection::new(addr)?);
        Ok(self)
    }

    /// Adds a session-level attribute with validation
    pub fn attribute(mut self, name: &str, value: Option<&str>) -> Result<Self, SdpError> {
        validate_field(name, "attribute_name", MAX_ATTRIBUTE_NAME_LENGTH)?;
        if let Some(val) = value {
            validate_field(val, "attribute_value", MAX_ATTRIBUTE_VALUE_LENGTH)?;
        }

        if self.sdp.attributes.len() >= MAX_ATTRIBUTES_PER_DESCRIPTION {
            return Err(SdpError::TooManyItems {
                collection: "session_attributes",
                max: MAX_ATTRIBUTES_PER_DESCRIPTION,
                actual: self.sdp.attributes.len() + 1,
            });
        }

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
        Ok(self)
    }

    /// Sets the session encryption key with validation
    pub fn encryption_key(mut self, key: &str) -> Result<Self, SdpError> {
        validate_field(key, "encryption_key", MAX_ATTRIBUTE_VALUE_LENGTH)?;
        self.sdp.encryption_key = Some(SmolStr::new(key));
        Ok(self)
    }

    /// Adds a time zone adjustment with validation
    pub fn time_zone_adjustment(
        mut self,
        adjustment_time: &str,
        offset: &str,
    ) -> Result<Self, SdpError> {
        validate_field(
            adjustment_time,
            "adjustment_time",
            MAX_ATTRIBUTE_NAME_LENGTH,
        )?;
        validate_field(offset, "offset", MAX_ATTRIBUTE_NAME_LENGTH)?;

        if self.sdp.time_zones.len() >= MAX_TIME_ZONES {
            return Err(SdpError::TooManyItems {
                collection: "time_zones",
                max: MAX_TIME_ZONES,
                actual: self.sdp.time_zones.len() + 1,
            });
        }

        self.sdp.time_zones.push(TimeZoneAdjustment {
            adjustment_time: SmolStr::new(adjustment_time),
            offset: SmolStr::new(offset),
        });
        Ok(self)
    }

    /// Adds a media description with validation
    pub fn media(mut self, media: MediaDescription) -> Result<Self, SdpError> {
        if self.sdp.media.len() >= MAX_MEDIA_DESCRIPTIONS {
            return Err(SdpError::TooManyItems {
                collection: "media_descriptions",
                max: MAX_MEDIA_DESCRIPTIONS,
                actual: self.sdp.media.len() + 1,
            });
        }

        self.sdp.media.push(media);
        Ok(self)
    }

    /// Sets the time description (default is 0 0 for permanent session)
    pub fn time(mut self, start: u64, stop: u64) -> Self {
        self.sdp.times = vec![TimeDescription {
            start_time: start,
            stop_time: stop,
            repeats: Vec::new(),
        }];
        self
    }

    /// Adds an additional time description with validation
    pub fn add_time(mut self, start: u64, stop: u64) -> Result<Self, SdpError> {
        if self.sdp.times.len() >= MAX_TIME_DESCRIPTIONS {
            return Err(SdpError::TooManyItems {
                collection: "time_descriptions",
                max: MAX_TIME_DESCRIPTIONS,
                actual: self.sdp.times.len() + 1,
            });
        }

        self.sdp.times.push(TimeDescription {
            start_time: start,
            stop_time: stop,
            repeats: Vec::new(),
        });
        Ok(self)
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
