// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
//!
//! This module implements the RTP/AVP profile defined in RFC 3551, which specifies
//! static payload type mappings for common audio and video codecs.

use std::fmt;

const MAX_ENCODING_NAME_LENGTH: usize = 32;

/// Static payload type information from RFC 3551.
///
/// Represents a codec with its fixed assignment in the RTP/AVP profile.
///
/// # Security Note
///
/// All instances of this type are const, making the public fields effectively
/// immutable. While the fields are public for backward compatibility, they
/// cannot be modified at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticPayloadType {
    /// Payload type number (0-95)
    payload_type: u8,
    /// Encoding name (e.g., "PCMU", "GSM", "H261")
    encoding_name: &'static str,
    /// Clock rate in Hz
    clock_rate: u32,
    /// Number of channels (for audio) or None (for video)
    channels: Option<u8>,
    /// Media type ("audio" or "video")
    media_type: &'static str,
}

impl StaticPayloadType {
    /// Returns the payload type number.
    pub const fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns the encoding name.
    pub const fn encoding_name(&self) -> &'static str {
        self.encoding_name
    }

    /// Returns the clock rate in Hz.
    pub const fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Returns the number of channels (for audio) or None (for video).
    pub const fn channels(&self) -> Option<u8> {
        self.channels
    }

    /// Returns the media type ("audio" or "video").
    pub const fn media_type(&self) -> &'static str {
        self.media_type
    }
}

impl fmt::Display for StaticPayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PT {} {} {}/{}",
            self.payload_type(),
            self.encoding_name(),
            self.media_type(),
            self.clock_rate()
        )?;
        if let Some(ch) = self.channels() {
            write!(f, "/{}", ch)?;
        }
        Ok(())
    }
}

// Audio payload types

/// PCMU (ITU-T G.711 μ-law) - PT 0
pub const PCMU: StaticPayloadType = StaticPayloadType {
    payload_type: 0,
    encoding_name: "PCMU",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// GSM (GSM 06.10) - PT 3
pub const GSM: StaticPayloadType = StaticPayloadType {
    payload_type: 3,
    encoding_name: "GSM",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// G723 (ITU-T G.723.1) - PT 4
pub const G723: StaticPayloadType = StaticPayloadType {
    payload_type: 4,
    encoding_name: "G723",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// DVI4 8kHz (Intel DVI4) - PT 5
pub const DVI4_8000: StaticPayloadType = StaticPayloadType {
    payload_type: 5,
    encoding_name: "DVI4",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// DVI4 16kHz (Intel DVI4) - PT 6
pub const DVI4_16000: StaticPayloadType = StaticPayloadType {
    payload_type: 6,
    encoding_name: "DVI4",
    clock_rate: 16000,
    channels: Some(1),
    media_type: "audio",
};

/// LPC (Linear Predictive Coding) - PT 7
pub const LPC: StaticPayloadType = StaticPayloadType {
    payload_type: 7,
    encoding_name: "LPC",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// PCMA (ITU-T G.711 A-law) - PT 8
pub const PCMA: StaticPayloadType = StaticPayloadType {
    payload_type: 8,
    encoding_name: "PCMA",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// G722 (ITU-T G.722) - PT 9
pub const G722: StaticPayloadType = StaticPayloadType {
    payload_type: 9,
    encoding_name: "G722",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// L16 stereo (Linear PCM) - PT 10
pub const L16_STEREO: StaticPayloadType = StaticPayloadType {
    payload_type: 10,
    encoding_name: "L16",
    clock_rate: 44100,
    channels: Some(2),
    media_type: "audio",
};

/// L16 mono (Linear PCM) - PT 11
pub const L16_MONO: StaticPayloadType = StaticPayloadType {
    payload_type: 11,
    encoding_name: "L16",
    clock_rate: 44100,
    channels: Some(1),
    media_type: "audio",
};

/// QCELP (Qualcomm Code Excited Linear Prediction) - PT 12
pub const QCELP: StaticPayloadType = StaticPayloadType {
    payload_type: 12,
    encoding_name: "QCELP",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// CN (Comfort Noise) - PT 13
pub const CN: StaticPayloadType = StaticPayloadType {
    payload_type: 13,
    encoding_name: "CN",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// MPA (MPEG-1 or MPEG-2 audio) - PT 14
pub const MPA: StaticPayloadType = StaticPayloadType {
    payload_type: 14,
    encoding_name: "MPA",
    clock_rate: 90000,
    channels: None,
    media_type: "audio",
};

/// G728 (ITU-T G.728) - PT 15
pub const G728: StaticPayloadType = StaticPayloadType {
    payload_type: 15,
    encoding_name: "G728",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

/// DVI4 11.025kHz (Intel DVI4) - PT 16
pub const DVI4_11025: StaticPayloadType = StaticPayloadType {
    payload_type: 16,
    encoding_name: "DVI4",
    clock_rate: 11025,
    channels: Some(1),
    media_type: "audio",
};

/// DVI4 22.05kHz (Intel DVI4) - PT 17
pub const DVI4_22050: StaticPayloadType = StaticPayloadType {
    payload_type: 17,
    encoding_name: "DVI4",
    clock_rate: 22050,
    channels: Some(1),
    media_type: "audio",
};

/// G729 (ITU-T G.729) - PT 18
pub const G729: StaticPayloadType = StaticPayloadType {
    payload_type: 18,
    encoding_name: "G729",
    clock_rate: 8000,
    channels: Some(1),
    media_type: "audio",
};

// Video payload types

/// CelB (Cell-B video) - PT 25
pub const CELB: StaticPayloadType = StaticPayloadType {
    payload_type: 25,
    encoding_name: "CelB",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// JPEG (JPEG video) - PT 26
pub const JPEG: StaticPayloadType = StaticPayloadType {
    payload_type: 26,
    encoding_name: "JPEG",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// nv (nv video) - PT 28
pub const NV: StaticPayloadType = StaticPayloadType {
    payload_type: 28,
    encoding_name: "nv",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// H261 (ITU-T H.261) - PT 31
pub const H261: StaticPayloadType = StaticPayloadType {
    payload_type: 31,
    encoding_name: "H261",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// MPV (MPEG-1 or MPEG-2 video) - PT 32
pub const MPV: StaticPayloadType = StaticPayloadType {
    payload_type: 32,
    encoding_name: "MPV",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// MP2T (MPEG-2 transport stream) - PT 33
pub const MP2T: StaticPayloadType = StaticPayloadType {
    payload_type: 33,
    encoding_name: "MP2T",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// H263 (ITU-T H.263) - PT 34
pub const H263: StaticPayloadType = StaticPayloadType {
    payload_type: 34,
    encoding_name: "H263",
    clock_rate: 90000,
    channels: None,
    media_type: "video",
};

/// Complete table of all static payload types defined in RFC 3551.
///
/// Indexed by payload type number. None for unassigned payload types.
pub const STATIC_PAYLOAD_TYPES: [Option<&'static StaticPayloadType>; 128] = [
    Some(&PCMU),       // 0
    None,              // 1 - reserved
    None,              // 2 - reserved
    Some(&GSM),        // 3
    Some(&G723),       // 4
    Some(&DVI4_8000),  // 5
    Some(&DVI4_16000), // 6
    Some(&LPC),        // 7
    Some(&PCMA),       // 8
    Some(&G722),       // 9
    Some(&L16_STEREO), // 10
    Some(&L16_MONO),   // 11
    Some(&QCELP),      // 12
    Some(&CN),         // 13
    Some(&MPA),        // 14
    Some(&G728),       // 15
    Some(&DVI4_11025), // 16
    Some(&DVI4_22050), // 17
    Some(&G729),       // 18
    None,              // 19 - reserved
    None,              // 20 - unassigned
    None,              // 21 - unassigned
    None,              // 22 - unassigned
    None,              // 23 - unassigned
    None,              // 24 - unassigned
    Some(&CELB),       // 25
    Some(&JPEG),       // 26
    None,              // 27 - unassigned
    Some(&NV),         // 28
    None,              // 29 - unassigned
    None,              // 30 - unassigned
    Some(&H261),       // 31
    Some(&MPV),        // 32
    Some(&MP2T),       // 33
    Some(&H263),       // 34
    // 35-71: unassigned (37 elements)
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    // 72-76: reserved for RTCP conflict avoidance (5 elements)
    None,
    None,
    None,
    None,
    None,
    // 77-95: unassigned (19 elements)
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    // 96-127: dynamic (32 elements)
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
];

/// Returns static payload type information for a given payload type number.
///
/// # Arguments
///
/// * `pt` - Payload type number (0-127)
///
/// # Returns
///
/// * `Some(&StaticPayloadType)` if the payload type is statically defined
/// * `None` if the payload type is unassigned, reserved, or dynamic (96-127)
///
/// # Example
///
/// ```
/// use sip_core::rtp_avp::get_static_payload_type;
///
/// let pcmu = get_static_payload_type(0).unwrap();
/// assert_eq!(pcmu.encoding_name(), "PCMU");
/// assert_eq!(pcmu.clock_rate(), 8000);
///
/// // Dynamic payload types return None
/// assert!(get_static_payload_type(96).is_none());
/// ```
pub fn get_static_payload_type(pt: u8) -> Option<&'static StaticPayloadType> {
    if (pt as usize) < STATIC_PAYLOAD_TYPES.len() {
        STATIC_PAYLOAD_TYPES[pt as usize]
    } else {
        None
    }
}

/// Returns the payload type number for a given encoding name.
///
/// For encodings with multiple payload types (e.g., DVI4 at different clock rates),
/// this returns the first matching payload type. Use `get_payload_type_with_rate`
/// for more specific matching.
///
/// # Arguments
///
/// * `encoding_name` - Encoding name (case-insensitive, max 32 chars)
///
/// # Returns
///
/// * `Some(pt)` if a static payload type exists for this encoding
/// * `None` if no static payload type is defined or name is too long
///
/// # Example
///
/// ```
/// use sip_core::rtp_avp::get_payload_type;
///
/// assert_eq!(get_payload_type("PCMU"), Some(0));
/// assert_eq!(get_payload_type("pcmu"), Some(0));  // case-insensitive
/// assert_eq!(get_payload_type("G729"), Some(18));
/// assert_eq!(get_payload_type("Unknown"), None);
/// ```
pub fn get_payload_type(encoding_name: &str) -> Option<u8> {
    // Reject oversized input to prevent DoS
    if encoding_name.len() > MAX_ENCODING_NAME_LENGTH {
        return None;
    }

    let name_upper = encoding_name.to_uppercase();
    STATIC_PAYLOAD_TYPES
        .iter()
        .enumerate()
        .find_map(|(pt, opt_info)| {
            opt_info.and_then(|info| {
                if info.encoding_name().to_uppercase() == name_upper {
                    Some(pt as u8)
                } else {
                    None
                }
            })
        })
}

/// Returns the payload type number for a given encoding name and clock rate.
///
/// This is useful for encodings like DVI4 that have multiple payload types
/// at different clock rates.
///
/// # Arguments
///
/// * `encoding_name` - Encoding name (case-insensitive, max 32 chars)
/// * `clock_rate` - Clock rate in Hz
///
/// # Example
///
/// ```
/// use sip_core::rtp_avp::get_payload_type_with_rate;
///
/// assert_eq!(get_payload_type_with_rate("DVI4", 8000), Some(5));
/// assert_eq!(get_payload_type_with_rate("DVI4", 16000), Some(6));
/// assert_eq!(get_payload_type_with_rate("DVI4", 11025), Some(16));
/// assert_eq!(get_payload_type_with_rate("DVI4", 22050), Some(17));
/// ```
pub fn get_payload_type_with_rate(encoding_name: &str, clock_rate: u32) -> Option<u8> {
    // Reject oversized input to prevent DoS
    if encoding_name.len() > MAX_ENCODING_NAME_LENGTH {
        return None;
    }

    let name_upper = encoding_name.to_uppercase();
    STATIC_PAYLOAD_TYPES
        .iter()
        .enumerate()
        .find_map(|(pt, opt_info)| {
            opt_info.and_then(|info| {
                if info.encoding_name().to_uppercase() == name_upper
                    && info.clock_rate() == clock_rate
                {
                    Some(pt as u8)
                } else {
                    None
                }
            })
        })
}

/// Checks if a payload type number is in the static range (0-95).
///
/// Note that not all numbers in this range have static assignments.
/// Use `get_static_payload_type` to check for actual assignments.
pub fn is_static_range(pt: u8) -> bool {
    pt < 96
}

/// Checks if a payload type number is in the dynamic range (96-127).
pub fn is_dynamic_range(pt: u8) -> bool {
    (96..=127).contains(&pt)
}

/// Checks if a payload type number is reserved (72-76) for RTCP conflict avoidance.
pub fn is_reserved(pt: u8) -> bool {
    (72..=76).contains(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_static_payload_type_pcmu() {
        let pt = get_static_payload_type(0).unwrap();
        assert_eq!(pt.payload_type(), 0);
        assert_eq!(pt.encoding_name(), "PCMU");
        assert_eq!(pt.clock_rate(), 8000);
        assert_eq!(pt.channels(), Some(1));
        assert_eq!(pt.media_type(), "audio");
    }

    #[test]
    fn test_get_static_payload_type_g729() {
        let pt = get_static_payload_type(18).unwrap();
        assert_eq!(pt.payload_type(), 18);
        assert_eq!(pt.encoding_name(), "G729");
        assert_eq!(pt.clock_rate(), 8000);
    }

    #[test]
    fn test_get_static_payload_type_h261() {
        let pt = get_static_payload_type(31).unwrap();
        assert_eq!(pt.payload_type(), 31);
        assert_eq!(pt.encoding_name(), "H261");
        assert_eq!(pt.clock_rate(), 90000);
        assert_eq!(pt.media_type(), "video");
        assert_eq!(pt.channels(), None);
    }

    #[test]
    fn test_get_static_payload_type_dynamic() {
        assert!(get_static_payload_type(96).is_none());
        assert!(get_static_payload_type(127).is_none());
    }

    #[test]
    fn test_get_payload_type_by_name() {
        assert_eq!(get_payload_type("PCMU"), Some(0));
        assert_eq!(get_payload_type("PCMA"), Some(8));
        assert_eq!(get_payload_type("G729"), Some(18));
        assert_eq!(get_payload_type("H261"), Some(31));
    }

    #[test]
    fn test_get_payload_type_case_insensitive() {
        assert_eq!(get_payload_type("pcmu"), Some(0));
        assert_eq!(get_payload_type("PcMu"), Some(0));
        assert_eq!(get_payload_type("PCMU"), Some(0));
    }

    #[test]
    fn test_get_payload_type_with_rate_dvi4() {
        assert_eq!(get_payload_type_with_rate("DVI4", 8000), Some(5));
        assert_eq!(get_payload_type_with_rate("DVI4", 16000), Some(6));
        assert_eq!(get_payload_type_with_rate("DVI4", 11025), Some(16));
        assert_eq!(get_payload_type_with_rate("DVI4", 22050), Some(17));
    }

    #[test]
    fn test_get_payload_type_with_rate_l16() {
        assert_eq!(get_payload_type_with_rate("L16", 44100), Some(10)); // Returns first match (stereo)
    }

    #[test]
    fn test_is_static_range() {
        assert!(is_static_range(0));
        assert!(is_static_range(50));
        assert!(is_static_range(95));
        assert!(!is_static_range(96));
        assert!(!is_static_range(127));
    }

    #[test]
    fn test_is_dynamic_range() {
        assert!(!is_dynamic_range(95));
        assert!(is_dynamic_range(96));
        assert!(is_dynamic_range(100));
        assert!(is_dynamic_range(127));
        assert!(!is_dynamic_range(128));
    }

    #[test]
    fn test_is_reserved() {
        assert!(!is_reserved(71));
        assert!(is_reserved(72));
        assert!(is_reserved(74));
        assert!(is_reserved(76));
        assert!(!is_reserved(77));
    }

    #[test]
    fn test_static_payload_type_display() {
        let pcmu = get_static_payload_type(0).unwrap();
        assert_eq!(pcmu.to_string(), "PT 0 PCMU audio/8000/1");

        let h261 = get_static_payload_type(31).unwrap();
        assert_eq!(h261.to_string(), "PT 31 H261 video/90000");
    }

    #[test]
    fn test_all_audio_codecs() {
        // Test all audio codecs are present
        assert!(get_static_payload_type(0).is_some()); // PCMU
        assert!(get_static_payload_type(3).is_some()); // GSM
        assert!(get_static_payload_type(4).is_some()); // G723
        assert!(get_static_payload_type(5).is_some()); // DVI4
        assert!(get_static_payload_type(6).is_some()); // DVI4
        assert!(get_static_payload_type(7).is_some()); // LPC
        assert!(get_static_payload_type(8).is_some()); // PCMA
        assert!(get_static_payload_type(9).is_some()); // G722
        assert!(get_static_payload_type(10).is_some()); // L16
        assert!(get_static_payload_type(11).is_some()); // L16
        assert!(get_static_payload_type(12).is_some()); // QCELP
        assert!(get_static_payload_type(13).is_some()); // CN
        assert!(get_static_payload_type(14).is_some()); // MPA
        assert!(get_static_payload_type(15).is_some()); // G728
        assert!(get_static_payload_type(16).is_some()); // DVI4
        assert!(get_static_payload_type(17).is_some()); // DVI4
        assert!(get_static_payload_type(18).is_some()); // G729
    }

    #[test]
    fn test_all_video_codecs() {
        // Test all video codecs are present
        assert!(get_static_payload_type(25).is_some()); // CelB
        assert!(get_static_payload_type(26).is_some()); // JPEG
        assert!(get_static_payload_type(28).is_some()); // nv
        assert!(get_static_payload_type(31).is_some()); // H261
        assert!(get_static_payload_type(32).is_some()); // MPV
        assert!(get_static_payload_type(33).is_some()); // MP2T
        assert!(get_static_payload_type(34).is_some()); // H263
    }

    // Security tests

    #[test]
    fn reject_oversized_encoding_name() {
        let long_name = "x".repeat(MAX_ENCODING_NAME_LENGTH + 1);
        assert_eq!(get_payload_type(&long_name), None);
        assert_eq!(get_payload_type_with_rate(&long_name, 8000), None);
    }

    #[test]
    fn const_data_cannot_be_mutated() {
        // This test documents that even though fields are public,
        // const instances cannot be mutated
        let pcmu = get_static_payload_type(0).unwrap();

        // Can read fields
        let _ = pcmu.payload_type();
        let _ = pcmu.encoding_name();

        // Cannot mutate (these would not compile):
        // pcmu.payload_type = 99;  // ← Does not compile! (const data)
        // let mut_pcmu = pcmu;
        // mut_pcmu.payload_type = 99;  // ← Also does not compile!
    }
}
