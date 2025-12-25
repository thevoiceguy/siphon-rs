// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Core SIP types, messages, headers, and URIs.
//!
//! This crate provides the foundational types for the Siphon SIP stack:
//! - **Messages**: [`Request`], [`Response`], [`SipMessage`]
//! - **URIs**: [`SipUri`] (sip/sips), [`TelUri`] (RFC 3966 telephone numbers), [`Uri`] (unified)
//! - **Headers**: [`Headers`] container and typed header structures
//! - **Methods**: [`Method`] enum (INVITE, REGISTER, SUBSCRIBE, etc.)
//! - **SDP**: Session Description Protocol types and offer/answer engine
//! - **Extensions**: PRACK (RFC 3262), Session Timers (RFC 4028), Privacy (RFC 3323), and more
//!
//! All types are designed for zero-copy parsing where possible, using [`SmolStr`](smol_str::SmolStr)
//! and [`Bytes`](bytes::Bytes) for efficient string and binary data handling.
//!
//! # Examples
//!
//! ```
//! # use sip_core::*;
//! // Parse a SIP URI
//! let uri = SipUri::parse("sip:alice@example.com").unwrap();
//!
//! // Create a tel URI (E.164)
//! let tel = TelUri::new("+15551234567", true);
//! ```

pub mod addr_headers;
pub mod auth;
pub mod caller_preferences;
pub mod capabilities;
pub mod contact;
pub mod cpim;
pub mod date;
pub mod event;
pub mod geolocation;
pub mod headers;
pub mod history_info;
pub mod max_forwards;
pub mod message_waiting;
pub mod method;
pub mod mime;
pub mod msg;
pub mod name_addr;
pub mod p_headers;
pub mod presence;
pub mod priority;
pub mod privacy;
pub mod reason;
pub mod refer_sub;
pub mod referred_by;
pub mod reg_event;
pub mod replaces;
pub mod resource_priority;
pub mod route;
pub mod rseq;
pub mod rtp_avp;
pub mod sdp;
pub mod sdp_offer_answer;
pub mod security;
pub mod service_route;
pub mod session_timer;
pub mod sip_etag;
pub mod sipfrag;
pub mod subject;
pub mod tel_uri;
pub mod token_list;
pub mod uri;
pub mod version;
pub mod via;
pub mod watcher_info;

pub use addr_headers::{FromHeader, NameAddrHeader, ToHeader};
pub use auth::AuthorizationHeader;
pub use caller_preferences::{
    score_contacts, AcceptContact, CancelDirective, ForkDirective, ParallelDirective,
    ProxyDirective, QueueDirective, RecurseDirective, RejectContact, RequestDisposition,
    ScoredContact,
};
pub use capabilities::{Capability, CapabilitySet, FeatureTag, FeatureValue};
pub use contact::ContactHeader;
pub use cpim::{parse_cpim, CpimHeader, CpimMessage};
pub use date::DateHeader;
pub use event::{EventHeader, SubscriptionState, SubscriptionStateHeader};
pub use geolocation::{
    GeolocationErrorHeader, GeolocationHeader, GeolocationRoutingHeader, GeolocationValue,
};
pub use headers::{Header, Headers};
pub use history_info::{HistoryInfoEntry, HistoryInfoHeader};
pub use max_forwards::{decrement_max_forwards, is_valid_branch, MaxForwardsError};
pub use message_waiting::{
    parse_message_summary, MessageContextClass, MessageCounts, MessageHeader, MessageSummary,
};
pub use method::Method;
pub use mime::MimeType;
pub use msg::{Request, RequestLine, Response, SipMessage, StatusLine};
pub use name_addr::NameAddr;
pub use p_headers::{
    parse_p_asserted_identity, parse_p_preferred_identity, PAccessNetworkInfo,
    PAssertedIdentityHeader, PIdentity, PPreferredIdentityHeader, PVisitedNetworkIdHeader,
};
pub use presence::{parse_pidf, BasicStatus, PresenceDocument, Tuple};
pub use priority::PriorityValue;
pub use privacy::{
    enforce_privacy, parse_privacy_header, requires_privacy_enforcement, PrivacyHeader,
    PrivacyValue,
};
pub use reason::{parse_reason_header, Q850Cause, ReasonHeader, ReasonProtocol};
pub use refer_sub::ReferSubHeader;
pub use referred_by::ReferredByHeader;
pub use reg_event::{
    Contact, ContactEvent, ContactState, RegInfo, RegInfoState, Registration, RegistrationState,
};
pub use replaces::ReplacesHeader;
pub use resource_priority::{ResourcePriorityHeader, ResourcePriorityValue};
pub use route::RouteHeader;
pub use rseq::{RAckHeader, RSeqHeader};
pub use sdp::{
    Attribute, Bandwidth, BandwidthType, CapabilityDescription, CapabilityParameter,
    CapabilityParameterType, ConfirmStatus, Connection, CurrentStatus, DesiredStatus, Direction,
    EncryptionKey, Fmtp, GroupSemantics, MediaDescription, MediaGroup, Origin,
    PreconditionDirection, PreconditionType, RepeatTime, RtcpAttribute, RtpMap, SdpCapabilitySet,
    SdpError, SdpSession, StatusType, StrengthTag, TimeZone, Timing,
};
pub use sdp_offer_answer::{AnswerOptions, CodecInfo, NegotiationError, OfferAnswerEngine};
pub use security::{
    parse_security_client, parse_security_server, parse_security_verify, SecurityClientHeader,
    SecurityEntry, SecurityMechanism, SecurityServerHeader, SecurityVerifyHeader,
};
pub use service_route::{PathHeader, ServiceRouteHeader};
pub use session_timer::{MinSessionExpires, RefresherRole, SessionExpires};
pub use sip_etag::{SipETagHeader, SipIfMatchHeader};
pub use sipfrag::{SipFrag, StartLine};
pub use subject::SubjectHeader;
pub use tel_uri::TelUri;
pub use token_list::{AllowHeader, SupportedHeader, TokenList};
pub use uri::{SipUri, Uri};
pub use version::SipVersion;
pub use via::ViaHeader;
pub use watcher_info::{
    parse_watcherinfo, Watcher, WatcherEvent, WatcherList, WatcherStatus, WatcherinfoDocument,
};
