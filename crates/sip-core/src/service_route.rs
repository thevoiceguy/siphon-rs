// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::name_addr::NameAddr;
use crate::Uri;
use std::fmt;

/// RFC 3327 Path header.
///
/// The Path header is used in REGISTER requests to record the sequence of
/// proxies traversed by the request. The registrar stores this information
/// and uses it to build a route set for requests sent to the registered UA.
///
/// # RFC 3327 Overview
///
/// - Path headers record the forward path taken by a REGISTER request
/// - Registrars store Path information with each Contact binding
/// - Requests to the registered UA use the Path as a route set
/// - Multiple Path headers may be present (one per proxy traversed)
/// - Path URIs typically contain the 'lr' (loose routing) parameter
///
/// # Examples
///
/// ```
/// use sip_core::{PathHeader, SipUri, Uri};
///
/// // Single Path entry
/// let proxy_uri = SipUri::parse("sip:proxy.example.com;lr").unwrap();
/// let path = PathHeader::single(Uri::from(proxy_uri));
///
/// // Multiple Path entries
/// let proxy1 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
/// let proxy2 = SipUri::parse("sip:proxy2.example.com;lr").unwrap();
/// let path = PathHeader::from_uris(vec![Uri::from(proxy1), Uri::from(proxy2)]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHeader {
    pub routes: Vec<NameAddr>,
}

impl PathHeader {
    /// Creates a new Path header with the given routes.
    pub fn new(routes: Vec<NameAddr>) -> Self {
        Self { routes }
    }

    /// Creates a Path header with a single route.
    pub fn single(uri: Uri) -> Self {
        Self {
            routes: vec![NameAddr {
                display_name: None,
                uri,
                params: Default::default(),
            }],
        }
    }

    /// Creates a Path header from a list of URIs.
    pub fn from_uris(uris: Vec<Uri>) -> Self {
        Self {
            routes: uris
                .into_iter()
                .map(|uri| NameAddr {
                    display_name: None,
                    uri,
                    params: Default::default(),
                })
                .collect(),
        }
    }

    /// Returns true if the Path header is empty (no routes).
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns the number of routes in the Path header.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Adds a route to the end of the Path header.
    pub fn add_route(&mut self, uri: Uri) {
        self.routes.push(NameAddr {
            display_name: None,
            uri,
            params: Default::default(),
        });
    }

    /// Returns an iterator over the route URIs.
    pub fn uris(&self) -> impl Iterator<Item = &Uri> {
        self.routes.iter().map(|r| &r.uri)
    }

    /// Checks if all routes have the 'lr' (loose routing) parameter.
    ///
    /// Per RFC 3327, Path URIs should typically include the 'lr' parameter
    /// to indicate loose routing support.
    pub fn all_loose_routing(&self) -> bool {
        self.routes
            .iter()
            .all(|r| r.uri.as_sip().map(|sip| sip.params.contains_key("lr")).unwrap_or(false))
    }
}

impl fmt::Display for PathHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, route) in self.routes.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", route.uri.as_str())?;
            for (key, value) in &route.params {
                if let Some(v) = value {
                    write!(f, ";{}={}", key, v)?;
                } else {
                    write!(f, ";{}", key)?;
                }
            }
        }
        Ok(())
    }
}

/// RFC 3608 Service-Route header.
///
/// The Service-Route header is returned in a 200 OK response to REGISTER
/// to inform the UA of a route set that should be used for requests within
/// a dialog or for out-of-dialog requests to this Address-of-Record.
///
/// # RFC 3608 Overview
///
/// - Service-Route is returned by the registrar in 200 OK to REGISTER
/// - Provides a route set for the UA to use for subsequent requests
/// - Used for directing requests through specific proxies/services
/// - Multiple Service-Route headers may be present
/// - Service-Route URIs typically contain the 'lr' parameter
///
/// # Examples
///
/// ```
/// use sip_core::{ServiceRouteHeader, SipUri, Uri};
///
/// // Single Service-Route entry
/// let service_uri = SipUri::parse("sip:service.example.com;lr").unwrap();
/// let sr = ServiceRouteHeader::single(Uri::from(service_uri));
///
/// // Multiple Service-Route entries
/// let service1 = SipUri::parse("sip:service1.example.com;lr").unwrap();
/// let service2 = SipUri::parse("sip:service2.example.com;lr").unwrap();
/// let sr = ServiceRouteHeader::from_uris(vec![Uri::from(service1), Uri::from(service2)]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRouteHeader {
    pub routes: Vec<NameAddr>,
}

impl ServiceRouteHeader {
    /// Creates a new Service-Route header with the given routes.
    pub fn new(routes: Vec<NameAddr>) -> Self {
        Self { routes }
    }

    /// Creates a Service-Route header with a single route.
    pub fn single(uri: Uri) -> Self {
        Self {
            routes: vec![NameAddr {
                display_name: None,
                uri,
                params: Default::default(),
            }],
        }
    }

    /// Creates a Service-Route header from a list of URIs.
    pub fn from_uris(uris: Vec<Uri>) -> Self {
        Self {
            routes: uris
                .into_iter()
                .map(|uri| NameAddr {
                    display_name: None,
                    uri,
                    params: Default::default(),
                })
                .collect(),
        }
    }

    /// Returns true if the Service-Route header is empty (no routes).
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns the number of routes in the Service-Route header.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Adds a route to the end of the Service-Route header.
    pub fn add_route(&mut self, uri: Uri) {
        self.routes.push(NameAddr {
            display_name: None,
            uri,
            params: Default::default(),
        });
    }

    /// Returns an iterator over the route URIs.
    pub fn uris(&self) -> impl Iterator<Item = &Uri> {
        self.routes.iter().map(|r| &r.uri)
    }

    /// Checks if all routes have the 'lr' (loose routing) parameter.
    pub fn all_loose_routing(&self) -> bool {
        self.routes
            .iter()
            .all(|r| r.uri.as_sip().map(|sip| sip.params.contains_key("lr")).unwrap_or(false))
    }
}

impl fmt::Display for ServiceRouteHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, route) in self.routes.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", route.uri.as_str())?;
            for (key, value) in &route.params {
                if let Some(v) = value {
                    write!(f, ";{}={}", key, v)?;
                } else {
                    write!(f, ";{}", key)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SipUri;
    use smol_str::SmolStr;

    #[test]
    fn path_header_single() {
        let uri = SipUri::parse("sip:proxy.example.com;lr").unwrap();
        let path = PathHeader::single(Uri::from(uri));

        assert_eq!(path.len(), 1);
        assert!(!path.is_empty());
        assert_eq!(path.routes[0].uri.as_str(), "sip:proxy.example.com;lr");
    }

    #[test]
    fn path_header_from_uris() {
        let uri1 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:proxy2.example.com;lr").unwrap();
        let path = PathHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);

        assert_eq!(path.len(), 2);
        assert!(!path.is_empty());
        assert_eq!(path.routes[0].uri.as_str(), "sip:proxy1.example.com;lr");
        assert_eq!(path.routes[1].uri.as_str(), "sip:proxy2.example.com;lr");
    }

    #[test]
    fn path_header_add_route() {
        let uri1 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
        let mut path = PathHeader::single(Uri::from(uri1));

        let uri2 = SipUri::parse("sip:proxy2.example.com;lr").unwrap();
        path.add_route(Uri::from(uri2));

        assert_eq!(path.len(), 2);
        assert_eq!(path.routes[1].uri.as_str(), "sip:proxy2.example.com;lr");
    }

    #[test]
    fn path_header_is_empty() {
        let path = PathHeader::new(vec![]);
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
    }

    #[test]
    fn path_header_display() {
        let uri1 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:proxy2.example.com;lr").unwrap();
        let path = PathHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);

        let display = path.to_string();
        assert!(display.contains("sip:proxy1.example.com"));
        assert!(display.contains("sip:proxy2.example.com"));
        assert!(display.contains(", "));
    }

    #[test]
    fn path_header_all_loose_routing() {
        // All routes have lr
        let uri1 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:proxy2.example.com;lr").unwrap();
        let path = PathHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);
        assert!(path.all_loose_routing());

        // One route missing lr
        let uri3 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
        let uri4 = SipUri::parse("sip:proxy2.example.com").unwrap();
        let path2 = PathHeader::from_uris(vec![Uri::from(uri3), Uri::from(uri4)]);
        assert!(!path2.all_loose_routing());
    }

    #[test]
    fn path_header_uris_iterator() {
        let uri1 = SipUri::parse("sip:proxy1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:proxy2.example.com;lr").unwrap();
        let path = PathHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);

        let uris: Vec<&str> = path.uris().map(|u| u.as_str()).collect();
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0], "sip:proxy1.example.com;lr");
        assert_eq!(uris[1], "sip:proxy2.example.com;lr");
    }

    #[test]
    fn service_route_header_single() {
        let uri = SipUri::parse("sip:service.example.com;lr").unwrap();
        let sr = ServiceRouteHeader::single(Uri::from(uri));

        assert_eq!(sr.len(), 1);
        assert!(!sr.is_empty());
        assert_eq!(sr.routes[0].uri.as_str(), "sip:service.example.com;lr");
    }

    #[test]
    fn service_route_header_from_uris() {
        let uri1 = SipUri::parse("sip:service1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:service2.example.com;lr").unwrap();
        let sr = ServiceRouteHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);

        assert_eq!(sr.len(), 2);
        assert!(!sr.is_empty());
        assert_eq!(sr.routes[0].uri.as_str(), "sip:service1.example.com;lr");
        assert_eq!(sr.routes[1].uri.as_str(), "sip:service2.example.com;lr");
    }

    #[test]
    fn service_route_header_add_route() {
        let uri1 = SipUri::parse("sip:service1.example.com;lr").unwrap();
        let mut sr = ServiceRouteHeader::single(Uri::from(uri1));

        let uri2 = SipUri::parse("sip:service2.example.com;lr").unwrap();
        sr.add_route(Uri::from(uri2));

        assert_eq!(sr.len(), 2);
        assert_eq!(sr.routes[1].uri.as_str(), "sip:service2.example.com;lr");
    }

    #[test]
    fn service_route_header_is_empty() {
        let sr = ServiceRouteHeader::new(vec![]);
        assert!(sr.is_empty());
        assert_eq!(sr.len(), 0);
    }

    #[test]
    fn service_route_header_display() {
        let uri1 = SipUri::parse("sip:service1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:service2.example.com;lr").unwrap();
        let sr = ServiceRouteHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);

        let display = sr.to_string();
        assert!(display.contains("sip:service1.example.com"));
        assert!(display.contains("sip:service2.example.com"));
        assert!(display.contains(", "));
    }

    #[test]
    fn service_route_header_all_loose_routing() {
        // All routes have lr
        let uri1 = SipUri::parse("sip:service1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:service2.example.com;lr").unwrap();
        let sr = ServiceRouteHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);
        assert!(sr.all_loose_routing());

        // One route missing lr
        let uri3 = SipUri::parse("sip:service1.example.com;lr").unwrap();
        let uri4 = SipUri::parse("sip:service2.example.com").unwrap();
        let sr2 = ServiceRouteHeader::from_uris(vec![Uri::from(uri3), Uri::from(uri4)]);
        assert!(!sr2.all_loose_routing());
    }

    #[test]
    fn service_route_header_uris_iterator() {
        let uri1 = SipUri::parse("sip:service1.example.com;lr").unwrap();
        let uri2 = SipUri::parse("sip:service2.example.com;lr").unwrap();
        let sr = ServiceRouteHeader::from_uris(vec![Uri::from(uri1), Uri::from(uri2)]);

        let uris: Vec<&str> = sr.uris().map(|u| u.as_str()).collect();
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0], "sip:service1.example.com;lr");
        assert_eq!(uris[1], "sip:service2.example.com;lr");
    }

    #[test]
    fn path_header_display_with_params() {
        let uri = SipUri::parse("sip:proxy.example.com").unwrap();
        let mut path = PathHeader::single(Uri::from(uri));

        // Manually add lr param to the NameAddr
        path.routes[0].params.insert(SmolStr::new("lr"), None);

        let display = path.to_string();
        assert!(display.contains(";lr"));
    }
}
