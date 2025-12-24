# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

11/30/2025

- Add async trait support for registrar/auth storage (`AsyncLocationStore`, `AsyncCredentialStore`) with adapters for sync/async interop.
- Extend `BasicRegistrar` and `DigestAuthenticator` with async handlers to enable non-blocking storage backends.
- Update memory stores to implement both sync and async traits and add Tokio/async-trait dependencies where required.


## [0.4.0] - 2025-12-23

### Added
- Core SIP types, headers, URIs, and message primitives
- RFC 3261 transaction layer with transport-aware timers and metrics
- UDP/TCP/TLS transport with rustls and RFC-compliant TLS shutdown
- RFC 3263 DNS resolution (NAPTR/SRV/A/AAAA)
- Dialog management, subscriptions/NOTIFY, PRACK, REFER/Replaces, and tel URI support
- Digest authentication, registrar, and UAC/UAS helpers
- Observability, metrics, and test utilities
- `siphond` multi-mode SIP testing daemon and examples
