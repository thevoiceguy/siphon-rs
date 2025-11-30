# Changelog

All notable changes to this project will be documented in this file.

## Unreleased
11/30/2025

- Add async trait support for registrar/auth storage (`AsyncLocationStore`, `AsyncCredentialStore`) with adapters for sync/async interop.
- Extend `BasicRegistrar` and `DigestAuthenticator` with async handlers to enable non-blocking storage backends.
- Update memory stores to implement both sync and async traits and add Tokio/async-trait dependencies where required.
