# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Mutual TLS for SIP over TLS: client certificates, server-side verification, and peer
  identity on the transport context** ([#129](https://github.com/thevoiceguy/siphon-rs/issues/129)).
  A SIP peer that reaches a listener over mTLS can now be *identified* by the transaction
  user rather than merely encrypted to: the connection proves who is calling before a single
  SIP message is read, which is what a trunk INVITE that bypasses per-user checks (PIN, lock,
  capacity) needs.
  - `sip-transport` (feature `tls`): new `mtls` module. **Server side** —
    `load_rustls_server_config_with_client_auth(cert, key, client_ca, mode)` builds a
    `ServerConfig` that requests a client certificate and verifies it against a PEM CA bundle
    (`WebPkiClientVerifier`); `ClientAuthMode::Required` fails the handshake for a peer with
    no certificate, `ClientAuthMode::Optional` admits it (with no identity) while still
    refusing a certificate that does not chain. `load_rustls_server_config` is unchanged and
    still never asks. Composable pieces (`load_cert_chain`, `load_private_key`,
    `load_client_ca_roots`, `client_cert_verifier`, `build_rustls_server_config`) for callers
    that hold parsed material or hot-reload via `ArcSwap`. **Client side** —
    `ClientIdentity::load(cert, key)` + `build_rustls_client_config(roots, Some(identity))`
    produce a `ClientConfig` that presents a certificate on outbound connections; it drops
    into the existing `TlsConfig` / `TlsPool::send_tls` plumbing untouched. Private keys are
    refused unless owner-only readable, the guard the server key always had.
  - `sip-transport`: new `PeerIdentity` (always compiled; parsing behind `tls`) — subject DN,
    Common Name, DNS / URI / IP / e-mail SANs (RFC 5922 §7.1 puts a SIP identity in a `sip:`
    URI SAN, a DNS SAN, or the CN), SHA-256 fingerprint, and the leaf DER. Helpers
    `has_dns_name` (case-insensitive, no wildcards), `has_uri_name` (exact), `names()`. It is
    data, not policy: matching an expected node id against it belongs to the application.
  - `sip-transport`: `InboundPacket::peer_identity()` / `with_peer_identity()`. Stamped on
    every packet from a TLS listener connection whose client certificate verified, from a WSS
    connection likewise, and from an outbound `TlsPool` connection (where it is the *server*
    certificate the dial was verified against, so an in-dialog request coming back down that
    connection is identified too). `None` on UDP/TCP/WS and on a TLS peer that presented
    nothing — presence *is* the verification signal, since rustls only reports a certificate
    it accepted.
  - `sip-transaction`: `TransportContext::peer_identity()` / `with_peer_identity()`; the
    dispatch loop copies it from the packet, so every `UasRequestHandler` callback that takes
    a `ctx` can authorize by it.
  - `siphond`: `--tls-client-ca <PATH>` + `--tls-client-auth optional|required` enable mTLS
    on the SIPS and WSS listeners; `--tls-client-cert` / `--tls-client-key` present an identity
    on outbound TLS. An unloadable CA bundle or a bad mode is fatal regardless of
    `--require-tls` — there is no cleartext fallback for "verify the peer".
  - Tests: `crates/sip-transport/tests/mtls.rs` — an rcgen private CA issues server and
    client certificates; loopback runs cover accepted handshake with the identity (CN, DNS
    SAN, `sip:` URI SAN, fingerprint) arriving on the packet, rejected handshake without a
    certificate under `Required`, rejected certificate from a different CA, `Optional` with
    and without a certificate, the no-client-auth listener unchanged, and the outbound pool
    presenting a client identity while the response carries the server's.
  - New dependency (feature `tls` only): `x509-parser` for subject/SAN extraction off the
    verified leaf; `sha2` (already in the tree via `sip-auth`) for the fingerprint.

  Crate bumps: sip-transport 0.5.0 → 0.6.0 (additive API; the private `InboundPacket` gains a
  field, so struct-literal construction was never possible outside the crate),
  sip-transaction 0.6.0 → 0.7.0 (additive), siphond 0.6.0 → 0.7.0 (new flags).

## [2026-08-25] — workspace release

Crate versions in this release: sip-uas 0.5.0. (sip-core 0.7.7,
sip-transport 0.5.0, sip-dns 0.3.0, sip-transaction 0.6.0,
sip-dialog 0.3.4, sip-uac 0.7.1, sip-auth 0.4.0, sip-registrar 0.3.1,
sip-sdp 0.3.1, sip-observe 0.3.0, sip-ratelimit 0.3.0,
sip-testkit 0.1.1, sip-parse 0.3.4, sip-proxy 0.3.0, sip-hep 0.0.1,
sip-identity 0.3.0, and siphond 0.6.0 are unchanged.)

Breaking changes: **sip-uas 0.5.0** — `UasRequestHandler::on_register`
now takes `ctx: &TransportContext` like `on_invite`/`on_bye`
([#127](https://github.com/thevoiceguy/siphon-rs/pull/127)); trait
implementors add the parameter (the default body ignores it and still
405s). Downstream absorbs this with a one-line signature change per
`on_register` override.

### Changed

- **`sip-uas`: `on_register` receives the `TransportContext`.** A registrar binding
  registrations to their connection (RFC 7118 §5.2 / RFC 5626-lite — a WebSocket client is
  reachable only down the connection it opened) needs the per-connection writer, which lives
  on the `TransportContext` the dispatch loop already holds at the REGISTER arm. First
  consumer: siphon-ai's browser registrar (DEV_PLAN_WebRTC.md Phase 1 §3.2).

## [2026-08-24.1] — workspace release

Crate versions in this release: sip-transport 0.5.0. (sip-core 0.7.7,
sip-dns 0.3.0, sip-transaction 0.6.0, sip-dialog 0.3.4, sip-uac 0.7.1,
sip-uas 0.4.0, sip-auth 0.4.0, sip-registrar 0.3.1, sip-sdp 0.3.1,
sip-observe 0.3.0, sip-ratelimit 0.3.0, sip-testkit 0.1.1, sip-parse 0.3.4,
sip-proxy 0.3.0, sip-hep 0.0.1, sip-identity 0.3.0, and siphond 0.6.0 are
unchanged.)

Breaking changes: none. sip-transport takes a minor bump for additive public
API (#125), all behind the `ws` feature; existing `run_ws` / `run_wss`
signatures are unchanged. The WS idle timeout is a behaviour change for
`ws`-feature consumers only: WS sessions now idle out on the same two-phase
schedule TCP/TLS always had (previously never). Downstream absorbs this by
bumping the tag alone.

### Added

- **`sip-transport`: `Origin` allow-list for the SIP WebSocket listeners (feature `ws`).**
  Browsers stamp every WebSocket upgrade with the opening page's `Origin`; a SIP-over-WSS
  listener is typically dialed only by an operator's own web app, so `WsAcceptPolicy
  { allowed_origins }` turns "any page on the internet can open signalling to this daemon"
  into "only pages we serve can" (the CSWSH class). Empty list (the default, and the old
  behaviour of the unchanged `run_ws` / `run_wss` signatures) = no check; non-empty = the
  header must be present and match ASCII-case-insensitively or the upgrade is refused
  `403 Forbidden` before subprotocol selection. Advisory against non-browser clients (they
  can forge the header) — digest auth remains the real authentication. New entry points:
  `run_ws_with_policy`, `run_wss_with_swappable_config_and_policy`. First consumer:
  siphon-ai's browser/WebRTC plan (`DEV_PLAN_WebRTC.md` Phase 1).

### Fixed

- **`sip-transport`: WS sessions now idle out; previously they never did.** The WS read
  loop applies the same two-phase idle timeout as the TCP/TLS loops (#60): the 60 s
  Slowloris window until the first complete SIP message, the configurable established
  window after ([`set_established_idle_timeout`]). Only SIP traffic in either direction
  resets the timer — WS-native ping/pong is transport liveness, not dialog activity, the
  same way TCP ACKs don't reset the stream loops' timer — so a browser that keeps pinging
  from a dead page still idles out. Also new in tests: a pin on the RFC 7118 §5.2 property
  that a reply written to `InboundPacket::stream` goes back down the same WS connection (a
  browser's Via/Contact addresses are unroutable; this is the only response path that
  works).

## [2026-08-24] — workspace release

Crate versions in this release: sip-identity 0.3.0. (sip-core 0.7.7,
sip-transport 0.4.0, sip-dns 0.3.0, sip-transaction 0.6.0, sip-dialog 0.3.4,
sip-uac 0.7.1, sip-uas 0.4.0, sip-auth 0.4.0, sip-registrar 0.3.1,
sip-sdp 0.3.1, sip-observe 0.3.0, sip-ratelimit 0.3.0, sip-testkit 0.1.1,
sip-parse 0.3.4, sip-proxy 0.3.0, sip-hep 0.0.1, and siphond 0.6.0 are
unchanged.)

Breaking changes: none. sip-identity takes a minor bump for additive public
API (#123), all behind the new off-by-default `sign` feature —
verification-only builds are unchanged. Downstream absorbs this by bumping
the tag alone.

### Added

- **`sip-identity`: PASSporT *signing* (feature `sign`).** The complement to the existing ES256
  verification path: build a SHAKEN (ATIS-1000074) PASSporT from a claim set (`attest`, `orig.tn`,
  `dest.tn`, `iat`, `origid`, `x5u`), sign it ES256 with a P-256 `EcdsaKeyPair`, and get the
  compact-JWS token plus the RFC 8224 `Identity` header value (`<token>;info=<x5u>;alg=ES256;ppt=shaken`).
  It round-trips exactly through `Passport::decode` + `verify_signature` (a test signs, decodes, and
  verifies under the signing key, and confirms a different key fails). Adds no dependency — only
  `ring`'s ECDSA signing, already in the tree. Provider-side only: whether a deployment is *entitled*
  to assert a number (SPC token / STI certificate) is an operating-authority question the crate does
  not decide; a non-authorized gateway MUST NOT present a self-signed PASSporT as attestation. New
  public API: `sign`, `PassportParams`, `SignedPassport`, `SignError` (all behind `sign`).


## [2026-08-21] — workspace release

Crate versions in this release: sip-uac 0.7.1. (sip-core 0.7.7,
sip-transport 0.4.0, sip-dns 0.3.0, sip-transaction 0.6.0, sip-dialog 0.3.4,
sip-uas 0.4.0, sip-auth 0.4.0, sip-identity 0.2.0, sip-registrar 0.3.1,
sip-sdp 0.3.1, sip-observe 0.3.0, sip-ratelimit 0.3.0, sip-testkit 0.1.1,
sip-parse 0.3.4, sip-proxy 0.3.0, sip-hep 0.0.1, and siphond 0.6.0 are
unchanged.)

Breaking changes: none. sip-uac takes a patch bump — both entries are
behaviour corrections behind unchanged signatures. Downstream absorbs this
by bumping the tag alone.

- **Fix: a UAC dialog's local URI is the request's `From` URI, not the client's configured identity** (sip-uac) — closes siphon-ai #549. `process_invite_response` built the confirmed dialog with `self.local_uri`, ignoring the `From` the dialog-forming INVITE actually put on the wire. The two agree for an embedder that always dials as itself, which is why this went unnoticed; they diverge for one that sets a per-call `From` — `create_invite_with_from` exists precisely so it can — and then every in-dialog request built from that dialog (BYE, re-INVITE, REFER) swaps the `From` URI mid-dialog while keeping the tag. RFC 3261 §12.2.1.1 takes the local URI from the dialog-forming request. Peers matching on Call-ID + tags tolerate the mismatch; peers validating the URI answer `481`, and anything correlating by `From` attributes the two halves of one call to different identities. Observed downstream as a B2BUA dialling for a registered AOR: `INVITE From: <sip:1000@pbx>` and `BYE From: <sip:siphon@10.0.0.2>`, same tag.
  * The early placeholder dialogs in `integrated.rs` take the same source, so an in-dialog request built before the 2xx agrees with one built after.
  * Falls back to the configured identity when the request carries no parseable `From`, so a malformed request behaves as it did before rather than losing the dialog.
- **Fix: every request builder stamps `User-Agent`** (sip-uac) — the other half of siphon-ai #549. Roughly half of them did: a capture of one call showed the token on the INVITE and nothing on the ACK, the BYE, the REFER, the INFO, the PRACK, the NOTIFY or the MESSAGE. Builders that delegate (`create_invite`, `create_session_refresh`, `create_bye_with_reason`, `create_reg_subscribe`, `create_message_with_headers`, both PRACK entry points) inherit it from the builder they call; `create_authenticated_request*` still inherit it from the request they re-sign. `create_ack` and `create_notify` push it outside their body branches, so a body-less ACK or NOTIFY carries it too. `configured_user_agent_reaches_every_request_builder` never checked an in-dialog request despite its name; a companion test now does.

## [2026-08-20.1] — workspace release

Crate versions in this release: sip-uac 0.7.0, sip-uas 0.4.0. (sip-core 0.7.7,
sip-transport 0.4.0, sip-dns 0.3.0, sip-transaction 0.6.0, sip-dialog 0.3.4,
sip-auth 0.4.0, sip-identity 0.2.0, sip-registrar 0.3.1, sip-sdp 0.3.1,
sip-observe 0.3.0, sip-ratelimit 0.3.0, sip-testkit 0.1.1, sip-parse 0.3.4,
sip-proxy 0.3.0, sip-hep 0.0.1, and siphond 0.6.0 are unchanged.)

The day's second release, under the same-day counter rule in RELEASING.md.

Breaking changes: `IntegratedUACBuilder::local_uri` / `contact_uri` and
`IntegratedUASBuilder::local_uri` / `contact_uri` now return `Result<Self>`
(#119). Callers add `?`, or `.unwrap()` in tests — the same shape as
`local_addr` / `public_addr` on the same builders, which have always been
fallible.

- **Fix: the integrated builders' `local_uri` / `contact_uri` report a parse failure instead of discarding it** (sip-uac, sip-uas) — closes #118. Both setters parsed with `SipUri::parse(...).ok()`, so a rejected URI became indistinguishable from an unset one and the caller had no way to learn it had been dropped. `build()` then either reported `local_uri is required` for a URI that *was* supplied, or — for `contact_uri` — synthesized a default and `unwrap()`ed *that* parse, panicking when it failed too. An ephemeral `:0` bind reaches the panic: `sip:user@127.0.0.1:0` does not parse, so both the caller's Contact and the synthesized one fail. Observed downstream in siphon-ai as `called Result::unwrap() on an Err value: InvalidPort("port cannot be 0")` from `integrated.rs:4117`.
  * **Breaking**: `IntegratedUACBuilder::local_uri` / `contact_uri` and `IntegratedUASBuilder::local_uri` / `contact_uri` now return `Result<Self>`. Callers add `?` (or `.unwrap()` in tests), the same shape as `local_addr` / `public_addr` two methods down, which have always been fallible.
  * The two default-Contact `unwrap()`s become errors naming the address that failed and what to do about it — `build()` already returned `Result`, and an address the caller supplied can fail for reasons the caller can fix.
  * Tests cover both halves in both crates: a setter rejecting a bad URI, and `build()` erroring rather than panicking when the synthesized Contact cannot parse.

## [2026-08-20] — workspace release

Crate versions in this release: sip-uac 0.6.0. (sip-core 0.7.7, sip-transport 0.4.0,
sip-dns 0.3.0, sip-transaction 0.6.0, sip-dialog 0.3.4, sip-auth 0.4.0,
sip-identity 0.2.0, sip-registrar 0.3.1, sip-uas 0.3.0, sip-sdp 0.3.1,
sip-observe 0.3.0, sip-ratelimit 0.3.0, sip-testkit 0.1.1, sip-parse 0.3.4,
sip-proxy 0.3.0, sip-hep 0.0.1, and siphond 0.6.0 are unchanged.)

Breaking changes: `UacError` gains two variants — `UserAgentContainsControlChars`
and `UserAgentTooLong` (#116) — so a downstream `match` over it without a wildcard
arm needs updating. No signature changed; everything else in this release is
additive.

Note for anyone who does *not* configure a product token: sip-uac's
`DEFAULT_USER_AGENT` is derived from the crate version (#113), so it moves from
`sip-uac/0.5.0` to `sip-uac/0.6.0` with this release. Configure
`UACConfig::user_agent` — which now actually works, see below — if you would
rather advertise your own product than the version of a library.

- **Fix: `UACConfig::user_agent` now reaches the `User-Agent` header** (sip-uac) — the field existed and was documented as "User-Agent header value", but nothing on the request path read it. All ten request builders in `UserAgentClient` (`create_register`, `create_options`, `create_invite_with_from`, `create_invite_with_body`, `create_reinvite`, `create_update`, `create_publish`, `create_subscribe`, and both unsolicited-NOTIFY variants) pushed the crate constant `DEFAULT_USER_AGENT` directly, so **every embedder advertised `sip-uac/<version>` on the wire no matter what it configured**; the only consumer of the configured value was the SDP session name in `negotiate_answer`. Found downstream in siphon-ai ([#539](https://github.com/thevoiceguy/siphon-ai/issues/539)), where a documented `[sip].user_agent` key could brand responses via `UASConfig` but not requests.
  * `UserAgentClient` gains a `user_agent` field with `with_user_agent` / `set_user_agent` / `user_agent()`, mirroring the existing display-name accessors, and `IntegratedUAC::build` seeds it from `UACConfig::user_agent`. Unconfigured behaviour is unchanged: the field defaults to `DEFAULT_USER_AGENT`.
  * The token is validated once on the way in — control characters (a header-injection vector, since this string goes out on every request) and a 256-byte cap, matching what `sip-uas` already applies to `Server`. Two new `UacError` variants: `UserAgentContainsControlChars`, `UserAgentTooLong`.
  * New `IntegratedUACBuilder::user_agent(...)`, because reaching for `config()` to set one field is a trap: `config()` replaces the struct wholesale, and `tls_server_name`, `credential_provider`, `sdp_answer_generator`, `sdp_profile` and `local_audio_port` all write into it — so `.config()` after any of them silently discards credentials or a TLS reference identity. `config()`'s doc comment now says so.

- **Docs: `RELEASING.md`** — the versioning model (CalVer tags over per-crate SemVer), tag format including the same-day counter, per-crate bump conventions, the release checklist, and how downstream consumers should pin (#115). Plus a changelog backfill for #113 (#114). No code.

## [2026-08-19] — workspace release

Crate versions in this release: sip-core 0.7.7, sip-transport 0.4.0, sip-dns 0.3.0,
sip-transaction 0.6.0, sip-dialog 0.3.4, sip-auth 0.4.0, sip-identity 0.2.0,
sip-registrar 0.3.1, sip-uas 0.3.0, sip-uac 0.5.0, sip-sdp 0.3.1, sip-observe 0.3.0,
sip-ratelimit 0.3.0, sip-testkit 0.1.1, siphond 0.6.0. (sip-parse 0.3.4, sip-proxy 0.3.0,
and sip-hep 0.0.1 are unchanged.)

Breaking changes: sip-uas response builders (`create_ok`, `create_reliable_provisional`,
`accept_publish`, `create_notify_sipfrag`) now return `Result`, and `on_bye`/`on_cancel`
receive a `TransportContext` (#43); sip-uac's `*_via_flow` methods take a `Flow` struct
instead of separate stream/peer arguments (#57), and `CallHandle::start_session_timer`
no longer takes a `Dialog` (#96); sip-transaction's `ack_received` now returns `bool`
(#102 — source-compatible in statement position); sip-ratelimit's `RateLimitConfig::new`
returns `Result`.

- **Fix: default `User-Agent`/`Server` tokens derive from crate versions at compile time** (sip-uac, sip-uas, siphond) — #113: the defaults were hardcoded at pre-release values (`siphon-rs/0.1.0`, `siphond/0.1`), so un-configured deployments advertised `0.1` on the wire forever; they are now `env!("CARGO_PKG_VERSION")`-derived (`sip-uac/0.5.0`, `sip-uas/0.3.0`, `siphond/0.6.0`) via a shared `sip_uac::DEFAULT_USER_AGENT` constant.

- **Change: `IntegratedUAC`'s per-transaction chatter drops to `debug!`** (sip-uac) — closes #108 (at `info` the log volume tracked request rate rather than anything an operator chose):
  * Four sites fired once per client transaction: the transaction start, the authenticated-retry start, and `on_final` in **both** `InviteTransactionUser` and `SimpleTransactionUser`. The precedent was already in the file — `on_provisional`, the sibling method handling the same class of event, has always been `debug!`. A 180 was debug and a 200 was info for the same "a response arrived on the transaction I started" mechanic.
  * Measured downstream at `RUST_LOG=info`: **~13,100 client transactions produced 52,568 lines from these four statements alone** — four per REGISTER refresh cycle, ~750 lines/s at a sustained 566 transactions/s, and a 20 MB log in 70 s of driving. The cost lands hardest on someone who turns `info` on to investigate a live problem, which is when per-request logging is least affordable.
  * A per-transaction signal at `info` is not lost: `TransactionMetrics` already records starts, completions, outcomes and durations, which is the right home for something that scales with traffic.
  * All four gain structured fields (`branch`, `method`, `attempt`, `code`) in place of positional format strings; `on_provisional`'s message is restyled to match the `on_final` beside it. Levels and formatting only — no behaviour change.

- **Change: the expected first digest challenge logs at `debug!`, not `warn!`** (sip-uac) — closes #107 (a registered node emitted one WARN per registration refresh forever):
  * `IntegratedUAC` warned whenever a `401`/`407` arrived and `auto_retry_auth` was set. That is the first leg of RFC 3261 §22 working exactly as specified — the registrar is *supposed* to challenge, the stack answers immediately, and the request succeeds. Nothing happened that an operator can act on.
  * Measured downstream on a node registering with a 120 s granted expiry (refresh once a minute): **~1,440 WARNs/day on an idle, healthy box**, 361 of them in a 6-hour window. A permanent non-zero baseline is what makes warn-level alerting useless.
  * The two genuinely abnormal auth outcomes in the same function keep their `warn!` — `auth still rejected; retrying with refreshed credentials` and `auth retry limit reached; returning last challenge to caller`. Those fire when credentials or nonces really are wrong; this one fired when everything was right.
  * Now `debug!` with structured fields (`code`, `method`) rather than a positional format string. No behaviour change: the retry path and `max_auth_retries` accounting are untouched.

- **Fix: `ack_received` reports whether it absorbed the ACK** (sip-transaction) — closes #101 (the caller could not tell a hop-by-hop ACK from one the transaction user must see, so ACK dispatch had to guess):
  * `TransactionManager::ack_received` took a key, silently no-op'd on a miss and returned `()`. RFC 3261 §17.2.1 makes the distinction it was swallowing load-bearing: an ACK for a **non-2xx** final is absorbed by the completed INVITE server transaction and must never reach the transaction user, while an ACK for a **2xx** is end-to-end and the TU is the only layer that can handle it — it carries the answer to a delayed offer, among other things.
  * The manager already knew which was which and simply did not say. `send_final` terminates the server transaction as it sends a 2xx (`fsm.rs`, `ServerInviteState::Terminated` plus a `Terminate` action that removes the entry), and leaves it `Completed` for a non-2xx. So **"matched an entry" is exactly "ACK to a non-2xx"** — the signal is precise, needs no new state, and only had to be returned.
  * `ack_received` now returns `bool`: `true` when the ACK was absorbed (do not dispatch), `false` when nothing matched (an ACK to a 2xx, or a stray). `ServerTransactionHandle::ack_received` forwards it. **Source-compatible** — every call site uses it in statement position, and it is deliberately not `#[must_use]`, so existing callers keep compiling and can adopt the signal when they choose.
  * Found from downstream siphon-ai#497, which had to dispatch *every* ACK to reach the 2xx population and consequently fed the absorbed ones to `IntegratedUAS`, where they resolve to no dialog and draw a `warn!("Received ACK for unknown dialog")` — measured at roughly 660/day on a public-facing node, one per scanner INVITE rejected with a `403` and then ACKed, plus a dialog-manager lock and a task spawn for each. Nothing was broken by it: absorption itself is unaffected, since the embedder calls `ack_received` either way.
  * Regression tests: `ack_for_a_non_2xx_reports_that_it_was_absorbed`, `ack_after_a_2xx_reports_that_nothing_absorbed_it` and `ack_matching_no_transaction_reports_that_nothing_absorbed_it`. The first two are mutually discriminating, so an implementation that returns a constant fails one of them.
  * `siphond` is **deliberately left dispatching no ACKs**. It handles them inline (proxy forwarding, the B2BUA bridge) and routes everything else through its own dispatcher, which has no ACK handler and answers `501` to unknown methods — and an ACK must never draw a response (RFC 3261 §17.1.1.3). Its unconditional `return` is now commented as the deliberate choice it is rather than an oversight.

- **Fix: a session timer that has given up now says so** (sip-uac) — closes #93 (refresh failures retried forever with no signal, so a consumer believed a dead session was healthy):
  * The refresh loop only `warn!`'d on failure and kept ticking at the same cadence. Against a peer that had gone away it retried until the task was dropped, and the owner of the `CallHandle` had no way to learn that nothing was keeping the session alive — the one guarantee the timer exists to provide.
  * New `CallHandle::session_timer_state()` returns a `watch::Receiver<SessionTimerState>`: `Idle`, `Healthy { last_refresh }`, `Failing { consecutive }`, or `Stopped { reason }` (`DialogGone`, `Exhausted { consecutive }`, `Cancelled`). `stop_session_timer` publishes `Cancelled`, so a consumer watching the channel sees every way the timer can end.
  * **`408`/`481` is terminal on the first occurrence**, whatever the failure threshold: the peer has said the dialog does not exist and no number of retries brings it back (RFC 3261 §12.2.1.2). Detected by reading the dialog's state — `apply_in_dialog_response` terminates it — rather than by matching error text, which also catches an owner that tore the call down mid-refresh.
  * **A non-2xx response now counts as a failed refresh.** `apply_in_dialog_response` maps `408`/`481` to `Err` but returns `Ok` for every *other* non-2xx, so a `422 Session Interval Too Small` or a `503` that rejected the refresh was previously indistinguishable from success — the session was left to expire while the timer reported health. (Retrying a `422` with the peer's `Min-SE`, per RFC 4028 §7.4, is a separate enhancement; for now it is counted, reported and retried at the same interval.)
  * Otherwise the loop gives up after `UACConfig::max_session_refresh_failures` consecutive failures (default **3**, `0` treated as 1). It deliberately does **not** send a BYE: RFC 4028 §10 suggests the refresher tear the session down, but that is the application's decision — it may prefer to keep media flowing and alert an operator — so the library signals and leaves the choice alone.
  * The loop moved out of the `tokio::spawn` body into `run_session_timer`, so its failure policy is testable without standing up a whole `CallHandle`. Regression tests: `session_timer_stops_immediately_when_the_peer_says_the_dialog_is_gone` and `session_timer_gives_up_after_the_configured_consecutive_failures`. Both fail against the old behaviour — the first reporting `Failing { consecutive: 1 }` forever, the second reporting `Healthy` for a `503`.

- **Fix: session-timer refreshes publish their CSeq to the dialog's owner** (sip-uac) — closes #95 (the owner's next in-dialog request reused a consumed CSeq and a record-routing peer answered `408`):
  * `CallHandle::start_session_timer` took the `Dialog` **by value** and moved it into the spawned task. `Dialog` is `Clone` and `local_cseq` is a plain `u32`, so every refresh advanced the *task's* copy while the caller's stayed frozen at the arming value. The moment the owner sent an in-dialog request of its own — the teardown BYE, a hold/resume re-INVITE, a REFER — it reused a CSeq the peer had already seen, and a proxy that treats the duplicate as a retransmission dropped or `408`'d it. This is the same failure class as siphon-ai#353, reintroduced from inside the library.
  * The `dialog` parameter is **gone** — a breaking signature change, but `CallHandle` already owns the same dialog as `Arc<RwLock<Dialog>>` (the field the transaction user writes the confirmed dialog into), so the parameter was always redundant with better state. The task now re-reads that shared dialog at every tick, so refreshes also pick up advances made by the owner in between, and commits the consumed CSeq back afterwards.
  * The commit happens **on failure too**: `prepare_in_dialog_request` consumes the CSeq when it *builds* the request, so a refresh that times out has still put the number on the wire. Dropping the advance because the response disappointed us would hand the owner a CSeq the peer has already seen — precisely the reuse being fixed.
  * One race is bounded rather than closed, and is documented on the method: an owner that resolves, sends and commits while a refresh is in flight collides on the same CSeq. Serialising the two would mean holding the dialog's write lock across a network round trip (up to Timer B/F, ~32 s) and stalling the very BYE this keeps working, so the commit instead refuses to move the CSeq *backwards* and keeps the owner's newer state.
  * Regression tests: `session_refresh_commits_the_advanced_cseq_to_the_shared_dialog` (two refreshes leave the shared dialog at CSeq 3, not frozen at 1), `session_refresh_commits_the_cseq_even_when_the_refresh_fails` (481 → the advance and the termination both reach the owner) and `session_refresh_commit_never_regresses_the_owners_cseq`. Both wire tests fail in 5 s against the old behaviour — regressing the fix produces no second request at all, so the waits are bounded deliberately.
- **Fix: client transactions that complete normally are reaped** (sip-transaction) — closes #103 (#104): the terminal wait timers (K for non-INVITE, D for INVITE) moved the FSM to `Terminated` but emitted only `Cancel`, and the manager removed entries solely on `Terminate` — so a transaction that failed was reclaimed while one that succeeded stayed in the table forever. Terminated FSMs are now removed on the normal completion path too.

- **Fix: the session refresh reserves its CSeq before the request leaves** (sip-uac) — closes #99 (#100): `refresh_shared_session` cloned the dialog, sent, and committed the CSeq advance only after the response — so for the whole round trip an owner resolving the shared dialog (teardown BYE, hold re-INVITE, REFER) built its request on the number the refresh was already using, two requests on one sequence number (RFC 3261 §12.2.1.1). The CSeq is now reserved on the shared dialog before the refresh goes out.

- **Fix: a doomed session timer stops and tells the owner** (sip-uac) — closes #93 (#98): the refresh loop only `warn!`'d on failure and kept ticking against a peer that had gone away, so the owner believed a dead session was healthy until the peer expired the call. New `CallHandle::session_timer_state()` returns a `watch::Receiver<SessionTimerState>`; on a fatal refresh outcome the timer stops and publishes why (`SessionTimerStop`).

- **Fix: session refreshes are scheduled at Session-Expires/2, not immediately and not at the deadline** (sip-uac) — closes #92: `start_session_timer` used `max(90, se/2)`, which for any Session-Expires under 180 s landed the refresh on (or past) the expiry deadline — at the RFC 4028 minimum of 90 s, exactly on it — and `tokio::time::interval`'s immediate first tick fired a gratuitous re-INVITE/UPDATE the moment the call was answered. The refresh now fires at se/2 per §10, starting half an interval after answer.

- **Fix: the ingress rate-limit warning throttle is keyed by source IP** (sip-transport, sip-ratelimit) — closes #90 (#91): the one-per-second warning throttle was global, so a single noisy peer suppressed drop warnings for every other source. Each source IP now gets its own throttle window, independently per limiter.

- **Fix: per-source ingress rate limits are observable and configurable** (sip-transport, sip-observe, siphond) — closes #88 (#89): every dropped packet/frame is now counted via a new defaulted `TransportMetrics::on_rate_limited` hook, and the limits are configurable at startup via `sip_transport::set_udp_rate_limit()` / `set_stream_rate_limit()` (siphond: `--udp-rate-limit` / `--stream-rate-limit`, 0 disables; default 200/sec).

- **Feat: nonce reuse-window rejection is discriminated from credential failure** (sip-auth) — #87: new `reuse_window_exceeded` / `is_nonce_reuse_expired` APIs let a server distinguish a stale-but-honest client (re-challenge with `stale=true`) from bad credentials, instead of lumping both into one rejection.

- **Fix: the UAC auto-retries INVITE on 401/407 auth challenges** (sip-uac) — #86: `auto_retry_auth` was never read on the INVITE path, so a digest-authenticated gateway's 407 was surfaced as a terminal rejection while REGISTER through the same UAC authenticated fine. A challenged INVITE now resends with credentials (same Call-ID and From tag, CSeq+1, fresh branch, original body) in a new client transaction.

- **Fix: `negotiate_answer` accepts only one m-line per media type** (sip-sdp) — #85: an offer carrying duplicate m-lines of the same type no longer produces an answer accepting both.

- **Fix: configurable TLS certificate name for IP-literal dial targets** (sip-uac) — #79: carrier edges Record-Route themselves as IP literals, so a fresh TLS dial to a route-set hop took its SNI from the connect address and failed verification against the trunk's hostname-only certificate. New `UACConfig::tls_server_name` (builder: `tls_server_name(...)`) carries the trunk hostname, applied centrally in `resolve_target` so every dial path inherits it; it only kicks in for TLS/WSS targets whose SNI would otherwise be an IP literal.

- **Fix: a mid-dialog 2xx no longer replaces the dialog's route set** (sip-dialog) — closes #81 (BYE after a hold/resume on a re-dialed connection drew a `408` and stalled teardown 30 s):
  * `Dialog::update_from_response` refreshed the remote target (correct — RFC 3261 §12.2.1.2 / RFC 5057 target refresh) and then **also** overwrote `route_set` from the response's `Record-Route`, for *any* response. RFC 3261 fixes the route set when the dialog is created; §12.2.1.2 refreshes the target and nothing else. The one exception is §13.2.2.4: a 2xx that confirms an **early** dialog recomputes the set, because RFC 2543 peers mirrored `Record-Route` only in the 2xx. The recompute is now gated on exactly that condition.
  * Live symptom (Twilio Secure Trunking, inbound TLS leg whose connection the carrier had idle-closed, so in-dialog requests take the #73 pool fallback): `hold` → 200, `resume` → 200, then `BYE` → **408 after 30 s**. The carrier's `Record-Route` in a 2xx returned over a connection *we* dialed carries `twnat=sip:<our-ip>:<our-ephemeral-port>` — a NAT hint scoped to that transaction's connection, absent from the original INVITE's `Record-Route` (which arrived on our listener). We adopted it as dialog state, and the BYE carried it back. Teardown stalled 30 s and the CDR's `ended_at` inflated by the same.
  * Isolated three ways before the fix: BYE with no preceding re-INVITE over the **same** fallback connection → 200 in 40 ms (rules out the fallback path); the identical hold/resume/BYE sequence on a **non**-re-dialed connection, where the carrier's `Record-Route` carries no `twnat` → 200 in 35 ms (rules out the sequence). The BYE was otherwise identical in shape to the resume that had just been answered 200 — same tags, Call-ID and R-URI — leaving the route set as the only difference.
  * Regression tests: `confirmed_dialog_keeps_its_route_set_across_a_target_refresh` (the fix) and `early_dialog_recomputes_its_route_set_on_the_confirming_2xx` (guards the §13.2.2.4 behaviour that must stay). The existing suite could not catch this — a response returned over the same connection echoes the same `Record-Route`, so the overwrite was a no-op.

- **Fix: inbound stream sessions tear their writer down on peer close — dead `Flow` sends fail fast and fail over to the pool instead of blackholing until Timer B** (sip-transport, sip-uac) — closes #73 (in-dialog requests written into a CLOSE-WAIT socket; caller stranded on teardown; fd leak):
  * A carrier edge (Twilio Secure Trunking) idle-closes a quiet trunk connection ~2 minutes after the last signaling. The inbound TCP/TLS session's read loop saw the FIN and exited, but its cleanup relied on **sender-drop** to stop the writer task (`drop(writer_tx)` then `writer_handle.await`) — and the `Flow` clones of `writer_tx` held by dialogs live past every call on the connection, so the writer task parked forever, the socket shutdown never ran (permanent CLOSE-WAIT + one leaked fd per idle-closed connection), and — worse — the writer channel stayed **accepting**. Every subsequent `*_via_flow` request on an inbound leg (hold re-INVITE, REFER, and the teardown BYE) was written into the half-closed socket, "succeeded", and died at Timer B ~32 s later: `hold_failed`, CDRs inflated by 32 s, and the caller left in dead air until the carrier's own inactivity cleanup BYE'd us.
  * **Transport (1/3 — fail fast + no leak):** `spawn_tls_session` and `spawn_stream_session` now signal the writer task explicitly when the read side ends. The writer closes its channel (so all `Flow` clones' sends return an error immediately), drains frames already queued (a response racing the FIN still goes out), and the socket is properly shut down — close_notify + fd release on TLS, FIN on TCP. Regression test `flow_sender_fails_fast_and_socket_closes_after_peer_fin` half-closes the client and asserts both our FIN arrives and a retained writer clone starts erroring; verified red on the previous code (the socket never closed).
  * **UAC (2/3 — recover):** the `*_via_flow` senders (`bye_via_flow`, `send_refer_via_flow`, `send_reinvite_via_flow`) now hand the transaction a **second target**: the dialog's route-set edge resolved through the normal pool path (same transport, SNI kept for the TLS pool, no stream). The existing RFC 3263 §4.3 dispatch failover does the rest — flow send fails fast, transaction re-transmits via the pool, the edge is dialable (proven by the carrier's own fresh-connection BYE reaching us, and by #70's cross-SNI pool reuse). The 2xx ACK send likewise falls back to the dispatcher with the stream cleared if the flow dies between the 2xx and the ACK. Regression test `bye_via_flow_falls_back_to_pool_when_flow_is_dead` drives a BYE through a dead flow against a production-shaped dispatcher and asserts the BYE goes out as a pool dial-out to the route-set edge (with SNI, still loose-routed) and completes on 200.
  * **Keepalive (3/3 — avoid needing recovery):** new opt-in `sip_transport::set_stream_keepalive_interval(secs)` (default 0 = off, same knob shape as `set_established_idle_timeout`) makes established inbound sessions emit a keepalive every interval — never HEP-captured — so a quiet call's signaling path survives carrier idle windows (~120 s observed) in the first place. Covered by `established_connection_receives_crlf_keepalives`. (Originally a single CRLF, on the reasoning that it is invisible to any compliant framer per RFC 3261 §7.5; that shipped and made Twilio reap connections *sooner* — the single CRLF is RFC 5626's *pong*. Corrected to the §3.5.1 double-CRLF ping in #80, after which a quiet connection survives indefinitely.)
  * Note: the RST-on-first-write edge from #73 is inherently unfixable for the *first* request (TCP can't know the peer will RST until the write is on the wire) — but with (1) the session now tears down on the write error so the *next* send fails fast and recovers via (2), and (3) keeps the window from opening at all.

- **Fix: the From tag is generated per request, not once per `UserAgentClient`** (sip-uac, sip-dialog) — closes #71 (RFC 3261 §8.1.1.3 / §19.3):
  * `UserAgentClient` generated one `local_tag` at construction and stamped it on **every** outbound out-of-dialog request for the process lifetime — all INVITEs (so every unrelated outbound call carried the identical From tag; confirmed on a live trunk capture: 7 calls / 7 Call-IDs / 1 tag over 86 minutes), plus OPTIONS, SUBSCRIBE, MESSAGE, PUBLISH, and unsolicited NOTIFY. §8.1.1.3 requires a *new* tag per request and §19.3 requires ≥32 bits of randomness per generated tag. Not call-breaking (dialog matching includes the per-call Call-ID), but it weakens §8.2.2.2 merged-request detection, confuses tag-sensitive intermediaries that key leg correlation partly on the From tag, and hands every peer a stable process-lifetime fingerprint.
  * The `local_tag` field is gone. `format_from_header` / `format_from_header_with` mint a fresh `generate_tag()` per call via a new `format_from_header_tagged` core, and the three builders that formatted From inline (`create_unsolicited_notify`, `create_unsolicited_notify_with_state`, `create_options`) call `generate_tag()` directly.
  * **REGISTER is the deliberate exception**: a refresh series already reuses one Call-ID + monotonic CSeq per registrar (§10.2), and the From tag now lives with them — a new `register_from_tags` map (same per-registrar keying and `MAX_REGISTRAR_CALL_IDS` cap as the Call-ID map) keeps one stable tag per registrar so registrars correlating refresh series on (Call-ID, From tag) still see one series. Distinct registrars get distinct tags — previously they shared the process-wide one.
  * The placeholder early-dialog `DialogId` in `IntegratedUAC`'s four INVITE paths read `helper.local_tag`; it is now seeded from the **on-wire request's** From tag (new `request_from_tag`, backed by `sip_dialog::extract_tag`, which is now `pub`) so the early dialog and the emitted INVITE always agree. Confirmed dialogs were already derived from request/response headers and are unaffected. Auth retries copy the original request's headers, so the 401/407 resend keeps the same tag as the challenged request.
  * New regression tests: two `create_invite` calls on one client produce different From tags (red before the fix); OPTIONS/SUBSCRIBE/MESSAGE/NOTIFY tags are pairwise distinct; REGISTER tags are stable per registrar and distinct across registrars.

- **Fix: the TLS pool reuses a peer's connection across SNI for in-dialog requests** (sip-transport) — fixes the **outbound half** of thevoiceguy/siphon-ai#342 (locally terminated outbound calls sent no BYE; hold/transfer re-INVITEs never left the box):
  * `TlsPool::send_tls` keyed connection reuse by `(peer_addr, server_name)`. An outbound call's initial INVITE opens its connection with the request-URI **hostname** as SNI (e.g. `example.pstn.twilio.com`), but an **in-dialog** request (BYE / re-INVITE / REFER) derives its target — and therefore its SNI — from the peer's `Record-Route`, which for a carrier edge is an **IP literal**. So the in-dialog `(addr, "203.0.113.5")` key missed the established `(addr, "example.pstn.twilio.com")` connection, and the pool dialed a **fresh** connection instead. That fails twice over: a carrier edge (Twilio) accepts only the original signaling connection, and the fresh handshake presents the IP as SNI and is rejected by the edge's hostname certificate (`outbound TLS connect … (sni=203.0.113.5)` → transport error). The request never reached the wire, so a locally hung-up outbound call (admin hangup, WS `server_hangup`, drain, controller exit) sent **no BYE** — stranding the callee in dead air until the carrier's session timer (~60 s) — and bot-initiated `hold` failed with `re-INVITE failed`. Inbound legs were unaffected because they reuse their inbound connection explicitly via a `flow`; this is the same #342 symptom on the path that has no flow.
  * On an exact-key miss, `send_tls` now falls back to reusing **any** live connection to the same peer `addr` before opening a new one (RFC 5923 connection reuse). This both rides the connection the dialog was established on (which the peer expects — Twilio's `twnat` Route param even names our original source port) and avoids the doomed fresh IP-SNI handshake. The TCP pool already keys by `addr` alone, so only TLS was affected.
  * New `send_tls_reuses_connection_to_same_addr_across_sni` test seeds a pooled connection under a hostname SNI and asserts a `send_tls` with a mismatched (IP) SNI to the same addr rides the existing connection rather than dialing out. Verified load-bearing (without the fix the request diverts to a fresh connect that fails). It runs under the existing `cargo test --all` because `bins/siphond` enables `sip-transport`'s `tls` feature, so workspace feature unification compiles the TLS path in CI.

- **Fix: in-dialog BYE now carries the dialog route set** (sip-uac) — fixes the transport-layer half of thevoiceguy/siphon-ai#342 (stranded caller / dead air on local call teardown):
  * `IntegratedUAC::bye` and `bye_via_flow` were the only in-dialog senders that did **not** route through `prepare_in_dialog_request`. They emitted the BYE straight from `create_bye` with **no `Route` headers** and the peer's Contact as Request-URI. For a peer we talk to directly (a SIPp UAC, a phone on the same LAN) that is fine — which is why it passed local TCP testing. But a **record-routing proxy** (a carrier edge such as Twilio) cannot correlate a Route-less in-dialog request whose Request-URI is the far side's private media-gateway address, so it answers **`481 Call/Transaction Does Not Exist`** and never relays the BYE to the PSTN. The caller's leg then sits in dead air until the carrier's own session timer fires (~60 s on Twilio). This hit every *local* teardown path (admin force-hangup, WS `server_hangup`, bridge-ended) on a call answered through a record-routing trunk; only the far-end-initiated BYE was unaffected. The condition is a record-routing peer, not the transport per se — TLS merely happens to be how the box reaches Twilio.
  * Both methods now apply the dialog route set via `prepare_in_dialog_request` (loose-route → Route headers + remote-target Request-URI; strict-route → first-route Request-URI + remote target appended), identical to `reinvite` / `send_update` / `send_refer_via_flow`. When the route set is empty (a direct peer) the output is byte-identical to before, so the common non-proxied case is unchanged. The public `&Dialog` signatures are kept — the route set is applied on a clone, since the CSeq bump on a terminal dialog is inconsequential — so no downstream signature churn.
  * `create_bye` also now builds the From header from the **dialog's** local URI (RFC 3261 §12.2.1.1) rather than the UAC's configured `local_uri`. On a UAS-role dialog (an inbound call we answered) those differ: the dialog local URI is the INVITE's To (the dialled AOR), while `self.local_uri` is the daemon's own identity — so the closing BYE had put the wrong AOR in From.
  * New `bye_via_flow_carries_route_set_and_dialog_local_uri` test drives a UAS-role confirmed dialog with a record-route set through `bye_via_flow`, captures the wire BYE, and asserts it carries the proxy `Route` header, keeps the remote target as Request-URI, and sources From from the dialog local URI. Verified load-bearing — fails without the route-set fix (no `Route` header emitted).

- **Fix: the client connection pool now emits SIP HEP on both legs** (sip-transport) — closes the transport-layer half of thevoiceguy/siphon-ai#341:
  * `ConnectionPool` (TCP) and `TlsPool` (TLS) — used for every **outbound** SIP connection (a UAC's INVITE/ACK/BYE and the responses it reads) — emitted no HEP at all. The standalone one-shot `send_tcp`/`send_tls` and the inbound accept loops (`run_tcp`/`run_tls`) all have HEP hooks, but the pool's persistent-connection writer and reader tasks bypassed them entirely (`grep -c sip_hep pool.rs` was 0). So a Homer capture showed the full SIP ladder for calls the box *received* but **nothing** for calls it *originated* — even though RTCP/QoS/CDR chunks for the same outbound call were present, because those don't go through the pool.
  * The pool's shared writer helper (`run_stream_writer_with_keepalive`, used by both TCP and TLS) now emits an `Outbound` chunk on each real send — never on the `\r\n\r\n` keepalive — and both reader tasks emit an `Inbound` chunk per framed response. `IpProto::Tcp` for both TCP and TLS, matching the standalone TLS path's existing convention (TLS runs on TCP; Homer renders transport from the message, not the proto byte). The connection's local socket address is read once before the stream is split, for the HEP `src`.
  * New `tests/pool_hep.rs` drives a real send + reply through the TCP pool with a `sip-hep` emitter installed and asserts both an outbound INVITE (dst=trunk) and an inbound 200 OK (src=trunk) produce a `HepPacket` carrying the Call-ID correlation. Verified load-bearing (fails when the emit is stubbed out).

- **Feat: `IntegratedUACBuilder::dialog_manager` — share a `DialogManager` with the UAS** (sip-uac) — closes #66; unblocks thevoiceguy/siphon-ai#324:
  * `IntegratedUAS` exposes `dialog_manager()` and its doc-comment advises sharing the store with the rest of the stack, but there was no UAC-side input to act on it: `IntegratedUACBuilder` had no setter, and `build()` unconditionally took the helper's private manager. Every `IntegratedUAC` therefore owned a dialog store nothing else could see, so for a daemon that both originates and receives on one endpoint, UAS dispatch resolving an inbound in-dialog request through *its* manager's `find_by_request` always missed. Practical effect: **a BYE from the far end of an outbound call is answered `481 Call/Transaction Does Not Exist` and the call never tears down** — observed against a Twilio Secure trunk, where the call then survived another 60 s until a media-inactivity watchdog killed it, and the daemon's own late BYE died on Timer F against a dialog the peer had already discarded.
  * New `IntegratedUACBuilder::dialog_manager(Arc<DialogManager>)`, matching the existing `transaction_manager` / `dispatcher` / `resolver` injection pattern. Optional — when unset the UAC keeps its private manager, so existing single-role embedders are byte-identical.
  * **The injection points at the inner `UserAgentClient` helper, not just the `IntegratedUAC` handle.** Redirecting only the handle would not have fixed the bug: an outbound call's confirmed dialog is registered by `UserAgentClient::process_invite_response`, which inserts into the *helper's* manager and runs on every INVITE response path — so the dialog would still land somewhere dispatch can't see and the 481 would be unchanged. `build()` assigns the shared store into the helper before cloning the handle, so both halves agree.
  * Four unit tests: the injected store reaches both the handle and the helper (`Arc::ptr_eq` on each); an un-injected build keeps its private store and still agrees with itself; a UAC-created dialog is resolvable by `find_by_request` on the shared manager using an inbound BYE with the peer's tag ordering (the exact lookup UAS dispatch performs); and the same lookup against an unrelated manager still misses, pinning the 481 path so the positive test can't pass for the wrong reason.

- **Feat: `IntegratedUAC::invite_with_from` — per-call From override for outbound INVITE** (sip-uac) — enables trunk-supplied caller-ID (thevoiceguy/siphon-ai#316):
  * `invite` derived the From header entirely from client-global state (`local_uri`, or the stateful `from_uri_override`), so a caller placing calls on behalf of many identities (an outbound-origination service dialing a PSTN trunk) had no per-call way to set From. The only override, `set_from_uri`, mutates the shared helper and is racy under concurrent INVITEs. Any trunk that validates caller-ID (Twilio Secure Trunking, most commercial providers) declines an INVITE whose From isn't an owned/verified number, so outbound calls couldn't complete.
  * New `IntegratedUAC::invite_with_from(target, sdp_body, from_override: Option<SipUri>)` threads the From URI as a **per-call argument**, safe under concurrency. `invite` now delegates to it with `None` (byte-identical behaviour). Backed by `UserAgentClient::create_invite_with_from` and `format_from_header_with`; precedence is per-call override → stateful `from_uri_override` → `local_uri`. The local tag and display name are unchanged, and `create_invite`/`format_from_header` keep their exact prior output. New unit test asserts the override reaches the From while the default path still carries the local identity.

- **Fix: outbound TLS SNI is the URI hostname, not the resolved IP** (sip-dns, sip-uac) — RFC 5922 §4 reference-identity; unblocks Twilio Secure Trunking outbound (thevoiceguy/siphon-ai#312):
  * RFC 3263 resolution of a hostname URI (`sips:…@example.pstn.twilio.com`) with no SRV records goes down the A/AAAA fallback, which built each `DnsTarget` with `host` set to the **resolved IP string** — permanently discarding the original hostname. The UAC's `create_transport_context` then set the TLS `server_name` from `dns_target.host()` (now the IP), so rustls sent **`sni=203.0.113.5`** and attempted cert verification against the IP. Any trunk serving a hostname-scoped cert and keying on SNI (Twilio `*.pstn.twilio.com`) rejects the handshake, so the call never connects (`result="unreachable"` downstream). The connect address was correct; only the TLS reference identity was wrong. The same applied to the explicit-port A/AAAA branch (`sip:host:5061;transport=tls`).
  * `DnsTarget` gains an optional `tls_name` (the pre-resolution domain) and an `sni()` accessor returning `tls_name` when set, else `host`. The two A/AAAA branches in `resolve_internal` now attach the original hostname via `.with_tls_name(host)`; the numeric-IP branch and SRV branch are unchanged (SRV already carries a name in `host`; an IP literal legitimately SNIs the IP). The UAC's four SNI call sites (`create_transport_context` + the flow / re-INVITE / dialog paths) read `dns_target.sni()` instead of `.host()`; the **connect address** still uses `.host()` (the IP), so RFC 3263 address selection is unchanged. Net: connect to the resolved IP, but SNI + cert-verify the original domain.
  * Non-TLS transports are unaffected (`server_name` is only consumed by TLS/WSS; `sni()` still equals `host` for them). New `sip-dns` unit tests cover `sni()` fallback, `with_tls_name` overriding SNI while `host` stays the IP, and the IP-literal URI keeping the IP as SNI.

- **Feat: `IntegratedUAC::send_refer_via_flow` — REFER reuses an inbound TCP/TLS connection; new `Flow` type for the `*_via_flow` family** (sip-uac) — closes #57:
  * `send_refer` only had the DNS-resolve path: it built a fresh `TransportContext` with no stream, so a downstream whose dispatcher is inbound-only could not send REFER on a dialog that arrived over TCP/TLS — the transaction died with a transport error, blocking call transfer on TLS trunks (thevoiceguy/siphon-ai#159). The new `send_refer_via_flow(dialog, refer_to, target_dialog, flow)` mirrors `bye_via_flow`: identical in-dialog preparation (CSeq, route set, Request-URI), `Replaces` support for attended transfer, and the implicit "refer" subscription on 202 — but the request rides the existing connection.
  * **API change:** the connection parameters of the `*_via_flow` methods (`flow_stream: mpsc::Sender<Bytes>`, `peer_addr: SocketAddr`) are now bundled in a `Flow` struct (`Flow::new(stream, peer_addr)`, optional `.with_local_addr(addr)`), taken by `invite_via_flow`, `bye_via_flow`, and the new `send_refer_via_flow`. Call sites change from `uac.bye_via_flow(&dialog, stream, peer)` to `uac.bye_via_flow(&dialog, Flow::new(stream, peer))`.
  * Fixes the `Via` cosmetic nit noted in #57: flow-routed requests auto-filled `Via` from the UAC's configured address, so a BYE leaving over the TLS listener's connection advertised the UDP listener's port (e.g. `Via: SIP/2.0/TLS <ip>:5060`). When `Flow::with_local_addr` names the listener that owns the connection, the `Via` **port** now follows it (host still comes from the `via_advertised`/public/local preference chain, mirroring #56's `Contact` rule). Harmless on the wire — responses ride the connection per RFC 3261 §18.2.2 — but now consistent with the `Contact` the UAS side advertises. Via construction factored into a pure `build_via_value` helper with unit tests; the flow's local address is also stamped on the `TransportContext` (`with_local_addr`), matching the inbound path.
  * The shared transaction tail of `bye_via_flow`/`send_refer_via_flow` factored into one `send_non_invite_via_flow` helper. New round-trip test drives `send_refer_via_flow` against a capturing dispatcher and asserts the REFER carries the flow stream and peer address, `CSeq` advances the dialog, `Via` advertises the flow listener's port, and an injected 202 completes the transaction.

- **Fix: auto-filled `Contact` port follows the receiving listener, not a single global address** (sip-transport, sip-transaction, sip-uas) — RFC 3261 §8.1.1.8 reachability on multi-listener daemons:
  * `IntegratedUAS::auto_fill_headers` built the `Contact` from one configured address (`public_addr`/`local_addr`) for every dialog, so the port was fixed regardless of which listener received the request. With UDP on 5060 and TLS on 5061, a TLS INVITE produced `Contact: <sip:user@<ip>:5060;transport=tls>` — `transport=tls` but the UDP port. The peer (e.g. Twilio's secure trunk) then dialed TLS to `<ip>:5060`, where nothing listens, so the in-dialog ACK and BYE were silently lost; the call stayed up until an RTP/inactivity watchdog tore it down, and the BYE we sent fared no better. Inbound UDP trunks never hit this (port matched), so it was invisible until a TLS trunk was used.
  * `InboundPacket` now carries the receiving listener's local address (`with_local_addr` / `local()`), set at every UDP/TCP/TLS/WS listener spawn, and `TransportContext` carries it through (`with_local_addr` / `local_addr()`). `auto_fill_headers` takes the Contact **port** from that listener (falling back to the configured port when absent — UAC-originated requests, pooled-connection reuse, tests), keeping `port` and `transport` consistent. The advertised **host** still comes from `public_addr`, so NAT/public-IP advertisement is unchanged.
  * Contact construction factored into a pure `build_contact_value` helper with three unit tests: a TLS request on the 5061 listener emits `:5061;transport=tls` even when the configured port is 5060; host tracks the public IP while port tracks the listener; and the no-listener fallback preserves the prior single-listener behaviour. Backward-compatible — single-listener deployments emit byte-identical Contacts.

- **Fix: responses use `Server` instead of `User-Agent`, advertise `Allow`, and OPTIONS skips empty `Supported`** (sip-uas, siphond) — RFC 3261 §20.41 / §20.50 / §13.2.1 / §20.37 polish:
  * `IntegratedUAS::auto_fill_headers` now stamps `Server:` on every outbound response (the UAS-facing header per §20.41) instead of `User-Agent:` (§20.50, which is the UAC-facing request header). The config field name (`UASConfig::user_agent`) stays the same — same value, just emitted under the correct wire name. Carriers tolerated the old behaviour but it confused header-name-strict SIP analysers (sngrep, Wireshark filters keyed on `sip.Server`) and was technically wrong.
  * `auto_fill_headers` also now backfills `Allow:` (from the installed handler's `allow_header()`) on any response that doesn't already carry one. RFC 3261 §13.2.1 — a 2xx response to INVITE SHOULD advertise the methods the UAS supports so the peer knows what mid-dialog requests (re-INVITE, UPDATE, REFER, INFO) are legal without having to follow up with an OPTIONS probe. The OPTIONS-200 and 405 paths already set `Allow:` explicitly upstream of this call, so it's a backstop for the dialog-forming paths that previously stamped no `Allow:` at all.
  * `UserAgentServer::accept_options` no longer emits an empty `Supported:` header. RFC 3261 §20.37 — the field "enumerates all the extensions supported by the UAC or UAS"; an empty enumeration implies nothing and some peers treat the blank value as a parse oddity. Absence is the correct default for a UAS that advertises no extensions; callers that *do* support specific extensions (e.g. `timer`, `100rel`, `path`) should `set_or_push("Supported", ...)` after this call.
  * `siphond` OPTIONS responder (`handlers/options.rs`) updated symmetrically to emit `Server:` instead of `User-Agent:`.
  * New integration test in `crates/sip-uas/tests/dialog_tracking.rs` drives a real INVITE through `IntegratedUAS::dispatch` and asserts the captured 200 OK wire bytes carry `Server:` (not `User-Agent:`) and an `Allow:` listing the baseline methods. Existing `accept_options_advertises_capabilities` test updated to assert `Supported:` is absent.

- **Fix: UAS copies `Record-Route` from request into response** (sip-uas) — RFC 3261 §12.1.1 compliance:
  * `UserAgentServer::create_response` previously dropped every `Record-Route` header on the floor. Dialog-establishing responses (2xx, reliable 1xx) to an INVITE that arrived through one or more loose-route proxies omitted the route set entirely, so subsequent in-dialog requests (ACK / BYE / re-INVITE / REFER) bypassed those proxies and went straight to the UAS's `Contact`. Silent until a strict intermediary was in path: against Twilio's edge (which inserts itself into `Record-Route` on every inbound PSTN call) calls worked because Twilio's edge tolerates direct-to-Contact in-dialog routing, but a stricter SBC or a multi-proxy topology would drop the dialog mid-call.
  * The response builder now copies every `Record-Route` value from the request verbatim — original order, every URI parameter (including unknown ones) preserved exactly. Applied unconditionally in the canonical helper, matching how `Via` / `From` / `To` / `Call-ID` / `CSeq` are handled; harmless on responses where `Record-Route` carries no dialog meaning.
  * Four new unit tests cover: single header copy, multi-header order preservation, absence-in-request → absence-in-response, and verbatim URI/header-parameter preservation.

- **Fix: `create_reliable_provisional` honours dialog's local tag** (sip-uas) — RFC 3262 §3 / RFC 3261 §12.1.1 compliance:
  * `UserAgentServer::create_reliable_provisional` previously let `create_response` stamp a fresh random `To`-tag, ignoring the local tag carried by the passed-in `Dialog`. `PrackValidator` keys its registration off `dialog.id()` (which includes that tag), so the registration tag and the wire tag disagreed by default and any inbound PRACK addressed to the wire tag never matched the registration — 1xx retransmits would never cancel, and the helper would silently leak retransmissions until the peer gave up.
  * The response now copies the `To`-tag from `dialog.id().local_tag()` (via a new internal `replace_to_tag` helper). Test extended to assert the wire tag equals the dialog's local tag.
  * No API change. Callers that already build a `Dialog` via `Dialog::new_uas(req, &response, …)` get the matching tag for free; the contract becomes "the response carries the dialog's tag" rather than "PRACK only works if the dialog was built from this exact response."

- **Fix: 405 / OPTIONS `Allow` header advertises only supported methods** (sip-uas) - RFC 3261 §20.5 / §21.4.6 compliance:
  * `405 Method Not Allowed` and `OPTIONS 200 OK` previously advertised `REGISTER, SUBSCRIBE, NOTIFY, REFER, UPDATE, PRACK, INFO` (plus `MESSAGE, PUBLISH` on OPTIONS) — methods the default `IntegratedUAS` itself rejects with 405. A scanner probing REGISTER received a 405 whose `Allow` listed REGISTER.
  * Added `UasRequestHandler::supported_methods()` and `allow_header()`. The `Allow` header is now derived from the methods the installed handler actually answers (default: `INVITE, ACK, BYE, CANCEL, OPTIONS`). Both trait methods are provided with defaults, so this is a non-breaking addition for existing implementors.
  * `UserAgentServer::accept_options` baseline `Allow` reduced to the honestly-supported set; `IntegratedUAS` overwrites it with the handler's capability set on both the OPTIONS and 405 paths.
  * Handlers that override `on_register` / `on_refer` / `on_update` / etc. to return real responses should override `supported_methods()` to add those methods (see the updated `integrated_server` example).

- **Security hardening: sip-uas crate** - CRLF injection and DoS prevention:
  * Added `UasError` enum with 7 detailed error variants
  * MAX_REASON_PHRASE_LENGTH = 128 bytes (CRLF injection prevention)
  * MAX_SIP_ETAG_LENGTH = 256 bytes (header injection prevention)
  * MAX_BODY_LENGTH = 1 MB (DoS prevention)
  * Control character validation in reason_phrase and sip_etag
  * `create_ok()` now returns `Result<Response, UasError>`
  * `create_reliable_provisional()` now returns `Result<Response, UasError>`
  * `accept_publish()` now returns `Result<Response, UasError>`
  * `create_notify_sipfrag()` now returns `Result<Request, UasError>`
  * Fixed 6 compilation errors in siphond handlers (adapt to Result API)
  * Fixed 7 test call sites to unwrap Result types
  * All 28 sip-uas tests passing

- **Refactor: clean up unused validation constants** - Remove incomplete security features:
  * Removed 7 unused constants from sip-sdp (MAX_URI_LENGTH, MAX_EMAIL_LENGTH, MAX_PHONE_LENGTH, MAX_BANDWIDTH_TYPE_LENGTH, MAX_BANDWIDTH_ENTRIES, MAX_PORT)
  * Removed 2 unused error variants (InvalidPort, InvalidBandwidth)
  * Removed unused validate_port() function
  * Removed unused test helpers (Origin::test, Connection::test)
  * Marked sip-uas future constants with #[allow(dead_code)] (prepared for integrated.rs)
  * Zero build warnings (was 13 warnings)

- **Docs: fix sip-ratelimit doctest** - Update module example after API hardening to unwrap Result from RateLimitConfig::new() before chaining methods. All doctests passing.

- **Refactor: eliminate production unwrap() calls (91 total)** - Replace panic-inducing unwrap/expect with graceful error handling across the codebase:
  * **bins/siphond handlers (16 fixes)**: bye.rs and refer.rs
    - Replaced `.expect()` with `match` for graceful error handling
    - `header.push()` failures: Log warning and skip problematic headers
    - `Request::new()` failures: Log error, clean up state, abort gracefully
    - `Response::new()` failures: Log error, don't send response
    - Zero crashes from bad requests/dialogs in B2BUA mode
  * **crates/sip-core/watcher_info.rs (4 fixes)**:
    - Replaced char iteration `.unwrap()` with `.ok_or_else()` returning XmlParseError
    - `xml_unescape()` and `extract_attribute()` handle invalid UTF-8 gracefully
    - Zero crashes from malformed XML
  * **crates/sip-auth (5 fixes)**:
    - Replaced header push `.unwrap()` with `?` operator in `DigestAuthenticator::challenge()`
    - Clean error propagation for Via, From, To, Call-ID, CSeq header copies
    - Zero crashes from malformed authentication challenges
  * **crates/sip-registrar (41 fixes)**:
    - Replaced 41 header push `.unwrap()` with `?` operator across all response builders
    - Functions: `build_error_response()`, `build_interval_too_brief()`, `handle_register_async()`, `handle_register()`
    - Zero crashes from malformed REGISTER requests
  * **Philosophy**: In a production SIP stack, one bad request must never crash the server and terminate hundreds of active calls
  * All 235+ tests passing after changes

- **Refactor: eliminate panic risk in AnswerOptions::default()** - Complete unwrap/expect elimination effort:
  * **crates/sip-core/sdp_offer_answer.rs (5 fixes)**:
    - Replaced 5 `.expect()` calls with `.ok()` + `.flatten()` pattern
    - audio_codecs: PCMU, PCMA, telephone-event (3 codecs)
    - video_codecs: H264, VP8 (2 codecs)
    - Failed codec creation results in omission from default list, never panic
  * **Result**: Zero panic risk from Default trait implementations
  * **Total production unwrap/expect eliminations: 96 fixes**
  * All 16 sdp_offer_answer tests passing

- Add async trait support for registrar/auth storage (`AsyncLocationStore`, `AsyncCredentialStore`) with adapters for sync/async interop.
- Extend `BasicRegistrar` and `DigestAuthenticator` with async handlers to enable non-blocking storage backends.
- Update memory stores to implement both sync and async traits and add Tokio/async-trait dependencies where required.
- Harden transport metrics labels with strict enums/validation and add a rate-limited tracing metrics implementation.
- Strengthen SIP digest authentication defaults and validation (SHA-256 default, size/nonce bounds, replay window configuration, and parsing hardening) with new tests.
- Harden Privacy header handling (reject `none` mixed with other values, enforce privacy correctly).
- Normalize Reason header protocol/params and support quoted-string unescape in parsing.
- Preserve PIDF document notes, unescape XML entities, and reject invalid basic status values in presence parsing.
- Improve P-Asserted/P-Preferred-Identity parsing for comma-separated identities and parameters.
- Harden reginfo (RFC 3680) XML generation with validation, private fields, and escaping.

## [0.6.26] - sip-core - 2025-12-29

### Breaking Changes
- **BREAKING**: `AuthorizationHeader` fields are now private with accessor methods (`scheme()`, `params()`)
- **BREAKING**: `parse_params()` in `route.rs` now returns `Option<BTreeMap>` instead of `BTreeMap`

### Security
- **AuthorizationHeader (RFC 7235) Complete Rewrite**:
  * Private fields (`scheme`, `params`) - prevents validation bypass
  * MAX_SCHEME_LENGTH = 64 bytes
  * MAX_AUTH_PARAMS = 30 parameters
  * MAX_PARAM_NAME_LENGTH = 64 bytes
  * MAX_PARAM_VALUE_LENGTH = 256 bytes
  * Control character blocking in scheme and parameters
  * Token character validation per RFC 7235
  * Duplicate parameter detection via `add_param()` (rejects)
  * Parser-specific `add_param_overwrite()` for last-value-wins behavior
  * Added `AuthorizationError` enum with 6 detailed error variants
  * 22 comprehensive tests for encapsulation and validation

- **Parameter Bounds in parse_params()**:
  * MAX_PARAMS = 64 limit enforced
  * Returns `None` if parameter count exceeds limit
  * Prevents DoS attacks via unbounded parameter collections
  * Applied to Route, Service-Route, Path header parsing

### Added
- `AuthorizationHeader::new()` - Create with validation
- `AuthorizationHeader::from_raw()` - Parser constructor with full validation
- `AuthorizationHeader::add_param()` - Rejects duplicates (for application code)
- `AuthorizationHeader::add_param_overwrite()` - Allows overwrite (for parsers)
- `AuthorizationHeader::scheme()` - Public getter
- `AuthorizationHeader::params()` - Public getter
- Module-level security constants for validation limits

### Changed
- AuthorizationHeader implementation: 21 lines → 565 lines with comprehensive validation
- `parse_params()` return type changed to `Option<BTreeMap>` for bounds checking
- All AuthorizationHeader construction now validates inputs at parse time (fail-fast)

### Fixed
- Prevented validation bypass via direct field access
- Prevented DoS attacks via excessive parameters

## [0.3.1] - sip-parse - 2025-12-29

### Breaking Changes
- **BREAKING**: `split_quoted_commas()` signature changed to take `max_parts: usize` parameter
- **BREAKING**: `parse_service_route()` now returns `Result<ServiceRouteHeader, RouteError>`
- **BREAKING**: `parse_path()` now returns `Result<PathHeader, RouteError>`
- **BREAKING**: `parse_history_info()` now returns `Result<HistoryInfoHeader, HistoryInfoError>`
- **BREAKING**: `parse_geolocation_header()` signature unchanged but uses new bounded split_quoted_commas
- **BREAKING**: `parse_name_addr_list()` now returns `Option<Vec<NameAddr>>`
- **BREAKING**: Removed `parse_token_list()` - replaced with `TokenList::parse()`

### Security
- **Parameterized Collection Bounds**:
  * `split_quoted_commas()` now takes `max_parts` parameter
  * Type-specific limits: MAX_ROUTES, MAX_GEO_VALUES, MAX_HISTORY_ENTRIES, MAX_PARAMS
  * Returns `None` if bounds exceeded
  * Added unbalanced quote detection (returns `None`)
  * Prevents DoS attacks via excessive comma-separated values

- **parse_params() Bounds**:
  * MAX_PARAMS = 64 limit enforced
  * Returns `None` if parameter count exceeds limit
  * Prevents DoS via unbounded parameter collections

- **parse_name_addr_list() Bounds**:
  * MAX_ROUTES limit enforced with early exit
  * Returns `None` if limit exceeded
  * Prevents DoS via unbounded name-addr lists

- **Token Validation**:
  * RFC 3261 token character validation
  * MAX_TOKENS = 64 limit enforced
  * Validates character set: alphanum + `-` `.` `!` `%` `*` `_` `+` `` ` `` `'` `~`
  * Rejects empty tokens and invalid characters

### Added
- `TokenList::parse()` method replacing standalone `parse_token_list()` function
- Quote balance validation in `split_quoted_commas()`
- Comprehensive error messages in Result types (RouteError, HistoryInfoError, GeolocationError)

### Changed
- `parse_service_route()` returns Result for proper error handling
- `parse_path()` returns Result for proper error handling
- `parse_history_info()` returns Result for proper error handling
- `parse_allow_header()` and `parse_supported_header()` use `TokenList::parse()`
- `split_quoted_commas()` is now parameterized and more flexible
- Better error propagation instead of silent fallbacks to defaults

### Fixed
- Prevented DoS attacks via memory exhaustion
- Added parse-time validation (fail-fast design)
- Enforced RFC-compliant input validation

## [0.6.2] - sip-core

### Breaking Changes
- **BREAKING**: `EventHeader` and `SubscriptionStateHeader` fields are now private with accessor methods
- **BREAKING**: `EventHeader::params` changed from `Vec<(SmolStr, Option<SmolStr>)>` to `BTreeMap<SmolStr, Option<SmolStr>>` for duplicate detection

### Security
- **Event Package Headers (RFC 3265)**:
  * MAX_PACKAGE_LENGTH = 64 bytes (event package names)
  * MAX_ID_LENGTH = 256 bytes (event ID parameter)
  * MAX_PARAMS = 20 (parameters per Event header)
  * MAX_PARAM_NAME_LENGTH = 64 bytes
  * MAX_PARAM_VALUE_LENGTH = 256 bytes
  * MAX_STATE_LENGTH = 32 bytes (subscription state names)
  * MAX_REASON_LENGTH = 128 bytes (termination reason)
  * Control character blocking in all string fields (prevents CRLF injection)
  * Case-insensitive duplicate parameter detection via BTreeMap
  * Parameter name validation (alphanumeric + safe symbols only)
  * Added `EventHeaderError` enum with 12 detailed error variants

### Added
- `EventHeader` accessor methods: `package()`, `id()`, `params()`, `get_param()`
- `SubscriptionStateHeader` accessor methods: `state()`, `expires()`, `retry_after()`, `reason()`
- `SubscriptionState::parse()` method (replaces `from_str()` to avoid confusion with trait)
- `FromStr` trait implementation for `SubscriptionState` (enables `.parse()` syntax)
- Case-insensitive parameter lookup via `get_param()`
- 18 comprehensive security tests covering CRLF injection, oversized inputs, duplicate params, control characters
- Module-level documentation with security guarantees and usage examples

### Changed
- `EventHeader::add_param()` now validates parameter names and values
- Parameter lookup is now case-insensitive for robustness
- Params stored in BTreeMap for automatic deduplication and sorted iteration

### Fixed
- Removed method name conflict: renamed `SubscriptionState::from_str()` to `parse()` to avoid clippy warning

## [0.2.4] - sip-parse

### Changed
- Updated `parse_subscription_state()` to use `SubscriptionState::parse()` instead of deprecated `from_str()` method
- Maintains backward compatibility with existing parser behavior

## [0.6.1] - sip-core

### Added
- Implemented actual RFC 1123 date parsing and formatting using `httpdate` crate
- Added 8 comprehensive validation tests for DateHeader (15 total tests)
- Added strict format validation for day names, months, year range (1970-2100), and time components
- Added `DateHeader::now()` - Create DateHeader from current system time
- Added `DateHeader::from_timestamp()` - Create DateHeader from SystemTime
- Added `DateHeader::is_past()` and `DateHeader::is_future()` - Date comparison methods

### Changed
- `DateHeader` fields are now private with accessor methods (`raw()`, `timestamp()`)
- `DateHeader::new()` now performs comprehensive validation and returns `Result<DateHeader, DateHeaderError>`
- Date parsing now actually works (was stub implementation)
- Strengthened format validation: validates day names (Mon-Sun), months (Jan-Dec), day numbers (01-31), year range, time format (HH:MM:SS)

### Fixed
- Restored missing copyright header
- Fixed placeholder implementations that always returned None/hardcoded values
- Fixed clippy warnings (use range contains syntax)

### Dependencies
- Added `httpdate = "1.0"` for RFC 1123 date parsing/formatting

## [0.2.3] - sip-parse

### Changed
- Updated `parse_date_header()` to use new validated `DateHeader::new()` API
- Falls back to current timestamp if date validation fails (maintains backward compatibility)
- Updated test to use `timestamp()` getter instead of direct field access

### Removed
- Removed duplicate `httpdate` dependency (now handled by sip-core)

## [0.6.0] - sip-core

### Breaking Changes
- **BREAKING**: `CpimMessage` and `CpimHeader` fields are now private with accessor methods
- **BREAKING**: `CpimMessage::new()` now returns `Result<CpimMessage, CpimError>`
- **BREAKING**: All builder methods (`with_from`, `with_to`, `with_subject`, etc.) now return `Result<Self, CpimError>`
- **BREAKING**: `CpimMessage::to_string()` now returns `Result<String, CpimError>`
- **BREAKING**: `CpimHeader::new()` now returns `Result<CpimHeader, CpimError>`
- **BREAKING**: `CpimHeader::with_param()` now returns `Result<Self, CpimError>`
- **BREAKING**: `parse_cpim()` now returns `Result<CpimMessage, CpimError>` instead of `Option<CpimMessage>`

### Security
- **CPIM Message Format (RFC 3862)**:
  * MAX_BODY_SIZE = 10 MB (message body limit)
  * MAX_PARSE_SIZE = 20 MB (input size limit)
  * MAX_HEADERS = 50 (message headers)
  * MAX_CONTENT_HEADERS = 20 (content headers)
  * MAX_PARAMS_PER_HEADER = 10 (parameters per header)
  * MAX_HEADER_NAME_LENGTH = 128 bytes
  * MAX_HEADER_VALUE_LENGTH = 1024 bytes
  * MAX_PARAM_NAME_LENGTH = 64 bytes
  * MAX_PARAM_VALUE_LENGTH = 256 bytes
  * MAX_CONTENT_TYPE_LENGTH = 256 bytes
  * Control character blocking in headers, params, and content type
  * CRLF injection prevention in content headers
  * Invalid character detection (`:`, `;`, `=`, `\`, `"` in header names)
  * Parameter validation with separate checks for names and values
  * Content-Type validation (non-empty, length-limited)
  * Added `CpimError` enum with detailed error variants

### Performance
- Added unchecked builder methods for trusted internal use:
  * `CpimMessage::new_unchecked()` - Skip validation when inputs are known valid
  * `CpimMessage::set_header_unchecked()` - Skip header validation
  * `CpimHeader::new_unchecked()` - Skip value validation
- Added `body_as_str()` method that returns `&str` without cloning (preferred over `body_as_string()`)

### Added
- Comprehensive module-level documentation with security guarantees and error handling examples
- CPIM message accessor methods: `headers()`, `content_type()`, `content_headers()`, `body()`
- CPIM header accessor methods: `value()`, `params()`
- `set_body()` method with validation
- `add_content_header()` method for mutable header addition
- `parse_cpim.rs` fuzz target for parser hardening
- 4 doc tests demonstrating usage patterns and error handling

### Fixed
- Removed redundant CRLF validation (already covered by control character check)
- Optimized header validation to avoid duplicate checks

## [0.5.0] - sip-core

### Breaking Changes
- **BREAKING**: `AcceptContact` and `RejectContact` fields are now private
- **BREAKING**: Builder methods (`with_feature`, `with_q`, `add_feature`) now return `Result<T, CallerPrefsError>`
- **BREAKING**: `score_contacts()` now returns `Result<Vec<ScoredContact>, CallerPrefsError>`
- **BREAKING**: `Capability` fields (`tag`, `value`) are now private
- **BREAKING**: All `Capability` and `CapabilitySet` constructors now return `Result<T, CapabilityError>`
- **BREAKING**: `FeatureValue::to_param_value()` and `from_param_value()` now return `Result`
- **BREAKING**: `CapabilitySet::to_params()` and `from_params()` now return `Result`
- **BREAKING**: `ContactHeader::capabilities()` now returns `Result<CapabilitySet, CapabilityError>`

### Security
- **Caller Preferences (RFC 3841)**:
  * MAX_FEATURES = 50 (features per header)
  * MAX_TOKEN_LIST_SIZE = 20 (tokens in list)
  * MAX_TOKEN_LENGTH = 64 (token length)
  * MAX_STRING_LENGTH = 256 (string values)
  * MAX_CONTACTS = 1024 (contacts to score)
  * MAX_ACCEPT_HEADERS = 32 (Accept-Contact headers)
  * MAX_REJECT_HEADERS = 32 (Reject-Contact headers)
  * Control character rejection in string feature values
  * Finite value validation for q-values and numeric features (no NaN/Infinity)
  * Token validation (alphanumeric + safe symbols only)
  * Added `CallerPrefsError` enum for validation errors
- **Capabilities (RFC 3840)**:
  * MAX_TOKEN_LENGTH = 64 (token length)
  * MAX_STRING_LENGTH = 256 (string value length)
  * MAX_TOKEN_LIST_SIZE = 20 (tokens in token list)
  * Control character rejection in tokens and strings
  * Quote character rejection in strings (prevents injection)
  * Finite value validation for numeric features (no NaN/Infinity)
  * Token validation (alphanumeric + safe symbols only)
  * Quote validation (proper opening/closing)
  * Added `CapabilityError` enum for validation errors
  * New validated constructors: `new_token()`, `new_token_list()`, `new_string()`, `new_numeric()`
  * Added `FeatureValue::validate()` method

### Performance
- Optimized token list matching from O(n²) to O(n) using HashSet (both caller_preferences and capabilities)

### Added
- Caller preferences accessor methods: `features()`, `require()`, `explicit()`, `q()`, `feature_count()`
- Capabilities accessor methods: `tag()`, `value()`
- 12 new security validation tests (4 caller_preferences + 8 capabilities)

## [0.4.0] - sip-core

### Security
- **BREAKING**: `NameAddr::new()` now returns `Result<NameAddr, NameAddrError>` for validated construction
- **BREAKING**: Made `NameAddr` fields private to enforce validation
- Added comprehensive input validation with configurable limits (display name: 256 bytes, params: 64 max, param names: 64 bytes, param values: 256 bytes)
- CRLF injection prevention: Reject `\r`, `\n`, and `\0` characters in display names and parameter values
- Parameter name validation: Only allow safe ASCII alphanumerics and specific symbols
- Case-insensitive duplicate parameter detection
- Export `NameAddrError` for error handling

### Changed
- Updated `addr_headers.rs`, `contact.rs`, `route.rs`, `service_route.rs`, `referred_by.rs` to use validated NameAddr API

## [0.2.2] - sip-parse

### Security
- Added `MAX_CONTENT_LENGTH = 64 MB` limit to prevent DoS attacks via memory exhaustion
- Integer overflow protection for Content-Length parsing (parse as u64, check against usize::MAX)
- Reject oversized Content-Length values that exceed security limit
- Enhanced strict parsing modes (`parse_request_strict`, `parse_response_strict`) with exact Content-Length matching
- Comprehensive test coverage for Content-Length edge cases (overflow, oversized, invalid formats)

### Changed
- `parse_name_addr()` now handles `Result` from `NameAddr::new()` and propagates validation errors


## [0.4.0]

### Added
- Core SIP types, headers, URIs, and message primitives
- RFC 3261 transaction layer with transport-aware timers and metrics
- UDP/TCP/TLS transport with rustls and RFC-compliant TLS shutdown
- RFC 3263 DNS resolution (NAPTR/SRV/A/AAAA)
- Dialog management, subscriptions/NOTIFY, PRACK, REFER/Replaces, and tel URI support
- Digest authentication, registrar, and UAC/UAS helpers
- Observability, metrics, and test utilities
- `siphond` multi-mode SIP testing daemon and examples
