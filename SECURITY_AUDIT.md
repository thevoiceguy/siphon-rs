# Security Audit: siphon-rs

**Date:** 2026-07-10
**Scope:** All 19 workspace crates + `siphond` binary (~90k lines)
**Method:** Seven parallel deep-dive audits across parser, transport, auth, crypto/identity,
transaction/dialog/registrar, proxy/ratelimit/dns, and UAC/UAS/SDP/HEP. Highest-impact
findings were manually verified against source (marked *verified* below).

## Summary

The codebase is, on the whole, defensively well-written: constant-time auth comparisons,
CSPRNG token generation, bounded Content-Length framing, DoS caps on
parameters/bindings/transactions, and correct dialog-identifier matching are all present.
The real issues cluster in three areas:

1. **One authorization bypass** in the registrar (registration hijack).
2. **A family of remote-triggerable panics** in hand-written body/header sub-parsers.
3. **A set of resource-exhaustion / DoS gaps.**

### Findings at a glance

| # | Severity | Title | Location | Status |
|---|----------|-------|----------|--------|
| 1 | HIGH | Registration hijack via `tel:` / host-only AORs (auth bypass) | `sip-registrar/src/lib.rs:1537,1886` | **Fixed** |
| 2 | HIGH | Pre-auth remote panic in name-addr parsing (`>` before `<`) | `siphond/src/sdp_utils.rs:25` + 5 inline dup sites (`invite.rs`, `bye.rs`) | **Fixed** (all 6 sites) |
| 3 | HIGH | Remote panic: Referred-By quoted-string strip | `sip-core/src/referred_by.rs:424` | **Fixed** |
| 4 | HIGH | Remote panic: PIDF presence body parser | `sip-core/src/presence.rs:496` | **Fixed** |
| 5 | HIGH | Remote panic: watcherinfo body parser | `sip-core/src/watcher_info.rs:796` | **Fixed** |
| 6 | MEDIUM | Nonce replay-state poisoned before password check (on-path DoS) | `sip-auth/src/lib.rs:969` vs `:1304` | Open |
| 7 | MEDIUM | Rate limiter fail-closed lockout | `sip-ratelimit/src/lib.rs:535` | Open |
| 8 | MEDIUM | DNS resolution has no internal-address filtering (SSRF) | `sip-dns/src/lib.rs:403-485` | Open |
| 9 | MEDIUM | Transport handshake/slow-drip DoS | `sip-transport/src/lib.rs:1211,1057,814,1435` | Open |
| 10 | MEDIUM | Registrar AOR auth ignores domain/realm | `sip-registrar/src/lib.rs:1537` | Open |
| 11 | MEDIUM | Forking proxy: no loop detection + missing CANCEL on 6xx | `sip-proxy/src/service.rs:86-195` | Open |
| 12 | MEDIUM | DialogManager exhaustion (no eviction, terminated retained) | `sip-dialog/src/lib.rs:702` | Open |
| 13 | MEDIUM | Insecure-by-default full-uas posture | `siphond/src/config.rs:77` | Open |
| 14 | LOW | Username enumeration (Err vs Ok(false) + timing) | `sip-auth/src/lib.rs:1287` | Open |
| 15 | LOW | sip-identity latent gaps (iat freshness, orig/dest binding, x5u) | `sip-identity/*` | Open |
| 16 | LOW | DNS: uncapped NAPTR fan-out; hostname validation bypass | `sip-dns/src/lib.rs:436,651` | Open |
| 17 | LOW | Proxy: Max-Forwards-exhausted target silently dropped, no 483 | `sip-proxy/src/service.rs:145` | Open |
| 18 | LOW | Server transaction key omits top-Via sent-by | `sip-transaction/src/lib.rs:224` | Open |
| 19 | LOW | InMemoryTransactionStore unbounded (latent) | `sip-transaction/src/storage.rs:82` | Open |
| 20 | LOW | Auth: identical-request replay within self-extending window | `sip-auth/src/lib.rs:490` | Open |

---

## Critical / High

### 1. HIGH — Registration hijack via `tel:` and host-only AORs (auth bypass) *(verified)*

**Location:** `crates/sip-registrar/src/lib.rs:1537` (async handler), `:1886` (sync handler)

The AOR-to-identity check derives the authorized user by splitting the AOR on `@`:

```rust
let aor_user = aor
    .split_once(':')
    .and_then(|(_, rest)| rest.split_once('@'))
    .map(|(user, _)| user);

if let Some(aor_user) = aor_user {
    if !usernames_equal(aor_user, auth_user.as_str()) { /* 403 */ }
}
```

For any AOR without an `@` — every `tel:+1555…` URI and every host-only `sip:example.com` —
`aor_user` is `None`, so the authorization block is skipped entirely. `normalize_aor`
explicitly accepts `tel:` AORs, so this is reachable functionality.

**Attack:** An attacker with valid credentials for any account (e.g. `alice`) sends
`REGISTER` with `To: tel:+15551234567` (a victim's number) and
`Contact: sip:attacker@evil.com`. Auth passes; the identity check is bypassed; the
attacker's contact is bound to the victim's tel AOR. Any call routed to that AOR is
delivered to the attacker.

**Impact:** Cross-account registration hijack / call interception for the entire `tel:` and
host-only AOR namespace.

**Fix:** Reject (or explicitly authorize) any AOR whose identity cannot be matched to the
authenticated user, instead of silently skipping the check.

### 2. HIGH — Pre-auth remote panic in name-addr parsing (`>` before `<`) *(verified, PoC-confirmed)*

**Location:** `bins/siphond/src/sdp_utils.rs:25` (`parse_name_addr_uri`)

```rust
if let Some(start) = value.find('<') {
    let end = value.find('>').unwrap_or(value.len());
    SipUri::parse(&value[start + 1..end]).ok()   // panics when '>' precedes '<'
```

`value.find('>')` scans the whole string, so a value like `From: "x>y" <sip:a@b>` yields
`end < start+1` and the slice panics (`begin <= end`).

**Reachable call sites (all attacker-controlled headers):**
- `handlers/invite.rs:1358` — parses `From` on any INVITE with `Supported: 100rel`
  (PRACK on by default); reached **pre-auth** in the default (auth-off) full-uas/call-server config.
- `handlers/invite.rs:1579` — `From` in the Replaces authorization path.
- `handlers/refer.rs:318,322,541` — `From`, `Contact`, and `Refer-To` in REFER handling.
- Duplicated inline (same bug): `handlers/invite.rs:375,619,637,690` (B2BUA), `handlers/bye.rs:67`.

**Attack:** An unauthenticated attacker sends a single INVITE (`Supported: 100rel`,
`From: "x>y" <sip:a@b>`). The handler task panics.

**Impact:** Handlers run in per-request `tokio::spawn` and the workspace sets no
`panic = "abort"`, so under the default unwind each malicious request aborts only its task —
but the server transaction is left with no response, retransmitting until timeout. Flooding
accumulates orphaned transactions (resource-exhaustion DoS). **Any build compiled with
`panic = "abort"` turns this into a full-process remote crash.**

**Fix:** Search for `>` only within `value[start+1..]`, exactly as the library crates already
do safely — `crates/sip-uas/src/lib.rs:1555` and `crates/sip-uac/src/lib.rs:3306`.

### 3. HIGH — Remote panic in Referred-By param parsing (unguarded quoted-string strip) *(verified, PoC-confirmed)*

**Location:** `crates/sip-core/src/referred_by.rs:424`

```rust
let value = if value.starts_with('"') && value.ends_with('"') {
    &value[1..value.len() - 1]   // slices [1..0] when value is a lone '"'
```

Missing the `&& value.len() >= 2` guard that sibling parsers (`mime.rs:449`, `reason.rs:552`)
have.

**Trigger:** `ReferredByHeader::parse("<sip:a@b>;x=\"")` — a parameter whose value is a single
`"`. Both `starts_with`/`ends_with` are true, so it slices `[1..0]`.

**Reach:** Public parse API for the `Referred-By` header (compact form `b`), used for
attended-transfer REFER processing.

**Fix:** Add `&& value.len() >= 2` (or use `trim_matches('"')`).

### 4. HIGH — Remote panic in PIDF presence body parser (out-of-order tag finds) *(verified, PoC-confirmed)*

**Location:** `crates/sip-core/src/presence.rs:496`

```rust
if let Some(basic_start) = xml.find("<basic>") {
    if let Some(basic_end) = xml.find("</basic>") {
        let status_str = &xml[basic_start + 7..basic_end].trim();  // panics if </basic> precedes <basic>
```

`basic_start` and `basic_end` are independent absolute searches; if `</basic>` appears first,
`basic_end < basic_start + 7`.

**Trigger:** `parse_pidf(r#"<presence entity="x"><tuple id="a"></basic><basic></tuple></presence>"#)`

**Reach:** `pub fn parse_pidf` — entry point for PIDF NOTIFY bodies (presence subscriptions), all untrusted.

**Fix:** Search `</basic>` relative to `basic_start`: `xml[basic_start..].find("</basic>")`.

### 5. HIGH — Remote panic in watcherinfo body parser (unclosed opening tag) *(verified, PoC-confirmed)*

**Location:** `crates/sip-core/src/watcher_info.rs:796`

```rust
if let Some(content_start) = xml.find('>') {
    if let Some(content_end) = xml.find("</watcher>") {
        let uri = xml_unescape(xml[content_start + 1..content_end].trim())?;  // panics if '>' found is inside </watcher>
```

If the opening `<watcher …>` tag has no `>`, the first `>` found is the one inside
`</watcher>`, making `content_end < content_start`.

**Trigger:** `parse_watcherinfo(r#"<watcherinfo version="0" state="full"><watcher-list resource="sip:a@b" package="presence"><watcher id="a" status="active" event="subscribe"</watcher></watcher-list></watcherinfo>"#)`
(note the opening `<watcher …>` is not closed with `>`).

**Reach:** `pub fn parse_watcherinfo` — entry point for RFC 3858 watcherinfo NOTIFY bodies.

**Fix:** Guard `content_end > content_start`, or search `</watcher>` within `xml[content_start..]`.

---

## Medium

### 6. MEDIUM — Nonce replay-state poisoned before password check (on-path DoS) *(verified)*

**Location:** `crates/sip-auth/src/lib.rs:969` vs `:1304`

`prepare_digest` calls `nonce_manager.verify_with_nc(...)`, which unconditionally advances
`last_nc` (`validate_nc_with_request`, line 486), *before* the response digest is compared in
`verify()` (line 1304). An on-path attacker who observes a victim's cleartext nonce can send a
request with a high `nc` and garbage `response`: auth fails (`Ok(false)`), but `last_nc` is
already bumped, so the victim's next legitimate request is rejected as nc-decreasing (replay).

**Impact:** Disruption of legitimate clients by poisoning per-nonce replay state without
knowing the password (on-path required; DoS, not credential bypass).

**Fix:** Only advance replay state after the response digest verifies.
*(The digest comparison itself is correctly constant-time — this is a state-ordering bug.)*

### 7. MEDIUM — Rate limiter fail-closed lockout *(verified)*

**Location:** `crates/sip-ratelimit/src/lib.rs:535`

At `MAX_TRACKED_KEYS` (100k) any *new* key is rejected (`return false`). Keys are
attacker-influenceable (`check_by_ip` on spoofable UDP source, or From/Via-derived auth keys),
so flooding distinct junk keys fills the table and denies all new legitimate clients for up to
the 300s idle window — the DoS-prevention mechanism becomes a DoS vector.

**Fix:** LRU-evict instead of reject, or scope caps per source.

### 8. MEDIUM — DNS resolution has no internal-address filtering (SSRF) *(verified)*

**Location:** `crates/sip-dns/src/lib.rs:403-485` (`resolve_internal`, `lookup_a_aaaa`, `lookup_srv`)

Resolved A/AAAA/SRV targets are returned verbatim — no rejection of loopback
(`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), or RFC1918 ranges — and flow straight
into the UAC send path (`crates/sip-uac/src/integrated.rs:1078`). An attacker controlling DNS
for a destination (or the Request-URI host) can steer the stack at internal hosts (DNS
rebinding, internal SIP-service reach). Partly expected for a SIP resolver, but worth an
optional deny-list.

### 9. MEDIUM — Transport handshake / slow-drip DoS

**Location:** `crates/sip-transport/src/lib.rs:1211` (TLS), `:1057` (WSS), `:814` (WS), `:1435` (read loop)

- Session permits are acquired *before* TLS/WS/WSS handshakes, which have **no timeout** — a
  peer that completes TCP then stalls pins slots indefinitely (handshake slowloris).
- The idle timeout resets on any nonzero read, so a body trickled one byte per ~59s lives
  forever holding up to ~10 MB (`MAX_BODY_SIZE`).
- WS/WSS listeners lack the per-IP cap (`MAX_SESSIONS_PER_IP = 64`) that TCP/TLS enforce, so
  one IP can take all 1024 global slots.

**Fix:** Wrap handshakes in `tokio::time::timeout`; add an overall message-assembly deadline;
mirror the per-IP counter to the WS/WSS accept loops.

*(Note: the Content-Length framing core itself is clean — no attacker-controlled
pre-allocation, `checked_mul`/`checked_add` on length math, hard caps on
header/body/buffer size, duplicate/missing Content-Length rejected.)*

### 10. MEDIUM — Registrar AOR auth ignores domain/realm

**Location:** `crates/sip-registrar/src/lib.rs:1537,1886`

Even for normal `sip:user@host` AORs, only the user-part is compared against the authenticated
username; the host/domain and the digest realm are never checked. In a multi-domain deployment
sharing one location store, `alice`@realm-X can register bindings for
`sip:alice@any-other-domain`. Same-username-different-account takeover is possible where
usernames collide across realms.

### 11. MEDIUM — Forking proxy: no loop detection + missing CANCEL on 6xx

**Location:** `crates/sip-proxy/src/service.rs:86-170` (`start_forking`), `:182-195` (`handle_branch_response`)

The forking service never calls the existing `detect_loop`/`detect_loop_hashed` helpers or
checks Via hop count before forwarding (`prepare_forward` only does Max-Forwards + `add_via`).
Because forking multiplies each hop, a request routed back into the proxy is re-forked —
message-amplification loop bounded only by Max-Forwards. Separately, CANCELs are only generated
for 2xx responses, so a 6xx global failure / Timer-C 408 / transport-error 503 leaves sibling
branches ringing until their own ~32s timeout (violates RFC 3261 §16.7).

### 12. MEDIUM — DialogManager capacity exhaustion / terminated retention

**Location:** `crates/sip-dialog/src/lib.rs:702` (insert), `:551` (terminate), `:767` (cleanup)

`insert` hard-rejects new dialogs at `MAX_CONFIRMED_DIALOGS` (10k) with no eviction (contrast
the transaction manager, which evicts oldest). `terminate()` only flips state; terminated
dialogs occupy the cap until `cleanup_terminated()` is called manually. An attacker completing
many dialogs against an auto-accepting UAS can wedge new-dialog creation.

### 13. MEDIUM — Insecure-by-default full-uas posture

**Location:** `bins/siphond/src/config.rs:77-90`

Defaults are `authentication: false`, `auto_accept_calls/registrations/subscriptions: true`,
`enable_refer: true`. Combined with the documented `0.0.0.0` default binds, `--mode full-uas`
with no `--auth` accepts calls, registrations, and REFER-driven transfers from any source with
no credentials. Mitigated by it being a testing daemon, but a startup warning when auth is off
on a non-loopback bind would help.

---

## Low / Hardening

### 14. LOW — Username enumeration (Err vs Ok(false) + timing)

**Location:** `crates/sip-auth/src/lib.rs:1287` (sync), `:1354` (async)

Unknown user returns `Err` (short-circuit, no hash computed) vs wrong password returns
`Ok(false)` after computing the full digest. A caller that maps `Err` differently gives an
existence oracle; the presence/absence of the digest computation is also a timing side-channel.
**Fix:** Return `Ok(false)` for unknown users and compute a dummy digest to equalize timing.

### 15. LOW — sip-identity latent gaps (crate not yet wired into any caller)

**Location:** `crates/sip-identity/*`

Core ES256 signature and X.509 chain validation are **correct with no bypass** (alg pinned to
exact-case `ES256`, signature genuinely verified via ring/webpki, chain checked to
caller-supplied anchors with validity window). Missing boundary checks a future integrator must
add:
- No `iat` freshness enforcement → PASSporT replay (`passport.rs:81`).
- `orig`/`dest` never bound to the SIP message → caller-ID spoofing with a valid token.
- `x5u` stored with zero validation (no https allow-list, no host check) → SSRF/MITM once a
  fetcher exists (`passport.rs:166`).
- No revocation (CRL/OCSP) consulted.

### 16. LOW — DNS: uncapped NAPTR fan-out; hostname validation bypass

**Location:** `crates/sip-dns/src/lib.rs:436` (NAPTR→SRV), `:651` (`unchecked_new`)

`lookup_naptr` returns every matching record with no cap; `resolve_internal` issues one SRV
query per record (only the final target list is capped) → DNS query amplification. SRV and
A/AAAA-derived targets are built via `DnsTarget::unchecked_new`, skipping the
control-character/length validation applied in `DnsTarget::new`.

### 17. LOW — Proxy: Max-Forwards-exhausted target silently dropped in forking

**Location:** `crates/sip-proxy/src/service.rs:145`

When `check_max_forwards` returns `Err`, the caller swallows it via `if let Ok(...)`, silently
skipping the target. If all targets are exhausted, `start_forking` returns `Ok` with an empty
forward list and the mandated 483 Too Many Hops is never produced.

### 18. LOW — Server transaction matching omits top-Via sent-by

**Location:** `crates/sip-transaction/src/lib.rs:224` (`TransactionKey`)

RFC 3261 §17.2.3 keys server transactions on branch + top-Via sent-by + method; this matches on
branch + method only. Because generated branches are CSPRNG, off-path injection is not
practically exploitable — noting the RFC deviation.

### 19. LOW — InMemoryTransactionStore has no size cap

**Location:** `crates/sip-transaction/src/storage.rs:82`

`put_client`/`put_server` insert into unbounded `DashMap`s with no eviction, unlike the live
`TransactionManager`. Exported but not currently wired into the manager — latent DoS only if an
integrator adopts it directly.

### 20. LOW — Auth: identical-request replay within a self-extending window

**Location:** `crates/sip-auth/src/lib.rs:490`

When `nc == last_nc` and the request hash matches, the request is accepted as a retransmission
and `last_used` is refreshed. A captured authenticated request can be replayed and accepted for
up to `max_request_age` (10s) after the last acceptance; each accepted replay refreshes the
window, walking it forward up to the nonce TTL (300s). Intentional UDP-retransmit
accommodation, but weakens strict replay protection for non-idempotent methods over UDP.

---

## Verified sound (no action needed)

- **Parser core** (`sip-parse` framer, URI/Via/tel/version/header-value parsers): Content-Length
  bounded to 64 MB, body slice bounded, CSeq bounded to 2^31-1, singleton-header dedup,
  folded-line rejection, UTF-8-checked head/body split, `MAX_PARAMS`/`MAX_ROUTES` caps. ASCII-anchored
  slice indices.
- **SDP parser** (`sip-sdp`): `ParseLimits` caps bytes/lines/line-length and per-section attribute
  counts; ports/payloads parse without overflow or panic; no unbounded allocation.
- **Digest comparison path**: constant-time via `subtle::ConstantTimeEq`; nonce validation, nc
  replay protection, opaque/realm/uri/qop all enforced before accept; algorithm pinned; no
  default-allow path; SHA-256 default with MD5 deprecation warning.
- **Randomness**: branch IDs, RSeq, REGISTER To-tags, and nonces all use CSPRNGs.
- **Dialog matching**: requires Call-ID + both tags; off-path in-dialog injection needs the CSPRNG
  local tag.
- **CSeq handling**: `saturating_add`; ACK CSeq must equal INVITE CSeq; monotonic increment with
  jump cap; registrar CSeq bounds-checked.
- **Registrar DoS caps**: `MAX_BINDINGS_PER_AOR` (20), `MAX_TOTAL_BINDINGS` (100k), expiry
  clamping, wildcard requires `Expires: 0` and sole Contact.
- **REFER handling** (`siphond`): strips URI-headers from `Refer-To` (§19.1.5), real SSRF filter
  blocks loopback/RFC1918/link-local/multicast, bounds-safe percent-decode, Replaces requires
  both tags and authorizes the initiator against dialog participants.
- **Client TLS config** (`siphond`): proper `webpki_roots` verification, no `dangerous()` override.
- **HEP** (`sip-hep`): emit-only, no untrusted-packet parser; payload truncation and bounds-safe
  Call-ID extraction.
- **CANCEL matching**: correctly compares Call-ID/From-tag/CSeq/Request-URI, ignores To-tag per
  §9.2.

---

## Recommended remediation priority

1. **#1 registrar `tel:`/host-only AOR bypass** — real cross-account hijack in supported functionality.
2. **#2–#5 remote panics** — all one-line-class fixes, all reachable from unauthenticated network
   input; #2 is pre-auth in the default config.
3. **DoS-hardening cluster** (#6–#9, #12).
4. **DNS / proxy items** (#8, #11, #16, #17) and remaining low-severity hardening.
