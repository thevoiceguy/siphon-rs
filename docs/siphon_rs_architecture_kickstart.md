# SIPHON‑RS: A modern, full‑featured SIP stack in Rust

> Goal: Rebuild SIPHON in Rust as a production‑grade, RFC‑compliant SIP stack (client, server, proxy) with clear layering, async I/O, strong test coverage, and pluggable modules.

---

## 1) Scope & Compliance

**Core RFCs (MVP → GA)**
- **RFC 3261** – SIP: INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, INFO, UPDATE, MESSAGE
- **RFC 3262** – PRACK (Provisional Responses)
- **RFC 3263** – Locating SIP Servers (NAPTR/SRV/A/AAAA, transport selection)
- **RFC 3264** – Offer/Answer model (SDP handling via RFC 4566)
- **RFC 3581** – rport
- **RFC 4028** – Session Timers
- **RFC 3311** – UPDATE method
- **RFC 3265 → RFC 6665** – SUBSCRIBE/NOTIFY (event framework update)
- **RFC 3515** – REFER (attended/unattended transfer)
- **RFC 3903** – PUBLISH
- **RFC 4474.1 / RFC 8224** – STIR (stretch target; post‑GA)
- **RFC 5626/5627** – Outbound keep‑alive & GRUU
- **RFC 5923** – Connection Reuse
- **RFC 7616/7617** – HTTP‑Auth Digest (MD5/SHA‑256) & Basic (for test)
- **RFC 5764 / 8261** – DTLS‑SRTP (coordination via SDP; media out of scope but ensure signaling support)
- **RFC 7118** – SIP over WebSocket (post‑MVP)

**Transports**
- UDP, TCP, TLS (SIPS), (post‑MVP: WS/WSS per RFC 7118)
- IPv4/IPv6, Happy‑Eyeballs where appropriate

**Non‑Goals (initially)**
- Full B2BUA media anchoring (provide hooks, not RTP engine)
- Full presence/xcap stack (can be added later via features)

---

## 2) Architecture Overview (Layered)

```
+-----------------------------------------------------------+
| Applications / TUs: UAC, UAS, Proxy, Registrar, B2BUA*    |
+----------------------------+------------------------------+
| Dialog Layer               |  Subscription/Notify Layer   |
+----------------------------+------------------------------+
|     Transaction Layer (Client/Server state machines)      |
+-----------------------------------------------------------+
|     Core: Parsing, Message model, Routing, Timers         |
+-----------------------------------------------------------+
|     Transport: UDP/TCP/TLS/WS + DNS (NAPTR/SRV/A/AAAA)    |
+-----------------------------------------------------------+
```

- **Transport**: async sockets (Tokio), TLS via rustls, WS via tokio‑tungstenite (later). DNS via trust‑dns‑resolver. Connection reuse & keepalive.
- **Core**: immutable message model, header codecs, URI parser, loose/tight routing, Via management, branch params, CSeq, Max‑Forwards, Record‑Route/Route.
- **Transactions**: RFC 3261 state machines + timers (T1, T2, T4, A/B/C/D/E/F/K, etc.). Retransmissions, 100rel (PRACK).
- **Dialogs**: Early/confirmed dialogs, route sets, target refresh (re‑INVITE/UPDATE), session timer maintenance.
- **Services**: Registrar + Location (in‑mem trait + pluggable layers: Redis, Postgres). Authentication (Digest 7616), authorization hooks.
- **Extensions**: REFER, SUB/NOT, PUBLISH as feature‑gated crates.
- **Observability**: tracing + metrics (OpenTelemetry), structured spans (transaction/dialog IDs).

---

## 3) Workspace Layout

```
/siphon-rs
  Cargo.toml           # [workspace]
  /crates
    sip-core          # Message types, headers, parsing, utilities
    sip-parse         # Lexer/Parser (nom-based), codecs
    sip-transport     # UDP/TCP/TLS (+WS later), connection manager
    sip-dns           # NAPTR/SRV resolution, transport policy
    sip-transaction   # Client/Server transactions + timers
    sip-dialog        # Dialog state machine, target refresh
    sip-auth          # Digest (RFC 7616/7617)
    sip-registrar     # REGISTER handling, location service
    sip-proxy         # Stateful/stateless proxy logic
    sip-uas           # UAS helpers (INVITE server, etc.)
    sip-uac           # UAC helpers (invite client, options pinger)
    sip-sdp           # Thin SDP model (or integrate external crate)
    sip-testkit       # Integration harness, fuzz targets, sipp bindings
  /bins
    siphond           # Example daemon: registrar+proxy
    sipctl            # CLI tool: send, trace, register, options, etc.
```

**Key crates & deps**
- Runtime: `tokio`, `bytes`, `dashmap`, `parking_lot`
- Parsing: `nom`, `atoi`, `itoa`, `percent-encoding`
- TLS: `rustls` + `tokio-rustls`
- DNS: `trust-dns-resolver`
- Observability: `tracing`, `tracing-subscriber`, `opentelemetry`
- Config/serde: `serde`, `serde_json`, `toml`, `figment`
- Testing: `proptest`, `quickcheck`, `cargo-fuzz`

---

## 4) Core Models (sketch)

```rust
// crates/sip-core/src/lib.rs
pub mod method; pub mod uri; pub mod version; pub mod headers; pub mod msg;

pub use method::Method;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipVersion { V2 } // SIP/2.0 only

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine { pub method: Method, pub uri: SipUri, pub version: SipVersion }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine { pub version: SipVersion, pub code: u16, pub reason: SmolStr }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessage { Request(Request), Response(Response) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request { pub start: RequestLine, pub headers: Headers, pub body: Bytes }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response { pub start: StatusLine, pub headers: Headers, pub body: Bytes }
```

```rust
// crates/sip-core/src/method.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method { Invite, Ack, Bye, Cancel, Register, Options, Info, Update, Message, Prack, Refer, Subscribe, Notify, Publish }
```

```rust
// crates/sip-core/src/uri.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipUri {
  pub sips: bool,
  pub user: Option<SmolStr>,
  pub host: SmolStr,
  pub port: Option<u16>,
  pub params: BTreeMap<SmolStr, Option<SmolStr>>,
  pub headers: BTreeMap<SmolStr, SmolStr>,
}
```

```rust
// crates/sip-transaction/src/lib.rs
pub struct TxKey { pub branch: SmolStr, pub method: Method, pub is_server: bool }

pub enum ClientInviteState { Calling, Proceeding, Completed, Terminated, } // RFC 3261 Fig. 5
pub enum ServerInviteState { Proceeding, Completed, Confirmed, Terminated, }

pub struct Transaction { /* timers, transport handle, retransmit state */ }

pub trait TransportTx: Send + Sync {
  fn send(&self, target: &TransportTarget, msg: &SipMessage) -> Result<(), TransportError>;
}
```

**Timers**: wheel or slotting timer for A/B/E/F/K etc. Backed by `tokio::time` + custom scheduler for high volume. Feature flag for high‑perf timer wheel.

---

## 5) Transport & DNS

- **UDP**: stateless receive loop, reply path via source; fragmentation avoidance via Path‑MTU (send <1300 bytes when unsure; or use TCP per 3261 §18.1.1).
- **TCP/TLS**: connection pool keyed by (host, port, transport). `aut` keepalive and connection reuse (RFC 5923). TLS SNI, ALPN none, SIPS semantics.
- **DNS**: NAPTR → SRV → A/AAAA with transport order: TLS > TCP > UDP if SIPS or per rules in 3263. SRV weighting/priority + failover.

---

## 6) Registrar & Location

- `LocationStore` trait (mem/redis/sql backends).
- REGISTER processing (Expires, Contact params, Path support later, Outbound per 5626/5923).
- 200/401/423, Min‑Expires, GRUU (5627) later.

---

## 7) Authentication

- Server challenge (401/407) with `WWW-Authenticate` / `Proxy-Authenticate` using **RFC 7616** (MD5, SHA‑256, qop=auth, auth‑int later).
- Client auth helpers for UAC (nonce, opaque, algorithm, realm, cnonce, nonce‑count).

---

## 8) Dialogs & Session Timers

- Route set, remote target, local/remote CSeq, re‑INVITE/UPDATE target refresh.
- Session‑Expires/Min‑SE with refresher=uac/uas (RFC 4028). Keep‑alive ping (OPTIONS) optional.

---

## 9) Observability & Security

- `tracing` spans: transaction id, dialog id, call‑id, from‑tag/to‑tag.
- Metrics: requests/sec, retransmissions, timer fires, DNS latency, auth failures.
- Rate limiting per source IP, Max‑Forwards validation, malformed parser hardening, fuzz targets on parser and transaction layer.

---

## 10) Testing Strategy

- **Unit**: parser round‑trip, header canonicalization, auth hash vectors.
- **Property**: proptest for URI/header edge cases.
- **Fuzzing**: cargo‑fuzz corpus for parser.
- **Interops**: sipp scenarios; run against Asterisk/FreeSWITCH/Kamailio in CI (Docker compose).

---

## 11) Milestones

**M0 – Skeleton & Parsing (2–3 wks)**
- Workspace, core models, basic parser/serializer, UDP transport, OPTIONS ping UAC demo.

**M1 – Transactions (2–3 wks)**
- Full non‑INVITE + INVITE state machines, timers, retransmits; TCP support.

**M2 – Registrar + Proxy (3–4 wks)**
- REGISTER flows (401/200), in‑mem LocationStore, stateful proxy, rport, 100rel.

**M3 – Dialogs + Session Timers (3–4 wks)**
- Re‑INVITE/UPDATE, Session‑Expires, graceful shutdown, metrics.

**M4 – TLS + DNS NAPTR/SRV (2–3 wks)**
- SIPS, trust‑dns, SRV failover, connection reuse.

**M5 – Extensions (rolling)**
- REFER, SUB/NOT, PUBLISH; Outbound/GRUU; WS/WSS.

---

## 12) Kickstart: Cargo workspace & starter files

**Root `Cargo.toml`**
```toml
[workspace]
members = [
  "crates/sip-core",
  "crates/sip-parse",
  "crates/sip-transport",
  "crates/sip-dns",
  "crates/sip-transaction",
  "crates/sip-dialog",
  "crates/sip-auth",
  "crates/sip-registrar",
  "crates/sip-proxy",
  "crates/sip-uas",
  "crates/sip-uac",
  "crates/sip-sdp",
  "bins/siphond",
  "bins/sipctl",
]
resolver = "2"
```

**`crates/sip-core/Cargo.toml`**
```toml
[package]
name = "sip-core"
version = "0.1.0"
edition = "2021"

[dependencies]
bytes = "1"
smol_str = "0.2"
serde = { version = "1", features = ["derive"] }
```

**`crates/sip-transport/Cargo.toml`**
```toml
[package]
name = "sip-transport"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["net","rt-multi-thread","time"] }
tracing = "0.1"
bytes = "1"
sip-core = { path = "../sip-core" }
```

**UDP receive loop (sketch)**
```rust
// crates/sip-transport/src/udp.rs
pub async fn run_udp(bind: SocketAddr, msg_tx: mpsc::Sender<(SocketAddr, Bytes)>) -> anyhow::Result<()> {
  let socket = UdpSocket::bind(bind).await?;
  let mut buf = [0u8; 2048];
  loop {
    let (n, peer) = socket.recv_from(&mut buf).await?;
    msg_tx.send((peer, Bytes::copy_from_slice(&buf[..n]))).await.ok();
  }
}
```

**Transaction registry (sketch)**
```rust
// crates/sip-transaction/src/registry.rs
pub struct TxRegistry { inner: DashMap<TxKey, Arc<Transaction>> }
impl TxRegistry { pub fn get_or_create(&self, key: TxKey, f: impl FnOnce()->Transaction) -> Arc<Transaction> { /* ... */ } }
```

**Example daemon**
```rust
// bins/siphond/src/main.rs
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt::init();
  // load config, start UDP/TCP listeners, wire parser → transaction → TU
  Ok(())
}
```

---

## 13) Implementation Notes & Edge Cases

- **Parser strictness**: be liberal in what you accept but strict in what you send; retain original header casing where possible but normalize for matching.
- **Branch parameter**: RFC 3261 magic cookie `z9hG4bK` + uniqueness guarantees.
- **ACK handling**: outside transactions for 2xx to INVITE; via dialog layer.
- **Stateless vs Stateful proxy**: configurable; stateless for large floods, stateful to support forking/PRACK/Record‑Route.
- **Forking**: parallel vs sequential; canceling pending branches upon final response.
- **TCP message framing**: CRLF boundaries; use RFC 5626 keepalive (CRLF ping) for NAT.
- **Max‑Forwards**: decrement/483 at zero; loop detection via Via and branch hash.

---

## 14) Next Steps

1. Initialize repo with the workspace and crates above.
2. Implement `sip-parse` minimal: Request/Response start‑line + Via/To/From/Call‑ID/CSeq/Max‑Forwards bodies.
3. Wire UDP transport → parser → stateless OPTIONS UAS (200 OK) to validate loop.
4. Add non‑INVITE client transaction (OPTIONS pinger) → run interop with sipp.

> Ping me with your GitHub org/repo and I’ll tailor the initial commit pack (files + CI + sipp scenarios) to drop in.

