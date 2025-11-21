# SIPHON-RS (alpha)

A modern Rust reimplementation of the SIPHON SIP stack. This starter repo compiles and runs a minimal UDP **OPTIONS** UAS that replies `200 OK`. 
It provides a clean workspace layout you can extend into a full RFC 3261 stack (transactions, dialogs, registrar, proxy, etc.).

## Quick start

```bash
# build
cargo build

# run example daemon listening on 0.0.0.0:5060/udp
cargo run -p siphond -- --bind 0.0.0.0:5060

# test with netcat or sipp
printf 'OPTIONS sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKtest\r\nFrom: <sip:me@localhost>;tag=abc\r\nTo: <sip:you@localhost>\r\nCall-ID: 1234@localhost\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n' | nc -u -w1 127.0.0.1 5060
```

You should see a `200 OK` response returned to the sender.

> This is intentionally small but production-minded (Tokio, structured logging hooks). Extend it by filling in crates for parsing, transactions, dialogs, registrar, etc.

## Workspace layout

```
/crates
  /sip-core        # core types shared across crates
  /sip-parse       # very small header extractor + method detector (placeholder for full parser)
  /sip-transport   # UDP transport utility (placeholder for full transport layer)
/bins
  /siphond         # example daemon: answers OPTIONS with 200 OK over UDP
```

## License
MIT
