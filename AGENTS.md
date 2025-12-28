# Repository Guidelines

## Project Structure & Module Organization
This is a Cargo workspace. Core code lives in `crates/` (e.g., `sip-core`, `sip-parse`, `sip-transaction`, `sip-dialog`), binaries are in `bins/` (notably `bins/siphond`), and integration tooling lives in `sip-testkit/`. Fuzz targets are under `fuzz/`, while RFC and architecture notes are in `docs/` and `CLAUDE.md`. Examples are often in `crates/*/examples/`.

## Build, Test, and Development Commands
Use standard Cargo workflows:
- `cargo build` or `cargo build --all-features` for workspace builds.
- `cargo run -p siphond -- --mode full-uas` to run the SIP daemon in a full UAS mode.
- `cargo test --all` for unit and integration tests.
- `cargo test -p sip-parse` to focus on a crate.
- `cargo clippy --all` and `cargo fmt --all` before committing.
Integration SIPp scenarios live in `sip-testkit/sipp/` and can be run with `./run_scenarios.sh 127.0.0.1 5060`.

## Coding Style & Naming Conventions
Follow the Rust Style Guide and keep formatting via `cargo fmt --all`. Use `cargo clippy --all` and address warnings. Public APIs should have doc comments (`///`), and new modules should include module-level docs (`//!`). Reference RFCs in comments when implementing protocol behavior (e.g., `/// Per RFC 3261 §12.1`). Prefer established types like `SmolStr` and `Bytes` in performance-sensitive code.

## Testing Guidelines
Tests are primarily Rust unit/integration tests via `cargo test`. Property-based testing uses `proptest` for parsers and state machines; follow existing naming patterns in `crates/*/tests/`. SIPp-based integration tests run from `sip-testkit/sipp/`. Keep tests deterministic and add coverage for RFC edge cases.

## Commit & Pull Request Guidelines
Commit messages follow Conventional Commits (e.g., `feat(transaction): add Timer K support`). Pull requests should include a clear description, linked issues, and relevant RFC references. Add tests for new behavior, update docs for user-facing changes, and run `cargo fmt`/`cargo clippy`/`cargo test` before pushing.

## Security & Configuration Notes
Use `RUST_LOG=debug` for SIP trace logs when reporting issues. For security concerns, follow `SECURITY.md`. TLS settings and test notes are documented in `README.md` and `sip-testkit/sipp/README.md`.
