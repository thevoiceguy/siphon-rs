# Contributing to siphon-rs

Thank you for your interest in contributing to siphon-rs! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description** of the issue
- **Steps to reproduce** the behavior
- **Expected vs. actual behavior**
- **Environment details** (OS, Rust version, etc.)
- **SIP trace logs** if applicable (use `RUST_LOG=debug`)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear use case** for the enhancement
- **Describe the current behavior** and what you'd like to see changed
- **RFC references** if applicable (e.g., RFC 3261 §X.Y)

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding style** (see below)
3. **Add tests** for new functionality
4. **Update documentation** including:
   - Code comments for non-obvious logic
   - Module-level documentation (`//!`) for new modules
   - README.md if adding user-facing features
5. **Run the test suite** and ensure all tests pass
6. **Run cargo fmt and cargo clippy** before committing
7. **Write clear commit messages** (see below)

## Development Setup

```bash
# Clone your fork
git clone https://github.com/thevoiceguy/siphon-rs.git
cd siphon-rs

# Build the project
cargo build --all

# Run tests
cargo test --all

# Run integration tests with SIPp (requires sip-tester package)
cd sip-testkit/sipp
./run_scenarios.sh 127.0.0.1 5060
```

## Coding Style

### Rust Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Run `cargo fmt --all` before committing
- Run `cargo clippy --all` and address warnings
- Use `cargo check --all` frequently during development

### Documentation

- Add doc comments (`///`) for all public APIs
- Use module-level documentation (`//!`) for crates and major modules
- Include examples in doc comments where helpful
- Reference RFCs when implementing protocol features (e.g., `/// Per RFC 3261 §12.1`)

### Testing

- Write unit tests for business logic
- Add integration tests for protocol flows
- Use property-based testing (proptest) for parsers and state machines
- Ensure tests are deterministic (no flaky tests)

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, tooling

**Examples:**
```
feat(transaction): add Timer K support for INVITE transactions

Implements RFC 3261 §17.1.1.2 Timer K for INVITE client transactions.
Timer K waits for response retransmissions for 5 seconds (T4).

Closes #123

fix(parser): handle tel URIs without phone-context

RFC 3966 requires local numbers to have phone-context parameter.
Updated parser to reject local tel URIs without phone-context.

Fixes #456
```

## RFC Compliance

When implementing SIP features:

1. **Cite the RFC and section** in code comments
2. **Follow the spec precisely** - don't invent protocol extensions
3. **Handle edge cases** mentioned in the RFC
4. **Add tests** that verify RFC compliance
5. **Update documentation** with RFC references

Example:
```rust
/// Creates an ACK request for a 2xx INVITE response.
///
/// Per RFC 3261 §13.2.2.4, ACK for 2xx responses is a separate transaction
/// and uses the route set from the 2xx response.
pub fn create_ack_for_2xx(&self, response: &Response) -> Result<Request> {
    // ...
}
```

## Project Structure

- `crates/sip-core` - Core types (messages, headers, URIs)
- `crates/sip-parse` - Parser and serializer
- `crates/sip-transport` - UDP/TCP/TLS transport
- `crates/sip-transaction` - Transaction layer state machines
- `crates/sip-dialog` - Dialog management
- `crates/sip-auth` - Digest authentication
- `crates/sip-registrar` - REGISTER handling
- `crates/sip-uac` - User Agent Client helpers
- `crates/sip-uas` - User Agent Server helpers
- `crates/sip-proxy` - Proxy primitives
- `bins/siphond` - Multi-mode SIP daemon

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation.

## Performance Considerations

- Use `SmolStr` for small strings (headers, tokens)
- Use `Bytes` for zero-copy message handling
- Prefer `DashMap` over `Arc<Mutex<HashMap>>` for concurrent maps
- Avoid allocations in hot paths (transaction processing)
- Profile changes that affect transaction throughput

## Testing Strategy

### Unit Tests
```bash
cargo test --all
```

### Integration Tests with SIPp
```bash
cd sip-testkit/sipp
RUN_ALL=1 ./run_scenarios.sh 127.0.0.1 5060
```

### Fuzz Testing
```bash
cd fuzz
cargo fuzz run parse_request -- -max_total_time=60
```

### Property Testing
Use proptest for parser and state machine tests. See existing property tests in:
- `crates/sip-transaction/tests/branch_property_tests.rs`
- `crates/sip-core/tests/uri_property_tests.rs`

## Questions?

- Open a [GitHub Discussion](https://github.com/thevoiceguy/siphon-rs/discussions) for questions
- Check [existing issues](https://github.com/thevoiceguy/siphon-rs/issues) for similar topics
- Read the [architecture documentation](CLAUDE.md)

## License

By contributing to siphon-rs, you agree that your contributions will be licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at the user's option.
