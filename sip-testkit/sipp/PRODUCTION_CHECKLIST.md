# SIPp Interop Suite Production Readiness Checklist

Use this checklist before treating the SIPp interop suite as production-ready.

## CI & Automation
- [ ] CI job runs `sip-testkit/sipp/run_scenarios.sh` on every change.
- [ ] CI artifacts include `/tmp/sipp_*.log` (or archived logs) for failed runs.
- [ ] CI is deterministic: fixed ports, stable target setup, and seeded IDs if needed.
- [ ] Timeouts and retries are tuned for CI (no flakes at expected load).

## Coverage (Scenarios)
- [ ] Core UAC flows: OPTIONS, INVITE/ACK, INVITE/BYE, REGISTER.
- [ ] Mid-dialog: INFO, UPDATE, re-INVITE, PRACK.
- [ ] SUBSCRIBE/NOTIFY: initial, refresh, terminate.
- [ ] REFER: success + failure paths with NOTIFY.
- [ ] CANCEL: 200 OK to CANCEL + 487 to INVITE (tagged).
- [ ] Session timers: initial + refresh.
- [ ] Negative cases: bad/missing RAck, out-of-dialog INFO/UPDATE.
- [ ] Registrar edge cases: wildcard + multiple contacts.
- [ ] Proxy flows: basic INVITE/BYE routing.
- [ ] Route-set handling (Record-Route → Route headers).
- [ ] Forking behavior (multiple provisional responses).
- [ ] Multi-codec SDP offers.

## Transport & Security
- [ ] UDP core tests pass in CI.
- [ ] TCP core tests pass in CI.
- [ ] TLS core tests pass in CI (with CI-managed certs/keys).
- [ ] IPv6 core tests pass in CI (or explicitly marked unsupported).
- [ ] Auth tests pass: REGISTER and INVITE (401/407 challenges).

## Environment & Reproducibility
- [ ] Test runner documents required server modes (full-uas, registrar, proxy).
- [ ] All scenario inputs are versioned (CSV targets, certs, fixtures).
- [ ] Ports and bindings are configurable via env vars and documented.
- [ ] No local-only assumptions (e.g., hardcoded 127.0.0.1) in CI configs.

## Observability & Triage
- [ ] Logs include SIPp message/err traces for each scenario.
- [ ] Failures produce a concise summary (scenario + expected/received).
- [ ] Server logs are captured and correlated with SIPp logs.

## Performance & Stability
- [ ] Load test results captured (call rate, errors, RTT) in CI or scheduled runs.
- [ ] Soak test runs for extended periods (resource leakage checks).
- [ ] Known flakey scenarios documented with mitigations.

## Release Criteria
- [ ] All required scenarios pass on supported platforms.
- [ ] Known limitations are documented with explicit exclusions.
- [ ] CI pipeline is green with no manual steps.
