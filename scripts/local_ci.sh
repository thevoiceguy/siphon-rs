#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== Build =="
cargo build --all --verbose

echo "== Test =="
cargo test --all --verbose

echo "== Start siphond =="
cargo run -p siphond -- --mode full-uas --udp-bind 127.0.0.1:5060 &
SIPHOND_PID=$!
sleep 2

cleanup() {
  if kill -0 "$SIPHOND_PID" >/dev/null 2>&1; then
    kill "$SIPHOND_PID" || true
  fi
}
trap cleanup EXIT

echo "== Run SIPp suite =="
cd "$ROOT_DIR/sip-testkit/sipp"
RUN_ALL=1 SCENARIO_DELAY_MS=250 PRECHECK_OPTIONS=1 ./run_scenarios.sh 127.0.0.1 5060
