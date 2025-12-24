#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${CERT_DIR:-$ROOT_DIR/.certs}"
TLS_CERT="${TLS_CERT:-$CERT_DIR/cert.pem}"
TLS_KEY="${TLS_KEY:-$CERT_DIR/key.pem}"
TLS_CA="${TLS_CA:-$TLS_CERT}"
TLS_HOST="${TLS_HOST:-127.0.0.1}"
TLS_PORT="${TLS_PORT:-5061}"
SIP_BIND="${SIP_BIND:-127.0.0.1:5060}"
SIPP_TARGET_HOST="${SIPP_TARGET_HOST:-127.0.0.1}"
SIPP_TARGET_PORT="${SIPP_TARGET_PORT:-5060}"

echo "== Ensure SIPp is available =="
if ! command -v sipp >/dev/null 2>&1; then
  echo "SIPp is required but not found in PATH."
  exit 1
fi

echo "== Generate self-signed cert (dev only) =="
mkdir -p "$CERT_DIR"
if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_KEY" -out "$TLS_CERT" -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

echo "== Start siphond with TLS =="
cargo run -p siphond -- \
  --mode full-uas \
  --udp-bind "$SIP_BIND" \
  --sips-bind "127.0.0.1:$TLS_PORT" \
  --tls-cert "$TLS_CERT" \
  --tls-key "$TLS_KEY" &
SIPHON_PID=$!
sleep 2
if ! kill -0 "$SIPHON_PID" >/dev/null 2>&1; then
  echo "siphond failed to start (port in use?)"
  exit 1
fi

cleanup() {
  if [[ -n "${SIPHON_PID:-}" ]] && kill -0 "$SIPHON_PID" >/dev/null 2>&1; then
    kill "$SIPHON_PID" || true
  fi
}
trap cleanup EXIT

wait_for_port() {
  local host="$1"
  local port="$2"
  local proto="$3"
  local retries=15
  local delay=1
  local opts=()

  if [[ "$host" == *:* ]]; then
    opts+=("-6")
  fi

  while (( retries > 0 )); do
    if [[ "$proto" == "udp" ]]; then
      if nc "${opts[@]}" -u -z -w1 "$host" "$port" >/dev/null 2>&1; then
        return 0
      fi
    else
      if nc "${opts[@]}" -z -w1 "$host" "$port" >/dev/null 2>&1; then
        return 0
      fi
    fi
    retries=$((retries - 1))
    sleep "$delay"
  done

  echo "Timed out waiting for $proto $host:$port"
  return 1
}

echo "== Wait for listeners =="
wait_for_port "${SIP_BIND%:*}" "${SIP_BIND##*:}" udp
wait_for_port "$TLS_HOST" "$TLS_PORT" tcp

echo "== Run TLS core scenarios =="
cd "$ROOT_DIR/sip-testkit/sipp"
export SIPHON_TLS12_ONLY=1
RUN_TLS_CORE=1 \
SKIP_REACHABILITY=1 \
TLS_HOST="$TLS_HOST" TLS_PORT="$TLS_PORT" \
TLS_CERT="$TLS_CERT" TLS_KEY="$TLS_KEY" TLS_CA="$TLS_CA" \
./run_scenarios.sh "$SIPP_TARGET_HOST" "$SIPP_TARGET_PORT"
