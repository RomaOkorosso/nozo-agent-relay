#!/usr/bin/env bash
# One-command local start (loopback only). Safe to re-run.
#   ./scripts/start.sh            # plain-HTTP dev on 127.0.0.1:8765 (insecure cookies, loopback only)
#   NOZO_RELAY_HTTPS_PROXY=1 ./scripts/start.sh   # behind an HTTPS proxy (Tailscale Serve): Secure cookies; set ALLOWED_ORIGINS/HOSTS yourself
# It never binds a non-loopback address, never uses sudo and never prints secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

uv sync --extra mcp --quiet

DATA_DIR="${NOZO_RELAY_DATA_DIR:-./data}"
if [[ ! -e "$DATA_DIR/relay.sqlite" && ! -e "${NOZO_RELAY_SQLITE_PATH:-/nonexistent}" ]]; then
  echo ">> first start: bootstrapping (owner password -> $DATA_DIR/bootstrap_credentials.json, 0600)"
  uv run python -m nozo_relay bootstrap
  echo ">> copy the secrets to a private store, then delete bootstrap_credentials.json"
fi

if [[ "${NOZO_RELAY_HTTPS_PROXY:-0}" != "1" ]]; then
  export NOZO_RELAY_INSECURE_DEV_COOKIES=1
  echo ">> open http://127.0.0.1:${NOZO_RELAY_PORT:-8765}/login (log in as 'owner')"
else
  unset NOZO_RELAY_INSECURE_DEV_COOKIES
  : "${NOZO_RELAY_ALLOWED_ORIGINS:?set NOZO_RELAY_ALLOWED_ORIGINS='[\"https://<machine>.<tailnet>.ts.net\"]'}"
  : "${NOZO_RELAY_ALLOWED_HOSTS:?set NOZO_RELAY_ALLOWED_HOSTS='[\"<machine>.<tailnet>.ts.net\"]'}"
fi

uv run python -m nozo_relay check
exec uv run python -m nozo_relay serve
