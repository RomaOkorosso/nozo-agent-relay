#!/usr/bin/env bash
# Relay behind Tailscale Serve (owner) + Funnel (public coordinator). Free.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"
export NOZO_RELAY_ALLOWED_ORIGINS="[\"https://${HOST}\"]"
export NOZO_RELAY_ALLOWED_HOSTS="[\"${HOST}\"]"
export NOZO_RELAY_EXTERNAL_PUBLIC_HOSTS="[\"${HOST}\"]"
exec uv run python -m nozo_relay serve
