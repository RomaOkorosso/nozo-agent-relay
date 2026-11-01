#!/usr/bin/env bash
# Relay: Tailscale host + free-tunnel suffixes + GitHub Pages gateway Origin.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"
# Static gateway Origin (path /nozo-gateway/ does not change Origin host).
GATEWAY_ORIGIN="${NOZO_RELAY_GATEWAY_ORIGIN:-https://romaokorosso.github.io}"
# Loopback Origins are also built into Settings.origin_allowlist; listed here so local
# owner login stays explicit when this public profile is used.
export NOZO_RELAY_ALLOWED_ORIGINS="[\"https://${HOST}\",\"${GATEWAY_ORIGIN}\",\"http://127.0.0.1:8765\",\"http://localhost:8765\"]"
export NOZO_RELAY_ALLOWED_HOSTS="[\"${HOST}\"]"
export NOZO_RELAY_EXTERNAL_PUBLIC_HOSTS="[\"${HOST}\"]"
export NOZO_RELAY_CORS_ORIGIN_SUFFIXES='[".github.io"]'
# trycloudflare often blocks ChatGPT bots; Pinggy / localhost.run / tunnl are free fallbacks.
export NOZO_RELAY_EXTERNAL_PUBLIC_HOST_SUFFIXES='[".run.pinggy-free.link",".free.pinggy.net",".pinggy.link",".tunnl.gg",".trycloudflare.com",".bore.pub",".localhost.run",".lhr.life"]'
exec uv run python -m nozo_relay serve
