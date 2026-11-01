#!/usr/bin/env bash
# Stable profile: loopback owner UI + Tailscale Host + GitHub Pages CORS.
# Pair with: scripts/ensure_tailscale_surface.sh (Serve + Funnel → :8765).
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"
GATEWAY_ORIGIN="${NOZO_RELAY_GATEWAY_ORIGIN:-https://romaokorosso.github.io}"

export NOZO_RELAY_ALLOWED_ORIGINS="[\"https://${HOST}\",\"${GATEWAY_ORIGIN}\",\"http://127.0.0.1:8765\",\"http://localhost:8765\",\"http://[::1]:8765\"]"
export NOZO_RELAY_ALLOWED_HOSTS="[\"${HOST}\"]"
export NOZO_RELAY_EXTERNAL_PUBLIC_HOSTS="[\"${HOST}\"]"
# Funnel visitors (no Tailscale-User-*) get coordinator-only surface.
# Free-tunnel suffixes kept as fallback if Funnel is briefly unavailable.
export NOZO_RELAY_CORS_ORIGIN_SUFFIXES='[".github.io"]'
export NOZO_RELAY_EXTERNAL_PUBLIC_HOST_SUFFIXES='[".run.pinggy-free.link",".free.pinggy.net",".pinggy.link",".tunnl.gg",".trycloudflare.com",".bore.pub",".localhost.run",".lhr.life"]'
# Cookie Secure is chosen per-request (HTTPS/ts.net vs loopback HTTP); do not force insecure globally.
unset NOZO_RELAY_INSECURE_DEV_COOKIES || true

exec uv run python -m nozo_relay serve
