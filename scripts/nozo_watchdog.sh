#!/usr/bin/env bash
# Lightweight health watchdog: ensure Relay answers; refresh Tailscale surface; limited backoff.
# Does NOT start competing tunnel supervisors. Invoked by systemd timer or on-failure Restart.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${NOZO_RELAY_PORT:-8765}"
URL="http://127.0.0.1:${PORT}/api/v1/health/ready"
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"

ready=0
if curl -fsS -m 3 "$URL" >/dev/null 2>&1; then
  ready=1
fi

if [[ "$ready" -ne 1 ]]; then
  echo "$(date -Is) relay_not_ready" >&2
  exit 1
fi

# Refresh Serve/Funnel if missing (idempotent).
if ! tailscale funnel status 2>/dev/null | grep -q "${HOST}\|Funnel on\|https://"; then
  "$ROOT/scripts/ensure_tailscale_surface.sh" || true
fi

# Probe public Funnel API is JSON (not HTML interstitial) — best-effort, non-fatal.
pub="https://${HOST}/api/v1/health/live"
body="$(curl -fsS -m 8 -H 'Accept: application/json' "$pub" 2>/dev/null || true)"
if [[ -n "$body" ]] && [[ "$body" == *"{"* ]]; then
  echo "$(date -Is) public_ok"
else
  echo "$(date -Is) public_probe_soft_fail" >&2
fi
exit 0
