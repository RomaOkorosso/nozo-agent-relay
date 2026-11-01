#!/usr/bin/env bash
# Free Cloudflare quick tunnel → https://*.trycloudflare.com → Relay :8765
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
command -v cloudflared >/dev/null || { echo "cloudflared missing (~/.local/bin)" >&2; exit 2; }
URL_FILE="${1:-/tmp/nozo-cloudflare-url.txt}"
LOG="${2:-/tmp/nozo-cloudflare-tunnel.log}"
rm -f "$URL_FILE"
: >"$LOG"

# Kill previous quick tunnel if any
pkill -f 'cloudflared tunnel --url http://127.0.0.1:8765' 2>/dev/null || true
sleep 1

nohup cloudflared tunnel --url "http://127.0.0.1:8765" --no-autoupdate >"$LOG" 2>&1 &
echo "cloudflared pid $!"

for _ in $(seq 1 60); do
  if url="$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG" | head -1)"; then
    printf '%s\n' "$url" >"$URL_FILE"
    echo "PUBLIC_URL=$url"
    echo "LOGIN=${url}/login"
    exit 0
  fi
  sleep 1
done
echo "timed out waiting for trycloudflare URL; see $LOG" >&2
tail -50 "$LOG" >&2 || true
exit 1
