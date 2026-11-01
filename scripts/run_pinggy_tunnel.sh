#!/usr/bin/env bash
# Free HTTPS via Pinggy (60 min free). localhost.run drops ChatGPT POSTs; tunnl.gg has interstitials.
set -euo pipefail
URL_FILE="${1:-/tmp/nozo-public-url.txt}"
LOG="${2:-/tmp/nozo-pinggy.log}"
PIDFILE="${3:-/tmp/nozo-pinggy.pid}"

pkill -f 'a.pinggy.io' 2>/dev/null || true
pkill -f 'stable@proxy.tunnl.gg' 2>/dev/null || true
pkill -f 'nokey@localhost.run' 2>/dev/null || true
sleep 1
: >"$URL_FILE"

(
  while true; do
    : >"$LOG"
    ssh -p 443 \
        -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -o TCPKeepAlive=yes \
        -R0:127.0.0.1:8765 \
        a.pinggy.io >>"$LOG" 2>&1 &
    ssh_pid=$!
    echo "$ssh_pid" >"$PIDFILE"

    while kill -0 "$ssh_pid" 2>/dev/null; do
      if url="$(grep -oE 'https://[a-z0-9-]+\.(run\.pinggy-free\.link|free\.pinggy\.net)' "$LOG" | head -1)"; then
        prev="$(cat "$URL_FILE" 2>/dev/null || true)"
        if [[ "$url" != "$prev" ]]; then
          printf '%s\n' "$url" >"$URL_FILE"
          echo "$(date -Is) PUBLIC_URL=$url" >>"$LOG"
        fi
      fi
      sleep 2
    done

    wait "$ssh_pid" || true
    echo "$(date -Is) tunnel exited; reconnecting in 3s" >>"$LOG"
    sleep 3
  done
) >/tmp/nozo-pinggy-supervisor.log 2>&1 &
echo $! > /tmp/nozo-pinggy-supervisor.pid
echo "supervisor pid $(cat /tmp/nozo-pinggy-supervisor.pid)"

for _ in $(seq 1 45); do
  if [[ -s "$URL_FILE" ]]; then
    echo "PUBLIC_URL=$(cat "$URL_FILE")"
    echo "LOGIN=$(cat "$URL_FILE")/login"
    exit 0
  fi
  sleep 1
done
echo "failed to obtain URL; see $LOG" >&2
tail -40 "$LOG" >&2 || true
exit 1
