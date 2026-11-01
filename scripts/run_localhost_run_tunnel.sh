#!/usr/bin/env bash
# Free HTTPS tunnel via localhost.run with auto-reconnect (free tier drops / rotates often).
set -euo pipefail
URL_FILE="${1:-/tmp/nozo-public-url.txt}"
LOG="${2:-/tmp/nozo-localhost-run.log}"
PIDFILE="${3:-/tmp/nozo-localhost-run.pid}"

pkill -f 'nokey@localhost.run' 2>/dev/null || true
sleep 1
: >"$URL_FILE"

(
  while true; do
    : >"$LOG"
    ssh -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -o TCPKeepAlive=yes \
        -R 80:127.0.0.1:8765 nokey@localhost.run >>"$LOG" 2>&1 &
    ssh_pid=$!
    echo "$ssh_pid" >"$PIDFILE"

    # Keep URL_FILE on the *latest* *.lhr.life announcement (host can rotate mid-session).
    while kill -0 "$ssh_pid" 2>/dev/null; do
      if url="$(grep -oE 'https://[a-f0-9]+\.lhr\.life' "$LOG" | tail -1)"; then
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
) >/tmp/nozo-localhost-run-supervisor.log 2>&1 &
echo $! > /tmp/nozo-localhost-run-supervisor.pid
echo "supervisor pid $(cat /tmp/nozo-localhost-run-supervisor.pid)"

# Wait for first URL
for _ in $(seq 1 50); do
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
