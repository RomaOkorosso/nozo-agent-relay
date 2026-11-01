#!/usr/bin/env bash
# Free HTTPS tunnel via tunnl.gg (stable URL tied to SSH key). localhost.run drops POSTs often.
set -euo pipefail
URL_FILE="${1:-/tmp/nozo-public-url.txt}"
LOG="${2:-/tmp/nozo-tunnl.log}"
PIDFILE="${3:-/tmp/nozo-tunnl.pid}"
KEY="${NOZO_TUNNL_KEY:-$HOME/.ssh/nozo_tunnl_ed25519}"

if [[ ! -f "$KEY" ]]; then
  ssh-keygen -t ed25519 -f "$KEY" -N '' -C 'nozo-relay-tunnl' </dev/null
fi

pkill -f 'stable@proxy.tunnl.gg' 2>/dev/null || true
pkill -f 'proxy.tunnl.gg' 2>/dev/null || true
pkill -f 'nokey@localhost.run' 2>/dev/null || true
sleep 1
: >"$URL_FILE"

(
  while true; do
    : >"$LOG"
    # -n: no remote shell stdin; -T: no tty (URL still printed on stderr/stdout).
    ssh -i "$KEY" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -o TCPKeepAlive=yes \
        -n -T \
        -R 80:127.0.0.1:8765 \
        stable@proxy.tunnl.gg >>"$LOG" 2>&1 &
    ssh_pid=$!
    echo "$ssh_pid" >"$PIDFILE"

    while kill -0 "$ssh_pid" 2>/dev/null; do
      # strip ANSI; match https://*.tunnl.gg
      if url="$(sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -oE 'https://[a-z0-9-]+\.tunnl\.gg' | tail -1)"; then
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
) >/tmp/nozo-tunnl-supervisor.log 2>&1 &
echo $! > /tmp/nozo-tunnl-supervisor.pid
echo "supervisor pid $(cat /tmp/nozo-tunnl-supervisor.pid)"

for _ in $(seq 1 40); do
  if [[ -s "$URL_FILE" ]]; then
    echo "PUBLIC_URL=$(cat "$URL_FILE")"
    echo "LOGIN=$(cat "$URL_FILE")/login"
    exit 0
  fi
  sleep 1
done
echo "failed to obtain URL; see $LOG" >&2
tail -60 "$LOG" >&2 || true
exit 1
