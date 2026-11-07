#!/usr/bin/env bash
# Fully stop Nozo Relay public surface + free IPv4 tunnel + local relay.
# Idempotent. Does not print secrets.
#
# Usage:
#   ./scripts/nozo_stop.sh              # stop + disable (survive logout/login)
#   ./scripts/nozo_stop.sh --keep-enabled  # stop only until reboot/login (Linger=no)
#   ./scripts/nozo_stop.sh --dry-run     # print actions; change nothing
#
# Exit nonzero if localhost.run SSH or Funnel still appear to consume public traffic.
set -euo pipefail

KEEP_ENABLED=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --keep-enabled) KEEP_ENABLED=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "unknown flag: $arg (use --keep-enabled or --dry-run)" >&2
      exit 2
      ;;
  esac
done

PORT="${NOZO_RELAY_PORT:-8765}"
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"

UNITS=(
  nozo-watchdog.timer
  nozo-ipv4-tunnel.service
  nozo-tailscale-surface.service
  nozo-relay.service
)

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run] ';
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

echo "== Nozo stop =="
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "mode: dry-run (no changes)"
elif [[ "$KEEP_ENABLED" -eq 1 ]]; then
  echo "mode: temporary stop (--keep-enabled; units stay enabled)"
else
  echo "mode: full stop + disable (will not auto-start on next login)"
fi

# 1) Watchdog first so it cannot re-enable Funnel / republish while we tear down.
echo "-- systemd: stop watchdog"
run systemctl --user stop nozo-watchdog.timer || true
run systemctl --user stop nozo-watchdog.service || true
# Cancel a queued/running oneshot if present.
run systemctl --user reset-failed nozo-watchdog.service 2>/dev/null || true

echo "-- systemd: stop tunnel / surface / relay"
run systemctl --user stop nozo-ipv4-tunnel.service || true
run systemctl --user stop nozo-tailscale-surface.service || true
run systemctl --user stop nozo-relay.service || true
# Clear failed leftover from abrupt stop so status reads inactive, not failed.
run systemctl --user reset-failed nozo-ipv4-tunnel.service nozo-tailscale-surface.service nozo-relay.service 2>/dev/null || true

if [[ "$KEEP_ENABLED" -eq 0 ]]; then
  echo "-- systemd: disable units"
  for u in "${UNITS[@]}"; do
    run systemctl --user disable "$u" || true
  done
fi

# 2) Leftover free-tunnel processes (unit Stop may leave supervisor/ssh).
echo "-- kill leftover localhost.run tunnel processes"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] pkill -f nokey@localhost.run / run_localhost_run_tunnel; clear supervisor pid files"
else
  pkill -f 'nokey@localhost.run' 2>/dev/null || true
  pkill -f 'run_localhost_run_tunnel' 2>/dev/null || true
  for pf in /tmp/nozo-localhost-run-supervisor.pid /tmp/nozo-localhost-run.pid; do
    if [[ -f "$pf" ]]; then
      pid="$(tr -d '[:space:]' <"$pf" || true)"
      if [[ -n "${pid:-}" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
        kill "$pid" 2>/dev/null || true
        # Kill process group / children if still around.
        kill -TERM -"$pid" 2>/dev/null || true
      fi
      rm -f "$pf" || true
    fi
  done
  # Second pass after brief settle.
  sleep 1
  pkill -f 'nokey@localhost.run' 2>/dev/null || true
  pkill -f 'run_localhost_run_tunnel' 2>/dev/null || true
fi

# 3) Public Funnel off, then targeted Serve teardown for HTTPS:443 (Nozo host/port).
# Prefer targeted --https=443 off over serve reset so unrelated Serve (if any) is less likely harmed.
# Funnel+Serve on this host are owned by nozo-tailscale-surface for :8765.
echo "-- Tailscale Funnel / Serve off (tolerate already-off)"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] tailscale funnel --https=443 off"
  echo "[dry-run] tailscale serve --https=443 off"
else
  if command -v tailscale >/dev/null 2>&1; then
    tailscale funnel --https=443 off >/dev/null 2>&1 || true
    # Targeted Serve clear for the same HTTPS listener Funnel used.
    tailscale serve --https=443 off >/dev/null 2>&1 || true
    # If Serve still proxies our loopback port only, clear that handler; avoid blanket reset
    # unless status still shows our 8765 proxy after targeted off.
    serve_blob="$(tailscale serve status 2>/dev/null || true)"
    if grep -Eq "127\\.0\\.0\\.1:${PORT}|localhost:${PORT}" <<<"$serve_blob"; then
      echo "Serve still mentions :${PORT}; funnel reset + serve --https=443 off again"
      tailscale funnel reset >/dev/null 2>&1 || true
      tailscale serve --https=443 off >/dev/null 2>&1 || true
      serve_blob="$(tailscale serve status 2>/dev/null || true)"
      # Last resort: this host's Serve is Nozo-owned (:8765). Avoid if possible.
      if grep -Eq "127\\.0\\.0\\.1:${PORT}|localhost:${PORT}" <<<"$serve_blob"; then
        echo "Serve still proxies Relay; running tailscale serve reset"
        tailscale serve reset >/dev/null 2>&1 || true
      fi
    fi
  else
    echo "tailscale not installed; skipped Funnel/Serve teardown" >&2
  fi
fi

# 4) Status report
echo
echo "== status =="
critical=0

unit_line() {
  local u="$1"
  local active state
  active="$(systemctl --user is-active "$u" 2>/dev/null || true)"
  state="$(systemctl --user is-enabled "$u" 2>/dev/null || true)"
  printf '  %-32s active=%-12s enabled=%s\n' "$u" "${active:-unknown}" "${state:-unknown}"
}

echo "units:"
unit_line nozo-watchdog.timer
unit_line nozo-ipv4-tunnel.service
unit_line nozo-tailscale-surface.service
unit_line nozo-relay.service

ssh_n=0
if pgrep -af 'nokey@localhost.run' >/dev/null 2>&1; then
  ssh_n="$(pgrep -af 'nokey@localhost.run' | wc -l | tr -d ' ')"
fi
if [[ "$ssh_n" -gt 0 ]]; then
  echo "ssh tunnel: STILL UP ($ssh_n process line(s)) — public traffic risk"
  critical=1
else
  echo "ssh tunnel: none (nokey@localhost.run)"
fi

funnel_status="$(tailscale funnel status 2>/dev/null || echo 'unavailable')"
if grep -q 'Funnel on' <<<"$funnel_status"; then
  echo "funnel: STILL ON"
  echo "$funnel_status" | head -8 | sed 's/^/  /'
  critical=1
else
  echo "funnel: off (or unavailable)"
fi

serve_status="$(tailscale serve status 2>/dev/null || echo 'unavailable')"
if grep -Eq "127\\.0\\.0\\.1:${PORT}|localhost:${PORT}" <<<"$serve_status"; then
  echo "serve: still proxies :${PORT}"
  echo "$serve_status" | head -8 | sed 's/^/  /'
else
  echo "serve: no proxy to :${PORT}"
fi

if ss -ltn "sport = :${PORT}" 2>/dev/null | grep -q ":${PORT}"; then
  echo "listen :${PORT}: STILL LISTENING (local only; no public surface if funnel/tunnel off)"
else
  echo "listen :${PORT}: not listening"
fi

echo
echo "notes:"
echo "  - GitHub Pages static site stays up; Relay API is dead until ./scripts/nozo_start.sh"
echo "  - tailscaled (OS) may still run; we only stopped Nozo Funnel/Serve/tunnel/relay"
echo "  - pointer.json on Pages may still point at a dead tunnel until next start+publish"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo
  echo "dry-run complete (exit 0); re-run without --dry-run to apply"
  exit 0
fi

if [[ "$critical" -ne 0 ]]; then
  echo
  echo "FAIL: public traffic sources still active (see above)" >&2
  exit 1
fi

echo
echo "OK: Nozo public surface stopped"
exit 0
