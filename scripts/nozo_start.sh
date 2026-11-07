#!/usr/bin/env bash
# Start Nozo Relay + Tailscale surface + free IPv4 tunnel + watchdog.
# Idempotent. Does not print secrets. Does not auto-commit/push pointer.json.
#
# Usage:
#   ./scripts/nozo_start.sh
#   ./scripts/nozo_start.sh --dry-run
set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,9p' "$0"
      exit 0
      ;;
    *)
      echo "unknown flag: $arg (use --dry-run)" >&2
      exit 2
      ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${NOZO_RELAY_PORT:-8765}"
READY_URL="http://127.0.0.1:${PORT}/api/v1/health/ready"
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

echo "== Nozo start =="
[[ "$DRY_RUN" -eq 1 ]] && echo "mode: dry-run (no changes)"

# Order: relay first (surface Requires it), then surface, ipv4 tunnel, watchdog timer.
echo "-- enable --now relay"
run systemctl --user enable --now nozo-relay.service

echo "-- enable --now Tailscale surface"
run systemctl --user enable --now nozo-tailscale-surface.service

echo "-- enable --now IPv4 localhost.run tunnel"
run systemctl --user enable --now nozo-ipv4-tunnel.service

echo "-- enable --now watchdog timer"
run systemctl --user enable --now nozo-watchdog.timer

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] wait for ${READY_URL}"
  echo "[dry-run] optional ensure_tailscale_surface.sh"
  echo "dry-run complete"
  exit 0
fi

echo "-- wait for local ready"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS -m 2 "$READY_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "FAIL: ${READY_URL} not ready after ~60s" >&2
  echo "check: systemctl --user status nozo-relay.service" >&2
  echo "logs:  journalctl --user -u nozo-relay.service -n 50 --no-pager" >&2
  exit 1
fi
echo "local ready: ok"

# Refresh Funnel/Serve + local pointer if surface oneshot already exited or Funnel missing.
need_surface=0
if ! systemctl --user is-active --quiet nozo-tailscale-surface.service; then
  need_surface=1
fi
funnel_status="$(tailscale funnel status 2>/dev/null || true)"
if ! grep -q 'Funnel on' <<<"$funnel_status"; then
  need_surface=1
fi
if [[ "$need_surface" -eq 1 ]]; then
  echo "-- refresh Tailscale surface (ensure_tailscale_surface.sh)"
  if ! "$ROOT/scripts/ensure_tailscale_surface.sh"; then
    echo "WARN: ensure_tailscale_surface.sh failed; relay is up locally, public surface may need a retry" >&2
  fi
else
  echo "surface: Funnel already on"
fi

# Tunnel URL settle (best-effort; tunnel may take a few seconds).
if [[ -s /tmp/nozo-public-url.txt ]]; then
  echo "ipv4 tunnel url file: present ($(tr -d '[:space:]' </tmp/nozo-public-url.txt))"
else
  echo "ipv4 tunnel url file: not yet (/tmp/nozo-public-url.txt) — wait a few seconds or check tunnel unit"
fi

echo
echo "== status =="
for u in nozo-relay.service nozo-tailscale-surface.service nozo-ipv4-tunnel.service nozo-watchdog.timer; do
  active="$(systemctl --user is-active "$u" 2>/dev/null || true)"
  state="$(systemctl --user is-enabled "$u" 2>/dev/null || true)"
  printf '  %-32s active=%-12s enabled=%s\n' "$u" "${active:-unknown}" "${state:-unknown}"
done

# Pointer dirty note (no auto-commit/push).
pointer="$ROOT/gateway/pointer.json"
if [[ -f "$pointer" ]] && command -v git >/dev/null 2>&1; then
  if ! git -C "$ROOT" diff --quiet -- gateway/pointer.json 2>/dev/null \
    || ! git -C "$ROOT" diff --cached --quiet -- gateway/pointer.json 2>/dev/null; then
    echo
    echo "note: gateway/pointer.json is dirty locally — Pages will stay stale until you"
    echo "  ./scripts/publish_pointer_if_changed.sh   # or commit+push when ready"
  fi
fi

echo
echo "checks:"
echo "  curl -fsS ${READY_URL}"
echo "  systemctl --user status nozo-relay.service nozo-tailscale-surface.service nozo-ipv4-tunnel.service nozo-watchdog.timer"
echo "  tailscale funnel status"
echo "docs: docs/CONNECT.md · docs/OPERATOR_STABLE_ACCESS.md"
echo
echo "OK: Nozo start complete"
exit 0
