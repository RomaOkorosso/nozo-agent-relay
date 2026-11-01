#!/usr/bin/env bash
# Health watchdog: local ready + Funnel AllowFunnel/status + JSON live health (SA-02, SA-03).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${NOZO_RELAY_PORT:-8765}"
URL="http://127.0.0.1:${PORT}/api/v1/health/ready"
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"

if ! curl -fsS -m 3 "$URL" >/dev/null 2>&1; then
  echo "$(date -Is) relay_not_ready" >&2
  exit 1
fi

# SA-02: require explicit "Funnel on" — do NOT treat bare hostname/https as success (Serve-only).
funnel_status="$(tailscale funnel status 2>/dev/null || true)"
need_repair=0
if ! grep -q 'Funnel on' <<<"$funnel_status"; then
  need_repair=1
fi
# Prefer structured JSON when available (AllowFunnel[host:443] == true).
if command -v python3 >/dev/null; then
  if ! python3 - "$HOST" "$PORT" <<'PY'
import json, subprocess, sys
host, port = sys.argv[1], sys.argv[2]
try:
    raw = subprocess.check_output(["tailscale", "serve", "status", "--json"], text=True, stderr=subprocess.DEVNULL)
    data = json.loads(raw)
except Exception:
    sys.exit(0)  # no JSON — fall back to text check already done
allow = data.get("AllowFunnel") or {}
key = f"{host}:443"
if allow.get(key) is not True and allow.get(host) is not True:
    sys.exit(2)
# Optional: confirm proxy target mentions our port
blob = json.dumps(data)
if f"127.0.0.1:{port}" not in blob and f"localhost:{port}" not in blob:
    sys.exit(2)
sys.exit(0)
PY
  then
    need_repair=1
  fi
fi

if [[ "$need_repair" -eq 1 ]]; then
  echo "$(date -Is) funnel_serve_only_or_missing; repairing" >&2
  "$ROOT/scripts/ensure_tailscale_surface.sh"
fi

# SA-03: public health must be JSON with status==live (not HTML containing '{').
pub="https://${HOST}/api/v1/health/live"
body="$(curl -fsS -m 8 -H 'Accept: application/json' "$pub" 2>/dev/null || true)"
if python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d.get("status")=="live"' "$body" 2>/dev/null; then
  echo "$(date -Is) public_ok"
else
  echo "$(date -Is) public_probe_soft_fail" >&2
fi
exit 0

# Keep Pages pointer in sync when free-tunnel URL rotates (rate-limited push).
if [[ -x "$ROOT/scripts/publish_pointer_if_changed.sh" ]]; then
  "$ROOT/scripts/publish_pointer_if_changed.sh" >/tmp/nozo-pointer-publish.log 2>&1 || true
fi
