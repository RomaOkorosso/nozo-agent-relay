#!/usr/bin/env bash
# Idempotent: Tailscale Funnel (public coordinator HTTPS) + Serve on same Host.
# Stable public URL: https://$HOST — no ephemeral free-tunnel hostname.
set -euo pipefail
HOST="${NOZO_RELAY_PUBLIC_HOST:-roma-gv628rc.tailbfec94.ts.net}"
PORT="${NOZO_RELAY_PORT:-8765}"
POINTER_DIR="${NOZO_POINTER_DIR:-$(cd "$(dirname "$0")/.." && pwd)/gateway}"
POINTER_FILE="${POINTER_DIR}/pointer.json"

if ! command -v tailscale >/dev/null; then
  echo "tailscale not installed" >&2
  exit 1
fi
if ! tailscale status >/dev/null 2>&1; then
  echo "tailscaled not ready / not logged in" >&2
  exit 1
fi

# Modern CLI: funnel --bg <port> enables HTTPS:443 proxy + AllowFunnel.
# (Older docs used `funnel --bg on` after serve; that now mis-parses as target "on".)
if ! tailscale funnel status 2>/dev/null | grep -q 'Funnel on'; then
  tailscale funnel --bg "${PORT}"
else
  # Refresh proxy target if needed (idempotent).
  tailscale funnel --bg "${PORT}" >/dev/null 2>&1 || true
fi

desired="https://${HOST}"
mkdir -p "$POINTER_DIR"
prev=""
if [[ -f "$POINTER_FILE" ]]; then
  prev="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('relay_base',''))" "$POINTER_FILE" 2>/dev/null || true)"
fi
if [[ "$prev" != "$desired" ]]; then
  python3 - <<PY
import json
from datetime import datetime, timezone
path = ${POINTER_FILE@Q}
doc = {
  "relay_base": ${desired@Q},
  "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "transport": "tailscale_funnel",
  "note": "Public coordinator HTTPS via Tailscale Funnel. No keys. Gateway may auto-fill this URL.",
}
open(path, "w", encoding="utf-8").write(json.dumps(doc, indent=2) + "\n")
print("wrote", path, "->", doc["relay_base"])
PY
else
  echo "pointer unchanged: $desired"
fi

echo "SERVE_FUNNEL=https://${HOST}"
tailscale funnel status 2>&1 | head -20 || true
