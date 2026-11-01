#!/usr/bin/env bash
# Idempotent: Tailscale Funnel (public coordinator HTTPS) + Serve on same Host.
# Stable public URL: https://$HOST — no ephemeral free-tunnel hostname.
# Fail closed: nonzero exit if Funnel apply/verify fails (SA-04). Do not write pointer on failure.
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

# Always apply; never swallow failure (SA-04).
if ! tailscale funnel --bg "${PORT}"; then
  echo "tailscale funnel --bg ${PORT} failed" >&2
  exit 1
fi

status="$(tailscale funnel status 2>&1 || true)"
if ! grep -q 'Funnel on' <<<"$status"; then
  echo "Funnel not enabled after apply:" >&2
  echo "$status" >&2
  exit 1
fi
if ! grep -Eq "127\\.0\\.0\\.1:${PORT}|localhost:${PORT}" <<<"$status"; then
  echo "Funnel proxy target is not 127.0.0.1:${PORT}:" >&2
  echo "$status" >&2
  exit 1
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
  "note": "Public coordinator HTTPS via Tailscale Funnel. No keys. Local file; Pages needs commit/push to publish.",
}
open(path, "w", encoding="utf-8").write(json.dumps(doc, indent=2) + "\n")
print("wrote", path, "->", doc["relay_base"])
PY
else
  echo "pointer unchanged: $desired"
fi

echo "SERVE_FUNNEL=https://${HOST}"
echo "$status" | head -20
