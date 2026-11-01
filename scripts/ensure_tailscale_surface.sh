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

funnel_url="https://${HOST}"
# Prefer live IPv4 free-tunnel URL as Pages primary when present (Funnel AAAA often times out → browser Failed to fetch).
ipv4_tunnel=""
if [[ -s /tmp/nozo-public-url.txt ]]; then
  ipv4_tunnel="$(tr -d '[:space:]' </tmp/nozo-public-url.txt || true)"
fi
mkdir -p "$POINTER_DIR"
python3 - <<PY
import json
from datetime import datetime, timezone
from pathlib import Path
path = Path(${POINTER_FILE@Q})
funnel = ${funnel_url@Q}
ipv4 = ${ipv4_tunnel@Q}
fallbacks = []
if ipv4 and ipv4.startswith("https://") and ipv4 != funnel:
    primary, transport = ipv4, "localhost_run_ipv4_primary"
    fallbacks = [funnel]
else:
    primary, transport = funnel, "tailscale_funnel"
doc = {
  "relay_base": primary,
  "relay_fallbacks": fallbacks,
  "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "transport": transport,
  "note": "No keys. Pages needs commit/push to publish pointer. Funnel kept for tailnet/owner; IPv4 tunnel preferred for browsers when available.",
}
path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
print("wrote", path, "->", doc["relay_base"], "fallbacks=", doc["relay_fallbacks"])
PY

echo "SERVE_FUNNEL=https://${HOST}"
echo "$status" | head -20
