#!/usr/bin/env bash
# If gateway/pointer.json changed vs origin/master, commit+push so Pages picks up the new tunnel URL.
# Rate-limited: at most once per 3 minutes. No secrets in pointer.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
STAMP=/tmp/nozo-pointer-publish.stamp
now=$(date +%s)
if [[ -f "$STAMP" ]]; then
  prev=$(cat "$STAMP" 2>/dev/null || echo 0)
  if (( now - prev < 180 )); then
    echo "publish skipped (rate limit)"
    exit 0
  fi
fi

# Refresh pointer from Funnel + /tmp/nozo-public-url.txt first
"$ROOT/scripts/ensure_tailscale_surface.sh" >/tmp/nozo-pointer-ensure.out 2>&1 || {
  echo "ensure failed; see /tmp/nozo-pointer-ensure.out" >&2
  exit 1
}

git fetch origin master -q 2>/dev/null || true
if git show origin/master:gateway/pointer.json >/tmp/nozo-pointer-origin.json 2>/dev/null; then
  if cmp -s gateway/pointer.json /tmp/nozo-pointer-origin.json; then
    echo "pointer unchanged vs origin"
    exit 0
  fi
fi

# Sanity: primary must be https and respond live (best-effort)
primary="$(python3 -c "import json;print(json.load(open('gateway/pointer.json'))['relay_base'])")"
if ! curl -4 -fsS -m 12 -H 'Accept: application/json' "$primary/api/v1/health/live" | grep -q '"live"'; then
  echo "primary not live: $primary" >&2
  exit 1
fi

git add gateway/pointer.json
if git diff --cached --quiet; then
  echo "nothing staged"
  exit 0
fi
git commit -m "chore: refresh gateway pointer for live public Relay URL"
git push origin HEAD
echo "$now" >"$STAMP"
echo "published pointer -> $primary"
