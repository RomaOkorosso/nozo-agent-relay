#!/usr/bin/env bash
# Stdio MCP for tunnel-client. Expects NOZO_RELAY_MCP_AGENT_KEY + NOZO_RELAY_DATA_DIR in env.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export NOZO_RELAY_DATA_DIR="${NOZO_RELAY_DATA_DIR:-$ROOT/data}"
if [[ -z "${NOZO_RELAY_MCP_AGENT_KEY:-}" ]]; then
  echo "NOZO_RELAY_MCP_AGENT_KEY is required" >&2
  exit 2
fi
exec uv run python -m nozo_relay.mcp_stdio
