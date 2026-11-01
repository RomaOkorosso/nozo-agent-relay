#!/usr/bin/env bash
# Secure MCP Tunnel: ChatGPT → private Relay MCP (stdio). Admin UI stays on Tailscale.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
export PATH="${HOME}/.local/bin:${PATH}"

TUNNEL_DIR="${ROOT}/data/tunnel"
CREDS="${ROOT}/data/clients/chatgpt_credentials.json"
TUNNEL_ID_FILE="${TUNNEL_DIR}/tunnel_id"
API_KEY_FILE="${TUNNEL_DIR}/runtime_api_key"
PROFILE="nozo-relay-chatgpt"
PROFILE_DIR="${TUNNEL_DIR}/profiles"
WRAPPER="${ROOT}/scripts/mcp_stdio_chatgpt.sh"

command -v tunnel-client >/dev/null || { echo "tunnel-client missing (~/.local/bin)" >&2; exit 2; }
[[ -f "$CREDS" ]] || { echo "missing $CREDS" >&2; exit 2; }
[[ -s "$TUNNEL_ID_FILE" ]] || { echo "Put tunnel_id in $TUNNEL_ID_FILE (from Platform Tunnels UI)" >&2; exit 2; }
[[ -s "$API_KEY_FILE" ]] || { echo "Put runtime API key in $API_KEY_FILE" >&2; exit 2; }

TUNNEL_ID="$(tr -d ' \n\r\t' < "$TUNNEL_ID_FILE")"
export CONTROL_PLANE_API_KEY
CONTROL_PLANE_API_KEY="$(tr -d ' \n\r\t' < "$API_KEY_FILE")"
export NOZO_RELAY_DATA_DIR="${ROOT}/data"
export NOZO_RELAY_MCP_AGENT_KEY
NOZO_RELAY_MCP_AGENT_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key"])' "$CREDS")"

mkdir -p "$PROFILE_DIR"
chmod 700 "$TUNNEL_DIR" "$PROFILE_DIR" || true
chmod 600 "$TUNNEL_ID_FILE" "$API_KEY_FILE" || true

if [[ ! -f "${PROFILE_DIR}/${PROFILE}.yaml" ]]; then
  echo ">> init profile ${PROFILE}"
  tunnel-client init \
    --sample sample_mcp_stdio_local \
    --profile "$PROFILE" \
    --profile-dir "$PROFILE_DIR" \
    --tunnel-id "$TUNNEL_ID" \
    --mcp-command "$WRAPPER" \
    --health-listen-addr "127.0.0.1:0" \
    --force
fi

echo ">> Admin UI (you): https://roma-gv628rc.tailbfec94.ts.net/login"
echo ">> doctor"
tunnel-client doctor --profile "$PROFILE" --profile-dir "$PROFILE_DIR" --explain || true
echo ">> run"
exec tunnel-client run --profile "$PROFILE" --profile-dir "$PROFILE_DIR"
