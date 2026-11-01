# Nozo Gateway (GitHub Pages → Relay API)

Static SPA. ChatGPT opens a stable `*.github.io` page; the browser calls your **public Relay HTTPS URL** with the coordinator **Bearer** key. Messages/tasks land in Relay only (no Telegram/ntfy).

GitHub Pages is **not** a reverse proxy. Relay must be reachable over public HTTPS.

**Primary transport (stable):** Tailscale Funnel → `https://roma-gv628rc.tailbfec94.ts.net` (see `pointer.json`).  
Ephemeral free tunnels are fallback only. Operator guide: [`docs/OPERATOR_STABLE_ACCESS.md`](../docs/OPERATOR_STABLE_ACCESS.md).

## Deploy

1. Push this repo to GitHub; enable **Settings → Pages → Source: GitHub Actions**.
2. Workflow [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) publishes the `gateway/` folder (including `pointer.json`).
3. Run Relay + surface: `systemctl --user start nozo-relay.service nozo-tailscale-surface.service`
4. CORS: `NOZO_RELAY_CORS_ORIGIN_SUFFIXES=[".github.io"]` (set by `scripts/run_relay_stable.sh`).

## Connect ChatGPT

```bash
uv run python scripts/print_gateway_connect.py --print-key
```

1. Open the printed `GATEWAY_OPEN` URL (includes `?relay=` when the tunnel file exists).
2. Paste the coordinator Bearer from `data/clients/chatgpt_credentials.json`.
3. Use chat/tasks; owner sees the same project in the private panel.
4. **Create / manage tasks** (coordinator): fill title/requirements/acceptance, implementer & auditor UUIDs, `delegation_id`, allowed paths. By default **«сразу поставить в очередь»** calls `POST …/enqueue` with `If-Match` after create (draft → queued) so agents get real work, not draft spam. Click a task to open detail: enqueue / pause / resume / cancel. Chat can attach notes to the selected task (`task_id`). Pending create is stored in `sessionStorage` as an **immutable** `{idempotencyKey, payload}` until success or explicit discard. Acceptance/paths over API limits error out (no silent truncate). Agent UUIDs remembered in `sessionStorage` only.

Do **not** commit the Bearer key or put it in `config.example.json`.

## Local smoke

```bash
# terminal A — Relay with CORS for local static origin
NOZO_RELAY_ALLOWED_ORIGINS='["http://127.0.0.1:8766"]' \
  uv run python -m nozo_relay serve

# terminal B
cd gateway && python3 -m http.server 8766 --bind 127.0.0.1
```

Open `http://127.0.0.1:8766/`, base URL `http://127.0.0.1:8765`, Bearer from credentials file.
