# Nozo Gateway (GitHub Pages → Relay API)

Static SPA. ChatGPT opens a stable `*.github.io` page; the browser calls your **public Relay HTTPS URL** with the coordinator **Bearer** key. Messages/tasks land in Relay only (no Telegram/ntfy).

GitHub Pages is **not** a reverse proxy. A live tunnel to Relay is still required (`/tmp/nozo-public-url.txt`).

## Deploy

1. Push this repo to GitHub; enable **Settings → Pages → Source: GitHub Actions**.
2. Workflow [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) publishes the `gateway/` folder.
3. Set Relay env (or use `scripts/run_relay_public.sh`):
   - `NOZO_RELAY_GATEWAY_ORIGIN=https://<you>.github.io`
   - `NOZO_RELAY_CORS_ORIGIN_SUFFIXES=[".github.io"]`
4. Start a free tunnel + Relay as usual.

## Connect ChatGPT

```bash
uv run python scripts/print_gateway_connect.py --print-key
```

1. Open the printed `GATEWAY_OPEN` URL (includes `?relay=` when the tunnel file exists).
2. Paste the coordinator Bearer from `data/clients/chatgpt_credentials.json`.
3. Use chat/tasks; owner sees the same project in the private panel.

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
