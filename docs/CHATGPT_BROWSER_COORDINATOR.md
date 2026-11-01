# ChatGPT: браузерный доступ координатора (без MCP Tunnel)

Альтернатива платному Secure MCP Tunnel: ChatGPT (или вы) открывает панель Nozo Relay в браузере под ролью **координатора**.

**Предпочтительно для ChatGPT:** статический шлюз на GitHub Pages → Relay API (Bearer), см. [`gateway/README.md`](../gateway/README.md). UI стабилен на `*.github.io`; туннель к Relay всё равно нужен.

## Что уже есть локально

| | |
|---|---|
| Логин | `chatgpt_coordinator` (пароль в `data/clients/chatgpt_coordinator_login.json`, 0600) |
| Страница входа | http://127.0.0.1:8765/login |
| Права | чтение задач/чата/отчётов; сообщения; создание/управление задачами **в пределах действующей delegation**; без owner / emergency-stop / ключей агентов |
| Сессия | Secure/HttpOnly cookie + CSRF; ключи не в URL и не в JS |

Владелец по-прежнему: Tailscale Serve → https://roma-gv628rc.tailbfec94.ts.net/login (`owner` / `cursor`).

## Внешний HTTPS без Tailscale у посетителя (бесплатно)

**Tailscale Funnel** — $0. Relay уже запущен с `NOZO_RELAY_EXTERNAL_PUBLIC_HOSTS`.

Костыль: тот же `*.ts.net` Host. Публичный Funnel (нет заголовка `Tailscale-User-Login`) → только координатор. Serve из tailnet (есть identity) → полная панель владельца.

## Важно про ChatGPT

| URL | Типичный ответ ChatGPT |
|---|---|
| `*.ts.net` (Funnel) | `remote connection failure` (блок по зоне) |
| `*.trycloudflare.com` | `Your request was blocked` (**Cloudflare** до Relay; в логах Relay запроса нет) |
| `*.lhr.life` (localhost.run) | обычно проходит; бесплатный SSH-туннель |

Актуальный URL: `cat /tmp/nozo-public-url.txt`  
Вход: `<URL>/login` → `chatgpt_coordinator` → пароль в `data/clients/chatgpt_coordinator_login.json`.

Поднятие lhr-туннеля:

```bash
ssh -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 \
  -R 80:127.0.0.1:8765 nokey@localhost.run
./scripts/run_relay_public.sh
```

## Пароль заново

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
uv run python scripts/set_chatgpt_coordinator_login.py
```
