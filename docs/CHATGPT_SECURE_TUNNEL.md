# Secure MCP Tunnel (вариант 2) + ваша админка

## Разделение ролей

| Кто | Как | URL |
|---|---|---|
| **Вы (админка)** | Tailscale Serve, логин `owner` или `cursor` | https://roma-gv628rc.tailbfec94.ts.net/login |
| **ChatGPT** | Secure MCP Tunnel → локальный MCP stdio (coordinator) | не `/login`, а Connectors → Tunnel |

Админку в интернет через Funnel **не** открываем. Облачный браузер ChatGPT в tailnet не входит — это нормально.

## Что уже сделано на ноутбуке

- Relay слушает `127.0.0.1:8765`, Serve → HTTPS в tailnet.
- Coordinator key: `data/clients/chatgpt_credentials.json`
- `tunnel-client` 0.0.18 установлен в `~/.local/bin/tunnel-client`
- Скрипт: `./scripts/run_chatgpt_tunnel.sh`

## Что нужно сделать вам (секреты только у вас)

### 1. Platform: туннель и runtime key

1. Откройте [Tunnels](https://platform.openai.com/settings/organization/tunnels)  
   - права: **Tunnels Read + Manage** (создание), для runtime — **Read + Use**  
   - привяжите туннель к **ChatGPT workspace**, которым пользуетесь  
2. Создайте tunnel → скопируйте `tunnel_id`  
3. [Runtime API keys](https://platform.openai.com/settings/organization/api-keys) → ключ с Tunnels Use  
4. Сохраните **локально** (не в Git, не в чат):

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
mkdir -p data/tunnel && chmod 700 data/tunnel
printf '%s' 'tunnel_XXXXXXXX' > data/tunnel/tunnel_id
printf '%s' 'sk-XXXXXXXX'     > data/tunnel/runtime_api_key
chmod 600 data/tunnel/tunnel_id data/tunnel/runtime_api_key
```

**Стоимость / доступность туннеля** зависят от вашего тарифа Platform/ChatGPT — я ничего не покупаю. Если UI требует оплату или прав нет — это blocker от аккаунта.

### 2. Запуск туннеля (ноутбук онлайн)

```bash
./scripts/run_chatgpt_tunnel.sh
```

Оставить процесс живым. Проверка: URL `/ui` / `/readyz`, который печатает клиент.

### 3. ChatGPT

1. https://chatgpt.com/#settings/Connectors  
2. Add custom MCP server → **Connection: Tunnel** → выбрать тот же tunnel / вставить `tunnel_id`  
3. Authentication: **No authentication** (ключ координатора уже внедрён в stdio на ноутбуке; наружу не уходит)  
4. Подтвердить риск → Create → Install plugin  
5. В чате: `@` → ваш plugin → например list projects / create task  

Ожидаемо: ChatGPT **не** входит в `/login` и **не** получает owner-права. Только tools координатора (задачи, сообщения, limited control, request approval — без approve/publish).

## Если застряли

| Симптом | Действие |
|---|---|
| Нет пункта Tunnels / «Tunnels access required» | Роли в Platform organization (People → Roles/Groups) |
| Туннель не виден в ChatGPT | Привязка tunnel ↔ ChatGPT workspace |
| doctor/run fail | `tunnel-client doctor --profile nozo-relay-chatgpt --profile-dir data/tunnel/profiles --explain` |
| MCP auth errors | Проверить `chatgpt_credentials.json` и что Relay/data_dir те же |
| Нужен OAuth вместо no-auth | Consent page в Relay ещё 404 — отдельная задача |

После того как положите `tunnel_id` и runtime key в `data/tunnel/`, напишите — запущу `./scripts/run_chatgpt_tunnel.sh` и проверим `/readyz`.
