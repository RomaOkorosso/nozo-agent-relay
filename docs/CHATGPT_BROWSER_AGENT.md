# Почему облачный браузер ChatGPT не открывает Relay

## Что происходит

Ссылка вида `https://roma-gv628rc.tailbfec94.ts.net/...` доступна **только устройствам в вашем Tailscale tailnet** (ноутбук, телефон с Tailscale).

Облачный браузер ChatGPT / Operator **не состоит в tailnet**, поэтому получает `remote connection failure`. Ключ Relay это **не чинит**: это сетевая граница, не ошибка логина.

Панель владельца `/login` и должна оставаться частной (Serve, не Funnel). Агенту ChatGPT браузерный owner-login **не выдаём**.

## Правильный канал для ChatGPT

| Канал | Для кого | Статус |
|---|---|---|
| HTTPS UI через Tailscale Serve | Owner / Cursor на ноутбуке и телефоне с Tailscale | работает |
| MCP `POST /mcp` + Bearer coordinator key | ChatGPT как coordinator | нужен маршрут из облака ChatGPT → ваш `/mcp` |
| Owner `/login` из ChatGPT | — | **не использовать** |

Credentials координатора (ключ, `delegation_id`, project):  
`data/clients/chatgpt_credentials.json` (режим 0600). В чаты/промпты ключ не копировать целиком без нужды.

Локальный MCP (с ноутбука): `http://127.0.0.1:8765/mcp`  
Tailnet MCP: `https://roma-gv628rc.tailbfec94.ts.net/mcp` (только из tailnet)

## Как дать ChatGPT доступ к MCP без открытия admin UI

Два варианта (нужно явное решение владельца):

### A. Tailscale Funnel только для MCP (публичный HTTPS + Bearer)

Открывает в интернет **только** путь MCP, не панель владельца. Все равно требуется Bearer key координатора.

```bash
# пример (уточнить актуальный синтаксис serve/funnel path на вашей версии):
sudo tailscale funnel --bg --set-path=/mcp http://127.0.0.1:8765/mcp
```

После включения в ChatGPT добавляется custom MCP на  
`https://roma-gv628rc.tailbfec94.ts.net/mcp` с auth Bearer из `chatgpt_credentials.json`.

Замечания:
- OAuth consent page в Relay ещё не реализована; если ChatGPT требует только OAuth — Funnel+Bearer может не хватить.
- Funnel = публикация в интернет; ACL приложения и ключ обязательны, но поверхность шире, чем Serve.

### B. Официальный Secure MCP Tunnel / ChatGPT Platform connector

Предпочтительный путь из design (T11): tunnel с Platform rights, без публикации admin UI. Требует проверки тарифа/прав аккаунта ChatGPT и отдельного согласия владельца. Не покупать доступ автоматически.

## Что делать владельцу в UI

1. Свой телефон / ноутбук: Tailscale ON → `https://roma-gv628rc.tailbfec94.ts.net/login` → проект → вкладка **Чат**.
2. ChatGPT: не слать ему `/login`; настроить MCP по варианту A или B.
3. Сообщения в чате Relay видят оба, когда ChatGPT пишет через `relay_post_message`, а вы — через UI.
