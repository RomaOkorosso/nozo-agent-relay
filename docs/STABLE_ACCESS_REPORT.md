# Отчёт: устойчивый доступ Relay (2026-11-01)

## Итоговая архитектура

Основной транспорт: **Tailscale Funnel** на стабильном `https://roma-gv628rc.tailbfec94.ts.net` → `127.0.0.1:8765`.  
GitHub Pages SPA читает `gateway/pointer.json` и ходит в Relay с coordinator Bearer + CORS `.github.io`.  
Owner: loopback HTML login и/или Serve в tailnet. Cookie `Secure` выбирается **per-request**.

## Изменённые / добавленные файлы

- `src/nozo_relay/api/deps.py` — same-origin Origin fallback  
- `src/nozo_relay/api/auth_routes.py` — `cookie_secure_for_request`  
- `src/nozo_relay/ui/routes.py` — передача `request` в cookies; UX forbidden  
- `src/nozo_relay/api/cors.py` — OPTIONS без 405 для чужих Origin  
- `scripts/run_relay_stable.sh`, `ensure_tailscale_surface.sh`, `nozo_watchdog.sh`  
- systemd user: `~/.config/systemd/user/nozo-*.service` / `.timer`  
- `gateway/{app.js,index.html,app.css,pointer.json}` — состояния, pointer, drafts, msg idempotency  
- `tests/test_origin_login_cookies.py`, `tests/test_gateway_pointer.py`  
- `docs/OPERATOR_STABLE_ACCESS.md`, этот отчёт  
- `evidence/stable-access-2026-11-01/matrix.jsonl`

## Ветка / коммиты

Gateway-часть публикуется в `master` (Pages). Полное дерево `src/` исторически было незакоммичено в remote — рабочие файлы на диске; gateway commits отдельно.

## Локальная матрица (выполнено)

| Кейс | Результат |
|---|---|
| Local owner login + Origin | 303 + session cookie, без Origin-ошибки |
| Local /projects | 200 |
| Funnel coordinator /me + ACAO github.io | 200 |
| Idempotent message (double POST) | одна запись |
| Owner на «голом» Funnel Host | 403 |
| CORS evil Origin | без ACAO |
| Bad token | 401 |
| JSON health не HTML | ok |
| Restart Relay | local ready + public live, сообщения на месте |
| Coordinator GET /agents | 403 |

## Не завершено без Ромы / ChatGPT

- Реальный вход ChatGPT cloud browser на Pages (сценарий 1) — **нужно подтверждение**  
- Реальный телефон (сценарий 3) — **нужно подтверждение**  
- Полная перезагрузка ноутбука с linger — **не прогонялась** (Linger=no)  
- Сворачивание мобильного браузера — зависит от телефона  

## Ограничения бесплатного транспорта

См. `OPERATOR_STABLE_ACCESS.md`. Ноутбук offline = сервис offline. Funnel бесплатен в рамках личного Tailscale; платные API/туннели не подключались.
