# Устойчивый доступ к Nozo Relay (бесплатно)

Обновлено: 2026-11-01. Ноутбук должен быть онлайн и в сессии пользователя `roma` (systemd --user).

## Архитектура

| Сценарий | Как |
|---|---|
| ChatGPT / любой браузер → coordinator | GitHub Pages `https://romaokorosso.github.io/nozo-agent-relay/` → API на **Tailscale Funnel** `https://roma-gv628rc.tailbfec94.ts.net` (Bearer) |
| Рома на ноутбуке → owner | `http://127.0.0.1:8765/login` **или** `https://roma-gv628rc.tailbfec94.ts.net/login` из tailnet (Serve) |
| Рома с телефона | Tailscale app + Serve URL (owner) **или** Pages + coordinator Bearer (мобильный интернет через Funnel) |

Адрес Funnel **стабилен** (hostname ноды). Эфемерные lhr.life/Pinggy больше не нужны как основной транспорт.

Публичный указатель без секретов: `gateway/pointer.json` (Pages отдаёт его рядом со SPA).

## Службы (systemd --user)

```bash
systemctl --user status nozo-relay.service nozo-tailscale-surface.service nozo-watchdog.timer
systemctl --user restart nozo-relay.service
systemctl --user start nozo-tailscale-surface.service
journalctl --user -u nozo-relay.service -n 50 --no-pager
tail -50 ~/.local/state/nozo-relay/relay.log
```

| Unit | Назначение |
|---|---|
| `nozo-relay.service` | Relay на `127.0.0.1:8765`, CORS для github.io + loopback + ts.net |
| `nozo-tailscale-surface.service` | `tailscale funnel --bg 8765` + обновление `pointer.json` при смене URL |
| `nozo-watchdog.timer` | каждые 2 мин: health + мягкий refresh Funnel |

Остановка:

```bash
systemctl --user stop nozo-watchdog.timer nozo-tailscale-surface.service nozo-relay.service
tailscale funnel --https=443 off   # снять публичный Funnel
```

Восстановление после аварии процесса: `Restart=on-failure` у Relay; watchdog/поверхность поднимают Funnel снова.

**Linger:** сейчас `Linger=no` — user-службы стартуют после входа в KDE. Для старта до логина: `sudo loginctl enable-linger roma` (нужен пароль sudo).

## Ограничения (честно)

- Ноутбук выключен / нет интернета → **Relay API и Funnel недоступны**; статическая GitHub Pages страница при этом может открываться, но операции к Relay не работают.
- Funnel публично открывает **только coordinator HTTP/API** (без WebSocket; owner login с «голого» интернета запрещён).
- С телефона owner-панель требует Tailscale на телефоне; без него — только Pages как coordinator.
- `gateway/pointer.json` обновляется локально скриптом surface; **публикация на Pages — отдельный commit/push**, не авто-recovery.
- OpenAI Platform MCP Tunnel / платные туннели **не** используются в этом профиле.
- Смена hostname Tailscale (редко) → обновить `NOZO_RELAY_PUBLIC_HOST`, перезапустить surface, закоммитить и запушить новый `pointer.json`.
- Origin:null (Cursor Simple Browser) по умолчанию **отклонён**; используйте обычный браузер или (только loopback) `NOZO_RELAY_ALLOW_OPAQUE_ORIGIN=1`.

## Проверки состояния

```bash
curl -fsS http://127.0.0.1:8765/api/v1/health/ready
curl -fsS https://roma-gv628rc.tailbfec94.ts.net/api/v1/health/live
tailscale funnel status
```
