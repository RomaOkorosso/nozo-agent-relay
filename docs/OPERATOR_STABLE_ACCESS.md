# Устойчивый доступ к Nozo Relay (бесплатно)

Обновлено: 2026-11-07. Ноутбук должен быть онлайн и в сессии пользователя `roma` (systemd --user).

**Инструкция «вставь в проект» для Ромы / Codex / ChatGPT:** [`CONNECT.md`](CONNECT.md).

## Архитектура

| Сценарий | Как |
|---|---|
| ChatGPT / браузер → coordinator | GitHub Pages → `pointer.json` → обычно **IPv4 `*.lhr.life`** (Bearer); Funnel `*.ts.net` — fallback (IPv6 у браузеров часто ломается) |
| Рома на ноутбуке → owner | `https://roma-gv628rc.tailbfec94.ts.net/login` (Serve) или `http://127.0.0.1:8765/login` |
| Рома с телефона | Tailscale + Serve (owner) **или** Pages + coordinator Bearer |

Funnel-hostname стабилен; **lhr.life hostname плавает** — актуальный URL только в опубликованном `pointer.json`.

## Службы (systemd --user)

```bash
systemctl --user status nozo-relay.service nozo-tailscale-surface.service nozo-ipv4-tunnel.service nozo-watchdog.timer
systemctl --user restart nozo-relay.service
systemctl --user start nozo-tailscale-surface.service
journalctl --user -u nozo-relay.service -n 50 --no-pager
tail -50 ~/.local/state/nozo-relay/relay.log
```

| Unit | Назначение |
|---|---|
| `nozo-relay.service` | Relay на `127.0.0.1:8765`, CORS для github.io + loopback + ts.net |
| `nozo-tailscale-surface.service` | `tailscale funnel --bg 8765` + обновление `pointer.json` при смене URL |
| `nozo-ipv4-tunnel.service` | бесплатный IPv4 SSH-туннель `nokey@localhost.run` (основной трафик Pages) |
| `nozo-watchdog.timer` | каждые 2 мин: health + мягкий refresh Funnel (+ может пушить pointer) |

### Полный стоп / старт (рекомендуется)

Чтобы **не жрать трафик** (localhost.run + Funnel probes) до следующего включения:

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
./scripts/nozo_stop.sh    # полный стоп, без трафика
./scripts/nozo_start.sh   # снова поднять
```

- `nozo_stop.sh` останавливает watchdog → ipv4-tunnel → surface → relay, убивает leftover SSH/`run_localhost_run_tunnel`, снимает Funnel (`tailscale funnel --https=443 off`) и Serve на `:443` (targeted; `serve reset` только если всё ещё проксирует `:8765`). По умолчанию ещё **`systemctl --user disable`** этих четырёх unit’ов — при `Linger=no` они **не** поднимутся после следующего графического логина. Флаг `--keep-enabled` — только временный стоп до reboot/login. `--dry-run` — показать действия без изменений.
- `nozo_start.sh` делает `enable --now` (relay → surface → ipv4-tunnel → watchdog.timer), ждёт local ready, при необходимости освежает surface. **Не** коммитит/пушит `pointer.json` сам; если pointer грязный — скажет.
- Честно: статическая GitHub Pages остаётся доступной; **API мёртв**, пока не сделан start. Демон `tailscaled` (OS) может продолжать работать — скрипты гасят только Nozo surface/tunnel/relay.

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
