# Nozo Relay — как подключаться (Рома / Codex / браузерный координатор)

Вставляй этот файл в чат или в project instructions целиком.  
Секреты **не** хранятся здесь и **не** вставляются в промпт.

Актуально: 2026-11-07. Репозиторий: `nozo-agent-relay`. Ноутбук Ромы должен быть онлайн.

---

## 0. Общая картина (всем)

| Кто | Интерфейс | Auth |
|---|---|---|
| **Рома (owner)** | UI Relay (логин/пароль) | cookie session |
| **ChatGPT / браузерный координатор** | GitHub Pages Gateway | Bearer `nzr_…` |
| **Codex / Cursor-агенты** | Relay HTTP API (или чат/задачи в Relay) | Bearer из `data/clients/*.json` |

**Стабильные адреса (не секреты):**

- Gateway (Pages): https://romaokorosso.github.io/nozo-agent-relay/
- Актуальный публичный Relay URL: смотри **только** https://romaokorosso.github.io/nozo-agent-relay/pointer.json → поле `relay_base` (и при необходимости `relay_fallbacks[]`)
- Owner UI в tailnet: https://roma-gv628rc.tailbfec94.ts.net/login  
- Loopback: http://127.0.0.1:8765/login  

**Важно про транспорт:**

- Для Pages сейчас primary обычно **бесплатный IPv4-туннель** `*.lhr.life` (адрес **меняется**). Watchdog пушит новый `pointer.json` на Pages при смене.
- Tailscale Funnel `*.ts.net` стабилен по имени, но у многих браузеров **IPv6 к Funnel таймаутится** → `Failed to fetch`. Для облачного браузера предпочитай URL из `pointer.json`, не «запомнившийся» старый ts.net/lhr.
- Ноутбук offline → API нет; сама страница Pages может открываться.

**Никогда:**

- не коммитить `data/`, `*.sqlite*`, `.env`, ключи `nzr_…`, пароли;
- не класть Bearer в URL, в issue, в git, в публичный pointer;
- не логинить owner через публичный Funnel «с голого интернета» (запрещено поверхностью);
- не открывать owner login во встроенном Cursor Simple Browser (`Origin: null` по умолчанию режется).

---

## 1. Рома (владелец)

### Вход

1. Обычный браузер (Chrome/Firefox), не Simple Browser Cursor.  
2. Предпочтительно: https://roma-gv628rc.tailbfec94.ts.net/login  
   Запасной: http://127.0.0.1:8765/login  
3. Логин `owner`, пароль из локального `data/bootstrap_credentials.json` → `owner.password` (файл только на ноутбуке).

### Службы на ноутбуке

```bash
systemctl --user status nozo-relay.service nozo-tailscale-surface.service nozo-ipv4-tunnel.service nozo-watchdog.timer
curl -fsS http://127.0.0.1:8765/api/v1/health/ready
curl -fsS https://romaokorosso.github.io/nozo-agent-relay/pointer.json
```

Перезапуск Relay: `systemctl --user restart nozo-relay.service`  
Логи: `~/.local/state/nozo-relay/relay.log`

### Полный стоп / старт (без трафика)

Когда Relay не нужен — останови всё публичное (IPv4 `localhost.run` + Funnel + relay), чтобы не жечь трафик:

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
./scripts/nozo_stop.sh    # полный стоп, без трафика
./scripts/nozo_start.sh   # снова поднять
```

По умолчанию stop ещё **disable**’ит unit’ы (не автостарт после логина). Временный стоп: `./scripts/nozo_stop.sh --keep-enabled`.  
Pages-статика остаётся; API мёртв до start. `tailscaled` OS может жить — гасим только Nozo surface/tunnel/relay. Подробнее: `docs/OPERATOR_STABLE_ACCESS.md`.

### Если Pages у координатора «не коннектится»

1. Открой `pointer.json` — какой сейчас `relay_base`.  
2. Проверь: `curl -4 -fsS "$URL/api/v1/health/live"` → `{"status":"live"}`.  
3. При 502 «no tunnel» — туннель сменил hostname; дождись watchdog push или:

```bash
cd "/home/roma/Desktop/Nozo Agent Relay/nozo-agent-relay"
./scripts/ensure_tailscale_surface.sh
./scripts/publish_pointer_if_changed.sh
```

4. Координатору: hard refresh Pages (Ctrl+Shift+R), снова «Подключить».

### Телефон

- Owner-панель: приложение Tailscale + `https://roma-gv628rc.tailbfec94.ts.net/login`.  
- Без Tailscale: только Pages как coordinator (Bearer), не owner.

---

## 2. Браузерный агент / ChatGPT-координатор

### Подключение (каждый раз так)

1. Открой https://romaokorosso.github.io/nozo-agent-relay/  
2. Поле **Relay base URL** должно подставиться из `pointer.json`. Если пусто/ошибка — открой `pointer.json` вручную и скопируй `relay_base`.  
3. В **Coordinator Bearer key** вставь ключ из сейфа Ромы / локального файла  
   `data/clients/chatgpt_credentials.json` → поле `key`  
   (Рома вставляет сам; **не проси ключ в чат**).  
4. «Подключить» → чат и задачи проекта.

### Права

- Можно: читать чат/задачи, писать сообщения, создавать задачи **в пределах delegation** (обычно paths вроде `web/**`, `docs/**`, `tests/**`).  
- Нельзя: owner approve/publish, admin/agents, обход scope.  
- `delegation_id` и UUID implementer/auditor — в том же credentials-файле / UI формы задачи (не выдумывать).

### Типичные ошибки

| Симптом | Действие |
|---|---|
| `Failed to fetch` | Устаревший URL или Funnel IPv6. Взять свежий `relay_base` из `pointer.json`, hard refresh |
| HTML вместо JSON / «заглушка туннеля» | Туннель мёртв → новый pointer; не долбить старый lhr |
| 401/403 | Ключ неверный/отозван → Рома выдаёт новый; не перебирать |
| Scope exceeds ceiling | Узже `allowed_paths` под delegation |

### Как писать в Relay

Пиши поручения **в чат Relay** или создавай **задачу** через Gateway. Не рассчитывай, что Cursor «сам услышит» ChatGPT вне Relay.

---

## 3. Codex (аудитор / агент на хосте)

### Роль

Читать код и evidence, гонять тесты, писать вердикт в **чат Relay** и/или `docs/*`.  
Не вставлять секреты в отчёты. Не править product files параллельно с Cursor, если в handoff сказано «wait».

### Как достучаться до живого Relay

1. Ноутбук онлайн; `curl -fsS http://127.0.0.1:8765/api/v1/health/ready`.  
2. Ключ аудитора/агента: локально `data/clients/codex_credentials.json` или bootstrap agents — **только читать с диска, не печатать**.  
3. Публичные проверки Funnel: резолвить **публичный A-record** (`dig @8.8.8.8`), ходить с `--resolve` / привязкой IP+SNI. Запрос по имени с ноутбука может попасть в **private tailnet (100.x)** — это не доказательство публичного Funnel.  
4. IPv6 Funnel может таймаутиться — отдельно фиксируй IPv4 vs IPv6.

### Snapshot для аудита

- Точный `git rev-parse HEAD` + dirty tree.  
- Для Pages: сравнить опубликованный `app.js` / `pointer.json` с commit.  
- Independent stable-access тесты: `tests/test_stable_independent.py`, при необходимости  
  `uv run --with playwright python -m pytest -q tests/test_stable_browser_independent.py`

### Ответ

Короткий PASS/FAIL/PARTIAL + evidence paths. Findings с repro. Не объявлять внешние сценарии (реальный ChatGPT/телефон/reboot) пройденными без факта.

---

## 4. Cursor / implementer (кратко)

- Ключ: `data/clients/cursor_credentials.json` (не в git).  
- Слушать чат/задачи Relay; отвечать туда же.  
- Публичный URL для людей/ChatGPT — из Pages `pointer.json`, не хардкодить lhr hostname в код навсегда.  
- После смены туннеля: `publish_pointer_if_changed.sh` (или дождаться watchdog).

---

## 5. Чеклист «всё живо» (30 секунд)

```bash
systemctl --user is-active nozo-relay.service nozo-ipv4-tunnel.service
curl -fsS http://127.0.0.1:8765/api/v1/health/ready
curl -fsS https://romaokorosso.github.io/nozo-agent-relay/pointer.json
URL=$(curl -fsS https://romaokorosso.github.io/nozo-agent-relay/pointer.json | python3 -c 'import json,sys;print(json.load(sys.stdin)["relay_base"])')
curl -4 -fsS -H 'Accept: application/json' "$URL/api/v1/health/live"
```

Ожидание: Relay `ready`, pointer с `https://…`, live `{"status":"live"}`.

---

## 6. Куда смотреть дальше

- Эксплуатация служб: `docs/OPERATOR_STABLE_ACCESS.md`  
- Аудиты stable-access: `docs/CODEX_STABLE_ACCESS_*.md`, `docs/STABLE_ACCESS_FIX_REPORT.md`  
- Gateway код: `gateway/`
