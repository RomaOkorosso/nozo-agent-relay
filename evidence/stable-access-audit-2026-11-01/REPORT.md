# Независимый аудит Stable Access — 2026-11-01

**Вердикт: FAIL / NO-GO для утверждения «устойчивый публичный доступ только coordinator».** Текущий HTTP-доступ работает, но WebSocket обходит ограничение публичной поверхности; автоматическое восстановление имеет воспроизводимые дефекты.

Аудитор: Codex. Объект: `docs/STABLE_ACCESS_REPORT.md`, `docs/OPERATOR_STABLE_ACCESS.md`, связанные Gateway/Relay/scripts и установленные systemd user units. Это отдельный аудит stable-access, не повтор всего T12.

Snapshot: HEAD `9deb042552a276c94e1250680878664612010584` плюс untracked working tree. SHA256 snapshot.json: `69b96a1e3823da2a00696e34ca0fc6644b6894f5170d600450c9908a9283586c`. Проверено 260 исходных файлов: изменений со стороны аудита нет. HEAD сам по себе не описывает src/, поскольку эти файлы всё ещё untracked; точные hashes — `evidence/stable-access-audit-2026-11-01/snapshot.json`. Копия для тестов: `/tmp/nozo-stable-audit-ozjmwsl2/repo`.

Окружение: Python 3.14.7, SQLite 3.53.1, FastAPI 0.162.0, Starlette 1.10.0, pytest 9.2.0, Chrome 155.0.8059.39, Tailscale 1.104.4.

## Что подтверждено

- Local ready и HTTPS live возвращают 200 JSON; Pages pointer.json и app.js доступны и побайтово совпадают с проверенной копией.
- nozo-relay.service running/enabled, nozo-tailscale-surface.service active(exited)/enabled, watchdog.timer active(waiting)/enabled; Linger=no, как заявлено в runbook. Аудит не перезапускал/останавливал службы и не менял Funnel.
- HTTPS через **публичный IP** 176.58.88.82 с исходным hostname/SNI и обычной проверкой сертификата: health 200; GET /api/v1/agents 404; подставные Tailscale-User-Login/Name не изменили 404; auditor GET /me 403; Pages preflight 204 с ACAO.
- Fixture owner login на public Host без identity headers даёт 403 и не выпускает cookie. Реальные owner credentials для входа не использовались.
- 53 профильных штатных теста passed. Пять старых независимых Gateway regression tests теперь passed: прежние retry/reload/limit/list дефекты не воспроизвелись.
- Новый browser test подтвердил retry сообщения после потери ответа/reload с тем же operation key; восстановление уже подключённой вкладки через обновлённый pointer тоже прошло. Эти два теста используют настоящий Chrome и **mock transport**, не реальный ChatGPT/телефон.

## Findings

Всего 8 findings: 1 S0, 3 S1, 4 S2. Содержимое приватных событий и ключи в evidence не сохранялись.

### SA-01 — S0: публичный WebSocket обходит coordinator-only boundary

Компоненты: `src/nozo_relay/api/external_surface.py:95`, `src/nozo_relay/ws/routes.py:46`, `src/nozo_relay/main.py:162`.

Repro: тем же действующим auditor key выполнить GET /api/v1/me через публичный Funnel (403), затем открыть `wss://<public-host>/ws/v1/projects/<project-id>?after_seq=0` с Bearer. Подключаться к публичному DNS IP, сохраняя TLS hostname, чтобы исключить private tailnet.

Expected: WebSocket handshake отклонён до accept; в текущем external-surface allowlist WS намеренно отсутствует.

Actual: **101 Switching Protocols**, получен frame типа `delegation.created` с данными проекта. Это реальная публичная проверка, не только TestClient. Доступ всё ещё требует действующего ключа и project membership; анонимного/cross-project доступа этим тестом не обнаружено.

Причина: ExternalSurfaceMiddleware наследует BaseHTTPMiddleware и не обрабатывает ASGI websocket; WS authenticate отдельно допускает implementer/auditor и не проверяет external-public policy.

Evidence: `public-ws-probe.json`, сопоставить `public-probe.json`; independent `test_public_surface_denies_auditor_websocket` также failing.

Fix scope: единая проверка публичной поверхности для HTTP и WS до accept. При текущем контракте — запрет WS на публичном Funnel, сохранив private tailnet/loopback. Regression: anonymous, auditor, implementer, coordinator и owner-cookie; private routes продолжают работать.

### SA-02 — S1: watchdog не восстанавливает Funnel, если остался только Serve

Компонент: `scripts/nozo_watchdog.sh:21`.

Repro на disposable shell fixtures: local ready=200, `tailscale funnel status` печатает `https://<host> (tailnet only)` без Funnel on. Выполнить watchdog.

Expected: отличить Serve-only от Funnel и вызвать предусмотренное восстановление публичного маршрута.

Actual: regex `<HOST>|Funnel on|https://` считает любой HTTPS/этот hostname достаточным; `ensure_tailscale_surface.sh` не вызывается. Проверка URL с этого же ноутбука может дополнительно вернуть private tailnet success. Публичный маршрут остаётся отключён.

Evidence: `test_watchdog_repairs_serve_only_surface` в independent.log; log stub фиксирует только `tailscale funnel status`, ни одного `funnel --bg`. Live Funnel не отключался.

Fix: разбирать структурированный статус/AllowFunnel и точный target/port; не использовать альтернативы, совпадающие с private Serve. Отдельно проверять публичную доступность.

### SA-03 — S2: HTML ошибочно признаётся успешным JSON health

Компонент: `scripts/nozo_watchdog.sh:28`. Repro: HTTP 200 body `<html><script>const x={};</script>proxy error</html>`. Expected: malformed/non-JSON health не получает public_ok. Actual: наличие символа `{` приводит к `public_ok`, exit 0.

Evidence: `test_watchdog_does_not_accept_html_with_brace`. Fix: HTTP status + JSON parse + ожидаемый status live, при необходимости Content-Type. Также проверять JSON error-объекты вместо одной фигурной скобки.

### SA-04 — S2: ошибка обновления Funnel скрывается успешным exit

Компонент: `scripts/ensure_tailscale_surface.sh:27`. Repro: статус содержит Funnel on, но `tailscale funnel --bg <port>` возвращает 1 (например, отказ смены target). Expected: ошибка применения конфигурации видна вызывающему unit. Actual: `|| true` проглатывает её; script пишет/подтверждает pointer и завершается 0.

Evidence: `test_surface_refresh_failure_is_not_success`. Fix: проверить конечную конфигурацию и вернуть ошибку, если требуемый port/target не применён; не объявлять успешное обновление pointer до проверки.

### SA-05 — S1: сохранённый мёртвый URL блокирует переход на новый pointer при старте

Компоненты: `gateway/app.js:706`, `:280`, `:366`.

Repro: в sessionStorage savedBase=A, savedKey=fixture; pointer.json отдаёт рабочий B; A недоступен. Открыть/перезагрузить Gateway.

Expected: recovery рассматривает новый pointer и восстанавливает соединение либо предоставляет рабочий B как очевидный вариант; старый URL не должен постоянно побеждать актуальный указатель.

Actual: pointer получен, но выбирается savedBase; connect(A) падает, showConnect вызывает stopPoll. Проверено после 16 s виртуального browser time: запроса /me к B нет. Пользователь остаётся на форме с устаревшим A. Отдельно проверенный fallback **уже подключённой** вкладки работает — проблема именно startup/reload.

Evidence: `test_startup_uses_current_pointer_if_saved_endpoint_dead`, browser-independent.log. Fix: bounded startup recovery и явное применение нового доверенного pointer, без бесконечных повторов и отправки ключа на произвольный untrusted URL.

### SA-06 — S2: UI-инструкция сброса отклонённого сообщения не работает

Компоненты: `gateway/app.js:578`, `:587`, `:542`, `:333`.

Repro: POST сообщения получает окончательный 422. Изменить текст; UI предлагает очистить поле и отключиться/подключиться. Выполнить эти шаги.

Expected: отклонённое сообщение можно исправить или явно отменить, сохранив защиту unknown-outcome retries.

Actual: pendingMsg сохраняется в sessionStorage, disconnect его не очищает, reconnect восстанавливает старый текст. Новый текст снова отклоняется клиентом. У сообщения нет отдельного discard control. Пользователь застревает без очистки storage/новой вкладки.

Evidence: `test_rejected_message_can_be_cleared_by_documented_ui_steps`. Fix: различать окончательный отказ и неизвестный исход, дать реальный reconcile/discard путь; не удалять pending вслепую после сетевого timeout.

### SA-07 — S1: Origin:null доверяется по адресу назначения, а не источнику

Компонент: `src/nozo_relay/api/deps.py:88–114`.

Repro в disposable API: POST /api/v1/auth/login с корректным fixture owner password и Origin:null. Expected по исходному security contract: неизвестный opaque origin отклонён; Host allowlist не заменяет Origin allowlist. Actual: 200 и session cookie.

Условие допуска смотрит на доверенный **Host назначения** (loopback/allowed_hosts/external host); эти адреса и так допустимы для всех клиентов. Origin:null бывает не только у IDE, но и у opaque/sandboxed документов, поэтому это не надёжный признак доверенного клиента.

Evidence: `test_null_origin_does_not_bypass_login_origin_boundary`; штатный тест специально закрепляет разрешение null, поэтому 53 passed не покрывают эту границу корректно.

Impact: ослаблена защита login от cross-origin инициирования; пароль всё ещё обязателен, CSRF-token на последующих session mutations остаётся. В этом аудите не доказана кража cookie, обход пароля или полноценный browser exploit; finding не утверждает этого. Fix: не разрешать null глобально, выделить ограниченный opt-in local-dev профиль либо использовать обычный браузер. Дополнительно зафиксировать изменение SameSite Strict→Lax относительно design 05_SECURITY, а не считать его нейтральным refactor.

### SA-08 — S2: таблица отчёта противоречит сохранённому evidence

Компоненты: `docs/STABLE_ACCESS_REPORT.md:34`, `evidence/stable-access-2026-11-01/matrix.jsonl`, `docs/OPERATOR_STABLE_ACCESS.md:47`.

Отчёт заявляет owner public Funnel 403, но matrix.jsonl содержит `funnel_owner_login: http=303, forbidden=false`. Эти значения не подтверждают заявленный PASS. На данном ноутбуке обычный DNS hostname возвращает 100.108.253.65 (tailnet), а публичный DNS — публичные Funnel IP. Поэтому запрос по имени с ноутбука нельзя автоматически считать интернет/Funnel проверкой. Точную причину старого результата без сохранённого network path восстановить нельзя; private routing — обоснованное объяснение, не доказанный факт того запуска.

Новый аудит разделяет private HTTP, публичный IP/SNI и fixture owner login. Последний действительно даёт 403; это не заменяет недостающий прежний live owner receipt.

Также фраза «ноутбук offline → Pages и Funnel недоступны» неверна для статических Pages: недоступны Relay API/операции, сама страница размещена отдельно. Surface script пишет local pointer; публикация Pages при смене hostname требует отдельного commit/push, что правильно упомянуто ниже в runbook, но не является автоматическим recovery.

Fix: исправить таблицу по фактическим данным и повторить разделённые acceptance checks с timestamp, network route, snapshot и exit codes.

## Проверки и evidence

| Команда / проверка | Итог | Exit | Evidence |
|---|---|---|---|
| uv sync --extra mcp (audit copy) | success | 0 | sync.log |
| uv run pytest -q tests/test_origin_login_cookies.py tests/test_gateway_pointer.py tests/test_gateway_cors.py tests/test_chatgpt_coordinator_browser.py tests/test_t01_foundation.py | 53 passed, 7.88s | 0 | baseline.log |
| uv run pytest -q tests/test_stable_independent.py | 5 failed, 1 passed, 1.41s | 1 | independent.log |
| uv run --with playwright python -m pytest -q tests/test_stable_browser_independent.py | 2 failed, 2 passed, 3.97s | 1 | browser-independent.log |
| uv run --with playwright python -m pytest -q tests/test_gateway_previous_regression.py | 5 passed, 7.91s | 0 | previous-gateway-regression.log |
| bash -n scripts/run_relay_stable.sh scripts/ensure_tailscale_surface.sh scripts/nozo_watchdog.sh | shell syntax valid | 0 | command ledger |
| systemctl --user cat/show; loginctl show-user; tailscale version/funnel status | read-only live inventory | 0 | systemd-*, linger, tailscale-version, funnel-status |
| HTTP health/Pages + public DNS read | 200; published assets match copy | 0 | live-http.json, public-dns.json, published-* |
| public_probe.py (HTTP through forced public IP, verified TLS/SNI) | expected HTTP restrictions passed | 0 | public-probe.json |
| public_ws_probe.py (same public IP, own auditor credential) | prohibited WS accepted: 101 + event | 0 script / FAIL assertion | public-ws-probe.json |
| source SHA256 verification | 260 original files unchanged | 0 | integrity.json |

Evidence directory: `evidence/stable-access-audit-2026-11-01/`. Independent tests should be copied to `tests/` in a separate snapshot copy so that conftest/fixture imports resolve. All shell fault scenarios substitute curl/tailscale in a private PATH; live system configuration was not mutated. Browser fault tests use sentinel credentials and mock HTTP transport; earlier Gateway regression uses disposable real Relay application.

Intermediate browser harness initially checked recovery before asynchronous completion; corrected synchronization to await the changed endpoint, without changing expected product behavior. Final 2 failed/2 passed replaces that harness timing result. No production tests or expectations were weakened.

## Осталось NOT_VERIFIED

- Actual ChatGPT cloud browser coordinator login/create/retry/revoke through this stable Funnel. No чужие coordinator/owner credentials used.
- Physical phone, Wi-Fi/LTE, background/sleep, tagged-device identity and mobile cookie behavior.
- Full reboot/logout/linger; live crash/restart/recovery with active workloads. Linger=no подтверждён; sudo и reboot не выполнялись.
- All historical T12 fixes and production real-agent cycle: not the scope of this audit. Full suite not rerun; only relevant regression and new negative tests.
- Full owner-cookie live public WS rejection after fix (current auditor bypass already sufficient for NO-GO).

## Основания и следующий шаг

Критерии: утверждения двух проверяемых документов и design 05_SECURITY (Origin/Host/CSRF, session boundaries). Для интерпретации transport использована [официальная документация Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve#identity-headers): identity headers различают tailnet и публичный Funnel, входные identity headers очищаются прокси. Не считается vulnerability возможность вручную подставить такие headers напрямую на loopback: эта доверенная граница требует проверки через фактический proxy. Публичный spoof test в этом аудите прошёл.

Исправить SA-01 до признания coordinator-only exposure безопасным; затем WS/HTTP parity regression. Для устойчивости исправить SA-02/SA-05, классификацию health и failure propagation; закрыть message recovery и Origin:null. Исправить evidence таблицу, затем повторить affected checks на новом exact snapshot. Это первый аудит данного stable-access snapshot; не сбрасывает историю других audit задач. Production-исходники и исходные два документа аудитом не менялись.
