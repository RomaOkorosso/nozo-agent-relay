# Independent audit report — T12

- Auditor principal: Codex, независимый сеанс владельца от 2026-10-29.
- Project/task/revision/run: Nozo Agent Relay / T12 final audit (включает отложенный T05) / v1.0-draft.2 / audit-hbw3pu28.
- Snapshot ID: `07288eedf6a8b30cb9e118f7434585179136d634`; base/head отсутствуют (no commits). Рабочее дерево, 173 исходных файла.
- Reference tree без handoff/status: `ca63a22ca562ba0654c831896593bc5c9bcea268` — совпадает с handoff.
- SHA256 полного manifest: `3d0734a9c7df9d1c37ea0f79434d58f4f3c848eeaa92a837e810c71e6be5174f`.
- Environment: Linux 7.0.0-34-generic x86_64, Python 3.14.7, SQLite 3.53.1, uv 0.12.18; FastAPI 0.162.0, Starlette 1.10.0, SQLAlchemy 2.1.6, Pydantic 2.14.1, MCP 2.3.0, pytest 9.2.0, httpx 0.28.1, Uvicorn 0.54.0; real Codex CLI 0.156.1.
- Scope/criteria: design README/AGENTS, 02–06, 09_QA_CODEX, 10_IMPLEMENTATION_PLAN, tasks/T12_V1_AUDIT и implementation CODEX_AUDIT_HANDOFF.
- **Verdict: FAIL. Gate: NO-GO.**
- Production-исходники не изменены: сверены SHA256 всех 173 исходных файлов, differences=0. Добавлены только audit documents/evidence; нет commits/push/publish/sudo/покупок.

## Gates

| Stage/capability | Verdict | Основание |
|---|---|---|
| M0 | NO-GO | F02: любой runner проекта может подтвердить чужой stop; F03: лишний доступ runner к чату. Q32 real phone не доказан |
| M1 | NO-GO | F01: scope ceiling bypass; F05: incomplete restore |
| M2 | NO-GO | F04: host metadata mutation из sandbox; F02; production runner daemon отсутствует; Q27 blocked |
| M3 | NO-GO | F01 переносится в общие use cases; ChatGPT web/mobile не проверены, OAuth consent отсутствует |
| Local protocol regression | PASS в пределах существующих assertions | 408 passed, 4 skipped. Это не отменяет независимые failing tests |
| Local phone/browser | PASS / LOCAL_BROWSER | 3 Chrome tests (360×800/desktop), T11 12 passed; не физический телефон |
| Codex host audit | PASS / REAL_CLI ограниченно | 2 real tests passed; host_probe_no_landlock; full-cycle использует MOCK Cursor |
| Sandbox штатный probe | probe_pass, но isolation gate FAIL | exit 0; независимый chmod outside workspace успешен |
| Local MCP facade | regression PASS, overall guard FAIL | t10 в полной suite; F01/F03 не позволяют объявить безопасную интеграцию готовой |

## Выполненные проверки

| Check | Expected | Actual | Exit | Evidence |
|---|---|---|---|---|
| uv sync --extra mcp | dependencies installed | success | 0 | evidence/t12/sync.log |
| uv run pytest -q | штатная suite green | 408 passed, 4 skipped, 2 warnings, 229.73s | 0 | evidence/t12/pytest.log |
| python -m pytest -q (копия исходного venv) | fallback во время загрузки deps | 408 passed, 4 skipped, 227.57s | 0 | evidence/t12/pytest-existing-env.log |
| uv run --with playwright python -m pytest -q tests/test_t04_browser_smoke.py | real local Chrome | 3 passed, 25.24s | 0 | evidence/t12/browser.log, browser/ |
| python -m pytest -q tests/test_t11_phone_regression.py | honest receipts, UI controls | 12 passed, 5.89s | 0 | evidence/t12/phone.log |
| NOZO_RUN_REAL_CLI=1 uv run pytest -q -m real_cli | real providers or explicit blocker | 2 passed, Cursor auth skip; browser module also skip, 70.38s | 0 | evidence/t12/real-cli.log, codex_finds_defect.json, full_cycle_real_codex.json |
| python -m nozo_relay sandbox-probe | apply/deny/kill | probe_pass | 0 | evidence/t12/sandbox.log |
| python -m pytest -q tests/test_independent_audit.py | correct behavior per design | 8 failed, 3 passed, 3.87s | 1 | evidence/t12/independent.log, test_independent_audit.py |

Все запуски — в `/tmp/nozo-audit-hbw3pu28/repo`, на временных БД. Первые две baseline suites собрали штатные тесты до добавления независимого файла. Повторная baseline suite запущена, пока uv скачивал зависимости; новых признаков неисправности после её прохождения не было, дальнейших полных повторов не выполнялось.

## Qxx coverage achieved

Existing suite rerun означает независимый запуск существующих assertions, а не заново написанный independent harness для каждого Q. Дополнительный harness использует public HTTP и disposable fault injection, не меняет production и не ослабляет ожидаемое поведение.

| Qxx | Expected | Actual / status | Evidence |
|---|---|---|---|
| Q01–Q02 | idempotency/replay/conflict | PASS; дополнительно replay через restart и changed-body 409 | t02 + independent create_replay |
| Q03–Q05 | one lease/result; no duplicate effect | PASS fixture; независимые concurrent claims дали 200/204 | t03 + independent concurrent_claim |
| Q06 | durable replay после commit-before-notify crash | PASS штатные assertions | t02/t04 |
| Q07 | stale output rejected | PASS; independent cancel -> result 409 | t03 + independent concurrent_claim |
| Q08 | lease lost -> recovery, no parallel writer | PASS штатная lifecycle/sandbox regression; чужой reconcile boundary требует fix F02 | t03/t07 |
| Q09–Q10 | fence/kill + honest stop | PARTIAL/FAIL: normal tests pass, чужой supervisor переводит task в cancelled (F02) | t03/t07 + independent unrelated_supervisor |
| Q11–Q13 | failure budget, restart, loop detection | PASS штатные assertions | t03/t06 |
| Q14 | cross-project REST/WS/artifacts/messages/MCP isolation | PASS штатные cross-project assertions; same-project supervisor overread отдельно FAIL F03 | t06/t10 + independent supervisor_chat |
| Q15 | no role/authority escalation | FAIL F01/F02/F03 при PASS существующей regression | independent.log |
| Q16–Q17 | snapshot/epoch binding; no PASS with not_run | PASS; независимый not_run PASS -> 422, task reviewing | t03/t09 + independent not_run |
| Q18–Q21 | WS reconnect/slow/revoke; CSRF/Origin/XSS | PASS штатная suite + LOCAL_BROWSER | t01/t04, browser.log |
| Q22 | no secrets outside permitted boundary | PARTIAL: sentinel redaction tests pass; F04 позволяет менять host mode. Реальной утечки credentials не проводилось | t01/t07 + independent sandbox_chmod |
| Q23 | DB busy/full -> 503 or explicit block; no lost outbox | PARTIAL: busy test pass; injected disk-full -> 500/retryable=false F07; retry после fault ->201. Реальный ENOSPC/все routes не проверены | t04 + independent disk_full |
| Q24 | complete restore, history intact, sessions revoked | FAIL F05 при PASS штатных happy-path/migrate tests | t06 + independent incomplete_backup |
| Q25–Q26 | scope/shell isolation, original intact | PARTIAL/FAIL: штатные rename/symlink/binary/shell tests pass; chmod outside workspace succeeds F04 | t06/t07 + independent sandbox_chmod |
| Q27 | real Cursor edit/deny/cancel | NOT_VERIFIED / BLOCKED_EXTERNAL: no auth | real-cli.log |
| Q28 | real Codex independently finds defect | PASS REAL_CLI host mode, disposable fixture | codex_finds_defect.json |
| Q29 | exact auth/quota blockers | PASS fixture failures + actual Cursor auth blocker; live quota exhaustion not induced | t08/t09, real-cli.log |
| Q30–Q31 | real ChatGPT web/native/mobile separate receipts | NOT_VERIFIED | original t11 receipts, no new connection |
| Q32 | real phone private HTTPS, Wi-Fi/LTE/background/revoke | LOCAL_BROWSER PASS; real phone BLOCKED_EXTERNAL/NOT_VERIFIED | browser/, phone.log |
| Q33–Q34 | approval binding/single-use; paused project fairness | PASS штатные assertions; executor absent by design | t06/t03 |
| Q35 | serialized races cancel/result/revoke/revise | PASS штатные tests; дополнительно real threads concurrent claims | t03 + independent concurrent_claim |
| Q36 | hostile model JSON cannot execute/escalate | PASS mock parser checks + real Codex injection fixture; not a complete proof of all prompt injection | t07/t08/t09, codex_finds_defect.json |

## Findings

Полные repro/expected/actual/component/severity/fix scope: `../CODEX_FINDINGS.md`. 7 findings: F01–F04 S0 (authorization/isolation), F05 S1 (restore integrity), F06–F07 S2. S0/S1 блокируют соответствующие gates.

## Обязательные not_verified / limitations

- Q27 real Cursor, полноценный REAL Cursor→REAL Codex cycle; нет production runner daemon.
- Q30 ChatGPT web; Q31 native app и mobile web; MCP Inspector не запускался. Локальный SDK не считается ChatGPT.
- Q32 физический телефон/private HTTPS/Wi-Fi↔LTE/sleep; нет устройства/настроенного маршрута в аудите.
- Codex в production Landlock+provider egress не доказан; host-mode evidence не подтверждает его изоляцию.
- Q23 реальное исчерпание диска, каждый mutation route, все outbox crash windows; выполнена только контролируемая fault injection и штатные retry tests.
- Backup при непрерывной live-WAL нагрузке отдельно не проверялся; happy-path backup/restore regression прошла.
- Долговременная WS/load проверка, Safari/WebKit/Android, aarch64, airtight fast-double-fork cleanup без cgroup, disk quota, provider billing/overage — не проверены.
- Отсутствие изменений 173 исходных файлов доказано; универсальное отсутствие неизвестных secrets во всех исторических файлах не утверждается. Новые audit logs проверены на формат Relay keys, ключей не найдено.

## Итерация и следующий шаг

Первый независимый T12 round этого snapshot: FAIL. Live Relay failure counter не читался/не менялся; 8 падающих assertions — не 8 audit rounds. Исправить F01–F05 до GO; F06–F07 передать как диагностику/атомарность. Production daemon и OAuth consent — отдельные незавершённые capabilities. После исправлений передать новый tree hash, changelist и self-check; повторить repro и затронутую регрессию. При третьем неуспешном audit round или loop — остановить зависимый цикл и эскалировать owner.

Инструкция владельцу: `CODEX_AUDIT_RUNBOOK.md`. Полная v1 не объявляется готовой; публикация не выполнялась.
