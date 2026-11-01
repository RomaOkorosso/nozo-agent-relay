# Независимые findings Codex — T12

Дата: 2026-10-29. Design v1.0-draft.2. Snapshot `07288eedf6a8b30cb9e118f7434585179136d634`; HEAD отсутствует.

**Verdict FAIL / NO-GO.** 7 findings: 4 S0, 1 S1, 2 S2. Production-код не исправлялся.

Environment: Linux 7.0.0-34-generic x86_64, Python 3.14.7, SQLite 3.53.1.
Evidence: `evidence/t12/independent.log`; 11 независимых assertions: 8 failed (два относятся к F01), 3 passed.
Каждый failed test ожидает правильное поведение, а не закрепляет дефект. Все данные disposable.

Воспроизведение в отдельной копии:

```bash
cp evidence/t12/test_independent_audit.py /path/to/audit-copy/tests/test_independent_audit.py
cd /path/to/audit-copy
uv sync --extra mcp
uv run pytest -q tests/test_independent_audit.py
```

Тесты используют существующий Api helper только как транспорт/fixture setup; ожидаемые решения взяты из design. В sandbox-тесте используется реальный launcher, без отключения ограничений.

## F01 [S0] Scope ceiling обходится заменой glob

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `scope.ceiling.subset`. Component: `src/nozo_relay/services/acl.py:128`.
- Preconditions/repro: Owner задаёт allowed_paths=[src/*.py] в delegation или project policy; coordinator/owner создаёт task с allowed_paths=[src/*.sh].
- Expected: 403 для coordinator, 422 для project policy; новой задачи нет.
- Actual: Оба POST вернули 201. Сравниваются только префиксы до wildcard (src/), расширение .py теряется.
- Evidence/regression: `test_delegation_cannot_widen_file_glob / test_project_policy_cannot_widen_file_glob` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: M1 и M3; authority ceiling нельзя считать enforceable.
- Предполагаемая область исправления: Проверять включение glob-языков консервативно; если включение не доказано — отказ. Повторить REST/MCP create, revise, enqueue и scope manifests.
- Fingerprint: Relay не вызывался; не выдуман.

## F02 [S0] Посторонний supervisor подтверждает чужую остановку

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `supervisor.run.ownership`. Component: `src/nozo_relay/services/controls.py:650`.
- Preconditions/repro: Запустить run с runner_instance_id=original-supervisor; owner cancel; после этого зарегистрировать unrelated runner и отправить stopped для старого run.
- Expected: 403/404; stop_requested сохраняется до receipt владельца run.
- Actual: HTTP 200; task=cancelled. Проверяется только runner kind + membership проекта, привязки credential к run нет. Физический child в этом API-repro не запускался; доказан обход авторизации receipt, а не фактическое убийство процесса.
- Evidence/regression: `test_unrelated_supervisor_cannot_confirm_another_run` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: M0/M2; чужой ключ может создать ложное подтверждение остановки, а при reassign разрешить дальнейшую работу.
- Предполагаемая область исправления: Серверная неизменяемая привязка supervisor principal к run, проверка stopped и reconcile. Строка runner_instance_id из запроса сама по себе не является доказательством владения.
- Fingerprint: Relay не вызывался; не выдуман.

## F03 [S0] Runner читает полный чат проекта вместо lifecycle metadata

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `supervisor.read.minimum`. Component: `src/nozo_relay/services/acl.py:30`.
- Preconditions/repro: Owner пишет сообщение; зарегистрированный runner проекта выполняет GET /projects/{p}/messages.
- Expected: 403/404: security matrix разрешает supervisor только lifecycle metadata собственных runs.
- Actual: HTTP 200 с сообщениями проекта. Общая membership проверка даёт runner права чтения чата.
- Evidence/regression: `test_supervisor_cannot_read_project_chat` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: M0/M1/M3 boundary; раскрытие данных сверх утверждённой роли.
- Предполагаемая область исправления: Отдельные разрешения runner на чтение; проверить tasks, reports, artifacts, events, WS и MCP. В этом repro подтверждён именно REST messages.
- Fingerprint: Relay не вызывался; не выдуман.

## F04 [S0] Sandbox разрешает chmod файла вне workspace

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `sandbox.host.metadata`. Component: `src/nozo_relay/runner/sandbox_exec.py:223`.
- Preconditions/repro: Создать disposable sentinel вне всех allowed roots, mode 0600; через штатный launch_shim запустить Python os.chmod(path,0o644).
- Expected: Отказ; mode остаётся 0600.
- Actual: Child exit=0, mode=0644. Штатный sandbox-probe при этом exit=0/probe_pass. Реальные файлы пользователя и credentials не затрагивались.
- Evidence/regression: `test_sandbox_cannot_chmod_protected_host_file` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: M2 isolation: неразрешённая модификация host metadata; возможность раскрыть права чтения другим локальным principal. Это известное ограничение handoff, независимо подтверждённое как gate blocker.
- Предполагаемая область исправления: Запретить опасные metadata syscalls либо использовать отдельную OS identity/изоляцию, предотвращающую операции над host-owned files. Повторить chmod/chown/utime и остановку дерева.
- Fingerprint: Relay не вызывался; не выдуман.

## F05 [S1] Restore принимает заведомо неполную резервную копию

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `backup.restore.completeness`. Component: `src/nozo_relay/backup.py:183`.
- Preconditions/repro: Загрузить disposable artifact через API; удалить только его fixture bytes; create_backup выдаёт complete=false и пропускает artifact; вызвать restore_backup.
- Expected: BackupError до объявления успешного восстановления.
- Actual: Исключения нет; restore возвращает успешный результат с DB row для отсутствующего artifact. verify_backup проверяет только entries manifest, не complete/problems и не полноту соответствия DB artifacts.
- Evidence/regression: `test_incomplete_backup_must_not_restore` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: M1 Q24: успешное восстановление с потерянным evidence. Исходные данные пользователя не изменялись.
- Предполагаемая область исправления: Отвергать incomplete manifest; сверять наборы artifacts в SQLite и manifest, размеры и hashes. Regression: missing/corrupt/omitted artifact и штатный live-WAL backup.
- Fingerprint: Relay не вызывался; не выдуман.

## F06 [S2] mint-key оставляет файл после rollback commit

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `keymint.commit.atomicity`. Component: `src/nozo_relay/keymint.py:66`.
- Preconditions/repro: На disposable bootstrap БД инъецировать ошибку Session.commit; mint_key существующему implementer.
- Expected: Операция не оставляет файл ключа, не связанного с committed credential.
- Actual: Commit raises; в minted_keys остаётся один JSON. Значения ключей в отчёт не включены.
- Evidence/regression: `test_mint_commit_failure_does_not_leave_key_file` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: Не блокирует gate отдельно: unusable key и лишний секрет на диске, а не подтверждённая выдача прав.
- Предполагаемая область исправления: Cleanup охватывает выход из transaction context; определить восстановление после crash между fsync и DB commit.
- Fingerprint: Relay не вызывался; не выдуман.

## F07 [S2] Disk-full не классифицируется как recoverable storage failure

- Task/revision/snapshot: T12 / v1.0-draft.2 / `07288eedf6a8b30cb9e118f7434585179136d634`.
- Invariant: `storage.diskfull.classification`. Component: `src/nozo_relay/api/errors.py:140`.
- Preconditions/repro: Инъецировать sqlite3.OperationalError(database or disk is full) перед INSERT messages; повторить тот же запрос/key после снятия fault.
- Expected: 503 либо явный storage block с определённым recovery.
- Actual: Первый ответ 500 internal_error/retryable=false; повтор после снятия fault — 201. Ложный success и потеря committed write НЕ обнаружены.
- Evidence/regression: `test_disk_full_is_explicit_retryable_failure` в `evidence/t12/test_independent_audit.py`, вывод `independent.log`.
- Frequency/confidence: воспроизведено на текущем snapshot; high.
- Gate impact: Q23 partial; диагностический дефект, не доказательство потери данных.
- Предполагаемая область исправления: Классифицировать SQLITE_FULL/ENOSPC и сохранять outbox; проверить реальные disk-full и все mutating routes отдельно.
- Fingerprint: Relay не вызывался; не выдуман.

## Подтверждённые gaps, не выданы за новые defects

Нет production claim loop для реальных adapters: только test_worker/harness; M2 autonomous cycle не готов. OAuth consent page отсутствует; ChatGPT OAuth flow не готов. Реальный Cursor заблокирован отсутствием auth; ChatGPT web/mobile и Q32 real phone не проверены. Это дополнительные причины NO-GO, независимо от исправления F01–F07.

Round: первый независимый T12 аудит этого snapshot. Счётчик failed rounds в рабочей Relay DB не читался и не изменялся. Следующий шаг: исправления Cursor, новый exact snapshot, re-audit findings и затронутой регрессии. После трёх неуспешных audit rounds или доказанного цикла — эскалация; тестовые ошибки не являются отдельными audit rounds.
