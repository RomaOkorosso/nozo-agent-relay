# Эксплуатация после аудита T12

2026-10-29: **NO-GO для production**. Локальную демонстрацию проводить на disposable данных; runner isolation и authority boundaries требуют исправлений F01–F05.

## Запуск и остановка локальной демонстрации

Из project root: `./scripts/start.sh`. Он выполняет sync, одноразовый bootstrap и serve на 127.0.0.1:8765. Открыть `/login`; пароль находится в private `data/bootstrap_credentials.json`, не вставлять его в отчёты/чат. Для отдельной БД передать `NOZO_RELAY_DATA_DIR=/абсолютный/путь/к/новой/demo-data`.

Для остановки задачи использовать pause/cancel в UI, дождаться подтверждения supervisor; «Запрошено» не означает физическую остановку. Из-за F02 сейчас receipt нельзя считать надёжным при наличии чужого runner проекта. Сервер в foreground остановить Ctrl-C. Само выключение сервера не доказывает завершение дочерних процессов. После lease expiry задача должна попасть в recovery_required, без автоматического повторного запуска. Production real-agent daemon ещё отсутствует.

## Backup и восстановление

Команды: `uv run python -m nozo_relay backup --to /path/backup-NEW`, затем `uv run python -m nozo_relay verify-backup --from /path/backup-NEW`. **До fix F05 exit 0 verify/restore недостаточен**: обязательно complete=true, problems=[], полный набор artifact records/bytes и hashes; при отсутствующем artifact такой backup не использовать как подтверждённое восстановление. Исходную БД/backup сохранять.

Восстанавливать только в новую директорию: `uv run python -m nozo_relay restore --from /path/backup-NEW --to-data-dir /path/restored-NEW`. Для поддерживаемой старой схемы предусмотрен `--migrate`. После восстановления sessions revoked, active runs fenced; очистку старого child/workspace должен подтвердить его supervisor, затем owner resume. Перед запуском restored server исключить одновременно работающие старые workers; два сервера на одной data dir не запускать.

## Что делать дальше

1. Передать Cursor CODEX_FINDINGS.md и evidence/t12/test_independent_audit.py; production fixes этим аудитом не вносились.
2. Получить новый exact snapshot и regression evidence, затем re-audit.
3. Для Q27 нужен Cursor login/provider access; для Q32 — owner phone + private HTTPS; для Q30/31 — consent/transport и отдельные реальные проверки клиентов. Эти шаги здесь не выполнялись.
4. Не считать host-mode real Codex доказательством production sandbox; не считать mock Cursor реальной реализацией.

Подробности: CODEX_AUDIT_REPORT.md, ../CODEX_FINDINGS.md, исходный RUNBOOK.md (его рецепты проверялись в scope, но known gaps теперь уточнены этим аудитом).
